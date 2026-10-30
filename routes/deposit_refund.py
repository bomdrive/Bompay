"""Bompay — Deposit Refund routes (admin only)."""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from database import db
from core import get_admin_user, calculate_nip_inward_commission, sh_internal_transfer

router = APIRouter()
logger = logging.getLogger(__name__)

# ─── Settings helpers ──────────────────────────────────────────────────────────

async def get_refund_settings() -> dict:
    doc = await db.deposit_refund_settings.find_one({})
    if not doc:
        return {
            "user_enabled": False,
            "business_enabled": False,
            "user_refund_type": "full",
            "business_refund_type": "full",
            "user_partial_amount": 25.0,
            "business_partial_amount": 25.0,
            "source_account": "",
            "source_bank": "",
            "updated_at": None,
            "updated_by": None,
        }
    doc.pop("_id", None)
    return doc


# ─── Core refund processor ─────────────────────────────────────────────────────

async def process_deposit_refund(
    *,
    txn_id: str,
    user_id: str,
    customer_type: str,          # "user" | "business"
    deposit_amount_ngn: float,
    charge_amount_ngn: float,
    customer_name: str = "",
    customer_account: str = "",  # SafeHaven account number for merchants
    merchant_id: str = "",
):
    """Process deposit fee refund.
    - ALWAYS creates an audit record (SKIPPED / PENDING → COMPLETED or FAILED).
    - For 'user': silently credits the BOMPAY shadow wallet in MongoDB.
    - For 'business': makes a real SafeHaven internal transfer from the configured
      source account to the merchant's SafeHaven account number.
    """

    # ── Step 1: read settings ─────────────────────────────────────────────────
    try:
        settings = await get_refund_settings()
    except Exception as ex:
        logger.error(f"[DepositRefund] cannot read settings for txn={txn_id}: {ex}")
        return

    enabled = (
        settings.get("user_enabled")
        if customer_type == "user"
        else settings.get("business_enabled")
    )

    # ── Step 2: calculate refund amount ───────────────────────────────────────
    refund_type = (
        settings.get("user_refund_type", "full")
        if customer_type == "user"
        else settings.get("business_refund_type", "full")
    )
    partial_ngn = (
        float(settings.get("user_partial_amount", 25))
        if customer_type == "user"
        else float(settings.get("business_partial_amount", 25))
    )
    refund_ngn  = charge_amount_ngn if refund_type == "full" else min(partial_ngn, charge_amount_ngn)
    refund_kobo = int(round(refund_ngn * 100))

    # ── Determine initial status (ALWAYS create a record) ─────────────────────
    if not enabled:
        initial_status = "SKIPPED"
        skip_reason    = f"{customer_type} refund disabled in admin settings"
    elif refund_kobo <= 0:
        initial_status = "SKIPPED"
        skip_reason    = f"Refund amount is zero (charge_ngn={charge_amount_ngn:.2f})"
    else:
        initial_status = "PENDING"
        skip_reason    = ""

    logger.info(
        f"[DepositRefund] txn={txn_id} type={customer_type} enabled={enabled} "
        f"charge=₦{charge_amount_ngn:.2f} refund=₦{refund_ngn:.2f} → {initial_status}"
    )

    # ── Step 3: create audit record FIRST ─────────────────────────────────────
    refund_id = f"DR-{uuid.uuid4().hex[:12].upper()}"
    audit_doc = {
        "refund_id":             refund_id,
        "original_txn_id":       txn_id,
        "user_id":               str(user_id)      if user_id      else "",
        "merchant_id":           str(merchant_id)  if merchant_id  else "",
        "customer_type":         customer_type,
        "customer_name":         customer_name,
        "customer_account":      customer_account,
        "deposit_amount_kobo":   int(deposit_amount_ngn * 100),
        "charge_amount_kobo":    int(charge_amount_ngn  * 100),
        "refund_amount_kobo":    refund_kobo,
        "refund_type":           refund_type,
        "source_account":        settings.get("source_account", ""),
        "source_bank":           settings.get("source_bank", ""),
        "status":                initial_status,
        "skip_reason":           skip_reason,
        "sh_transfer_reference": "",
        "failure_reason":        "",
        "created_at":            datetime.now(timezone.utc).isoformat(),
    }
    try:
        await db.deposit_refunds.insert_one(audit_doc)
        logger.info(f"[DepositRefund] audit record created refund_id={refund_id} status={initial_status}")
    except Exception as ex:
        logger.error(f"[DepositRefund] failed to create audit record txn={txn_id}: {ex}")
        return

    if initial_status == "SKIPPED":
        return

    # ── Step 4: perform the actual refund ─────────────────────────────────────
    source_acct = settings.get("source_account", "").strip()
    credit_ok   = False
    failure_reason = ""
    sh_ref         = ""

    if customer_type == "user":
        # Local wallet credit — BOMPAY users have a MongoDB shadow wallet
        try:
            res = await db.wallets.update_one(
                {"user_id": user_id},
                {"$inc": {"available_balance": refund_kobo, "ledger_balance": refund_kobo}},
            )
            credit_ok = res.matched_count > 0
            if not credit_ok:
                failure_reason = f"User wallet not found (user_id={user_id})"
                logger.warning(f"[DepositRefund] {failure_reason}")
        except Exception as ex:
            failure_reason = str(ex)
            logger.error(f"[DepositRefund] user wallet update failed refund_id={refund_id}: {ex}")

    else:
        # Business / merchant — split by whether we have a real merchant_id
        if merchant_id:
            # BOMPAY Business App merchant — real SafeHaven internal transfer
            # Their balance is live from SafeHaven; the transfer credits their account directly.
            if not source_acct:
                failure_reason = "Source account not configured in admin settings"
                logger.warning(f"[DepositRefund] {failure_reason} refund_id={refund_id}")
            elif not customer_account:
                failure_reason = "Merchant SafeHaven account number unavailable"
                logger.warning(f"[DepositRefund] {failure_reason} refund_id={refund_id}")
            else:
                try:
                    sh_resp = await sh_internal_transfer(
                        from_account_number=source_acct,
                        to_account_number=customer_account,
                        amount_ngn=refund_ngn,
                        narration=f"Deposit fee refund {refund_id}",
                        ref=refund_id,
                    )
                    # call_sh raises HTTPException on provider errors;
                    # reaching here means the transfer was accepted.
                    resp_data = (sh_resp or {}).get("data") or {}
                    sh_ref = (
                        resp_data.get("paymentReference") or
                        resp_data.get("sessionId") or
                        (sh_resp or {}).get("paymentReference") or
                        (sh_resp or {}).get("sessionId") or ""
                    )
                    credit_ok = True
                    logger.info(
                        f"[DepositRefund] SafeHaven transfer OK refund_id={refund_id} "
                        f"₦{refund_ngn:.2f} {source_acct}→{customer_account} sh_ref={sh_ref}"
                    )
                except HTTPException as he:
                    failure_reason = f"SafeHaven rejected: {he.detail}"
                    logger.warning(f"[DepositRefund] {failure_reason} refund_id={refund_id}")
                except Exception as ex:
                    failure_reason = str(ex)
                    logger.error(f"[DepositRefund] SafeHaven transfer failed refund_id={refund_id}: {ex}")
        else:
            # Business wallet user (db.businesses) — local balance update.
            # A SafeHaven transfer would trigger a recursive webhook refund cycle.
            try:
                res = await db.business_wallets.update_one(
                    {"business_id": user_id},
                    {"$inc": {"available_balance": refund_kobo, "ledger_balance": refund_kobo}},
                )
                credit_ok = res.matched_count > 0
                if not credit_ok:
                    failure_reason = f"Business wallet not found (business_id={user_id})"
                    logger.warning(f"[DepositRefund] {failure_reason}")
            except Exception as ex:
                failure_reason = str(ex)
                logger.error(f"[DepositRefund] business wallet update failed refund_id={refund_id}: {ex}")

    # ── Step 5: update audit record with final status ─────────────────────────
    final_status = "COMPLETED" if credit_ok else "FAILED"
    try:
        await db.deposit_refunds.update_one(
            {"refund_id": refund_id},
            {"$set": {
                "status":                final_status,
                "sh_transfer_reference": sh_ref,
                "failure_reason":        failure_reason,
            }},
        )
    except Exception as ex:
        logger.error(f"[DepositRefund] status update failed refund_id={refund_id}: {ex}")

    logger.info(
        f"[DepositRefund] {'✅' if credit_ok else '❌'} refund_id={refund_id} "
        f"status={final_status} ₦{refund_ngn:.2f} → {customer_type} "
        f"[{user_id or merchant_id or customer_account}]"
    )


# ─── Request models ────────────────────────────────────────────────────────────

class DepositRefundSettingsIn(BaseModel):
    user_enabled:            bool  = False
    business_enabled:        bool  = False
    user_refund_type:        str   = "full"
    business_refund_type:    str   = "full"
    user_partial_amount:     float = 25.0
    business_partial_amount: float = 25.0
    source_account:          str   = ""
    source_bank:             str   = ""


class ManualRefundIn(BaseModel):
    txn_id:            str
    customer_type:     str           # "user" | "business"
    user_id:           str   = ""
    merchant_id:       str   = ""
    customer_name:     str   = ""
    customer_account:  str   = ""
    deposit_amount_ngn: float
    charge_amount_ngn:  float = 0.0  # 0 = auto-calculate


# ─── Admin Endpoints ────────────────────────────────────────────────────────────

@router.get("/admin/deposit-refund/settings")
async def get_deposit_refund_settings(request: Request):
    await get_admin_user(request)
    return await get_refund_settings()


@router.put("/admin/deposit-refund/settings")
async def update_deposit_refund_settings(request: Request, payload: DepositRefundSettingsIn):
    admin = await get_admin_user(request)
    now   = datetime.now(timezone.utc).isoformat()
    doc   = {
        **payload.dict(),
        "updated_at": now,
        "updated_by": admin.get("email", "admin"),
    }
    await db.deposit_refund_settings.replace_one({}, doc, upsert=True)
    return {"ok": True, "settings": doc}


@router.post("/admin/deposit-refund/manual")
async def manual_deposit_refund(request: Request, payload: ManualRefundIn):
    """Manually trigger a deposit refund for a specific transaction (admin only)."""
    await get_admin_user(request)

    charge = payload.charge_amount_ngn
    if charge <= 0:
        charge = await calculate_nip_inward_commission(payload.deposit_amount_ngn)

    await process_deposit_refund(
        txn_id=payload.txn_id,
        user_id=payload.user_id,
        customer_type=payload.customer_type,
        deposit_amount_ngn=payload.deposit_amount_ngn,
        charge_amount_ngn=charge,
        customer_name=payload.customer_name,
        customer_account=payload.customer_account,
        merchant_id=payload.merchant_id,
    )
    return {"ok": True, "message": "Refund processed — check records for result"}


@router.get("/admin/deposit-refund/records")
async def list_deposit_refund_records(
    request: Request,
    page: int = 1,
    limit: int = 50,
    search: str = "",
    customer_type: str = "",
    status: str = "",
    refund_type: str = "",
    date_from: str = "",
    date_to: str = "",
):
    await get_admin_user(request)
    q: dict = {}
    if search:
        q["$or"] = [
            {"customer_name":    {"$regex": search, "$options": "i"}},
            {"original_txn_id":  {"$regex": search, "$options": "i"}},
            {"refund_id":        {"$regex": search, "$options": "i"}},
            {"customer_account": {"$regex": search, "$options": "i"}},
        ]
    if customer_type in ("user", "business"):
        q["customer_type"] = customer_type
    if status in ("COMPLETED", "FAILED", "PENDING", "SKIPPED"):
        q["status"] = status
    if refund_type in ("full", "partial"):
        q["refund_type"] = refund_type
    if date_from:
        q.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        q.setdefault("created_at", {})["$lte"] = date_to + "T23:59:59"

    skip    = (page - 1) * limit
    records = (
        await db.deposit_refunds.find(q, {"_id": 0})
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
        .to_list(limit)
    )
    total = await db.deposit_refunds.count_documents(q)
    return {"records": records, "total": total, "page": page, "limit": limit}


@router.get("/admin/deposit-refund/summary")
async def deposit_refund_summary(request: Request):
    await get_admin_user(request)
    today = datetime.now(timezone.utc).date().isoformat()

    total_all       = await db.deposit_refunds.count_documents({})
    total_completed = await db.deposit_refunds.count_documents({"status": "COMPLETED"})
    total_failed    = await db.deposit_refunds.count_documents({"status": "FAILED"})
    total_skipped   = await db.deposit_refunds.count_documents({"status": "SKIPPED"})
    today_count     = await db.deposit_refunds.count_documents({"created_at": {"$gte": today}})

    def _sum_pipeline(match: dict):
        return [{"$match": match}, {"$group": {"_id": None, "k": {"$sum": "$refund_amount_kobo"}}}]

    async def _sum(match):
        r = await db.deposit_refunds.aggregate(_sum_pipeline(match)).to_list(1)
        return r[0]["k"] if r else 0

    return {
        "total_all":             total_all,
        "total_completed":       total_completed,
        "total_failed":          total_failed,
        "total_skipped":         total_skipped,
        "today_count":           today_count,
        "total_refunded_ngn":    await _sum({"status": "COMPLETED"}) / 100,
        "today_refunded_ngn":    await _sum({"status": "COMPLETED", "created_at": {"$gte": today}}) / 100,
        "user_refunded_ngn":     await _sum({"status": "COMPLETED", "customer_type": "user"}) / 100,
        "business_refunded_ngn": await _sum({"status": "COMPLETED", "customer_type": "business"}) / 100,
    }
