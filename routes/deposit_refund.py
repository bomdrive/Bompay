"""Bompay — Deposit Refund routes (admin only)."""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

from database import db
from core import get_admin_user

router = APIRouter()
logger = logging.getLogger(__name__)

# ─── Helpers ──────────────────────────────────────────────────────────────────

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


async def process_deposit_refund(
    *,
    txn_id: str,
    user_id: str,
    customer_type: str,   # "user" | "business"
    deposit_amount_ngn: float,
    charge_amount_ngn: float,
    customer_name: str = "",
    customer_account: str = "",
    merchant_id: str = "",
):
    """Credit a silent refund of the SafeHaven deposit charge back to the wallet.
    No entry appears in the customer's visible transaction history."""
    try:
        settings = await get_refund_settings()

        # Check if enabled for this customer type
        if customer_type == "user" and not settings.get("user_enabled"):
            return
        if customer_type == "business" and not settings.get("business_enabled"):
            return

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

        if refund_type == "full":
            refund_ngn = charge_amount_ngn
        else:
            # Partial: refund the configured amount but never more than the actual charge
            refund_ngn = min(partial_ngn, charge_amount_ngn)

        refund_kobo = int(round(refund_ngn * 100))
        if refund_kobo <= 0:
            return

        # ── Silently credit the wallet balance (no visible transaction) ──
        if customer_type == "user":
            res = await db.wallets.update_one(
                {"user_id": user_id},
                {"$inc": {"available_balance": refund_kobo}},
            )
        else:
            # For business accounts, credit the merchant's account balance
            res = await db.merchant_accounts.update_one(
                {"merchant_id": merchant_id},
                {"$inc": {"balance_kobo": refund_kobo}},
            )

        # ── Admin audit record ──
        refund_id = f"DR-{uuid.uuid4().hex[:12].upper()}"
        await db.deposit_refunds.insert_one({
            "refund_id": refund_id,
            "original_txn_id": txn_id,
            "user_id": user_id,
            "merchant_id": merchant_id,
            "customer_type": customer_type,
            "customer_name": customer_name,
            "customer_account": customer_account,
            "deposit_amount_kobo": int(deposit_amount_ngn * 100),
            "charge_amount_kobo": int(charge_amount_ngn * 100),
            "refund_amount_kobo": refund_kobo,
            "refund_type": refund_type,
            "source_account": settings.get("source_account", ""),
            "source_bank": settings.get("source_bank", ""),
            "status": "COMPLETED" if res.modified_count else "FAILED",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

        logger.info(
            f"[DepositRefund] ₦{refund_ngn:.2f} refunded to {customer_type} "
            f"{user_id or merchant_id} for txn={txn_id} status={'OK' if res.modified_count else 'FAIL'}"
        )
    except Exception as exc:
        logger.error(f"[DepositRefund] failed for txn={txn_id}: {exc}")


# ─── Request models ────────────────────────────────────────────────────────────

class DepositRefundSettingsIn(BaseModel):
    user_enabled: bool = False
    business_enabled: bool = False
    user_refund_type: str = "full"
    business_refund_type: str = "full"
    user_partial_amount: float = 25.0
    business_partial_amount: float = 25.0
    source_account: str = ""
    source_bank: str = ""


# ─── Admin Endpoints ────────────────────────────────────────────────────────────

@router.get("/admin/deposit-refund/settings")
async def get_deposit_refund_settings(request: Request):
    await get_admin_user(request)
    return await get_refund_settings()


@router.put("/admin/deposit-refund/settings")
async def update_deposit_refund_settings(request: Request, payload: DepositRefundSettingsIn):
    admin = await get_admin_user(request)
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        **payload.dict(),
        "updated_at": now,
        "updated_by": admin.get("email", "admin"),
    }
    await db.deposit_refund_settings.replace_one({}, doc, upsert=True)
    return {"ok": True, "settings": doc}


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
    if status in ("COMPLETED", "FAILED"):
        q["status"] = status
    if refund_type in ("full", "partial"):
        q["refund_type"] = refund_type
    if date_from:
        q.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        q.setdefault("created_at", {})["$lte"] = date_to + "T23:59:59"

    skip = (page - 1) * limit
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

    total_all = await db.deposit_refunds.count_documents({})
    total_completed = await db.deposit_refunds.count_documents({"status": "COMPLETED"})
    total_failed = await db.deposit_refunds.count_documents({"status": "FAILED"})
    today_count = await db.deposit_refunds.count_documents({"created_at": {"$gte": today}})

    pipeline = [
        {"$match": {"status": "COMPLETED"}},
        {"$group": {"_id": None, "total_kobo": {"$sum": "$refund_amount_kobo"}}},
    ]
    agg = await db.deposit_refunds.aggregate(pipeline).to_list(1)
    total_refunded_kobo = agg[0]["total_kobo"] if agg else 0

    pipeline_today = [
        {"$match": {"status": "COMPLETED", "created_at": {"$gte": today}}},
        {"$group": {"_id": None, "total_kobo": {"$sum": "$refund_amount_kobo"}}},
    ]
    agg_today = await db.deposit_refunds.aggregate(pipeline_today).to_list(1)
    today_refunded_kobo = agg_today[0]["total_kobo"] if agg_today else 0

    pipeline_user = [
        {"$match": {"status": "COMPLETED", "customer_type": "user"}},
        {"$group": {"_id": None, "total_kobo": {"$sum": "$refund_amount_kobo"}}},
    ]
    agg_user = await db.deposit_refunds.aggregate(pipeline_user).to_list(1)
    user_refunded_kobo = agg_user[0]["total_kobo"] if agg_user else 0

    pipeline_biz = [
        {"$match": {"status": "COMPLETED", "customer_type": "business"}},
        {"$group": {"_id": None, "total_kobo": {"$sum": "$refund_amount_kobo"}}},
    ]
    agg_biz = await db.deposit_refunds.aggregate(pipeline_biz).to_list(1)
    biz_refunded_kobo = agg_biz[0]["total_kobo"] if agg_biz else 0

    return {
        "total_all": total_all,
        "total_completed": total_completed,
        "total_failed": total_failed,
        "today_count": today_count,
        "total_refunded_ngn": total_refunded_kobo / 100,
        "today_refunded_ngn": today_refunded_kobo / 100,
        "user_refunded_ngn": user_refunded_kobo / 100,
        "business_refunded_ngn": biz_refunded_kobo / 100,
    }
