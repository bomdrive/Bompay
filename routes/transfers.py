"""Bompay — Transfers routes."""
import os, uuid, secrets, logging, time, json, asyncio, hashlib, re
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from pathlib import Path
from bson import ObjectId
import bcrypt
import jwt as pyjwt
import httpx
import requests as _requests
from fastapi import APIRouter, HTTPException, Request, Response, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
import csv, io
from fpdf import FPDF

from rate_limit import limiter
from database import db
from core import (  # noqa: F401,F403,F405
    # auth
    hash_password, verify_password, hash_pin, verify_pin_hash,
    create_access_token, create_refresh_token, get_current_user, get_admin_user,
    set_auth_cookies, log_login_session,
    # wallet / ledger
    gen_account_number, get_wallet, ledger_entry,
    # notifications
    notify, audit, send_event_sms, send_event_email, send_event_notification, send_email,
    send_push_notification,
    # fraud
    fraud_check, fraud_check_user, auto_block_user,
    # providers
    call_sh, mock_sh, call_cdh, call_pg,
    get_vas_provider, get_service_provider, get_sms_config,
    get_sms_provider, get_sendora_api_key, get_sendora_sender_id, get_bulksms_credentials,
    # private helpers (explicitly imported)
    _cloudinary_upload, _cloudinary_delete, _email_html,
    _send_tier_approval_email, _send_tier_revoke_email,
    _send_via_sendora, _send_via_bulksms,
    _get_client_ip, _parse_ua,
)
from core import (  # noqa: F401,F403,F405
    # constants
    JWT_SECRET, JWT_ALGORITHM, ADMIN_EMAIL, ADMIN_PASSWORD,
    FRONTEND_URL, WEBHOOK_CRON_SECRET, SAFEHAVEN_BASE_URL, SAFEHAVEN_OWN_BANK_CODE,
    CDH_BASE_URL, PAIRGATE_BASE_URL,
    PG_DISCO_SLUGS, PG_BET_SLUGS,
    CDH_AIRTIME_NETWORK_IDS, CDH_ELECTRICITY_DISCO_IDS, CDH_DATA_PLANS, CDH_CABLE_PLANS,
    NIGERIAN_BANKS, MOCK_NAMES, CHARGE_CATEGORIES,
    WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN, WEBAUTHN_RP_NAME,
    APP_NAME, EMERGENT_LLM_KEY,
    # webauthn
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    base64url_to_bytes, options_to_json,
    AuthenticatorSelectionCriteria, UserVerificationRequirement,
    ResidentKeyRequirement, AttestationConveyancePreference,
    AuthenticatorAttachment, PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse, RegistrationCredential,
    AuthenticatorAssertionResponse, AuthenticationCredential,
    cloudinary,
)
from core import (  # noqa: F401
    NameEnquiryReq, TransferReq, BompayTransferReq, BaseModel,
    require_virtual_account, verify_transaction_pin, calculate_fee,
    calculate_stamp_duty,
    get_sh_subaccount_balance, get_nip_fee, _sweep_fee_margin,
    _credit_cashback_bg, _check_referral_bg, _complete_epos_txn_bg,
    require_service_enabled,
)
import ledger as pg_ledger
from routes.strowallet import strow_name_enquiry, strow_bank_transfer

router = APIRouter()
logger = logging.getLogger(__name__)


# ── WAT timezone + free-transfer helpers ───────────────────────────────────

def _get_wat_day_start_utc() -> str:
    """ISO string of WAT (UTC+1) midnight expressed as UTC for the current WAT calendar day."""
    now_utc = datetime.now(timezone.utc)
    # WAT = UTC+1 (no DST). Find the start of *today* in WAT.
    total_minutes = now_utc.hour * 60 + now_utc.minute + 60  # +60 for WAT offset
    if total_minutes >= 1440:  # current UTC time already belongs to the next WAT day
        wat_date = (now_utc + timedelta(days=1)).date()
    else:
        wat_date = now_utc.date()
    # WAT midnight = today 00:00 WAT = (today 00:00 UTC) − 1 h = yesterday 23:00 UTC
    midnight_utc = datetime(wat_date.year, wat_date.month, wat_date.day,
                            tzinfo=timezone.utc) - timedelta(hours=1)
    return midnight_utc.isoformat()


async def _refund_nip_fee_bg(txn_id: str, user_id: str, user_account: str,
                              nip_fee_ngn: float, refund_account_number: str) -> None:
    """Background: transfer the NIP fee from admin's dedicated SH account → user's SH sub-account.
    Creates a reimbursement record; marks COMPLETED on success, FAILED on error.
    This is NOT exposed as a customer transfer."""
    reimbursement_id = f"REIMB{secrets.token_hex(8).upper()}"
    now = datetime.now(timezone.utc).isoformat()
    await db.free_transfer_reimbursements.insert_one({
        "reimbursement_id": reimbursement_id,
        "txn_id": txn_id,
        "user_id": user_id,
        "nip_fee_kobo": int(round(nip_fee_ngn * 100)),
        "refund_account_number": refund_account_number,
        "status": "PENDING",
        "created_at": now,
        "updated_at": now,
    })
    try:
        # Name-enquiry for the user's Safe Haven sub-account (required by SH transfer API)
        ne_resp = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": SAFEHAVEN_OWN_BANK_CODE,
            "accountNumber": user_account,
        })
        ne_data = ne_resp.get("data", {})
        ne_ref = ne_data.get("sessionId") or f"NEQ{secrets.token_hex(8).upper()}"
        # Transfer NIP fee from refund account → user's account
        r = await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": ne_ref,
            "debitAccountNumber": refund_account_number,
            "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
            "beneficiaryAccountNumber": user_account,
            "amount": round(nip_fee_ngn, 2),
            "saveBeneficiary": False,
            "narration": "NIP fee refund",
            "paymentReference": f"RFND{reimbursement_id}",
        })
        r_data = r.get("data", {})
        # SH may return HTTP 201 with embedded failure status — guard against it
        if str(r_data.get("status") or "").lower() in ("failed", "fail"):
            raise Exception(f"SH rejected refund: {r_data}")
        provider_ref = r_data.get("transactionReference") or r_data.get("reference") or ""
        await db.free_transfer_reimbursements.update_one(
            {"reimbursement_id": reimbursement_id},
            {"$set": {
                "status": "COMPLETED",
                "provider_reference": provider_ref,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }}
        )
        logger.info(f"[FreeTransfer] Reimbursement {reimbursement_id} completed "
                    f"(txn={txn_id}, ₦{nip_fee_ngn:.2f})")
    except Exception as exc:
        logger.error(f"[FreeTransfer] Reimbursement {reimbursement_id} FAILED "
                     f"(txn={txn_id}): {exc}")
        await db.free_transfer_reimbursements.update_one(
            {"reimbursement_id": reimbursement_id},
            {"$set": {
                "status": "FAILED",
                "error": str(exc)[:500],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }}
        )


@router.get("/transfers/banks")
async def get_banks():
    try:
        r = await call_sh("GET", "/transfers/banks")
        raw = r.get("data", NIGERIAN_BANKS)
        # Normalize Safe Haven format (bankCode) to standard format (code) used by frontend
        normalized = []
        for b in raw:
            if isinstance(b, dict):
                normalized.append({
                    "name": b.get("name", b.get("bankName", "")),
                    "code": b.get("bankCode", b.get("code", b.get("routingKey", ""))),
                })
        return normalized if normalized else NIGERIAN_BANKS
    except Exception:
        return NIGERIAN_BANKS

@router.post("/transfers/name-enquiry")
async def name_enquiry(req: NameEnquiryReq, request: Request):
    await get_current_user(request)
    transfer_provider = await get_service_provider("TRANSFER")   # "SAFEHAVEN" or "STROWALLET"
    if transfer_provider == "STROWALLET":
        result = await strow_name_enquiry(req.bank_code, req.account_number)
        sid = result["session_id"]
        account_name = result["account_name"]
    else:
        r = await call_sh("POST", "/transfers/name-enquiry",
                           body={"bankCode": req.bank_code, "accountNumber": req.account_number})
        data = r.get("data", {})
        sid = data.get("sessionId") or f"NEQ{secrets.token_hex(8).upper()}"
        account_name = data.get("accountName", "")
    await db.name_enquiries.update_one({"session_id": sid},
        {"$setOnInsert": {"session_id": sid, "bank_code": req.bank_code,
          "account_number": req.account_number, "account_name": account_name,
          "created_at": datetime.now(timezone.utc).isoformat()}}, upsert=True)
    return {"account_name": account_name, "account_number": req.account_number,
            "bank_code": req.bank_code, "session_id": sid}

@router.post("/transfers/send")
@limiter.limit("10/minute")
async def send_money(request: Request, req: TransferReq):
    user = await get_current_user(request)
    await require_virtual_account(user)
    await require_service_enabled("TRANSFERS")
    if req.amount < 100 or req.amount > 5_000_000:
        raise HTTPException(400, "Transfer amount must be between ₦100 and ₦5,000,000")
    await verify_transaction_pin(user["_id"], req.transaction_pin, getattr(req, "biometric_token", None))

    # ─── KYC tier limit check ───
    user_tier = user.get("kyc_tier", 0)
    tier_cfg = await db.kyc_tier_configs.find_one({"tier": user_tier})
    if tier_cfg:
        single_limit = tier_cfg.get("single_transfer_limit_naira", 0)
        daily_limit = tier_cfg.get("daily_transfer_limit_naira", 0)
        if single_limit == 0:
            raise HTTPException(403, "Your account needs to be verified to make transfers. Please complete your KYC.")
        if req.amount > single_limit:
            raise HTTPException(403, f"₦{req.amount:,.0f} exceeds your Tier {user_tier} single-transfer limit of ₦{single_limit:,}. Upgrade your account tier to increase.")
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        daily_agg = await db.transactions.aggregate([
            {"$match": {"user_id": user["_id"], "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]}, "direction": "DEBIT", "status": {"$ne": "FAILED"}, "created_at": {"$gte": today_start}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]).to_list(1)
        daily_used_kobo = daily_agg[0]["total"] if daily_agg else 0
        if daily_used_kobo + int(req.amount * 100) > daily_limit * 100:
            remaining = max(0, daily_limit * 100 - daily_used_kobo)
            raise HTTPException(403, f"Daily transfer limit reached. Tier {user_tier} limit: ₦{daily_limit:,}/day. Remaining today: ₦{(remaining/100):,.2f}. Upgrade your account tier to increase.")

    # ─── Enhanced risk scoring (populates risk_assessments / risk queue) ───
    fraud_signals = await fraud_check_user(str(user["_id"]), int(req.amount * 100))
    if "RAPID_TRANSACTIONS" in fraud_signals:
        await auto_block_user(str(user["_id"]), "RAPID_TRANSACTIONS", fraud_signals,
                              {"amount": int(req.amount * 100), "bank_code": req.bank_code})
        raise HTTPException(429, "Account temporarily blocked: too many transactions in a short period. Contact support.")
    if fraud_signals and not ("RAPID_TRANSACTIONS" in fraud_signals):
        await db.fraud_alerts.insert_one({
            "alert_id": str(uuid.uuid4()), "user_id": str(user["_id"]),
            "type": "SUSPICIOUS_TRANSFER", "signals": fraud_signals,
            "amount": int(req.amount * 100), "status": "OPEN", "auto_blocked": False,
            "metadata": {"bank_code": req.bank_code, "account_number": req.account_number, "amount_ngn": req.amount},
            "created_at": datetime.now(timezone.utc).isoformat()
        })

    # Velocity + 0-100 scoring — blocks critical-risk transfers
    try:
        from routes.fraud import assess_transaction_risk
        _risk = await assess_transaction_risk(str(user["_id"]), int(req.amount * 100), "BANK_TRANSFER", None)
        if _risk.get("decision") == "block":
            raise HTTPException(403,
                f"Transaction blocked by fraud prevention (risk score: {_risk['score']}/100). "
                "Please contact BOMPAY support if you believe this is an error.")
    except HTTPException:
        raise
    except Exception:
        pass   # Risk engine failure must not block legitimate transfers
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    dup = await db.transactions.find_one({
        "user_id": user["_id"],
        "type": "BANK_TRANSFER",
        "amount": int(req.amount * 100),
        "metadata.account_number": req.account_number,
        "created_at": {"$gte": cutoff}
    })
    if dup:
        raise HTTPException(409, "Duplicate transfer detected. This exact transfer was just sent. Please wait a moment before trying again.")
    idem = req.idempotency_key or str(uuid.uuid4())
    existing = await db.transactions.find_one({"idempotency_key": idem})
    if existing:
        return {"transaction_id": existing["transaction_id"], "status": existing["status"]}
    amt = int(req.amount * 100)
    fee_ngn = await calculate_fee("TRANSFER", req.amount)     # NIP Commission
    stamp_duty_ngn = await calculate_stamp_duty(req.amount)   # NIP Stamp Duty (0 if ≤10k)
    fee = int(fee_ngn * 100)
    stamp_duty = int(stamp_duty_ngn * 100)
    total = amt + fee + stamp_duty
    w = await get_wallet(user["_id"])
    # PRIMARY: Live Safe Haven balance check (SH is the financial authority)
    sh_id = w.get("sh_account_id")
    sh_balance: float | None = None
    if sh_id:
        sh_balance = await get_sh_subaccount_balance(sh_id)
        if sh_balance * 100 < total:
            raise HTTPException(400, f"Insufficient balance. Available: ₦{sh_balance:,.2f}.")
    elif w["available_balance"] < total:
        # Fallback: no SH account linked — use Mongo mirror
        raise HTTPException(400, f"Insufficient balance. Available: ₦{(w['available_balance']/100):,.2f}, Need: ₦{(total/100):,.2f}")
    signals = fraud_check(amt)
    if signals:
        await db.fraud_alerts.insert_one({
            "alert_id": str(uuid.uuid4()), "user_id": str(user["_id"]),
            "type": "SUSPICIOUS_TRANSFER", "signals": signals, "amount": amt,
            "status": "OPEN", "created_at": datetime.now(timezone.utc).isoformat()
        })
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": idem, "user_id": user["_id"],
        "type": "BANK_TRANSFER", "direction": "DEBIT", "amount": amt, "fee": fee,
        "fee_stamp_duty": stamp_duty,
        "vat": 0, "currency": "NGN", "status": "PROCESSING", "provider": "SAFEHAVEN",
        "description": f"Transfer to {req.beneficiary_name}",
        "metadata": {"bank_code": req.bank_code, "account_number": req.account_number,
                     "beneficiary_name": req.beneficiary_name, "narration": req.narration,
                     "stamp_duty_applied": stamp_duty_ngn > 0},
        "balance_before_kobo": int(sh_balance * 100) if sh_balance is not None else w["available_balance"],
        "balance_after_kobo": int((sh_balance - total / 100) * 100) if sh_balance is not None else w["available_balance"] - total,
        "created_at": datetime.now(timezone.utc).isoformat(), "updated_at": datetime.now(timezone.utc).isoformat()
    })
    # SHADOW: Mirror debit — SH is the financial authority; this keeps Mongo mirror in sync
    await db.wallets.update_one(
        {"user_id": user["_id"]},
        {"$inc": {"available_balance": -total, "ledger_balance": -total}}
    )
    try:
        transfer_provider = await get_service_provider("TRANSFER")
        # ── Free-transfer eligibility (Safe Haven only; refunds NIP fee on success) ──
        _ft_cfg = await db.free_transfer_config.find_one({}) or {}
        _is_free = (
            transfer_provider != "STROWALLET"
            and bool(_ft_cfg.get("enabled"))
            and int(_ft_cfg.get("daily_free_count", 0)) > 0
            and bool(str(_ft_cfg.get("refund_account_number", "")).strip())
        )
        if _is_free:
            _free_used = await db.transactions.count_documents({
                "user_id": user["_id"], "type": "BANK_TRANSFER", "direction": "DEBIT",
                "status": {"$nin": ["FAILED", "PROCESSING"]},
                "free_transfer_used": True,
                "created_at": {"$gte": _get_wat_day_start_utc()},
            })
            _is_free = _free_used < int(_ft_cfg["daily_free_count"])
        if transfer_provider == "STROWALLET":
            # ── Strowallet transfer path ──────────────────────────────────
            result = await strow_bank_transfer(
                amount=req.amount,
                bank_code=req.bank_code,
                account_number=req.account_number,
                narration=req.narration or "BOMPAY Transfer",
                payment_reference=txn_id,
                sender_name=f"{user.get('first_name','')} {user.get('last_name','')}".strip() or "BOMPAY",
                name_enquiry_ref=req.name_enquiry_reference or "",
            )
            pdata = result.get("raw", {}).get("data", {})
            provider_ref = result["reference"]
        else:
            # ── Safe Haven transfer path (default) ────────────────────────
            pr = await call_sh("POST", "/transfers", body={
                "nameEnquiryReference": req.name_enquiry_reference,
                "debitAccountNumber": w["account_number"],
                "beneficiaryBankCode": req.bank_code,
                "beneficiaryAccountNumber": req.account_number,
                "amount": req.amount,
                "saveBeneficiary": False,
                "narration": req.narration or f"Transfer from Bompay",
                "paymentReference": txn_id
            })
            pdata = pr.get("data", {})
            provider_ref = pdata.get("transactionReference", "")
        await db.transactions.update_one({"transaction_id": txn_id}, {"$set": {
            "status": "COMPLETED",
            "provider_reference": provider_ref,
            "provider": transfer_provider,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }})
        await ledger_entry(user["_id"], w["_id"], txn_id, "DEBIT", total, f"Transfer to {req.beneficiary_name}")
        # Record fee income separately for revenue tracking
        if fee > 0:
            await db.transactions.insert_one({
                "transaction_id": f"FEE{txn_id}", "user_id": "PLATFORM",
                "type": "FEE_INCOME", "direction": "CREDIT", "amount": fee, "fee": 0,
                "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
                "description": f"Transfer fee from {user['first_name']} {user.get('last_name','')}",
                "metadata": {"source_txn": txn_id, "payer_id": user["_id"], "service": "TRANSFER"},
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
        # Sweep BOMPAY margin to Transfer Fees charge account (Safe Haven only)
        if transfer_provider != "STROWALLET":
            sh_fee_ngn = float(pdata.get("fee") or pdata.get("charges") or pdata.get("charge") or
                               await get_nip_fee(req.amount))
            asyncio.create_task(_sweep_fee_margin(
                txn_id=txn_id, user_account=w["account_number"],
                bompay_fee_ngn=fee_ngn, sh_fee_ngn=sh_fee_ngn, category="TRANSFER_FEES"
            ))
            # ── Free transfer: mark txn + schedule NIP-fee reimbursement ──────
            if _is_free:
                await db.transactions.update_one(
                    {"transaction_id": txn_id}, {"$set": {"free_transfer_used": True}}
                )
                asyncio.create_task(_refund_nip_fee_bg(
                    txn_id=txn_id, user_id=user["_id"], user_account=w["account_number"],
                    nip_fee_ngn=sh_fee_ngn,
                    refund_account_number=_ft_cfg["refund_account_number"],
                ))
        # Mirror to PostgreSQL immutable ledger
        try:
            await pg_ledger.record_transfer_out(
                user_id=user["_id"], user_name=f"{user['first_name']} {user['last_name']}",
                amount_ngn=req.amount, fee_ngn=fee/100,
                reference=txn_id, mongo_txn_id=txn_id
            )
        except Exception as le:
            logger.error(f"[Ledger] transfer_out mirror failed: {le}")
        await notify(user["_id"], "Transfer Successful",
                     f"₦{req.amount:,.2f} sent to {req.beneficiary_name}.", "success")
        await audit(user["_id"], "BANK_TRANSFER", "wallet",
                    {"amount": req.amount, "beneficiary": req.beneficiary_name})
        w_after = await get_wallet(user["_id"])
        # Use live SH balance for notification; fall back to shadow if SH not configured
        bal_for_notif = (sh_balance - total / 100) if sh_balance is not None else (w_after["available_balance"] / 100)
        asyncio.create_task(send_event_notification(user["_id"], "TRANSFER_DEBIT", {
            "amount": req.amount, "beneficiary": req.beneficiary_name,
            "ref": txn_id, "balance": bal_for_notif
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "TRANSFER", f"bank transfer to {req.beneficiary_name}"))
        asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
        return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount,
                "fee": fee/100, "beneficiary_name": req.beneficiary_name,
                "provider_reference": provider_ref, "provider": transfer_provider}
    except Exception as e:
        await db.wallets.update_one({"user_id": user["_id"]}, {"$inc": {"available_balance": total, "ledger_balance": total}})
        await db.transactions.update_one({"transaction_id": txn_id}, {"$set": {"status": "FAILED"}})
        await notify(user["_id"], "Transfer Failed", f"Transfer of ₦{req.amount:,.2f} failed. Funds reversed.", "error")
        raise HTTPException(500, "Transfer failed. Funds reversed.")

# ===== BOMPAY INTERNAL TRANSFER =====
@router.get("/users/lookup")
async def lookup_bompay_user(q: str, request: Request):
    """Look up a BOMPAY user by phone number or Safe Haven virtual account number."""
    await get_current_user(request)
    q = q.strip()
    if not q:
        raise HTTPException(400, "Provide a phone number or account number")
    # Try by SA account number first
    receiver_wallet = await db.wallets.find_one({"sh_account_number": q})
    receiver_doc = None
    if receiver_wallet:
        receiver_doc = await db.users.find_one({"_id": ObjectId(receiver_wallet["user_id"])})
    # Try by phone number
    if not receiver_wallet:
        receiver_doc = await db.users.find_one({"phone": q})
        if receiver_doc:
            receiver_wallet = await db.wallets.find_one({"user_id": str(receiver_doc["_id"])})
    if not receiver_wallet or not receiver_doc:
        raise HTTPException(404, "No BOMPAY user found with that phone or account number")
    if not receiver_wallet.get("sh_account_number"):
        raise HTTPException(400, "Recipient hasn't activated their BOMPAY account yet")
    name = f"{receiver_doc.get('first_name','')} {receiver_doc.get('last_name','')}".strip().upper()
    return {"name": name, "sh_account_number": receiver_wallet["sh_account_number"]}

@router.get("/transfers/recent")
async def get_recent_transfers(request: Request, limit: int = 5):
    """Return the user's most recent completed outgoing transfers — deduplicated by account_number."""
    user = await get_current_user(request)
    txns = await db.transactions.find({
        "user_id": user["_id"],
        "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]},
        "direction": "DEBIT",
        "status": "COMPLETED"
    }).sort("created_at", -1).limit(50).to_list(50)

    seen = set()
    result = []
    for txn in txns:
        meta = txn.get("metadata", {})
        acct = meta.get("account_number", meta.get("sh_account_number", ""))
        if acct and acct in seen:
            continue
        if acct:
            seen.add(acct)
        result.append({
            "transaction_id": txn["transaction_id"],
            "beneficiary_name": meta.get("beneficiary_name", txn.get("description", "").replace("Transfer to ", "")),
            "bank_code": meta.get("bank_code", ""),
            "bank_name": meta.get("bank_name", ""),
            "account_number": acct,
            "amount": txn["amount"] / 100,
            "type": txn["type"],
            "created_at": txn["created_at"]
        })
        if len(result) >= limit:
            break
    return result

# ─── User Saved Beneficiaries ──────────────────────────────────────────────

class UserBeneficiaryIn(BaseModel):
    account_number: str
    bank_code: str
    bank_name: str
    account_name: str
    nickname: str | None = None

@router.get("/transfers/beneficiaries")
async def list_user_beneficiaries(request: Request):
    user = await get_current_user(request)
    bens = await db.user_beneficiaries.find(
        {"user_id": str(user["_id"])}, {"_id": 0}
    ).sort("used_count", -1).to_list(50)
    return {"beneficiaries": bens}

@router.post("/transfers/beneficiaries")
async def save_user_beneficiary(req: UserBeneficiaryIn, request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    existing = await db.user_beneficiaries.find_one(
        {"user_id": uid, "account_number": req.account_number, "bank_code": req.bank_code}
    )
    ts = datetime.now(timezone.utc).isoformat()
    if existing:
        await db.user_beneficiaries.update_one(
            {"_id": existing["_id"]},
            {"$set": {"account_name": req.account_name, "nickname": req.nickname, "updated_at": ts},
             "$inc": {"used_count": 1}}
        )
        return {"message": "Beneficiary updated"}
    await db.user_beneficiaries.insert_one({
        "user_id": uid, "account_number": req.account_number,
        "bank_code": req.bank_code, "bank_name": req.bank_name,
        "account_name": req.account_name, "nickname": req.nickname,
        "used_count": 1, "created_at": ts, "updated_at": ts
    })
    return {"message": "Beneficiary saved"}

@router.delete("/transfers/beneficiaries/{account_number}")
async def delete_user_beneficiary(account_number: str, request: Request):
    user = await get_current_user(request)
    await db.user_beneficiaries.delete_one(
        {"user_id": str(user["_id"]), "account_number": account_number}
    )
    return {"message": "Removed"}

# ─── Scheduled Transfers ───────────────────────────────────────────────────

class ScheduledTransferReq(BaseModel):
    bank_code: str
    account_number: str
    beneficiary_name: str
    name_enquiry_reference: str
    amount: float
    narration: str = "Transfer from Bompay"
    scheduled_for: str  # YYYY-MM-DD
    transaction_pin: str | None = None
    biometric_token: str | None = None

@router.post("/transfers/scheduled")
async def create_scheduled_transfer(req: ScheduledTransferReq, request: Request):
    user = await get_current_user(request)
    try:
        from datetime import date as _date
        scheduled_date = datetime.strptime(req.scheduled_for, "%Y-%m-%d").date()
        if scheduled_date <= datetime.now(timezone.utc).date():
            raise HTTPException(400, "Scheduled date must be in the future")
    except ValueError:
        raise HTTPException(400, "Invalid date format. Use YYYY-MM-DD")
    sched_id = f"SCHED{secrets.token_hex(8).upper()}"
    doc = {
        "user_id": user["_id"],
        "scheduled_id": sched_id,
        "bank_code": req.bank_code,
        "account_number": req.account_number,
        "beneficiary_name": req.beneficiary_name,
        "name_enquiry_reference": req.name_enquiry_reference,
        "amount": req.amount,
        "narration": req.narration,
        "scheduled_for": req.scheduled_for,
        "status": "SCHEDULED",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.scheduled_transfers.insert_one(doc)
    return {
        "scheduled_id": sched_id,
        "scheduled_for": req.scheduled_for,
        "beneficiary_name": req.beneficiary_name,
        "amount": req.amount,
        "status": "SCHEDULED",
    }

@router.get("/transfers/scheduled")
async def list_scheduled_transfers(request: Request):
    user = await get_current_user(request)
    docs = await db.scheduled_transfers.find(
        {"user_id": user["_id"], "status": {"$in": ["SCHEDULED", "REMINDED"]}},
    ).sort("scheduled_for", 1).to_list(50)
    return [
        {
            "scheduled_id": d.get("scheduled_id"),
            "beneficiary_name": d.get("beneficiary_name"),
            "amount": d.get("amount"),
            "scheduled_for": d.get("scheduled_for"),
            "status": d.get("status"),
            "bank_code": d.get("bank_code"),
            "account_number": d.get("account_number"),
            "narration": d.get("narration"),
        }
        for d in docs
    ]

@router.delete("/transfers/scheduled/{scheduled_id}")
async def cancel_scheduled_transfer(scheduled_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.scheduled_transfers.update_one(
        {"scheduled_id": scheduled_id, "user_id": user["_id"], "status": "SCHEDULED"},
        {"$set": {"status": "CANCELLED"}}
    )
    if result.modified_count == 0:
        raise HTTPException(404, "Scheduled transfer not found or already processed")
    return {"ok": True}

# ─── Transfer Settings ────────────────────────────────────────────────────

TIER_LIMITS = {
    0: {"daily": 0, "per_tx": 0},
    1: {"daily": 50000, "per_tx": 10000},
    2: {"daily": 200000, "per_tx": 50000},
    3: {"daily": 5000000, "per_tx": 1000000},
}

@router.get("/user/transfer-settings")
async def get_transfer_settings(request: Request):
    user = await get_current_user(request)
    tier = user.get("kyc_tier", 0)
    tier_cfg = await db.kyc_tier_configs.find_one({"tier": tier})
    tier_daily = (tier_cfg or {}).get("daily_transfer_limit_naira", TIER_LIMITS.get(tier, {}).get("daily", 0))
    tier_per_tx = (tier_cfg or {}).get("single_transfer_limit_naira", TIER_LIMITS.get(tier, {}).get("per_tx", 0))
    settings = user.get("transfer_settings", {})
    return {
        "kyc_tier": tier,
        "tier_daily_limit": tier_daily,
        "tier_per_tx_limit": tier_per_tx,
        "daily_limit": settings.get("daily_limit", tier_daily),
        "per_tx_limit": settings.get("per_tx_limit", tier_per_tx),
    }

@router.put("/user/transfer-settings")
async def update_transfer_settings(request: Request):
    user = await get_current_user(request)
    body = await request.json()
    daily_limit = body.get("daily_limit")
    per_tx_limit = body.get("per_tx_limit")
    tier = user.get("kyc_tier", 0)
    tier_cfg = await db.kyc_tier_configs.find_one({"tier": tier})
    tier_daily = (tier_cfg or {}).get("daily_transfer_limit_naira", TIER_LIMITS.get(tier, {}).get("daily", 0))
    tier_per_tx = (tier_cfg or {}).get("single_transfer_limit_naira", TIER_LIMITS.get(tier, {}).get("per_tx", 0))
    if daily_limit is not None and daily_limit > tier_daily:
        raise HTTPException(400, f"Daily limit cannot exceed your Tier {tier} limit of ₦{tier_daily:,}")
    if per_tx_limit is not None and per_tx_limit > tier_per_tx:
        raise HTTPException(400, f"Per-transaction limit cannot exceed your Tier {tier} limit of ₦{tier_per_tx:,}")
    update: dict = {}
    if daily_limit is not None:
        update["transfer_settings.daily_limit"] = daily_limit
    if per_tx_limit is not None:
        update["transfer_settings.per_tx_limit"] = per_tx_limit
    if update:
        await db.users.update_one({"_id": user["_id"]}, {"$set": update})
    return {"ok": True, "daily_limit": daily_limit, "per_tx_limit": per_tx_limit}

# ─── Cron: Scheduled Transfer Reminders ─────────────────────────────────

@router.post("/cron/scheduled-transfer-reminders")
async def cron_scheduled_reminders(request: Request):
    today = datetime.now(timezone.utc).date().isoformat()
    docs = await db.scheduled_transfers.find(
        {"scheduled_for": today, "status": "SCHEDULED"}
    ).to_list(None)
    reminded = 0
    for doc in docs:
        uid = doc.get("user_id")
        u = await db.users.find_one({"_id": ObjectId(uid) if isinstance(uid, str) else uid})
        if u:
            msg = (f"Reminder: You scheduled a BOMPAY transfer of \u20a6{doc['amount']:,.2f} to "
                   f"{doc['beneficiary_name']} for today. Open the app to confirm and send.")
            phone = u.get("phone", "")
            if phone:
                await _send_via_sendora(phone, msg)
            await send_event_notification(
                u, "scheduled_transfer_reminder",
                f"Scheduled transfer of \u20a6{doc['amount']:,.2f} to {doc['beneficiary_name']} is due today",
                {"amount": doc["amount"], "beneficiary": doc["beneficiary_name"]}
            )
            await db.scheduled_transfers.update_one(
                {"_id": doc["_id"]},
                {"$set": {"status": "REMINDED", "reminded_at": datetime.now(timezone.utc).isoformat()}}
            )
            reminded += 1
    return {"reminded": reminded, "date": today}

@router.post("/transfers/bompay-send")
@limiter.limit("10/minute")
async def bompay_transfer(request: Request, req: BompayTransferReq):
    """Transfer funds from sender's SA subaccount directly to receiver's SA subaccount."""
    user = await get_current_user(request)
    await require_virtual_account(user)
    await require_service_enabled("TRANSFERS")
    if req.amount < 100 or req.amount > 5_000_000:
        raise HTTPException(400, "Transfer amount must be between ₦100 and ₦5,000,000")
    await verify_transaction_pin(user["_id"], req.transaction_pin, getattr(req, "biometric_token", None))

    # ─── KYC tier limit check ───
    user_tier_b = user.get("kyc_tier", 0)
    tier_cfg_b = await db.kyc_tier_configs.find_one({"tier": user_tier_b})
    if tier_cfg_b:
        single_limit_b = tier_cfg_b.get("single_transfer_limit_naira", 0)
        daily_limit_b = tier_cfg_b.get("daily_transfer_limit_naira", 0)
        if single_limit_b == 0:
            raise HTTPException(403, "Your account needs to be verified to make transfers. Please complete your KYC.")
        if req.amount > single_limit_b:
            raise HTTPException(403, f"₦{req.amount:,.0f} exceeds your Tier {user_tier_b} single-transfer limit of ₦{single_limit_b:,}. Upgrade your account tier to increase.")
        today_start_b = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        daily_agg_b = await db.transactions.aggregate([
            {"$match": {"user_id": user["_id"], "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]}, "direction": "DEBIT", "status": {"$ne": "FAILED"}, "created_at": {"$gte": today_start_b}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]).to_list(1)
        daily_used_kobo_b = daily_agg_b[0]["total"] if daily_agg_b else 0
        if daily_used_kobo_b + int(req.amount * 100) > daily_limit_b * 100:
            remaining_b = max(0, daily_limit_b * 100 - daily_used_kobo_b)
            raise HTTPException(403, f"Daily transfer limit reached. Tier {user_tier_b} limit: ₦{daily_limit_b:,}/day. Remaining today: ₦{(remaining_b/100):,.2f}. Upgrade your account tier to increase.")

    # Resolve receiver
    recipient = req.recipient.strip()
    receiver_wallet = await db.wallets.find_one({"sh_account_number": recipient})
    receiver_doc = None
    if receiver_wallet:
        receiver_doc = await db.users.find_one({"_id": ObjectId(receiver_wallet["user_id"])})
    if not receiver_wallet:
        receiver_doc = await db.users.find_one({"phone": recipient})
        if receiver_doc:
            receiver_wallet = await db.wallets.find_one({"user_id": str(receiver_doc["_id"])})
    if not receiver_wallet or not receiver_doc:
        raise HTTPException(404, "BOMPAY user not found with that phone or account number")
    if not receiver_wallet.get("sh_account_number"):
        raise HTTPException(400, "Recipient hasn't activated their BOMPAY account yet")
    if str(receiver_wallet["user_id"]) == user["_id"]:
        raise HTTPException(400, "Cannot transfer to yourself")

    # ─── Duplicate transfer guard (100-second window) ───
    cutoff_bompay = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    dup_bompay = await db.transactions.find_one({
        "user_id": user["_id"],
        "type": "BOMPAY_INTERNAL_TRANSFER",
        "amount": int(req.amount * 100),
        "metadata.sh_account_number": receiver_wallet["sh_account_number"],
        "created_at": {"$gte": cutoff_bompay}
    })
    if dup_bompay:
        raise HTTPException(409, "Duplicate transfer detected. This same transfer was just made. Please wait a moment before trying again.")

    idem = req.idempotency_key or str(uuid.uuid4())
    existing = await db.transactions.find_one({"idempotency_key": idem})
    if existing:
        return {"transaction_id": existing["transaction_id"], "status": existing["status"]}

    amt = int(req.amount * 100)
    fee_ngn = await calculate_fee("BOMPAY_TRANSFER", req.amount)
    fee = int(fee_ngn * 100)
    total = amt + fee

    sender_wallet = await get_wallet(user["_id"])
    # PRIMARY: Live Safe Haven balance check
    sh_id = sender_wallet.get("sh_account_id")
    if not sh_id:
        raise HTTPException(400, "Safe Haven account not configured. Please complete KYC.")
    sh_balance = await get_sh_subaccount_balance(sh_id)
    if sh_balance * 100 < total:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{sh_balance:,.2f}")

    receiver_name = f"{receiver_doc.get('first_name','')} {receiver_doc.get('last_name','')}".strip().upper()
    txn_id = f"TXN{secrets.token_hex(12).upper()}"

    sender_sa_account = sender_wallet.get("sh_account_number") or sender_wallet.get("account_number", "")

    # Name enquiry on receiver
    name_enquiry_ref = txn_id
    try:
        ne_res = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": SAFEHAVEN_OWN_BANK_CODE,
            "accountNumber": receiver_wallet["sh_account_number"]
        })
        ne_data = ne_res.get("data", {})
        name_enquiry_ref = ne_data.get("sessionId", txn_id)
        if ne_data.get("accountName"):
            receiver_name = ne_data["accountName"]
    except Exception as ne_err:
        logger.warning(f"[BompayTransfer] name enquiry failed: {ne_err}")

    # PRIMARY: Execute Safe Haven transfer (blocking, SH is the gate)
    try:
        pr = await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": name_enquiry_ref,
            "debitAccountNumber": sender_sa_account,
            "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
            "beneficiaryAccountNumber": receiver_wallet["sh_account_number"],
            "amount": req.amount,
            "saveBeneficiary": False,
            "narration": req.narration or f"BOMPAY Transfer from {user['first_name']}",
            "paymentReference": txn_id
        })
    except Exception as e:
        raise HTTPException(502, f"Transfer failed. Please try again. ({e})")

    pdata = pr.get("data", {})
    provider_ref = pdata.get("transactionReference", txn_id)

    # Record sender DEBIT transaction
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": idem, "user_id": user["_id"],
        "type": "BOMPAY_INTERNAL_TRANSFER", "direction": "DEBIT", "amount": amt, "fee": fee,
        "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "SAFEHAVEN",
        "description": f"BOMPAY Transfer to {receiver_name}",
        "metadata": {
            "sh_account_number": receiver_wallet["sh_account_number"],
            "beneficiary_name": receiver_name, "narration": req.narration,
            "receiver_user_id": str(receiver_wallet["user_id"])
        },
        "balance_before_kobo": int(sh_balance * 100),
        "balance_after_kobo":  int(sh_balance * 100) - total,
        "provider_reference": provider_ref,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })

    # SHADOW: Debit sender BOMPAY wallet mirror
    asyncio.create_task(db.wallets.update_one(
        {"user_id": user["_id"]},
        {"$inc": {"available_balance": -total, "ledger_balance": -total}}
    ))

    # Credit receiver BOMPAY wallet mirror (SH already credited via transfer)
    credit_txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": credit_txn_id,
        "user_id": str(receiver_wallet["user_id"]),
        "type": "BOMPAY_INTERNAL_TRANSFER", "direction": "CREDIT", "amount": amt,
        "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
        "provider": "SAFEHAVEN",
        "description": f"BOMPAY Transfer from {user['first_name']} {user.get('last_name','')}".strip(),
        "provider_reference": provider_ref,
        "metadata": {"sender_user_id": user["_id"],
                     "sender_name": f"{user['first_name']} {user.get('last_name','')}".strip()},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })
    asyncio.create_task(db.wallets.update_one(
        {"user_id": str(receiver_wallet["user_id"])},
        {"$inc": {"available_balance": amt, "ledger_balance": amt}}
    ))

    # Fee income record
    if fee > 0:
        await db.transactions.insert_one({
            "transaction_id": f"FEE{txn_id}", "user_id": "PLATFORM",
            "type": "FEE_INCOME", "direction": "CREDIT", "amount": fee, "fee": 0,
            "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"BOMPAY transfer fee from {user['first_name']}",
            "metadata": {"source_txn": txn_id, "payer_id": user["_id"], "service": "BOMPAY_TRANSFER"},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        })
    sh_bompay_fee_ngn = float(pdata.get("fee") or pdata.get("charge") or 0)
    asyncio.create_task(_sweep_fee_margin(
        txn_id=txn_id, user_account=sender_sa_account,
        bompay_fee_ngn=fee_ngn, sh_fee_ngn=sh_bompay_fee_ngn, category="BOMPAY_TRANSFER_FEES"
    ))

    await notify(user["_id"], "Transfer Successful",
                 f"₦{req.amount:,.2f} sent to {receiver_name}.", "success")
    await notify(str(receiver_wallet["user_id"]), "Money Received",
                 f"₦{req.amount:,.2f} received from {user['first_name']}.", "success")
    await audit(user["_id"], "BOMPAY_INTERNAL_TRANSFER", "wallet",
                {"amount": req.amount, "receiver": receiver_name})
    asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "TRANSFER", f"BOMPAY transfer to {receiver_name}"))
    asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
    asyncio.create_task(_complete_epos_txn_bg(str(receiver_wallet["user_id"]), int(req.amount * 100), "BOMPAY"))

    return {
        "transaction_id": txn_id, "status": "COMPLETED",
        "amount": req.amount, "fee": fee / 100,
        "receiver_name": receiver_name,
        "provider_reference": provider_ref
    }

# ===== TRANSACTIONS =====

@router.get("/transfers/daily-usage")
async def get_daily_transfer_usage(request: Request):
    """Returns the user's daily transfer totals and their tier limits."""
    user = await get_current_user(request)
    uid = user["_id"]
    user_tier = user.get("kyc_tier", 0)
    tier_cfg = await db.kyc_tier_configs.find_one({"tier": user_tier}) or {}
    daily_limit = tier_cfg.get("daily_transfer_limit_naira", 0)
    single_limit = tier_cfg.get("single_transfer_limit_naira", 0)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    daily_agg = await db.transactions.aggregate([
        {"$match": {"user_id": uid, "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]}, "direction": "DEBIT", "status": {"$ne": "FAILED"}, "created_at": {"$gte": today_start}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    daily_used_kobo = daily_agg[0]["total"] if daily_agg else 0
    daily_used_naira = daily_used_kobo / 100
    return {
        "kyc_tier": user_tier,
        "daily_limit_naira": daily_limit,
        "single_limit_naira": single_limit,
        "daily_used_naira": round(daily_used_naira, 2),
        "daily_remaining_naira": max(0, round(daily_limit - daily_used_naira, 2)),
        "transfers_allowed": single_limit > 0,
    }

@router.get("/transfers/free-transfer-eligible")
async def get_free_transfer_eligible(request: Request):
    """Returns whether the current user has a free external transfer available today."""
    user = await get_current_user(request)
    ft_cfg = await db.free_transfer_config.find_one({}) or {}
    transfer_provider = await get_service_provider("TRANSFER")
    enabled = (
        transfer_provider != "STROWALLET"
        and bool(ft_cfg.get("enabled"))
        and int(ft_cfg.get("daily_free_count", 0)) > 0
        and bool(str(ft_cfg.get("refund_account_number", "")).strip())
    )
    if not enabled:
        return {"eligible": False, "remaining": 0, "daily_free_count": 0}
    daily_free_count = int(ft_cfg["daily_free_count"])
    used = await db.transactions.count_documents({
        "user_id": user["_id"], "type": "BANK_TRANSFER", "direction": "DEBIT",
        "status": {"$nin": ["FAILED", "PROCESSING"]},
        "free_transfer_used": True,
        "created_at": {"$gte": _get_wat_day_start_utc()},
    })
    remaining = max(0, daily_free_count - used)
    return {"eligible": remaining > 0, "remaining": remaining, "daily_free_count": daily_free_count}


@router.get("/transfers/fee-preview")
async def preview_transfer_fee(amount: float, request: Request):
    """User-facing fee preview for transfer confirmation screen."""
    await get_current_user(request)
    bompay_fee = await calculate_fee("TRANSFER", amount)       # NIP Commission
    stamp_duty = await calculate_stamp_duty(amount)            # NIP Stamp Duty
    sh_fee = await get_nip_fee(amount)
    margin = round(max(bompay_fee - sh_fee, 0.0), 2)
    return {
        "amount": amount,
        "fee": bompay_fee,            # NIP Commission (shown on preview)
        "stamp_duty": stamp_duty,     # NIP Stamp Duty (shown on preview if > 0)
        "total": amount + bompay_fee + stamp_duty,
        "sh_fee": sh_fee,
        "bompay_margin": margin
    }


@router.get("/transfers/bank-health")
async def user_bank_health(bank_code: str, request: Request):
    """Consumer-facing bank health check based on recent transfer outcomes."""
    await get_current_user(request)
    cfg = await db.bank_network_config.find_one({}) or {}
    threshold = int(cfg.get("failure_threshold", 3))
    window = int(cfg.get("time_window_hours", 2))
    mode = cfg.get("mode", "warn")

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat()
    failures = await db.bank_health_events.count_documents({
        "bank_code": bank_code, "event_type": "TRANSFER_FAILED", "created_at": {"$gte": cutoff}
    })
    successes = await db.bank_health_events.count_documents({
        "bank_code": bank_code, "event_type": "TRANSFER_SUCCESS", "created_at": {"$gte": cutoff}
    })
    total = failures + successes
    health_pct = round(successes / total * 100, 1) if total > 0 else 100.0
    is_flagged = failures >= threshold

    return {
        "bank_code": bank_code,
        "failures": failures,
        "successes": successes,
        "health_pct": health_pct,
        "is_flagged": is_flagged,
        "mode": mode,
        "threshold": threshold,
        "window_hours": window,
    }

# ===== CDH PLANS & VALIDATION =====
