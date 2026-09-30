"""Bompay — ePOS & Waitlist routes."""
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
    EposActivateReq, BaseModel,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/epos/activate")
async def epos_activate(req: EposActivateReq, request: Request):
    user = await get_current_user(request)
    existing = await db.epos_accounts.find_one({"user_id": user["_id"]})
    if existing:
        await db.epos_accounts.update_one(
            {"user_id": user["_id"]},
            {"$set": {"business_name": req.business_name, "business_type": req.business_type}}
        )
        return {"message": "e-POS account updated", "activated": True}
    await db.epos_accounts.insert_one({
        "user_id": user["_id"], "business_name": req.business_name,
        "business_type": req.business_type, "status": "ACTIVE",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"message": "e-POS activated successfully!", "activated": True}

@router.get("/epos/status")
async def epos_status(request: Request):
    user = await get_current_user(request)
    acct = await db.epos_accounts.find_one({"user_id": user["_id"]}, {"_id": 0})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_agg = await db.epos_transactions.aggregate([
        {"$match": {"merchant_user_id": user["_id"], "status": "COMPLETED", "created_at": {"$gte": today}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
    ]).to_list(1)
    today_stats = today_agg[0] if today_agg else {"total": 0, "count": 0}
    return {
        "activated": acct is not None,
        "account": acct,
        "today_received_naira": round(today_stats["total"] / 100, 2),
        "today_count": today_stats["count"],
    }

class EposRequestPayment(BaseModel):
    amount: float
    note: Optional[str] = ""

@router.post("/epos/request-payment")
async def epos_request_payment(req: EposRequestPayment, request: Request):
    user = await get_current_user(request)
    acct = await db.epos_accounts.find_one({"user_id": user["_id"]})
    if not acct:
        raise HTTPException(400, "Activate your e-POS account first")
    if req.amount < 1:
        raise HTTPException(400, "Minimum amount is ₦1.00")
    ref = str(uuid.uuid4())[:12].upper()
    await db.epos_transactions.insert_one({
        "merchant_user_id": user["_id"], "business_name": acct["business_name"],
        "amount_kobo": int(req.amount * 100), "note": req.note,
        "reference": ref, "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    wallet = await db.wallets.find_one({"user_id": user["_id"]})
    return {
        "reference": ref,
        "amount": req.amount,
        "merchant_name": acct["business_name"],
        "account_number": wallet.get("virtual_account_number") if wallet else None,
        "bank_name": wallet.get("virtual_bank_name") if wallet else None,
        "qr_data": f"bompay://pay?to={user['_id']}&amount={int(req.amount*100)}&ref={ref}&name={acct['business_name']}",
        "expires_at": (datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
    }

class EposPayQrReq(BaseModel):
    merchant_user_id: str
    amount_kobo: int
    reference: str
    pin: str

@router.post("/epos/pay-qr")
async def epos_pay_qr(req: EposPayQrReq, request: Request):
    user = await get_current_user(request)
    if user["_id"] == req.merchant_user_id:
        raise HTTPException(400, "You cannot pay yourself")
    # Verify PIN
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"pin_hash": 1, "pin_failed_attempts": 1, "pin_locked_until": 1})
    if not doc or not doc.get("pin_hash"):
        raise HTTPException(400, "Set a transaction PIN first")
    locked_until = doc.get("pin_locked_until")
    if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
        raise HTTPException(403, "PIN locked. Try again later")
    if not verify_pin_hash(req.pin, doc["pin_hash"]):
        fails = (doc.get("pin_failed_attempts") or 0) + 1
        upd = {"pin_failed_attempts": fails}
        if fails >= 5:
            upd["pin_locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": upd})
        raise HTTPException(403, f"Wrong PIN. {5 - fails} attempt(s) remaining")
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {"pin_failed_attempts": 0}})
    # Check payer balance
    payer_wallet = await db.wallets.find_one({"user_id": user["_id"]})
    if not payer_wallet or payer_wallet.get("available_balance", 0) < req.amount_kobo:
        raise HTTPException(400, "Insufficient balance")
    # Verify ePOS transaction exists and is PENDING
    epos_txn = await db.epos_transactions.find_one({"merchant_user_id": req.merchant_user_id, "reference": req.reference, "status": "PENDING"})
    if not epos_txn:
        raise HTTPException(404, "Payment request not found or already completed")
    if epos_txn.get("amount_kobo") != req.amount_kobo:
        raise HTTPException(400, "Amount mismatch")
    # Debit payer
    await db.wallets.update_one({"user_id": user["_id"]}, {"$inc": {"available_balance": -req.amount_kobo, "ledger_balance": -req.amount_kobo}})
    # Credit merchant
    await db.wallets.update_one({"user_id": req.merchant_user_id}, {"$inc": {"available_balance": req.amount_kobo, "ledger_balance": req.amount_kobo}})
    # Record transactions
    naira = round(req.amount_kobo / 100, 2)
    txn_id = str(uuid.uuid4())
    merchant_acct = await db.epos_accounts.find_one({"user_id": req.merchant_user_id})
    merchant_name = merchant_acct.get("business_name", "Merchant") if merchant_acct else "Merchant"
    payer_name = f"{user.get('first_name','')} {user.get('last_name','')}".strip()
    now = datetime.now(timezone.utc).isoformat()
    await db.transactions.insert_many([
        {"user_id": user["_id"], "transaction_id": txn_id, "type": "EPOS_PAYMENT",
         "direction": "DEBIT", "amount": req.amount_kobo, "status": "COMPLETED",
         "description": f"ePOS payment to {merchant_name}", "created_at": now},
        {"user_id": req.merchant_user_id, "transaction_id": txn_id + "_c", "type": "EPOS_RECEIPT",
         "direction": "CREDIT", "amount": req.amount_kobo, "status": "COMPLETED",
         "description": f"Payment from {payer_name}", "created_at": now},
    ])
    # Complete ePOS transaction
    await db.epos_transactions.update_one(
        {"merchant_user_id": req.merchant_user_id, "reference": req.reference},
        {"$set": {"status": "COMPLETED", "channel": "QR_BOMPAY", "payer_user_id": user["_id"], "completed_at": now}}
    )
    await notify(user["_id"], "Payment Sent!", f"₦{naira:,.2f} paid to {merchant_name}", "success")
    await notify(req.merchant_user_id, "Payment Received!", f"₦{naira:,.2f} from {payer_name}", "success")
    return {"message": f"₦{naira:,.2f} sent to {merchant_name}!", "amount": naira, "reference": req.reference}

@router.get("/epos/check/{reference}")
async def epos_check_status(reference: str, request: Request):
    """Poll endpoint for live payment status."""
    user = await get_current_user(request)
    txn = await db.epos_transactions.find_one(
        {"merchant_user_id": user["_id"], "reference": reference},
        {"_id": 0, "status": 1, "completed_at": 1, "channel": 1, "amount_kobo": 1}
    )
    if not txn:
        raise HTTPException(404, "Transaction not found")
    return txn

@router.post("/epos/complete/{reference}")
async def epos_manual_complete(reference: str, request: Request):
    """Merchant manually marks a transaction as completed (e.g. cash or external payment)."""
    user = await get_current_user(request)
    txn = await db.epos_transactions.find_one({"merchant_user_id": user["_id"], "reference": reference})
    if not txn:
        raise HTTPException(404, "Transaction not found")
    if txn.get("status") == "COMPLETED":
        return {"message": "Already completed"}
    await db.epos_transactions.update_one(
        {"merchant_user_id": user["_id"], "reference": reference},
        {"$set": {"status": "COMPLETED", "channel": "MANUAL", "completed_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "Transaction marked as completed"}

@router.get("/epos/transactions")
async def epos_transactions(request: Request, page: int = 1, limit: int = 20):
    user = await get_current_user(request)
    skip = (page - 1) * limit
    txns = await db.epos_transactions.find(
        {"merchant_user_id": user["_id"]},
        {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.epos_transactions.count_documents({"merchant_user_id": user["_id"]})
    return {"transactions": txns, "total": total, "page": page}

@router.get("/epos/reports")
async def epos_reports(request: Request):
    """Returns daily (7 days) and weekly (4 weeks) ePOS sales summaries."""
    user = await get_current_user(request)
    from datetime import timezone as _tz
    now = datetime.now(timezone.utc)
    # Daily: last 7 days
    daily = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        label = day_start.strftime("%a")
        count = await db.epos_transactions.count_documents({
            "merchant_user_id": {"$in": [user["_id"], str(user["_id"])]}, "status": "COMPLETED",
            "created_at": {"$gte": day_start.isoformat(), "$lt": day_end.isoformat()}
        })
        agg = await db.epos_transactions.aggregate([
            {"$match": {"merchant_user_id": {"$in": [user["_id"], str(user["_id"])]}, "status": "COMPLETED",
                        "created_at": {"$gte": day_start.isoformat(), "$lt": day_end.isoformat()}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}}
        ]).to_list(1)
        total_kobo = (agg[0]["total"] if agg else 0)
        daily.append({"label": label, "amount": round(total_kobo / 100, 2), "count": count})
    # Weekly: last 4 weeks
    weekly = []
    for i in range(3, -1, -1):
        week_start = (now - timedelta(weeks=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        week_start -= timedelta(days=week_start.weekday())
        week_end = week_start + timedelta(weeks=1)
        label = f"Wk {4 - i}"
        count = await db.epos_transactions.count_documents({
            "merchant_user_id": {"$in": [user["_id"], str(user["_id"])]}, "status": "COMPLETED",
            "created_at": {"$gte": week_start.isoformat(), "$lt": week_end.isoformat()}
        })
        agg = await db.epos_transactions.aggregate([
            {"$match": {"merchant_user_id": {"$in": [user["_id"], str(user["_id"])]}, "status": "COMPLETED",
                        "created_at": {"$gte": week_start.isoformat(), "$lt": week_end.isoformat()}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}}
        ]).to_list(1)
        total_kobo = (agg[0]["total"] if agg else 0)
        weekly.append({"label": label, "amount": round(total_kobo / 100, 2), "count": count})
    return {"daily": daily, "weekly": weekly}


class WaitlistJoinReq(BaseModel):
    type: str  # "CARDS" or "BUSINESS"
    name: Optional[str] = ""
    phone: Optional[str] = ""
    reason: Optional[str] = ""
    business_name: Optional[str] = ""

@router.post("/waitlist/join")
async def waitlist_join(req: WaitlistJoinReq, request: Request):
    user = await get_current_user(request)
    if req.type not in ["CARDS", "BUSINESS"]:
        raise HTTPException(400, "Invalid waitlist type")
    existing = await db.waitlists.find_one({"user_id": user["_id"], "type": req.type})
    if existing:
        return {"message": "You are already on the waitlist!", "position": existing.get("position", 0)}
    count = await db.waitlists.count_documents({"type": req.type}) + 1
    await db.waitlists.insert_one({
        "user_id": user["_id"], "type": req.type, "name": req.name,
        "phone": req.phone, "reason": req.reason,
        "business_name": req.business_name,
        "position": count, "status": "WAITING",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await notify(user["_id"], "Waitlist Joined!", f"You are #{ count } on the {req.type.title()} waitlist. We'll notify you when a spot opens!", "success")
    return {"message": f"You joined the {req.type.title()} waitlist!", "position": count}

@router.get("/waitlist/status")
async def waitlist_status(request: Request):
    user = await get_current_user(request)
    cards = await db.waitlists.find_one({"user_id": user["_id"], "type": "CARDS"}, {"_id": 0})
    business = await db.waitlists.find_one({"user_id": user["_id"], "type": "BUSINESS"}, {"_id": 0})
    return {
        "cards": {"joined": cards is not None, "position": cards.get("position") if cards else None, "status": cards.get("status") if cards else None},
        "business": {"joined": business is not None, "position": business.get("position") if business else None, "status": business.get("status") if business else None},
    }

# ===== ADMIN E-POS =====
@router.get("/admin/epos")
async def admin_list_epos(request: Request, page: int = 1, limit: int = 20):
    await get_admin_user(request)
    skip = (page - 1) * limit
    accounts = await db.epos_accounts.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.epos_accounts.count_documents({})
    for a in accounts:
        u = await db.users.find_one({"_id": ObjectId(a["user_id"])})
        if u:
            a["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            a["user_email"] = u.get("email", "")
        else:
            a["user_name"] = "Unknown"
            a["user_email"] = ""
        agg = await db.epos_transactions.aggregate([
            {"$match": {"merchant_user_id": a["user_id"], "status": "COMPLETED"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
        ]).to_list(1)
        a["total_received_naira"] = round((agg[0]["total"] if agg else 0) / 100, 2)
        a["txn_count"] = agg[0]["count"] if agg else 0
    return {"accounts": accounts, "total": total, "page": page}

@router.get("/admin/epos/{user_id}/transactions")
async def admin_epos_transactions(user_id: str, request: Request, page: int = 1, limit: int = 20):
    await get_admin_user(request)
    skip = (page - 1) * limit
    txns = await db.epos_transactions.find({"merchant_user_id": user_id}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.epos_transactions.count_documents({"merchant_user_id": user_id})
    return {"transactions": txns, "total": total, "page": page}

# ===== ADMIN WAITLIST =====
@router.get("/admin/waitlist")
async def admin_waitlist(request: Request, type: Optional[str] = None, page: int = 1, limit: int = 50):
    await get_admin_user(request)
    skip = (page - 1) * limit
    q = {}
    if type:
        q["type"] = type.upper()
    entries = await db.waitlists.find(q, {"_id": 0}).sort("created_at", 1).skip(skip).limit(limit).to_list(limit)
    for e in entries:
        u = await db.users.find_one({"_id": ObjectId(e["user_id"])})
        if u:
            e["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            e["user_email"] = u.get("email", "")
            e["user_phone"] = u.get("phone_number", "")
    total = await db.waitlists.count_documents(q)
    return {"entries": entries, "total": total, "page": page}

@router.put("/admin/waitlist/{user_id}/{type}")
async def admin_update_waitlist_status(user_id: str, type: str, request: Request):
    await get_admin_user(request)
    body = await request.json()
    new_status = body.get("status", "WAITING")
    await db.waitlists.update_one(
        {"user_id": user_id, "type": type.upper()},
        {"$set": {"status": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if new_status == "APPROVED":
        await notify(user_id, f"{type.title()} Access Approved!", f"Your {type.title()} waitlist application has been approved!", "success")
    return {"message": "Status updated"}
