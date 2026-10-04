"""Bompay — Wallet & KYC routes."""
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
    require_virtual_account,
    KYCInitiateReq,
    KYCCreateAccountReq,
    get_sh_subaccount_balance,
    FundReq,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/wallet")
async def get_wallet_balance(request: Request):
    user = await get_current_user(request)
    w = await get_wallet(user["_id"])
    is_admin = user.get("role") == "admin"

    # ── PRIMARY: Live Safe Haven balance ──────────────────────────────────────
    sh_id = w.get("sh_account_id")
    sh_balance_ngn = w["available_balance"] / 100  # fallback (shadow)
    if sh_id:
        try:
            sh_balance_ngn = await get_sh_subaccount_balance(sh_id)
        except Exception as e:
            logger.warning(f"[Wallet] SH balance fetch failed for {user['_id']}: {e}")
            # Serve shadow balance if SH is unreachable

    return {
        "account_number": w.get("sh_account_number") or w["account_number"],
        "account_name": w.get("sh_account_name") or f"{user.get('first_name','')} {user.get('last_name','')}".strip().upper(),
        "has_virtual_account": is_admin or bool(w.get("sh_account_number")),
        "sh_account_id": w.get("sh_account_id"),
        "available_balance": sh_balance_ngn,          # Live SH balance (Naira)
        "ledger_balance":    sh_balance_ngn,           # Mirror for UI consistency
        "pending_balance":   w["pending_balance"] / 100,
        "held_balance":      w["held_balance"] / 100,
        "currency": "NGN", "status": w["status"], "tier": w["tier"],
    }

@router.post("/wallet/fund")
async def fund_wallet(req: FundReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    if req.amount <= 0 or req.amount > 1_000_000:
        raise HTTPException(400, "Invalid amount. Max: ₦1,000,000")
    idem = req.idempotency_key or str(uuid.uuid4())
    existing = await db.transactions.find_one({"idempotency_key": idem})
    if existing:
        return {"transaction_id": existing["transaction_id"], "status": existing["status"]}
    amt = int(req.amount * 100)
    w_before = await get_wallet(user["_id"])
    bal_before = w_before["available_balance"]
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": idem, "user_id": user["_id"],
        "type": "WALLET_FUNDING", "direction": "CREDIT", "amount": amt,
        "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
        "provider": "DEMO", "description": f"Wallet funding — ₦{req.amount:,.2f}",
        "metadata": {},
        "balance_before_kobo": bal_before,
        "balance_after_kobo": bal_before + amt,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })
    await db.wallets.update_one({"user_id": user["_id"]},
        {"$inc": {"available_balance": amt, "ledger_balance": amt}})
    w = await get_wallet(user["_id"])
    await ledger_entry(user["_id"], w["_id"], txn_id, "CREDIT", amt, "Wallet funding")
    # Mirror to PostgreSQL immutable ledger
    try:
        await pg_ledger.record_wallet_funding(
            user_id=user["_id"], user_name=f"{user['first_name']} {user['last_name']}",
            amount_ngn=req.amount, reference=txn_id, mongo_txn_id=txn_id
        )
    except Exception as le:
        logger.error(f"[Ledger] wallet_funding mirror failed: {le}")
    pts = int(req.amount * 0.5)
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$inc": {"reward_points": pts}})
    await notify(user["_id"], "Wallet Funded", f"₦{req.amount:,.2f} added to your wallet.", "success")
    await audit(user["_id"], "FUND_WALLET", "wallet", {"amount": req.amount, "txn_id": txn_id})
    return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount}

# ===== KYC / VIRTUAL ACCOUNT =====
@router.get("/kyc/status")
async def kyc_status(request: Request):
    user = await get_current_user(request)
    w = await db.wallets.find_one({"user_id": user["_id"]})
    has_va = bool((w or {}).get("sh_account_number"))
    return {
        "has_virtual_account": has_va,
        "account_number": (w or {}).get("sh_account_number"),
        "account_name": (w or {}).get("sh_account_name"),
        "sh_account_id": (w or {}).get("sh_account_id"),
    }

@router.post("/kyc/initiate")
async def kyc_initiate(req: KYCInitiateReq, request: Request):
    user = await get_current_user(request)
    w = await db.wallets.find_one({"user_id": user["_id"]})
    if (w or {}).get("sh_account_number"):
        raise HTTPException(400, "Virtual account already created for this account.")
    if req.identity_type not in ("BVN", "NIN"):
        raise HTTPException(400, "Identity type must be BVN or NIN")
    if not re.match(r"^\d{11}$", req.identity_number.strip()):
        raise HTTPException(400, f"{req.identity_type} must be exactly 11 digits")
    # Get platform account number for debit fee
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    platform_acct = (settings or {}).get("account_number", "").strip()
    is_live = bool((settings or {}).get("client_id", "").strip())
    # In live mode, debitAccountNumber is required by Safe Haven to charge the ₦50 identity verification fee.
    # Without it, Safe Haven returns 400 Bad Request.
    if is_live and not platform_acct:
        raise HTTPException(400, "PLATFORM_ACCOUNT_NOT_CONFIGURED: Your BOMPAY Platform Account Number is not set. Go to Console → Providers → Platform Account Number and enter BOMPAY's main Safe Haven account number, then try again.")
    try:
        body = {
            "type": req.identity_type,
            "number": req.identity_number.strip(),
            "async": False
        }
        if platform_acct:
            body["debitAccountNumber"] = platform_acct
        r = await call_sh("POST", "/identity/v2", body=body)
    except Exception as e:
        raise HTTPException(400, f"Identity verification failed: {e}")
    data = r.get("data") or {}
    identity_id = data.get("_id")
    if not identity_id:
        msg = r.get("message") or "Identity verification returned no ID. Check BVN/NIN number and Safe Haven credentials."
        raise HTTPException(400, msg)
    # Store identity_id temporarily on user profile
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {
        "kyc_identity_id": identity_id,
        "kyc_identity_type": req.identity_type,
        "kyc_identity_number": req.identity_number.strip()
    }})
    return {"message": f"OTP sent to your {req.identity_type}-registered phone number. Enter it below.", "identity_id": identity_id}

# Admin helper: fetch platform's own Safe Haven accounts so admin can pick the account number
@router.get("/admin/safehaven/accounts")
async def admin_sh_accounts(request: Request):
    await get_admin_user(request)
    try:
        r = await call_sh("GET", "/accounts")
        accounts = r.get("data", [])
        if isinstance(accounts, dict):
            accounts = [accounts]
        return {"accounts": [
            {"account_number": a.get("accountNumber", ""), "account_name": a.get("accountName", ""),
             "balance": a.get("accountBalance", 0), "status": a.get("status", "")}
            for a in accounts if isinstance(a, dict)
        ]}
    except Exception as e:
        raise HTTPException(400, f"Could not fetch Safe Haven accounts: {e}")

@router.post("/kyc/create-account")
async def kyc_create_account(req: KYCCreateAccountReq, request: Request):
    user = await get_current_user(request)
    w = await db.wallets.find_one({"user_id": user["_id"]})
    if (w or {}).get("sh_account_number"):
        raise HTTPException(400, "Virtual account already created for this account.")
    if req.identity_type not in ("BVN", "NIN"):
        raise HTTPException(400, "Identity type must be BVN or NIN")
    if not re.match(r"^\d{11}$", req.identity_number.strip()):
        raise HTTPException(400, f"{req.identity_type} must be exactly 11 digits")
    # Basic date-of-birth validation (YYYY-MM-DD)
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", req.date_of_birth.strip()):
        raise HTTPException(400, "Date of birth must be in YYYY-MM-DD format")

    _base = (os.environ.get("WEBHOOK_BASE_URL") or os.environ.get("API_BASE_URL") or "").rstrip("/")
    callback_url = f"{_base}/api/webhooks/safehaven"
    phone = user.get("phone", "")
    if phone and not phone.startswith("+"):
        phone = "+234" + phone.lstrip("0") if phone.startswith("0") else "+" + phone

    # ── BVN Indemnity flow — single step, no OTP required ──────────────────
    try:
        r = await call_sh("POST", "/accounts/subaccount", body={
            "phoneNumber": phone,
            "emailAddress": user.get("email", ""),
            "externalReference": user["_id"],
            "identityType": req.identity_type,
            "identityNumber": req.identity_number.strip(),
            "dateOfBirth": req.date_of_birth.strip(),
            "booleanMatch": True,
            "autoSweep": False,
            "callbackUrl": callback_url,
        })
    except Exception as e:
        raise HTTPException(400, f"Account creation failed: {e}")

    data = r.get("data") or {}
    acct_num  = data.get("accountNumber")
    acct_name = data.get("accountName")
    sh_id     = data.get("_id") or data.get("id") or ""
    if not acct_num:
        msg = r.get("message") or "Account creation failed. Check your BVN/NIN and date of birth."
        raise HTTPException(400, msg)

    # Update wallet with Safe Haven account details
    await db.wallets.update_one({"user_id": user["_id"]}, {"$set": {
        "sh_account_id": sh_id,
        "sh_account_number": acct_num,
        "sh_account_name": acct_name,
        "account_number": acct_num,
    }})
    # Update user's legal name from Safe Haven KYC
    if acct_name:
        clean_name = acct_name.strip()
        if " / " in clean_name:
            clean_name = clean_name.split(" / ", 1)[1].strip()
        parts = clean_name.split()
        if len(parts) >= 2:
            await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {
                "first_name": parts[0].capitalize(),
                "last_name": " ".join(parts[1:]).capitalize(),
                "kyc_verified_name": acct_name,
            }})
    # Set KYC Tier 1 and persist identity fields for later use (cards, loans, etc.)
    identity_update: dict = {"kyc_tier": 1, "kyc_status": "VERIFIED", "date_of_birth": req.date_of_birth.strip()}
    if req.identity_type == "NIN":
        identity_update["nin"] = req.identity_number.strip()
    else:
        identity_update["bvn"] = req.identity_number.strip()
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": identity_update})
    # Persist identity_id from SH response to kyc_records for later use (business accounts)
    if sh_id:
        await db.kyc_records.update_one(
            {"user_id": str(user["_id"])},
            {"$set": {"identity_id": sh_id}},
            upsert=True,
        )
    await notify(user["_id"], "Account Activated!",
                 f"Your virtual account number is {acct_num}. You can now receive and send money.", "success")
    await audit(user["_id"], "CREATE_VIRTUAL_ACCOUNT", "wallet", {"account_number": acct_num})
    return {
        "account_number": acct_num,
        "account_name": acct_name,
        "message": "Virtual account created successfully! Your account number is ready.",
    }

@router.get("/kyc/subaccount-balance")
async def subaccount_balance(request: Request):
    """Live sub-account balance from Safe Haven."""
    user = await get_current_user(request)
    w = await db.wallets.find_one({"user_id": user["_id"]})
    sh_id = (w or {}).get("sh_account_id")
    if not sh_id:
        raise HTTPException(404, "No virtual account found")
    balance = await get_sh_subaccount_balance(sh_id)
    return {"balance": balance, "account_number": (w or {}).get("sh_account_number")}

# ===== TRANSFERS =====

@router.get("/wallet/paystack/public-key")
async def paystack_public_key(request: Request):
    await get_current_user(request)
    doc = await db.admin_settings.find_one({"key": "paystack"})
    return {
        "public_key": (doc or {}).get("public_key", ""),
        "configured": bool((doc or {}).get("secret_key")),
    }

# ── Paystack: User — initialize transaction ────────────────────────
@router.post("/wallet/paystack/init")
async def paystack_init(request: Request):
    user = await get_current_user(request)
    body = await request.json()
    amount = float(body.get("amount", 100))
    if amount < 100:
        raise HTTPException(400, "Minimum amount is ₦100")
    doc = await db.admin_settings.find_one({"key": "paystack"})
    secret_key = (doc or {}).get("secret_key", "")
    if not secret_key:
        raise HTTPException(400, "Card payment is not configured. Please contact support.")
    email = user.get("email") or f"user_{user['_id']}@bompay.ng"
    ref = f"BOMPAY_{secrets.token_hex(10).upper()}"
    amount_kobo = int(amount * 100)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            "https://api.paystack.co/transaction/initialize",
            headers={"Authorization": f"Bearer {secret_key}", "Content-Type": "application/json"},
            json={"email": email, "amount": amount_kobo, "reference": ref,
                  "metadata": {"user_id": str(user["_id"]), "purpose": body.get("purpose", "card_binding")}},
        )
    if r.status_code != 200:
        raise HTTPException(400, "Payment initialization failed. Please try again.")
    d = r.json()["data"]
    return {"reference": d["reference"], "authorization_url": d["authorization_url"], "access_code": d["access_code"]}

# ── Paystack: User — verify payment + store card token ────────────
@router.post("/wallet/paystack/verify")
async def paystack_verify(request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    body = await request.json()
    reference = body.get("reference", "")
    purpose = body.get("purpose", "card_binding")
    if not reference:
        raise HTTPException(400, "Reference is required")
    # Idempotency — don't double-credit
    if await db.transactions.find_one({"idempotency_key": reference}):
        return {"success": True, "already_processed": True}
    doc = await db.admin_settings.find_one({"key": "paystack"})
    secret_key = (doc or {}).get("secret_key", "")
    if not secret_key:
        raise HTTPException(400, "Payment gateway not configured")
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"https://api.paystack.co/transaction/verify/{reference}",
                        headers={"Authorization": f"Bearer {secret_key}"})
    if r.status_code != 200:
        raise HTTPException(400, "Payment verification failed")
    data = r.json()["data"]
    if data["status"] != "success":
        raise HTTPException(400, f"Payment {data['status']}")
    auth = data.get("authorization", {})
    amount_paid_ngn = data["amount"] / 100
    # Store card token if reusable
    if auth.get("reusable") and auth.get("authorization_code"):
        if not await db.saved_cards.find_one({"user_id": uid, "authorization_code": auth["authorization_code"]}):
            await db.saved_cards.insert_one({
                "user_id": uid,
                "authorization_code": auth["authorization_code"],
                "card_type": auth.get("card_type", ""),
                "last4": auth.get("last4", ""),
                "exp_month": auth.get("exp_month", ""),
                "exp_year": auth.get("exp_year", ""),
                "bank": auth.get("bank", ""),
                "email": data.get("customer", {}).get("email", ""),
                "added_at": datetime.now(timezone.utc).isoformat(),
            })
    # Credit wallet
    if purpose in ("card_binding", "fund"):
        amt = int(amount_paid_ngn * 100)
        txn_id = f"TXN{secrets.token_hex(12).upper()}"
        now = datetime.now(timezone.utc).isoformat()
        await db.transactions.insert_one({
            "transaction_id": txn_id, "idempotency_key": reference,
            "user_id": uid, "type": "WALLET_FUNDING", "direction": "CREDIT",
            "amount": amt, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
            "provider": "PAYSTACK",
            "description": f"Card funding — ₦{amount_paid_ngn:,.2f} (•••• {auth.get('last4','')})",
            "metadata": {"reference": reference, "card_last4": auth.get("last4", "")},
            "created_at": now, "updated_at": now,
        })
        await db.wallets.update_one({"user_id": uid}, {"$inc": {"available_balance": amt, "ledger_balance": amt}})
        await notify(uid, "Wallet Funded", f"₦{amount_paid_ngn:,.2f} added via card •••• {auth.get('last4','')}", "success")
    return {"success": True, "amount": amount_paid_ngn,
            "card": {"last4": auth.get("last4",""), "card_type": auth.get("card_type",""), "bank": auth.get("bank","")}}

# ── Paystack: User — list saved cards ─────────────────────────────
@router.get("/wallet/saved-cards")
async def get_saved_cards(request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    cards = await db.saved_cards.find({"user_id": uid}).sort("added_at", -1).to_list(20)
    return {"cards": [
        {"id": str(c["_id"]), "last4": c["last4"], "card_type": c["card_type"],
         "bank": c["bank"], "exp_month": c["exp_month"], "exp_year": c["exp_year"],
         "added_at": c["added_at"]}
        for c in cards
    ]}

# ── Paystack: User — delete saved card ────────────────────────────
@router.delete("/wallet/saved-cards/{card_id}")
async def delete_saved_card(card_id: str, request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    try:
        await db.saved_cards.delete_one({"_id": ObjectId(card_id), "user_id": uid})
    except Exception:
        raise HTTPException(404, "Card not found")
    return {"success": True}

# ── Paystack: User — charge saved card to fund wallet ─────────────
@router.post("/wallet/paystack/charge-card")
async def paystack_charge_card(request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    body = await request.json()
    card_id = body.get("card_id", "")
    amount = float(body.get("amount", 0))
    if amount < 100:
        raise HTTPException(400, "Minimum funding amount is ₦100")
    try:
        card = await db.saved_cards.find_one({"_id": ObjectId(card_id), "user_id": uid})
    except Exception:
        raise HTTPException(404, "Card not found")
    if not card:
        raise HTTPException(404, "Card not found")
    doc = await db.admin_settings.find_one({"key": "paystack"})
    secret_key = (doc or {}).get("secret_key", "")
    if not secret_key:
        raise HTTPException(400, "Payment gateway not configured")
    email = card.get("email") or user.get("email") or f"user_{uid}@bompay.ng"
    ref = f"BOMPAY_{secrets.token_hex(10).upper()}"
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            "https://api.paystack.co/transaction/charge_authorization",
            headers={"Authorization": f"Bearer {secret_key}", "Content-Type": "application/json"},
            json={"authorization_code": card["authorization_code"], "email": email,
                  "amount": int(amount * 100), "reference": ref,
                  "metadata": {"user_id": uid, "purpose": "wallet_funding"}},
        )
    d = r.json()
    if r.status_code != 200 or not d.get("status"):
        raise HTTPException(400, d.get("message", "Card charge failed"))
    charge_data = d["data"]
    if charge_data["status"] != "success":
        raise HTTPException(400, f"Charge failed: {charge_data.get('gateway_response','')}")
    amt = int(amount * 100)
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    now = datetime.now(timezone.utc).isoformat()
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": ref,
        "user_id": uid, "type": "WALLET_FUNDING", "direction": "CREDIT",
        "amount": amt, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
        "provider": "PAYSTACK",
        "description": f"Card funding — ₦{amount:,.2f} (•••• {card.get('last4','')})",
        "metadata": {"reference": ref, "card_last4": card.get("last4", "")},
        "created_at": now, "updated_at": now,
    })
    await db.wallets.update_one({"user_id": uid}, {"$inc": {"available_balance": amt, "ledger_balance": amt}})
    await notify(uid, "Wallet Funded", f"₦{amount:,.2f} added via card •••• {card.get('last4','')}", "success")
    return {"success": True, "amount": amount, "transaction_id": txn_id}


# ── Admin: Balance Accounts ───────────────────────────────────────────────────
