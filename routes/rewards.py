"""Bompay — Rewards routes."""
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
    get_rewards_config,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/rewards")
async def get_rewards(request: Request):
    user = await get_current_user(request)
    full = await db.users.find_one({"_id": ObjectId(user["_id"])})
    cashback_kobo = (full or {}).get("cashback_balance", 0)
    referral_kobo = (full or {}).get("referral_balance", 0)
    cfg = await get_rewards_config()
    cashback_hist = await db.cashback_history.find({"user_id": user["_id"]}, {"_id": 0}).sort("created_at", -1).to_list(30)
    referral_hist = await db.referral_history.find({"user_id": user["_id"]}, {"_id": 0}).sort("created_at", -1).to_list(20)
    referral_count = await db.referral_history.count_documents({"user_id": user["_id"], "role": "REFERRER"})
    return {
        "cashback_balance": round(cashback_kobo / 100, 2),
        "referral_balance": round(referral_kobo / 100, 2),
        "referral_code": (full or {}).get("referral_code", ""),
        "referral_count": referral_count,
        "cashback_history": cashback_hist,
        "referral_history": referral_hist,
        "config": {
            "cashback_enabled": cfg.get("cashback_enabled", True),
            "referral_enabled": cfg.get("referral_enabled", True),
            "airtime_cashback_pct": cfg.get("airtime_cashback_pct", 1.5),
            "data_cashback_pct": cfg.get("data_cashback_pct", 1.5),
            "electricity_cashback_pct": cfg.get("electricity_cashback_pct", 1.0),
            "cable_cashback_pct": cfg.get("cable_cashback_pct", 1.0),
            "betting_cashback_pct": cfg.get("betting_cashback_pct", 0.5),
            "referral_bonus_referrer_naira": cfg.get("referral_bonus_referrer_naira", 500),
            "referral_bonus_referee_naira": cfg.get("referral_bonus_referee_naira", 500),
        }
    }

@router.post("/rewards/withdraw-cashback")
async def withdraw_cashback(request: Request):
    user = await get_current_user(request)
    full = await db.users.find_one({"_id": ObjectId(user["_id"])})
    kobo = (full or {}).get("cashback_balance", 0)
    if kobo < 100:
        raise HTTPException(400, "Minimum withdrawal is ₦1.00")
    naira = round(kobo / 100, 2)
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {"cashback_balance": 0}})
    await db.wallets.update_one({"user_id": user["_id"]}, {"$inc": {"available_balance": kobo, "ledger_balance": kobo}})
    txn_id = str(uuid.uuid4())
    await db.transactions.insert_one({
        "user_id": user["_id"], "transaction_id": txn_id, "type": "CASHBACK_WITHDRAWAL",
        "direction": "CREDIT", "amount": kobo, "status": "COMPLETED",
        "description": f"Cashback withdrawal — ₦{naira:,.2f}",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await db.cashback_history.insert_one({
        "user_id": user["_id"], "amount_kobo": -kobo, "type": "WITHDRAWAL",
        "description": "Cashback withdrawn to wallet", "cashback_naira": -naira,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await notify(user["_id"], "Cashback Withdrawn!", f"₦{naira:,.2f} moved to your wallet", "success")
    return {"message": f"₦{naira:,.2f} moved to wallet!", "amount": naira}

@router.post("/rewards/withdraw-referral")
async def withdraw_referral(request: Request):
    user = await get_current_user(request)
    full = await db.users.find_one({"_id": ObjectId(user["_id"])})
    kobo = (full or {}).get("referral_balance", 0)
    if kobo < 100:
        raise HTTPException(400, "Minimum withdrawal is ₦1.00")
    naira = round(kobo / 100, 2)
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {"referral_balance": 0}})
    await db.wallets.update_one({"user_id": user["_id"]}, {"$inc": {"available_balance": kobo, "ledger_balance": kobo}})
    txn_id = str(uuid.uuid4())
    await db.transactions.insert_one({
        "user_id": user["_id"], "transaction_id": txn_id, "type": "REFERRAL_WITHDRAWAL",
        "direction": "CREDIT", "amount": kobo, "status": "COMPLETED",
        "description": f"Referral bonus withdrawal — ₦{naira:,.2f}",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await db.referral_history.insert_one({
        "user_id": user["_id"], "role": "WITHDRAWAL", "amount_kobo": -kobo,
        "description": "Referral bonus withdrawn to wallet",
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await notify(user["_id"], "Referral Bonus Withdrawn!", f"₦{naira:,.2f} moved to your wallet", "success")
    return {"message": f"₦{naira:,.2f} moved to wallet!", "amount": naira}

# ===== NOTIFICATIONS =====
