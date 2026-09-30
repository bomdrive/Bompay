"""Bompay — shared configuration, constants, and utility helpers."""
from dotenv import load_dotenv
load_dotenv()
import os, uuid, secrets, logging, time, json, asyncio, hashlib
import re as _re
import ipaddress as _ipaddress
from html import escape as _escape
from html.parser import HTMLParser as _HTMLParser
from urllib.parse import urlparse as _urlparse
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from pathlib import Path
from bson import ObjectId
import bcrypt
import jwt as pyjwt
import httpx
import requests as _requests
import csv, io
from fpdf import FPDF
from pydantic import BaseModel, EmailStr

# FastAPI
from fastapi import HTTPException, Request, Response, UploadFile

# WebAuthn
from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
    base64url_to_bytes, options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, UserVerificationRequirement,
    ResidentKeyRequirement, AttestationConveyancePreference,
    AuthenticatorAttachment, PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse, RegistrationCredential,
    AuthenticatorAssertionResponse, AuthenticationCredential,
)
import cloudinary
import cloudinary.uploader

from database import db

logger = logging.getLogger(__name__)

# ===== CONFIG =====
JWT_SECRET = os.environ.get("JWT_SECRET", "bompay-secret-change-in-prod")
JWT_ALGORITHM = "HS256"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "percosoerp@gmail.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "BomPay@2024!")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://bompay-ledger.preview.emergentagent.com")
WEBHOOK_CRON_SECRET = os.environ.get("WEBHOOK_CRON_SECRET", "")
SAFEHAVEN_BASE_URL = os.environ.get("SAFEHAVEN_BASE_URL", "https://api.sandbox.safehavenmfb.com")
SAFEHAVEN_OWN_BANK_CODE = os.environ.get("SAFEHAVEN_BANK_CODE", "090286")  # Safe Haven MFB NIP bank code

CDH_BASE_URL = "https://www.cheapdatahub.ng/api/v1/resellers"
PAIRGATE_BASE_URL = "https://pairgate.com/api/v1"

# ===== CLOUDINARY IMAGE STORAGE =====
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
    secure=True
)
APP_NAME = "bompay"
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY_B64 = os.environ.get("VAPID_KEY_PATH", os.environ.get("VAPID_PRIVATE_KEY", ""))
VAPID_EMAIL = os.environ.get("VAPID_EMAIL", "mailto:admin@bompay.ng")
MIME_EXT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}
PROMO_IMG_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
PROMO_IMG_MAX = 2 * 1024 * 1024  # 2 MB

def _cloudinary_upload(data: bytes, public_id: str) -> str:
    """Upload raw bytes to Cloudinary. Returns the secure CDN URL."""
    result = cloudinary.uploader.upload(
        data,
        public_id=public_id,
        resource_type="image",
        overwrite=True,
        invalidate=True,
    )
    return result["secure_url"]

def _cloudinary_delete(public_id: str) -> None:
    cloudinary.uploader.destroy(public_id, resource_type="image", invalidate=True)

# PairGate electricity provider slugs (keyed by BOMPAY internal disco code)
PG_DISCO_SLUGS = {
    "IKEDC": "ikedc", "EKEDC": "eko", "PHEDC": "ph", "AEDC": "aedc",
    "BEDC": "benin", "EEDC": "enugu", "IBEDC": "ibedc", "KEDCO": "kedco",
    "KAEDC": "kaduna", "JEDC": "jedc", "ABA": "aba", "YEDC": "yola",
}
# PairGate bet slugs
PG_BET_SLUGS = {
    "BET9JA": "bet9ja", "SPORTYBET": "sportybet", "BETKING": "betking",
    "1XBET": "1xbet", "MSPORT": "msport", "BETWAY": "betway",
    "BANGBET": "bangbet", "NAIRABET": "nairabet", "NAIJABET": "naijabet",
    "MERRYBET": "merrybet-", "SUPABET": "supabet",
}
CDH_AIRTIME_NETWORK_IDS = {"MTN": 1, "GLO": 2, "AIRTEL": 3, "9MOBILE": 4}
CDH_ELECTRICITY_DISCO_IDS = {
    "IKEDC": 1, "AEDC": 2, "BEDC": 3, "EKEDC": 4, "EEDC": 5,
    "IBEDC": 6, "JEDC": 7, "KAEDCO": 8, "KAEDC": 9, "PHEDC": 10
}

# CDH verified plan IDs from https://www.cheapdatahub.ng/api/plan-ids/
CDH_DATA_PLANS = {
    "MTN": [
        {"id": 43, "name": "110MB", "validity": "1 Day", "amount": 99},
        {"id": 74, "name": "230MB", "validity": "1 Day", "amount": 200},
        {"id": 76, "name": "500MB SME", "validity": "2 Days", "amount": 250},
        {"id": 44, "name": "500MB", "validity": "30 Days", "amount": 300},
        {"id": 77, "name": "1GB SME", "validity": "2 Days", "amount": 399},
        {"id": 78, "name": "1GB Awoof", "validity": "30 Days", "amount": 430},
        {"id": 45, "name": "1GB SME", "validity": "7 Days", "amount": 450},
        {"id": 46, "name": "1GB SME", "validity": "30 Days", "amount": 570},
        {"id": 71, "name": "2GB", "validity": "7 Days", "amount": 900},
        {"id": 47, "name": "2GB SME", "validity": "7 Days", "amount": 930},
        {"id": 48, "name": "2GB SME", "validity": "30 Days", "amount": 1150},
        {"id": 49, "name": "3GB SME", "validity": "30 Days", "amount": 1370},
        {"id": 50, "name": "5GB SME", "validity": "30 Days", "amount": 2050},
        {"id": 53, "name": "6GB", "validity": "7 Days", "amount": 2495},
        {"id": 67, "name": "10GB", "validity": "30 Days", "amount": 4800},
        {"id": 57, "name": "36GB", "validity": "30 Days", "amount": 10900},
        {"id": 51, "name": "75GB SME", "validity": "30 Days", "amount": 17990},
    ],
    "GLO": [
        {"id": 42, "name": "200MB Corporate", "validity": "1 Day", "amount": 92},
        {"id": 35, "name": "500MB Corporate", "validity": "30 Days", "amount": 225},
        {"id": 84, "name": "1GB Awoof", "validity": "1 Day", "amount": 250},
        {"id": 68, "name": "1GB Corporate", "validity": "3 Days", "amount": 300},
        {"id": 36, "name": "1GB Corporate", "validity": "30 Days", "amount": 425},
        {"id": 41, "name": "1GB", "validity": "14 Days", "amount": 485},
        {"id": 40, "name": "2GB Corporate", "validity": "30 Days", "amount": 850},
        {"id": 37, "name": "3GB Corporate", "validity": "30 Days", "amount": 1300},
        {"id": 54, "name": "5GB Corporate", "validity": "7 Days", "amount": 1699},
        {"id": 38, "name": "5GB Corporate", "validity": "30 Days", "amount": 2250},
        {"id": 39, "name": "10GB Corporate", "validity": "30 Days", "amount": 4390},
        {"id": 59, "name": "20.5GB", "validity": "30 Days", "amount": 5300},
        {"id": 58, "name": "107GB", "validity": "30 Days", "amount": 19300},
    ],
    "AIRTEL": [
        {"id": 70, "name": "1GB Social (Gifting)", "validity": "3 Days", "amount": 295},
        {"id": 13, "name": "500MB Gifting", "validity": "7 Days", "amount": 490},
        {"id": 69, "name": "1.5GB Gifting", "validity": "1 Day", "amount": 500},
        {"id": 66, "name": "1.5GB Gifting", "validity": "2 Days", "amount": 599},
        {"id": 15, "name": "1GB Gifting", "validity": "7 Days", "amount": 800},
        {"id": 17, "name": "2GB Gifting", "validity": "30 Days", "amount": 1490},
        {"id": 52, "name": "5GB Gifting", "validity": "7 Days", "amount": 1570},
        {"id": 18, "name": "3GB Gifting", "validity": "30 Days", "amount": 1960},
        {"id": 22, "name": "6GB SME", "validity": "7 Days", "amount": 2455},
        {"id": 19, "name": "4GB Gifting", "validity": "30 Days", "amount": 2570},
        {"id": 20, "name": "8GB Gifting", "validity": "30 Days", "amount": 2999},
        {"id": 21, "name": "10GB Gifting", "validity": "30 Days", "amount": 4070},
    ],
}
CDH_CABLE_PLANS = {
    "DSTV": [
        {"id": 3, "name": "DStv Padi", "amount": 4400},
        {"id": 6, "name": "DStv Yanga", "amount": 6000},
        {"id": 7, "name": "DStv Confam", "amount": 11000},
        {"id": 8, "name": "DStv Compact", "amount": 19000},
        {"id": 9, "name": "DStv Compact Plus", "amount": 30000},
        {"id": 10, "name": "DStv Premium", "amount": 44500},
    ],
    "GOTV": [
        {"id": 4, "name": "GOtv Smallie", "amount": 1900},
        {"id": 11, "name": "GOtv Jinja", "amount": 3900},
        {"id": 12, "name": "GOtv Jolli", "amount": 5800},
        {"id": 13, "name": "GOtv Max", "amount": 8500},
        {"id": 14, "name": "GOtv Supa", "amount": 11400},
        {"id": 15, "name": "GOtv Supa Plus", "amount": 16800},
    ],
    "STARTIMES": [
        {"id": 5, "name": "Nova Antenna 1 Week", "amount": 700},
        {"id": 16, "name": "Nova Dish 1 Week", "amount": 700},
        {"id": 17, "name": "Nova Antenna 1 Month", "amount": 2100},
        {"id": 18, "name": "Basic Antenna 1 Week", "amount": 1400},
        {"id": 19, "name": "Basic Dish 1 Week", "amount": 1700},
        {"id": 20, "name": "Basic Antenna 1 Month", "amount": 4000},
        {"id": 21, "name": "Basic Dish 1 Month", "amount": 5100},
        {"id": 22, "name": "Classic Dish 1 Week", "amount": 2500},
        {"id": 23, "name": "Classic Dish 1 Month", "amount": 7400},
        {"id": 24, "name": "Super Dish 1 Week", "amount": 3300},
        {"id": 25, "name": "Super Antenna 1 Week", "amount": 3200},
        {"id": 26, "name": "Super Antenna 1 Month", "amount": 9500},
    ],
}

CHARGE_CATEGORIES = [
    {"category": "TRANSFER_FEES", "label": "Transfer Fees", "description": "Bank transfer fee collections"},
    {"category": "BOMPAY_TRANSFER_FEES", "label": "BOMPAY Transfer Fees", "description": "Internal BOMPAY transfer fees"},
    {"category": "SMS_CHARGES", "label": "SMS Charges", "description": "Monthly SMS notification charges"},
    {"category": "LOAN_REPAYMENTS", "label": "Loan Repayments", "description": "Loan repayment collections"},
    {"category": "SAVINGS_PROCEEDS", "label": "Savings Proceeds", "description": "Savings interest collections"},
    {"category": "VAS_FEES", "label": "VAS Fees", "description": "Airtime, data, electricity, cable TV fees"},
    {"category": "AJO_CONTRIBUTION_FEES", "label": "Ajo Contribution Fees", "description": "Fees charged on every Ajo group contribution"},
]

# WebAuthn config
WEBAUTHN_RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:3000")
WEBAUTHN_RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Bompay")

_sh_token: dict = {}

# ===== AUTH UTILS =====
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def hash_pin(pin: str) -> str:
    return bcrypt.hashpw(pin.encode("ascii"), bcrypt.gensalt(rounds=12)).decode("ascii")

def verify_pin_hash(pin: str, encoded_hash: str) -> bool:
    try:
        return bcrypt.checkpw(pin.encode("ascii"), encoded_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False

def create_access_token(uid: str, email: str) -> str:
    return pyjwt.encode(
        {"sub": uid, "email": email, "exp": datetime.now(timezone.utc) + timedelta(hours=1), "type": "access"},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

def create_refresh_token(uid: str) -> str:
    return pyjwt.encode(
        {"sub": uid, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "refresh"},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(401, "Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(401, "User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

async def get_admin_user(request: Request) -> dict:
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return user

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    opts = dict(httponly=True, secure=True, samesite="none", path="/")
    response.set_cookie("access_token", access_token, max_age=3600, **opts)
    response.set_cookie("refresh_token", refresh_token, max_age=604800, **opts)

# ===== WALLET / LEDGER UTILS =====
def gen_account_number() -> str:
    return "9" + "".join([str(secrets.randbelow(10)) for _ in range(9)])

async def get_wallet(user_id: str) -> dict:
    w = await db.wallets.find_one({"user_id": user_id})
    if not w:
        acct = gen_account_number()
        while await db.wallets.find_one({"account_number": acct}):
            acct = gen_account_number()
        doc = {"user_id": user_id, "account_number": acct, "available_balance": 0,
               "ledger_balance": 0, "pending_balance": 0, "held_balance": 0,
               "currency": "NGN", "status": "ACTIVE", "tier": 1,
               "created_at": datetime.now(timezone.utc).isoformat()}
        res = await db.wallets.insert_one(doc)
        doc["_id"] = str(res.inserted_id)
        return doc
    w["_id"] = str(w["_id"])
    return w

async def ledger_entry(user_id, wallet_id, txn_id, entry_type, amount, desc):
    await db.ledger_entries.insert_one({
        "entry_id": str(uuid.uuid4()), "transaction_id": txn_id,
        "user_id": user_id, "wallet_id": wallet_id,
        "entry_type": entry_type, "amount": amount, "currency": "NGN",
        "description": desc, "status": "POSTED",
        "created_at": datetime.now(timezone.utc).isoformat()
    })

async def notify(user_id, title, message, ntype="info", data=None):
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"notification_prefs": 1})
        prefs = (user or {}).get("notification_prefs", {})
        if not prefs.get("in_app_enabled", True):
            return
    except Exception:
        pass
    await db.notifications.insert_one({
        "notification_id": str(uuid.uuid4()), "user_id": user_id,
        "title": title, "message": message, "type": ntype,
        "data": data or {}, "read": False,
        "created_at": datetime.now(timezone.utc).isoformat()
    })

async def audit(user_id, action, resource, details=None, ip=None):
    await db.audit_logs.insert_one({
        "log_id": str(uuid.uuid4()), "user_id": user_id,
        "action": action, "resource": resource,
        "details": details or {}, "ip_address": ip,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

def fraud_check(amount_kobo: int) -> list:
    signals = []
    if amount_kobo > 50_000_000:
        signals.append("HIGH_VALUE_TRANSACTION")
    return signals

async def fraud_check_user(user_id: str, amount_kobo: int) -> list:
    """Full async fraud check — returns list of risk signals."""
    signals = []
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(seconds=60)).isoformat()

    # 1. Rapid-fire transactions (>4 in 60 seconds)
    rapid_count = await db.transactions.count_documents({
        "user_id": user_id,
        "created_at": {"$gte": window_start},
        "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER", "AIRTIME", "DATA", "ELECTRICITY", "CABLE_TV"]}
    })
    if rapid_count >= 4:
        signals.append("RAPID_TRANSACTIONS")

    # 2. High-value transaction (>₦500k)
    if amount_kobo > 50_000_000:
        signals.append("HIGH_VALUE_TRANSACTION")

    # 3. Multiple different recipients in 5 minutes
    five_min_ago = (now - timedelta(minutes=5)).isoformat()
    txns_5min = await db.transactions.distinct("metadata.account_number", {
        "user_id": user_id,
        "created_at": {"$gte": five_min_ago},
        "type": "BANK_TRANSFER"
    })
    if len(txns_5min) >= 3:
        signals.append("MULTIPLE_RECIPIENTS")

    # 4. Excessive failed PIN attempts (>=4)
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if user_id else None
    if user and int(user.get("pin_failed_attempts", 0)) >= 4:
        signals.append("EXCESSIVE_PIN_FAILURES")

    return signals

async def auto_block_user(user_id: str, reason: str, signals: list, extra_meta: dict = None):
    """Suspend a user for 24 hours and record a fraud alert."""
    now = datetime.now(timezone.utc)
    blocked_until = (now + timedelta(hours=24)).isoformat()
    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "status": "SUSPENDED",
        "blocked_until": blocked_until,
        "blocked_reason": reason,
        "blocked_at": now.isoformat(),
    }})
    await db.fraud_alerts.insert_one({
        "alert_id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": reason,
        "signals": signals,
        "amount": (extra_meta or {}).get("amount", 0),
        "status": "OPEN",
        "auto_blocked": True,
        "blocked_until": blocked_until,
        "metadata": extra_meta or {},
        "created_at": now.isoformat()
    })
    logger.info(f"[FraudEngine] Auto-blocked user {user_id}: {reason}")
    # Fire-and-forget email alert to admin
    asyncio.create_task(_send_fraud_block_email(user_id, reason, signals, blocked_until))

async def _send_fraud_block_email(user_id: str, reason: str, signals: list, blocked_until: str):
    """Notify admin email when a user is auto-blocked."""
    try:
        admin_email = os.environ.get("ADMIN_EMAIL", "")
        if not admin_email:
            return
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return
        name = f"{user.get('first_name','')} {user.get('last_name','')}".strip() or "Unknown"
        phone = user.get("phone", "—")
        frontend_url = os.environ.get("FRONTEND_URL", "").rstrip("/")
        unblock_url = f"{frontend_url}/console/fraud" if frontend_url else "#"
        signal_list = "".join(f'<li style="color:#dc2626;font-size:13px">{s.replace("_"," ")}</li>' for s in signals)
        html = (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td style="background:#064BCB;padding:20px 24px;border-radius:12px 12px 0 0">'
            f'<span style="color:#fff;font-size:18px;font-weight:800">BOMPAY</span>'
            f'<span style="color:#fff;font-size:12px;margin-left:12px;opacity:0.8">Fraud Alert</span></td></tr>'
            f'<tr><td style="background:#fff;padding:20px 24px;border-radius:0 0 12px 12px;font-family:Arial,sans-serif">'
            f'<p style="font-size:16px;font-weight:700;color:#0f172a;margin:0 0 16px">⚠️ User Auto-Blocked</p>'
            f'<table width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td style="color:#64748b;font-size:13px;padding:4px 0">User</td>'
            f'<td style="color:#0f172a;font-weight:600;font-size:13px;text-align:right">{name}</td></tr>'
            f'<tr><td style="color:#64748b;font-size:13px;padding:4px 0">Phone</td>'
            f'<td style="color:#0f172a;font-weight:600;font-size:13px;text-align:right">{phone}</td></tr>'
            f'<tr><td style="color:#64748b;font-size:13px;padding:4px 0">Reason</td>'
            f'<td style="color:#dc2626;font-weight:600;font-size:13px;text-align:right">{reason.replace("_"," ")}</td></tr>'
            f'<tr><td style="color:#64748b;font-size:13px;padding:4px 0">Blocked Until</td>'
            f'<td style="color:#0f172a;font-weight:600;font-size:13px;text-align:right">{blocked_until[:19].replace("T"," ")} UTC</td></tr>'
            f'</table>'
            f'<p style="font-size:13px;color:#64748b;margin:12px 0 6px">Triggered signals:</p>'
            f'<ul style="margin:0;padding-left:18px">{signal_list}</ul>'
            f'<div style="margin-top:20px">'
            f'<a href="{unblock_url}" style="background:#064BCB;color:#fff;padding:10px 20px;'
            f'border-radius:8px;text-decoration:none;font-size:13px;font-weight:700">View in Console →</a>'
            f'</div>'
            f'<p style="font-size:11px;color:#94a3b8;margin-top:16px">BOMPAY Fraud Engine · Auto-generated alert</p>'
            f'</td></tr></table>'
        )
        await send_email(to=admin_email, subject=f"[BOMPAY] User Auto-Blocked: {name} ({reason.replace('_',' ')})", html=html)
    except Exception as e:
        logger.error(f"[FraudEmail] Failed to send alert: {e}")

def _get_client_ip(request: Request) -> str:
    """Extract real client IP respecting proxy headers."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri.strip()
    return request.client.host if request.client else "unknown"

def _parse_ua(ua: str) -> str:
    """Return a short human-readable device description from user-agent."""
    ua = ua or ""
    if "Mobile" in ua or "Android" in ua:
        platform = "Mobile"
    elif "iPad" in ua:
        platform = "Tablet"
    else:
        platform = "Desktop"
    if "Chrome" in ua and "Edg" not in ua and "OPR" not in ua:
        browser = "Chrome"
    elif "Firefox" in ua:
        browser = "Firefox"
    elif "Safari" in ua and "Chrome" not in ua:
        browser = "Safari"
    elif "Edg" in ua:
        browser = "Edge"
    else:
        browser = "Browser"
    if "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS" in ua:
        os_name = "macOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"
    return f"{browser} on {os_name} ({platform})"

async def log_login_session(user_id: str, request: Request, event_type: str, success: bool, metadata: dict = None):
    """Record a login attempt with IP, device, and user-agent for fraud analysis."""
    ip = _get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    device_id = request.headers.get("X-Device-ID", "") or (metadata or {}).get("device_id", "")
    # Geo-lookup (best-effort, never blocks the login)
    geo: dict = {}
    try:
        if ip and ip not in ("unknown", "127.0.0.1", "::1", "testclient"):
            async with httpx.AsyncClient(timeout=3) as c:
                r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon")
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    geo = {"country": d.get("country",""), "country_code": d.get("countryCode",""),
                           "city": d.get("city",""), "lat": d.get("lat"), "lon": d.get("lon")}
    except Exception:
        pass
    await db.login_sessions.insert_one({
        "session_id": str(uuid.uuid4()),
        "user_id": user_id,
        "event_type": event_type,
        "success": success,
        "ip": ip,
        "user_agent": ua,
        "device": _parse_ua(ua),
        "device_id": device_id,
        "geo": geo,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **(metadata or {})
    })
    # Rapid-login detection: >10 sessions from same IP in 3 minutes → flag
    window = (datetime.now(timezone.utc) - timedelta(minutes=3)).isoformat()
    rapid_count = await db.login_sessions.count_documents({
        "ip": ip, "user_id": user_id, "created_at": {"$gte": window}
    })
    if rapid_count > 10 and success:
        existing = await db.fraud_alerts.find_one({
            "user_id": user_id, "type": "RAPID_LOGIN", "status": "OPEN"
        })
        if not existing:
            await db.fraud_alerts.insert_one({
                "alert_id": str(uuid.uuid4()), "user_id": user_id,
                "type": "RAPID_LOGIN", "signals": ["RAPID_LOGIN"],
                "amount": 0, "status": "OPEN", "auto_blocked": False,
                "metadata": {"ip": ip, "count": rapid_count, "window_minutes": 3},
                "created_at": datetime.now(timezone.utc).isoformat()
            })

# ===== SAFE HAVEN MOCK & PROVIDER =====
NIGERIAN_BANKS = [
    {"code": "011", "name": "First Bank of Nigeria"}, {"code": "044", "name": "Access Bank"},
    {"code": "057", "name": "Zenith Bank"}, {"code": "058", "name": "Guaranty Trust Bank"},
    {"code": "070", "name": "Fidelity Bank"}, {"code": "076", "name": "Polaris Bank"},
    {"code": "082", "name": "Keystone Bank"}, {"code": "033", "name": "United Bank for Africa"},
    {"code": "032", "name": "Union Bank of Nigeria"}, {"code": "215", "name": "Unity Bank"},
    {"code": "035", "name": "Wema Bank"}, {"code": "232", "name": "Sterling Bank"},
    {"code": "214", "name": "FCMB"}, {"code": "050", "name": "Ecobank Nigeria"},
    {"code": "090267", "name": "Kuda Microfinance Bank"}, {"code": "100004", "name": "OPay Digital Services"},
    {"code": "100033", "name": "PalmPay"}, {"code": "50515", "name": "Moniepoint MFB"},
    {"code": "120001", "name": "9PSB"}, {"code": "000026", "name": "Taj Bank"},
]
MOCK_NAMES = [
    "ADEBAYO OLUWASEUN JAMES", "CHUKWUEMEKA NNAMDI OKONKWO", "FATIMAH AISHA IBRAHIM",
    "OLUWAFEMI ADEYEMI SAMUEL", "NGOZI CHIDINMA OKAFOR", "BABATUNDE RASHEED ADENIYI",
    "AMAKA BLESSING EZE", "EMEKA CHUKWUDI OBI", "YETUNDE FOLAKE ADESANYA",
    "UCHE OBIORA NWACHUKWU", "TAIWO OLUMIDE ADELEKE", "KEMI TITILAYO BALOGUN",
]

async def mock_sh(path: str, body: dict = None) -> dict:
    import random
    if path == "/transfers/banks":
        return {"statusCode": 200, "data": NIGERIAN_BANKS}
    if path == "/transfers/name-enquiry":
        acct = (body or {}).get("accountNumber", "")
        idx = (sum(int(d) for d in acct if d.isdigit()) % len(MOCK_NAMES)) if acct else 0
        return {"statusCode": 200, "data": {
            "accountName": MOCK_NAMES[idx], "accountNumber": acct,
            "bankCode": (body or {}).get("bankCode", ""),
            "sessionId": f"SH{secrets.token_hex(16).upper()}"
        }}
    if path == "/transfers":
        return {"statusCode": 200, "data": {
            "transactionReference": f"TRF{secrets.token_hex(12).upper()}",
            "status": "COMPLETED", "responseCode": "00"
        }}
    if "/airtime" in path:
        return {"statusCode": 200, "data": {"transactionReference": f"AIR{secrets.token_hex(10).upper()}", "status": "COMPLETED"}}
    if "/data" in path:
        return {"statusCode": 200, "data": {"transactionReference": f"DAT{secrets.token_hex(10).upper()}", "status": "COMPLETED"}}
    if "/cable-tv" in path:
        return {"statusCode": 200, "data": {"transactionReference": f"CAB{secrets.token_hex(10).upper()}", "status": "COMPLETED"}}
    if "/utility" in path:
        units = str(round(float((body or {}).get("amount", 1000)) / 100, 1))
        token = "".join([str(random.randint(0, 9)) for _ in range(20)])
        return {"statusCode": 200, "data": {
            "transactionReference": f"ELC{secrets.token_hex(10).upper()}",
            "status": "COMPLETED", "token": token, "units": units
        }}
    if "/verify" in path:
        ident = (body or {}).get("entityNumber", "")
        svc = (body or {}).get("serviceCategoryId", "")
        if "cable" in svc or "tv" in svc:
            return {"statusCode": 200, "data": {"customerName": "MOCK CUSTOMER", "entityNumber": ident, "currentPackage": "DStv Compact", "status": "ACTIVE"}}
        return {"statusCode": 200, "data": {"customerName": "MOCK METER CUSTOMER", "meterNumber": ident, "address": "Lagos, Nigeria", "vendType": "PREPAID"}}
    # Identity verification (KYC)
    if path == "/identity/v2":
        return {"statusCode": 200, "message": "Record fetched successfully", "data": {
            "_id": f"MOCKID{secrets.token_hex(12).upper()}",
            "status": "SUCCESS",
            "otpId": f"OTPID{secrets.token_hex(12).upper()}"
        }}
    # Sub-account creation
    if "/accounts/v2/subaccount" in path:
        phone = (body or {}).get("phoneNumber", "+2340000000000")
        email = (body or {}).get("emailAddress", "user@bompay.ng")
        name_part = email.split("@")[0].upper()[:12]
        fake_acct = "80" + "".join([str(random.randint(0, 9)) for _ in range(8)])
        mock_id = f"MOCKSUB{secrets.token_hex(12).upper()}"
        return {"statusCode": 200, "message": "Account Created Successfully.", "data": {
            "_id": mock_id,
            "accountNumber": fake_acct,
            "accountName": f"BOMPAY / {name_part}",
            "accountType": "Current", "currencyCode": "NGN",
            "accountBalance": 0, "bookBalance": 0, "isSubAccount": True
        }}
    # Get sub-account balance
    if path.startswith("/accounts/") and len(path.split("/")) == 3:
        return {"statusCode": 200, "data": {
            "accountBalance": 0, "bookBalance": 0, "accountNumber": "0000000000",
            "status": "Active", "canDebit": True, "canCredit": True
        }}
    return {"statusCode": 200, "data": {}}

async def call_sh(method: str, path: str, body: dict = None) -> dict:
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    cid = (settings or {}).get("client_id", "")
    csec = (settings or {}).get("client_secret", "")   # RSA private key PEM
    issuer = (settings or {}).get("issuer", cid)       # Company URL for JWT iss claim
    base = (settings or {}).get("base_url", SAFEHAVEN_BASE_URL)

    # No credentials configured — use simulated responses
    if not cid or not csec:
        return await mock_sh(path, body)

    try:
        if not _sh_token.get("access_token") or _sh_token.get("expires_at", 0) < time.time() + 60:
            # Build RS256-signed JWT client assertion from private key PEM
            now = int(time.time())
            private_key = csec.strip().replace('\r\n', '\n').replace('\r', '\n')
            try:
                client_assertion = pyjwt.encode(
                    {"iss": issuer, "sub": cid, "aud": base, "iat": now, "exp": now + 300},
                    private_key, algorithm="RS256", headers={"typ": "JWT"}
                )
            except Exception as jwt_err:
                logger.error(f"[SafeHaven] JWT generation failed — check private key PEM: {jwt_err}")
                raise HTTPException(502, "Safe Haven: Invalid private key. Make sure you paste the PRIVATE KEY (-----BEGIN RSA PRIVATE KEY-----), NOT the certificate (-----BEGIN CERTIFICATE-----). Also set your Company URL in the Issuer field.")

            # Safe Haven token endpoint requires JSON body, not form-encoded
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(f"{base}/oauth2/token", json={
                    "grant_type": "client_credentials", "client_id": cid,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": client_assertion
                })

            if r.is_error:
                logger.error(f"[SafeHaven] Token error {r.status_code}: {r.text[:400]}")
                raise HTTPException(502, f"Safe Haven authentication failed ({r.status_code}). Verify your Client ID, private key, and Company URL (Issuer).")

            x = r.json()
            _sh_token.clear()
            _sh_token.update({
                "access_token": x.get("access_token"),
                "ibs_client_id": x.get("ibs_client_id", cid),   # Required: ibs_client_id from token response
                "expires_at": time.time() + int(x.get("expires_in", 1800))
            })

        hdrs = {
            "Authorization": f"Bearer {_sh_token['access_token']}",
            "ClientID": _sh_token.get("ibs_client_id", cid),   # Required: ibs_client_id from token response
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=45) as c:
            r = await c.request(method, base + path, json=body, headers=hdrs)

        if r.status_code == 401:
            _sh_token.clear()   # Force token refresh on next request
            logger.warning("[SafeHaven] 401 received — token cache cleared")
            raise HTTPException(502, "Safe Haven session expired. Please retry.")

        if r.is_error:
            logger.error(f"[SafeHaven] API error {r.status_code}: {r.text[:300]}")
            raise HTTPException(502, f"Safe Haven API error ({r.status_code}): {r.text[:200]}")

        return r.json()

    except HTTPException:
        raise   # Propagate meaningful errors — never silently mock when credentials are set
    except Exception as e:
        logger.error(f"[SafeHaven] Unexpected exception: {e}")
        raise HTTPException(502, f"Safe Haven connection error: {str(e)}")

async def call_cdh(method: str, path: str, body: dict = None) -> dict:
    """Call CheapDataHub VAS API."""
    api_key = os.environ.get("CHEAPDATAHUB_API_KEY", "")
    if not api_key:
        raise HTTPException(503, "VAS provider (CheapDataHub) is not configured.")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.request(method, f"{CDH_BASE_URL}{path}", json=body, headers=headers)
        try:
            data = r.json()
        except Exception:
            raise HTTPException(500, f"CheapDataHub returned an invalid response ({r.status_code})")
        if str(data.get("status", "")).lower() not in ("true", "success"):
            raise HTTPException(400, data.get("message") or "VAS request failed")
        return data

async def get_vas_provider() -> str:
    """Return the active VAS provider: CHEAPDATAHUB (default) or SAFEHAVEN."""
    doc = await db.settings.find_one({"key": "vas_provider"})
    return (doc or {}).get("value", "CHEAPDATAHUB")

async def get_service_provider(service: str) -> str:
    """Return the VAS provider configured for a specific service (AIRTIME, DATA, CABLE, ELECTRICITY, BETTING).
    Falls back to the global vas_provider, then CDH."""
    doc = await db.vas_routing.find_one({"service": service.upper()})
    if doc and doc.get("provider"):
        return doc["provider"].upper()
    return await get_vas_provider()

async def call_pg(method: str, path: str, body: dict = None) -> dict:
    """Call PairGate VAS API and return parsed response body."""
    api_key = os.environ.get("PAIRGATE_API_KEY", "")
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.request(method, f"{PAIRGATE_BASE_URL}{path}", json=body, headers=headers)
    try:
        data = r.json()
    except Exception:
        raise HTTPException(502, f"PairGate API returned non-JSON (HTTP {r.status_code})")
    if r.status_code not in (200, 201):
        # Log the full PairGate error body for diagnostics
        msg = data.get("message") or data.get("error") or f"PairGate error (HTTP {r.status_code})"
        errors = data.get("errors") or data.get("data") or {}
        logger.error(f"[PG] {method} {path} HTTP {r.status_code}: msg={msg} errors={errors} body={str(data)[:600]}")
        # Use 400 for PairGate 4xx (business errors: insufficient balance, invalid meter, etc.)
        # Cloudflare intercepts 502 from origin and shows its own 520 page — so use 400 for business rejections
        err_code = 400 if 400 <= r.status_code < 500 else 502
        raise HTTPException(err_code, f"PairGate: {msg}")
    # Accept any 2xx response — electricity purchases return status "processing" (async token delivery)
    # Only reject if PairGate explicitly signals a business failure via a non-success status
    pg_status = str(data.get("status", "")).lower()
    if pg_status in ("failed", "error", "false"):
        msg = data.get("message") or data.get("error") or "PairGate reported failure"
        logger.error(f"[PG] {method} {path} business failure: status={pg_status} msg={msg} body={str(data)[:600]}")
        raise HTTPException(400, f"PairGate: {msg}")
    logger.info(f"[PG] {method} {path} HTTP {r.status_code} status={pg_status}")
    return data.get("data", data)

async def get_sms_config() -> dict:
    doc = await db.settings.find_one({"key": "sms_config"})
    return (doc or {}).get("value", {"enabled": True, "unit_cost_ngn": 4.0, "billing_day": 1})

async def get_sms_provider() -> str:
    """Returns active SMS provider: SENDORA (default) or BULKSMSLIVE."""
    doc = await db.settings.find_one({"key": "sms_provider"})
    return (doc or {}).get("value", "SENDORA")

async def get_sendora_api_key() -> str:
    doc = await db.settings.find_one({"key": "sendora_config"})
    if doc and doc.get("value", {}).get("api_key"):
        return doc["value"]["api_key"]
    return os.environ.get("SENDORA_API_KEY", "")

async def get_sendora_sender_id() -> str:
    doc = await db.settings.find_one({"key": "sendora_config"})
    if doc and doc.get("value", {}).get("sender_id"):
        return doc["value"]["sender_id"]
    return os.environ.get("SENDORA_SENDER_ID", "BOMPAY")

async def get_bulksms_credentials() -> dict:
    doc = await db.settings.find_one({"key": "bulksms_config"})
    val = (doc or {}).get("value", {})
    return {
        "email": val.get("email") or os.environ.get("BULKSMSLIVE_EMAIL", ""),
        "password": val.get("password") or os.environ.get("BULKSMSLIVE_PASSWORD", ""),
        "sender_id": val.get("sender_id") or os.environ.get("BULKSMSLIVE_SENDER_ID", "BOMPAY"),
    }

async def _send_via_sendora(phone: str, body: str) -> dict:
    api_key = await get_sendora_api_key()
    if not api_key:
        return {"ok": False, "error": "Sendora API key not configured"}
    sender_id = await get_sendora_sender_id()
    base_url = os.environ.get("SENDORA_BASE_URL", "https://api.sendoracloud.com/api/v1")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{base_url}/sms/send",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"to": phone, "body": body, "sender_id": sender_id, "category": "transactional"})
    resp = {}
    try:
        resp = r.json()
    except Exception:
        pass
    return {"ok": r.status_code < 400, "ref": resp.get("id") or resp.get("messageId"), "raw": resp}

async def _send_via_bulksms(phone: str, body: str) -> dict:
    creds = await get_bulksms_credentials()
    if not creds["email"] or not creds["password"]:
        return {"ok": False, "error": "BulkSMSLive credentials not configured"}
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post("https://api.bulksmslive.com/v2/app/sms",
            headers={"Content-Type": "application/json"},
            json={
                "email": creds["email"],
                "password": creds["password"],
                "message": body,
                "sender_name": creds["sender_id"],
                "recipients": phone,
                "forcednd": "1"
            })
    resp = {}
    try:
        resp = r.json()
    except Exception:
        pass
    # BulkSMSLive returns numeric status: 1=ok, -4=invalid sender, -7=low balance, etc.
    status_code = resp.get("status")
    ok = r.status_code < 400 and status_code == 1
    return {"ok": ok, "ref": resp.get("msgid") or resp.get("messageid") or resp.get("id"), "status_code": status_code, "raw": resp}

async def send_event_sms(user_id: str, event_type: str, metadata: dict):
    """Fire-and-forget SMS notification. Logs to sms_logs. Never raises."""
    try:
        cfg = await get_sms_config()
        if not cfg.get("enabled", True):
            return
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"phone": 1, "first_name": 1, "notification_prefs": 1})
        if not user or not user.get("phone"):
            return
        # Check SMS notification preference
        prefs = user.get("notification_prefs", {})
        if not prefs.get("sms_enabled", True):
            return
        phone = user["phone"].strip()
        if phone.startswith("0"):
            phone = "+234" + phone[1:]
        elif not phone.startswith("+"):
            phone = "+234" + phone

        templates = {
            "TRANSFER_DEBIT": lambda m: f"BOMPAY Alert: Debit of NGN{m.get('amount',0):,.0f} sent to {m.get('beneficiary','')}. Ref: {m.get('ref','')}. Bal: NGN{m.get('balance',0):,.0f}",
            "TRANSFER_CREDIT": lambda m: f"BOMPAY Alert: Credit of NGN{m.get('amount',0):,.0f} from {m.get('sender','')}. Bal: NGN{m.get('balance',0):,.0f}",
            "AIRTIME": lambda m: f"BOMPAY: NGN{m.get('amount',0):,.0f} {m.get('network','')} airtime sent to {m.get('phone','')} successfully. Ref: {m.get('ref','')}",
            "DATA": lambda m: f"BOMPAY: {m.get('plan','')} data bundle for {m.get('phone','')} activated. Ref: {m.get('ref','')}",
            "ELECTRICITY": lambda m: (
                f"BOMPAY Electricity: Token {m.get('token')} | {m.get('units','')} units | Meter: {m.get('meter','')}"
                if m.get('token') and m.get('token') not in ('', 'N/A')
                else None  # Token not ready yet — webhook will send when token arrives
            ),
            "CABLE": lambda m: f"BOMPAY: {m.get('plan','')} Cable TV renewed for smartcard {m.get('smartcard','')}. Ref: {m.get('ref','')}",
            "SAVINGS_DEBIT": lambda m: f"BOMPAY: NGN{m.get('amount',0):,.0f} auto-debited to savings goal '{m.get('goal','')}'. Bal: NGN{m.get('balance',0):,.0f}",
            "LOAN_DISBURSED": lambda m: f"BOMPAY Loan: NGN{m.get('amount',0):,.0f} disbursed to wallet. Monthly repayment: NGN{m.get('monthly',0):,.0f} x {m.get('tenor',0)} months.",
            "LOAN_REPAYMENT": lambda m: f"BOMPAY: NGN{m.get('amount',0):,.0f} loan repayment received. Outstanding: NGN{m.get('outstanding',0):,.0f}.{'  Loan fully repaid!' if m.get('fully_repaid') else ''}",
            "AJO_PAYOUT_READY": lambda m: f"BOMPAY Ajo: Your NGN{m.get('amount',0):,.0f} pool from '{m.get('group','')}' is ready to collect. Open the BOMPAY app to claim your funds.",
            "REFERRAL_BONUS": lambda m: f"BOMPAY Referral: NGN{m.get('amount',0):,.0f} referral bonus added! {m.get('note','')} Check Referrals in the app.",
        }
        fn = templates.get(event_type)
        if not fn:
            return
        body = fn(metadata)
        if not body:
            return  # Template returned None — skip SMS (e.g. electricity token not yet available)
        active_provider = await get_sms_provider()
        log_id = str(uuid.uuid4())
        await db.sms_logs.insert_one({
            "log_id": log_id, "user_id": user_id, "phone": phone,
            "event_type": event_type, "body": body, "status": "SENDING",
            "provider": active_provider,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        try:
            if active_provider == "BULKSMSLIVE":
                result = await _send_via_bulksms(phone, body)
            else:
                result = await _send_via_sendora(phone, body)
            status = "SENT" if result.get("ok") else "FAILED"
            await db.sms_logs.update_one({"log_id": log_id}, {"$set": {
                "status": status,
                "provider_ref": result.get("ref"),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }})
        except Exception as e:
            await db.sms_logs.update_one({"log_id": log_id}, {"$set": {
                "status": "FAILED", "error": str(e),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }})
    except Exception as e:
        logger.error(f"[SMS] send_event_sms error for user {user_id} event {event_type}: {e}")

# ===== EMAIL (Emergent managed Resend) =====
EMAIL_BASE_URL = "https://integrations.emergentagent.com"
EMAIL_KEY = os.environ.get("EMERGENT_EMAIL_KEY", "")
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "BOMPAY")

_SHORTENERS = ("bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","goo.gl","rebrand.ly")
_CRED_ASK = ("reply with your password","reply with the code","send your password","cvv",
             "send us your password","enter your password below","confirm your card number",
             "your full card number","seed phrase","recovery phrase","verify your card",
             "social security number","confirm your bank details")
_HOSTISH = _re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", _re.I)

def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        _ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)

def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)

class _EmailScan(_HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []
    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href","src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(),v) for k,v in attrs).get("href")
            self._text = []
    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []

def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan(); scan.feed(html)
    if scan.tags & {"form","input","textarea","select"}:
        raise ValueError("No forms in email")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks for credentials: {p!r}")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:","tel:","cid:","#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Non-https link: {url!r}")
        host = _urlparse(low).hostname or ""
        if not _host_ok(host) or _urlparse(low).username is not None:
            raise ValueError(f"Bad URL: {url!r}")
    for href, text in scan.anchors:
        real = _urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor mismatch: {m.group(1)!r} vs {real!r}")

async def send_email(*, to: str, subject: str, html: str) -> None:
    """Fire-and-forget. Tries direct Resend API first, falls back to Emergent managed email."""
    if not to:
        return
    try:
        _assert_safe_email(subject, html)
        # Prefer direct Resend API key if configured in DB or env
        resend_cfg = await db.admin_settings.find_one({"key": "resend"})
        resend_key = (resend_cfg or {}).get("api_key") or os.environ.get("RESEND_API_KEY", "")
        from_name = (resend_cfg or {}).get("from_name") or os.environ.get("EMAIL_FROM_NAME", "BOMPAY")
        from_email = (resend_cfg or {}).get("from_email") or os.environ.get("EMAIL_FROM_ADDRESS", "no-reply@bompay.ng")

        if resend_key:
            payload = {
                "from": f"{from_name} <{from_email}>",
                "to": [to],
                "subject": subject,
                "html": html,
            }
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.post("https://api.resend.com/emails",
                                 headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                                 json=payload)
            if r.status_code >= 400:
                logger.warning(f"[Resend] send failed {r.status_code}: {r.text[:200]}")
        elif EMAIL_KEY:
            payload = {"to": [to], "subject": subject, "html": html, "from_name": from_name}
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.post(f"{EMAIL_BASE_URL}/api/v1/email/send",
                                 headers={"X-Email-Key": EMAIL_KEY}, json=payload)
            if r.status_code >= 400:
                logger.warning(f"[Email] send failed {r.status_code}: {r.text[:200]}")
        else:
            logger.debug(f"[Email] No email provider configured — dropping email to {to}")
    except Exception as e:
        logger.error(f"[Email] error: {e}")

def _email_html(title: str, body_lines: list, footer: str = "") -> str:
    rows = "".join(f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">{_escape(k)}</td>'
                   f'<td style="padding:4px 0;color:#0f172a;font-size:13px;font-weight:600;text-align:right">{_escape(str(v))}</td></tr>'
                   for k, v in body_lines)
    ft = f'<p style="font-size:11px;color:#94a3b8;margin-top:24px">{_escape(footer)}</p>' if footer else ""
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td style="background:#064BCB;padding:24px 24px 16px;border-radius:12px 12px 0 0">'
            f'<span style="color:#fff;font-size:18px;font-weight:800;letter-spacing:-0.5px">BOMPAY</span></td></tr>'
            f'<tr><td style="background:#fff;padding:20px 24px;border-radius:0 0 12px 12px;font-family:Arial,sans-serif">'
            f'<p style="font-size:16px;font-weight:700;color:#0f172a;margin-bottom:16px">{_escape(title)}</p>'
            f'<table width="100%" cellpadding="0" cellspacing="0">{rows}</table>'
            f'{ft}'
            f'<p style="font-size:11px;color:#94a3b8;margin-top:12px">BOMPAY — Your trusted Nigerian fintech. '
            f'We never ask for your PIN or password by email.</p>'
            f'</td></tr></table>')

async def _send_tier_approval_email(user_id: str, tier: int) -> None:
    """Fire-and-forget email for tier upgrade approval."""
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"email": 1, "first_name": 1})
        if not user or not user.get("email"):
            return
        name = user.get("first_name", "Customer")
        email_addr = user["email"]
        tier_info = {
            2: {"label": "Tier 2 — Verified", "daily": "₦500,000", "single": "₦100,000"},
            3: {"label": "Tier 3 — Premium",  "daily": "₦5,000,000", "single": "₦1,000,000"},
        }
        info = tier_info.get(tier, {"label": f"Tier {tier}", "daily": "—", "single": "—"})
        subject = f"Your BOMPAY {info['label']} is Active!"
        html = _email_html(
            f"Hi {name}, your Tier {tier} upgrade is approved!",
            [
                ("Status", "Approved"),
                ("Tier",   info["label"]),
                ("Daily Transfer Limit",  info["daily"]),
                ("Single Transfer Limit", info["single"]),
            ],
            footer="Open the BOMPAY app to start enjoying your new limits. "
                   "We never ask for your PIN or password.",
        )
        await send_email(to=email_addr, subject=subject, html=html)
    except Exception as e:
        logger.error(f"[Email] Tier {tier} approval email error: {e}")


async def _send_tier_revoke_email(user_id: str, revoked_tier: int, new_tier: int, reason: str = "") -> None:
    """Fire-and-forget email for tier revocation."""
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"email": 1, "first_name": 1})
        if not user or not user.get("email"):
            return
        name = user.get("first_name", "Customer")
        email_addr = user["email"]
        tier_names = {0: "Tier 0 (Unverified)", 1: "Tier 1 (Basic)", 2: "Tier 2 (Verified)", 3: "Tier 3 (Premium)"}
        subject = f"BOMPAY: Your Tier {revoked_tier} Access Has Been Updated"
        body_lines: list = [
            ("Previous Tier", tier_names.get(revoked_tier, f"Tier {revoked_tier}")),
            ("Current Tier",  tier_names.get(new_tier,     f"Tier {new_tier}")),
        ]
        if reason:
            body_lines.append(("Reason", reason))
        html = _email_html(
            f"Hi {name}, your Tier {revoked_tier} access has been revoked",
            body_lines,
            footer="If you believe this is an error, please contact BOMPAY support. "
                   "You can re-apply for verification in the app.",
        )
        await send_email(to=email_addr, subject=subject, html=html)
    except Exception as e:
        logger.error(f"[Email] Tier {revoked_tier} revocation email error: {e}")


async def send_event_email(user_id: str, event_type: str, metadata: dict):
    """Fire-and-forget email notification. Never raises."""
    try:
        cfg = await db.settings.find_one({"key": "email_config"})
        if not (cfg or {}).get("value", {}).get("enabled", True):
            return
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"email": 1, "first_name": 1, "notification_prefs": 1})
        if not user or not user.get("email"):
            return
        # Check user notification prefs
        prefs = user.get("notification_prefs", {})
        if not prefs.get("email_enabled", True):
            return
        email = user["email"]
        name = user.get("first_name", "Customer")
        templates = {
            "TRANSFER_DEBIT": ("Debit Alert", [
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
                ("To", metadata.get("beneficiary","")),
                ("Reference", metadata.get("ref","")),
                ("Balance", f"₦{metadata.get('balance',0):,.2f}"),
            ]),
            "TRANSFER_CREDIT": ("Credit Alert", [
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
                ("From", metadata.get("sender","")),
                ("Balance", f"₦{metadata.get('balance',0):,.2f}"),
            ]),
            "AIRTIME": ("Airtime Purchase", [
                ("Network", metadata.get("network","")),
                ("Phone", metadata.get("phone","")),
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
                ("Reference", metadata.get("ref","")),
            ]),
            "DATA": ("Data Bundle Purchase", [
                ("Plan", metadata.get("plan","")),
                ("Phone", metadata.get("phone","")),
                ("Reference", metadata.get("ref","")),
            ]),
            "ELECTRICITY": ("Electricity Payment", [
                ("Token", metadata.get("token","")),
                ("Units", metadata.get("units","")),
                ("Meter", metadata.get("meter","")),
            ]),
            "CABLE": ("Cable TV Renewal", [
                ("Plan", metadata.get("plan","")),
                ("Smartcard", metadata.get("smartcard","")),
                ("Reference", metadata.get("ref","")),
            ]),
            "SAVINGS_DEBIT": ("Savings Auto-Debit", [
                ("Goal", metadata.get("goal","")),
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
                ("Balance", f"₦{metadata.get('balance',0):,.2f}"),
            ]),
            "LOAN_DISBURSED": ("Loan Disbursed", [
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
                ("Monthly Repayment", f"₦{metadata.get('monthly',0):,.2f}"),
                ("Tenor", f"{metadata.get('tenor',0)} months"),
            ]),
            "LOAN_REPAYMENT": ("Loan Repayment", [
                ("Amount Paid", f"₦{metadata.get('amount',0):,.2f}"),
                ("Outstanding", f"₦{metadata.get('outstanding',0):,.2f}"),
                ("Status", "Fully Repaid!" if metadata.get("fully_repaid") else "Active"),
            ]),
            "AJO_PAYOUT_READY": ("Ajo Payout Ready", [
                ("Group", metadata.get("group","")),
                ("Amount", f"₦{metadata.get('amount',0):,.2f}"),
            ]),
            "CASHBACK_EARNED": ("Cashback Earned", [
                ("Service", metadata.get("service","")),
                ("Cashback", f"₦{metadata.get('amount',0):,.2f}"),
            ]),
            "REFERRAL_BONUS": ("Referral Bonus", [
                ("Bonus", f"₦{metadata.get('amount',0):,.0f}"),
                ("Note", metadata.get("note","")),
            ]),
        }
        tpl = templates.get(event_type)
        if not tpl:
            return
        title, rows = tpl
        html = _email_html(f"Hi {name}, {title}", rows, "Open BOMPAY app for details.")
        subject = f"BOMPAY: {title}"
        asyncio.create_task(send_email(to=email, subject=subject, html=html))
    except Exception as e:
        logger.error(f"[Email] send_event_email error for user {user_id} event {event_type}: {e}")

async def send_event_notification(user_id: str, event_type: str, metadata: dict):
    """Fire SMS, email, and push notifications. Fire-and-forget, never raises."""
    push_titles = {
        "TRANSFER_DEBIT": ("Debit Alert", f"₦{metadata.get('amount',0):,.0f} sent"),
        "TRANSFER_CREDIT": ("Credit Alert", f"₦{metadata.get('amount',0):,.0f} received"),
        "AIRTIME": ("Airtime", f"₦{metadata.get('amount',0):,.0f} airtime purchased"),
        "DATA": ("Data Bundle", f"{metadata.get('plan','')} activated"),
        "ELECTRICITY": ("Electricity", f"Token: {metadata.get('token','')}" if metadata.get('token') and metadata.get('token') != 'N/A' else "Electricity payment successful"),
        "CABLE": ("Cable TV", f"{metadata.get('plan','')} renewed"),
        "LOAN_DISBURSED": ("Loan Disbursed", f"₦{metadata.get('amount',0):,.0f} added to wallet"),
        "AJO_PAYOUT_READY": ("Ajo Payout", f"₦{metadata.get('amount',0):,.0f} ready for collection"),
        "CASHBACK_EARNED": ("Cashback", f"₦{metadata.get('amount',0):,.2f} cashback earned"),
    }
    tasks = [
        send_event_sms(user_id, event_type, metadata),
        send_event_email(user_id, event_type, metadata),
    ]
    if event_type in push_titles:
        title, body = push_titles[event_type]
        tasks.append(send_push_notification(user_id, f"BOMPAY: {title}", body))
    await asyncio.gather(*tasks, return_exceptions=True)

async def send_push_notification(user_id: str, title: str, body: str, url: str = "/dashboard"):
    """Fire-and-forget Web Push notification. Never raises."""
    if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY_B64:
        return
    try:
        import json as _json
        from pywebpush import webpush, WebPushException
        subs = await db.push_subscriptions.find({"user_id": user_id}).to_list(10)
        for sub in subs:
            try:
                payload_str = _json.dumps({"title": title, "body": body, "url": url})
                webpush(
                    subscription_info={"endpoint": sub["endpoint"], "keys": sub["keys"]},
                    data=payload_str,
                    vapid_private_key=VAPID_PRIVATE_KEY_B64,
                    vapid_claims={"sub": VAPID_EMAIL},
                )
            except WebPushException as e:
                if e.response and e.response.status_code in (404, 410):
                    await db.push_subscriptions.delete_one({"_id": sub["_id"]})
    except Exception as e:
        logger.error(f"[Push] error: {e}")

# ===== PYDANTIC MODELS =====
class RegisterReq(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    phone: str
    referral_code: Optional[str] = None

class PromotionReq(BaseModel):
    title: str
    subtitle: Optional[str] = None
    image_url: Optional[str] = None
    bg_color: Optional[str] = "#EEF4FF"
    text_color: Optional[str] = "#064BCB"
    action_url: Optional[str] = None
    button_label: Optional[str] = "GO"
    is_active: bool = True
    sort_order: int = 0

class LoginReq(BaseModel):
    email: EmailStr
    password: str

class FundReq(BaseModel):
    amount: float
    idempotency_key: Optional[str] = None

class TransferReq(BaseModel):
    bank_code: str
    account_number: str
    amount: float
    narration: str
    name_enquiry_reference: str
    beneficiary_name: str
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None
    biometric_token: Optional[str] = None

class NameEnquiryReq(BaseModel):
    bank_code: str
    account_number: str

class AirtimeReq(BaseModel):
    phone_number: str
    amount: float
    network: str
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None

class DataReq(BaseModel):
    phone_number: str
    plan_id: str
    amount: float
    network: str
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None

class CableReq(BaseModel):
    smartcard_number: str
    package_id: str
    amount: float
    provider: str
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None

class ElectricityReq(BaseModel):
    meter_number: str
    amount: float
    disco: str
    meter_type: str
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None

class VerifyReq(BaseModel):
    service_type: str
    identifier: str

class SavingsReq(BaseModel):
    name: str
    target_amount: float
    target_date: Optional[str] = None
    savings_type: str = "TARGET"   # FLEX | TARGET | FIXED
    term_days: Optional[int] = None  # for FIXED: 30,60,90,180,365
    auto_save: bool = False
    auto_save_amount: Optional[float] = None
    auto_save_frequency: Optional[str] = None

class SavingsConfigReq(BaseModel):
    flex_interest_rate: float = 10.0
    target_interest_rate: float = 10.0
    fixed_rate_30: float = 12.0
    fixed_rate_60: float = 14.0
    fixed_rate_90: float = 16.0
    fixed_rate_180: float = 18.0
    fixed_rate_365: float = 20.0
    min_flex_amount: float = 100.0
    min_target_amount: float = 500.0
    min_fixed_amount: float = 5000.0
    defaulter_fee_type: str = "FLAT"
    defaulter_fee_amount: float = 200.0
    defaulter_fee_percentage: float = 2.0

class LoanConfigReq(BaseModel):
    disbursement_sh_account: str = ""
    disbursement_sh_account_name: str = ""
    interest_rate_tier1: float = 8.0
    interest_rate_tier2: float = 5.0
    defaulter_fee_type: str = "FLAT"    # FLAT | PERCENTAGE
    defaulter_fee_amount: float = 500.0
    defaulter_fee_percentage: float = 2.0
    max_amount: float = 500000.0
    min_amount: float = 5000.0
    max_tenor: int = 12

# ─── Config helpers ───
async def get_savings_config() -> dict:
    doc = await db.settings.find_one({"key": "savings_config"})
    defaults = {
        "flex_interest_rate": 10.0, "target_interest_rate": 10.0,
        "fixed_rate_30": 12.0, "fixed_rate_60": 14.0, "fixed_rate_90": 16.0,
        "fixed_rate_180": 18.0, "fixed_rate_365": 20.0,
        "min_flex_amount": 100.0, "min_target_amount": 500.0, "min_fixed_amount": 5000.0,
        "defaulter_fee_type": "FLAT", "defaulter_fee_amount": 200.0, "defaulter_fee_percentage": 2.0
    }
    return {**defaults, **(doc or {}).get("value", {})}

async def get_loan_config() -> dict:
    doc = await db.settings.find_one({"key": "loan_config"})
    defaults = {
        "disbursement_sh_account": "", "disbursement_sh_account_name": "",
        "interest_rate_tier1": 8.0, "interest_rate_tier2": 5.0,
        "defaulter_fee_type": "FLAT", "defaulter_fee_amount": 500.0, "defaulter_fee_percentage": 2.0,
        "max_amount": 500000.0, "min_amount": 5000.0, "max_tenor": 12
    }
    return {**defaults, **(doc or {}).get("value", {})}

# ─── Ajo helpers ───
def _ajo_invite_code() -> str:
    return secrets.token_hex(3).upper()  # 6-char hex e.g. "A3F9C2"

def _period_due_date(start_date_str: str, period_index: int, frequency: str):
    from datetime import date as _date
    start = _date.fromisoformat(start_date_str)
    days = 7 if frequency == "WEEKLY" else 30
    return start + timedelta(days=days * period_index)

def _current_period_index(start_date_str: str, frequency: str) -> int:
    from datetime import date as date_type
    start = date_type.fromisoformat(start_date_str)
    today = datetime.now(timezone.utc).date()
    if today < start:
        return -1
    days = 7 if frequency == "WEEKLY" else 30
    return (today - start).days // days


class LoanReq(BaseModel):
    amount: float
    purpose: str
    tenor_months: int
    transaction_pin: Optional[str] = None

class LoanRepayReq(BaseModel):
    amount: float
    transaction_pin: Optional[str] = None

# ─── Ajo (Group/Rotating Savings) Models ───
class AjoCreateReq(BaseModel):
    name: str
    max_members: int          # 2–20
    contribution_amount: float
    frequency: str            # WEEKLY | MONTHLY
    start_date: str           # YYYY-MM-DD
    payout_order_method: str  # RANDOM | CREATOR | BIDDING
    one_round_only: bool = True
    transaction_pin: str

class AjoJoinReq(BaseModel):
    invite_code: str
    transaction_pin: str

class AjoContributeReq(BaseModel):
    transaction_pin: str

class AjoSetOrderReq(BaseModel):
    order: List[str]  # list of user_ids in payout position order

class AjoBidSlotReq(BaseModel):
    position: int     # 1-based slot to claim

class ContributeReq(BaseModel):
    amount: float
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None

class WebAuthnRegVerifyReq(BaseModel):
    credential: dict

class WebAuthnAuthVerifyReq(BaseModel):
    credential: dict

class KYCBVNReq(BaseModel):
    bvn: str
    date_of_birth: str

class KYCNINReq(BaseModel):
    nin: str

class KYCTierConfigUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    daily_transfer_limit_naira: Optional[int] = None
    single_transfer_limit_naira: Optional[int] = None

class KYCRevokeReq(BaseModel):
    user_id: str
    tier: int
    reason: str

class KYCApproveReq(BaseModel):
    submission_id: str
    notes: Optional[str] = None

class ProviderSettingsReq(BaseModel):
    safehaven_client_id: str
    safehaven_client_secret: str = ""   # Optional — blank = keep existing key (RSA private key PEM)
    safehaven_issuer: str = ""          # Company URL used as JWT iss claim — blank = keep existing
    safehaven_base_url: str
    safehaven_account_number: str = ""  # Platform's main Safe Haven account (for KYC debit fees)
    mode: str

class KYCInitiateReq(BaseModel):
    identity_type: str   # BVN or NIN
    identity_number: str

class KYCCreateAccountReq(BaseModel):
    identity_id: str
    otp: str
    identity_type: str
    identity_number: str

class BettingReq(BaseModel):
    platform: str
    account_id: str
    amount: float
    transaction_pin: Optional[str] = None

class BetVerifyReq(BaseModel):
    platform: str   # slug e.g. "sportybet"
    customer_id: str

class BompayTransferReq(BaseModel):
    recipient: str          # phone number OR Safe Haven virtual account number
    amount: float
    narration: Optional[str] = None
    idempotency_key: Optional[str] = None
    transaction_pin: Optional[str] = None
    biometric_token: Optional[str] = None

class SetPinReq(BaseModel):
    pin: str

class ResetPinReq(BaseModel):
    pin: str
    password: str

class VerifyPinReq(BaseModel):
    pin: str

class FeeConfigReq(BaseModel):
    service: str
    fee_type: str = "TIERED"
    flat_amount: float = 0
    percentage: float = 0
    min_fee: float = 0
    max_fee: float = 0
    tiers: List[dict] = []
    is_active: bool = True

class SupportMessageReq(BaseModel):
    message: str

class AdminReplyReq(BaseModel):
    message: str

class ChargeAccountReq(BaseModel):
    sh_account_number: str
    sh_account_name: str = ""

class SmsConfigReq(BaseModel):
    enabled: bool = True
    unit_cost_ngn: float = 4.0    # cost per SMS charged to user
    billing_day: int = 1           # day of month to run billing (1-28)

class SendoraConfigReq(BaseModel):
    api_key: str
    sender_id: str = "BOMPAY"

class BulkSmsCredentialsReq(BaseModel):
    email: str
    password: str
    sender_id: str = "BOMPAY"

class SmsProviderReq(BaseModel):
    provider: str  # SENDORA or BULKSMSLIVE

class CableValidateReq(BaseModel):
    smartcard_number: str
    provider: str   # DSTV, GOTV, STARTIMES

class MeterValidateReq(BaseModel):
    meter_number: str
    disco: str
    meter_type: str = "PREPAID"

class CheckPhoneReq(BaseModel):
    phone: str

class SendPhoneOtpReq(BaseModel):
    phone: str

class VerifyPhoneOtpReq(BaseModel):
    phone: str
    otp_code: str

class SendEmailOtpReq(BaseModel):
    phone: str
    email: EmailStr

class VerifyEmailOtpReq(BaseModel):
    phone: str
    email: EmailStr
    otp_code: str

class PhoneRegisterReq(BaseModel):
    phone: str
    otp_token: str
    first_name: str
    last_name: str
    email: Optional[EmailStr] = None
    pin: str
    referral_code: Optional[str] = None

class PhoneLoginReq(BaseModel):
    phone: str
    pin: str

class NotifPrefsReq(BaseModel):
    sms_enabled: bool = True
    email_enabled: bool = True
    in_app_enabled: bool = True

class EmailConfigReq(BaseModel):
    enabled: bool = True

class AdminRoleReq(BaseModel):
    name: str
    description: str = ""
    permissions: List[str] = []

class AdminStaffReq(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str = ""
    admin_role: str = "support"
    status: str = "ACTIVE"

class EposReportsReq(BaseModel):
    period: str = "daily"  # daily or weekly

# ===== STARTUP =====

class EposActivateReq(BaseModel):
    business_name: str
    business_type: Optional[str] = "retail"

# ===== CROSS-ROUTE HELPERS =====

async def verify_transaction_pin(user_id: str, pin: Optional[str], biometric_token: Optional[str] = None) -> None:
    """Verify transaction PIN or biometric token. Admin users exempt."""
    doc = await db.users.find_one({"_id": ObjectId(user_id)},
        {"role": 1, "pin_hash": 1, "pin_failed_attempts": 1, "pin_locked_until": 1})
    if not doc:
        raise HTTPException(404, "User not found")
    if doc.get("role") == "admin":
        return
    if not doc.get("pin_hash"):
        return  # No PIN set, allow transaction
    # Check biometric token (short-lived, 90s)
    if biometric_token:
        now_iso = datetime.now(timezone.utc).isoformat()
        bt = await db.biometric_tokens.find_one({"user_id": user_id, "token": biometric_token})
        if bt and bt.get("expires_at", "") > now_iso:
            await db.biometric_tokens.delete_one({"_id": bt["_id"]})
            return
        raise HTTPException(401, "Biometric token invalid or expired")
    if not pin:
        raise HTTPException(401, "Transaction PIN required")
    if not pin.isdigit() or len(pin) != 4:
        raise HTTPException(401, "Invalid PIN format")
    now = datetime.now(timezone.utc).isoformat()
    locked_until = doc.get("pin_locked_until")
    if locked_until and locked_until > now:
        raise HTTPException(401, "PIN locked. Try again in 15 minutes.")
    if not verify_pin_hash(pin, doc["pin_hash"]):
        attempts = int(doc.get("pin_failed_attempts", 0)) + 1
        update: dict = {"$set": {"pin_failed_attempts": attempts}}
        if attempts >= 5:
            update["$set"]["pin_locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        await db.users.update_one({"_id": ObjectId(user_id)}, update)
        raise HTTPException(401, "Incorrect transaction PIN")
    await db.users.update_one({"_id": ObjectId(user_id)},
        {"$set": {"pin_failed_attempts": 0, "pin_locked_until": None}})


async def get_nip_fee(amount_ngn: float) -> float:
    """NIP fee: reads admin-configurable tiers from DB, falls back to standard NIBSS tiers."""
    try:
        config = await db.sh_fee_config.find_one({"type": "NIP_FEE_TIERS"})
        if config and config.get("tiers"):
            for tier in sorted(config["tiers"], key=lambda t: t.get("max_amount", 1e18)):
                if amount_ngn <= tier.get("max_amount", 1e18):
                    return float(tier["fee"])
    except Exception:
        pass
    # Standard NIBSS NIP fallback
    if amount_ngn <= 5_000:   return 10.0
    if amount_ngn <= 50_000:  return 25.0
    return 50.0

async def _sweep_fee_margin(
    txn_id: str, user_account: str,
    bompay_fee_ngn: float, sh_fee_ngn: float, category: str
):
    """Sweep BOMPAY margin to charge account; queue for retry on failure; alert on high balance."""
    margin = round(bompay_fee_ngn - sh_fee_ngn, 2)
    if margin < 0.50:
        return
    try:
        charge_doc = await db.charge_accounts.find_one({"category": category})
        charge_acct_num = (charge_doc or {}).get("sh_account_number", "").strip()
        if not charge_acct_num or not user_account:
            logger.warning(f"[FeeSwept] No charge account for {category} — queuing ₦{margin:.2f}")
            await _queue_pending_sweep(txn_id, user_account, bompay_fee_ngn, sh_fee_ngn, margin, category, "No charge account")
            return
        ne = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": SAFEHAVEN_OWN_BANK_CODE, "accountNumber": charge_acct_num
        })
        ne_ref = ne.get("data", {}).get("sessionId") or f"CHG{txn_id}"
        margin_ref = f"FEE{txn_id}"
        await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": ne_ref,
            "debitAccountNumber": user_account,
            "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
            "beneficiaryAccountNumber": charge_acct_num,
            "amount": margin,
            "saveBeneficiary": False,
            "narration": f"BOMPAY fee margin {txn_id}",
            "paymentReference": margin_ref
        })
        await db.transactions.insert_one({
            "transaction_id": margin_ref, "user_id": "PLATFORM",
            "type": "FEE_SWEEP", "direction": "CREDIT", "amount": int(margin * 100), "fee": 0,
            "currency": "NGN", "status": "COMPLETED", "provider": "SAFEHAVEN",
            "description": f"Fee sweep for {txn_id}",
            "metadata": {"source_txn": txn_id, "charge_account": charge_acct_num, "category": category,
                         "bompay_fee": bompay_fee_ngn, "sh_fee": sh_fee_ngn, "margin": margin},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        })
        # Update cumulative and check high-balance threshold
        updated_ca = await db.charge_accounts.find_one_and_update(
            {"category": category},
            {"$inc": {"total_swept_kobo": int(margin * 100)}},
            return_document=True
        )
        await _check_high_balance_alert(category, updated_ca)
        logger.info(f"[FeeSwept] {txn_id} ₦{margin:.2f} → {charge_acct_num} ({category})")
    except Exception as e:
        logger.error(f"[FeeSwept] Failed {txn_id}: {e}")
        await _queue_pending_sweep(txn_id, user_account, bompay_fee_ngn, sh_fee_ngn, margin, category, str(e))

async def _queue_pending_sweep(txn_id, user_account, bompay_fee_ngn, sh_fee_ngn, margin, category, reason):
    try:
        exists = await db.pending_fee_sweeps.find_one({"txn_id": txn_id})
        if exists:
            return
        await db.pending_fee_sweeps.insert_one({
            "txn_id": txn_id, "user_account": user_account,
            "bompay_fee_ngn": bompay_fee_ngn, "sh_fee_ngn": sh_fee_ngn,
            "margin": margin, "category": category, "reason": reason,
            "retries": 0, "status": "PENDING",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "next_retry_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        })
    except Exception as qe:
        logger.error(f"[FeeQueue] Could not queue {txn_id}: {qe}")

async def _check_high_balance_alert(category: str, charge_doc: Optional[dict]):
    if not charge_doc:
        return
    threshold_ngn = float(charge_doc.get("alert_threshold_ngn", 0))
    if threshold_ngn <= 0:
        return
    total_ngn = charge_doc.get("total_swept_kobo", 0) / 100
    if total_ngn < threshold_ngn:
        return
    last_alert = charge_doc.get("last_alert_at", "")
    now = datetime.now(timezone.utc)
    if last_alert:
        try:
            la = datetime.fromisoformat(last_alert.replace("Z", "+00:00"))
            if (now - la) < timedelta(hours=6):
                return
        except Exception:
            pass
    admins = await db.users.find({"role": "admin"}).to_list(10)
    for au in admins:
        await db.notifications.insert_one({
            "notification_id": str(uuid.uuid4()), "user_id": au["_id"],
            "title": f"High Balance Alert: {category.replace('_', ' ').title()}",
            "message": (f"Cumulative fee sweeps for {category} have reached "
                        f"₦{total_ngn:,.2f} (threshold: ₦{threshold_ngn:,.2f}). "
                        f"Consider sweeping to your master account."),
            "type": "warning", "is_read": False,
            "created_at": now.isoformat()
        })
    await db.charge_accounts.update_one({"category": category}, {"$set": {"last_alert_at": now.isoformat()}})
    logger.info(f"[HighBalance] Alert sent for {category} at ₦{total_ngn:,.2f}")

async def calculate_fee(service: str, amount_ngn: float) -> float:
    """Return fee in NGN for a given service and amount."""
    config = await db.fee_configs.find_one({"service": service, "is_active": True})
    if not config:
        if service == "TRANSFER":
            return min(max(10, amount_ngn * 0.01), 100)
        return 0
    fee_type = config.get("fee_type", "TIERED")
    if fee_type == "FLAT":
        return float(config.get("flat_amount", 0))
    elif fee_type == "PERCENTAGE":
        fee = amount_ngn * (config.get("percentage", 0) / 100)
        min_f = config.get("min_fee", 0)
        max_f = config.get("max_fee", 0)
        if max_f > 0:
            return min(max(min_f, fee), max_f)
        return max(min_f, fee)
    elif fee_type == "TIERED":
        tiers = sorted(config.get("tiers", []), key=lambda t: t["min"])
        for tier in tiers:
            if amount_ngn >= tier["min"] and amount_ngn < tier.get("max", float("inf")):
                return float(tier["fee"])
        if tiers:
            return float(tiers[-1]["fee"])
    return 0

# ===== WEBAUTHN HELPERS =====
def _parse_reg_credential(data: dict) -> RegistrationCredential:
    return RegistrationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(data["response"]["clientDataJSON"]),
            attestation_object=base64url_to_bytes(data["response"]["attestationObject"]),
        ),
        authenticator_attachment=data.get("authenticatorAttachment"),
    )

def _parse_auth_credential(data: dict) -> AuthenticationCredential:
    resp = data["response"]
    return AuthenticationCredential(
        id=data["id"],
        raw_id=base64url_to_bytes(data["rawId"]),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(resp["clientDataJSON"]),
            authenticator_data=base64url_to_bytes(resp["authenticatorData"]),
            signature=base64url_to_bytes(resp["signature"]),
            user_handle=base64url_to_bytes(resp["userHandle"]) if resp.get("userHandle") else None,
        ),
    )


async def get_sh_subaccount_balance(account_id: str) -> float:
    """Fetch the live Safe Haven sub-account balance."""
    try:
        r = await call_sh("GET", f"/accounts/{account_id}")
        return float((r.get("data") or {}).get("accountBalance", 0))
    except Exception:
        return 0.0

async def require_virtual_account(user: dict):
    """Raise 403 if user hasn't created their Safe Haven virtual account yet."""
    if user.get("role") == "admin":
        return
    wallet = await db.wallets.find_one({"user_id": user["_id"]})
    if not (wallet or {}).get("sh_account_number"):
        raise HTTPException(403, detail={
            "code": "VIRTUAL_ACCOUNT_REQUIRED",
            "message": "Please complete your KYC verification to activate your account before performing transactions."
        })

def _ajo_member_info(m: dict, users_cache: dict) -> dict:
    u = users_cache.get(str(m["user_id"]), {})
    return {
        "user_id": str(m["user_id"]),
        "display_name": u.get("display_name") or f"{u.get('first_name','')} {u.get('last_name','')}".strip() or "Unknown",
        "status": m["status"],
        "payout_position": m.get("payout_position"),
        "consecutive_default_days": m.get("consecutive_default_days", 0),
        "joined_at": m.get("joined_at"),
    }


async def _build_ajo_detail(group: dict, current_user_id: str = "") -> dict:
    """Enrich a group doc with member list, contributions and pending payout info."""
    gid = group["group_id"]
    members_raw = await db.ajo_members.find({"group_id": gid, "status": {"$ne": "LEFT"}}, {"_id": 0}).to_list(50)
    user_ids = [m["user_id"] for m in members_raw]
    users_raw = await db.users.find({"_id": {"$in": [ObjectId(uid) for uid in user_ids]}},
                                     {"first_name": 1, "last_name": 1, "display_name": 1}).to_list(50)
    users_cache = {str(u["_id"]): u for u in users_raw}
    members = [_ajo_member_info(m, users_cache) for m in members_raw]

    period_idx = _current_period_index(group["start_date"], group["frequency"]) if group["status"] == "ACTIVE" else -1
    due_date = _period_due_date(group["start_date"], max(period_idx, 0), group["frequency"]).isoformat() if period_idx >= 0 else None

    # Contributions for current period
    contributions = []
    if period_idx >= 0:
        contribs = await db.ajo_contributions.find(
            {"group_id": gid, "round": group.get("current_round", 1), "period_index": period_idx}, {"_id": 0}
        ).to_list(50)
        contrib_map = {c["user_id"]: c for c in contribs}
        for m in members_raw:
            c = contrib_map.get(m["user_id"], {})
            u = users_cache.get(str(m["user_id"]), {})
            contributions.append({
                "user_id": m["user_id"],
                "display_name": f"{u.get('first_name','')} {u.get('last_name','')}".strip() or "Unknown",
                "status": c.get("status", "DUE"),
                "paid_at": c.get("paid_at"),
                "days_overdue": c.get("days_overdue", 0),
            })

    # Pending payout for current user
    pending_payout = None
    if current_user_id:
        pp = await db.ajo_payouts.find_one({"group_id": gid, "recipient_user_id": current_user_id, "status": "PENDING"}, {"_id": 0})
        if pp:
            pending_payout = {"payout_id": pp["payout_id"], "amount": pp["amount"], "period_index": pp["period_index"]}

    # Bidding: which slots are taken
    taken_positions = {m.get("payout_position") for m in members_raw if m.get("payout_position") is not None}
    available_slots = [i + 1 for i in range(group["max_members"]) if (i + 1) not in taken_positions]

    return {**group, "members": members, "member_count": len(members_raw),
            "period_index": period_idx, "current_period_due_date": due_date,
            "contributions": contributions, "pending_payout": pending_payout,
            "available_slots": available_slots if group.get("payout_order_method") == "BIDDING" else []}



async def _handle_sh_transfer_reversal(data: dict, eid: str) -> None:
    """
    Called when Safe Haven reverses an outgoing transfer.
    Finds the original BOMPAY transaction, credits wallet back, marks original as REVERSED.
    Idempotent via reversal_ref.
    """
    try:
        # Locate original transaction by Safe Haven paymentReference or sessionId
        orig_ref = data.get("paymentReference") or data.get("sessionId") or data.get("reference", "")
        amount = float(data.get("amount", 0))
        debit_acct_num = data.get("debitAccountNumber", "")

        if not orig_ref and not debit_acct_num:
            logger.warning(f"[SH Reversal] Insufficient data to process reversal event_id={eid}")
            return

        # Idempotency key for this reversal
        rev_ref = f"REV_{orig_ref or eid}"
        if await db.transactions.find_one({"provider_reference": rev_ref}):
            logger.info(f"[SH Reversal] Already processed {rev_ref}")
            return

        # Find the original BOMPAY transaction
        orig_txn = None
        if orig_ref:
            orig_txn = await db.transactions.find_one({
                "$or": [
                    {"provider_reference": orig_ref},
                    {"transaction_id": orig_ref},
                    {"metadata.payment_reference": orig_ref},
                ]
            })
        if not orig_txn and debit_acct_num:
            # Fallback: find by wallet account number + approximate amount + DEBIT direction
            wallet = await db.wallets.find_one({"sh_account_number": debit_acct_num})
            if wallet:
                amt_kobo = int(amount * 100)
                orig_txn = await db.transactions.find_one({
                    "user_id": wallet["user_id"], "direction": "DEBIT",
                    "amount": {"$gte": amt_kobo - 100, "$lte": amt_kobo + 100},
                    "status": "COMPLETED", "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]},
                })

        if not orig_txn:
            logger.warning(f"[SH Reversal] Original txn not found for ref={orig_ref}")
            return

        user_id = orig_txn["user_id"]
        refund_amt = orig_txn["amount"]  # Credit back original amount + fee
        orig_fee = orig_txn.get("fee", 0)
        total_refund = refund_amt + orig_fee
        now_iso = datetime.now(timezone.utc).isoformat()
        rev_txn_id = f"TXN{secrets.token_hex(12).upper()}"

        # Mark original as REVERSED
        await db.transactions.update_one(
            {"transaction_id": orig_txn["transaction_id"]},
            {"$set": {"status": "REVERSED", "reversed_at": now_iso,
                      "reversal_ref": rev_ref, "updated_at": now_iso}}
        )

        # Credit wallet back (amount + fee)
        await db.transactions.insert_one({
            "transaction_id": rev_txn_id, "user_id": user_id,
            "type": "TRANSFER_REVERSAL", "direction": "CREDIT",
            "amount": total_refund, "fee": 0, "vat": 0, "currency": "NGN",
            "status": "COMPLETED", "provider": "SAFEHAVEN",
            "description": f"Reversal: {orig_txn.get('description', 'Transfer reversed by Safe Haven')}",
            "provider_reference": rev_ref,
            "metadata": {"original_txn_id": orig_txn["transaction_id"], "event_id": eid},
            "created_at": now_iso, "updated_at": now_iso,
        })
        await db.wallets.update_one({"user_id": user_id},
            {"$inc": {"available_balance": total_refund, "ledger_balance": total_refund}})
        w = await get_wallet(user_id)
        await ledger_entry(user_id, w["_id"], rev_txn_id, "CREDIT", total_refund, "Transfer Reversal")
        await notify(user_id, "Transfer Reversed",
                     f"₦{total_refund/100:,.2f} refunded — your earlier transfer was reversed by the bank. "
                     f"New balance: ₦{w['available_balance']/100:,.2f}", "info")
        logger.info(f"[SH Reversal] Processed: uid={user_id} refund=₦{total_refund/100:,.2f} rev_ref={rev_ref}")
    except Exception as e:
        logger.error(f"[SH Reversal] Handler error eid={eid}: {e}")




async def _handle_sh_transfer_failure(data: dict, eid: str) -> None:
    """
    Called when Safe Haven asynchronously reports a transfer as failed/declined.
    Same flow as reversal: credit wallet back and mark original as FAILED.
    """
    try:
        orig_ref = data.get("paymentReference") or data.get("reference", "")
        fail_ref = f"FAIL_{orig_ref or eid}"
        if await db.transactions.find_one({"provider_reference": fail_ref}):
            return
        orig_txn = None
        if orig_ref:
            orig_txn = await db.transactions.find_one({
                "$or": [{"provider_reference": orig_ref}, {"transaction_id": orig_ref}]
            })
        if not orig_txn:
            logger.warning(f"[SH Failure] Original txn not found for ref={orig_ref}")
            return

        # Skip if already reversed/failed/refunded
        if orig_txn.get("status") in ("REVERSED", "FAILED", "REFUNDED"):
            return

        user_id = orig_txn["user_id"]
        total_refund = orig_txn["amount"] + orig_txn.get("fee", 0)
        now_iso = datetime.now(timezone.utc).isoformat()
        fail_txn_id = f"TXN{secrets.token_hex(12).upper()}"

        await db.transactions.update_one(
            {"transaction_id": orig_txn["transaction_id"]},
            {"$set": {"status": "FAILED", "failed_at": now_iso, "failure_ref": fail_ref, "updated_at": now_iso}}
        )
        await db.transactions.insert_one({
            "transaction_id": fail_txn_id, "user_id": user_id,
            "type": "TRANSFER_REVERSAL", "direction": "CREDIT",
            "amount": total_refund, "fee": 0, "vat": 0, "currency": "NGN",
            "status": "COMPLETED", "provider": "SAFEHAVEN",
            "description": f"Refund: transfer failed — {orig_txn.get('description', '')}",
            "provider_reference": fail_ref,
            "metadata": {"original_txn_id": orig_txn["transaction_id"], "event_id": eid},
            "created_at": now_iso, "updated_at": now_iso,
        })
        await db.wallets.update_one({"user_id": user_id},
            {"$inc": {"available_balance": total_refund, "ledger_balance": total_refund}})
        w = await get_wallet(user_id)
        await notify(user_id, "Transfer Failed — Refunded",
                     f"₦{total_refund/100:,.2f} refunded — your transfer could not be completed. "
                     f"New balance: ₦{w['available_balance']/100:,.2f}", "warning")
        logger.info(f"[SH Failure] Refund processed: uid={user_id} refund=₦{total_refund/100:,.2f}")
    except Exception as e:
        logger.error(f"[SH Failure] Handler error eid={eid}: {e}")




def _verify_cron(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth[7:]
    if not WEBHOOK_CRON_SECRET or not secrets.compare_digest(token.encode(), WEBHOOK_CRON_SECRET.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")



async def _run_auto_save(run_id: str):
    now = datetime.now(timezone.utc)
    goals = await db.savings_goals.find({"auto_save": True, "auto_save_amount": {"$gt": 0}, "status": "ACTIVE"}).to_list(2000)
    cfg = await get_savings_config()
    for goal in goals:
        freq = goal.get("auto_save_frequency", "WEEKLY")
        last_auto = goal.get("last_auto_save")
        if last_auto:
            try:
                last_dt = datetime.fromisoformat(last_auto)
                days = (now - last_dt).days
                if (freq == "WEEKLY" and days < 7) or (freq == "MONTHLY" and days < 28):
                    continue
            except (ValueError, TypeError):
                pass
        amt = goal.get("auto_save_amount", 0)
        user_id = goal["user_id"]
        idem = f"autosave-{goal['goal_id']}-{run_id}"
        if await db.transactions.find_one({"idempotency_key": idem}):
            continue
        # ─── Atomic debit ───
        updated_w = await db.wallets.find_one_and_update(
            {"user_id": user_id, "available_balance": {"$gte": amt}},
            {"$inc": {"available_balance": -amt, "ledger_balance": -amt}},
            return_document=True
        )
        if not updated_w:
            # ─── Defaulter fee ───
            fee_type = cfg.get("defaulter_fee_type", "FLAT")
            fee_amt = int(cfg.get("defaulter_fee_amount", 200.0) * 100) if fee_type == "FLAT" \
                else int(amt * cfg.get("defaulter_fee_percentage", 2.0) / 100)
            if fee_amt > 0:
                fee_deducted = await db.wallets.find_one_and_update(
                    {"user_id": user_id, "available_balance": {"$gte": fee_amt}},
                    {"$inc": {"available_balance": -fee_amt, "ledger_balance": -fee_amt}},
                    return_document=True
                )
                if fee_deducted:
                    fee_txn_id = f"TXN{secrets.token_hex(12).upper()}"
                    await db.transactions.insert_one({
                        "transaction_id": fee_txn_id, "idempotency_key": f"fee-{idem}",
                        "user_id": user_id, "type": "SAVINGS_DEFAULTER_FEE", "direction": "DEBIT",
                        "amount": fee_amt, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
                        "provider": "INTERNAL", "description": f"Missed auto-save defaulter fee: {goal['name']}",
                        "metadata": {"goal_id": goal["goal_id"]},
                        "created_at": now.isoformat(), "updated_at": now.isoformat()
                    })
            await notify(user_id, "Auto-Save Missed", f"Insufficient balance for '{goal['name']}'. Defaulter fee applied.", "warning")
            continue
        txn_id = f"TXN{secrets.token_hex(12).upper()}"
        await db.transactions.insert_one({
            "transaction_id": txn_id, "idempotency_key": idem, "user_id": user_id,
            "type": "SAVINGS_CONTRIBUTION", "direction": "DEBIT", "amount": amt,
            "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"Auto-save: {goal['name']}", "metadata": {"goal_id": goal["goal_id"], "auto": True},
            "created_at": now.isoformat(), "updated_at": now.isoformat()
        })
        await db.savings_goals.update_one({"goal_id": goal["goal_id"]},
            {"$inc": {"current_amount": amt}, "$set": {"last_auto_save": now.isoformat()}})
        # SH sweep
        try:
            savings_acct = await db.charge_accounts.find_one({"category": "SAVINGS_PROCEEDS"})
            sh_dest = (savings_acct or {}).get("sh_account_number", "")
            wallet_doc = await db.wallets.find_one({"user_id": user_id})
            user_sh = (wallet_doc or {}).get("sh_account_number", "")
            if sh_dest and user_sh:
                await call_sh("POST", "/transfers", body={
                    "debitAccountNumber": user_sh, "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                    "beneficiaryAccountNumber": sh_dest, "amount": amt / 100,
                    "saveBeneficiary": False, "narration": f"BOMPAY auto-save {goal['name'][:20]}",
                    "paymentReference": txn_id
                })
        except Exception as e:
            logger.warning(f"[AutoSave] SH sweep failed: {e}")
        await notify(user_id, "Auto-Save Complete", f"₦{amt/100:,.2f} auto-saved to '{goal['name']}'.", "success")



async def _run_loan_reminders(run_id: str):
    now = datetime.now(timezone.utc)
    loans = await db.loan_applications.find({"status": "DISBURSED", "due_date": {"$exists": True}}).to_list(2000)
    for loan in loans:
        due = loan.get("due_date")
        if not due:
            continue
        try:
            due_dt = datetime.fromisoformat(due)
            days_left = (due_dt - now).days
            if 0 <= days_left <= 3:
                idem = f"loanrem-{loan['loan_id']}-{due[:10]}"
                if await db.notifications.find_one({"metadata.idempotency_key": idem}):
                    continue
                day_word = "today" if days_left == 0 else (f"in {days_left} day{'s' if days_left > 1 else ''}")
                await db.notifications.insert_one({
                    "notification_id": str(uuid.uuid4()), "user_id": loan["user_id"],
                    "title": "Loan Payment Due Soon",
                    "message": f"Your repayment of ₦{loan.get('monthly_payment',0):,.2f} is due {day_word}.",
                    "type": "warning", "read": False,
                    "metadata": {"idempotency_key": idem, "loan_id": loan["loan_id"]},
                    "created_at": now.isoformat()
                })
        except (ValueError, TypeError):
            continue



async def _complete_epos_txn_bg(merchant_user_id: str, amount_kobo: int, channel: str = "BANK"):
    """Auto-complete matching pending ePOS transaction when a credit arrives."""
    try:
        pending = await db.epos_transactions.find(
            {"merchant_user_id": merchant_user_id, "status": "PENDING", "amount_kobo": amount_kobo}
        ).sort("created_at", -1).limit(1).to_list(1)
        if not pending:
            return
        txn = pending[0]
        await db.epos_transactions.update_one(
            {"_id": txn["_id"]},
            {"$set": {"status": "COMPLETED", "channel": channel, "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        naira = amount_kobo / 100
        await notify(merchant_user_id, "Payment Received!", f"₦{naira:,.2f} received via {channel}", "success")
    except Exception:
        pass

async def get_rewards_config():
    doc = await db.admin_config.find_one({"key": "rewards_config"})
    defaults = {
        "cashback_enabled": True, "referral_enabled": True,
        "signup_bonus_naira": 0.0,
        "referral_bonus_referrer_naira": 500.0, "referral_bonus_referee_naira": 500.0,
        "min_referral_txn_naira": 300.0,
        "airtime_cashback_pct": 1.5, "data_cashback_pct": 1.5,
        "electricity_cashback_pct": 1.0, "cable_cashback_pct": 1.0,
        "transfer_cashback_pct": 0.5, "betting_cashback_pct": 0.5,
        "max_cashback_per_txn_naira": 500.0,
    }
    if doc:
        return {**defaults, **doc.get("value", {})}
    return defaults


class ResendSettingsReq(BaseModel):
    api_key: str = ""
    from_name: str = "BOMPAY"
    from_email: str = "no-reply@bompay.ng"


class CloudinarySettingsReq(BaseModel):
    cloud_name: str
    api_key: str
    api_secret: str = ""  # blank = keep existing


# ===== VAS HELPERS (shared across routes) =====
async def _sh_vas_sweep(user_id: str, amount_kobo: int, txn_id: str, narration: str) -> None:
    """Fire-and-forget: mirror VAS deduction on user's Safe Haven virtual account."""
    try:
        user_wallet = await db.wallets.find_one({"user_id": user_id})
        user_sh = (user_wallet or {}).get("sh_account_number", "")
        if not user_sh:
            return
        vas_acct = await db.charge_accounts.find_one({"category": "VAS_FEES"})
        vas_sh = (vas_acct or {}).get("sh_account_number", "")
        if not vas_sh:
            logger.warning(f"[VAS Sweep] No VAS_FEES charge account configured — txn {txn_id} not swept")
            return
        await call_sh("POST", "/transfers", body={
            "debitAccountNumber": user_sh,
            "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
            "beneficiaryAccountNumber": vas_sh,
            "amount": amount_kobo / 100,
            "saveBeneficiary": False,
            "narration": f"BMPAY VAS {narration[:30]}",
            "paymentReference": f"VAS_{txn_id}",
        })
        logger.info(f"[VAS Sweep] SH debit OK txn={txn_id} ₦{amount_kobo/100:,.2f}")
    except Exception as e:
        logger.warning(f"[VAS Sweep] SH debit failed txn={txn_id}: {e}")


async def vas_debit(user_id: str, amount_kobo: int, idem: str, txn_type: str, desc: str, meta: dict):
    existing = await db.transactions.find_one({"idempotency_key": idem})
    if existing:
        return existing["transaction_id"], True
    w = await get_wallet(user_id)
    if w["available_balance"] < amount_kobo:
        raise HTTPException(400, "Insufficient funds")
    bal_before = w["available_balance"]
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": idem, "user_id": user_id,
        "type": txn_type, "direction": "DEBIT", "amount": amount_kobo, "fee": 0,
        "vat": 0, "currency": "NGN", "status": "PROCESSING", "provider": "SAFEHAVEN",
        "description": desc, "metadata": meta,
        "balance_before_kobo": bal_before,
        "balance_after_kobo": bal_before - amount_kobo,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })
    updated = await db.wallets.find_one_and_update(
        {"user_id": user_id, "available_balance": {"$gte": amount_kobo}},
        {"$inc": {"available_balance": -amount_kobo, "ledger_balance": -amount_kobo}},
        return_document=True
    )
    if not updated:
        await db.transactions.update_one({"transaction_id": txn_id}, {"$set": {"status": "FAILED"}})
        raise HTTPException(400, "Insufficient funds")
    return txn_id, False


async def vas_complete(user_id: str, txn_id: str, amount_kobo: int, pref: str,
                       notif_title: str, notif_msg: str, points: int = 0):
    w = await get_wallet(user_id)
    await db.transactions.update_one({"transaction_id": txn_id}, {"$set": {
        "status": "COMPLETED", "provider_reference": pref, "updated_at": datetime.now(timezone.utc).isoformat()
    }})
    await ledger_entry(user_id, w["_id"], txn_id, "DEBIT", amount_kobo, notif_title)
    if points > 0:
        await db.users.update_one({"_id": ObjectId(user_id)}, {"$inc": {"reward_points": points}})
    await notify(user_id, notif_title, notif_msg, "success")
    asyncio.create_task(_sh_vas_sweep(user_id, amount_kobo, txn_id, notif_title))


async def vas_refund(user_id: str, txn_id: str, amount_kobo: int, title: str):
    await db.wallets.update_one({"user_id": user_id},
        {"$inc": {"available_balance": amount_kobo, "ledger_balance": amount_kobo}})
    await db.transactions.update_one({"transaction_id": txn_id}, {"$set": {"status": "FAILED"}})
    await notify(user_id, title, "Payment failed. Funds reversed.", "error")


# ===== REWARDS / REFERRAL HELPERS =====
async def _credit_cashback_bg(user_id: str, amount_naira: float, txn_type: str, description: str):
    try:
        cfg = await get_rewards_config()
        if not cfg.get("cashback_enabled"):
            return
        rate_key = {"AIRTIME": "airtime_cashback_pct", "DATA": "data_cashback_pct",
                    "ELECTRICITY": "electricity_cashback_pct", "CABLE_TV": "cable_cashback_pct",
                    "CABLE": "cable_cashback_pct", "BETTING": "betting_cashback_pct",
                    "TRANSFER": "transfer_cashback_pct"}.get(txn_type)
        if not rate_key:
            return
        rate = cfg.get(rate_key, 0)
        if rate <= 0:
            return
        cashback_naira = min(round(amount_naira * rate / 100, 2), cfg.get("max_cashback_per_txn_naira", 500))
        if cashback_naira < 0.01:
            return
        cashback_kobo = int(cashback_naira * 100)
        await db.users.update_one({"_id": ObjectId(user_id)}, {"$inc": {"cashback_balance": cashback_kobo}})
        await db.cashback_history.insert_one({
            "user_id": user_id, "amount_kobo": cashback_kobo, "type": txn_type,
            "description": description, "cashback_naira": cashback_naira,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        await notify(user_id, "Cashback Earned!", f"₦{cashback_naira:,.2f} cashback added to rewards", "success")
        if txn_type != "TRANSFER":
            asyncio.create_task(send_event_notification(user_id, "CASHBACK_EARNED", {
                "amount": cashback_naira, "service": description
            }))
    except Exception:
        pass


async def _check_referral_bg(user_id: str, amount_naira: float):
    try:
        cfg = await get_rewards_config()
        if not cfg.get("referral_enabled"):
            return
        if amount_naira < cfg.get("min_referral_txn_naira", 300):
            return
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user or user.get("referral_credited"):
            return
        referred_by_code = user.get("referred_by")
        if not referred_by_code:
            return
        referrer = await db.users.find_one({"referral_code": referred_by_code})
        if not referrer:
            return
        now = datetime.now(timezone.utc).isoformat()
        referee_bonus_kobo = int(cfg.get("referral_bonus_referee_naira", 500) * 100)
        referrer_bonus_kobo = int(cfg.get("referral_bonus_referrer_naira", 500) * 100)
        if referee_bonus_kobo > 0:
            await db.users.update_one({"_id": ObjectId(user_id)}, {"$inc": {"referral_balance": referee_bonus_kobo}})
            await db.referral_history.insert_one({
                "user_id": user_id, "role": "REFEREE", "referrer_id": str(referrer["_id"]),
                "amount_kobo": referee_bonus_kobo,
                "description": f"Referral bonus for joining via {referred_by_code}",
                "created_at": now
            })
            await notify(user_id, "Referral Bonus!", f"₦{cfg.get('referral_bonus_referee_naira', 500):,.0f} referral bonus added!", "success")
            asyncio.create_task(send_event_notification(user_id, "REFERRAL_BONUS", {
                "amount": cfg.get("referral_bonus_referee_naira", 500),
                "note": f"You joined via a referral code."
            }))
        if referrer_bonus_kobo > 0:
            await db.users.update_one({"_id": ObjectId(referrer["_id"])}, {"$inc": {"referral_balance": referrer_bonus_kobo}})
            await db.referral_history.insert_one({
                "user_id": str(referrer["_id"]), "role": "REFERRER", "referee_id": user_id,
                "amount_kobo": referrer_bonus_kobo,
                "description": f"You referred {user.get('first_name', 'a friend')}",
                "created_at": now
            })
            await notify(str(referrer["_id"]), "Referral Bonus!", f"₦{cfg.get('referral_bonus_referrer_naira', 500):,.0f} earned for referring {user.get('first_name', 'a friend')}!", "success")
            asyncio.create_task(send_event_notification(str(referrer["_id"]), "REFERRAL_BONUS", {
                "amount": cfg.get("referral_bonus_referrer_naira", 500),
                "note": f"Your friend {user.get('first_name', '')} just qualified."
            }))
        await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"referral_credited": True}})
    except Exception:
        pass


# ===== SMS BILLING HELPER =====
async def _run_sms_billing(run_id: str):
    """Debit each user's wallet + SH account for their monthly SMS usage."""
    cfg = await get_sms_config()
    if not cfg.get("enabled", True):
        logger.info("[SMS Billing] disabled, skipping")
        return
    unit_cost = cfg.get("unit_cost_ngn", 4.0)
    acct_doc = await db.charge_accounts.find_one({"category": "SMS_CHARGES"})
    sh_charge_acct = (acct_doc or {}).get("sh_account_number", "")
    now = datetime.now(timezone.utc)
    billing_month = now.strftime("%Y-%m")
    users = await db.users.find({"role": {"$ne": "admin"}}, {"_id": 1}).to_list(10000)
    billed = 0
    for u in users:
        uid = str(u["_id"])
        idem = f"sms-billing-{billing_month}-{uid}"
        if await db.transactions.find_one({"idempotency_key": idem}):
            continue
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        sent_count = await db.sms_logs.count_documents({
            "user_id": uid, "status": "SENT", "created_at": {"$gte": month_start}
        })
        total_count = await db.sms_logs.count_documents({
            "user_id": uid, "created_at": {"$gte": month_start}
        })
        if total_count == 0:
            continue
        charge_ngn = round(total_count * unit_cost, 2)
        charge_kobo = int(charge_ngn * 100)
        w = await db.wallets.find_one({"user_id": uid})
        if not w:
            continue
        updated = await db.wallets.find_one_and_update(
            {"user_id": uid, "available_balance": {"$gte": charge_kobo}},
            {"$inc": {"available_balance": -charge_kobo, "ledger_balance": -charge_kobo}},
            return_document=True
        )
        if not updated:
            logger.warning(f"[SMS Billing] Insufficient funds for user {uid}, charge NGN{charge_ngn}")
            continue
        txn_id = f"SMSB{secrets.token_hex(10).upper()}"
        await db.transactions.insert_one({
            "transaction_id": txn_id, "idempotency_key": idem, "user_id": uid,
            "type": "SMS_CHARGE", "direction": "DEBIT", "amount": charge_kobo, "fee": 0,
            "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"SMS notification charges — {billing_month} ({total_count} messages)",
            "metadata": {"billing_month": billing_month, "sms_count": total_count, "unit_cost": unit_cost, "run_id": run_id},
            "created_at": now.isoformat(), "updated_at": now.isoformat()
        })
        await notify(uid, "SMS Charges Billed",
            f"₦{charge_ngn:,.2f} deducted for {total_count} SMS notifications in {billing_month}.", "info")
        if sh_charge_acct:
            try:
                sender_w = await db.wallets.find_one({"user_id": uid})
                if sender_w and sender_w.get("sh_account_number"):
                    await call_sh("POST", "/transfers", body={
                        "debitAccountNumber": sender_w["sh_account_number"],
                        "beneficiaryBankCode": "090286",
                        "beneficiaryAccountNumber": sh_charge_acct,
                        "amount": charge_ngn,
                        "saveBeneficiary": False,
                        "narration": f"BOMPAY SMS charges {billing_month}",
                        "paymentReference": txn_id
                    })
            except Exception as e:
                logger.warning(f"[SMS Billing] SH transfer failed for user {uid}: {e}")
        billed += 1
    logger.info(f"[SMS Billing] run_id={run_id} billed {billed} users for {billing_month}")
