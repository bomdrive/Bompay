"""Bompay — Auth & WebAuthn routes."""
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
from models import *  # noqa: F401,F403,F405
from core import (  # noqa: F401,F403,F405
    RegisterReq,
    LoginReq,
    MIME_EXT,
    SetPinReq,
    VerifyPinReq,
    ResetPinReq,
    CheckPhoneReq,
    SendPhoneOtpReq,
    VerifyPhoneOtpReq,
    SendEmailOtpReq,
    VerifyEmailOtpReq,
    PhoneRegisterReq,
    PhoneLoginReq,
    NotifPrefsReq,
    WebAuthnRegVerifyReq,
    WebAuthnAuthVerifyReq,
    BaseModel,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/health")
async def health():
    return {"status": "ok", "service": "bompay-api"}

# ===== AUTH ROUTES =====
@router.post("/auth/register")
async def register(req: RegisterReq, response: Response):
    email = req.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    if req.phone and await db.users.find_one({"phone": req.phone}):
        raise HTTPException(400, "Phone number already registered")
    if len(req.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    ref_code = secrets.token_hex(4).upper()
    res = await db.users.insert_one({
        "email": email, "password_hash": hash_password(req.password),
        "first_name": req.first_name, "last_name": req.last_name, "phone": req.phone,
        "role": "user", "status": "ACTIVE", "kyc_tier": 0, "kyc_status": "PENDING",
        "referral_code": ref_code, "referred_by": req.referral_code, "reward_points": 500,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    uid = str(res.inserted_id)
    acct = gen_account_number()
    while await db.wallets.find_one({"account_number": acct}):
        acct = gen_account_number()
    await db.wallets.insert_one({
        "user_id": uid, "account_number": acct, "available_balance": 0,
        "ledger_balance": 0, "pending_balance": 0, "held_balance": 0,
        "currency": "NGN", "status": "ACTIVE", "tier": 1,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await notify(uid, "Welcome to Bompay!", f"Hi {req.first_name}! Your account is ready. You've earned 500 reward points!", "success")
    set_auth_cookies(response, create_access_token(uid, email), create_refresh_token(uid))
    await audit(uid, "REGISTER", "auth", {"email": email})
    return {"id": uid, "email": email, "first_name": req.first_name, "last_name": req.last_name,
            "phone": req.phone, "role": "user", "kyc_tier": 0, "kyc_status": "PENDING",
            "reward_points": 500, "referral_code": ref_code, "account_number": acct}

@router.post("/auth/login")
async def login(req: LoginReq, request: Request, response: Response):
    email = req.email.lower().strip()
    ip = request.client.host
    identifier = email  # Use email-only (not ip:email) to work correctly in multi-pod deployments
    attempts = await db.login_attempts.find_one({"identifier": identifier})
    if attempts:
        locked = attempts.get("locked_at")
        if locked:
            try:
                locked_dt = datetime.fromisoformat(locked)
                if (datetime.now(timezone.utc) - locked_dt) < timedelta(minutes=15):
                    raise HTTPException(status_code=429, detail="Account temporarily locked. Try again in 15 minutes.")
                else:
                    # Lockout expired — clear it
                    await db.login_attempts.delete_one({"identifier": identifier})
                    attempts = None
            except (ValueError, TypeError):
                raise HTTPException(status_code=429, detail="Account temporarily locked. Try again in 15 minutes.")
        elif attempts.get("count", 0) >= 5:
            # Count threshold reached but locked_at was missing — set it now and lock
            await db.login_attempts.update_one({"identifier": identifier},
                {"$set": {"locked_at": datetime.now(timezone.utc).isoformat()}})
            raise HTTPException(status_code=429, detail="Account temporarily locked. Try again in 15 minutes.")
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"last_attempt": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
        count = (attempts.get("count", 0) + 1) if attempts else 1
        if count >= 5:
            await db.login_attempts.update_one({"identifier": identifier},
                {"$set": {"locked_at": datetime.now(timezone.utc).isoformat()}})
            raise HTTPException(status_code=429, detail="Account temporarily locked after too many failed attempts. Try again in 15 minutes.")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.get("status") == "SUSPENDED":
        raise HTTPException(403, "Account suspended. Contact support.")
    await db.login_attempts.delete_one({"identifier": identifier})
    uid = str(user["_id"])
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}})
    set_auth_cookies(response, create_access_token(uid, email), create_refresh_token(uid))
    wallet = await db.wallets.find_one({"user_id": uid})
    await audit(uid, "LOGIN", "auth", {"email": email, "ip": _get_client_ip(request)})
    await log_login_session(uid, request, "ADMIN_LOGIN", True)
    return {"id": uid, "email": email, "first_name": user.get("first_name", ""),
            "last_name": user.get("last_name", ""), "phone": user.get("phone", ""),
            "role": user.get("role", "user"), "kyc_tier": user.get("kyc_tier", 0),
            "kyc_status": user.get("kyc_status", "PENDING"), "reward_points": user.get("reward_points", 0),
            "referral_code": user.get("referral_code", ""), "avatar": user.get("avatar", ""),
            "account_number": (wallet or {}).get("account_number", "")}

@router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    wallet = await db.wallets.find_one({"user_id": user["_id"]})
    if wallet:
        user["account_number"] = wallet.get("account_number", "")
    user["has_profile_picture"] = bool(user.get("profile_picture_url"))
    user["profile_picture_url"] = user.get("profile_picture_url") or None
    return user


# ── Profile Picture Upload ──────────────────────────────────────────────────

PROFILE_PIC_IMG_TYPES = {"image/jpeg", "image/png", "image/webp"}
PROFILE_PIC_MAX = 5 * 1024 * 1024  # 5 MB

@router.post("/user/upload-profile-picture")
async def upload_profile_picture(request: Request, file: UploadFile = File(...)):
    user = await get_current_user(request)
    user_id = user["_id"]
    ct = file.content_type or ""
    if ct not in PROFILE_PIC_IMG_TYPES:
        raise HTTPException(400, "Only JPEG, PNG, or WebP images are allowed")
    data = await file.read()
    if len(data) > PROFILE_PIC_MAX:
        raise HTTPException(400, "Image must be under 5 MB")
    ext = MIME_EXT.get(ct, "jpg")
    # Deterministic public_id per user — overwrites on re-upload
    public_id = f"{APP_NAME}/profile-pics/{user_id}"
    try:
        pic_url = _cloudinary_upload(data, public_id)
    except Exception as e:
        logger.error(f"[Cloudinary] Profile pic upload failed: {e}")
        raise HTTPException(500, "Upload failed. Please try again.")
    # Update user document with Cloudinary URL
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"profile_picture_url": pic_url}}
    )
    return {"success": True, "has_profile_picture": True, "profile_picture_url": pic_url}


@router.get("/user/profile-picture")
async def get_profile_picture(request: Request):
    user = await get_current_user(request)
    url = user.get("profile_picture_url")
    if not url:
        raise HTTPException(404, "No profile picture set")
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=url, status_code=302)

@router.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(401, "No refresh token")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(401, "User not found")
        uid = str(user["_id"])
        response.set_cookie("access_token", create_access_token(uid, user["email"]),
                           httponly=True, secure=True, samesite="none", max_age=3600, path="/")
        return {"message": "Token refreshed"}
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired. Please login again.")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid refresh token")

# ===== TRANSACTION PIN =====
@router.get("/auth/pin-status")
async def get_pin_status(request: Request):
    user = await get_current_user(request)
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"pin_hash": 1})
    return {"has_pin": bool(doc and doc.get("pin_hash"))}

@router.post("/auth/set-pin")
async def set_pin(req: SetPinReq, request: Request):
    if not req.pin.isdigit() or len(req.pin) != 4:
        raise HTTPException(400, "PIN must be exactly 4 digits")
    user = await get_current_user(request)
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"pin_hash": 1})
    if doc and doc.get("pin_hash"):
        raise HTTPException(409, "PIN already set. Use reset to change it.")
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {
        "pin_hash": hash_pin(req.pin), "pin_failed_attempts": 0,
        "pin_locked_until": None, "pin_set_at": datetime.now(timezone.utc).isoformat()
    }})
    return {"message": "Transaction PIN set successfully"}

@router.post("/auth/verify-pin")
async def verify_pin_endpoint(req: VerifyPinReq, request: Request):
    if not req.pin.isdigit() or len(req.pin) != 4:
        raise HTTPException(401, "PIN verification failed")
    user = await get_current_user(request)
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])},
        {"pin_hash": 1, "pin_failed_attempts": 1, "pin_locked_until": 1})
    if not doc or not doc.get("pin_hash"):
        raise HTTPException(401, "PIN verification failed")
    now = datetime.now(timezone.utc).isoformat()
    locked_until = doc.get("pin_locked_until")
    if locked_until and locked_until > now:
        raise HTTPException(401, "PIN locked. Try again in 15 minutes.")
    if verify_pin_hash(req.pin, doc["pin_hash"]):
        await db.users.update_one({"_id": ObjectId(user["_id"])},
            {"$set": {"pin_failed_attempts": 0, "pin_locked_until": None}})
        return {"verified": True}
    attempts = int(doc.get("pin_failed_attempts", 0)) + 1
    update: dict = {"$set": {"pin_failed_attempts": attempts}}
    if attempts >= 5:
        update["$set"]["pin_locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    await db.users.update_one({"_id": ObjectId(user["_id"])}, update)
    raise HTTPException(401, "Incorrect PIN")

@router.post("/auth/reset-pin")
async def reset_pin_endpoint(req: ResetPinReq, request: Request):
    if not req.pin.isdigit() or len(req.pin) != 4:
        raise HTTPException(400, "New PIN must be exactly 4 digits")
    user = await get_current_user(request)
    user_doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"password_hash": 1})
    if not user_doc or not verify_password(req.password, user_doc.get("password_hash", "")):
        raise HTTPException(401, "Password confirmation failed")
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {
        "pin_hash": hash_pin(req.pin), "pin_failed_attempts": 0,
        "pin_locked_until": None, "pin_set_at": datetime.now(timezone.utc).isoformat()
    }})
    return {"message": "Transaction PIN updated successfully"}

# ===== PHONE OTP AUTH =====
def _normalize_phone(phone: str) -> str:
    p = phone.strip().replace(" ", "").replace("-", "")
    if p.startswith("0"):
        return "+234" + p[1:]
    if p.startswith("234") and not p.startswith("+"):
        return "+" + p
    return p

@router.post("/auth/check-phone")
async def check_phone(req: CheckPhoneReq):
    """Check if phone number is registered. Returns user info for Welcome Back flow."""
    phone = _normalize_phone(req.phone)
    raw = req.phone.strip()
    user = await db.users.find_one(
        {"$or": [{"phone": phone}, {"phone": raw}, {"phone": req.phone.strip()}]},
        {"first_name": 1, "kyc_status": 1, "pin_hash": 1}
    )
    if not user:
        return {"exists": False}
    has_pin = bool(user.get("pin_hash"))
    return {
        "exists": True,
        "first_name": user.get("first_name", ""),
        "has_pin": has_pin,
    }

@router.post("/auth/send-phone-otp")
async def send_phone_otp(req: SendPhoneOtpReq):
    """Send OTP to phone via BulkSMSLive. Rate-limited to 1 per minute."""
    phone = _normalize_phone(req.phone)
    # Rate limit: 1 per minute per phone
    recent = await db.otp_sessions.find_one({"phone": phone, "type": "SMS"})
    if recent:
        sent_at = recent.get("sent_at", "")
        try:
            sent_dt = datetime.fromisoformat(sent_at)
            if (datetime.now(timezone.utc) - sent_dt) < timedelta(seconds=60):
                raise HTTPException(429, "Please wait 60 seconds before requesting another OTP")
        except (ValueError, TypeError):
            pass
    otp_code = "".join(secrets.choice("0123456789") for _ in range(6))
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    await db.otp_sessions.delete_many({"phone": phone, "type": "SMS"})
    await db.otp_sessions.insert_one({
        "phone": phone, "type": "SMS", "otp_hash": otp_hash,
        "expires_at": expires, "attempts": 0, "verified": False,
        "sent_at": datetime.now(timezone.utc).isoformat()
    })
    sms_body = f"Your BOMPAY verification code is: {otp_code}. Valid for 10 minutes. Do not share this code."
    result = await _send_via_bulksms(phone, sms_body)
    if not result.get("ok"):
        logger.warning(f"[OTP] SMS send to {phone} failed: {result}")
    return {"sent": True, "message": "OTP sent to your phone number"}

@router.post("/auth/verify-phone-otp")
async def verify_phone_otp(req: VerifyPhoneOtpReq):
    """Verify phone OTP. Returns otp_token for use in register/login."""
    phone = _normalize_phone(req.phone)
    session = await db.otp_sessions.find_one({"phone": phone, "type": "SMS"})
    if not session:
        raise HTTPException(400, "No OTP session found. Please request a new OTP.")
    if session.get("expires_at", "") < datetime.now(timezone.utc).isoformat():
        raise HTTPException(400, "OTP has expired. Please request a new one.")
    if session.get("attempts", 0) >= 5:
        raise HTTPException(429, "Too many failed attempts. Please request a new OTP.")
    entered_hash = hashlib.sha256(req.otp_code.strip().encode()).hexdigest()
    if entered_hash != session.get("otp_hash", ""):
        await db.otp_sessions.update_one({"_id": session["_id"]}, {"$inc": {"attempts": 1}})
        remaining = max(0, 4 - session.get("attempts", 0))
        raise HTTPException(400, f"Incorrect OTP. {remaining} attempts remaining.")
    otp_token = secrets.token_urlsafe(32)
    await db.otp_sessions.update_one({"_id": session["_id"]}, {"$set": {
        "verified": True, "otp_token": otp_token,
        "verified_at": datetime.now(timezone.utc).isoformat()
    }})
    # Check if user exists
    raw = req.phone.strip()
    user = await db.users.find_one(
        {"$or": [{"phone": phone}, {"phone": raw}]},
        {"first_name": 1, "pin_hash": 1}
    )
    return {
        "verified": True,
        "otp_token": otp_token,
        "user_exists": bool(user),
        "first_name": user.get("first_name", "") if user else "",
    }

@router.post("/auth/send-email-otp")
async def send_email_otp_endpoint(req: SendEmailOtpReq):
    """Email OTP fallback. Sends OTP to provided email."""
    phone = _normalize_phone(req.phone)
    otp_code = "".join(secrets.choice("0123456789") for _ in range(6))
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    await db.otp_sessions.delete_many({"phone": phone, "type": "EMAIL"})
    await db.otp_sessions.insert_one({
        "phone": phone, "type": "EMAIL", "email": req.email,
        "otp_hash": otp_hash, "expires_at": expires, "attempts": 0, "verified": False,
        "sent_at": datetime.now(timezone.utc).isoformat()
    })
    html = _email_html(
        "Your BOMPAY Verification Code",
        [("Code", otp_code), ("Valid for", "10 minutes")],
        "Do not share this code with anyone. BOMPAY will never ask for your PIN."
    )
    await send_email(to=req.email, subject="BOMPAY Verification Code", html=html)
    return {"sent": True, "message": "OTP sent to your email address"}

@router.post("/auth/verify-email-otp")
async def verify_email_otp_endpoint(req: VerifyEmailOtpReq):
    """Verify email OTP."""
    phone = _normalize_phone(req.phone)
    session = await db.otp_sessions.find_one({"phone": phone, "type": "EMAIL", "email": req.email})
    if not session:
        raise HTTPException(400, "No email OTP session found.")
    if session.get("expires_at", "") < datetime.now(timezone.utc).isoformat():
        raise HTTPException(400, "OTP has expired. Please request a new one.")
    if session.get("attempts", 0) >= 5:
        raise HTTPException(429, "Too many failed attempts. Request a new OTP.")
    entered_hash = hashlib.sha256(req.otp_code.strip().encode()).hexdigest()
    if entered_hash != session.get("otp_hash", ""):
        await db.otp_sessions.update_one({"_id": session["_id"]}, {"$inc": {"attempts": 1}})
        raise HTTPException(400, "Incorrect OTP.")
    otp_token = secrets.token_urlsafe(32)
    await db.otp_sessions.update_one({"_id": session["_id"]}, {"$set": {
        "verified": True, "otp_token": otp_token,
        "verified_at": datetime.now(timezone.utc).isoformat()
    }})
    raw = req.phone.strip()
    user = await db.users.find_one(
        {"$or": [{"phone": phone}, {"phone": raw}]},
        {"first_name": 1, "pin_hash": 1}
    )
    return {
        "verified": True,
        "otp_token": otp_token,
        "user_exists": bool(user),
        "first_name": user.get("first_name", "") if user else "",
    }

@router.post("/auth/phone-register")
async def phone_register(req: PhoneRegisterReq, response: Response):
    """Register new user via phone+OTP verification."""
    phone = _normalize_phone(req.phone)
    raw_phone = req.phone.strip()
    # Verify otp_token
    session = await db.otp_sessions.find_one({
        "phone": phone, "verified": True, "otp_token": req.otp_token
    })
    if not session:
        # Try raw phone too
        session = await db.otp_sessions.find_one({
            "phone": raw_phone, "verified": True, "otp_token": req.otp_token
        })
    if not session:
        raise HTTPException(400, "OTP not verified or token expired. Please re-verify.")
    # Check PIN
    if not req.pin.isdigit() or len(req.pin) != 4:
        raise HTTPException(400, "PIN must be exactly 4 digits")
    # Check phone not already registered
    existing = await db.users.find_one({"$or": [{"phone": phone}, {"phone": raw_phone}]})
    if existing:
        raise HTTPException(400, "Phone number already registered. Please login instead.")
    # Check email if provided
    email_val = str(req.email).lower().strip() if req.email else ""
    if email_val:
        if await db.users.find_one({"email": email_val}):
            raise HTTPException(400, "Email already registered")
    ref_code = secrets.token_hex(4).upper()
    res = await db.users.insert_one({
        "email": email_val or None,
        "password_hash": None,
        "first_name": req.first_name.strip(),
        "last_name": req.last_name.strip(),
        "phone": phone,
        "pin_hash": hash_pin(req.pin),
        "pin_set_at": datetime.now(timezone.utc).isoformat(),
        "role": "user", "status": "ACTIVE", "kyc_tier": 0, "kyc_status": "PENDING",
        "referral_code": ref_code, "referred_by": req.referral_code, "reward_points": 500,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    uid = str(res.inserted_id)
    acct = gen_account_number()
    while await db.wallets.find_one({"account_number": acct}):
        acct = gen_account_number()
    await db.wallets.insert_one({
        "user_id": uid, "account_number": acct, "available_balance": 0,
        "ledger_balance": 0, "pending_balance": 0, "held_balance": 0,
        "currency": "NGN", "status": "ACTIVE", "tier": 1,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await db.otp_sessions.delete_many({"phone": {"$in": [phone, raw_phone]}})
    await notify(uid, "Welcome to Bompay!", f"Hi {req.first_name}! Your account is ready. You've earned 500 reward points!", "success")
    set_auth_cookies(response, create_access_token(uid, email_val or phone), create_refresh_token(uid))
    await audit(uid, "REGISTER_PHONE", "auth", {"phone": phone})
    return {"id": uid, "email": email_val, "first_name": req.first_name.strip(),
            "last_name": req.last_name.strip(), "phone": phone, "role": "user",
            "kyc_tier": 0, "kyc_status": "PENDING", "reward_points": 500,
            "referral_code": ref_code, "account_number": acct}

@router.post("/auth/phone-login")
async def phone_login(req: PhoneLoginReq, response: Response, request: Request):
    """Login existing user with phone + PIN."""
    phone = _normalize_phone(req.phone)
    raw_phone = req.phone.strip()
    user = await db.users.find_one({"$or": [{"phone": phone}, {"phone": raw_phone}]})
    if not user:
        raise HTTPException(401, "Phone number not registered")
    if user.get("status") == "SUSPENDED":
        raise HTTPException(403, "Account suspended. Contact support.")
    if not user.get("pin_hash"):
        raise HTTPException(400, "PIN not set. Please complete setup.")
    if not req.pin.isdigit() or len(req.pin) != 4:
        raise HTTPException(401, "Invalid PIN")
    # PIN lockout check
    locked_until = user.get("pin_locked_until")
    now_iso = datetime.now(timezone.utc).isoformat()
    if locked_until and locked_until > now_iso:
        raise HTTPException(429, "PIN locked. Try again in 15 minutes.")
    if not verify_pin_hash(req.pin, user["pin_hash"]):
        attempts = int(user.get("pin_failed_attempts", 0)) + 1
        upd: dict = {"$set": {"pin_failed_attempts": attempts}}
        if attempts >= 4:
            blocked_until = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
            upd["$set"]["pin_locked_until"] = blocked_until
            upd["$set"]["status"] = "SUSPENDED"
            upd["$set"]["blocked_reason"] = "EXCESSIVE_PIN_FAILURES"
            upd["$set"]["blocked_at"] = datetime.now(timezone.utc).isoformat()
            upd["$set"]["blocked_until"] = blocked_until
            await db.users.update_one({"_id": user["_id"]}, upd)
            # Create fraud alert
            await db.fraud_alerts.insert_one({
                "alert_id": str(uuid.uuid4()), "user_id": str(user["_id"]),
                "type": "EXCESSIVE_PIN_FAILURES", "signals": ["EXCESSIVE_PIN_FAILURES"],
                "amount": 0, "status": "OPEN", "auto_blocked": True,
                "blocked_until": blocked_until,
                "metadata": {"phone": phone, "failed_attempts": attempts},
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            raise HTTPException(429, "Account blocked for 24 hours due to too many failed PIN attempts.")
        await db.users.update_one({"_id": user["_id"]}, upd)
        remaining = 4 - attempts
        await log_login_session(str(user["_id"]), request, "PHONE_LOGIN_FAILED", False,
                                {"phone": phone, "attempts": attempts})
        raise HTTPException(401, f"Incorrect PIN. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
    uid = str(user["_id"])
    email_val = user.get("email") or phone
    await db.users.update_one({"_id": user["_id"]}, {"$set": {
        "last_login": now_iso, "pin_failed_attempts": 0, "pin_locked_until": None
    }})
    set_auth_cookies(response, create_access_token(uid, email_val), create_refresh_token(uid))
    wallet = await db.wallets.find_one({"user_id": uid})
    await audit(uid, "PHONE_LOGIN", "auth", {"phone": phone})
    await log_login_session(uid, request, "PHONE_LOGIN", True)
    return {
        "id": uid, "email": user.get("email", ""), "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""), "phone": user.get("phone", ""),
        "role": user.get("role", "user"), "kyc_tier": user.get("kyc_tier", 0),
        "kyc_status": user.get("kyc_status", "PENDING"), "reward_points": user.get("reward_points", 0),
        "referral_code": user.get("referral_code", ""), "avatar": user.get("avatar", ""),
        "account_number": (wallet or {}).get("account_number", "")
    }

# ===== NOTIFICATION PREFERENCES =====
@router.get("/user/notification-prefs")
async def get_notification_prefs(request: Request):
    user = await get_current_user(request)
    prefs = user.get("notification_prefs", {})
    return {
        "sms_enabled": prefs.get("sms_enabled", True),
        "email_enabled": prefs.get("email_enabled", True),
        "in_app_enabled": prefs.get("in_app_enabled", True),
    }

@router.put("/user/notification-prefs")
async def update_notification_prefs(req: NotifPrefsReq, request: Request):
    user = await get_current_user(request)
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {
        "notification_prefs": {
            "sms_enabled": req.sms_enabled,
            "email_enabled": req.email_enabled,
            "in_app_enabled": req.in_app_enabled,
        }
    }})
    return {"message": "Notification preferences updated"}

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

# ===== WEBAUTHN ENDPOINTS =====
@router.get("/webauthn/passkeys")
async def list_passkeys(request: Request):
    user = await get_current_user(request)
    passkeys = await db.webauthn_credentials.find(
        {"user_id": user["_id"]}, {"_id": 0, "credential_id": 1, "device_type": 1, "registered_at": 1}
    ).to_list(10)
    return {"passkeys": passkeys}

@router.post("/webauthn/register/options")
async def webauthn_register_options(request: Request):
    user = await get_current_user(request)
    existing = await db.webauthn_credentials.find(
        {"user_id": user["_id"]}, {"credential_id": 1}
    ).to_list(10)
    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in existing]
    opts = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID, rp_name=WEBAUTHN_RP_NAME,
        user_id=user["_id"].encode(),
        user_name=user["email"],
        user_display_name=f"{user.get('first_name','')} {user.get('last_name','')}".strip() or user["email"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=exclude,
    )
    challenge_hex = opts.challenge.hex()
    await db.webauthn_challenges.insert_one({
        "user_id": user["_id"], "challenge": challenge_hex, "type": "registration",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    })
    return json.loads(options_to_json(opts))

@router.post("/webauthn/register/verify")
async def webauthn_register_verify(req: WebAuthnRegVerifyReq, request: Request):
    user = await get_current_user(request)
    doc = await db.webauthn_challenges.find_one(
        {"user_id": user["_id"], "type": "registration"}, sort=[("_id", -1)]
    )
    if not doc:
        raise HTTPException(400, "No pending registration challenge")
    await db.webauthn_challenges.delete_many({"user_id": user["_id"], "type": "registration"})
    try:
        credential = _parse_reg_credential(req.credential)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=bytes.fromhex(doc["challenge"]),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {e}")
    await db.webauthn_credentials.insert_one({
        "user_id": user["_id"], "credential_id": req.credential["id"],
        "public_key": verification.credential_public_key.hex(),
        "sign_count": verification.sign_count,
        "device_type": req.credential.get("authenticatorAttachment", "unknown"),
        "registered_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"message": "Biometric registered successfully"}

@router.post("/webauthn/auth/options")
async def webauthn_auth_options(request: Request):
    user = await get_current_user(request)
    credentials = await db.webauthn_credentials.find(
        {"user_id": user["_id"]}, {"credential_id": 1}
    ).to_list(10)
    if not credentials:
        raise HTTPException(404, "No biometric registered. Please register using PIN.")
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in credentials]
    opts = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID, allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    await db.webauthn_challenges.insert_one({
        "user_id": user["_id"], "challenge": opts.challenge.hex(), "type": "authentication",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    })
    return json.loads(options_to_json(opts))

@router.post("/webauthn/auth/verify")
async def webauthn_auth_verify(req: WebAuthnAuthVerifyReq, request: Request):
    user = await get_current_user(request)
    doc = await db.webauthn_challenges.find_one(
        {"user_id": user["_id"], "type": "authentication"}, sort=[("_id", -1)]
    )
    if not doc:
        raise HTTPException(400, "No pending authentication challenge")
    await db.webauthn_challenges.delete_many({"user_id": user["_id"], "type": "authentication"})
    credential_id = req.credential["id"]
    stored = await db.webauthn_credentials.find_one({"user_id": user["_id"], "credential_id": credential_id})
    if not stored:
        raise HTTPException(404, "Credential not found")
    try:
        credential = _parse_auth_credential(req.credential)
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=bytes.fromhex(doc["challenge"]),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=bytes.fromhex(stored["public_key"]),
            credential_current_sign_count=stored.get("sign_count", 0),
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(401, f"Biometric verification failed: {e}")
    await db.webauthn_credentials.update_one(
        {"user_id": user["_id"], "credential_id": credential_id},
        {"$set": {"sign_count": verification.new_sign_count}}
    )
    # Issue a short-lived biometric transaction token (30 seconds)
    bio_token = secrets.token_urlsafe(32)
    await db.biometric_tokens.insert_one({
        "user_id": str(user["_id"]),
        "token": bio_token,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat(),
    })
    return {"verified": True, "biometric_token": bio_token}

# ===== BIOMETRIC LOGIN (no session — for Welcome Back flow) =====
class BiometricLoginOptionsReq(BaseModel):
    phone: str

class BiometricLoginVerifyReq(BaseModel):
    phone: str
    credential: dict

@router.post("/auth/biometric-login/options")
async def biometric_login_options(req: BiometricLoginOptionsReq):
    """Returns WebAuthn challenge for phone-based biometric login (no session needed)."""
    phone = _normalize_phone(req.phone)
    raw = req.phone.strip()
    user = await db.users.find_one({"$or": [{"phone": phone}, {"phone": raw}]})
    if not user:
        raise HTTPException(404, "Phone number not registered")
    credentials = await db.webauthn_credentials.find(
        {"user_id": str(user["_id"])}, {"credential_id": 1}
    ).to_list(10)
    if not credentials:
        raise HTTPException(404, "No biometric registered for this account")
    allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])) for c in credentials]
    opts = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID, allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    await db.webauthn_challenges.insert_one({
        "user_id": str(user["_id"]), "challenge": opts.challenge.hex(), "type": "biometric_login",
        "phone": phone,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    })
    return json.loads(options_to_json(opts))

@router.post("/auth/biometric-login/verify")
async def biometric_login_verify(req: BiometricLoginVerifyReq, response: Response):
    """Verify biometric credential and create session — no prior session needed."""
    phone = _normalize_phone(req.phone)
    raw = req.phone.strip()
    user = await db.users.find_one({"$or": [{"phone": phone}, {"phone": raw}]})
    if not user:
        raise HTTPException(404, "Phone number not registered")
    uid = str(user["_id"])
    doc = await db.webauthn_challenges.find_one(
        {"user_id": uid, "type": "biometric_login"}, sort=[("_id", -1)]
    )
    if not doc:
        raise HTTPException(400, "No pending biometric challenge")
    await db.webauthn_challenges.delete_many({"user_id": uid, "type": "biometric_login"})
    credential_id = req.credential.get("id", "")
    stored = await db.webauthn_credentials.find_one({"user_id": uid, "credential_id": credential_id})
    if not stored:
        raise HTTPException(404, "Biometric credential not found")
    try:
        credential = _parse_auth_credential(req.credential)
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=bytes.fromhex(doc["challenge"]),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=bytes.fromhex(stored["public_key"]),
            credential_current_sign_count=stored.get("sign_count", 0),
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(401, f"Biometric verification failed: {e}")
    await db.webauthn_credentials.update_one(
        {"user_id": uid, "credential_id": credential_id},
        {"$set": {"sign_count": verification.new_sign_count}}
    )
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now_iso}})
    email_val = user.get("email") or phone
    set_auth_cookies(response, create_access_token(uid, email_val), create_refresh_token(uid))
    wallet = await db.wallets.find_one({"user_id": uid})
    await audit(uid, "BIOMETRIC_LOGIN", "auth", {"phone": phone})
    return {
        "id": uid, "email": user.get("email", ""), "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""), "phone": user.get("phone", ""),
        "role": user.get("role", "user"), "kyc_tier": user.get("kyc_tier", 0),
        "kyc_status": user.get("kyc_status", "PENDING"), "reward_points": user.get("reward_points", 0),
        "referral_code": user.get("referral_code", ""), "avatar": user.get("avatar", ""),
        "account_number": (wallet or {}).get("account_number", "")
    }

@router.delete("/webauthn/passkeys/{credential_id}")
async def delete_passkey(credential_id: str, request: Request):
    user = await get_current_user(request)
    result = await db.webauthn_credentials.delete_one(
        {"user_id": user["_id"], "credential_id": credential_id}
    )
    if result.deleted_count == 0:
        raise HTTPException(404, "Passkey not found")
    return {"message": "Biometric removed"}

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

