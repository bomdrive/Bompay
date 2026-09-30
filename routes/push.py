"""Bompay — Push Notifications & Files routes."""
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
    MIME_EXT, PROMO_IMG_TYPES, PROMO_IMG_MAX, BaseModel,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/admin/promotions/upload-image")
async def admin_upload_promo_image(request: Request, file: UploadFile = File(...)):
    await get_admin_user(request)
    ct = file.content_type or ""
    if ct not in PROMO_IMG_TYPES:
        raise HTTPException(400, "Only JPEG, PNG, WebP, or GIF images are allowed")
    data = await file.read()
    if len(data) > PROMO_IMG_MAX:
        raise HTTPException(400, "Image must be under 2 MB")
    ext = MIME_EXT.get(ct, "jpg")
    public_id = f"{APP_NAME}/promotions/{uuid.uuid4()}"
    try:
        image_url = _cloudinary_upload(data, public_id)
    except Exception as e:
        logger.error(f"[Cloudinary] Promo upload failed: {e}")
        raise HTTPException(500, "Image upload failed. Please try again.")
    await db.promo_images.insert_one({
        "storage_path": image_url,
        "original_filename": file.filename,
        "content_type": ct,
        "size": len(data),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"image_url": image_url, "path": image_url}

@router.get("/files/promo/{path:path}")
async def serve_promo_image(path: str):
    """Legacy route — promo images now served directly from Cloudinary CDN."""
    # Try to find the Cloudinary URL from the database
    from fastapi.responses import RedirectResponse
    img = await db.promo_images.find_one({"storage_path": {"$regex": path.split("/")[-1]}})
    if img and img.get("storage_path", "").startswith("https://"):
        return RedirectResponse(url=img["storage_path"], status_code=301)
    raise HTTPException(404, "Image not found")


VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY_B64 = os.environ.get("VAPID_KEY_PATH", os.environ.get("VAPID_PRIVATE_KEY", ""))
VAPID_EMAIL = os.environ.get("VAPID_EMAIL", "mailto:admin@bompay.ng")

class PushSubscriptionReq(BaseModel):
    endpoint: str
    keys: dict  # {p256dh, auth}


@router.get("/push/vapid-key")
async def get_vapid_key():
    return {"publicKey": VAPID_PUBLIC_KEY}

@router.post("/push/subscribe")
async def subscribe_push(req: PushSubscriptionReq, request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    sub_doc = {
        "user_id": uid,
        "endpoint": req.endpoint,
        "keys": req.keys,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.push_subscriptions.update_one(
        {"user_id": uid, "endpoint": req.endpoint},
        {"$set": sub_doc},
        upsert=True
    )
    return {"subscribed": True}

@router.delete("/push/unsubscribe")
async def unsubscribe_push(request: Request):
    user = await get_current_user(request)
    uid = str(user["_id"])
    await db.push_subscriptions.delete_many({"user_id": uid})
    return {"unsubscribed": True}
