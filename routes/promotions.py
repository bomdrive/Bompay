"""Bompay — Promotions routes."""
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
    PromotionReq,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/promotions")
async def get_promotions():
    """Public endpoint — returns active promotions sorted by order."""
    promos = await db.promotions.find({"is_active": True}, {"_id": 1, "title": 1, "subtitle": 1,
        "image_url": 1, "bg_color": 1, "text_color": 1, "action_url": 1, "button_label": 1,
        "sort_order": 1}).sort("sort_order", 1).to_list(20)
    return {"promotions": [{"id": str(p["_id"]), **{k: v for k, v in p.items() if k != "_id"}} for p in promos]}

@router.get("/admin/promotions")
async def admin_get_promotions(request: Request):
    await get_admin_user(request)
    promos = await db.promotions.find({}, {"_id": 1, "title": 1, "subtitle": 1, "image_url": 1,
        "bg_color": 1, "text_color": 1, "action_url": 1, "button_label": 1,
        "is_active": 1, "sort_order": 1, "created_at": 1}).sort("sort_order", 1).to_list(50)
    return {"promotions": [{"id": str(p["_id"]), **{k: v for k, v in p.items() if k != "_id"}} for p in promos]}

@router.post("/admin/promotions")
async def admin_create_promotion(req: PromotionReq, request: Request):
    await get_admin_user(request)
    doc = {
        "title": req.title.strip(),
        "subtitle": (req.subtitle or "").strip(),
        "image_url": req.image_url or "",
        "bg_color": req.bg_color or "#EEF4FF",
        "text_color": req.text_color or "#064BCB",
        "action_url": req.action_url or "",
        "button_label": req.button_label or "GO",
        "is_active": req.is_active,
        "sort_order": req.sort_order,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    res = await db.promotions.insert_one(doc)
    return {"id": str(res.inserted_id), "title": doc["title"], "subtitle": doc["subtitle"],
            "image_url": doc["image_url"], "bg_color": doc["bg_color"], "text_color": doc["text_color"],
            "action_url": doc["action_url"], "button_label": doc["button_label"],
            "is_active": doc["is_active"], "sort_order": doc["sort_order"], "created_at": doc["created_at"]}

@router.put("/admin/promotions/{promo_id}")
async def admin_update_promotion(promo_id: str, req: PromotionReq, request: Request):
    await get_admin_user(request)
    await db.promotions.update_one({"_id": ObjectId(promo_id)}, {"$set": {
        "title": req.title.strip(),
        "subtitle": (req.subtitle or "").strip(),
        "image_url": req.image_url or "",
        "bg_color": req.bg_color or "#EEF4FF",
        "text_color": req.text_color or "#064BCB",
        "action_url": req.action_url or "",
        "button_label": req.button_label or "GO",
        "is_active": req.is_active,
        "sort_order": req.sort_order,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }})
    return {"message": "Promotion updated"}

@router.delete("/admin/promotions/{promo_id}")
async def admin_delete_promotion(promo_id: str, request: Request):
    await get_admin_user(request)
    await db.promotions.delete_one({"_id": ObjectId(promo_id)})
    return {"message": "Promotion deleted"}
