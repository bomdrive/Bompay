"""Bompay — Notifications routes."""
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
    _current_period_index, _period_due_date,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/notifications")
async def get_notifications(request: Request):
    user = await get_current_user(request)
    notifs = await db.notifications.find({"user_id": user["_id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"notifications": notifs, "unread": sum(1 for n in notifs if not n.get("read"))}

@router.put("/notifications/{nid}/read")
async def mark_read(nid: str, request: Request):
    user = await get_current_user(request)
    await db.notifications.update_one({"notification_id": nid, "user_id": user["_id"]}, {"$set": {"read": True}})
    return {"message": "Marked as read"}

@router.put("/notifications/read-all")
async def mark_all_read(request: Request):
    user = await get_current_user(request)
    await db.notifications.update_many({"user_id": user["_id"]}, {"$set": {"read": True}})
    return {"message": "All notifications marked as read"}

# ===================================================================
# AJO (Group / Rotating Savings)
# ===================================================================

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

