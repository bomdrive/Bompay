"""Bompay — Admin Console routes."""
import os, uuid, secrets, logging, time, json, asyncio, hashlib, re
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from pathlib import Path
from bson import ObjectId
import bcrypt
import jwt as pyjwt
import httpx
import requests as _requests
from fastapi import APIRouter, HTTPException, Request, Response, BackgroundTasks, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse, StreamingResponse
import csv, io
from fpdf import FPDF

from database import db
from core import (  # noqa: F401,F403,F405
    hash_password, verify_password, hash_pin, verify_pin_hash,
    create_access_token, create_refresh_token, get_current_user, get_admin_user,
    set_auth_cookies, log_login_session,
    gen_account_number, get_wallet, ledger_entry,
    notify, audit, send_event_sms, send_event_email, send_event_notification, send_email,
    send_push_notification,
    fraud_check, fraud_check_user, auto_block_user,
    call_sh, mock_sh, call_cdh, call_pg,
    get_vas_provider, get_service_provider, get_sms_config,
    get_sms_provider, get_sendora_api_key, get_sendora_sender_id, get_bulksms_credentials,
    _cloudinary_upload, _cloudinary_delete, _email_html,
    _send_tier_approval_email, _send_tier_revoke_email,
    _send_via_sendora, _send_via_bulksms,
    _get_client_ip, _parse_ua,
)
from core import (  # noqa: F401,F403,F405
    JWT_SECRET, JWT_ALGORITHM, ADMIN_EMAIL, ADMIN_PASSWORD,
    FRONTEND_URL, WEBHOOK_CRON_SECRET, SAFEHAVEN_BASE_URL, SAFEHAVEN_OWN_BANK_CODE,
    CDH_BASE_URL, PAIRGATE_BASE_URL,
    PG_DISCO_SLUGS, PG_BET_SLUGS,
    CDH_AIRTIME_NETWORK_IDS, CDH_ELECTRICITY_DISCO_IDS, CDH_DATA_PLANS, CDH_CABLE_PLANS,
    NIGERIAN_BANKS, MOCK_NAMES, CHARGE_CATEGORIES,
    WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN, WEBAUTHN_RP_NAME,
    APP_NAME, EMERGENT_LLM_KEY,
    cloudinary,
)
from core import (  # noqa: F401,F403,F405
    ProviderSettingsReq,
    _sh_token,
    get_savings_config,
    SavingsConfigReq,
    get_loan_config,
    LoanConfigReq,
    get_rewards_config,
    _build_ajo_detail,
    KYCTierConfigUpdate,
    KYCRevokeReq,
    KYCApproveReq,
    FeeConfigReq,
    calculate_fee,
    get_nip_fee,
    CableValidateReq,
    MeterValidateReq,
    ChargeAccountReq,
    _sweep_fee_margin,
    SmsConfigReq,
    _verify_cron,
    SendoraConfigReq,
    BulkSmsCredentialsReq,
    SmsProviderReq,
    EmailConfigReq,
    BaseModel,
    AdminRoleReq,
    AdminStaffReq,
    PromotionReq,
    get_sh_subaccount_balance,
    get_service_bucket_account,
    ResendSettingsReq,
    CloudinarySettingsReq,
    _run_sms_billing,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/admin/stats")
async def admin_stats(request: Request):
    await get_admin_user(request)
    pipe_vol = [{"$match": {"status": "COMPLETED", "direction": "DEBIT"}},
                {"$group": {"_id": None, "total": {"$sum": "$amount"}}}]
    pipe_rev = [{"$match": {"status": "COMPLETED"}},
                {"$group": {"_id": None, "total": {"$sum": "$fee"}}}]
    vol = await db.transactions.aggregate(pipe_vol).to_list(1)
    rev = await db.transactions.aggregate(pipe_rev).to_list(1)
    return {
        "total_users": await db.users.count_documents({}),
        "total_transactions": await db.transactions.count_documents({}),
        "completed_transactions": await db.transactions.count_documents({"status": "COMPLETED"}),
        "total_volume": (vol[0]["total"] if vol else 0) / 100,
        "total_revenue": (rev[0]["total"] if rev else 0) / 100,
        "open_fraud_alerts": await db.fraud_alerts.count_documents({"status": "OPEN"}),
        "kyc_pending": await db.users.count_documents({"kyc_status": "PENDING"}),
        "active_loans": await db.loan_applications.count_documents({"status": "DISBURSED"}),
    }

@router.get("/admin/users")
async def admin_users(request: Request, page: int = 1, limit: int = 25,
                      search: str = None, user_status: str = None, kyc_tier: int = None,
                      date_from: str = None, date_to: str = None, account_number: str = None):
    await get_admin_user(request)
    query: dict = {"role": {"$ne": "admin"}}  # hide system/admin accounts
    if search:
        query["$or"] = [{"email": {"$regex": search, "$options": "i"}},
                        {"first_name": {"$regex": search, "$options": "i"}},
                        {"last_name": {"$regex": search, "$options": "i"}},
                        {"phone": {"$regex": search, "$options": "i"}}]
    if user_status:
        query["status"] = user_status
    if kyc_tier is not None:
        query["kyc_tier"] = kyc_tier
    if date_from or date_to:
        date_q: dict = {}
        if date_from: date_q["$gte"] = date_from + "T00:00:00"
        if date_to:   date_q["$lte"] = date_to   + "T23:59:59"
        query["created_at"] = date_q
    if account_number:
        wallet = await db.wallets.find_one({"sh_account_number": account_number})
        if wallet:
            and_clauses = query.pop("$and", [])
            and_clauses.append({"_id": ObjectId(wallet["user_id"])})
            query["$and"] = and_clauses
        else:
            return {"users": [], "total": 0, "page": page}
    skip = (page - 1) * limit
    users = await db.users.find(query, {"password_hash": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    for u in users:
        u["_id"] = str(u["_id"])
    return {"users": users, "total": await db.users.count_documents(query), "page": page}

@router.get("/admin/users/risk-scores")
async def admin_user_risk_scores(request: Request):
    """Return a risk score (0-100) for each non-admin user."""
    await get_admin_user(request)
    # Aggregate open fraud alerts per user
    alert_map: dict = {}
    async for row in db.fraud_alerts.aggregate([
        {"$match": {"status": "OPEN"}},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}}}
    ]):
        alert_map[row["_id"]] = row["count"]
    # Aggregate failed login sessions (last 24h) per user
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    failed_map: dict = {}
    async for row in db.login_sessions.aggregate([
        {"$match": {"success": False, "created_at": {"$gte": since_24h}}},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}}}
    ]):
        failed_map[row["_id"]] = row["count"]
    # Compute scores
    scores: dict = {}
    async for u in db.users.find({"role": {"$ne": "admin"}},
                                  {"_id": 1, "status": 1, "pin_failed_attempts": 1}):
        uid = str(u["_id"])
        score = 0
        if u.get("status") == "SUSPENDED":
            score += 40
        pfa = int(u.get("pin_failed_attempts", 0))
        if pfa >= 4:   score += 30
        elif pfa >= 2: score += 15
        elif pfa == 1: score += 5
        open_alerts = alert_map.get(uid, 0)
        score += min(open_alerts * 15, 35)
        failed_logins = failed_map.get(uid, 0)
        score += min(failed_logins * 5, 20)
        scores[uid] = min(score, 100)
    return {"scores": scores}

@router.get("/admin/transactions")
async def admin_transactions(request: Request, page: int = 1, limit: int = 25,
                              txn_status: str = None, txn_type: str = None,
                              direction: str = None, date_from: str = None, date_to: str = None,
                              phone: str = None, account_number: str = None, search: str = None):
    await get_admin_user(request)
    query: dict = {}
    if txn_status: query["status"] = txn_status
    if txn_type: query["type"] = txn_type
    if direction: query["direction"] = direction
    if date_from or date_to:
        date_q: dict = {}
        if date_from: date_q["$gte"] = date_from + "T00:00:00"
        if date_to:   date_q["$lte"] = date_to   + "T23:59:59"
        query["created_at"] = date_q
    if phone:
        user = await db.users.find_one({"phone": {"$regex": phone, "$options": "i"}}, {"_id": 1})
        if user:
            query["user_id"] = str(user["_id"])
        else:
            return {"transactions": [], "total": 0, "page": page}
    if account_number:
        wallet = await db.wallets.find_one({"sh_account_number": account_number})
        if wallet:
            uid = wallet["user_id"]
            if "user_id" in query and query["user_id"] != uid:
                return {"transactions": [], "total": 0, "page": page}
            query["user_id"] = uid
        else:
            return {"transactions": [], "total": 0, "page": page}
    if search:
        query["$or"] = [
            {"transaction_id": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
    skip = (page - 1) * limit
    txns = await db.transactions.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return {"transactions": txns, "total": await db.transactions.count_documents(query), "page": page}

@router.get("/admin/audit-logs")
async def admin_audit_logs(request: Request, page: int = 1, limit: int = 50):
    await get_admin_user(request)
    skip = (page - 1) * limit
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit).to_list(limit)
    return {"logs": logs, "total": await db.audit_logs.count_documents({})}

@router.get("/admin/fraud-alerts")
async def admin_fraud_alerts(request: Request):
    await get_admin_user(request)
    raw = await db.fraud_alerts.find({}).sort("created_at", -1).to_list(200)
    alerts = []
    for a in raw:
        a.pop("_id", None)
        if "user_id" in a:
            a["user_id"] = str(a["user_id"])
        if "resolved_by" in a:
            a["resolved_by"] = str(a["resolved_by"])
        # Enrich with user details
        try:
            u = await db.users.find_one({"_id": __import__("bson").ObjectId(a["user_id"])}) if a.get("user_id") else None
        except Exception:
            u = None
        a["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip() if u else "Unknown"
        a["user_phone"] = u.get("phone", "") if u else ""
        alerts.append(a)
    return {"alerts": alerts}

@router.put("/admin/fraud-alerts/{alert_id}/resolve")
async def resolve_fraud(alert_id: str, request: Request):
    admin = await get_admin_user(request)
    await db.fraud_alerts.update_one({"alert_id": alert_id},
        {"$set": {"status": "RESOLVED", "resolved_by": str(admin["_id"]),
                  "resolved_at": datetime.now(timezone.utc).isoformat()}})
    return {"message": "Alert resolved"}

@router.post("/admin/fraud/block-user/{user_id}")
async def admin_block_user(user_id: str, request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    reason = body.get("reason", "MANUAL_BLOCK")
    hours = int(body.get("hours", 24))
    blocked_until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

    # Save previous KYC status so it can be restored on unblock
    user = await db.users.find_one({"_id": ObjectId(user_id)}, {"kyc_status": 1})
    prev_kyc = (user or {}).get("kyc_status", "PENDING")

    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "status": "SUSPENDED", "blocked_until": blocked_until,
        "blocked_reason": reason, "blocked_at": datetime.now(timezone.utc).isoformat(),
        "blocked_by": str(admin["_id"]),
        # Demote KYC to PENDING and save previous value for restoration
        "kyc_status": "PENDING",
        "prev_kyc_status": prev_kyc,
    }})
    await db.fraud_alerts.insert_one({
        "alert_id": str(uuid.uuid4()), "user_id": user_id,
        "type": "MANUAL_BLOCK", "signals": [reason], "amount": 0,
        "status": "OPEN", "auto_blocked": False, "blocked_until": blocked_until,
        "metadata": {"reason": reason, "hours": hours, "admin": str(admin["_id"])},
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    await audit(str(admin["_id"]), "BLOCK_USER", "fraud", {"user_id": user_id, "reason": reason, "hours": hours, "prev_kyc_status": prev_kyc})
    return {"message": f"User blocked for {hours} hours", "blocked_until": blocked_until}

@router.post("/admin/fraud/unblock-user/{user_id}")
async def admin_unblock_user(user_id: str, request: Request):
    admin = await get_admin_user(request)

    # Restore previous KYC status saved at block time
    user = await db.users.find_one({"_id": ObjectId(user_id)}, {"prev_kyc_status": 1})
    restored_kyc = (user or {}).get("prev_kyc_status") or "APPROVED"

    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {
        "status": "ACTIVE", "blocked_until": None,
        "blocked_reason": None, "pin_failed_attempts": 0, "pin_locked_until": None,
        # Restore KYC status
        "kyc_status": restored_kyc,
    }, "$unset": {"prev_kyc_status": ""}})

    # Resolve any open fraud alerts for this user
    await db.fraud_alerts.update_many(
        {"user_id": user_id, "status": "OPEN"},
        {"$set": {"status": "RESOLVED", "resolved_by": str(admin["_id"]), "resolved_at": datetime.now(timezone.utc).isoformat()}}
    )
    await audit(str(admin["_id"]), "UNBLOCK_USER", "fraud", {"user_id": user_id, "restored_kyc_status": restored_kyc})
    return {"message": "User unblocked and all open alerts resolved", "kyc_status_restored": restored_kyc}

@router.get("/admin/fraud/user/{user_id}/activity")
async def admin_fraud_user_activity(user_id: str, request: Request):
    await get_admin_user(request)
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(404, "User not found")
    # Last 50 transactions
    txns = await db.transactions.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).limit(50).to_list(50)
    # All fraud alerts for this user
    alerts_raw = await db.fraud_alerts.find({"user_id": user_id}).sort("created_at", -1).to_list(20)
    alerts = []
    for a in alerts_raw:
        a.pop("_id", None)
        if "resolved_by" in a: a["resolved_by"] = str(a["resolved_by"])
        alerts.append(a)
    # Login/OTP attempts summary
    login_attempts = await db.login_attempts.count_documents({"identifier": user.get("email", "")})
    # Login sessions (last 50)
    sessions_raw = await db.login_sessions.find(
        {"user_id": user_id}, {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    # Aggregate device patterns: group by device_id/IP for anomaly highlights
    ip_counts: dict = {}
    device_counts: dict = {}
    for s in sessions_raw:
        ip_counts[s.get("ip","?")] = ip_counts.get(s.get("ip","?"), 0) + 1
        dk = s.get("device_id") or s.get("device","?")
        device_counts[dk] = device_counts.get(dk, 0) + 1
    wallet = await db.wallets.find_one({"user_id": user_id}, {"_id": 0})
    return {
        "user": {
            "id": user_id, "name": f"{user.get('first_name','')} {user.get('last_name','')}".strip(),
            "phone": user.get("phone",""), "email": user.get("email",""),
            "status": user.get("status","ACTIVE"), "kyc_status": user.get("kyc_status",""),
            "blocked_reason": user.get("blocked_reason",""), "blocked_at": user.get("blocked_at",""),
            "blocked_until": user.get("blocked_until",""), "blocked_by": str(user.get("blocked_by","")) if user.get("blocked_by") else "",
            "pin_failed_attempts": user.get("pin_failed_attempts", 0),
            "created_at": user.get("created_at",""), "last_login": user.get("last_login",""),
        },
        "wallet": {"balance_ngn": (wallet or {}).get("available_balance", 0) / 100 if wallet else 0, "account_number": (wallet or {}).get("account_number","")},
        "transactions": txns,
        "fraud_alerts": alerts,
        "login_sessions": sessions_raw,
        "login_attempt_count": login_attempts,
        "device_summary": [{"key": k, "count": v} for k, v in sorted(device_counts.items(), key=lambda x: -x[1])[:10]],
        "ip_summary": [{"ip": k, "count": v} for k, v in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]],
    }

@router.get("/admin/fraud/blocked-users")
async def admin_blocked_users(request: Request):
    await get_admin_user(request)
    blocked = []
    async for u in db.users.find({"status": "SUSPENDED"}).sort("blocked_at", -1).limit(100):
        uid = str(u["_id"])
        open_alerts = await db.fraud_alerts.count_documents({"user_id": uid, "status": "OPEN"})
        blocked.append({
            "id": uid, "name": f"{u.get('first_name','')} {u.get('last_name','')}".strip(),
            "phone": u.get("phone",""), "email": u.get("email",""),
            "blocked_reason": u.get("blocked_reason",""), "blocked_at": u.get("blocked_at",""),
            "blocked_until": u.get("blocked_until",""), "open_alerts": open_alerts,
            "pin_failed_attempts": u.get("pin_failed_attempts", 0),
        })
    return {"blocked_users": blocked, "total": len(blocked)}

@router.post("/admin/fraud/bulk-block")
async def admin_bulk_block(request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    user_ids = body.get("user_ids", [])
    reason = body.get("reason", "MANUAL_BLOCK")
    hours = int(body.get("hours", 24))
    if not user_ids:
        raise HTTPException(400, "No user IDs provided")
    blocked_until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    success, failed = [], []
    for uid in user_ids:
        try:
            # Save previous KYC before blocking
            user = await db.users.find_one({"_id": ObjectId(uid)}, {"kyc_status": 1})
            prev_kyc = (user or {}).get("kyc_status", "PENDING")
            await db.users.update_one({"_id": ObjectId(uid)}, {"$set": {
                "status": "SUSPENDED", "blocked_until": blocked_until,
                "blocked_reason": reason, "blocked_at": datetime.now(timezone.utc).isoformat(),
                "blocked_by": str(admin["_id"]),
                "kyc_status": "PENDING",
                "prev_kyc_status": prev_kyc,
            }})
            await db.fraud_alerts.insert_one({
                "alert_id": str(uuid.uuid4()), "user_id": uid,
                "type": "MANUAL_BLOCK", "signals": [reason], "amount": 0,
                "status": "OPEN", "auto_blocked": False, "blocked_until": blocked_until,
                "metadata": {"reason": reason, "hours": hours, "bulk": True, "admin": str(admin["_id"])},
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            success.append(uid)
        except Exception:
            failed.append(uid)
    await audit(str(admin["_id"]), "BULK_BLOCK", "fraud",
                {"user_ids": success, "reason": reason, "hours": hours})
    return {"blocked": len(success), "failed": len(failed), "blocked_until": blocked_until}

@router.post("/admin/fraud/bulk-unblock")
async def admin_bulk_unblock(request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    user_ids = body.get("user_ids", [])
    if not user_ids:
        raise HTTPException(400, "No user IDs provided")
    success = 0
    for uid in user_ids:
        try:
            # Restore previous KYC status
            user = await db.users.find_one({"_id": ObjectId(uid)}, {"prev_kyc_status": 1})
            restored_kyc = (user or {}).get("prev_kyc_status") or "APPROVED"
            await db.users.update_one({"_id": ObjectId(uid)}, {"$set": {
                "status": "ACTIVE", "blocked_until": None, "blocked_reason": None,
                "pin_failed_attempts": 0, "pin_locked_until": None,
                "kyc_status": restored_kyc,
            }, "$unset": {"prev_kyc_status": ""}})
            await db.fraud_alerts.update_many(
                {"user_id": uid, "status": "OPEN"},
                {"$set": {"status": "RESOLVED", "resolved_by": str(admin["_id"]),
                          "resolved_at": datetime.now(timezone.utc).isoformat()}}
            )
            success += 1
        except Exception:
            pass
    await audit(str(admin["_id"]), "BULK_UNBLOCK", "fraud", {"user_ids": user_ids})
    return {"unblocked": success}

@router.get("/admin/fraud/alerts/export")
async def export_fraud_alerts(request: Request, alert_status: str = "all", fmt: str = "csv"):
    """Export fraud alerts as CSV."""
    await get_admin_user(request)
    query: dict = {}
    if alert_status != "all":
        query["status"] = alert_status.upper()
    raw = await db.fraud_alerts.find(query).sort("created_at", -1).to_list(10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Type", "User ID", "User Name", "User Phone",
                     "Signals", "Amount (NGN)", "Status", "Auto-blocked",
                     "Blocked Until", "Created At", "Resolved At"])
    for a in raw:
        a.pop("_id", None)
        writer.writerow([
            a.get("alert_id",""), a.get("type",""),
            a.get("user_id",""), a.get("user_name",""), a.get("user_phone",""),
            "|".join(a.get("signals",[])), round(a.get("amount",0)/100,2),
            a.get("status",""), a.get("auto_blocked",""),
            a.get("blocked_until",""), a.get("created_at",""), a.get("resolved_at","")
        ])
    from fastapi.responses import StreamingResponse as SR
    return SR(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=fraud_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.csv"}
    )

@router.get("/admin/providers")
async def admin_providers(request: Request):
    await get_admin_user(request)
    settings = await db.provider_settings.find({}, {"_id": 0}).to_list(20)
    for s in settings:
        if s.get("client_secret") and len(s["client_secret"]) > 4:
            s["client_secret"] = "****" + s["client_secret"][-4:]
    return {"providers": settings}

@router.get("/admin/providers/vas")
async def get_vas_provider_admin(request: Request):
    await get_admin_user(request)
    active = await get_vas_provider()
    return {
        "active_provider": active,
        "providers": [
            {
                "id": "CHEAPDATAHUB",
                "name": "CheapDataHub",
                "services": "Airtime, Data, Cable TV, Electricity",
                "configured": bool(os.environ.get("CHEAPDATAHUB_API_KEY")),
                "description": "Nigerian VAS aggregator — cheapdatahub.ng"
            },
            {
                "id": "SAFEHAVEN",
                "name": "Safe Haven MFB",
                "services": "Airtime, Data, Cable TV, Electricity (via banking VAS)",
                "configured": bool((await db.provider_settings.find_one({"provider": "safehaven"}) or {}).get("client_id")),
                "description": "Safe Haven microfinance bank VAS API"
            },
        ]
    }

@router.put("/admin/providers/vas")
async def switch_vas_provider_admin(request: Request):
    await get_admin_user(request)
    body = await request.json()
    provider_id = body.get("provider_id", "").upper()
    if provider_id not in ("CHEAPDATAHUB", "SAFEHAVEN"):
        raise HTTPException(400, "Invalid provider. Choose CHEAPDATAHUB or SAFEHAVEN")
    await db.settings.update_one(
        {"key": "vas_provider"},
        {"$set": {"key": "vas_provider", "value": provider_id, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"active_provider": provider_id, "message": f"VAS provider switched to {provider_id}"}

@router.put("/admin/providers/safehaven")
async def update_provider(req: ProviderSettingsReq, request: Request):
    admin = await get_admin_user(request)
    _sh_token.clear()
    update_fields = {
        "client_id": req.safehaven_client_id,
        "base_url": req.safehaven_base_url, "mode": req.mode,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    # Only overwrite private key if a non-blank value was submitted (preserves existing key)
    if req.safehaven_client_secret.strip():
        key_pem = req.safehaven_client_secret.strip()
        if "CERTIFICATE" in key_pem.upper():
            raise HTTPException(400, "Invalid key: You pasted a Certificate, not a Private Key. Safe Haven requires an RSA Private Key (-----BEGIN RSA PRIVATE KEY----- or -----BEGIN PRIVATE KEY-----).")
        update_fields["client_secret"] = key_pem
    # Only overwrite issuer if a non-blank value was submitted (preserves existing)
    if req.safehaven_issuer.strip():
        update_fields["issuer"] = req.safehaven_issuer.strip()
    # Only overwrite account number if a non-blank value was submitted
    if req.safehaven_account_number.strip():
        update_fields["account_number"] = req.safehaven_account_number.strip()
    await db.provider_settings.update_one({"provider": "safehaven"}, {"$set": update_fields}, upsert=True)
    await audit(admin["_id"], "UPDATE_PROVIDER", "safehaven", {"mode": req.mode})
    return {"message": "Provider settings updated successfully"}

@router.post("/admin/providers/safehaven/test")
async def test_provider(request: Request):
    await get_admin_user(request)
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    if not (settings or {}).get("client_id"):
        return {"status": "MOCK", "message": "Using simulated provider (no credentials configured)"}
    try:
        _sh_token.clear()
        r = await call_sh("GET", "/transfers/banks")
        if r and r.get("data"):
            return {"status": "CONNECTED", "message": "Safe Haven API connected successfully"}
        return {"status": "FAILED", "message": "Connected but received unexpected response"}
    except Exception as e:
        return {"status": "FAILED", "message": str(e)}

@router.put("/admin/users/{user_id}/status")
async def update_user_status(user_id: str, request: Request):
    await get_admin_user(request)
    body = await request.json()
    await db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": body.get("status", "ACTIVE")}})
    return {"message": "User status updated"}


@router.post("/admin/users/{user_id}/reset-pin")
async def admin_reset_user_pin(user_id: str, request: Request):
    """Admin: reset a customer's transaction PIN to default 0000."""
    await get_admin_user(request)
    try:
        oid = ObjectId(user_id)
    except Exception:
        raise HTTPException(400, "Invalid user ID")
    user = await db.users.find_one({"_id": oid}, {"phone": 1, "first_name": 1})
    if not user:
        raise HTTPException(404, "User not found")
    await db.users.update_one({"_id": oid}, {"$set": {
        "pin_hash": hash_pin("0000"),
        "pin_failed_attempts": 0,
        "pin_locked_until": None
    }})
    await audit(str(oid), "ADMIN_PIN_RESET", "auth", {"reset_to": "0000"})
    return {"message": f"PIN reset to 0000 for {user.get('phone', user_id)}"}

@router.get("/admin/users/{user_id}")
async def admin_user_detail(user_id: str, request: Request):
    await get_admin_user(request)
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"password_hash": 0})
    except Exception:
        raise HTTPException(404, "User not found")
    if not user:
        raise HTTPException(404, "User not found")
    uid = str(user["_id"])
    user["_id"] = uid
    wallet = await db.wallets.find_one({"user_id": uid}, {"_id": 0})
    loans = await db.loan_applications.find({"user_id": uid}, {"_id": 0}).sort("created_at", -1).to_list(10)
    savings = await db.savings_goals.find({"user_id": uid, "status": {"$ne": "DELETED"}}, {"_id": 0}).to_list(10)
    txns = await db.transactions.find({"user_id": uid}, {"_id": 0}).sort("created_at", -1).to_list(20)
    return {"user": user, "wallet": wallet, "loans": loans, "savings": savings, "transactions": txns}

@router.get("/admin/savings")
async def admin_savings(request: Request, page: int = 1, limit: int = 25,
                        search: str = None, savings_type: str = None,
                        date_from: str = None, date_to: str = None):
    await get_admin_user(request)
    q: dict = {"status": {"$ne": "DELETED"}}
    if savings_type:
        q["savings_type"] = savings_type
    if date_from or date_to:
        date_q: dict = {}
        if date_from: date_q["$gte"] = date_from + "T00:00:00"
        if date_to:   date_q["$lte"] = date_to   + "T23:59:59"
        q["created_at"] = date_q
    if search:
        matching_users = await db.users.find(
            {"$or": [{"first_name": {"$regex": search, "$options": "i"}},
                     {"last_name":  {"$regex": search, "$options": "i"}},
                     {"phone":      {"$regex": search, "$options": "i"}}]},
            {"_id": 1}
        ).to_list(100)
        uid_list = [str(u["_id"]) for u in matching_users]
        q["user_id"] = {"$in": uid_list}
    skip = (page - 1) * limit
    goals = await db.savings_goals.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    # Enrich with user info
    for g in goals:
        u = await db.users.find_one({"_id": ObjectId(g["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1})
        if u:
            g["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            g["user_phone"] = u.get("phone", "")
        g["target_amount_ngn"] = g.get("target_amount", 0) / 100
        g["current_amount_ngn"] = g.get("current_amount", 0) / 100
        g["interest_earned_ngn"] = g.get("interest_earned", 0) / 100
    return {"goals": goals, "total": await db.savings_goals.count_documents(q)}

@router.get("/admin/savings/{goal_id}")
async def admin_savings_detail(goal_id: str, request: Request):
    """Admin: get full detail + contribution breakdown for one savings goal."""
    await get_admin_user(request)
    goal = await db.savings_goals.find_one({"goal_id": goal_id}, {"_id": 0})
    if not goal:
        raise HTTPException(404, "Goal not found")
    u = await db.users.find_one({"_id": ObjectId(goal["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1, "email": 1})
    if u:
        goal["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        goal["user_phone"] = u.get("phone", "")
        goal["user_email"] = u.get("email", "")
    goal["target_amount_ngn"] = goal.get("target_amount", 0) / 100
    goal["current_amount_ngn"] = goal.get("current_amount", 0) / 100
    goal["interest_earned_ngn"] = goal.get("interest_earned", 0) / 100
    txns = await db.transactions.find(
        {"user_id": goal["user_id"], "type": "SAVINGS_CONTRIBUTION", "metadata.goal_id": goal_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(200)
    for t in txns:
        t["amount_ngn"] = t.get("amount", 0) / 100
    return {"goal": goal, "contributions": txns, "contribution_count": len(txns),
            "total_contributed": sum(t.get("amount", 0) for t in txns) / 100}

@router.get("/admin/savings-config")
async def admin_get_savings_config(request: Request):
    await get_admin_user(request)
    return await get_savings_config()

@router.put("/admin/savings-config")
async def update_savings_config(req: SavingsConfigReq, request: Request):
    await get_admin_user(request)
    await db.settings.update_one(
        {"key": "savings_config"},
        {"$set": {"key": "savings_config", "value": req.dict(),
                  "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"message": "Savings configuration updated successfully"}

# ─── Loan Admin Config ───
@router.get("/admin/loan-config")
async def get_loan_config_endpoint(request: Request):
    await get_admin_user(request)
    return await get_loan_config()

@router.put("/admin/loan-config")
async def update_loan_config(req: LoanConfigReq, request: Request):
    await get_admin_user(request)
    await db.settings.update_one(
        {"key": "loan_config"},
        {"$set": {"key": "loan_config", "value": req.dict(),
                  "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"message": "Loan configuration updated"}

# ─── Admin Ajo Endpoints ───
@router.get("/admin/ajo-config")
async def admin_get_ajo_config(request: Request):
    await get_admin_user(request)
    doc = await db.settings.find_one({"key": "ajo_config"})
    defaults = {
        "defaulter_fee_amount": 200.0,
        "savings_sh_account": "",
        "savings_sh_account_name": "Ajo Pool Account",
        "contribution_fee_type": "flat",   # "flat" | "percentage"
        "contribution_fee_value": 0.0,     # ₦ flat OR % value
    }
    return {**defaults, **(doc or {}).get("value", {})}

@router.put("/admin/ajo-config")
async def admin_update_ajo_config(request: Request):
    await get_admin_user(request)
    body = await request.json()
    await db.settings.update_one(
        {"key": "ajo_config"},
        {"$set": {"key": "ajo_config", "value": body, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"message": "Ajo configuration updated"}

@router.get("/admin/rewards-config")
async def admin_get_rewards_config(request: Request):
    await get_admin_user(request)
    return await get_rewards_config()

@router.put("/admin/rewards-config")
async def admin_update_rewards_config(request: Request):
    await get_admin_user(request)
    body = await request.json()
    await db.admin_config.update_one(
        {"key": "rewards_config"},
        {"$set": {"key": "rewards_config", "value": body, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"message": "Rewards config updated"}

@router.get("/admin/rewards-stats")
async def admin_rewards_stats(request: Request):
    await get_admin_user(request)
    total_cashback_agg = await db.cashback_history.aggregate([
        {"$match": {"amount_kobo": {"$gt": 0}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}}
    ]).to_list(1)
    total_cashback_naira = round((total_cashback_agg[0]["total"] if total_cashback_agg else 0) / 100, 2)
    total_referrals = await db.referral_history.count_documents({"role": "REFERRER"})
    total_referral_agg = await db.referral_history.aggregate([
        {"$match": {"amount_kobo": {"$gt": 0}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}}
    ]).to_list(1)
    total_referral_naira = round((total_referral_agg[0]["total"] if total_referral_agg else 0) / 100, 2)
    top_refs_pipeline = [
        {"$match": {"role": "REFERRER"}},
        {"$group": {"_id": "$user_id", "count": {"$sum": 1}, "total_earned": {"$sum": "$amount_kobo"}}},
        {"$sort": {"count": -1}}, {"$limit": 5}
    ]
    top_refs = await db.referral_history.aggregate(top_refs_pipeline).to_list(5)
    top_referrers = []
    for r in top_refs:
        try:
            u = await db.users.find_one({"_id": ObjectId(r["_id"])})
            if u:
                top_referrers.append({
                    "name": f"{u.get('first_name','')} {u.get('last_name','')}".strip(),
                    "email": u.get("email", ""), "count": r["count"],
                    "total_earned": round(r["total_earned"] / 100, 2)
                })
        except Exception:
            pass
    return {
        "total_cashback_paid_naira": total_cashback_naira,
        "total_referrals": total_referrals,
        "total_referral_bonus_naira": total_referral_naira,
        "top_referrers": top_referrers,
    }

@router.get("/admin/ajo")
async def admin_ajo_list(request: Request, page: int = 1, ajo_status: str = "",
                         search: str = None, frequency: str = None,
                         date_from: str = None, date_to: str = None):
    await get_admin_user(request)
    q: dict = {}
    if ajo_status:
        q["status"] = ajo_status
    if search:
        q["name"] = {"$regex": search, "$options": "i"}
    if frequency:
        q["frequency"] = frequency
    if date_from or date_to:
        date_q: dict = {}
        if date_from: date_q["$gte"] = date_from + "T00:00:00"
        if date_to:   date_q["$lte"] = date_to   + "T23:59:59"
        q["created_at"] = date_q
    skip = (page - 1) * 25
    groups = await db.ajo_groups.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(25).to_list(25)
    total = await db.ajo_groups.count_documents(q)
    for g in groups:
        g["member_count"] = await db.ajo_members.count_documents({"group_id": g["group_id"], "status": {"$ne": "LEFT"}})
        g["overdue_count"] = await db.ajo_members.count_documents({
            "group_id": g["group_id"], "status": {"$ne": "LEFT"},
            "consecutive_default_days": {"$gt": 0}
        })
        creator = await db.users.find_one({"_id": ObjectId(g["creator_id"])}, {"first_name": 1, "last_name": 1})
        g["creator_name"] = f"{(creator or {}).get('first_name','')} {(creator or {}).get('last_name','')}".strip()
    return {"groups": groups, "total": total, "page": page}

@router.get("/admin/ajo/{group_id}")
async def admin_ajo_detail(group_id: str, request: Request):
    await get_admin_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Ajo group not found")
    return await _build_ajo_detail(group)

@router.post("/admin/ajo/{group_id}/pause")
async def admin_ajo_pause(group_id: str, request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    reason = body.get("reason", "Paused by admin")
    group = await db.ajo_groups.find_one({"group_id": group_id})
    if not group:
        raise HTTPException(404, "Group not found")
    if group["status"] != "ACTIVE":
        raise HTTPException(400, f"Group is already {group['status']}")
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
        "status": "PAUSED", "pause_reason": reason, "paused_at": now_iso, "updated_at": now_iso
    }})
    await audit(admin["_id"], "AJO_PAUSED", "ajo_groups", {"group_id": group_id, "reason": reason})
    members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
    for m in members_raw:
        await notify(m["user_id"], f"Ajo '{group['name']}' Paused", f"Admin paused the group. Reason: {reason}", "warning")
    return {"message": "Group paused"}

@router.post("/admin/ajo/{group_id}/resume")
async def admin_ajo_resume(group_id: str, request: Request):
    admin = await get_admin_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id})
    if not group:
        raise HTTPException(404, "Group not found")
    if group["status"] != "PAUSED":
        raise HTTPException(400, "Group is not paused")
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
        "status": "ACTIVE", "pause_reason": None, "paused_at": None, "updated_at": now_iso
    }})
    await audit(admin["_id"], "AJO_RESUMED", "ajo_groups", {"group_id": group_id})
    members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
    for m in members_raw:
        await notify(m["user_id"], f"Ajo '{group['name']}' Resumed!", "Admin has resumed the group. Contributions continue.", "success")
    return {"message": "Group resumed"}

@router.get("/admin/loans")
async def admin_loans_all(request: Request, page: int = 1, loan_status: str = "",
                          search: str = None, date_from: str = None, date_to: str = None):
    await get_admin_user(request)
    q: dict = {}
    if loan_status:
        q["status"] = loan_status
    if date_from or date_to:
        date_q: dict = {}
        if date_from: date_q["$gte"] = date_from + "T00:00:00"
        if date_to:   date_q["$lte"] = date_to   + "T23:59:59"
        q["created_at"] = date_q
    if search:
        matching_users = await db.users.find(
            {"$or": [{"first_name": {"$regex": search, "$options": "i"}},
                     {"last_name":  {"$regex": search, "$options": "i"}},
                     {"phone":      {"$regex": search, "$options": "i"}}]},
            {"_id": 1}
        ).to_list(50)
        uid_list = [str(u["_id"]) for u in matching_users]
        q["user_id"] = {"$in": uid_list}
    skip = (page - 1) * 25
    loans = await db.loan_applications.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(25).to_list(25)
    for ln in loans:
        u = await db.users.find_one({"_id": ObjectId(ln["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1})
        if u:
            ln["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            ln["user_phone"] = u.get("phone", "")
    total = await db.loan_applications.count_documents(q)
    return {"loans": loans, "total": total, "page": page}

@router.get("/admin/loans-stats")
async def admin_loans_stats(request: Request):
    """Global loan counts independent of pagination/filters."""
    await get_admin_user(request)
    pipeline = [{"$group": {"_id": "$status", "count": {"$sum": 1}, "total_amount": {"$sum": "$amount"}}}]
    rows = await db.loan_applications.aggregate(pipeline).to_list(20)
    counts = {r["_id"]: r["count"] for r in rows}
    amounts = {r["_id"]: r["total_amount"] for r in rows}
    return {
        "total": sum(counts.values()),
        "pending": counts.get("PENDING", 0),
        "disbursed": counts.get("DISBURSED", 0),
        "repaid": counts.get("REPAID", 0),
        "rejected": counts.get("REJECTED", 0),
        "total_disbursed_amount": amounts.get("DISBURSED", 0) + amounts.get("REPAID", 0),
    }

@router.get("/admin/loans/{loan_id}")
async def admin_loan_detail(loan_id: str, request: Request):
    await get_admin_user(request)
    loan = await db.loan_applications.find_one({"loan_id": loan_id}, {"_id": 0})
    if not loan:
        raise HTTPException(404, "Loan not found")
    u = await db.users.find_one({"_id": ObjectId(loan["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1, "email": 1})
    if u:
        loan["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        loan["user_phone"] = u.get("phone",""); loan["user_email"] = u.get("email","")
    # Enrich schedule
    schedule = loan.get("repayment_schedule", [])
    paid = sum(1 for s in schedule if s["status"] == "PAID")
    defaulted = sum(1 for s in schedule if s["status"] == "DEFAULTED")
    total_defaulter_fees = sum((s.get("defaulter_fee") or 0) for s in schedule if s["status"] == "DEFAULTED")
    loan["schedule_summary"] = {"paid": paid, "defaulted": defaulted, "pending": len(schedule) - paid - defaulted, "total_defaulter_fees": total_defaulter_fees}
    return loan

@router.post("/admin/loans/{loan_id}/approve")
async def admin_approve_loan(loan_id: str, request: Request):
    """Admin approves a PENDING loan: generates schedule, does SH disbursement, credits wallet."""
    admin = await get_admin_user(request)
    loan = await db.loan_applications.find_one({"loan_id": loan_id})
    if not loan:
        raise HTTPException(404, "Loan not found")
    if loan["status"] != "PENDING":
        raise HTTPException(400, f"Loan is already {loan['status']}; only PENDING loans can be approved")
    loan_cfg = await get_loan_config()
    disbursed_at = datetime.now(timezone.utc)
    monthly = loan["monthly_payment"]
    # ─── Build repayment schedule now ───
    schedule = []
    for i in range(1, loan["tenor_months"] + 1):
        due_dt = disbursed_at + timedelta(days=30 * i)
        schedule.append({
            "installment": i, "due_date": due_dt.date().isoformat(),
            "amount": monthly, "status": "PENDING",
            "paid_at": None, "paid_amount": None, "defaulter_fee": None
        })
    # Disbursement: check LOANS service bucket first, fall back to loan_cfg.disbursement_sh_account
    disburse_sh_acct = await get_service_bucket_account("LOANS") or loan_cfg.get("disbursement_sh_account", "")
    amt = int(loan["amount"] * 100)
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    user_id = loan["user_id"]
    wallet_doc = await db.wallets.find_one({"user_id": user_id})
    user_sh = (wallet_doc or {}).get("sh_account_number", "")
    if disburse_sh_acct and user_sh:
        try:
            await call_sh("POST", "/transfers", body={
                "debitAccountNumber": disburse_sh_acct,
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": user_sh,
                "amount": loan["amount"], "saveBeneficiary": False,
                "narration": f"BOMPAY loan disbursement {loan_id[:8]}",
                "paymentReference": txn_id
            })
        except Exception as e:
            raise HTTPException(502, f"Safe Haven disbursement failed: {e}")
    elif disburse_sh_acct and not user_sh:
        logger.warning(f"[Loans] User {user_id} has no SH account; crediting BOMPAY wallet only")
    else:
        logger.warning("[Loans] No disbursement SH account configured; skipping SH transfer")
    # Credit BOMPAY wallet
    await db.wallets.update_one({"user_id": user_id}, {"$inc": {"available_balance": amt, "ledger_balance": amt}})
    await db.transactions.insert_one({
        "transaction_id": txn_id, "user_id": user_id,
        "type": "LOAN_DISBURSEMENT", "direction": "CREDIT", "amount": amt,
        "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
        "description": f"Loan approved — ₦{loan['amount']:,.2f}",
        "metadata": {"loan_id": loan_id, "approved_by": str(admin["_id"])},
        "created_at": disbursed_at.isoformat(), "updated_at": disbursed_at.isoformat()
    })
    await db.loan_applications.update_one({"loan_id": loan_id}, {"$set": {
        "status": "DISBURSED", "transaction_id": txn_id,
        "disbursed_at": disbursed_at.isoformat(),
        "repayment_schedule": schedule,
        "due_date": schedule[-1]["due_date"] if schedule else None,
        "approved_by": str(admin["_id"]), "updated_at": disbursed_at.isoformat()
    }})
    await notify(user_id, "Loan Approved!", f"₦{loan['amount']:,.2f} has been credited to your BOMPAY wallet.", "success")
    asyncio.create_task(send_event_notification(user_id, "LOAN_DISBURSED", {
        "amount": loan["amount"], "monthly": monthly, "tenor": loan["tenor_months"]
    }))
    await audit(admin["_id"], "LOAN_APPROVED", "loan_applications", {"loan_id": loan_id, "amount": loan["amount"]})
    return {"message": "Loan approved and disbursed", "loan_id": loan_id, "transaction_id": txn_id, "amount": loan["amount"]}

@router.post("/admin/loans/{loan_id}/reject")
async def admin_reject_loan(loan_id: str, request: Request):
    """Admin rejects a PENDING loan."""
    admin = await get_admin_user(request)
    body = await request.json()
    reason = body.get("reason", "Application did not meet requirements.")
    loan = await db.loan_applications.find_one({"loan_id": loan_id})
    if not loan:
        raise HTTPException(404, "Loan not found")
    if loan["status"] != "PENDING":
        raise HTTPException(400, f"Loan is {loan['status']}; only PENDING loans can be rejected")
    now = datetime.now(timezone.utc)
    await db.loan_applications.update_one({"loan_id": loan_id}, {"$set": {
        "status": "REJECTED", "rejection_reason": reason,
        "rejected_by": str(admin["_id"]), "rejected_at": now.isoformat(), "updated_at": now.isoformat()
    }})
    await notify(loan["user_id"], "Loan Application Rejected",
                 f"Your loan application for ₦{loan['amount']:,.2f} was not approved. Reason: {reason}", "error")
    await audit(admin["_id"], "LOAN_REJECTED", "loan_applications", {"loan_id": loan_id, "reason": reason})
    return {"message": "Loan application rejected", "loan_id": loan_id}

@router.get("/admin/kyc-queue")
async def admin_kyc_queue(request: Request):
    await get_admin_user(request)
    users = await db.users.find(
        {"kyc_tier": {"$gte": 0}},
        {"password_hash": 0}
    ).sort("created_at", -1).to_list(100)
    for u in users:
        u["_id"] = str(u["_id"])
    return {"users": users, "total": len(users)}


# ══════════════════════════════════════════════════════
# KYC TIER SYSTEM v2 — Tier 1/2/3 with document upload
# ══════════════════════════════════════════════════════

async def _ai_face_match(doc_bytes: bytes, doc_mime: str, selfie_bytes: bytes, selfie_mime: str) -> dict:
    """Use GPT-5.4 vision to compare face in ID document vs selfie."""
    try:
        import json as _json, re as _re, base64 as _b64
        from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent
        session_id = f"kyc-face-{uuid.uuid4()}"
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=session_id,
            system_message="You are a KYC document verification AI. Analyse identity documents and selfies for face matching. Always respond with valid JSON only."
        ).with_model("openai", "gpt-5.4")

        doc_b64 = _b64.b64encode(doc_bytes).decode()
        selfie_b64 = _b64.b64encode(selfie_bytes).decode()
        msg = UserMessage(
            text="""Analyse these two images for KYC verification.
Image 1: An identity document (passport, national ID, driver's licence, voter's card)
Image 2: A selfie/portrait photo of a person

Evaluate carefully:
1. Is Image 1 a valid, readable government identity document?
2. Do the faces in both images appear to be the same person?

Respond ONLY with this JSON (no markdown, no extra text):
{"is_valid_document":true,"faces_match":true,"confidence_score":0.85,"document_type":"passport","reason":"Faces match clearly"}""",
            file_contents=[ImageContent(image_base64=doc_b64), ImageContent(image_base64=selfie_b64)]
        )
        response = await chat.send_message(msg)
        text = (response or "").strip()
        m = _re.search(r'\{.*?\}', text, _re.DOTALL)
        if m:
            return _json.loads(m.group())
    except Exception as e:
        logger.error(f"[KYC AI] face match error: {e}")
    return {"is_valid_document": False, "faces_match": False, "confidence_score": 0.0, "document_type": "unknown", "reason": "AI analysis unavailable — pending manual review"}


def _serialize_submission(s: dict) -> dict:
    s = dict(s)
    s["_id"] = str(s.get("_id", ""))
    return s


# ── User: get tier requirements ────────────────────────────────────
@router.get("/kyc/tier-requirements")
async def kyc_tier_requirements():
    configs = await db.kyc_tier_configs.find({}, {"_id": 0}).sort("tier", 1).to_list(10)
    return {"tiers": configs}


# ── User: comprehensive KYC status (all tiers) ───────────────────
@router.get("/kyc/my-status")
async def kyc_my_status(request: Request):
    user = await get_current_user(request)
    uid = user["_id"]
    submissions = await db.kyc_submissions.find({"user_id": uid}).sort("tier", 1).to_list(10)
    for s in submissions:
        s["_id"] = str(s["_id"])
    # Remove sensitive paths from response
    for s in submissions:
        s.pop("id_document_path", None)
        s.pop("selfie_path", None)
        s.pop("passport_path", None)
    return {
        "current_tier": user.get("kyc_tier", 0),
        "kyc_status": user.get("kyc_status", "UNVERIFIED"),
        "submissions": submissions,
    }


# ── User: submit Tier 2 ────────────────────────────────────────────
@router.post("/kyc/submit-tier2")
async def kyc_submit_tier2(
    request: Request,
    id_type: str = Form(...),
    id_number: str = Form(...),
    address: str = Form(...),
    state: str = Form(...),
    lga: str = Form(...),
    id_document: UploadFile = File(...),
):
    user = await get_current_user(request)
    uid = user["_id"]
    if user.get("kyc_tier", 0) < 1:
        raise HTTPException(400, "You must complete Tier 1 (virtual account) before applying for Tier 2")
    if user.get("kyc_tier", 0) >= 2:
        raise HTTPException(400, "Tier 2 already approved")
    # Check for pending submission
    existing = await db.kyc_submissions.find_one({"user_id": uid, "tier": 2, "status": "pending"})
    if existing:
        raise HTTPException(400, "A Tier 2 submission is already under review")

    # Validate document
    ct = id_document.content_type or ""
    if ct not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(400, "ID document must be a JPEG, PNG, or WebP image")
    doc_data = await id_document.read()
    if len(doc_data) > 10 * 1024 * 1024:
        raise HTTPException(400, "Document must be under 10 MB")
    if id_type not in {"national_id", "drivers_license", "voter_card"}:
        raise HTTPException(400, "Invalid ID type")

    # Upload to Cloudinary
    public_id = f"{APP_NAME}/kyc/{uid}/tier2_id"
    try:
        doc_url = _cloudinary_upload(doc_data, public_id)
    except Exception as e:
        logger.error(f"[Cloudinary] Tier2 doc upload failed: {e}")
        raise HTTPException(500, "Document upload failed")

    # Auto-approve Tier 2 (document stored; admin can revoke)
    now = datetime.now(timezone.utc).isoformat()
    sub_doc = {
        "user_id": uid, "tier": 2, "status": "auto_approved",
        "id_type": id_type, "id_number": id_number,
        "address": address, "state": state, "lga": lga,
        "id_document_path": doc_url,
        "submitted_at": now, "reviewed_at": now,
        "auto_approved": True, "revoke_reason": None,
    }
    await db.kyc_submissions.insert_one(sub_doc)
    # Grant Tier 2
    await db.users.update_one(
        {"_id": ObjectId(uid)},
        {"$set": {"kyc_tier": 2, "kyc_status": "TIER_2_VERIFIED", "kyc_tier2_at": now}}
    )
    asyncio.create_task(_send_tier_approval_email(str(uid), 2))
    return {"success": True, "message": "Tier 2 approved — ID document verified", "tier": 2}


# ── User: submit Tier 3 (passport + selfie liveness) ──────────────
@router.post("/kyc/submit-tier3")
async def kyc_submit_tier3(
    request: Request,
    passport: UploadFile = File(...),
    selfie: UploadFile = File(...),
):
    user = await get_current_user(request)
    uid = user["_id"]
    if user.get("kyc_tier", 0) < 2:
        raise HTTPException(400, "You must complete Tier 2 before applying for Tier 3")
    if user.get("kyc_tier", 0) >= 3:
        raise HTTPException(400, "Tier 3 already approved")
    existing = await db.kyc_submissions.find_one({"user_id": uid, "tier": 3, "status": "pending"})
    if existing:
        raise HTTPException(400, "A Tier 3 submission is already under review")

    for f, label in [(passport, "passport"), (selfie, "selfie")]:
        ct = f.content_type or ""
        if ct not in {"image/jpeg", "image/png", "image/webp"}:
            raise HTTPException(400, f"{label} must be a JPEG, PNG, or WebP image")

    passport_data = await passport.read()
    selfie_data = await selfie.read()
    if len(passport_data) > 10 * 1024 * 1024:
        raise HTTPException(400, "Passport image must be under 10 MB")
    if len(selfie_data) > 10 * 1024 * 1024:
        raise HTTPException(400, "Selfie must be under 10 MB")

    pct = passport.content_type or "image/jpeg"
    sct = selfie.content_type or "image/jpeg"
    try:
        passport_url = _cloudinary_upload(passport_data, f"{APP_NAME}/kyc/{uid}/tier3_passport")
        selfie_url = _cloudinary_upload(selfie_data, f"{APP_NAME}/kyc/{uid}/tier3_selfie")
    except Exception as e:
        logger.error(f"[Cloudinary] Tier3 upload failed: {e}")
        raise HTTPException(500, "Image upload failed")

    # AI face match
    ai_result = await _ai_face_match(passport_data, pct, selfie_data, sct)
    confidence = float(ai_result.get("confidence_score", 0))
    faces_match = ai_result.get("faces_match", False)
    is_valid_doc = ai_result.get("is_valid_document", False)
    auto_approve = is_valid_doc and faces_match and confidence >= 0.70

    now = datetime.now(timezone.utc).isoformat()
    submission_status = "auto_approved" if auto_approve else "pending"
    sub_doc = {
        "user_id": uid, "tier": 3, "status": submission_status,
        "passport_path": passport_url, "selfie_path": selfie_url,
        "ai_result": ai_result,
        "confidence_score": confidence,
        "submitted_at": now,
        "reviewed_at": now if auto_approve else None,
        "auto_approved": auto_approve, "revoke_reason": None,
    }
    await db.kyc_submissions.insert_one(sub_doc)

    if auto_approve:
        await db.users.update_one(
            {"_id": ObjectId(uid)},
            {"$set": {"kyc_tier": 3, "kyc_status": "TIER_3_VERIFIED", "kyc_tier3_at": now}}
        )
        asyncio.create_task(_send_tier_approval_email(str(uid), 3))
        return {"success": True, "message": "Tier 3 approved — passport and face verified", "tier": 3, "auto_approved": True}
    else:
        return {"success": True, "message": "Tier 3 submission received — under manual review", "tier": 3, "auto_approved": False, "pending": True}


# ── Admin: serve KYC document image ───────────────────────────────
@router.get("/admin/kyc/document")
async def admin_get_kyc_document(request: Request, path: str):
    await get_admin_user(request)
    # path is now a Cloudinary URL — validate it's a Cloudinary URL before redirecting
    if not (path.startswith("https://res.cloudinary.com/") or path.startswith(f"{APP_NAME}/kyc/")):
        raise HTTPException(403, "Invalid document path")
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=path, status_code=302)


# ── Admin: get tier configs ────────────────────────────────────────
@router.get("/admin/kyc/tier-configs")
async def admin_get_tier_configs(request: Request):
    await get_admin_user(request)
    configs = await db.kyc_tier_configs.find({}, {"_id": 0}).sort("tier", 1).to_list(10)
    return {"tiers": configs}


# ── Admin: update tier config ──────────────────────────────────────
@router.put("/admin/kyc/tier-config/{tier}")
async def admin_update_tier_config(tier: int, body: KYCTierConfigUpdate, request: Request):
    admin = await get_admin_user(request)
    if tier not in (0, 1, 2, 3):
        raise HTTPException(400, "Tier must be 0, 1, 2, or 3")
    update = {"updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": str(admin["_id"])}
    if body.name is not None:
        update["name"] = body.name
    if body.description is not None:
        update["description"] = body.description
    if body.daily_transfer_limit_naira is not None:
        update["daily_transfer_limit_naira"] = body.daily_transfer_limit_naira
    if body.single_transfer_limit_naira is not None:
        update["single_transfer_limit_naira"] = body.single_transfer_limit_naira
    await db.kyc_tier_configs.update_one({"tier": tier}, {"$set": update}, upsert=True)
    return {"success": True, "message": f"Tier {tier} config updated"}


# ── Admin: list all KYC submissions ───────────────────────────────
@router.get("/admin/kyc/submissions")
async def admin_list_kyc_submissions(request: Request, tier: Optional[int] = None, submission_status: Optional[str] = None, page: int = 1):
    await get_admin_user(request)
    query: dict = {}
    if tier is not None:
        query["tier"] = tier
    if submission_status:
        query["status"] = submission_status
    skip = (page - 1) * 30
    subs = await db.kyc_submissions.find(query).sort("submitted_at", -1).skip(skip).limit(30).to_list(30)
    total = await db.kyc_submissions.count_documents(query)
    # Enrich with user info (name, phone)
    result = []
    for s in subs:
        s["_id"] = str(s["_id"])
        s.pop("id_document_path", None)
        s.pop("selfie_path", None)
        s.pop("passport_path", None)
        u = await db.users.find_one({"_id": ObjectId(s["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1, "email": 1, "kyc_tier": 1})
        if u:
            s["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            s["user_phone"] = u.get("phone", "")
            s["user_email"] = u.get("email", "")
            s["user_current_tier"] = u.get("kyc_tier", 0)
        result.append(s)
    return {"submissions": result, "total": total, "page": page, "pages": max(1, (total + 29) // 30)}


# ── Admin: full KYC details for a user ────────────────────────────
@router.get("/admin/kyc/user/{user_id}")
async def admin_get_user_kyc(user_id: str, request: Request):
    await get_admin_user(request)
    try:
        user = await db.users.find_one({"_id": ObjectId(user_id)}, {"pin_hash": 0, "password_hash": 0})
    except Exception:
        raise HTTPException(404, "User not found")
    if not user:
        raise HTTPException(404, "User not found")
    user["_id"] = str(user["_id"])
    subs = await db.kyc_submissions.find({"user_id": user_id}).sort("tier", 1).to_list(10)
    for s in subs:
        s["_id"] = str(s["_id"])
        # Documents are now Cloudinary URLs stored directly in the fields
        # Expose them as _url fields for the frontend while keeping field naming consistent
        for field in ("id_document_path", "selfie_path", "passport_path"):
            if s.get(field):
                s[f"{field}_url"] = s[field]  # Cloudinary URL stored directly
    # KYC record (BVN/NIN from original flow)
    kyc_record = await db.kyc_records.find_one({"user_id": user_id})
    if kyc_record:
        kyc_record["_id"] = str(kyc_record["_id"])
    return {"user": user, "submissions": subs, "kyc_record": kyc_record}


# ── Admin: revoke KYC tier ────────────────────────────────────────
@router.post("/admin/kyc/revoke")
async def admin_revoke_kyc(body: KYCRevokeReq, request: Request):
    admin = await get_admin_user(request)
    if body.tier not in (1, 2, 3):
        raise HTTPException(400, "Can only revoke tiers 1, 2, or 3")
    try:
        user = await db.users.find_one({"_id": ObjectId(body.user_id)})
    except Exception:
        raise HTTPException(404, "User not found")
    if not user:
        raise HTTPException(404, "User not found")
    current_tier = user.get("kyc_tier", 0)
    if current_tier < body.tier:
        raise HTTPException(400, f"User does not currently hold Tier {body.tier}")

    new_tier = body.tier - 1
    tier_status_map = {0: "UNVERIFIED", 1: "TIER_1_VERIFIED", 2: "TIER_2_VERIFIED"}
    new_status = tier_status_map.get(new_tier, "UNVERIFIED")
    now = datetime.now(timezone.utc).isoformat()

    # Mark submission as revoked
    await db.kyc_submissions.update_many(
        {"user_id": body.user_id, "tier": body.tier},
        {"$set": {"status": "revoked", "revoke_reason": body.reason, "revoked_at": now, "revoked_by": str(admin["_id"])}}
    )
    # Also revoke higher tiers
    for higher in range(body.tier + 1, 4):
        await db.kyc_submissions.update_many(
            {"user_id": body.user_id, "tier": higher},
            {"$set": {"status": "revoked", "revoke_reason": f"Revoked due to Tier {body.tier} revocation", "revoked_at": now}}
        )
    # Update user
    await db.users.update_one(
        {"_id": ObjectId(body.user_id)},
        {"$set": {"kyc_tier": new_tier, "kyc_status": new_status, f"kyc_tier{body.tier}_revoked_at": now}}
    )
    asyncio.create_task(_send_tier_revoke_email(str(body.user_id), body.tier, new_tier, body.reason or ""))
    # Audit log
    await db.audit_logs.insert_one({
        "admin_id": str(admin["_id"]), "action": "KYC_REVOKE",
        "target_user": body.user_id, "tier": body.tier,
        "reason": body.reason, "timestamp": now
    })
    return {"success": True, "message": f"Tier {body.tier} revoked. User downgraded to Tier {new_tier}.", "new_tier": new_tier}


# ── Admin: manually approve pending submission ────────────────────
@router.post("/admin/kyc/approve")
async def admin_approve_kyc(body: KYCApproveReq, request: Request):
    admin = await get_admin_user(request)
    try:
        sub = await db.kyc_submissions.find_one({"_id": ObjectId(body.submission_id)})
    except Exception:
        raise HTTPException(404, "Submission not found")
    if not sub:
        raise HTTPException(404, "Submission not found")
    if sub["status"] not in ("pending", "rejected"):
        raise HTTPException(400, f"Submission is already {sub['status']}")
    now = datetime.now(timezone.utc).isoformat()
    tier = sub["tier"]
    tier_status_map = {1: "TIER_1_VERIFIED", 2: "TIER_2_VERIFIED", 3: "TIER_3_VERIFIED"}
    await db.kyc_submissions.update_one(
        {"_id": ObjectId(body.submission_id)},
        {"$set": {"status": "approved", "reviewed_at": now, "reviewed_by": str(admin["_id"]), "admin_notes": body.notes or ""}}
    )
    await db.users.update_one(
        {"_id": ObjectId(sub["user_id"])},
        {"$set": {"kyc_tier": tier, "kyc_status": tier_status_map.get(tier, "VERIFIED"), f"kyc_tier{tier}_at": now}}
    )
    asyncio.create_task(_send_tier_approval_email(str(sub["user_id"]), tier))
    return {"success": True, "message": f"Tier {tier} manually approved", "tier": tier}


@router.post("/admin/notifications/broadcast")
async def broadcast_notification(request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    title = body.get("title", "System Notice")
    message = body.get("message", "")
    notif_type = body.get("type", "info")
    target = body.get("target", "all")
    query = {}
    if target == "active":
        query["status"] = "ACTIVE"
    elif target == "verified":
        query["kyc_tier"] = {"$gte": 1}
    users = await db.users.find(query, {"_id": 1}).to_list(10000)
    notifs = []
    for u in users:
        notifs.append({
            "notification_id": f"NOTIF{secrets.token_hex(8).upper()}",
            "user_id": str(u["_id"]),
            "title": title,
            "message": message,
            "type": notif_type,
            "read": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    if notifs:
        await db.notifications.insert_many(notifs)
    await audit(admin["_id"], "BROADCAST_NOTIFICATION", "notifications", {"target": target, "count": len(notifs)})
    return {"message": f"Notification sent to {len(notifs)} users", "count": len(notifs)}

@router.get("/admin/overview-chart")
async def admin_chart(request: Request):
    await get_admin_user(request)
    pipe = [
        {"$match": {"status": "COMPLETED", "direction": "DEBIT"}},
        {"$group": {
            "_id": {"$substr": ["$created_at", 0, 10]},
            "volume": {"$sum": "$amount"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 30}
    ]
    data = await db.transactions.aggregate(pipe).to_list(30)
    return {"data": [{"date": d["_id"], "volume": d["volume"] / 100, "count": d["count"]} for d in data]}

# ===== WEBHOOKS =====
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



@router.get("/admin/ledger/summary")
async def admin_ledger_summary(request: Request):
    await get_admin_user(request)
    try:
        return await pg_ledger.get_ledger_summary()
    except Exception as e:
        raise HTTPException(503, f"Ledger unavailable: {e}")

@router.get("/admin/ledger/entries")
async def admin_ledger_entries(request: Request, limit: int = 50, user_id: str = None):
    await get_admin_user(request)
    try:
        entries = await pg_ledger.get_recent_entries(limit=min(limit, 200), user_id=user_id)
        return {"entries": entries, "count": len(entries)}
    except Exception as e:
        raise HTTPException(503, f"Ledger unavailable: {e}")

@router.get("/admin/ledger/entries/{entry_id}")
async def admin_ledger_entry_lines(entry_id: str, request: Request):
    await get_admin_user(request)
    try:
        lines = await pg_ledger.get_entry_lines(entry_id)
        return {"lines": lines, "entry_id": entry_id}
    except Exception as e:
        raise HTTPException(503, f"Ledger unavailable: {e}")

# ===== FEE MANAGEMENT ADMIN ENDPOINTS =====
@router.get("/admin/fees")
async def get_fee_configs(request: Request):
    await get_admin_user(request)
    configs = await db.fee_configs.find({}, {"_id": 0}).to_list(50)
    return {"configs": configs}

@router.put("/admin/fees/{service}")
async def update_fee_config(service: str, req: FeeConfigReq, request: Request):
    await get_admin_user(request)
    service = service.upper()
    req.service = service
    update_data = {
        "service": service,
        "fee_type": req.fee_type.upper(),
        "flat_amount": req.flat_amount,
        "percentage": req.percentage,
        "min_fee": req.min_fee,
        "max_fee": req.max_fee,
        "tiers": req.tiers,
        "is_active": req.is_active,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.fee_configs.update_one(
        {"service": service},
        {"$set": update_data},
        upsert=True
    )
    return {"message": f"Fee config for {service} updated", "config": update_data}

@router.get("/admin/fees/preview")
async def preview_fee(service: str, amount: float, request: Request):
    await get_admin_user(request)
    fee = await calculate_fee(service.upper(), amount)
    return {"service": service.upper(), "amount": amount, "fee": fee, "total": amount + fee}

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

@router.get("/transfers/fee-preview")
async def preview_transfer_fee(amount: float, request: Request):
    """User-facing fee preview for transfer confirmation screen."""
    await get_current_user(request)
    bompay_fee = await calculate_fee("TRANSFER", amount)
    sh_fee = await get_nip_fee(amount)
    margin = round(max(bompay_fee - sh_fee, 0.0), 2)
    return {"amount": amount, "fee": bompay_fee, "total": amount + bompay_fee,
            "sh_fee": sh_fee, "bompay_margin": margin}

# ===== CDH PLANS & VALIDATION =====
@router.get("/vas/plans")
async def get_vas_plans(plan_type: str = "data"):
    """Return CDH verified data or cable plans."""
    if plan_type == "cable":
        return {"plans": CDH_CABLE_PLANS}
    return {"plans": CDH_DATA_PLANS}

@router.post("/vas/cable-validate")
async def cable_validate(req: CableValidateReq, request: Request):
    """Validate a cable TV smartcard and return subscriber name/details."""
    await get_current_user(request)
    provider_map = {"DSTV": "dstv", "GOTV": "gotv", "STARTIMES": "startimes"}
    prov_key = req.provider.upper()
    # Try PairGate first (it reliably returns subscriber names)
    svc_provider = await get_service_provider("CABLE")
    if svc_provider == "PAIRGATE":
        try:
            api_key = os.environ.get("PAIRGATE_API_KEY", "")
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(f"{PAIRGATE_BASE_URL}/cable/verify",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={"provider_id": prov_key, "smartcard": req.smartcard_number})
            logger.info(f"[PG] cable-validate status={r.status_code} body={r.text[:300]}")
            if r.status_code == 200:
                data = r.json()
                inner = data.get("data") or data
                status_ok = inner.get("status") is True or str(inner.get("status", "")).lower() in ("true", "success")
                if status_ok:
                    name = (inner.get("customer_name") or inner.get("name") or "").strip()
                    if name:
                        return {"valid": True, "verified": True, "name": name,
                                "smartcard_number": req.smartcard_number, "provider": req.provider}
                    else:
                        # PairGate says number is valid format but no subscriber found
                        return {"valid": True, "verified": False, "unverifiable": True,
                                "name": "", "smartcard_number": req.smartcard_number,
                                "provider": req.provider, "note": "Number format accepted — subscriber name not found"}
                else:
                    err_msg = inner.get("message") or data.get("message") or "Smartcard not found"
                    return {"valid": False, "verified": False, "name": "",
                            "smartcard_number": req.smartcard_number, "error": err_msg}
        except Exception as e:
            logger.warning(f"[PG] cable-validate failed: {e}")
    # Try CDH validation endpoint
    cdh_reached = False
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            api_key = os.environ.get("CHEAPDATAHUB_API_KEY", "")
            r = await c.post(f"{CDH_BASE_URL}/cable/validate/",
                headers={"Authorization": f"Token {api_key}", "Content-Type": "application/json"},
                json={"provider": provider_map.get(prov_key, prov_key.lower()),
                      "smartcard_number": req.smartcard_number})
        cdh_reached = True
        logger.info(f"[CDH] cable-validate status={r.status_code} body={r.text[:300]}")
        if r.status_code == 200:
            data = r.json()
            status_val = str(data.get("status", "")).lower()
            if status_val in ("true", "success", "1", "200"):
                inner = data.get("data") or data
                name = (inner.get("name") or inner.get("customer_name") or
                        inner.get("customerName") or inner.get("Customer_Name") or "")
                return {
                    "valid": True, "verified": True,
                    "name": name,
                    "smartcard_number": req.smartcard_number,
                    "provider": req.provider,
                }
            else:
                # CDH returned HTTP 200 with explicit failure status → number is invalid
                err_msg = (data.get("message") or data.get("error") or
                           data.get("detail") or "Smartcard not found. Please check and try again.")
                logger.warning(f"[CDH] cable-validate rejection: {err_msg}")
                return {"valid": False, "verified": False, "name": "",
                        "smartcard_number": req.smartcard_number,
                        "error": err_msg}
        # Any non-200 (404 = endpoint missing, 5xx = CDH down, etc.) → unverifiable, don't block
        logger.info(f"[CDH] cable-validate HTTP {r.status_code} — treating as unverifiable")
    except Exception as e:
        logger.warning(f"[CDH] cable-validate network error: {e}")
    # Both providers unavailable — cannot verify, but allow user to proceed with caution
    return {"valid": True, "verified": False, "unverifiable": True,
            "name": "", "smartcard_number": req.smartcard_number,
            "provider": req.provider, "note": "Could not verify — check number carefully before paying"}

@router.post("/vas/meter-validate")
async def meter_validate(req: MeterValidateReq, request: Request):
    """Validate electricity meter number."""
    await get_current_user(request)
    disco_id = CDH_ELECTRICITY_DISCO_IDS.get(req.disco.upper(), 1)
    # Try PairGate first
    svc_provider = await get_service_provider("ELECTRICITY")
    if svc_provider == "PAIRGATE":
        try:
            api_key = os.environ.get("PAIRGATE_API_KEY", "")
            meter_type_int = 1 if req.meter_type.upper() == "PREPAID" else 2
            pg_disco = PG_DISCO_SLUGS.get(req.disco.upper(), req.disco.lower())
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(f"{PAIRGATE_BASE_URL}/electricity/verify",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={"provider_id": pg_disco, "meter_number": req.meter_number, "meter_type": meter_type_int})
            logger.info(f"[PG] meter-validate status={r.status_code} body={r.text[:300]}")
            if r.status_code == 200:
                data = r.json()
                inner = data.get("data") or data
                status_ok = inner.get("status") is True or str(inner.get("status", "")).lower() in ("true", "success")
                if status_ok:
                    name = (inner.get("customer_name") or inner.get("name") or "").strip()
                    address = (inner.get("address") or "").strip()
                    if name and name.lower() not in ("unknown customer", "unknown"):
                        return {"valid": True, "verified": True, "name": name,
                                "address": address, "meter_number": req.meter_number}
                    # PairGate says format valid but no name → fall through to CDH then unverifiable
                    logger.info(f"[PG] meter-validate: status=true but no name for {req.disco}, falling through")
                else:
                    # status: false — could be invalid OR unsupported DisCo — fall through to CDH
                    logger.info(f"[PG] meter-validate: status=false for {req.disco}, falling through to CDH")
        except Exception as e:
            logger.warning(f"[PG] meter-validate failed: {e}")
    # Try CDH
    cdh_reached = False
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            api_key = os.environ.get("CHEAPDATAHUB_API_KEY", "")
            r = await c.post(f"{CDH_BASE_URL}/electricity/validate/",
                headers={"Authorization": f"Token {api_key}", "Content-Type": "application/json"},
                json={"disco_id": disco_id, "meter_number": req.meter_number,
                      "meter_type": req.meter_type.lower()})
        cdh_reached = True
        logger.info(f"[CDH] meter-validate status={r.status_code} body={r.text[:300]}")
        if r.status_code == 200:
            data = r.json()
            status_val = str(data.get("status", "")).lower()
            if status_val in ("true", "success", "1", "200"):
                inner = data.get("data") or data
                name = (inner.get("name") or inner.get("customer_name") or
                        inner.get("customerName") or inner.get("Customer_Name") or "")
                address = inner.get("address", "")
                return {"valid": True, "verified": True, "name": name,
                        "address": address, "meter_number": req.meter_number}
            else:
                # CDH returned HTTP 200 with explicit failure status → number is invalid
                err_msg = (data.get("message") or data.get("error") or
                           data.get("detail") or "Meter number not found. Please check and try again.")
                logger.warning(f"[CDH] meter-validate rejection: {err_msg}")
                return {"valid": False, "verified": False, "name": "",
                        "address": "", "meter_number": req.meter_number, "error": err_msg}
        # Any non-200 → unverifiable, don't block
        logger.info(f"[CDH] meter-validate HTTP {r.status_code} — treating as unverifiable")
    except Exception as e:
        logger.warning(f"[CDH] meter-validate network error: {e}")
    # Both providers unavailable — cannot verify, but allow user to proceed with caution
    return {"valid": True, "verified": False, "unverifiable": True,
            "name": "", "address": "", "meter_number": req.meter_number,
            "note": "Could not verify — check number carefully before paying"}
    """Validate a cable TV smartcard and return subscriber name/details."""
    await get_current_user(request)
    provider_map = {"DSTV": "dstv", "GOTV": "gotv", "STARTIMES": "startimes"}
    prov_key = req.provider.upper()
    # Try CDH validation endpoint
    cdh_reached = False
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            api_key = os.environ.get("CHEAPDATAHUB_API_KEY", "")
            r = await c.post(f"{CDH_BASE_URL}/cable/validate/",
                headers={"Authorization": f"Token {api_key}", "Content-Type": "application/json"},
                json={"provider": provider_map.get(prov_key, prov_key.lower()),
                      "smartcard_number": req.smartcard_number})
        cdh_reached = True
        logger.info(f"[CDH] cable-validate status={r.status_code} body={r.text[:300]}")
        if r.status_code == 200:
            data = r.json()
            status_val = str(data.get("status", "")).lower()
            if status_val in ("true", "success", "1", "200"):
                inner = data.get("data") or data
                name = (inner.get("name") or inner.get("customer_name") or
                        inner.get("customerName") or inner.get("Customer_Name") or "")
                return {
                    "valid": True, "verified": True,
                    "name": name,
                    "smartcard_number": req.smartcard_number,
                    "provider": req.provider,
                }
            else:
                # CDH returned HTTP 200 with explicit failure status → number is invalid
                err_msg = (data.get("message") or data.get("error") or
                           data.get("detail") or "Smartcard not found. Please check and try again.")
                logger.warning(f"[CDH] cable-validate rejection: {err_msg}")
                return {"valid": False, "verified": False, "name": "",
                        "smartcard_number": req.smartcard_number,
                        "error": err_msg}
        # Any non-200 (404 = endpoint missing, 5xx = CDH down, etc.) → unverifiable, don't block
        logger.info(f"[CDH] cable-validate HTTP {r.status_code} — treating as unverifiable")
    except Exception as e:
        logger.warning(f"[CDH] cable-validate network error: {e}")
    # CDH endpoint unavailable — cannot verify, but allow user to proceed with caution
    return {"valid": True, "verified": False, "unverifiable": True,
            "name": "", "smartcard_number": req.smartcard_number,
            "provider": req.provider, "note": "Could not verify — check number carefully before paying"}


# ===== VAS ROUTING (per-service provider selection) =====
VAS_SERVICES  = ["AIRTIME", "DATA", "CABLE", "ELECTRICITY", "BETTING", "EDUCATION", "TRANSFER"]
VAS_PROVIDERS = ["CDH", "PAIRGATE", "STROWALLET", "SAFEHAVEN"]

@router.get("/admin/vas-routing")
async def get_vas_routing(request: Request):
    await get_admin_user(request)
    routing = {}
    for svc in VAS_SERVICES:
        doc = await db.vas_routing.find_one({"service": svc})
        default = "SAFEHAVEN" if svc == "TRANSFER" else "CDH"
        routing[svc] = (doc or {}).get("provider", default)
    return {"routing": routing, "services": VAS_SERVICES, "providers": VAS_PROVIDERS}

@router.post("/admin/vas-routing")
async def set_vas_routing(request: Request):
    await get_admin_user(request)
    body = await request.json()
    updates = body.get("routing", {})
    for svc, prov in updates.items():
        svc = svc.upper()
        prov = prov.upper()
        if svc not in VAS_SERVICES:
            raise HTTPException(400, f"Unknown service: {svc}")
        if prov not in VAS_PROVIDERS:
            raise HTTPException(400, f"Unknown provider: {prov}")
        # Validate TRANSFER can only use SAFEHAVEN or STROWALLET
        if svc == "TRANSFER" and prov not in ("SAFEHAVEN", "STROWALLET"):
            raise HTTPException(400, "Transfer provider must be SAFEHAVEN or STROWALLET")
        # Validate VAS services cannot use SAFEHAVEN
        if svc not in ("TRANSFER",) and prov == "SAFEHAVEN":
            raise HTTPException(400, "SAFEHAVEN is only valid for TRANSFER service")
        # Education must use STROWALLET
        if svc == "EDUCATION" and prov not in ("STROWALLET",):
            raise HTTPException(400, "Education service only supports STROWALLET provider")
        await db.vas_routing.update_one(
            {"service": svc},
            {"$set": {"service": svc, "provider": prov, "updated_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
    return {"message": "VAS routing updated", "routing": updates}


# ===== SERVICE FLAGS (enable/disable app services) =====
ALL_MANAGED_SERVICES = [
    {"key": "AIRTIME",      "label": "Airtime",          "category": "Bills & Top-ups", "icon": "phone"},
    {"key": "DATA",         "label": "Data Bundles",      "category": "Bills & Top-ups", "icon": "wifi"},
    {"key": "CABLE",        "label": "Cable TV",          "category": "Bills & Top-ups", "icon": "tv"},
    {"key": "ELECTRICITY",  "label": "Electricity",       "category": "Bills & Top-ups", "icon": "zap"},
    {"key": "BETTING",      "label": "Betting",           "category": "Bills & Top-ups", "icon": "gamepad"},
    {"key": "EDUCATION",    "label": "Education",         "category": "Bills & Top-ups", "icon": "book"},
    {"key": "TRANSFERS",    "label": "Bank Transfer",     "category": "Transfers",        "icon": "arrow-up-right"},
    {"key": "NAIRA_CARD",   "label": "Naira Virtual Card","category": "Business",         "icon": "credit-card"},
    {"key": "USD_CARD",     "label": "USD Virtual Card",  "category": "Business",         "icon": "credit-card"},
    {"key": "SAVINGS",      "label": "Savings",           "category": "Save & Grow",      "icon": "piggy-bank"},
    {"key": "LOANS",        "label": "Loans",             "category": "Save & Grow",      "icon": "landmark"},
    {"key": "AJO",          "label": "Ajo Groups",        "category": "Save & Grow",      "icon": "users-round"},
    {"key": "FAMILY",       "label": "Family Wallet",     "category": "Family",           "icon": "heart-handshake"},
    {"key": "EPOS",         "label": "e-POS",             "category": "Business",         "icon": "smartphone"},
    {"key": "BUSINESS",     "label": "Business Account",  "category": "Business",         "icon": "building2"},
    {"key": "AJO_WALLET",   "label": "Ajo (Thrift)",      "category": "Save & Grow",      "icon": "users-round"},
]


@router.get("/admin/service-flags")
async def get_service_flags_admin(request: Request):
    """Admin: get all service flags with enable/disable state."""
    await get_admin_user(request)
    docs = await db.service_flags.find({}).to_list(None)
    flags_map = {d["service"]: d.get("enabled", True) for d in docs}
    result = []
    for svc in ALL_MANAGED_SERVICES:
        result.append({
            **svc,
            "enabled": flags_map.get(svc["key"], True),
            "updated_at": next((d.get("updated_at") for d in docs if d["service"] == svc["key"]), None),
        })
    return {"services": result}


@router.put("/admin/service-flags/{service}")
async def toggle_service_flag(service: str, request: Request):
    """Admin: enable or disable a service."""
    await get_admin_user(request)
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    service = service.upper()
    valid_keys = {s["key"] for s in ALL_MANAGED_SERVICES}
    if service not in valid_keys:
        raise HTTPException(400, f"Unknown service: {service}")
    await db.service_flags.update_one(
        {"service": service},
        {"$set": {"service": service, "enabled": enabled, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    state = "enabled" if enabled else "disabled"
    return {"service": service, "enabled": enabled, "message": f"Service {service} {state}"}


@router.get("/service-flags")
async def get_service_flags_public(request: Request = None):
    """Public: returns enabled/disabled state for all managed services (no auth)."""
    docs = await db.service_flags.find({}).to_list(None)
    flags = {d["service"]: d.get("enabled", True) for d in docs}
    # Ensure all managed services appear (default True)
    for svc in ALL_MANAGED_SERVICES:
        if svc["key"] not in flags:
            flags[svc["key"]] = True
    return {"flags": flags}


# ===== STROWALLET SMS CONFIG =====
@router.get("/admin/strowallet-sms-config")
async def get_strowallet_sms_config(request: Request):
    await get_admin_user(request)
    doc = await db.settings.find_one({"key": "strowallet_sms_config"})
    val = (doc or {}).get("value", {})
    return {
        "sender_id": val.get("sender_id", "BOMPAY"),
        "configured": bool((await db.card_config.find_one({"_id": "global"}) or {}).get("strowallet_public_key") or os.environ.get("STROWALLET_PUBLIC_KEY")),
    }


@router.put("/admin/strowallet-sms-config")
async def update_strowallet_sms_config(request: Request):
    await get_admin_user(request)
    body = await request.json()
    sender_id = (body.get("sender_id") or "BOMPAY").strip()[:11]
    await db.settings.update_one(
        {"key": "strowallet_sms_config"},
        {"$set": {"key": "strowallet_sms_config", "value": {"sender_id": sender_id}, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"message": "Strowallet SMS config saved", "sender_id": sender_id}


# ===== CONSOLE PIN (Master Admin 2nd factor) =====
@router.get("/admin/console/pin-status")
async def console_pin_status(request: Request):
    """Returns whether the logged-in admin has a console PIN configured."""
    admin = await get_admin_user(request)
    has_pin = bool((await db.users.find_one({"_id": ObjectId(admin["_id"])}, {"console_pin_hash": 1}) or {}).get("console_pin_hash"))
    return {"has_pin": has_pin}


@router.post("/admin/console/set-pin")
async def set_console_pin(request: Request):
    """Admin sets or changes their console PIN (6 digits)."""
    admin = await get_admin_user(request)
    body = await request.json()
    pin = str(body.get("pin", "")).strip()
    if not pin.isdigit() or len(pin) != 6:
        raise HTTPException(400, "Console PIN must be exactly 6 digits")
    pin_hash = hash_pin(pin)
    await db.users.update_one(
        {"_id": ObjectId(admin["_id"])},
        {"$set": {"console_pin_hash": pin_hash, "console_pin_updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "Console PIN set successfully"}


@router.post("/admin/console/remove-pin")
async def remove_console_pin(request: Request):
    """Admin removes their console PIN."""
    admin = await get_admin_user(request)
    await db.users.update_one(
        {"_id": ObjectId(admin["_id"])},
        {"$unset": {"console_pin_hash": "", "console_pin_updated_at": ""}}
    )
    return {"message": "Console PIN removed"}


@router.post("/admin/console/verify-pin")
async def verify_console_pin(request: Request):
    """Verify admin's console PIN (called after login). No auth cookie needed yet."""
    # We still need to verify they're logged in as admin
    admin = await get_admin_user(request)
    body = await request.json()
    pin = str(body.get("pin", "")).strip()
    if not pin.isdigit() or len(pin) != 6:
        raise HTTPException(400, "Console PIN must be exactly 6 digits")
    doc = await db.users.find_one({"_id": ObjectId(admin["_id"])}, {"console_pin_hash": 1})
    stored_hash = (doc or {}).get("console_pin_hash")
    if not stored_hash:
        # No PIN configured — auto-pass
        return {"message": "No PIN configured", "verified": True}
    if not verify_pin_hash(pin, stored_hash):
        raise HTTPException(403, "Incorrect console PIN. Please try again.")
    return {"message": "PIN verified", "verified": True}


# ===== EDUCATION CONFIG =====
@router.get("/admin/education-config")
async def get_education_config(request: Request):
    """Admin: get education product pricing."""
    await get_admin_user(request)
    from routes.strowallet import EDUCATION_PRODUCTS
    doc = await db.education_config.find_one({"_id": "prices"}) or {}
    overrides = doc.get("prices", {})
    products = []
    for p in EDUCATION_PRODUCTS:
        products.append({**p, "amount": overrides.get(p["id"], p["default_amount"])})
    return {"products": products}


@router.put("/admin/education-config")
async def update_education_config(request: Request):
    """Admin: update education product pricing."""
    await get_admin_user(request)
    body = await request.json()
    prices = {k: float(v) for k, v in (body.get("prices") or {}).items() if v}
    await db.education_config.update_one(
        {"_id": "prices"},
        {"$set": {"_id": "prices", "prices": prices, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"message": "Education pricing updated", "prices": prices}


# ===== EDUCATION TRANSACTIONS (admin view) =====
@router.get("/admin/education/transactions")
async def get_education_transactions(request: Request, page: int = 1, limit: int = 50):
    """Admin: list all education purchase transactions."""
    await get_admin_user(request)
    skip = (page - 1) * limit
    cursor = db.transactions.find(
        {"type": "EDUCATION"},
        {"_id": 0, "transaction_id": 1, "user_id": 1, "amount": 1, "status": 1,
         "description": 1, "metadata": 1, "created_at": 1, "provider_ref": 1}
    ).sort("created_at", -1).skip(skip).limit(limit)
    txns = await cursor.to_list(limit)
    total = await db.transactions.count_documents({"type": "EDUCATION"})
    # Enrich with user info
    enriched = []
    for t in txns:
        user = await db.users.find_one({"_id": ObjectId(t["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1})
        enriched.append({
            **t,
            "user_name": f"{(user or {}).get('first_name', '')} {(user or {}).get('last_name', '')}".strip(),
            "user_phone": (user or {}).get("phone", ""),
        })
    return {"transactions": enriched, "total": total, "page": page, "pages": (total + limit - 1) // limit}


# ===== CHARGE ACCOUNTS =====
@router.get("/admin/charge-accounts")
async def get_charge_accounts(request: Request):
    await get_admin_user(request)
    accounts = []
    for cat in CHARGE_CATEGORIES:
        doc = await db.charge_accounts.find_one({"category": cat["category"]})
        accounts.append({
            **cat,
            "sh_account_number": (doc or {}).get("sh_account_number", ""),
            "sh_account_name": (doc or {}).get("sh_account_name", ""),
            "updated_at": (doc or {}).get("updated_at", ""),
        })
    return {"accounts": accounts}

@router.put("/admin/charge-accounts/{category}")
async def update_charge_account(category: str, req: ChargeAccountReq, request: Request):
    await get_admin_user(request)
    cat_keys = [c["category"] for c in CHARGE_CATEGORIES]
    if category not in cat_keys:
        raise HTTPException(400, f"Unknown category. Valid: {cat_keys}")
    # Optionally verify account via Safe Haven name enquiry
    acct_name = req.sh_account_name
    if req.sh_account_number and not req.sh_account_name:
        try:
            # Try to look up account name via SH
            r = await call_sh("POST", "/transfers/name-enquiry",
                body={"bankCode": "090286", "accountNumber": req.sh_account_number})
            acct_name = r.get("data", {}).get("accountName", "")
        except Exception:
            pass
    await db.charge_accounts.update_one(
        {"category": category},
        {"$set": {
            "category": category,
            "sh_account_number": req.sh_account_number,
            "sh_account_name": acct_name,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }},
        upsert=True
    )
    return {"message": f"Charge account for {category} updated", "sh_account_number": req.sh_account_number,
            "sh_account_name": acct_name}

# ===== FEE REVENUE & ANALYTICS =====

@router.get("/admin/fee-revenue")
async def get_fee_revenue(request: Request, days: int = 30):
    """Fee sweep analytics: totals, daily series, pending retries, charge account balances."""
    await get_admin_user(request)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    window_start = (now - timedelta(days=days)).isoformat()

    sweeps = await db.transactions.find({
        "type": "FEE_SWEEP", "status": "COMPLETED",
        "created_at": {"$gte": window_start}
    }).to_list(10000)

    today_total = sum(s["amount"] for s in sweeps if s.get("created_at", "") >= today_start) / 100
    month_total = sum(s["amount"] for s in sweeps if s.get("created_at", "") >= month_start) / 100

    categories = list({s.get("metadata", {}).get("category", "TRANSFER_FEES") for s in sweeps})
    by_category: dict = {}
    for cat in categories:
        cat_sweeps = [s for s in sweeps if s.get("metadata", {}).get("category") == cat]
        by_category[cat] = {
            "today": sum(s["amount"] for s in cat_sweeps if s.get("created_at", "") >= today_start) / 100,
            "month": sum(s["amount"] for s in cat_sweeps if s.get("created_at", "") >= month_start) / 100,
            "total_sweeps": len(cat_sweeps),
            "total_ngn": sum(s["amount"] for s in cat_sweeps) / 100,
        }

    # Build daily series
    from collections import defaultdict
    daily: dict = defaultdict(lambda: {"total": 0.0})
    for s in sweeps:
        day = (s.get("created_at") or "")[:10]
        cat = s.get("metadata", {}).get("category", "TRANSFER_FEES")
        daily[day]["total"] += s["amount"] / 100
        daily[day][cat] = daily[day].get(cat, 0.0) + s["amount"] / 100
    daily_series = sorted([{"date": d, **v} for d, v in daily.items()], key=lambda x: x["date"])

    # Pending retries
    pending = await db.pending_fee_sweeps.find({"status": "PENDING"}).to_list(100)
    pending_list = [{
        "id": str(p["_id"]), "txn_id": p.get("txn_id"), "category": p.get("category"),
        "margin": p.get("margin"), "reason": p.get("reason"), "retries": p.get("retries", 0),
        "created_at": p.get("created_at"), "next_retry_at": p.get("next_retry_at")
    } for p in pending]

    # Charge account balances
    charge_balances: dict = {}
    for cat_def in CHARGE_CATEGORIES:
        cat_key = cat_def["category"]
        doc = await db.charge_accounts.find_one({"category": cat_key})
        if doc:
            charge_balances[cat_key] = {
                "total_swept_ngn": doc.get("total_swept_kobo", 0) / 100,
                "alert_threshold_ngn": doc.get("alert_threshold_ngn", 0),
                "last_alert_at": doc.get("last_alert_at", ""),
                "sh_account_number": doc.get("sh_account_number", ""),
                "master_account_number": doc.get("master_account_number", ""),
                "master_account_name": doc.get("master_account_name", ""),
            }

    return {
        "today_total_ngn": round(today_total, 2),
        "month_total_ngn": round(month_total, 2),
        "total_sweeps": len(sweeps),
        "pending_retries": len(pending),
        "pending_list": pending_list,
        "by_category": by_category,
        "daily_series": daily_series,
        "charge_balances": charge_balances,
    }

@router.get("/admin/sh-fee-config")
async def get_sh_fee_config(request: Request):
    await get_admin_user(request)
    config = await db.sh_fee_config.find_one({"type": "NIP_FEE_TIERS"})
    if not config:
        return {"type": "NIP_FEE_TIERS", "tiers": [
            {"label": "Micro", "max_amount": 5000, "fee": 10},
            {"label": "Standard", "max_amount": 50000, "fee": 25},
            {"label": "Large", "max_amount": 999999999, "fee": 50},
        ]}
    return {"type": "NIP_FEE_TIERS", "tiers": config.get("tiers", [])}

@router.put("/admin/sh-fee-config")
async def update_sh_fee_config(request: Request):
    await get_admin_user(request)
    body = await request.json()
    tiers = body.get("tiers", [])
    if not tiers:
        raise HTTPException(400, "Tiers array is required")
    await db.sh_fee_config.update_one(
        {"type": "NIP_FEE_TIERS"},
        {"$set": {"type": "NIP_FEE_TIERS", "tiers": tiers, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )
    return {"message": "NIP fee tiers saved"}

@router.put("/admin/charge-accounts/{category}/threshold")
async def update_charge_account_threshold(category: str, request: Request):
    await get_admin_user(request)
    body = await request.json()
    threshold = float(body.get("alert_threshold_ngn", 0))
    master_acct = body.get("master_account_number", "").strip()
    reset = bool(body.get("reset_counter", False))
    set_fields: dict = {"alert_threshold_ngn": threshold}
    if master_acct:
        # Validate master account via name enquiry
        try:
            ne = await call_sh("POST", "/transfers/name-enquiry", body={
                "bankCode": SAFEHAVEN_OWN_BANK_CODE, "accountNumber": master_acct
            })
            set_fields["master_account_number"] = master_acct
            set_fields["master_account_name"] = ne.get("data", {}).get("accountName", "")
        except Exception:
            set_fields["master_account_number"] = master_acct
    if reset:
        set_fields["total_swept_kobo"] = 0
        set_fields["last_alert_at"] = ""
    await db.charge_accounts.update_one({"category": category}, {"$set": set_fields}, upsert=True)
    return {"message": "Settings updated", "master_account_name": set_fields.get("master_account_name", "")}

@router.post("/admin/charge-accounts/{category}/sweep-to-master")
async def sweep_charge_account_to_master(category: str, request: Request):
    """Drain accumulated fee balance from charge account → master account in one click."""
    await get_admin_user(request)
    charge_doc = await db.charge_accounts.find_one({"category": category})
    if not charge_doc:
        raise HTTPException(404, "Charge account not configured")
    charge_acct_num = (charge_doc.get("sh_account_number") or "").strip()
    master_acct_num = (charge_doc.get("master_account_number") or "").strip()
    if not charge_acct_num:
        raise HTTPException(400, "Charge account number not set")
    if not master_acct_num:
        raise HTTPException(400, "Master account not configured — set it in the High-Balance Alert settings first")
    total_swept_kobo = charge_doc.get("total_swept_kobo", 0)
    sweep_ngn = round(total_swept_kobo / 100, 2)
    if sweep_ngn < 1.0:
        raise HTTPException(400, f"Nothing to sweep (accumulated: ₦{sweep_ngn:.2f})")
    # Name enquiry on master account
    ne = await call_sh("POST", "/transfers/name-enquiry", body={
        "bankCode": SAFEHAVEN_OWN_BANK_CODE, "accountNumber": master_acct_num
    })
    ne_ref = ne.get("data", {}).get("sessionId") or f"MASTERCHG{category}"
    master_name = ne.get("data", {}).get("accountName", "Master Account")
    txn_id = f"MASTERSWEEP{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    await call_sh("POST", "/transfers", body={
        "nameEnquiryReference": ne_ref,
        "debitAccountNumber": charge_acct_num,
        "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
        "beneficiaryAccountNumber": master_acct_num,
        "amount": sweep_ngn,
        "saveBeneficiary": False,
        "narration": f"Master sweep {category}",
        "paymentReference": txn_id
    })
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.transactions.insert_one({
        "transaction_id": txn_id, "user_id": "PLATFORM",
        "type": "MASTER_SWEEP", "direction": "DEBIT", "amount": total_swept_kobo, "fee": 0,
        "currency": "NGN", "status": "COMPLETED", "provider": "SAFEHAVEN",
        "description": f"Master sweep: {category} → {master_acct_num}",
        "metadata": {"category": category, "charge_account": charge_acct_num,
                     "master_account": master_acct_num, "master_name": master_name},
        "created_at": now_iso, "updated_at": now_iso
    })
    await db.charge_accounts.update_one(
        {"category": category},
        {"$set": {"total_swept_kobo": 0, "last_alert_at": "", "last_master_sweep_at": now_iso}}
    )
    logger.info(f"[MasterSweep] {category} ₦{sweep_ngn:.2f} → {master_acct_num} ({master_name})")
    return {"message": f"Swept ₦{sweep_ngn:,.2f} to {master_name}",
            "amount_ngn": sweep_ngn, "master_account": master_acct_num,
            "master_name": master_name, "txn_id": txn_id}

@router.post("/cron/retry-fee-sweeps")
async def cron_retry_fee_sweeps(request: Request):
    """Cron: retry pending fee sweeps (up to 5 attempts each)."""
    MAX_RETRIES = 5
    now = datetime.now(timezone.utc)
    pending = await db.pending_fee_sweeps.find({
        "status": "PENDING",
        "next_retry_at": {"$lte": now.isoformat()}
    }).to_list(50)
    success = failed_perm = 0
    for p in pending:
        await db.pending_fee_sweeps.update_one({"_id": p["_id"]}, {"$set": {"status": "RETRYING"}})
        try:
            await _sweep_fee_margin(
                txn_id=p["txn_id"], user_account=p["user_account"],
                bompay_fee_ngn=p["bompay_fee_ngn"], sh_fee_ngn=p["sh_fee_ngn"],
                category=p["category"]
            )
            await db.pending_fee_sweeps.update_one(
                {"_id": p["_id"]}, {"$set": {"status": "COMPLETED", "last_retry_at": now.isoformat()}}
            )
            success += 1
        except Exception as e:
            retries = p.get("retries", 0) + 1
            if retries >= MAX_RETRIES:
                await db.pending_fee_sweeps.update_one(
                    {"_id": p["_id"]},
                    {"$set": {"status": "FAILED_PERMANENTLY", "retries": retries, "reason": str(e)}}
                )
                failed_perm += 1
                # Alert admins about permanent failure
                admins = await db.users.find({"role": "admin"}).to_list(5)
                for au in admins:
                    await db.notifications.insert_one({
                        "notification_id": str(uuid.uuid4()), "user_id": au["_id"],
                        "title": "Fee Sweep Permanently Failed",
                        "message": f"Sweep for {p['txn_id']} ({p['category']}, ₦{p['margin']:.2f}) failed after {MAX_RETRIES} retries: {e}",
                        "type": "error", "is_read": False,
                        "created_at": now.isoformat()
                    })
            else:
                backoff = 15 * (2 ** retries)
                next_retry = (now + timedelta(minutes=backoff)).isoformat()
                await db.pending_fee_sweeps.update_one(
                    {"_id": p["_id"]},
                    {"$set": {"status": "PENDING", "retries": retries, "reason": str(e),
                              "last_retry_at": now.isoformat(), "next_retry_at": next_retry}}
                )
    return {"processed": len(pending), "success": success, "failed_permanently": failed_perm}
@router.get("/admin/sms-config")
async def get_sms_config_endpoint(request: Request):
    await get_admin_user(request)
    cfg = await get_sms_config()
    return cfg

@router.put("/admin/sms-config")
async def update_sms_config(req: SmsConfigReq, request: Request):
    await get_admin_user(request)
    if req.billing_day < 1 or req.billing_day > 28:
        raise HTTPException(400, "billing_day must be 1-28")
    if req.unit_cost_ngn < 0:
        raise HTTPException(400, "unit_cost_ngn must be >= 0")
    cfg = {"enabled": req.enabled, "unit_cost_ngn": req.unit_cost_ngn, "billing_day": req.billing_day}
    await db.settings.update_one({"key": "sms_config"}, {"$set": {"key": "sms_config", "value": cfg}}, upsert=True)
    return {"message": "SMS config updated", **cfg}

@router.get("/admin/sms-metrics")
async def sms_metrics(request: Request, days: int = 30):
    await get_admin_user(request)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    total = await db.sms_logs.count_documents({"created_at": {"$gte": since}})
    sent = await db.sms_logs.count_documents({"created_at": {"$gte": since}, "status": "SENT"})
    failed = await db.sms_logs.count_documents({"created_at": {"$gte": since}, "status": "FAILED"})
    # By event type
    pipeline = [
        {"$match": {"created_at": {"$gte": since}}},
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}}
    ]
    by_type = {d["_id"]: d["count"] async for d in db.sms_logs.aggregate(pipeline)}
    cfg = await get_sms_config()
    cost_ngn = round(sent * cfg.get("unit_cost_ngn", 4.0), 2)
    return {
        "period_days": days,
        "total": total, "sent": sent, "failed": failed,
        "delivery_rate": round(sent / total * 100, 1) if total else 0,
        "by_event_type": by_type,
        "charged_per_sms_ngn": cfg.get("unit_cost_ngn", 4.0),
        "estimated_revenue_ngn": cost_ngn,
        "billing_day": cfg.get("billing_day", 1),
    }

@router.get("/admin/sms-logs")
async def get_sms_logs(request: Request, page: int = 1, limit: int = 50, event_type: str = None):
    await get_admin_user(request)
    query: dict = {}
    if event_type:
        query["event_type"] = event_type
    skip = (page - 1) * limit
    logs = await db.sms_logs.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.sms_logs.count_documents(query)
    return {"logs": logs, "total": total, "page": page, "limit": limit}

# ===== ENHANCED ADMIN STATS =====
@router.get("/admin/stats/overview")
async def admin_stats_overview(request: Request):
    await get_admin_user(request)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    total_users = await db.users.count_documents({"role": {"$ne": "admin"}})
    new_users_today = await db.users.count_documents({
        "role": {"$ne": "admin"}, "created_at": {"$gte": today_start}
    })
    active_vas = bool((await db.settings.find_one({"key": "vas_provider"}) or {}).get("value"))
    kyc_queue = await db.users.count_documents({"kyc_status": {"$in": ["PENDING", "UNDER_REVIEW"]}})
    virtual_accounts = await db.wallets.count_documents({"sh_account_number": {"$exists": True, "$ne": ""}})

    txn_today = await db.transactions.count_documents({"created_at": {"$gte": today_start}})
    txn_month = await db.transactions.count_documents({"created_at": {"$gte": month_start}})

    vol_pipeline = [
        {"$match": {"created_at": {"$gte": month_start}, "status": "COMPLETED", "direction": "DEBIT"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    vol_result = await db.transactions.aggregate(vol_pipeline).to_list(1)
    vol_month = (vol_result[0]["total"] / 100) if vol_result else 0

    fee_pipeline = [
        {"$match": {"created_at": {"$gte": month_start}, "type": "FEE_INCOME", "status": "COMPLETED"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]
    fee_result = await db.transactions.aggregate(fee_pipeline).to_list(1)
    fee_month = (fee_result[0]["total"] / 100) if fee_result else 0

    sms_sent_month = await db.sms_logs.count_documents({"created_at": {"$gte": month_start}, "status": "SENT"})
    sms_total_month = await db.sms_logs.count_documents({"created_at": {"$gte": month_start}})

    open_tickets = await db.support_tickets.count_documents({"status": {"$in": ["OPEN", "IN_PROGRESS"]}})
    fraud_alerts = await db.fraud_alerts.count_documents({"status": "OPEN"})
    active_loans = await db.loan_applications.count_documents({"status": "DISBURSED"})

    txn_type_pipeline = [
        {"$match": {"created_at": {"$gte": month_start}, "status": "COMPLETED"}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}, "volume": {"$sum": "$amount"}}}
    ]
    txn_by_type = {}
    async for d in db.transactions.aggregate(txn_type_pipeline):
        txn_by_type[d["_id"]] = {"count": d["count"], "volume": round(d["volume"] / 100, 2)}

    return {
        "users": {
            "total": total_users,
            "new_today": new_users_today,
            "with_virtual_account": virtual_accounts,
            "kyc_queue": kyc_queue,
        },
        "transactions": {
            "today_count": txn_today,
            "month_count": txn_month,
            "month_volume_ngn": round(vol_month, 2),
            "month_fee_income_ngn": round(fee_month, 2),
            "by_type": txn_by_type,
        },
        "sms": {
            "sent_this_month": sms_sent_month,
            "total_this_month": sms_total_month,
            "delivery_rate": round(sms_sent_month / sms_total_month * 100, 1) if sms_total_month else 0,
        },
        "operations": {
            "open_support_tickets": open_tickets,
            "fraud_alerts_open": fraud_alerts,
            "active_loans": active_loans,
            "vas_provider": (await get_vas_provider()),
        }
    }

@router.get("/admin/dashboard/full")
async def admin_dashboard_full(request: Request):
    """Consolidated dashboard endpoint: stats + providers + charts + recent activity."""
    await get_admin_user(request)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    # ── User metrics ──
    total_users = await db.users.count_documents({"role": {"$ne": "admin"}})
    new_today = await db.users.count_documents({"role": {"$ne": "admin"}, "created_at": {"$gte": today_start}})
    new_month = await db.users.count_documents({"role": {"$ne": "admin"}, "created_at": {"$gte": month_start}})
    kyc_pending = await db.users.count_documents({"kyc_status": {"$in": ["PENDING", "UNDER_REVIEW"]}})
    virtual_accts = await db.wallets.count_documents({"sh_account_number": {"$exists": True, "$ne": ""}})

    # ── All-time totals (accumulation) ──
    all_time_users = total_users  # already all-time
    all_time_txn_count = await db.transactions.count_documents({"user_id": {"$ne": "PLATFORM"}})
    vol_alltime_res = await db.transactions.aggregate([
        {"$match": {"status": "COMPLETED", "direction": "DEBIT", "user_id": {"$ne": "PLATFORM"}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    vol_all_time = (vol_alltime_res[0]["total"] / 100) if vol_alltime_res else 0
    fee_alltime_res = await db.transactions.aggregate([
        {"$match": {"type": "FEE_INCOME", "status": "COMPLETED"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    fee_all_time = (fee_alltime_res[0]["total"] / 100) if fee_alltime_res else 0
    stamp_alltime_res = await db.transactions.aggregate([
        {"$match": {"fee_stamp_duty": {"$gt": 0}, "status": "COMPLETED"}},
        {"$group": {"_id": None, "total": {"$sum": "$fee_stamp_duty"}}}
    ]).to_list(1)
    stamp_all_time = (stamp_alltime_res[0]["total"] / 100) if stamp_alltime_res else 0

    # ── Transaction metrics ──
    txn_today = await db.transactions.count_documents({"created_at": {"$gte": today_start}})
    txn_month = await db.transactions.count_documents({"created_at": {"$gte": month_start}})
    vol_res = await db.transactions.aggregate([
        {"$match": {"created_at": {"$gte": month_start}, "status": "COMPLETED", "direction": "DEBIT"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    vol_month = (vol_res[0]["total"] / 100) if vol_res else 0

    vol_today_res = await db.transactions.aggregate([
        {"$match": {"created_at": {"$gte": today_start}, "status": "COMPLETED", "direction": "DEBIT"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    vol_today = (vol_today_res[0]["total"] / 100) if vol_today_res else 0

    fee_res = await db.transactions.aggregate([
        {"$match": {"created_at": {"$gte": month_start}, "type": "FEE_SWEEP", "status": "COMPLETED"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    fee_month = (fee_res[0]["total"] / 100) if fee_res else 0

    # Transaction by type
    txn_by_type: dict = {}
    async for d in db.transactions.aggregate([
        {"$match": {"created_at": {"$gte": month_start}, "status": "COMPLETED"}},
        {"$group": {"_id": "$type", "count": {"$sum": 1}, "volume": {"$sum": "$amount"}}}
    ]):
        txn_by_type[d["_id"]] = {"count": d["count"], "volume": round(d["volume"] / 100, 2)}

    # ── Operational metrics ──
    open_tickets = await db.support_tickets.count_documents({"status": {"$in": ["OPEN", "IN_PROGRESS"]}})
    fraud_open = await db.fraud_alerts.count_documents({"status": "OPEN"})
    active_loans = await db.loan_applications.count_documents({"status": "DISBURSED"})
    active_savings = await db.savings_goals.count_documents({"status": "ACTIVE"})
    active_ajo = await db.ajo_groups.count_documents({"status": "ACTIVE"})
    epos_today = await db.epos_transactions.count_documents({"created_at": {"$gte": today_start}}) if hasattr(db, 'epos_transactions') else 0

    # SMS metrics
    sms_month = await db.sms_logs.count_documents({"created_at": {"$gte": month_start}})
    sms_sent = await db.sms_logs.count_documents({"created_at": {"$gte": month_start}, "status": "SENT"})
    sms_rate = round(sms_sent / sms_month * 100, 1) if sms_month else 0

    # ── 14-day daily series ──
    cutoff_14 = (now - __import__("datetime").timedelta(days=14)).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    daily_map: dict = {}
    # Fill empty days
    for i in range(14):
        d = (now - __import__("datetime").timedelta(days=13 - i)).date().isoformat()
        daily_map[d] = {"date": d, "volume": 0.0, "count": 0, "users": 0}
    async for row in db.transactions.aggregate([
        {"$match": {"created_at": {"$gte": cutoff_14}, "status": "COMPLETED", "direction": "DEBIT"}},
        {"$group": {"_id": {"$substr": ["$created_at", 0, 10]}, "volume": {"$sum": "$amount"}, "count": {"$sum": 1}}}
    ]):
        if row["_id"] in daily_map:
            daily_map[row["_id"]]["volume"] = round(row["volume"] / 100, 2)
            daily_map[row["_id"]]["count"] = row["count"]
    async for row in db.users.aggregate([
        {"$match": {"created_at": {"$gte": cutoff_14}, "role": {"$ne": "admin"}}},
        {"$group": {"_id": {"$substr": ["$created_at", 0, 10]}, "count": {"$sum": 1}}}
    ]):
        if row["_id"] in daily_map:
            daily_map[row["_id"]]["users"] = row["count"]
    daily_series = sorted(daily_map.values(), key=lambda x: x["date"])

    # ── Provider health ──
    sh_settings = await db.provider_settings.find_one({"provider": "safehaven"}) or {}
    active_sms = await get_sms_provider()
    active_vas = await get_vas_provider()
    email_cfg = (await db.settings.find_one({"key": "admin_email_config"})) or {}
    resend_ok = bool(email_cfg.get("resend_api_key") or os.environ.get("RESEND_API_KEY"))
    providers = [
        {"id": "MONGODB", "name": "MongoDB", "category": "Database", "status": "OK", "detail": "Primary database"},
        {"id": "API", "name": "API Server", "category": "Backend", "status": "OK", "detail": "FastAPI backend"},
        {"id": "SAFEHAVEN", "name": "Safe Haven MFB", "category": "Banking",
         "status": "OK" if sh_settings.get("client_id") else "UNCONFIGURED",
         "detail": sh_settings.get("mode", "sandbox").upper() + " mode" if sh_settings.get("client_id") else "Not configured"},
        {"id": "CHEAPDATAHUB", "name": "CheapDataHub", "category": "VAS",
         "status": "OK" if os.environ.get("CHEAPDATAHUB_API_KEY") else "UNCONFIGURED",
         "detail": "Active" if active_vas == "CHEAPDATAHUB" else "Standby"},
        {"id": "PAIRGATE", "name": "PairGate", "category": "VAS",
         "status": "OK" if os.environ.get("PAIRGATE_API_KEY") else "UNCONFIGURED",
         "detail": "Active" if active_vas == "PAIRGATE" else "Standby"},
        {"id": "BULKSMSLIVE", "name": "BulkSMSLive", "category": "SMS",
         "status": "OK" if active_sms == "BULKSMSLIVE" else "STANDBY",
         "detail": "Active SMS" if active_sms == "BULKSMSLIVE" else "Standby"},
        {"id": "SENDORA", "name": "Sendora", "category": "SMS",
         "status": "OK" if (os.environ.get("SENDORA_API_KEY") and active_sms == "SENDORA") else (
             "STANDBY" if os.environ.get("SENDORA_API_KEY") else "UNCONFIGURED"),
         "detail": "Active SMS" if active_sms == "SENDORA" else "Standby"},
        {"id": "RESEND", "name": "Resend Email", "category": "Email",
         "status": "OK" if resend_ok else "UNCONFIGURED",
         "detail": "Transactional email"},
    ]

    # ── Recent activity (for notifications) ──
    recent_users = []
    async for u in db.users.find({"role": {"$ne": "admin"}}, {"_id": 0, "first_name": 1, "last_name": 1, "phone": 1, "created_at": 1}).sort("created_at", -1).limit(5):
        recent_users.append({"type": "NEW_USER", "name": f"{u.get('first_name','')} {u.get('last_name','')}".strip() or u.get("phone",""), "created_at": u.get("created_at","")})

    recent_txns_raw = await db.transactions.find({}, {"_id": 0, "type": 1, "amount": 1, "direction": 1, "status": 1, "created_at": 1, "description": 1}).sort("created_at", -1).limit(5).to_list(5)
    recent_events = sorted(
        recent_users + [{"type": "TRANSACTION", "name": t.get("description") or t.get("type","").replace("_"," "), "amount": t.get("amount",0), "status": t.get("status",""), "created_at": t.get("created_at","")} for t in recent_txns_raw],
        key=lambda x: x.get("created_at",""), reverse=True
    )[:10]

    return {
        "users": {"total": total_users, "new_today": new_today, "new_month": new_month, "kyc_pending": kyc_pending, "virtual_accounts": virtual_accts},
        "transactions": {"today_count": txn_today, "month_count": txn_month, "vol_month_ngn": round(vol_month, 2), "vol_today_ngn": round(vol_today, 2), "fee_month_ngn": round(fee_month, 2), "by_type": txn_by_type},
        "all_time": {
            "users": all_time_users,
            "transactions": all_time_txn_count,
            "volume_ngn": round(vol_all_time, 2),
            "fee_income_ngn": round(fee_all_time, 2),
            "stamp_duty_ngn": round(stamp_all_time, 2),
        },
        "operations": {"active_loans": active_loans, "active_savings": active_savings, "active_ajo": active_ajo, "fraud_open": fraud_open, "open_tickets": open_tickets, "epos_today": epos_today},
        "sms": {"sent_month": sms_sent, "total_month": sms_month, "delivery_rate": sms_rate, "active_provider": active_sms},
        "providers": providers,
        "daily_series": daily_series,
        "recent_events": recent_events,
        "active_vas": active_vas,
        "server_time": now.isoformat(),
    }

@router.get("/admin/live-events")
async def admin_live_events(request: Request, since: str = None):
    """Poll for new users/transactions since a given ISO timestamp."""
    await get_admin_user(request)
    query: dict = {}
    if since:
        query["created_at"] = {"$gt": since}
    new_user_count = await db.users.count_documents({"role": {"$ne": "admin"}, **query})
    new_txn_count = await db.transactions.count_documents(query)
    events = []
    if new_user_count:
        async for u in db.users.find({"role": {"$ne": "admin"}, **query}, {"_id": 0, "first_name": 1, "last_name": 1, "phone": 1, "created_at": 1}).sort("created_at", -1).limit(5):
            events.append({"type": "NEW_USER", "name": f"{u.get('first_name','')} {u.get('last_name','')}".strip() or u.get("phone",""), "created_at": u.get("created_at","")})
    if new_txn_count:
        async for t in db.transactions.find(query, {"_id": 0, "type": 1, "amount": 1, "status": 1, "created_at": 1, "description": 1}).sort("created_at", -1).limit(5):
            events.append({"type": "TRANSACTION", "name": t.get("description") or t.get("type","").replace("_"," "), "amount": t.get("amount",0), "status": t.get("status",""), "created_at": t.get("created_at","")})
    return {"new_users": new_user_count, "new_transactions": new_txn_count, "events": events, "checked_at": datetime.now(timezone.utc).isoformat()}

# ===== ADMIN USER DETAIL =====
@router.get("/admin/users/{user_id}/detail")
async def admin_user_detail_full(user_id: str, request: Request):
    await get_admin_user(request)
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(404, "User not found")
    wallet = await db.wallets.find_one({"user_id": user_id})
    txns = await db.transactions.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).limit(20).to_list(20)
    savings = await db.savings_goals.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(10)
    loans = await db.loan_applications.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(10)
    tickets = await db.support_tickets.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(10)
    sms_count = await db.sms_logs.count_documents({"user_id": user_id})
    watchlist = await db.watchlist.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(10)
    full_user = await db.users.find_one({"_id": ObjectId(user_id)}, {"password_hash": 0, "pin_hash": 0})
    return {
        "user": {
            "id": user_id,
            "email": str(full_user.get("email", "")),
            "first_name": str(full_user.get("first_name", "")),
            "last_name": str(full_user.get("last_name", "")),
            "phone": str(full_user.get("phone", "")),
            "role": str(full_user.get("role", "user")),
            "kyc_tier": full_user.get("kyc_tier", 0),
            "kyc_status": str(full_user.get("kyc_status", "PENDING")),
            "status": str(full_user.get("status", "ACTIVE")),
            "reward_points": full_user.get("reward_points", 0),
            "referral_code": str(full_user.get("referral_code", "")),
            "created_at": str(full_user.get("created_at", "")),
            "last_login": str(full_user.get("last_login", "")),
        },
        "wallet": {
            "available_balance": (wallet or {}).get("available_balance", 0) / 100,
            "ledger_balance": (wallet or {}).get("ledger_balance", 0) / 100,
            "sh_account_number": (wallet or {}).get("sh_account_number", ""),
            "sh_account_name": (wallet or {}).get("sh_account_name", ""),
            "sh_account_id": (wallet or {}).get("sh_account_id", ""),
            "status": (wallet or {}).get("status", "ACTIVE"),
        } if wallet else None,
        "transactions": txns,
        "savings": savings,
        "loans": loans,
        "support_tickets": tickets,
        "sms_count": sms_count,
        "watchlist": watchlist,
    }

@router.post("/admin/users/{user_id}/watchlist")
async def add_to_watchlist(user_id: str, request: Request):
    await get_admin_user(request)
    body = await request.json()
    reason = body.get("reason", "")
    admin = await get_admin_user(request)
    entry = {
        "watchlist_id": str(uuid.uuid4()),
        "user_id": user_id,
        "reason": reason,
        "added_by": admin.get("email", "admin"),
        "status": "ACTIVE",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.watchlist.update_one(
        {"user_id": user_id, "status": "ACTIVE"},
        {"$set": entry},
        upsert=True
    )
    return {"message": "User added to watchlist", "entry": entry}

@router.delete("/admin/users/{user_id}/watchlist")
async def remove_from_watchlist(user_id: str, request: Request):
    await get_admin_user(request)
    await db.watchlist.update_many(
        {"user_id": user_id, "status": "ACTIVE"},
        {"$set": {"status": "REMOVED", "removed_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "User removed from watchlist"}

# ===== SENDORA CONFIG ADMIN =====
@router.get("/admin/sendora-config")
async def get_sendora_config_endpoint(request: Request):
    await get_admin_user(request)
    doc = await db.settings.find_one({"key": "sendora_config"})
    val = (doc or {}).get("value", {})
    raw_key = val.get("api_key") or os.environ.get("SENDORA_API_KEY", "")
    # Mask all but last 6 chars
    masked = ("*" * max(0, len(raw_key) - 6)) + raw_key[-6:] if raw_key else ""
    sender_id = val.get("sender_id") or os.environ.get("SENDORA_SENDER_ID", "BOMPAY")
    return {
        "api_key_masked": masked,
        "has_key": bool(raw_key),
        "sender_id": sender_id,
        "source": "database" if val.get("api_key") else "environment"
    }

@router.put("/admin/sendora-config")
async def update_sendora_config(req: SendoraConfigReq, request: Request):
    await get_admin_user(request)
    if not req.api_key.strip():
        raise HTTPException(400, "API key cannot be empty")
    await db.settings.update_one(
        {"key": "sendora_config"},
        {"$set": {"key": "sendora_config", "value": {
            "api_key": req.api_key.strip(),
            "sender_id": req.sender_id.strip() or "BOMPAY",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}},
        upsert=True
    )
    test_ok = False
    try:
        base_url = os.environ.get("SENDORA_BASE_URL", "https://api.sendoracloud.com/api/v1")
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(f"{base_url}/me", headers={"X-API-Key": req.api_key.strip()})
        test_ok = r.status_code < 400
    except Exception:
        pass
    return {
        "message": "Sendora configuration saved",
        "sender_id": req.sender_id or "BOMPAY",
        "api_key_valid": test_ok
    }

# ===== BULKSMSLIVE CONFIG =====
@router.get("/admin/bulksms-config")
async def get_bulksms_config_endpoint(request: Request):
    await get_admin_user(request)
    doc = await db.settings.find_one({"key": "bulksms_config"})
    val = (doc or {}).get("value", {})
    raw_email = val.get("email") or os.environ.get("BULKSMSLIVE_EMAIL", "")
    raw_pass = val.get("password") or os.environ.get("BULKSMSLIVE_PASSWORD", "")
    masked_pass = ("*" * max(0, len(raw_pass) - 3)) + raw_pass[-3:] if raw_pass else ""
    return {
        "email": raw_email,
        "password_masked": masked_pass,
        "has_credentials": bool(raw_email and raw_pass),
        "sender_id": val.get("sender_id") or os.environ.get("BULKSMSLIVE_SENDER_ID", "BOMPAY"),
        "source": "database" if val.get("email") else "environment"
    }

@router.put("/admin/bulksms-config")
async def update_bulksms_config(req: BulkSmsCredentialsReq, request: Request):
    await get_admin_user(request)
    if not req.email.strip() or not req.password.strip():
        raise HTTPException(400, "Email and password are required")
    await db.settings.update_one(
        {"key": "bulksms_config"},
        {"$set": {"key": "bulksms_config", "value": {
            "email": req.email.strip(),
            "password": req.password.strip(),
            "sender_id": req.sender_id.strip() or "BOMPAY",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}},
        upsert=True
    )
    # Test the credentials
    test_ok = False
    try:
        result = await _send_via_bulksms("+2340000000000", "BOMPAY test")
        test_ok = result.get("ok", False)
    except Exception:
        pass
    return {"message": "BulkSMSLive credentials saved", "sender_id": req.sender_id or "BOMPAY", "test_ok": test_ok}

# ===== SMS PROVIDER SWITCH =====
@router.get("/admin/sms-provider")
async def get_active_sms_provider(request: Request):
    await get_admin_user(request)
    provider = await get_sms_provider()
    return {"active_provider": provider, "available": ["SENDORA", "BULKSMSLIVE"]}

@router.put("/admin/sms-provider")
async def set_active_sms_provider(req: SmsProviderReq, request: Request):
    await get_admin_user(request)
    if req.provider not in ("SENDORA", "BULKSMSLIVE", "STROWALLET"):
        raise HTTPException(400, "Provider must be SENDORA, BULKSMSLIVE, or STROWALLET")
    await db.settings.update_one(
        {"key": "sms_provider"},
        {"$set": {"key": "sms_provider", "value": req.provider}},
        upsert=True
    )
    return {"message": f"Active SMS provider set to {req.provider}", "active_provider": req.provider}

# ===== ADMIN EMAIL CONFIG =====
@router.get("/admin/email-config")
async def get_email_config(request: Request):
    await get_admin_user(request)
    doc = await db.settings.find_one({"key": "email_config"})
    val = (doc or {}).get("value", {})
    resend_cfg = await db.admin_settings.find_one({"key": "resend"}) or {}
    return {
        "enabled": val.get("enabled", True),
        "from_name": resend_cfg.get("from_name") or os.environ.get("EMAIL_FROM_NAME", "BOMPAY"),
        "resend_configured": bool(resend_cfg.get("api_key") or os.environ.get("RESEND_API_KEY", "")),
    }

@router.put("/admin/email-config")
async def update_email_config(req: EmailConfigReq, request: Request):
    await get_admin_user(request)
    await db.settings.update_one(
        {"key": "email_config"},
        {"$set": {"key": "email_config", "value": {"enabled": req.enabled}}},
        upsert=True
    )
    return {"message": "Email config updated", "enabled": req.enabled}

@router.get("/admin/settings/resend")
async def get_resend_settings(request: Request):
    await get_admin_user(request)
    doc = await db.admin_settings.find_one({"key": "resend"}) or {}
    has_key = bool(doc.get("api_key") or os.environ.get("RESEND_API_KEY", ""))
    return {
        "configured": has_key,
        "from_name": doc.get("from_name") or os.environ.get("EMAIL_FROM_NAME", "BOMPAY"),
        "from_email": doc.get("from_email") or os.environ.get("EMAIL_FROM_ADDRESS", "no-reply@bompay.ng"),
    }

@router.post("/admin/settings/resend")
async def save_resend_settings(body: ResendSettingsReq, request: Request):
    await get_admin_user(request)
    existing = await db.admin_settings.find_one({"key": "resend"})
    api_key = body.api_key.strip()
    if not api_key and existing:
        api_key = existing.get("api_key", "")
    if not api_key:
        api_key = os.environ.get("RESEND_API_KEY", "")
    update = {
        "key": "resend",
        "api_key": api_key,
        "from_name": body.from_name.strip() or "BOMPAY",
        "from_email": body.from_email.strip() or "no-reply@bompay.ng",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.admin_settings.update_one({"key": "resend"}, {"$set": update}, upsert=True)
    return {"success": True, "message": "Resend settings saved", "configured": bool(api_key)}

@router.post("/admin/settings/resend/test")
async def test_resend_email(request: Request):
    """Send a test email to the admin's own address."""
    admin = await get_admin_user(request)
    test_to = admin.get("email")
    if not test_to:
        raise HTTPException(400, "Admin account has no email address")
    html = _email_html("Test Email from BOMPAY", [("Status", "Working"), ("Provider", "Resend")], "If you received this, your email provider is configured correctly.")
    await send_email(to=test_to, subject="BOMPAY: Email Test", html=html)
    return {"success": True, "message": f"Test email sent to {test_to}"}

# ===== ADMIN ROLE MANAGEMENT =====
ALL_PERMISSIONS = ["all", "users", "kyc", "fraud", "transactions", "financial", "providers", "promotions", "reports", "ajo", "loans", "roles"]

async def check_permission(request: Request, permission: str) -> dict:
    """Returns admin user if they have the required permission, raises 403 otherwise."""
    admin = await get_admin_user(request)
    role_name = admin.get("admin_role", "super_admin")
    role = await db.admin_roles.find_one({"name": role_name})
    if not role:
        # Default super_admin or unknown role — allow if they have role: admin
        return admin
    perms = role.get("permissions", [])
    if "all" in perms or permission in perms:
        return admin
    raise HTTPException(403, f"Your role '{role_name}' does not have '{permission}' permission")

@router.get("/admin/roles")
async def list_admin_roles(request: Request):
    await get_admin_user(request)
    roles = await db.admin_roles.find({}).sort("name", 1).to_list(100)
    return {"roles": [{"id": str(r["_id"]), **{k: v for k, v in r.items() if k != "_id"}} for r in roles]}

@router.post("/admin/roles")
async def create_admin_role(body: AdminRoleReq, request: Request):
    await check_permission(request, "roles")
    if await db.admin_roles.find_one({"name": body.name.strip().lower().replace(" ", "_")}):
        raise HTTPException(409, "A role with that name already exists")
    now = datetime.now(timezone.utc).isoformat()
    result = await db.admin_roles.insert_one({
        "name": body.name.strip().lower().replace(" ", "_"),
        "display_name": body.name.strip(),
        "description": body.description.strip(),
        "permissions": [p for p in body.permissions if p in ALL_PERMISSIONS],
        "is_system": False,
        "created_at": now,
    })
    return {"id": str(result.inserted_id), "message": "Role created"}

@router.put("/admin/roles/{role_id}")
async def update_admin_role(role_id: str, body: AdminRoleReq, request: Request):
    await check_permission(request, "roles")
    role = await db.admin_roles.find_one({"_id": ObjectId(role_id)})
    if not role:
        raise HTTPException(404, "Role not found")
    if role.get("is_system") and role.get("name") == "super_admin":
        raise HTTPException(400, "Cannot modify the super_admin role")
    await db.admin_roles.update_one({"_id": ObjectId(role_id)}, {"$set": {
        "description": body.description.strip(),
        "permissions": [p for p in body.permissions if p in ALL_PERMISSIONS],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }})
    return {"message": "Role updated"}

@router.delete("/admin/roles/{role_id}")
async def delete_admin_role(role_id: str, request: Request):
    await check_permission(request, "roles")
    role = await db.admin_roles.find_one({"_id": ObjectId(role_id)})
    if not role:
        raise HTTPException(404, "Role not found")
    if role.get("is_system"):
        raise HTTPException(400, "Cannot delete a system role")
    await db.admin_roles.delete_one({"_id": ObjectId(role_id)})
    return {"message": "Role deleted"}

@router.get("/admin/staff")
async def list_admin_staff(request: Request):
    await get_admin_user(request)
    staff = await db.users.find({"role": "admin"}).sort("created_at", -1).to_list(200)
    result = []
    for s in staff:
        result.append({
            "id": str(s["_id"]),
            "first_name": s.get("first_name", ""),
            "last_name": s.get("last_name", ""),
            "email": s.get("email", ""),
            "phone": s.get("phone", ""),
            "admin_role": s.get("admin_role", "super_admin"),
            "status": s.get("status", "ACTIVE"),
            "created_at": s.get("created_at", ""),
            "last_login": s.get("last_login", ""),
        })
    return {"staff": result}

@router.post("/admin/staff")
async def create_admin_staff(body: AdminStaffReq, request: Request):
    await check_permission(request, "roles")
    if await db.users.find_one({"email": body.email.strip().lower()}):
        raise HTTPException(409, "An account with this email already exists")
    if not body.password or len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    pwd_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    now = datetime.now(timezone.utc).isoformat()
    result = await db.users.insert_one({
        "first_name": body.first_name.strip(),
        "last_name": body.last_name.strip(),
        "email": body.email.strip().lower(),
        "phone": "",
        "password_hash": pwd_hash,
        "role": "admin",
        "admin_role": body.admin_role or "support",
        "status": "ACTIVE",
        "kyc_status": "NOT_STARTED",
        "kyc_tier": 0,
        "created_at": now,
    })
    return {"id": str(result.inserted_id), "message": "Admin user created"}

@router.put("/admin/staff/{staff_id}")
async def update_admin_staff(staff_id: str, body: AdminStaffReq, request: Request):
    await check_permission(request, "roles")
    staff = await db.users.find_one({"_id": ObjectId(staff_id), "role": "admin"})
    if not staff:
        raise HTTPException(404, "Admin user not found")
    update = {
        "first_name": body.first_name.strip(),
        "last_name": body.last_name.strip(),
        "admin_role": body.admin_role or staff.get("admin_role", "support"),
        "status": body.status or "ACTIVE",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if body.password and len(body.password) >= 8:
        update["password_hash"] = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    await db.users.update_one({"_id": ObjectId(staff_id)}, {"$set": update})
    return {"message": "Admin user updated"}

# ===== PROMOTIONS =====
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

# ── Admin: Cloudinary settings ─────────────────────────────────────
@router.get("/admin/settings/cloudinary")
async def get_cloudinary_settings(request: Request):
    await get_admin_user(request)
    doc = await db.admin_settings.find_one({"key": "cloudinary"})
    cloud_name = (doc or {}).get("cloud_name") or os.environ.get("CLOUDINARY_CLOUD_NAME", "")
    api_key = (doc or {}).get("api_key") or os.environ.get("CLOUDINARY_API_KEY", "")
    configured = bool(cloud_name and api_key)
    return {"cloud_name": cloud_name, "api_key": api_key, "configured": configured}

@router.post("/admin/settings/cloudinary")
async def save_cloudinary_settings(body: CloudinarySettingsReq, request: Request):
    await get_admin_user(request)
    existing = await db.admin_settings.find_one({"key": "cloudinary"})
    api_secret = body.api_secret.strip()
    if not api_secret and existing:
        api_secret = existing.get("api_secret", "")
    if not api_secret:
        api_secret = os.environ.get("CLOUDINARY_API_SECRET", "")
    update = {
        "key": "cloudinary",
        "cloud_name": body.cloud_name.strip(),
        "api_key": body.api_key.strip(),
        "api_secret": api_secret,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.admin_settings.update_one({"key": "cloudinary"}, {"$set": update}, upsert=True)
    # Re-configure Cloudinary with new credentials
    cloudinary.config(
        cloud_name=update["cloud_name"],
        api_key=update["api_key"],
        api_secret=update["api_secret"],
        secure=True
    )
    return {"success": True, "message": "Cloudinary configured successfully"}



# ── Paystack: Admin settings ──────────────────────────────────────
@router.get("/admin/settings/paystack")
async def get_paystack_settings(request: Request):
    await get_admin_user(request)
    doc = await db.admin_settings.find_one({"key": "paystack"})
    return {
        "configured": bool((doc or {}).get("secret_key")),
        "public_key": (doc or {}).get("public_key", ""),
        "mode": (doc or {}).get("mode", "test"),
    }

@router.post("/admin/settings/paystack")
async def save_paystack_settings(request: Request):
    await get_admin_user(request)
    body = await request.json()
    public_key = body.get("public_key", "").strip()
    secret_key = body.get("secret_key", "").strip()
    mode = body.get("mode", "test")
    update: dict = {
        "key": "paystack", "public_key": public_key, "mode": mode,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if secret_key:
        update["secret_key"] = secret_key
    await db.admin_settings.update_one({"key": "paystack"}, {"$set": update}, upsert=True)
    return {"success": True}

# ── Paystack: User — get public key ───────────────────────────────
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
@router.get("/admin/balance-accounts")
async def admin_balance_accounts(request: Request, page: int = 1, per_page: int = 25,
                                  search: str = None, has_transfer: str = None):
    await get_admin_user(request)
    wallet_query: dict = {"sh_account_number": {"$exists": True, "$ne": ""}}
    if search:
        matching_users = await db.users.find(
            {"$or": [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"phone": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
            ]},
            {"_id": 1}
        ).to_list(200)
        uid_list = [str(u["_id"]) for u in matching_users]
        wallet_query["user_id"] = {"$in": uid_list}
    skip = (page - 1) * per_page
    total = await db.wallets.count_documents(wallet_query)
    wallets = await db.wallets.find(wallet_query).skip(skip).limit(per_page).to_list(per_page)
    rows = []
    for w in wallets:
        uid = w.get("user_id", "")
        user = await db.users.find_one({"_id": ObjectId(uid)}, {"first_name": 1, "last_name": 1, "email": 1, "phone": 1})
        if not user:
            continue
        user_has_transfer = bool(await db.transactions.find_one({
            "user_id": uid, "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]},
            "direction": "DEBIT", "status": {"$nin": ["FAILED", "REVERSED"]}
        }))
        if has_transfer == "true" and not user_has_transfer:
            continue
        if has_transfer == "false" and user_has_transfer:
            continue
        rows.append({
            "user_id": uid,
            "name": f"{user.get('first_name','')} {user.get('last_name','')}".strip(),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "wallet_balance": w.get("available_balance", 0),
            "sh_account_number": w.get("sh_account_number", ""),
            "has_transfer": user_has_transfer,
        })
    return {"users": rows, "total": total, "page": page, "per_page": per_page}


# ── Admin: Bulk fetch all SH balances ──────────────────────────────
@router.get("/admin/balance-accounts/bulk-sh-balances")
async def admin_bulk_sh_balances(request: Request):
    """Fetch SH balance for every user who has a sh_account_id. Sequential to respect rate limits."""
    await get_admin_user(request)
    wallets = await db.wallets.find(
        {"sh_account_id": {"$exists": True, "$nin": [None, ""]}}
    ).to_list(200)
    results = {}
    for w in wallets:
        uid = w.get("user_id", "")
        sh_id = w.get("sh_account_id")
        if not sh_id:
            continue
        try:
            sh_bal_naira = await get_sh_subaccount_balance(sh_id)
            sh_balance_kobo = int(sh_bal_naira * 100)
            wallet_balance = w.get("available_balance", 0)
            results[uid] = {
                "sh_balance": sh_balance_kobo,
                "wallet_balance": wallet_balance,
                "discrepancy": wallet_balance - sh_balance_kobo,
            }
        except Exception as e:
            results[uid] = {"error": str(e)[:80]}
    return {"balances": results}


# ── Admin: Balance-all (sync all users with discrepancies) ─────────
@router.post("/admin/balance-accounts/balance-all")
async def admin_balance_all(request: Request):
    """Sync wallet to SH balance for all users with a discrepancy who have made at least one transfer."""
    await get_admin_user(request)
    wallets = await db.wallets.find(
        {"sh_account_id": {"$exists": True, "$nin": [None, ""]}}
    ).to_list(200)
    synced, skipped, errors = [], [], []
    for w in wallets:
        uid = w.get("user_id", "")
        sh_id = w.get("sh_account_id")
        if not sh_id:
            continue
        has_transfer = bool(await db.transactions.find_one({
            "user_id": uid, "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]},
            "direction": "DEBIT", "status": {"$nin": ["FAILED", "REVERSED"]}
        }))
        if not has_transfer:
            skipped.append(uid)
            continue
        try:
            sh_bal_naira = await get_sh_subaccount_balance(sh_id)
            sh_balance_kobo = int(sh_bal_naira * 100)
            old_balance = w.get("available_balance", 0)
            if old_balance == sh_balance_kobo:
                continue
            await db.wallets.update_one(
                {"user_id": uid},
                {"$set": {"available_balance": sh_balance_kobo, "ledger_balance": sh_balance_kobo}}
            )
            # Silent admin-only correction — no transaction entry
            logger.info(f"[BulkBalanceSync] uid={uid} {old_balance/100:,.2f}→{sh_balance_kobo/100:,.2f}")
            synced.append({"user_id": uid, "old": old_balance, "new": sh_balance_kobo})
        except Exception as e:
            errors.append({"user_id": uid, "error": str(e)[:80]})
    return {"synced": len(synced), "skipped_no_transfer": len(skipped), "errors": len(errors), "details": synced}


@router.get("/admin/balance-accounts/{user_id}/sh-balance")
async def admin_get_sh_balance(user_id: str, request: Request):
    await get_admin_user(request)
    wallet = await db.wallets.find_one({"user_id": user_id})
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    sh_id = wallet.get("sh_account_id")
    if not sh_id:
        raise HTTPException(400, "No Safe Haven account ID linked — account may have been created before this feature")
    sh_bal_naira = await get_sh_subaccount_balance(sh_id)
    sh_balance_kobo = int(sh_bal_naira * 100)
    wallet_balance = wallet.get("available_balance", 0)
    return {
        "user_id": user_id,
        "wallet_balance": wallet_balance,
        "sh_balance": sh_balance_kobo,
        "discrepancy": wallet_balance - sh_balance_kobo,
        "sh_account_number": wallet.get("sh_account_number", ""),
    }


@router.post("/admin/balance-accounts/{user_id}/sync")
async def admin_sync_wallet_to_sh(user_id: str, request: Request):
    await get_admin_user(request)
    has_transfer = bool(await db.transactions.find_one({
        "user_id": user_id, "type": {"$in": ["BANK_TRANSFER", "BOMPAY_INTERNAL_TRANSFER"]},
        "direction": "DEBIT", "status": {"$nin": ["FAILED", "REVERSED"]}
    }))
    if not has_transfer:
        raise HTTPException(400, "User has not made any transfers. Balance sync not permitted.")
    wallet = await db.wallets.find_one({"user_id": user_id})
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    sh_id = wallet.get("sh_account_id")
    if not sh_id:
        raise HTTPException(400, "No Safe Haven account ID linked")
    sh_bal_naira = await get_sh_subaccount_balance(sh_id)
    if sh_bal_naira == 0.0:
        raise HTTPException(502, "Could not fetch Safe Haven balance — Safe Haven returned 0 or failed")
    sh_balance_kobo = int(sh_bal_naira * 100)
    old_balance = wallet.get("available_balance", 0)
    await db.wallets.update_one(
        {"user_id": user_id},
        {"$set": {"available_balance": sh_balance_kobo, "ledger_balance": sh_balance_kobo}}
    )
    # Silent admin-only correction — no transaction entry created, not visible to user
    adjustment = sh_balance_kobo - old_balance
    logger.info(f"[BalanceSync] uid={user_id} {old_balance/100:,.2f}→{sh_balance_kobo/100:,.2f} (Δ{adjustment/100:,.2f})")
    return {"success": True, "old_balance": old_balance, "new_balance": sh_balance_kobo, "adjustment": adjustment}



@router.get("/admin/users/{user_id}/charges")
async def get_user_charges(user_id: str, request: Request, limit: int = 50, page: int = 1):
    await get_admin_user(request)
    skip = (page - 1) * limit
    # Charges = DEBIT transactions that are fees/charges, not purchases
    charge_types = ["SMS_CHARGE", "FEE_INCOME", "TRANSFER_FEE", "LOAN_FEE", "SAVINGS_FEE", "VAS_FEE", "MONTHLY_FEE"]
    pipeline_all = [
        {"$match": {"user_id": user_id, "direction": "DEBIT"}},
        {"$sort": {"created_at": -1}},
    ]
    all_debits = await db.transactions.find(
        {"user_id": user_id, "direction": "DEBIT"}, {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.transactions.count_documents({"user_id": user_id, "direction": "DEBIT"})
    # Sum by type
    agg = [
        {"$match": {"user_id": user_id, "direction": "DEBIT", "status": "COMPLETED"}},
        {"$group": {"_id": "$type", "total_ngn": {"$sum": {"$divide": ["$amount", 100]}}, "count": {"$sum": 1}}}
    ]
    by_type = {}
    async for d in db.transactions.aggregate(agg):
        by_type[d["_id"]] = {"total_ngn": round(d["total_ngn"], 2), "count": d["count"]}
    total_charged = sum(v["total_ngn"] for v in by_type.values())
    return {
        "transactions": all_debits,
        "total": total,
        "page": page,
        "limit": limit,
        "summary_by_type": by_type,
        "total_charged_ngn": round(total_charged, 2)
    }


@router.get("/admin/users/{user_id}/balance-history")
async def get_user_balance_history(user_id: str, request: Request):
    """Return the wallet balance timeline derived from transaction balance_after_kobo fields."""
    await get_admin_user(request)
    txns = await db.transactions.find(
        {"user_id": user_id, "balance_after_kobo": {"$ne": None}},
        {"_id": 0, "balance_before_kobo": 1, "balance_after_kobo": 1,
         "created_at": 1, "type": 1, "direction": 1, "amount": 1, "description": 1}
    ).sort("created_at", 1).to_list(500)

    points = []
    if txns and txns[0].get("balance_before_kobo") is not None:
        points.append({
            "ts": txns[0]["created_at"],
            "balance": round(txns[0]["balance_before_kobo"] / 100, 2),
            "type": None, "direction": None, "amount": 0, "label": "Opening balance",
        })

    for t in txns:
        if t.get("balance_after_kobo") is not None:
            typ = t.get("type", "")
            points.append({
                "ts": t["created_at"],
                "balance": round(t["balance_after_kobo"] / 100, 2),
                "type": typ,
                "direction": t.get("direction"),
                "amount": round(t.get("amount", 0) / 100, 2),
                "label": typ.replace("_", " ").title(),
            })

    balances = [p["balance"] for p in points]
    return {
        "points": points,
        "count": len(points),
        "min_balance": min(balances) if balances else 0,
        "max_balance": max(balances) if balances else 0,
        "current_balance": balances[-1] if balances else 0,
    }


# ===== E-POS =====
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
class EposActivateReq(BaseModel):
    business_name: str
    business_type: Optional[str] = "retail"


# ─────────────────────────────────────────────────────────
#  Admin Family Management endpoints
# ─────────────────────────────────────────────────────────

@router.get("/admin/family/stats")
async def admin_family_stats(request: Request):
    """High-level Family module statistics."""
    await get_admin_user(request)
    total_families = await db.family_groups.count_documents({})
    total_members = await db.family_members.count_documents({"status": {"$ne": "REMOVED"}})
    pipe = [{"$group": {"_id": None, "total_kobo": {"$sum": "$allocated_kobo"}}}]
    result = await db.family_groups.aggregate(pipe).to_list(1)
    total_allocated_kobo = result[0]["total_kobo"] if result else 0
    frozen_families = await db.family_groups.count_documents({"status": "FROZEN"})
    pending_requests = await db.family_requests.count_documents({"status": "PENDING"})
    return {
        "total_families": total_families,
        "total_members": total_members,
        "total_allocated_ngn": total_allocated_kobo / 100,
        "frozen_families": frozen_families,
        "pending_requests": pending_requests,
    }


@router.get("/admin/family/groups")
async def admin_family_groups(
    request: Request,
    page: int = 1,
    limit: int = 25,
    search: str = None,
    status: str = None,
):
    """Paginated list of all family groups with owner info."""
    await get_admin_user(request)
    query: dict = {}
    if status:
        query["status"] = status

    # Phone/name-based search: resolve owner user_ids first
    if search:
        matching_users = await db.users.find(
            {"$or": [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"phone_number": {"$regex": search, "$options": "i"}},
            ]},
            {"_id": 1}
        ).to_list(200)
        owner_ids = [str(u["_id"]) for u in matching_users]
        name_clause = {"name": {"$regex": search, "$options": "i"}}
        if owner_ids:
            query["$or"] = [name_clause, {"owner_user_id": {"$in": owner_ids}}]
        else:
            query["$or"] = [name_clause]

    skip = (page - 1) * limit
    families = await db.family_groups.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.family_groups.count_documents(query)

    enriched = []
    for fam in families:
        fam["_id"] = str(fam["_id"])
        # Enrich with owner name
        try:
            owner = await db.users.find_one(
                {"_id": ObjectId(fam["owner_user_id"])},
                {"first_name": 1, "last_name": 1, "phone_number": 1}
            )
        except Exception:
            owner = None
        fam["owner_name"] = (
            f"{owner.get('first_name', '')} {owner.get('last_name', '')}".strip()
            if owner else "Unknown"
        )
        fam["owner_phone"] = owner.get("phone_number", "") if owner else ""
        fam["member_count"] = await db.family_members.count_documents(
            {"family_id": fam["family_id"], "status": {"$ne": "REMOVED"}}
        )
        fam["allocated_ngn"] = fam.get("allocated_kobo", 0) / 100
        fam["available_ngn"] = fam.get("available_kobo", 0) / 100
        enriched.append(fam)

    return {"groups": enriched, "total": total, "page": page}


@router.get("/admin/family/groups/{family_id}")
async def admin_family_group_detail(family_id: str, request: Request):
    """Full detail for one family: owner, members, recent ledger."""
    await get_admin_user(request)
    fam = await db.family_groups.find_one({"family_id": family_id})
    if not fam:
        raise HTTPException(404, "Family not found")
    fam["_id"] = str(fam["_id"])
    fam["allocated_ngn"] = fam.get("allocated_kobo", 0) / 100
    fam["available_ngn"] = fam.get("available_kobo", 0) / 100

    # Owner info
    try:
        owner = await db.users.find_one(
            {"_id": ObjectId(fam["owner_user_id"])},
            {"first_name": 1, "last_name": 1, "phone_number": 1, "email": 1}
        )
    except Exception:
        owner = None
    fam["owner_name"] = (
        f"{owner.get('first_name', '')} {owner.get('last_name', '')}".strip()
        if owner else "Unknown"
    )
    fam["owner_phone"] = owner.get("phone_number", "") if owner else ""
    fam["owner_email"] = owner.get("email", "") if owner else ""

    # Members
    members_raw = await db.family_members.find(
        {"family_id": family_id, "status": {"$ne": "REMOVED"}}, {"_id": 0}
    ).to_list(100)
    members = []
    for m in members_raw:
        try:
            u = await db.users.find_one(
                {"_id": ObjectId(m["user_id"])},
                {"first_name": 1, "last_name": 1, "phone_number": 1}
            )
        except Exception:
            u = None
        m["display_name"] = (
            f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone_number", "")
            if u else "Member"
        )
        m["phone"] = u.get("phone_number", "") if u else ""
        m["allocated_ngn"] = m.get("allocated_kobo", 0) / 100
        m["spent_ngn"] = m.get("spent_kobo", 0) / 100
        m["remaining_ngn"] = (m.get("allocated_kobo", 0) - m.get("spent_kobo", 0)) / 100
        members.append(m)
    fam["members"] = members

    # Recent ledger (last 20 entries)
    ledger_raw = await db.family_ledger.find(
        {"family_id": family_id}, {"_id": 0}
    ).sort("created_at", -1).limit(20).to_list(20)
    fam["recent_ledger"] = ledger_raw

    # Pending requests count
    fam["pending_requests"] = await db.family_requests.count_documents(
        {"family_id": family_id, "status": "PENDING"}
    )

    return fam


@router.post("/admin/family/groups/{family_id}/freeze")
async def admin_freeze_family_group(family_id: str, request: Request):
    """Toggle freeze/unfreeze for an entire family group."""
    admin = await get_admin_user(request)
    fam = await db.family_groups.find_one({"family_id": family_id})
    if not fam:
        raise HTTPException(404, "Family not found")

    new_status = "ACTIVE" if fam.get("status") == "FROZEN" else "FROZEN"
    await db.family_groups.update_one(
        {"family_id": family_id},
        {"$set": {"status": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    action = "unfrozen" if new_status == "ACTIVE" else "frozen"
    audit_action = "ADMIN_FAMILY_FREEZE" if new_status == "FROZEN" else "ADMIN_FAMILY_UNFREEZE"
    await audit(str(admin["_id"]), audit_action, "family_groups",
                {"family_id": family_id, "family_name": fam.get("name"), "new_status": new_status})
    return {"status": new_status, "message": f"Family '{fam.get('name')}' {action} successfully"}



@router.get("/admin/webhook-events")
async def admin_webhook_events(limit: int = 20, admin=Depends(get_admin_user)):
    """View recent webhook events for debugging."""
    events = await db.webhooks.find({}).sort("received_at", -1).limit(limit).to_list(limit)
    result = []
    for e in events:
        e["_id"] = str(e["_id"])
        result.append(e)
    return result



@router.post("/admin/fix-callback-urls")
async def fix_callback_urls(admin=Depends(get_admin_user)):
    """Update callbackUrl for ALL existing virtual accounts on Safe Haven to the production URL."""
    prod_callback = os.environ.get("WEBHOOK_BASE_URL") or os.environ.get("API_BASE_URL", "")
    callback_url = f"{prod_callback}/api/webhooks/safehaven"

    wallets = await db.wallets.find(
        {"sh_account_id": {"$exists": True, "$ne": ""}}
    ).to_list(1000)

    results = []
    for w in wallets:
        sh_id = w.get("sh_account_id", "")
        acct_num = w.get("sh_account_number", "")
        user_id = w.get("user_id", "")
        if not sh_id:
            continue
        try:
            # Try virtual-accounts endpoint first, then accounts endpoint
            r = await call_sh("PUT", f"/virtual-accounts/{sh_id}", body={"callbackUrl": callback_url})
            results.append({"user_id": user_id, "account": acct_num, "sh_id": sh_id, "status": "updated", "callback": callback_url, "response": str(r)[:200]})
        except Exception as e1:
            try:
                r2 = await call_sh("PATCH", f"/accounts/{sh_id}", body={"callbackUrl": callback_url})
                results.append({"user_id": user_id, "account": acct_num, "sh_id": sh_id, "status": "updated_via_accounts", "callback": callback_url, "response": str(r2)[:200]})
            except Exception as e2:
                results.append({"user_id": user_id, "account": acct_num, "sh_id": sh_id, "status": "failed", "error": str(e2)})

    return {"callback_url_used": callback_url, "total": len(results), "results": results}


# ===== MONEY MOVEMENT REPORT =====

MONEY_MOVEMENT_MAP = {
    "SAVINGS": {
        "label": "Savings",
        "in_types": ["SAVINGS_CONTRIBUTION"],       # money flows INTO bucket
        "out_types": ["SAVINGS_WITHDRAWAL"],         # money flows OUT of bucket to users
        "ledger_collection": "savings_goals",
    },
    "LOANS": {
        "label": "Loans",
        "in_types": ["LOAN_REPAYMENT"],              # money flows INTO bucket (repayments)
        "out_types": ["LOAN_DISBURSEMENT"],          # money flows OUT of bucket (disbursements)
        "ledger_collection": "loan_applications",
    },
    "AJO": {
        "label": "Ajo Group",
        "in_types": ["AJO_CONTRIBUTION"],            # money flows INTO bucket
        "out_types": ["AJO_PAYOUT"],                 # money flows OUT to turn recipients
        "ledger_collection": "ajo_groups",
    },
    "EPOS": {
        "label": "e-POS",
        "in_types": ["EPOS_SETTLEMENT", "EPOS_CHARGE"],
        "out_types": [],
        "ledger_collection": None,
    },
    "CASHBACK": {
        "label": "Cashback",
        "in_types": [],                              # funded externally via SH
        "out_types": ["CASHBACK_CREDIT"],            # paid out to users
        "ledger_collection": "cashback_history",
    },
    "REFERRAL": {
        "label": "Referral Bonus",
        "in_types": [],
        "out_types": ["REFERRAL_BONUS"],
        "ledger_collection": "referral_history",
    },
    "NIP_INWARD": {
        "label": "NIP Inward Commission",
        "in_types": [],
        "out_types": [],                             # uses nip_inward_costs collection directly
        "ledger_collection": "nip_inward_costs",
    },
}


@router.get("/admin/money-movement/report")
async def money_movement_report(
    request: Request,
    period: str = "month",      # today / week / month / all / custom
    date_from: str = "",
    date_to: str = "",
):
    """Per-service fund flow report: IN (funds going to bucket), OUT (funds paid out to users), Net."""
    await get_admin_user(request)
    now = datetime.now(timezone.utc)

    # Build date range
    if period == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif period == "week":
        start = now - timedelta(days=7)
        end = now
    elif period == "month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif period == "custom" and date_from:
        try:
            start = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
            end = datetime.fromisoformat(date_to.replace("Z", "+00:00")) if date_to else now
        except Exception:
            start = now - timedelta(days=30)
            end = now
    else:  # "all"
        start = None
        end = None

    date_filter: dict = {}
    if start and end:
        date_filter = {"created_at": {"$gte": start.isoformat(), "$lte": end.isoformat()}}

    results = {}

    for svc_key, cfg in MONEY_MOVEMENT_MAP.items():
        if svc_key == "NIP_INWARD":
            # Use nip_inward_costs collection
            q = {**date_filter}
            if "created_at" in q:
                nip_docs = await db.nip_inward_costs.find(q, {"cost_ngn": 1, "status": 1}).to_list(None)
            else:
                nip_docs = await db.nip_inward_costs.find({}, {"cost_ngn": 1, "status": 1}).to_list(None)
            total_cost = round(sum(d.get("cost_ngn", 0) for d in nip_docs), 2)
            pending_cost = round(sum(d.get("cost_ngn", 0) for d in nip_docs if d.get("status") == "PENDING_BALANCE"), 2)
            results[svc_key] = {
                "label": cfg["label"],
                "in_ngn": 0,
                "out_ngn": total_cost,
                "net_ngn": -total_cost,
                "in_count": 0,
                "out_count": len(nip_docs),
                "pending_ngn": pending_cost,
            }
            continue

        # IN: transactions of in_types
        in_ngn = 0
        in_count = 0
        if cfg["in_types"]:
            in_q = {"type": {"$in": cfg["in_types"]}, "status": "COMPLETED", **date_filter}
            in_agg = await db.transactions.aggregate([
                {"$match": in_q},
                {"$group": {"_id": None, "total": {"$sum": "$amount"}, "count": {"$sum": 1}}}
            ]).to_list(1)
            if in_agg:
                in_ngn = round(in_agg[0]["total"] / 100, 2)
                in_count = in_agg[0]["count"]
        else:
            # Cashback/Referral: read from history collections
            if svc_key in ("CASHBACK", "REFERRAL"):
                coll = db.cashback_history if svc_key == "CASHBACK" else db.referral_history
                hist_q = {**date_filter}
                hist_agg = await coll.aggregate([
                    {"$match": hist_q},
                    {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
                ]).to_list(1)
                if hist_agg:
                    in_ngn = 0
                    in_count = 0
                    # cashback/referral are OUT (paid to users), not in
                    out_ngn_from_hist = round(hist_agg[0]["total"] / 100, 2)
                    out_count_from_hist = hist_agg[0]["count"]
                    results[svc_key] = {
                        "label": cfg["label"],
                        "in_ngn": 0,
                        "out_ngn": out_ngn_from_hist,
                        "net_ngn": round(-out_ngn_from_hist, 2),
                        "in_count": 0,
                        "out_count": out_count_from_hist,
                    }
                    continue

        # OUT: transactions of out_types
        out_ngn = 0
        out_count = 0
        if cfg["out_types"]:
            out_q = {"type": {"$in": cfg["out_types"]}, "status": "COMPLETED", **date_filter}
            out_agg = await db.transactions.aggregate([
                {"$match": out_q},
                {"$group": {"_id": None, "total": {"$sum": "$amount"}, "count": {"$sum": 1}}}
            ]).to_list(1)
            if out_agg:
                out_ngn = round(out_agg[0]["total"] / 100, 2)
                out_count = out_agg[0]["count"]

        # Fetch configured account
        svc_acct = await db.service_bucket_accounts.find_one({"service": svc_key, "is_active": True})

        results[svc_key] = {
            "label": cfg["label"],
            "in_ngn": in_ngn,
            "out_ngn": out_ngn,
            "net_ngn": round(in_ngn - out_ngn, 2),
            "in_count": in_count,
            "out_count": out_count,
            "account_number": (svc_acct or {}).get("sh_account_number"),
            "account_name": (svc_acct or {}).get("sh_account_name"),
        }

    # Grand totals
    total_in = round(sum(v["in_ngn"] for v in results.values()), 2)
    total_out = round(sum(v["out_ngn"] for v in results.values()), 2)

    return {
        "period": period,
        "date_from": start.isoformat() if start else None,
        "date_to": end.isoformat() if end else None,
        "services": results,
        "totals": {"in_ngn": total_in, "out_ngn": total_out, "net_ngn": round(total_in - total_out, 2)},
        "generated_at": now.isoformat(),
    }

@router.get("/admin/nip-inward/report")
async def nip_inward_report(request: Request, status: str = "all", page: int = 1, limit: int = 50):
    """Report of NIP Inward Commission costs (Bompay-absorbed). Filter by status: all/PENDING_BALANCE/BALANCED."""
    await get_admin_user(request)
    query: dict = {}
    if status != "all":
        query["status"] = status.upper()
    skip = (page - 1) * limit
    records = await db.nip_inward_costs.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.nip_inward_costs.count_documents(query)

    # Summary aggregation
    summary_agg = await db.nip_inward_costs.aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}, "total_ngn": {"$sum": "$cost_ngn"}}}
    ]).to_list(None)
    summary = {s["_id"]: {"count": s["count"], "total_ngn": round(s["total_ngn"], 2)} for s in summary_agg}

    pending_total = summary.get("PENDING_BALANCE", {}).get("total_ngn", 0)
    balanced_total = summary.get("BALANCED", {}).get("total_ngn", 0)

    # Last balance event
    last_balance = await db.transactions.find_one(
        {"type": "NIP_INWARD_BALANCE"}, sort=[("created_at", -1)]
    )

    return {
        "records": records,
        "total": total,
        "page": page,
        "summary": {
            "pending_count": summary.get("PENDING_BALANCE", {}).get("count", 0),
            "pending_ngn": pending_total,
            "balanced_count": summary.get("BALANCED", {}).get("count", 0),
            "balanced_ngn": balanced_total,
        },
        "last_auto_balance": {
            "ref": (last_balance or {}).get("transaction_id"),
            "amount_ngn": (last_balance or {}).get("amount", 0) / 100,
            "txn_count": (last_balance or {}).get("metadata", {}).get("txn_count", 0),
            "at": (last_balance or {}).get("created_at"),
        } if last_balance else None
    }


@router.get("/admin/nip-inward/preview-balance")
async def nip_inward_preview_balance(request: Request):
    """Preview all pending NIP Inward costs before executing a manual balance."""
    await get_admin_user(request)
    pending = await db.nip_inward_costs.find({"status": "PENDING_BALANCE"}, {"_id": 0}).sort("created_at", 1).to_list(None)
    total_ngn = round(sum(p.get("cost_ngn", 0) for p in pending), 2)

    # Enrich with user info
    enriched = []
    for p in pending:
        user = await db.users.find_one({"_id": ObjectId(p["user_id"])}, {"first_name": 1, "last_name": 1, "phone": 1}) if p.get("user_id") else None
        enriched.append({
            **p,
            "user_name": f"{(user or {}).get('first_name','')} {(user or {}).get('last_name','')}".strip() if user else "Unknown",
            "user_phone": (user or {}).get("phone", ""),
        })

    return {
        "count": len(pending),
        "total_ngn": total_ngn,
        "records": enriched
    }


@router.post("/admin/nip-inward/manual-balance")
async def nip_inward_manual_balance(request: Request):
    """Manually trigger NIP Inward balance (same logic as midnight cron)."""
    await get_admin_user(request)
    now = datetime.now(timezone.utc)

    pending = await db.nip_inward_costs.find({"status": "PENDING_BALANCE"}).to_list(None)
    if not pending:
        return {"message": "No pending NIP inward costs to balance", "count": 0, "total_ngn": 0}

    total_cost_ngn = round(sum(p.get("cost_ngn", 0) for p in pending), 2)
    txn_ids = [p["txn_id"] for p in pending]
    sweep_ref = f"NIPINM{int(now.timestamp())}"

    await db.nip_inward_costs.update_many(
        {"txn_id": {"$in": txn_ids}},
        {"$set": {"status": "BALANCED", "balance_ref": sweep_ref, "balanced_at": now.isoformat()}}
    )
    await db.transactions.insert_one({
        "transaction_id": sweep_ref,
        "user_id": "PLATFORM",
        "type": "NIP_INWARD_BALANCE",
        "direction": "DEBIT",
        "amount": int(total_cost_ngn * 100),
        "fee": 0, "vat": 0,
        "currency": "NGN",
        "status": "COMPLETED",
        "provider": "INTERNAL",
        "description": f"Manual NIP inward balance — {len(pending)} deposits",
        "metadata": {"txn_count": len(pending), "triggered_by": "admin_manual"},
        "created_at": now.isoformat(),
        "updated_at": now.isoformat()
    })
    await db.charge_accounts.update_one(
        {"category": "NIP_INWARD_COMMISSION"},
        {"$inc": {"total_swept_kobo": int(total_cost_ngn * 100)},
         "$set": {"last_balanced_at": now.isoformat()}},
        upsert=False
    )
    return {
        "message": f"Manual balance complete — {len(pending)} records",
        "count": len(pending),
        "total_ngn": total_cost_ngn,
        "reference": sweep_ref
    }


# ===== SERVICE BUCKET ACCOUNTS =====

SERVICE_BUCKET_SERVICES = [
    {"key": "SAVINGS", "label": "Savings", "description": "Receives savings contributions; returns on liquidation"},
    {"key": "LOANS", "label": "Loans", "description": "Holds disbursed loan funds; receives repayments"},
    {"key": "AJO", "label": "Ajo Group", "description": "Holds Ajo rotating savings contributions"},
    {"key": "EPOS", "label": "e-POS", "description": "Holds ePOS merchant transaction float"},
    {"key": "CARD", "label": "Card (Virtual Cards)", "description": "Receives Safe Haven debits when users create or fund Naira/USD virtual cards"},
    {"key": "FAMILY", "label": "Family", "description": "Family wallet allocations float"},
    {"key": "PAYROLL", "label": "Payroll Fee", "description": "Receives ₦50-per-staff payroll processing fee from businesses"},
    {"key": "VAS", "label": "VAS (Value Added Services)", "description": "Receives user SH debits for airtime, data, cable, electricity, betting"},
    {"key": "CASHBACK", "label": "Cashback", "description": "Source account for cashback payouts to users"},
    {"key": "REFERRAL", "label": "Referral Bonus", "description": "Source account for referral bonus payouts to users"},
]


@router.get("/admin/service-accounts")
async def get_service_accounts(request: Request):
    """Get current service-to-account mappings."""
    await get_admin_user(request)
    docs = await db.service_bucket_accounts.find({}, {"_id": 0}).to_list(None)
    mapping = {d["service"]: d for d in docs}
    return {
        "services": [
            {**s, "account": mapping.get(s["key"])}
            for s in SERVICE_BUCKET_SERVICES
        ]
    }


@router.put("/admin/service-accounts/{service}")
async def set_service_account(service: str, request: Request):
    """Assign a Safe Haven account to a service bucket."""
    await get_admin_user(request)
    body = await request.json()
    service = service.upper()
    if service not in {s["key"] for s in SERVICE_BUCKET_SERVICES}:
        raise HTTPException(400, f"Unknown service: {service}")
    sh_account_number = (body.get("sh_account_number") or "").strip()
    sh_account_name = (body.get("sh_account_name") or "").strip()
    sh_account_id = (body.get("sh_account_id") or "").strip()
    if not sh_account_number:
        raise HTTPException(400, "sh_account_number is required")
    now = datetime.now(timezone.utc).isoformat()
    await db.service_bucket_accounts.update_one(
        {"service": service},
        {"$set": {
            "service": service,
            "sh_account_number": sh_account_number,
            "sh_account_name": sh_account_name,
            "sh_account_id": sh_account_id,
            "is_active": True,
            "updated_at": now
        }},
        upsert=True
    )
    return {"message": f"{service} account updated", "service": service, "account_number": sh_account_number}


@router.delete("/admin/service-accounts/{service}")
async def clear_service_account(service: str, request: Request):
    """Remove a service account mapping."""
    await get_admin_user(request)
    service = service.upper()
    await db.service_bucket_accounts.delete_one({"service": service})
    return {"message": f"{service} account mapping removed"}


@router.get("/admin/service-accounts/fetch-sh")
async def fetch_sh_accounts_for_service(request: Request):
    """Fetch available Safe Haven accounts for the admin to pick from."""
    await get_admin_user(request)
    try:
        # Try to list platform sub-accounts from Safe Haven API
        result = await call_sh("GET", "/accounts?page=1&limit=100")
        accounts_raw = result.get("data", [])
        if not isinstance(accounts_raw, list):
            # Some SH versions return {"data": {"data": [...]}}
            accounts_raw = result.get("data", {}).get("data", []) if isinstance(result.get("data"), dict) else []
        accounts = [
            {
                "account_number": a.get("accountNumber") or a.get("account_number", ""),
                "account_name": a.get("accountName") or a.get("account_name", ""),
                "account_id": a.get("_id") or a.get("id", ""),
                "available_balance": a.get("availableBalance", 0),
                "type": a.get("type") or a.get("accountType", ""),
            }
            for a in accounts_raw if a.get("accountNumber") or a.get("account_number")
        ]
        return {"accounts": accounts, "source": "safehaven_api"}
    except Exception as e:
        logger.warning(f"[ServiceAccounts] SH fetch failed: {e}")
        # Fallback: return existing service accounts so admin can at least see what's configured
        docs = await db.service_bucket_accounts.find({}, {"_id": 0}).to_list(None)
        return {"accounts": [], "source": "fallback", "error": str(e), "existing": docs}
