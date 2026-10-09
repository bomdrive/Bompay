"""Bompay — VAS routes."""
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
    AirtimeReq, DataReq, CableReq, ElectricityReq, VerifyReq, BetVerifyReq,
    BettingReq, EducationReq, CableValidateReq, MeterValidateReq,
    require_virtual_account, verify_transaction_pin, calculate_fee, get_nip_fee,
    vas_debit, vas_complete, vas_refund,
    _credit_cashback_bg, _check_referral_bg,
)
from routes.strowallet import (
    strow_buy_airtime, strow_buy_data, strow_buy_cable, strow_buy_education,
    EDUCATION_PRODUCTS,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/vas/airtime")
async def buy_airtime(req: AirtimeReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    if req.amount < 50 or req.amount > 50000:
        raise HTTPException(400, "Amount must be ₦50–₦50,000")
    amt = int(req.amount * 100)
    idem = req.idempotency_key or str(uuid.uuid4())
    txn_id, was_existing = await vas_debit(user["_id"], amt, idem, "AIRTIME",
        f"{req.network} Airtime — {req.phone_number}", {"network": req.network, "phone_number": req.phone_number})
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}
    try:
        provider = await get_service_provider("AIRTIME")
        if provider == "PAIRGATE":
            r = await call_pg("POST", "/airtime/purchase", body={
                "provider_id": req.network.upper(), "amount": req.amount,
                "recipient": req.phone_number, "reference": txn_id,
            })
            pref = str(r.get("reference", r.get("transaction_ref", txn_id)))
        elif provider == "CHEAPDATAHUB":
            pid = CDH_AIRTIME_NETWORK_IDS.get(req.network.upper(), 1)
            r = await call_cdh("POST", "/airtime/purchase/", body={
                "provider_id": pid, "phone_number": req.phone_number, "amount": req.amount
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_id)))
        elif provider == "STROWALLET":
            result = await strow_buy_airtime(req.phone_number, req.amount, req.network)
            pref = result["reference"]
        else:
            r = await call_sh("POST", "/vas/pay/airtime", body={"serviceCategoryId": "airtime",
                "amount": req.amount, "channel": "WEB", "phoneNumber": req.phone_number, "network": req.network})
            pref = r.get("data", {}).get("transactionReference", "")
        pts = max(1, int(req.amount * 0.02))
        await vas_complete(user["_id"], txn_id, amt, pref,
            "Airtime Purchased", f"₦{req.amount:,.0f} {req.network} airtime → {req.phone_number}", pts,
            sms_event_type="AIRTIME",
            sms_meta={"amount": req.amount, "network": req.network, "phone": req.phone_number, "ref": txn_id})
        asyncio.create_task(send_event_notification(user["_id"], "AIRTIME", {
            "amount": req.amount, "network": req.network, "phone": req.phone_number, "ref": txn_id
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "AIRTIME", f"{req.network} airtime"))
        asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
        return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount, "points_earned": pts}
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt, "Airtime Purchase Failed")
        raise
    except Exception:
        await vas_refund(user["_id"], txn_id, amt, "Airtime Purchase Failed")
        raise HTTPException(500, "Airtime purchase failed. Funds reversed.")

@router.post("/vas/data")
async def buy_data(req: DataReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    amt = int(req.amount * 100)
    idem = req.idempotency_key or str(uuid.uuid4())
    txn_id, was_existing = await vas_debit(user["_id"], amt, idem, "DATA",
        f"{req.network} Data — {req.phone_number}", {"network": req.network, "phone_number": req.phone_number, "plan_id": req.plan_id})
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}
    try:
        provider = await get_service_provider("DATA")
        if provider == "PAIRGATE":
            r = await call_pg("POST", "/data/purchase", body={
                "provider_id": req.network.upper(), "plan_id": req.plan_id,
                "recipient": req.phone_number, "reference": txn_id,
            })
            pref = str(r.get("reference", r.get("transaction_ref", txn_id)))
        elif provider == "CHEAPDATAHUB":
            try:
                bundle_id = int(req.plan_id)
            except (ValueError, TypeError):
                raise HTTPException(400, "Invalid data bundle ID for CheapDataHub provider")
            r = await call_cdh("POST", "/data/purchase/", body={
                "bundle_id": bundle_id, "phone_number": req.phone_number
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_id)))
        elif provider == "STROWALLET":
            result = await strow_buy_data(
                phone=req.phone_number, amount=req.amount,
                network=req.network, variation_code=req.plan_id,
            )
            pref = result["reference"]
        else:
            r = await call_sh("POST", "/vas/pay/data", body={"serviceCategoryId": "data",
                "bundleCode": req.plan_id, "amount": req.amount, "channel": "WEB",
                "phoneNumber": req.phone_number})
            pref = r.get("data", {}).get("transactionReference", "")
        pts = max(1, int(req.amount * 0.02))
        await vas_complete(user["_id"], txn_id, amt, pref,
            "Data Purchased", f"₦{req.amount:,.0f} data bundle → {req.phone_number}", pts,
            sms_event_type="DATA",
            sms_meta={"amount": req.amount, "network": req.network, "phone": req.phone_number, "plan": req.plan_id, "ref": txn_id})
        asyncio.create_task(send_event_notification(user["_id"], "DATA", {
            "amount": req.amount, "network": req.network, "phone": req.phone_number,
            "plan": req.plan_id, "ref": txn_id
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "DATA", f"{req.network} data"))
        asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
        return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount, "points_earned": pts}
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt, "Data Purchase Failed")
        raise
    except Exception:
        await vas_refund(user["_id"], txn_id, amt, "Data Purchase Failed")
        raise HTTPException(500, "Data purchase failed. Funds reversed.")

@router.post("/vas/cable")
async def pay_cable(req: CableReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    amt = int(req.amount * 100)
    idem = req.idempotency_key or str(uuid.uuid4())
    txn_id, was_existing = await vas_debit(user["_id"], amt, idem, "CABLE_TV",
        f"{req.provider} — {req.smartcard_number}", {"provider": req.provider, "smartcard_number": req.smartcard_number, "package_id": req.package_id})
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}
    try:
        svc_provider = await get_service_provider("CABLE")
        if svc_provider == "PAIRGATE":
            r = await call_pg("POST", "/cable/purchase", body={
                "provider_id": req.provider.upper(),
                "plan_id": req.package_id,
                "smartcard": req.smartcard_number,
                "reference": txn_id,
            })
            pref = str(r.get("reference", r.get("transaction_ref", txn_id)))
        elif svc_provider == "CHEAPDATAHUB":
            try:
                plan_id = int(req.package_id)
            except (ValueError, TypeError):
                raise HTTPException(400, "Invalid cable plan ID for CheapDataHub provider")
            r = await call_cdh("POST", "/cable/purchase/", body={
                "plan_id": plan_id, "cardnumber": req.smartcard_number, "phone": req.smartcard_number
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_id)))
        elif svc_provider == "STROWALLET":
            result = await strow_buy_cable(
                phone=req.smartcard_number, amount=req.amount,
                provider=req.provider, variation_code=req.package_id,
                smartcard_number=req.smartcard_number,
            )
            pref = result["reference"]
        else:
            r = await call_sh("POST", "/vas/pay/cable-tv", body={"serviceCategoryId": "cable-tv",
                "bundleCode": req.package_id, "amount": req.amount, "channel": "WEB", "cardNumber": req.smartcard_number})
            pref = r.get("data", {}).get("transactionReference", "")
        await vas_complete(user["_id"], txn_id, amt, pref,
            "Cable TV Renewed", f"{req.provider} subscription renewed for {req.smartcard_number}",
            sms_event_type="CABLE",
            sms_meta={"plan": req.package_id, "smartcard": req.smartcard_number, "ref": txn_id})
        asyncio.create_task(send_event_notification(user["_id"], "CABLE", {
            "plan": req.package_id, "smartcard": req.smartcard_number, "ref": txn_id
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "CABLE_TV", f"{req.provider} cable TV"))
        asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
        return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount}
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt, "Cable TV Payment Failed")
        raise
    except Exception:
        await vas_refund(user["_id"], txn_id, amt, "Cable TV Payment Failed")
        raise HTTPException(500, "Cable TV payment failed. Funds reversed.")

@router.post("/vas/electricity")
async def pay_electricity(req: ElectricityReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    if req.amount < 1000:
        raise HTTPException(400, "Minimum electricity payment is ₦1,000")
    amt = int(req.amount * 100)
    idem = req.idempotency_key or str(uuid.uuid4())
    txn_id, was_existing = await vas_debit(user["_id"], amt, idem, "ELECTRICITY",
        f"{req.disco} — {req.meter_number}", {"disco": req.disco, "meter_number": req.meter_number, "meter_type": req.meter_type})
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}
    try:
        svc_provider = await get_service_provider("ELECTRICITY")
        if svc_provider == "PAIRGATE":
            meter_type_int = 1 if req.meter_type.upper() == "PREPAID" else 2
            pg_disco = PG_DISCO_SLUGS.get(req.disco.upper(), req.disco.lower())
            # Purchase directly — meter was already validated by the frontend via /vas/meter-validate.
            # Do NOT re-verify here to avoid redundant API calls and rate-limit (429) issues.
            r2 = await call_pg("POST", "/electricity/purchase", body={
                "provider_id": pg_disco, "meter_number": req.meter_number,
                "meter_type": meter_type_int,
                "amount": int(req.amount),  # PairGate expects integer naira, not float
                "reference": txn_id,
            })
            logger.info(f"[PG] electricity-purchase response keys={list(r2.keys())} data={str(r2)[:400]}")
            pref = str(r2.get("reference_code", r2.get("reference", r2.get("transaction_ref", txn_id))))
            # PairGate delivers token as 'pin' asynchronously via webhook; also try sync fields
            token = r2.get("pin", r2.get("token", r2.get("receipt", "N/A")))
            units = str(r2.get("units", r2.get("unit", "")))
        elif svc_provider == "CHEAPDATAHUB":
            disco_id = CDH_ELECTRICITY_DISCO_IDS.get(req.disco.upper(), 1)
            r = await call_cdh("POST", "/electricity/purchase/", body={
                "disco_id": disco_id, "meter_number": req.meter_number,
                "amount": req.amount, "meter_type": req.meter_type.lower(), "phone": ""
            })
            data = r.get("data") or r
            pref = str(r.get("reference", r.get("transaction_id", txn_id)))
            token = data.get("token", data.get("receipt", "N/A")) if isinstance(data, dict) else "N/A"
            units = data.get("units", "") if isinstance(data, dict) else ""
        else:
            r = await call_sh("POST", "/vas/pay/utility", body={"serviceCategoryId": "electricity",
                "amount": req.amount, "channel": "WEB", "meterNumber": req.meter_number,
                "vendType": req.meter_type, "disco": req.disco})
            data = r.get("data", {})
            pref = data.get("transactionReference", "")
            token = data.get("token", "N/A")
            units = data.get("units", "")
        await db.transactions.update_one({"transaction_id": txn_id},
            {"$set": {"metadata.token": token, "metadata.units": units, "metadata.pg_ref": pref}})
        await vas_complete(user["_id"], txn_id, amt, pref,
            "Electricity Purchased", f"Token: {token} | Units: {units}",
            sms_event_type="ELECTRICITY",
            sms_meta={"token": token, "units": units, "meter": req.meter_number, "disco": req.disco, "ref": txn_id})
        asyncio.create_task(send_event_notification(user["_id"], "ELECTRICITY", {
            "token": token, "units": units, "meter": req.meter_number
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], req.amount, "ELECTRICITY", f"{req.disco} electricity"))
        asyncio.create_task(_check_referral_bg(user["_id"], req.amount))
        return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount, "token": token, "units": units}
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt, "Electricity Payment Failed")
        raise
    except Exception:
        await vas_refund(user["_id"], txn_id, amt, "Electricity Payment Failed")
        raise HTTPException(500, "Electricity payment failed. Funds reversed.")

@router.post("/vas/verify")
async def verify_vas(req: VerifyReq, request: Request):
    await get_current_user(request)
    r = await call_sh("POST", "/vas/verify", body={"serviceCategoryId": req.service_type, "entityNumber": req.identifier})
    return r.get("data", {})

@router.post("/vas/bet-verify")
async def bet_verify(req: BetVerifyReq, request: Request):
    """Validate a betting platform user ID and return account name."""
    await get_current_user(request)
    slug = req.platform.lower().strip()
    svc_provider = await get_service_provider("BETTING")
    if svc_provider == "PAIRGATE":
        try:
            api_key = os.environ.get("PAIRGATE_API_KEY", "")
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.post(f"{PAIRGATE_BASE_URL}/bet/verify",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={"provider_id": slug, "customer_id": req.customer_id})
            logger.info(f"[PG] bet-verify {slug} status={r.status_code} body={r.text[:300]}")
            if r.status_code == 200:
                data = r.json()
                inner = data.get("data") or data
                status_ok = inner.get("status") is True or str(inner.get("status", "")).lower() in ("true", "success")
                if status_ok:
                    name = (inner.get("customer_name") or inner.get("name") or "").strip()
                    # If name looks like a canonical account ID (all digits, 10-15 chars),
                    # treat it as the canonical customer_id PairGate expects for funding
                    canonical_id = name if (name and name.isdigit() and 10 <= len(name) <= 15) else req.customer_id
                    return {"valid": True, "name": name or req.customer_id,
                            "customer_id": req.customer_id, "canonical_id": canonical_id}
                else:
                    err = inner.get("message") or data.get("message") or "User ID not found"
                    return {"valid": False, "name": "", "customer_id": req.customer_id, "error": err}
        except Exception as e:
            logger.warning(f"[PG] bet-verify error: {e}")
    # Fallback — cannot verify
    return {"valid": True, "unverifiable": True, "name": "", "customer_id": req.customer_id,
            "note": "Could not verify — proceed carefully"}

# ===== BETTING VAS =====
BETTING_PLATFORMS = {
    "BET9JA": "Bet9ja", "SPORTYBET": "SportyBet", "1XBET": "1xBet",
    "BETKING": "BetKing", "MSPORT": "MSport", "BETWAY": "Betway",
    "BANGBET": "BangBet", "NAIRABET": "NairaBet", "NAIJABET": "NaijaBet",
    "MERRYBET": "MerryBet", "SUPABET": "SupaBet",
}

@router.post("/vas/betting")
async def fund_betting_wallet(req: BettingReq, request: Request):
    user = await get_current_user(request)
    await require_virtual_account(user)
    platform = req.platform.upper()
    if platform not in BETTING_PLATFORMS:
        raise HTTPException(400, f"Unsupported betting platform. Choose: {', '.join(BETTING_PLATFORMS.keys())}")
    if req.amount < 100:
        raise HTTPException(400, "Minimum deposit is ₦100")
    if req.amount > 200000:
        raise HTTPException(400, "Maximum single deposit is ₦200,000")
    if not req.account_id.strip():
        raise HTTPException(400, "Account ID is required")
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    amt = int(req.amount * 100)
    idem = str(uuid.uuid4())
    txn_id, was_existing = await vas_debit(
        user["_id"], amt, idem, "BETTING",
        f"{BETTING_PLATFORMS[platform]} — {req.account_id}",
        {"platform": platform, "account_id": req.account_id}
    )
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}
    try:
        svc_provider = await get_service_provider("BETTING")
        if svc_provider == "PAIRGATE":
            pg_slug = PG_BET_SLUGS.get(platform, platform.lower())
            r = await call_pg("POST", "/bet/purchase", body={
                "provider_id": pg_slug, "customer_id": req.account_id,
                "amount": req.amount, "reference": txn_id,
            })
            pref = str(r.get("reference_code", r.get("reference", r.get("transaction_ref", txn_id))))
        else:
            pref = f"BET-{secrets.token_hex(8).upper()}"
        await vas_complete(
            user["_id"], txn_id, amt, pref,
            f"{BETTING_PLATFORMS[platform]} Wallet Funded",
            f"₦{req.amount:,.2f} deposited to {req.account_id}",
            sms_event_type="BETTING",
            sms_meta={"amount": req.amount, "platform": BETTING_PLATFORMS[platform], "ref": txn_id}
        )
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt, "Betting Deposit Failed")
        raise
    except Exception:
        await vas_refund(user["_id"], txn_id, amt, "Betting Deposit Failed")
        raise HTTPException(500, "Betting deposit failed. Funds reversed.")
    await audit(user["_id"], "BETTING_FUND", "vas", {"platform": platform, "account_id": req.account_id, "amount": req.amount})
    return {"transaction_id": txn_id, "status": "COMPLETED",
            "amount": req.amount, "platform": BETTING_PLATFORMS[platform], "account_id": req.account_id}

# ===== KYC TIER (legacy BVN/NIN tier tracking) =====

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


# ===== VAS ROUTING (per-service provider selection) =====
VAS_SERVICES = ["AIRTIME", "DATA", "CABLE", "ELECTRICITY", "BETTING"]
VAS_PROVIDERS = ["CDH", "PAIRGATE"]


# ===== EDUCATION VAS =====

@router.get("/vas/education-plans")
async def get_education_plans(request: Request):
    """Return available education products (WAEC, JAMB, NECO, NABTEB)."""
    await get_current_user(request)
    # Allow admin-configured prices from DB
    overrides = {}
    try:
        cfg = await db.education_config.find_one({"_id": "prices"}) or {}
        overrides = cfg.get("prices", {})
    except Exception:
        pass
    products = []
    for p in EDUCATION_PRODUCTS:
        product = dict(p)
        product["amount"] = overrides.get(p["id"], p["default_amount"])
        products.append(product)
    # Group by exam body
    grouped = {}
    for p in products:
        body = p["exam_body"]
        if body not in grouped:
            grouped[body] = []
        grouped[body].append(p)
    return {"products": products, "grouped": grouped}


@router.post("/vas/education")
async def buy_education(req: EducationReq, request: Request):
    """Purchase an education scratch card (WAEC, JAMB, NECO, NABTEB)."""
    user = await get_current_user(request)
    await require_virtual_account(user)
    await verify_transaction_pin(user["_id"], req.transaction_pin)

    # Validate product
    product = next((p for p in EDUCATION_PRODUCTS if p["variation_code"] == req.variation_code and p["service_name"] == req.service_name), None)
    if not product:
        raise HTTPException(400, "Invalid education product")

    qty = max(1, min(req.quantity or 1, 5))
    unit_amount = req.amount
    total = unit_amount * qty
    amt_kobo = int(total * 100)

    idem = req.idempotency_key or str(uuid.uuid4())
    label = f"{product['label']} x{qty}" if qty > 1 else product["label"]
    txn_id, was_existing = await vas_debit(
        user["_id"], amt_kobo, idem, "EDUCATION",
        label,
        {"service_name": req.service_name, "variation_code": req.variation_code, "quantity": qty, "phone": req.phone}
    )
    if was_existing:
        return {"transaction_id": txn_id, "status": "COMPLETED"}

    try:
        result = await strow_buy_education(
            phone=req.phone,
            amount=unit_amount,
            service_name=req.service_name,
            variation_code=req.variation_code,
        )
        pref = result["reference"]
        raw = result.get("raw", {})

        # Try to extract PIN from response
        pin_data = raw.get("data") or raw.get("pin") or raw.get("pins") or raw.get("cards") or ""
        if isinstance(pin_data, list):
            pin_str = " | ".join([str(p) for p in pin_data[:qty]])
        elif isinstance(pin_data, dict):
            pin_str = str(pin_data.get("pin") or pin_data.get("serial") or "")
        else:
            pin_str = str(pin_data) if pin_data else ""

        # Store pin in transaction metadata
        await db.transactions.update_one(
            {"transaction_id": txn_id},
            {"$set": {"metadata.pin": pin_str, "metadata.edu_ref": pref, "metadata.exam_body": product["exam_body"]}}
        )

        pts = max(1, int(total * 0.01))
        await vas_complete(
            user["_id"], txn_id, amt_kobo, pref,
            f"{product['label']} Purchased",
            f"Reference: {pref}",
            pts,
            sms_event_type="EDUCATION",
            sms_meta={"product": product["label"], "phone": req.phone, "ref": txn_id, "amount": total}
        )
        asyncio.create_task(send_event_notification(user["_id"], "EDUCATION", {
            "product": product["label"], "phone": req.phone, "ref": txn_id, "amount": total
        }))
        asyncio.create_task(_credit_cashback_bg(user["_id"], total, "EDUCATION", product["label"]))
        asyncio.create_task(_check_referral_bg(user["_id"], total))

        return {
            "transaction_id": txn_id,
            "status": "COMPLETED",
            "amount": total,
            "product": product["label"],
            "reference": pref,
            "pin": pin_str,
            "points_earned": pts,
        }
    except HTTPException:
        await vas_refund(user["_id"], txn_id, amt_kobo, f"{product['label']} Failed")
        raise
    except Exception as e:
        logger.error(f"[EDUCATION] purchase error: {e}")
        await vas_refund(user["_id"], txn_id, amt_kobo, f"{product['label']} Failed")
        raise HTTPException(500, f"{product['label']} purchase failed. Funds reversed.")

