"""Bompay — Savings routes."""
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
    KYCBVNReq, KYCNINReq, SavingsReq, ContributeReq, verify_transaction_pin,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/kyc/tier")
async def kyc_tier(request: Request):
    user = await get_current_user(request)
    kyc = await db.kyc_records.find_one({"user_id": user["_id"]}, {"_id": 0})
    return {"tier": user.get("kyc_tier", 0), "status": user.get("kyc_status", "PENDING"), "details": kyc or {}}

@router.post("/kyc/submit-bvn")
async def submit_bvn(req: KYCBVNReq, request: Request):
    user = await get_current_user(request)
    if not req.bvn.isdigit() or len(req.bvn) != 11:
        raise HTTPException(400, "BVN must be exactly 11 digits")
    # Enforce one account per BVN
    existing = await db.kyc_records.find_one({"bvn": req.bvn, "bvn_verified": True, "user_id": {"$ne": str(user["_id"])}})
    if existing:
        raise HTTPException(400, "This BVN is already linked to an existing BOMPAY account. Each BVN can only be registered once.")
    await db.kyc_records.update_one({"user_id": str(user["_id"])}, {"$set": {
        "user_id": str(user["_id"]), "bvn": req.bvn, "bvn_verified": True,
        "date_of_birth": req.date_of_birth, "bvn_verified_at": datetime.now(timezone.utc).isoformat()
    }}, upsert=True)
    await db.users.update_one({"_id": ObjectId(user["_id"])},
        {"$set": {"kyc_tier": 1, "kyc_status": "TIER_1_VERIFIED"}})
    await notify(user["_id"], "KYC Tier 1 Unlocked!", "BVN verified. Daily limit: ₦50,000.", "success")
    await audit(user["_id"], "KYC_BVN", "kyc", {"bvn_last4": req.bvn[-4:]})
    return {"tier": 1, "status": "TIER_1_VERIFIED", "message": "BVN verified! Tier 1 unlocked."}

@router.post("/kyc/submit-nin")
async def submit_nin(req: KYCNINReq, request: Request):
    user = await get_current_user(request)
    if not req.nin.isdigit() or len(req.nin) != 11:
        raise HTTPException(400, "NIN must be exactly 11 digits")
    kyc = await db.kyc_records.find_one({"user_id": user["_id"]})
    if not kyc or not kyc.get("bvn_verified"):
        raise HTTPException(400, "Complete Tier 1 (BVN) first")
    await db.kyc_records.update_one({"user_id": user["_id"]}, {"$set": {
        "nin": req.nin, "nin_verified": True, "nin_verified_at": datetime.now(timezone.utc).isoformat()
    }})
    await db.users.update_one({"_id": ObjectId(user["_id"])},
        {"$set": {"kyc_tier": 2, "kyc_status": "TIER_2_VERIFIED"}})
    await notify(user["_id"], "KYC Tier 2 Unlocked!", "NIN verified. Daily limit: ₦200,000.", "success")
    return {"tier": 2, "status": "TIER_2_VERIFIED", "message": "NIN verified! Tier 2 unlocked."}

# ===== SAVINGS =====
@router.get("/savings")
async def get_savings(request: Request):
    user = await get_current_user(request)
    goals = await db.savings_goals.find({"user_id": user["_id"], "status": {"$ne": "DELETED"}}, {"_id": 0}).to_list(100)
    for g in goals:
        g["target_amount_ngn"] = g.get("target_amount", 0) / 100
        g["current_amount_ngn"] = g.get("current_amount", 0) / 100
    total_saved = sum(g.get("current_amount", 0) for g in goals) / 100
    return {"goals": goals, "total_saved": total_saved}

@router.post("/savings")
async def create_savings_goal(req: SavingsReq, request: Request):
    user = await get_current_user(request)
    # Load savings config for interest rate
    cfg_doc = await db.settings.find_one({"key": "savings_config"})
    cfg = (cfg_doc or {}).get("value", {})
    savings_type = req.savings_type.upper() if req.savings_type else "TARGET"

    # Determine interest rate from config
    if savings_type == "FLEX":
        interest_rate = cfg.get("flex_interest_rate", 10.0)
    elif savings_type == "FIXED":
        td = req.term_days or 30
        rate_key = f"fixed_rate_{td}"
        interest_rate = cfg.get(rate_key, 12.0)
    else:
        interest_rate = cfg.get("target_interest_rate", 10.0)

    # Maturity date for FIXED
    locked_until = None
    if savings_type == "FIXED":
        td = req.term_days or 30
        locked_until = (datetime.now(timezone.utc) + timedelta(days=td)).date().isoformat()

    goal = {
        "goal_id": str(uuid.uuid4()), "user_id": user["_id"], "name": req.name,
        "savings_type": savings_type,
        "target_amount": int(req.target_amount * 100), "current_amount": 0,
        "target_date": req.target_date or locked_until,
        "term_days": req.term_days,
        "locked_until": locked_until,
        "auto_save": req.auto_save,
        "auto_save_amount": int((req.auto_save_amount or 0) * 100),
        "auto_save_frequency": req.auto_save_frequency,
        "interest_rate": interest_rate,
        "interest_earned": 0,
        "status": "ACTIVE", "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.savings_goals.insert_one(goal)
    await notify(user["_id"], "Savings Goal Created", f"'{req.name}' goal created!", "success")
    return {"goal_id": goal["goal_id"], "name": req.name, "target_amount": req.target_amount,
            "current_amount": 0, "savings_type": savings_type, "interest_rate": interest_rate,
            "target_date": goal["target_date"], "locked_until": locked_until, "status": "ACTIVE",
            "auto_save": req.auto_save, "auto_save_amount": req.auto_save_amount or 0,
            "auto_save_frequency": req.auto_save_frequency}

@router.post("/savings/{goal_id}/contribute")
async def contribute_savings(goal_id: str, req: ContributeReq, request: Request):
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    goal = await db.savings_goals.find_one({"goal_id": goal_id, "user_id": user["_id"]})
    if not goal:
        raise HTTPException(404, "Savings goal not found")
    amt = int(req.amount * 100)

    # ─── Idempotency guard ───
    idem = f"save-contrib-{goal_id}-{req.transaction_pin}-{amt}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H')}"
    if await db.transactions.find_one({"idempotency_key": idem}):
        raise HTTPException(409, "Duplicate contribution detected. Please wait before retrying.")

    # ─── Dual balance check: BOMPAY wallet AND Safe Haven ───
    wallet_doc = await db.wallets.find_one({"user_id": user["_id"]})
    if not wallet_doc or wallet_doc.get("available_balance", 0) < amt:
        raise HTTPException(400, f"Insufficient BOMPAY wallet balance. Required: ₦{req.amount:,.2f}")
    # Check SH balance if SH account linked
    sh_acct = wallet_doc.get("sh_account_number")
    if sh_acct:
        try:
            sh_bal_resp = await call_sh("GET", f"/accounts/{wallet_doc.get('sh_account_id', sh_acct)}/balance")
            sh_bal = sh_bal_resp.get("data", {}).get("availableBalance", sh_bal_resp.get("availableBalance", None))
            if sh_bal is not None and float(sh_bal) * 100 < amt:
                raise HTTPException(400, f"Insufficient balance. Available: ₦{float(sh_bal):,.2f}, Required: ₦{req.amount:,.2f}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"[Savings] SH balance check skipped: {e}")

    # ─── Atomic wallet debit (prevents race conditions) ───
    updated_w = await db.wallets.find_one_and_update(
        {"user_id": user["_id"], "available_balance": {"$gte": amt}},
        {"$inc": {"available_balance": -amt, "ledger_balance": -amt}},
        return_document=True
    )
    if not updated_w:
        raise HTTPException(400, "Insufficient balance (concurrent deduction detected)")

    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": txn_id, "idempotency_key": idem, "user_id": user["_id"],
        "type": "SAVINGS_CONTRIBUTION", "direction": "DEBIT",
        "amount": amt, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
        "provider": "INTERNAL", "description": f"Savings: {goal['name']}",
        "metadata": {"goal_id": goal_id}, "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })
    await db.savings_goals.update_one({"goal_id": goal_id}, {"$inc": {"current_amount": amt}})

    # ─── SH sweep: user SH → configured SAVINGS service account (best-effort) ───
    # Priority: service_bucket_accounts.SAVINGS → charge_accounts.SAVINGS_PROCEEDS
    try:
        svc_acct = await db.service_bucket_accounts.find_one({"service": "SAVINGS", "is_active": True})
        if svc_acct:
            sh_dest = svc_acct.get("sh_account_number", "")
        else:
            savings_acct = await db.charge_accounts.find_one({"category": "SAVINGS_PROCEEDS"})
            sh_dest = (savings_acct or {}).get("sh_account_number", "")
        if sh_acct and sh_dest:
            await call_sh("POST", "/transfers", body={
                "debitAccountNumber": sh_acct,
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": sh_dest,
                "amount": req.amount, "saveBeneficiary": False,
                "narration": f"BOMPAY savings {goal['name'][:20]}",
                "paymentReference": txn_id
            })
            logger.info(f"[Savings] SH sweep OK: ₦{req.amount} user→savings account={sh_dest}")
        else:
            logger.warning(f"[Savings] No SH destination configured for SAVINGS bucket — wallet debited only")
    except Exception as e:
        logger.warning(f"[Savings] SH sweep failed (wallet already debited): {e}")

    new_amt = (goal.get("current_amount", 0) + amt) / 100
    target = goal.get("target_amount", 0) / 100
    progress = (new_amt / target * 100) if target > 0 else 0
    await notify(user["_id"], "Savings Updated",
                 f"₦{req.amount:,.2f} added to '{goal['name']}'. Progress: {progress:.1f}%", "success")
    w_after = await get_wallet(user["_id"])
    asyncio.create_task(send_event_notification(user["_id"], "SAVINGS_DEBIT", {
        "amount": req.amount, "goal": goal["name"], "balance": w_after["available_balance"] / 100
    }))
    asyncio.create_task(send_event_sms(user["_id"], "SAVINGS_DEBIT", {
        "amount": req.amount, "goal": goal["name"], "balance": w_after["available_balance"] / 100
    }))
    return {"transaction_id": txn_id, "status": "COMPLETED", "amount": req.amount,
            "new_total": new_amt, "progress": round(progress, 1)}

@router.delete("/savings/{goal_id}")
async def delete_savings(goal_id: str, request: Request):
    user = await get_current_user(request)
    goal = await db.savings_goals.find_one({"goal_id": goal_id, "user_id": user["_id"]})
    if not goal:
        raise HTTPException(404, "Goal not found")

    current_kobo = goal.get("current_amount", 0)
    interest_kobo = goal.get("interest_earned", 0)
    today = datetime.now(timezone.utc).date().isoformat()
    locked_until = goal.get("locked_until")
    savings_type = goal.get("savings_type", "TARGET")
    is_early = savings_type == "FIXED" and locked_until and locked_until > today

    if is_early:
        # Early exit penalty: lose ALL interest + 5% of principal
        penalty_kobo = int(current_kobo * 0.05)
        payout_kobo = max(0, current_kobo - penalty_kobo)
        penalty_ngn = penalty_kobo / 100
        # Record penalty transaction
        if penalty_kobo > 0:
            pen_txn_id = f"TXN{secrets.token_hex(12).upper()}"
            await db.transactions.insert_one({
                "transaction_id": pen_txn_id, "user_id": user["_id"],
                "type": "SAVINGS_PENALTY", "direction": "DEBIT",
                "amount": penalty_kobo + interest_kobo, "fee": 0, "vat": 0, "currency": "NGN",
                "status": "COMPLETED", "provider": "INTERNAL",
                "description": f"Early exit penalty: {goal['name']} (5% principal + lost interest)",
                "metadata": {"goal_id": goal_id, "interest_forfeited": interest_kobo, "penalty_kobo": penalty_kobo},
                "created_at": datetime.now(timezone.utc).isoformat(), "updated_at": datetime.now(timezone.utc).isoformat()
            })
        await notify(user["_id"], "Early Exit Penalty Applied",
                     f"Early withdrawal from {goal['name']}: penalty ₦{penalty_ngn:,.2f} + all interest forfeited.", "warning")
    else:
        # At maturity or non-FIXED: return full amount + interest
        payout_kobo = current_kobo + interest_kobo

    if payout_kobo > 0:
        # Atomic credit to wallet
        await db.wallets.update_one({"user_id": user["_id"]},
            {"$inc": {"available_balance": payout_kobo, "ledger_balance": payout_kobo}})
        # SH reverse sweep: SAVINGS service account → user SH account (best-effort)
        try:
            svc_acct = await db.service_bucket_accounts.find_one({"service": "SAVINGS", "is_active": True})
            if svc_acct:
                sh_src = svc_acct.get("sh_account_number", "")
            else:
                savings_acct = await db.charge_accounts.find_one({"category": "SAVINGS_PROCEEDS"})
                sh_src = (savings_acct or {}).get("sh_account_number", "")
            wallet_doc = await db.wallets.find_one({"user_id": user["_id"]})
            user_sh = (wallet_doc or {}).get("sh_account_number", "")
            if sh_src and user_sh:
                await call_sh("POST", "/transfers", body={
                    "debitAccountNumber": sh_src,
                    "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                    "beneficiaryAccountNumber": user_sh,
                    "amount": payout_kobo / 100, "saveBeneficiary": False,
                    "narration": f"BOMPAY savings withdrawal {goal['name'][:20]}",
                    "paymentReference": f"TXN{secrets.token_hex(12).upper()}"
                })
                logger.info(f"[Savings] SH reverse sweep OK: ₦{payout_kobo/100} savings→user")
            else:
                logger.warning(f"[Savings] No SH source configured for SAVINGS bucket — wallet credited only")
        except Exception as e:
            logger.warning(f"[Savings] SH withdrawal sweep failed: {e}")

        await notify(user["_id"], "Savings Withdrawn",
                     f"₦{payout_kobo/100:,.2f} returned to wallet.", "info")

    await db.savings_goals.update_one({"goal_id": goal_id},
        {"$set": {"status": "DELETED", "current_amount": 0, "interest_earned": 0}})
    return {"message": "Goal closed, funds returned to wallet.", "payout": payout_kobo / 100,
            "early_exit_penalty_applied": is_early}

@router.get("/savings/{goal_id}/contributions")
async def get_savings_contributions(goal_id: str, request: Request):
    """User: get contribution breakdown for one savings goal."""
    user = await get_current_user(request)
    goal = await db.savings_goals.find_one({"goal_id": goal_id, "user_id": user["_id"]}, {"_id": 0})
    if not goal:
        raise HTTPException(404, "Goal not found")
    txns = await db.transactions.find(
        {"user_id": user["_id"], "type": "SAVINGS_CONTRIBUTION", "metadata.goal_id": goal_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(200)
    total_contributed = sum(t.get("amount", 0) for t in txns) / 100
    goal["target_amount_ngn"] = goal.get("target_amount", 0) / 100
    goal["current_amount_ngn"] = goal.get("current_amount", 0) / 100
    goal["interest_earned_ngn"] = goal.get("interest_earned", 0) / 100
    for t in txns:
        t["amount_ngn"] = t.get("amount", 0) / 100
    return {"goal": goal, "contributions": txns, "total_contributed": total_contributed,
            "contribution_count": len(txns)}

# ===== LOANS =====
