"""Bompay — Loans routes."""
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
    get_service_bucket_account,
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
    LoanReq, LoanRepayReq, verify_transaction_pin, get_loan_config,
    _credit_cashback_bg, _check_referral_bg,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/loans")
async def get_loans(request: Request):
    user = await get_current_user(request)
    loans = await db.loan_applications.find({"user_id": user["_id"]}, {"_id": 0}).sort("created_at", -1).to_list(20)
    return {"loans": loans}

@router.post("/loans/apply")
async def apply_loan(req: LoanReq, request: Request):
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    if user.get("kyc_tier", 0) < 1:
        raise HTTPException(403, "KYC verification required (Tier 1 minimum)")
    loan_cfg = await get_loan_config()
    min_amt = loan_cfg.get("min_amount", 5000.0)
    max_amt = loan_cfg.get("max_amount", 500000.0)
    max_tenor = loan_cfg.get("max_tenor", 12)
    if req.amount < min_amt or req.amount > max_amt:
        raise HTTPException(400, f"Loan amount must be ₦{min_amt:,.0f}–₦{max_amt:,.0f}")
    if req.tenor_months < 1 or req.tenor_months > max_tenor:
        raise HTTPException(400, f"Tenor must be 1–{max_tenor} months")
    # Block if user already has an active or pending loan
    existing = await db.loan_applications.find_one({"user_id": user["_id"], "status": {"$in": ["PENDING", "DISBURSED"]}})
    if existing:
        state = "active" if existing["status"] == "DISBURSED" else "pending review"
        raise HTTPException(400, f"You have a loan {state}. Repay/wait before applying for another.")

    rate = loan_cfg.get("interest_rate_tier2", 5.0) if user.get("kyc_tier", 0) >= 2 else loan_cfg.get("interest_rate_tier1", 8.0)
    total_interest = req.amount * (rate / 100) * req.tenor_months
    total = req.amount + total_interest
    monthly = round(total / req.tenor_months, 2)
    loan_id = str(uuid.uuid4())
    applied_at = datetime.now(timezone.utc)

    await db.loan_applications.insert_one({
        "loan_id": loan_id, "user_id": user["_id"], "amount": req.amount,
        "purpose": req.purpose, "tenor_months": req.tenor_months,
        "interest_rate": rate, "total_interest": round(total_interest, 2),
        "total_repayment": round(total, 2), "monthly_payment": monthly,
        "repayment_schedule": [], "amount_repaid": 0.0,
        "status": "PENDING", "created_at": applied_at.isoformat(),
        "due_date": None, "reminder_sent": False
    })
    await notify(user["_id"], "Loan Application Submitted",
                 f"Your ₦{req.amount:,.2f} loan application is under review. You will be notified once approved.", "info")
    return {"loan_id": loan_id, "amount": req.amount, "status": "PENDING",
            "interest_rate": rate, "total_repayment": round(total, 2),
            "monthly_payment": monthly, "tenor_months": req.tenor_months,
            "message": "Application submitted successfully. Awaiting admin approval."}

@router.post("/loans/{loan_id}/repay")
async def repay_loan(loan_id: str, req: LoanRepayReq, request: Request):
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    loan = await db.loan_applications.find_one({"loan_id": loan_id, "user_id": user["_id"]})
    if not loan:
        raise HTTPException(404, "Loan not found")
    if loan["status"] != "DISBURSED":
        raise HTTPException(400, "Loan is not active or already repaid")
    total_repayment = loan.get("total_repayment", 0)
    amount_repaid = loan.get("amount_repaid", 0.0)
    outstanding = round(total_repayment - amount_repaid, 2)
    if req.amount <= 0:
        raise HTTPException(400, "Repayment amount must be greater than zero")
    if req.amount > outstanding + 0.01:
        raise HTTPException(400, f"Amount exceeds outstanding balance of ₦{outstanding:,.2f}")
    # Clamp to outstanding to avoid floating-point overshoot
    repay_amount = min(req.amount, outstanding)
    amt_kobo = int(round(repay_amount * 100))

    # ── Dual balance check: Bompay wallet AND Safe Haven virtual account ──────
    pre_w = await db.wallets.find_one({"user_id": user["_id"]})
    if not pre_w or pre_w.get("available_balance", 0) < amt_kobo:
        raise HTTPException(400, f"Insufficient wallet balance. Required: ₦{repay_amount:,.2f}")
    sh_id = pre_w.get("sh_account_id", "")
    if sh_id:
        try:
            from core import get_sh_subaccount_balance
            sh_bal = await get_sh_subaccount_balance(sh_id)
            if sh_bal * 100 < amt_kobo:
                raise HTTPException(400, f"Insufficient balance. Available: ₦{sh_bal:,.2f}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"[Loans] SH balance check failed (non-fatal): {e}")
    # ─────────────────────────────────────────────────────────────────────────

    # Atomic wallet debit
    updated_wallet = await db.wallets.find_one_and_update(
        {"user_id": user["_id"], "available_balance": {"$gte": amt_kobo}},
        {"$inc": {"available_balance": -amt_kobo, "ledger_balance": -amt_kobo}},
        return_document=True
    )
    if not updated_wallet:
        w = await get_wallet(user["_id"])
        raise HTTPException(400, f"Insufficient wallet balance. Available: ₦{(w['available_balance']/100):,.2f}, Required: ₦{repay_amount:,.2f}")
    # Update loan record
    new_amount_repaid = round(amount_repaid + repay_amount, 2)
    new_outstanding = round(total_repayment - new_amount_repaid, 2)
    is_fully_repaid = new_outstanding <= 0.01
    # Update installment schedule — mark next PENDING installment as PAID
    schedule = loan.get("repayment_schedule", [])
    paid_idx = next((i for i, inst in enumerate(schedule) if inst["status"] == "PENDING"), None)
    sched_update = {}
    if paid_idx is not None:
        sched_update[f"repayment_schedule.{paid_idx}.status"] = "PAID"
        sched_update[f"repayment_schedule.{paid_idx}.paid_at"] = datetime.now(timezone.utc).isoformat()
        sched_update[f"repayment_schedule.{paid_idx}.paid_amount"] = repay_amount

    loan_update: dict = {
        "amount_repaid": new_amount_repaid,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        **sched_update
    }
    if is_fully_repaid:
        loan_update["status"] = "REPAID"
        loan_update["repaid_at"] = datetime.now(timezone.utc).isoformat()
    await db.loan_applications.update_one({"loan_id": loan_id}, {"$set": loan_update})
    # Record transaction
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    await db.transactions.insert_one({
        "transaction_id": txn_id, "user_id": user["_id"],
        "type": "LOAN_REPAYMENT", "direction": "DEBIT",
        "amount": amt_kobo, "fee": 0, "vat": 0, "currency": "NGN",
        "status": "COMPLETED", "provider": "INTERNAL",
        "description": f"Loan repayment — ₦{repay_amount:,.2f}",
        "metadata": {
            "loan_id": loan_id,
            "outstanding_before": outstanding,
            "outstanding_after": max(0.0, new_outstanding),
            "fully_repaid": is_fully_repaid
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    })
    # Try to sweep to LOANS service bucket → falls back to LOAN_REPAYMENTS charge account (best-effort)
    try:
        sh_repay_dest = await get_service_bucket_account("LOANS", "LOAN_REPAYMENTS")
        sender_w = await db.wallets.find_one({"user_id": user["_id"]})
        if sh_repay_dest and sender_w and sender_w.get("sh_account_number"):
            await call_sh("POST", "/transfers", body={
                "debitAccountNumber": sender_w["sh_account_number"],
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": sh_repay_dest,
                "amount": repay_amount,
                "saveBeneficiary": False,
                "narration": f"BOMPAY loan repayment {loan_id[:8]}",
                "paymentReference": txn_id
            })
        else:
            logger.info(f"[Loans] No LOANS SH bucket configured — repayment tracked internally only")
    except Exception as e:
        logger.warning(f"[Loans] LOANS SH repayment sweep failed (non-fatal): {e}")
    # Notify
    msg = "Loan fully repaid! Congratulations!" if is_fully_repaid else f"₦{repay_amount:,.2f} repaid. Outstanding: ₦{max(0.0, new_outstanding):,.2f}"
    await notify(user["_id"], "Loan Repayment", msg, "success")
    asyncio.create_task(send_event_notification(user["_id"], "LOAN_REPAYMENT", {
        "amount": repay_amount, "outstanding": max(0.0, new_outstanding), "fully_repaid": is_fully_repaid
    }))
    asyncio.create_task(send_event_sms(user["_id"], "LOAN_REPAYMENT", {
        "amount": repay_amount, "outstanding": max(0.0, new_outstanding), "fully_repaid": is_fully_repaid
    }))
    return {
        "transaction_id": txn_id,
        "amount_paid": repay_amount,
        "outstanding_balance": max(0.0, new_outstanding),
        "loan_status": "REPAID" if is_fully_repaid else "DISBURSED",
        "fully_repaid": is_fully_repaid,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

# ===== REWARDS =====
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

