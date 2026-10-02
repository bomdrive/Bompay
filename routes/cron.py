"""Bompay — Cron Jobs routes."""
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
    _verify_cron,
    _run_auto_save,
    _run_loan_reminders,
    get_savings_config,
    get_loan_config,
    _current_period_index,
    _period_due_date,
    _sweep_fee_margin,
    _run_sms_billing,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/cron/auto-save")
async def cron_auto_save(request: Request, bg: BackgroundTasks):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_auto_save, run_id)
    return {"accepted": True, "run_id": run_id}

@router.post("/cron/loan-reminders")
async def cron_loan_reminders(request: Request, bg: BackgroundTasks):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_loan_reminders, run_id)
    return {"accepted": True, "run_id": run_id}

# ─── Loan Auto-Debit Cron ───
async def _run_loan_autorepay(run_id: str):
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    cfg = await get_loan_config()
    loans = await db.loan_applications.find({
        "status": "DISBURSED",
        "repayment_schedule": {"$elemMatch": {"due_date": today, "status": "PENDING"}}
    }).to_list(5000)
    for loan in loans:
        schedule = loan.get("repayment_schedule", [])
        due_idx = next((i for i, s in enumerate(schedule) if s["due_date"] == today and s["status"] == "PENDING"), None)
        if due_idx is None:
            continue
        install = schedule[due_idx]
        amt_kobo = int(install["amount"] * 100)
        user_id = loan["user_id"]
        idem = f"loan-autorepay-{loan['loan_id']}-{today}"
        if await db.transactions.find_one({"idempotency_key": idem}):
            continue
        updated_w = await db.wallets.find_one_and_update(
            {"user_id": user_id, "available_balance": {"$gte": amt_kobo}},
            {"$inc": {"available_balance": -amt_kobo, "ledger_balance": -amt_kobo}},
            return_document=True
        )
        if not updated_w:
            fee_type = cfg.get("defaulter_fee_type", "FLAT")
            fee_kobo = int(cfg.get("defaulter_fee_amount", 500.0) * 100) if fee_type == "FLAT" \
                else int(amt_kobo * cfg.get("defaulter_fee_percentage", 2.0) / 100)
            if fee_kobo > 0:
                fee_w = await db.wallets.find_one_and_update(
                    {"user_id": user_id, "available_balance": {"$gte": fee_kobo}},
                    {"$inc": {"available_balance": -fee_kobo, "ledger_balance": -fee_kobo}},
                    return_document=True
                )
                if fee_w:
                    await db.transactions.insert_one({
                        "transaction_id": f"TXN{secrets.token_hex(12).upper()}",
                        "idempotency_key": f"loanfee-{loan['loan_id']}-{today}",
                        "user_id": user_id, "type": "LOAN_DEFAULTER_FEE", "direction": "DEBIT",
                        "amount": fee_kobo, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
                        "provider": "INTERNAL",
                        "description": f"Loan defaulter fee — installment {install['installment']}",
                        "metadata": {"loan_id": loan["loan_id"], "installment": install["installment"]},
                        "created_at": now.isoformat(), "updated_at": now.isoformat()
                    })
            await db.loan_applications.update_one({"loan_id": loan["loan_id"]}, {"$set": {
                f"repayment_schedule.{due_idx}.status": "DEFAULTED",
                f"repayment_schedule.{due_idx}.defaulter_fee": fee_kobo / 100,
                "updated_at": now.isoformat()
            }})
            await notify(user_id, "Loan Payment Missed",
                         f"Installment {install['installment']} of ₦{install['amount']:,.2f} missed. Defaulter fee charged.", "error")
        else:
            txn_id = f"TXN{secrets.token_hex(12).upper()}"
            new_repaid = loan.get("amount_repaid", 0.0) + install["amount"]
            is_done = new_repaid >= loan.get("total_repayment", 0) - 0.01
            await db.transactions.insert_one({
                "transaction_id": txn_id, "idempotency_key": idem, "user_id": user_id,
                "type": "LOAN_REPAYMENT", "direction": "DEBIT", "amount": amt_kobo,
                "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
                "description": f"Auto loan repayment — installment {install['installment']}",
                "metadata": {"loan_id": loan["loan_id"], "installment": install["installment"], "auto": True},
                "created_at": now.isoformat(), "updated_at": now.isoformat()
            })
            upd: dict = {
                f"repayment_schedule.{due_idx}.status": "PAID",
                f"repayment_schedule.{due_idx}.paid_at": now.isoformat(),
                f"repayment_schedule.{due_idx}.paid_amount": install["amount"],
                "amount_repaid": new_repaid, "updated_at": now.isoformat()
            }
            if is_done:
                upd["status"] = "REPAID"; upd["repaid_at"] = now.isoformat()
            await db.loan_applications.update_one({"loan_id": loan["loan_id"]}, {"$set": upd})
            try:
                repay_acct = await db.charge_accounts.find_one({"category": "LOAN_REPAYMENTS"})
                sh_dest = (repay_acct or {}).get("sh_account_number", "")
                w_doc = await db.wallets.find_one({"user_id": user_id})
                user_sh = (w_doc or {}).get("sh_account_number", "")
                if sh_dest and user_sh:
                    await call_sh("POST", "/transfers", body={
                        "debitAccountNumber": user_sh, "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                        "beneficiaryAccountNumber": sh_dest, "amount": install["amount"],
                        "saveBeneficiary": False, "narration": f"BOMPAY auto loan repayment {loan['loan_id'][:8]}",
                        "paymentReference": txn_id
                    })
            except Exception as e:
                logger.warning(f"[LoanAutoRepay] SH sweep failed: {e}")
            msg = "Loan fully repaid!" if is_done else f"Auto-deducted ₦{install['amount']:,.2f}. Outstanding: ₦{max(0, loan['total_repayment'] - new_repaid):,.2f}"
            await notify(user_id, "Auto Loan Repayment", msg, "success")

@router.post("/cron/loan-auto-debit")
async def cron_loan_auto_debit(request: Request, bg: BackgroundTasks):
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_loan_autorepay, run_id)
    return {"accepted": True, "run_id": run_id}

# ─── Savings Interest Crediting Cron ───
async def _run_interest_credit(run_id: str):
    now = datetime.now(timezone.utc)
    cfg = await get_savings_config()
    goals = await db.savings_goals.find({
        "status": "ACTIVE", "savings_type": {"$in": ["FLEX", "FIXED"]}, "current_amount": {"$gt": 0}
    }).to_list(5000)
    for goal in goals:
        idem = f"interest-{goal['goal_id']}-{now.strftime('%Y-%m-%d')}"
        if await db.transactions.find_one({"idempotency_key": idem}):
            continue
        stype = goal.get("savings_type", "FLEX")
        annual_rate = cfg.get("flex_interest_rate", 10.0) / 100 if stype == "FLEX" \
            else cfg.get(f"fixed_rate_{goal.get('term_days', 30)}", 12.0) / 100
        daily_kobo = int(goal.get("current_amount", 0) * annual_rate / 365)
        if daily_kobo <= 0:
            continue
        inc: dict = {"interest_earned": daily_kobo}
        if stype == "FLEX":
            inc["current_amount"] = daily_kobo
        await db.savings_goals.update_one({"goal_id": goal["goal_id"]}, {"$inc": inc})
        await db.transactions.insert_one({
            "transaction_id": f"TXN{secrets.token_hex(12).upper()}",
            "idempotency_key": idem, "user_id": goal["user_id"],
            "type": "SAVINGS_INTEREST", "direction": "CREDIT",
            "amount": daily_kobo, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
            "provider": "INTERNAL", "description": f"Daily interest: {goal['name']}",
            "metadata": {"goal_id": goal["goal_id"], "savings_type": stype},
            "created_at": now.isoformat(), "updated_at": now.isoformat()
        })

@router.post("/cron/savings-interest-credit")
async def cron_savings_interest_credit(request: Request, bg: BackgroundTasks):
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_interest_credit, run_id)
    return {"accepted": True, "run_id": run_id}

# ─── Ajo Auto-Contribute Cron ───
async def _run_ajo_auto_contribute(run_id: str):
    from datetime import date as _date
    today = datetime.now(timezone.utc).date()
    logger.info(f"[Ajo Cron] Starting auto-contribute run {run_id} for {today}")
    groups = await db.ajo_groups.find({"status": "ACTIVE"}, {"_id": 0}).to_list(500)
    for group in groups:
        gid = group["group_id"]
        period_idx = _current_period_index(group["start_date"], group["frequency"])
        if period_idx < 0:
            continue  # Not started yet
        if period_idx >= group["max_members"]:
            # All periods done; handle round end
            logger.info(f"[Ajo Cron] Group {gid} completed all periods in round {group.get('current_round',1)}")
            continue
        due_date = _period_due_date(group["start_date"], period_idx, group["frequency"])
        if due_date != today:
            continue  # Not due today

        members = await db.ajo_members.find({"group_id": gid, "status": "ACTIVE"}, {"_id": 0}).to_list(50)
        payout_created = False
        for member in members:
            uid = member["user_id"]
            # Check if already paid this period
            existing = await db.ajo_contributions.find_one({
                "group_id": gid, "round": group.get("current_round", 1), "period_index": period_idx, "user_id": uid})
            if existing and existing["status"] == "PAID":
                continue
            idem = f"ajo-auto-{gid}-{uid}-r{group.get('current_round',1)}-p{period_idx}-{run_id}"
            if await db.transactions.find_one({"idempotency_key": idem}):
                continue
            amt = int(group["contribution_amount"] * 100)
            updated_w = await db.wallets.find_one_and_update(
                {"user_id": uid, "available_balance": {"$gte": amt}},
                {"$inc": {"available_balance": -amt, "ledger_balance": -amt}},
                return_document=True
            )
            now_iso = datetime.now(timezone.utc).isoformat()
            if updated_w:
                txn_id = f"TXN{secrets.token_hex(12).upper()}"
                await db.transactions.insert_one({
                    "transaction_id": txn_id, "user_id": uid,
                    "type": "AJO_CONTRIBUTION", "direction": "DEBIT", "amount": amt, "fee": 0, "vat": 0,
                    "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
                    "description": f"Ajo auto-contribution — {group['name']}",
                    "metadata": {"group_id": gid, "period_index": period_idx, "round": group.get("current_round", 1)},
                    "idempotency_key": idem, "created_at": now_iso, "updated_at": now_iso
                })
                contrib_doc = {"contribution_id": str(uuid.uuid4()), "group_id": gid, "user_id": uid,
                               "round": group.get("current_round", 1), "period_index": period_idx,
                               "due_date": due_date.isoformat(), "amount": amt, "status": "PAID",
                               "paid_at": now_iso, "transaction_id": txn_id, "days_overdue": 0,
                               "idempotency_key": idem}
                if existing:
                    await db.ajo_contributions.update_one({"contribution_id": existing["contribution_id"]},
                        {"$set": {"status": "PAID", "paid_at": now_iso, "transaction_id": txn_id, "days_overdue": 0}})
                else:
                    try:
                        await db.ajo_contributions.insert_one(contrib_doc)
                    except Exception:
                        pass
                await db.ajo_members.update_one({"group_id": gid, "user_id": uid},
                                                {"$set": {"consecutive_default_days": 0}})
            else:
                # Failed to debit — charge daily defaulter fee
                days_od = member.get("consecutive_default_days", 0) + 1
                fee_amt = int(group.get("defaulter_fee_amount", 200.0) * 100)
                if fee_amt > 0:
                    fee_w = await db.wallets.find_one_and_update(
                        {"user_id": uid, "available_balance": {"$gte": fee_amt}},
                        {"$inc": {"available_balance": -fee_amt, "ledger_balance": -fee_amt}},
                        return_document=True
                    )
                    if fee_w:
                        fee_idem = f"ajo-fee-{gid}-{uid}-r{group.get('current_round',1)}-p{period_idx}-d{days_od}-{run_id}"
                        fee_txn_id = f"TXN{secrets.token_hex(12).upper()}"
                        await db.transactions.insert_one({
                            "transaction_id": fee_txn_id, "user_id": uid,
                            "type": "AJO_DEFAULTER_FEE", "direction": "DEBIT", "amount": fee_amt, "fee": 0, "vat": 0,
                            "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
                            "description": f"Ajo defaulter fee — {group['name']}",
                            "metadata": {"group_id": gid, "period_index": period_idx, "days_overdue": days_od},
                            "idempotency_key": fee_idem, "created_at": now_iso, "updated_at": now_iso
                        })
                if existing:
                    await db.ajo_contributions.update_one({"contribution_id": existing["contribution_id"]},
                                                          {"$inc": {"days_overdue": 1}})
                else:
                    try:
                        await db.ajo_contributions.insert_one({
                            "contribution_id": str(uuid.uuid4()), "group_id": gid, "user_id": uid,
                            "round": group.get("current_round", 1), "period_index": period_idx,
                            "due_date": due_date.isoformat(), "amount": amt, "status": "DUE",
                            "paid_at": None, "transaction_id": None, "days_overdue": 1,
                            "idempotency_key": f"ajo-due-{gid}-{uid}-r{group.get('current_round',1)}-p{period_idx}"
                        })
                    except Exception:
                        pass
                await db.ajo_members.update_one({"group_id": gid, "user_id": uid},
                                                {"$set": {"consecutive_default_days": days_od}})
                await notify(uid, "Ajo Contribution Failed",
                             f"Could not debit your wallet for '{group['name']}'. Days overdue: {days_od}. Daily fee: ₦{group.get('defaulter_fee_amount',200):.2f}", "warning")
                if days_od >= 7:
                    # Pause group
                    u_doc = await db.users.find_one({"_id": ObjectId(uid)}, {"first_name": 1, "last_name": 1})
                    u_name = f"{(u_doc or {}).get('first_name','')} {(u_doc or {}).get('last_name','')}".strip() or "A member"
                    await db.ajo_groups.update_one({"group_id": gid}, {"$set": {
                        "status": "PAUSED",
                        "pause_reason": f"{u_name} has defaulted for 7 consecutive days",
                        "paused_at": now_iso, "updated_at": now_iso
                    }})
                    all_members = await db.ajo_members.find({"group_id": gid, "status": "ACTIVE"}, {"user_id": 1}).to_list(50)
                    for m2 in all_members:
                        await notify(m2["user_id"], f"Ajo '{group['name']}' Paused",
                                     f"{u_name} has not contributed for 7 days. Group is paused until arrears are cleared.", "error")
                    logger.warning(f"[Ajo Cron] Group {gid} paused due to 7-day default by {uid}")
                    break  # Stop processing this group for this run
        # Check if all members paid → create payout
        paid_count = await db.ajo_contributions.count_documents({
            "group_id": gid, "round": group.get("current_round", 1), "period_index": period_idx, "status": "PAID"
        })
        if paid_count >= len(members):
            payout_order = group.get("payout_order", [])
            if len(payout_order) > period_idx:
                recipient_id = payout_order[period_idx]
                existing_payout = await db.ajo_payouts.find_one(
                    {"group_id": gid, "round": group.get("current_round", 1), "period_index": period_idx})
                if not existing_payout:
                    payout_amount = group["contribution_amount"] * len(members)
                    try:
                        await db.ajo_payouts.insert_one({
                            "payout_id": str(uuid.uuid4()), "group_id": gid,
                            "round": group.get("current_round", 1), "period_index": period_idx,
                            "recipient_user_id": recipient_id, "amount": payout_amount,
                            "status": "PENDING", "claimed_at": None, "transaction_id": None
                        })
                    except Exception:
                        pass
                    await notify(recipient_id, "Your Ajo Collection is Ready!",
                                 f"₦{payout_amount:,.2f} ready to collect from '{group['name']}'!", "success")
                    asyncio.create_task(send_event_notification(recipient_id, "AJO_PAYOUT_READY", {
                        "amount": payout_amount, "group": group["name"]
                    }))
    logger.info(f"[Ajo Cron] Run {run_id} complete")

@router.post("/cron/ajo-auto-contribute")
async def cron_ajo_auto_contribute(request: Request, bg: BackgroundTasks):
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_ajo_auto_contribute, run_id)
    return {"accepted": True, "run_id": run_id}

# ===== POSTGRESQL LEDGER ADMIN ENDPOINTS =====

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

@router.post("/cron/sms-billing")
async def cron_sms_billing(request: Request, bg: BackgroundTasks):
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_sms_billing, run_id)
    return {"accepted": True, "run_id": run_id}

# ===== ENHANCED ADMIN STATS =====



# ── Family Allowance Cron ──────────────────────────────────────────────────────
async def _run_family_allowances(run_id: str):
    """Distribute scheduled allowances (weekly / monthly) to active family members."""
    now = datetime.now(timezone.utc)
    today = now.date()
    distributed = 0
    skipped = 0

    members = await db.family_members.find({
        "allowance_frequency": {"$in": ["weekly", "monthly"]},
        "allowance_kobo": {"$gt": 0},
        "status": "ACTIVE",
        "role": {"$ne": "owner"},
    }).to_list(1000)

    for m in members:
        freq = m.get("allowance_frequency", "none")
        last_str = m.get("last_allowance_at")
        try:
            last_date = datetime.fromisoformat(last_str).date() if last_str else None
        except Exception:
            last_date = None

        if freq == "weekly":
            should = last_date is None or (today - last_date).days >= 7
        elif freq == "monthly":
            should = last_date is None or today.month != last_date.month
        else:
            continue

        if not should:
            continue

        family_id = m["family_id"]
        fam = await db.family_groups.find_one({"family_id": family_id})
        if not fam:
            continue

        allowance_kobo = m.get("allowance_kobo", 0)
        if fam.get("available_kobo", 0) < allowance_kobo:
            owner_uid = fam.get("owner_user_id")
            if owner_uid:
                await notify(
                    owner_uid,
                    "Allowance Failed",
                    f"Insufficient Family Wallet balance to distribute ₦{allowance_kobo/100:,.2f} allowance.",
                    "warning",
                )
            skipped += 1
            continue

        now_str = now.isoformat()
        await db.family_groups.update_one(
            {"family_id": family_id},
            {"$inc": {"available_kobo": -allowance_kobo}, "$set": {"updated_at": now_str}},
        )
        await db.family_members.update_one(
            {"member_id": m["member_id"]},
            {
                "$inc": {"allocated_kobo": allowance_kobo},
                "$set": {"last_allowance_at": now_str, "updated_at": now_str},
            },
        )
        await db.family_ledger.insert_one({
            "entry_id": str(uuid.uuid4()),
            "family_id": family_id,
            "member_id": m["member_id"],
            "type": "MEMBER_ALLOCATION",
            "amount_kobo": allowance_kobo,
            "description": f"Auto-allowance ({freq}) — ₦{allowance_kobo/100:,.2f}",
            "created_at": now_str,
        })
        owner_uid = fam.get("owner_user_id")
        if owner_uid:
            await notify(
                owner_uid,
                "Allowance Distributed",
                f"₦{allowance_kobo/100:,.2f} {freq} allowance distributed automatically.",
                "success",
            )
        distributed += 1

    logging.info("[Family] Allowances: distributed=%d skipped=%d run_id=%s", distributed, skipped, run_id)


@router.post("/cron/family-allowances")
async def cron_family_allowances(request: Request, bg: BackgroundTasks):
    _verify_cron(request)
    run_id = request.headers.get("X-Webhook-Id", str(uuid.uuid4()))
    bg.add_task(_run_family_allowances, run_id)
    return {"accepted": True, "run_id": run_id}


# ── NIP Inward Auto-Balance (midnight) ────────────────────────────────────────

@router.post("/cron/nip-inward-balance")
async def cron_nip_inward_balance(request: Request):
    """Midnight: aggregate all pending NIP inward costs and record the balance sweep.
    Updates nip_inward_costs records to BALANCED and notifies admins."""
    _verify_cron(request)
    now = datetime.now(timezone.utc)

    pending = await db.nip_inward_costs.find({"status": "PENDING_BALANCE"}).to_list(None)
    if not pending:
        return {"message": "No pending NIP inward costs", "count": 0, "total_ngn": 0}

    total_cost_ngn = round(sum(p.get("cost_ngn", 0) for p in pending), 2)
    txn_ids = [p["txn_id"] for p in pending]
    sweep_ref = f"NIPIN{int(now.timestamp())}"

    # Mark all as BALANCED
    await db.nip_inward_costs.update_many(
        {"txn_id": {"$in": txn_ids}},
        {"$set": {
            "status": "BALANCED",
            "balance_ref": sweep_ref,
            "balanced_at": now.isoformat()
        }}
    )

    # Record the sweep in transactions for audit trail
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
        "description": f"Auto NIP inward commission balance — {len(pending)} deposits",
        "metadata": {
            "txn_count": len(pending),
            "period_start": pending[0].get("created_at", "") if pending else "",
            "period_end": now.isoformat()
        },
        "created_at": now.isoformat(),
        "updated_at": now.isoformat()
    })

    # Update charge account cumulative
    await db.charge_accounts.update_one(
        {"category": "NIP_INWARD_COMMISSION"},
        {"$inc": {"total_swept_kobo": int(total_cost_ngn * 100)},
         "$set": {"last_balanced_at": now.isoformat()}},
        upsert=False
    )

    # Notify all admins
    admins = await db.users.find({"role": "admin"}).to_list(10)
    for au in admins:
        await db.notifications.insert_one({
            "notification_id": str(uuid.uuid4()),
            "user_id": au["_id"],
            "title": "NIP Inward Auto-Balance Complete",
            "message": (f"Midnight auto-balance: {len(pending)} deposits totalling "
                        f"₦{total_cost_ngn:,.2f} in NIP Inward Commission have been balanced. "
                        f"Ref: {sweep_ref}"),
            "type": "info",
            "is_read": False,
            "created_at": now.isoformat()
        })

    logger.info(f"[NIPInward] Auto-balanced {len(pending)} records, ₦{total_cost_ngn:.2f}, ref={sweep_ref}")
    return {
        "message": "NIP inward balance complete",
        "count": len(pending),
        "total_ngn": total_cost_ngn,
        "reference": sweep_ref
    }



# ─── BUSINESS PAYROLL AUTO-RUN ───────────────────────────────────────────────
@router.post("/cron/business-payroll")
async def cron_business_payroll(request: Request):
    """Daily 9 AM — finds all active businesses whose pay_day = today and runs payroll."""
    from bson import ObjectId as OID
    _verify_cron(request)

    today_day = datetime.now(timezone.utc).day
    businesses = await db.businesses.find(
        {"status": "active", "pay_day": today_day}
    ).to_list(None)

    results = []

    for b in businesses:
        biz_id   = str(b["_id"])
        owner_id = b["owner_id"]
        biz_name = b["name"]
        now      = datetime.now(timezone.utc)

        active_staff = await db.business_staff.find(
            {"business_id": biz_id, "status": "active"}
        ).to_list(None)

        if not active_staff:
            results.append({"business": biz_name, "status": "skipped", "reason": "no active staff"})
            continue

        total_kobo = sum(s.get("net_pay", 0) for s in active_staff)
        w = await db.business_wallets.find_one({"business_id": biz_id}) or {}

        # ── Insufficient balance ──────────────────────────────────────────────
        if w.get("available_balance", 0) < total_kobo:
            await notify(owner_id, f"Payroll Failed — {biz_name}",
                f"Auto-payroll failed: insufficient business balance. "
                f"Need ₦{total_kobo/100:,.2f}. Please fund your business wallet.")
            owner = await db.users.find_one({"_id": OID(owner_id)}) or {}
            owner_phone = owner.get("phone", "")
            if owner_phone:
                op = owner_phone.strip()
                if op.startswith("0"):   op = "+234" + op[1:]
                elif not op.startswith("+"): op = "+234" + op
                sms = (f"BOMPAY: Auto payroll for {biz_name} FAILED — insufficient balance. "
                       f"Fund your business wallet to pay {len(active_staff)} staff member(s). "
                       f"Amount needed: ₦{total_kobo/100:,.2f}.")
                try:
                    provider = await get_sms_provider()
                    if provider == "BULKSMSLIVE": await _send_via_bulksms(op, sms)
                    else:                          await _send_via_sendora(op, sms)
                except Exception as e:
                    logger.warning(f"[CRON-PAYROLL] SMS failed for {biz_name}: {e}")
            results.append({"business": biz_name, "status": "failed", "reason": "insufficient_balance",
                             "needed": total_kobo, "available": w.get("available_balance", 0)})
            continue

        # ── Run payroll with loan deductions ──────────────────────────────────
        errors = []
        paid   = []

        for staff in active_staff:
            net  = staff.get("net_pay", 0)
            name = staff.get("name", "?")
            try:
                sw = await db.wallets.find_one({"user_id": staff.get("user_id")})
                if not sw:
                    errors.append(f"{name}: wallet not found"); continue

                # Compute loan deductions for this staff member
                active_loans = await db.business_staff_loans.find(
                    {"business_id": biz_id, "staff_id": str(staff["_id"]), "status": "active"}
                ).to_list(None)
                loan_ded = sum(
                    min(l.get("monthly_deduction", 0), l.get("outstanding_balance", 0))
                    for l in active_loans
                )
                adj_net = max(0, net - loan_ded)

                # Debit business (adj_net only), credit staff
                await db.business_wallets.update_one(
                    {"business_id": biz_id},
                    {"$inc": {"available_balance": -adj_net, "ledger_balance": -adj_net}}
                )
                await db.wallets.update_one(
                    {"user_id": staff.get("user_id")},
                    {"$inc": {"available_balance": adj_net, "ledger_balance": adj_net}}
                )

                # SH transfer
                if b.get("sh_subaccount_id") and b.get("sh_account_number") and adj_net > 0:
                    try:
                        pay_ref = f"SAL-AUTO-{biz_id[:6]}-{str(staff['_id'])[:6]}-{int(now.timestamp())}"
                        await call_sh("POST", "/transfers", body={
                            "nameEnquiryReference": "",
                            "debitAccountNumber":   b["sh_account_number"],
                            "beneficiaryBankCode":  SAFEHAVEN_OWN_BANK_CODE,
                            "beneficiaryAccountNumber": sw.get("account_number", ""),
                            "amount":     adj_net,
                            "saveBeneficiary": False,
                            "narration":  f"Salary — {biz_name}",
                            "paymentReference": pay_ref,
                        })
                    except Exception as e:
                        logger.warning(f"[CRON-PAYROLL] SH for {name}: {e}")

                # Business transaction record
                await db.business_transactions.insert_one({
                    "business_id": biz_id,
                    "type": "DEBIT",
                    "category": "PAYROLL",
                    "amount": adj_net,
                    "description": f"Salary — {name}" + (f" (loan deducted ₦{loan_ded/100:,.2f})" if loan_ded else ""),
                    "staff_id": str(staff["_id"]),
                    "auto": True,
                    "created_at": now,
                })

                # Process loan repayments
                for loan in active_loans:
                    instalment  = min(loan.get("monthly_deduction", 0), loan.get("outstanding_balance", 0))
                    new_balance = max(0, loan.get("outstanding_balance", 0) - instalment)
                    new_status  = "completed" if new_balance == 0 else "active"
                    await db.business_staff_loans.update_one(
                        {"_id": loan["_id"]},
                        {"$set": {"outstanding_balance": new_balance, "status": new_status,
                                  "last_deduction_at": now},
                         "$push": {"repayments": {"amount": instalment, "date": now.isoformat(),
                                                  "remaining": new_balance}}}
                    )

                # Notify staff (in-app)
                await notify(staff["user_id"], "Salary Credited",
                             f"Your salary of ₦{adj_net/100:,.2f} from {biz_name} has been credited!"
                             + (f" Loan instalment ₦{loan_ded/100:,.2f} deducted." if loan_ded else ""))

                # Notify staff (SMS)
                staff_phone = staff.get("phone", "")
                if staff_phone:
                    sp = staff_phone.strip()
                    if sp.startswith("0"):    sp = "+234" + sp[1:]
                    elif not sp.startswith("+"): sp = "+234" + sp
                    sms = (f"BOMPAY: Your salary of ₦{adj_net/100:,.2f} from {biz_name} has been credited!"
                           + (f" Loan repayment ₦{loan_ded/100:,.2f} deducted." if loan_ded else ""))
                    try:
                        provider = await get_sms_provider()
                        if provider == "BULKSMSLIVE": await _send_via_bulksms(sp, sms)
                        else:                          await _send_via_sendora(sp, sms)
                    except Exception as e:
                        logger.warning(f"[CRON-PAYROLL] Staff SMS for {name}: {e}")

                paid.append(name)
            except Exception as e:
                errors.append(f"{name}: {e}")
                logger.error(f"[CRON-PAYROLL] Staff {name} error: {e}")

        # Record payroll run
        await db.business_payroll.insert_one({
            "business_id": biz_id,
            "owner_id":    owner_id,
            "total_amount": sum(s.get("net_pay", 0) for s in active_staff if s.get("name") in paid),
            "staff_paid":  paid,
            "errors":      errors,
            "status":      "completed" if not errors else "partial",
            "run_at":      now,
            "auto":        True,
        })

        # Notify owner
        msg = (f"Auto-payroll for {biz_name}: {len(paid)} staff paid, "
               + (f"{len(errors)} error(s)." if errors else "all successful!"))
        await notify(owner_id, f"Payroll Complete — {biz_name}", msg)

        results.append({
            "business": biz_name, "status": "done",
            "paid": len(paid), "errors": errors,
        })

    return {"results": results, "processed": len(businesses), "pay_day": today_day}


# ─── BUSINESS PAYROLL REMINDER ────────────────────────────────────────────────
@router.post("/cron/business-payroll-reminder")
async def business_payroll_reminder(request: Request):
    """Daily — sends owner an SMS preview 2 days before payday so they can fund the account."""
    today       = datetime.now(timezone.utc)
    target_day  = (today + timedelta(days=2)).day

    businesses = await db.businesses.find({"status": "active"}).to_list(None)
    results    = []

    for biz in businesses:
        pay_day = biz.get("pay_day")
        if not pay_day:
            continue
        try:
            if int(pay_day) != target_day:
                continue
        except (ValueError, TypeError):
            continue

        biz_id   = str(biz["_id"])
        owner_id = biz.get("owner_id", "")
        biz_name = biz.get("name", "Your Business")
        acct_num = biz.get("sh_account_number", "")

        # Idempotency — one reminder per business per calendar month
        month_key = f"{today.year}-{today.month:02d}"
        if await db.business_payroll_reminders.find_one({"business_id": biz_id, "month_key": month_key}):
            results.append({"business": biz_name, "status": "already_sent"})
            continue

        active_staff = await db.business_staff.find(
            {"business_id": biz_id, "status": "active"}
        ).to_list(None)
        if not active_staff:
            continue

        total_kobo   = sum(s.get("net_pay", s.get("gross_pay", 0)) for s in active_staff)
        staff_names  = [s.get("name", "Staff") for s in active_staff]
        name_preview = ", ".join(staff_names[:3]) + (f" +{len(staff_names)-3} more" if len(staff_names) > 3 else "")

        sms = (
            f"BOMPAY: Payroll for {biz_name} is due in 2 days. "
            f"{len(active_staff)} staff: {name_preview}. "
            f"Expected total: \u20A6{total_kobo/100:,.2f}. "
            f"Fund your account {acct_num} before payday."
        )

        # Send SMS to business owner
        if owner_id:
            owner = await db.users.find_one({"_id": ObjectId(owner_id)})
            phone = (owner or {}).get("phone", "")
            if phone:
                p = phone.strip()
                if p.startswith("0"):      p = "+234" + p[1:]
                elif not p.startswith("+"): p = "+234" + p
                try:
                    provider = await get_sms_provider()
                    if provider == "BULKSMSLIVE": await _send_via_bulksms(p, sms)
                    else:                          await _send_via_sendora(p, sms)
                except Exception as e:
                    logger.warning(f"[PAYROLL-REMINDER] SMS failed for {biz_name}: {e}")

            await notify(owner_id,
                         f"Payroll Reminder — {biz_name}",
                         f"Payroll due in 2 days. {len(active_staff)} staff. "
                         f"Total: \u20A6{total_kobo/100:,.2f}. Fund your business account.")

        # Record so we don't send again this month
        await db.business_payroll_reminders.insert_one({
            "business_id": biz_id,
            "month_key":   month_key,
            "sent_at":     today,
            "staff_count": len(active_staff),
            "total_kobo":  total_kobo,
        })

        results.append({"business": biz_name, "status": "reminder_sent",
                         "staff": len(active_staff), "total_ngn": total_kobo / 100})

    return {"results": results, "target_pay_day": target_day, "checked": len(businesses)}
