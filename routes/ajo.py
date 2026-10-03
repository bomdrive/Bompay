"""Bompay — Ajo routes."""
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
    gen_account_number, get_wallet, ledger_entry, get_sh_subaccount_balance,
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
from models import *  # noqa: F401,F403,F405
from core import (  # noqa: F401,F403,F405
    _period_due_date,
    AjoCreateReq,
    verify_transaction_pin,
    _ajo_invite_code,
    AjoJoinReq,
    AjoContributeReq,
    _current_period_index,
    AjoSetOrderReq,
    AjoBidSlotReq,
    _build_ajo_detail,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/ajo/{group_id}/history")
async def ajo_contribution_history(group_id: str, request: Request):
    """All contribution records for the current user across all rounds, plus defaulter fee transactions."""
    user = await get_current_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0, "name": 1, "contribution_amount": 1, "frequency": 1, "start_date": 1, "max_members": 1})
    if not group:
        raise HTTPException(404, "Group not found")
    member = await db.ajo_members.find_one({"group_id": group_id, "user_id": user["_id"]})
    if not member:
        raise HTTPException(403, "Not a member of this group")
    # All contribution records for this user
    contribs = await db.ajo_contributions.find(
        {"group_id": group_id, "user_id": user["_id"]}, {"_id": 0}
    ).sort([("round", 1), ("period_index", 1)]).to_list(500)
    # Defaulter fee transactions for this user in this group
    fee_txns = await db.transactions.find(
        {"user_id": user["_id"], "type": "AJO_DEFAULTER_FEE", "metadata.group_id": group_id}, {"_id": 0}
    ).sort("created_at", -1).to_list(200)
    # Payout records for this user
    payouts = await db.ajo_payouts.find(
        {"group_id": group_id, "recipient_user_id": user["_id"]}, {"_id": 0}
    ).sort([("round", 1), ("period_index", 1)]).to_list(50)
    # Enrich contributions with due_date if not stored
    for c in contribs:
        if not c.get("due_date"):
            c["due_date"] = _period_due_date(group["start_date"], c.get("period_index", 0), group["frequency"]).isoformat()
        c["amount_ngn"] = round(c.get("amount", 0) / 100, 2)
    total_contributed = sum(c["amount_ngn"] for c in contribs if c.get("status") == "PAID")
    total_fees = sum(t.get("amount", 0) / 100 for t in fee_txns)
    return {
        "group_id": group_id,
        "group_name": group["name"],
        "contributions": contribs,
        "defaulter_fee_transactions": fee_txns,
        "payouts": payouts,
        "summary": {
            "total_contributed": round(total_contributed, 2),
            "total_fees_charged": round(total_fees, 2),
            "periods_paid": sum(1 for c in contribs if c.get("status") == "PAID"),
            "periods_defaulted": sum(1 for c in contribs if c.get("status") == "DEFAULTED"),
        }
    }

@router.post("/ajo/create")
async def ajo_create(req: AjoCreateReq, request: Request):
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    if not (2 <= req.max_members <= 20):
        raise HTTPException(400, "Group size must be 2–20 members")
    if req.contribution_amount < 100:
        raise HTTPException(400, "Minimum contribution amount is ₦100")
    if req.frequency not in ("WEEKLY", "MONTHLY"):
        raise HTTPException(400, "Frequency must be WEEKLY or MONTHLY")
    if req.payout_order_method not in ("RANDOM", "CREATOR", "BIDDING"):
        raise HTTPException(400, "Payout order must be RANDOM, CREATOR, or BIDDING")
    from datetime import date as _date
    try:
        _date.fromisoformat(req.start_date)
    except ValueError:
        raise HTTPException(400, "Invalid start_date format (use YYYY-MM-DD)")

    # Defaulter fee from admin config, not user input
    ajo_cfg_doc = await db.settings.find_one({"key": "ajo_config"})
    ajo_cfg = {**{"defaulter_fee_amount": 200.0}, **(ajo_cfg_doc or {}).get("value", {})}
    defaulter_fee = float(ajo_cfg.get("defaulter_fee_amount", 200.0))

    # Generate unique invite code
    for _ in range(10):
        code = _ajo_invite_code()
        if not await db.ajo_groups.find_one({"invite_code": code}):
            break

    group_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    group = {
        "group_id": group_id, "name": req.name.strip(),
        "creator_id": user["_id"], "leader_id": user["_id"],
        "max_members": req.max_members, "contribution_amount": req.contribution_amount,
        "frequency": req.frequency, "start_date": req.start_date,
        "payout_order_method": req.payout_order_method, "payout_order": [],
        "one_round_only": req.one_round_only, "defaulter_fee_amount": defaulter_fee,
        "status": "FORMING", "current_round": 1, "invite_code": code,
        "pause_reason": None, "paused_at": None, "total_rounds_completed": 0,
        "created_at": now_iso, "updated_at": now_iso,
    }
    await db.ajo_groups.insert_one(group)
    # Creator auto-joins
    await db.ajo_members.insert_one({
        "member_id": str(uuid.uuid4()), "group_id": group_id, "user_id": user["_id"],
        "status": "ACTIVE", "payout_position": None, "consecutive_default_days": 0,
        "joined_at": now_iso,
    })
    group.pop("_id", None)
    return {**group, "message": "Ajo group created! Share the invite code with your group."}

@router.get("/ajo/preview")
async def ajo_preview(invite_code: str, request: Request):
    """Preview a group before joining (no auth required for peek, but user must be logged in to join)."""
    await get_current_user(request)
    group = await db.ajo_groups.find_one({"invite_code": invite_code.upper().strip()}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Invalid or expired invite code")
    member_count = await db.ajo_members.count_documents({"group_id": group["group_id"], "status": {"$ne": "LEFT"}})
    spots_left = group["max_members"] - member_count
    return {
        "group_id": group["group_id"], "name": group["name"],
        "contribution_amount": group["contribution_amount"], "frequency": group["frequency"],
        "max_members": group["max_members"], "member_count": member_count,
        "spots_left": spots_left, "start_date": group["start_date"],
        "payout_order_method": group["payout_order_method"],
        "one_round_only": group["one_round_only"], "status": group["status"],
        "defaulter_fee_amount": group["defaulter_fee_amount"],
        "invite_code": invite_code.upper().strip(),
    }

@router.post("/ajo/join")
async def ajo_join(req: AjoJoinReq, request: Request):
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    group = await db.ajo_groups.find_one({"invite_code": req.invite_code.upper().strip()})
    if not group:
        raise HTTPException(404, "Invalid or expired invite code")
    if group["status"] not in ("FORMING",):
        raise HTTPException(400, f"This group is {group['status']} and no longer accepting members")
    # Check already a member
    existing = await db.ajo_members.find_one({"group_id": group["group_id"], "user_id": user["_id"]})
    if existing:
        raise HTTPException(409, "You are already a member of this group")
    # Check capacity
    member_count = await db.ajo_members.count_documents({"group_id": group["group_id"], "status": {"$ne": "LEFT"}})
    if member_count >= group["max_members"]:
        raise HTTPException(400, "This group is full")
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.ajo_members.insert_one({
        "member_id": str(uuid.uuid4()), "group_id": group["group_id"], "user_id": user["_id"],
        "status": "ACTIVE", "payout_position": None, "consecutive_default_days": 0,
        "joined_at": now_iso,
    })
    new_count = member_count + 1
    # Check if group is now full
    if new_count >= group["max_members"]:
        method = group["payout_order_method"]
        if method == "RANDOM":
            # Assign random payout order immediately
            members_raw = await db.ajo_members.find(
                {"group_id": group["group_id"], "status": {"$ne": "LEFT"}}, {"user_id": 1}
            ).to_list(50)
            import random
            ids = [m["user_id"] for m in members_raw]
            random.shuffle(ids)
            for i, uid in enumerate(ids):
                await db.ajo_members.update_one(
                    {"group_id": group["group_id"], "user_id": uid},
                    {"$set": {"payout_position": i + 1}}
                )
            await db.ajo_groups.update_one({"group_id": group["group_id"]}, {"$set": {
                "status": "ACTIVE", "payout_order": ids, "updated_at": now_iso
            }})
            # Notify creator
            await notify(group["creator_id"], f"Ajo '{group['name']}' is Active!",
                         "All members joined! Payout order randomly assigned. Contributions start on the start date.", "success")
        elif method == "BIDDING":
            await db.ajo_groups.update_one({"group_id": group["group_id"]}, {"$set": {
                "status": "ORDERING", "updated_at": now_iso
            }})
            await notify(group["creator_id"], f"Ajo '{group['name']}' — Pick Your Slots!",
                         "All members joined! Members can now bid for their payout position.", "info")
        else:  # CREATOR
            await db.ajo_groups.update_one({"group_id": group["group_id"]}, {"$set": {
                "status": "ORDERING", "updated_at": now_iso
            }})
            await notify(group["creator_id"], f"Ajo '{group['name']}' — Set Payout Order",
                         "All members have joined! Set the payout order to start the group.", "info")
    else:
        await db.ajo_groups.update_one({"group_id": group["group_id"]}, {"$set": {"updated_at": now_iso}})
    # Notify the new member
    u_full = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"first_name": 1})
    member_name = (u_full or {}).get("first_name", "New member")
    await notify(group["creator_id"], f"{member_name} joined '{group['name']}'",
                 f"{new_count}/{group['max_members']} members", "info")
    return {"message": f"Joined '{group['name']}' successfully!", "group_id": group["group_id"],
            "spots_left": group["max_members"] - new_count}

@router.get("/ajo/my-groups")
async def ajo_my_groups(request: Request):
    user = await get_current_user(request)
    memberships = await db.ajo_members.find({"user_id": user["_id"], "status": {"$ne": "LEFT"}}, {"group_id": 1}).to_list(100)
    group_ids = [m["group_id"] for m in memberships]
    if not group_ids:
        return {"groups": []}
    groups = await db.ajo_groups.find({"group_id": {"$in": group_ids}}, {"_id": 0}).sort("created_at", -1).to_list(100)
    result = []
    for g in groups:
        mc = await db.ajo_members.count_documents({"group_id": g["group_id"], "status": {"$ne": "LEFT"}})
        my_member = await db.ajo_members.find_one({"group_id": g["group_id"], "user_id": user["_id"]}, {"payout_position": 1})
        pending_payout = await db.ajo_payouts.find_one(
            {"group_id": g["group_id"], "recipient_user_id": user["_id"], "status": "PENDING"}, {"amount": 1})
        result.append({**g, "member_count": mc,
                       "my_payout_position": (my_member or {}).get("payout_position"),
                       "has_pending_payout": pending_payout is not None,
                       "pending_payout_amount": (pending_payout or {}).get("amount")})
    return {"groups": result}

@router.get("/ajo/due-count")
async def ajo_due_count(request: Request):
    """Returns number of active groups where the current user has an unpaid contribution this period."""
    user = await get_current_user(request)
    memberships = await db.ajo_members.find(
        {"user_id": user["_id"], "status": {"$ne": "LEFT"}}, {"group_id": 1}
    ).to_list(100)
    due = 0
    for m in memberships:
        group = await db.ajo_groups.find_one(
            {"group_id": m["group_id"], "status": {"$in": ["ACTIVE", "ORDERING"]}},
            {"start_date": 1, "frequency": 1}
        )
        if not group:
            continue
        period_idx = _current_period_index(group["start_date"], group["frequency"])
        if period_idx < 0:
            continue  # group hasn't started yet
        paid = await db.ajo_contributions.find_one({
            "group_id": m["group_id"],
            "user_id": user["_id"],
            "period_index": period_idx,
            "status": "PAID",
        })
        if not paid:
            due += 1
    return {"due_count": due}

@router.get("/ajo/{group_id}")
async def ajo_detail(group_id: str, request: Request):
    user = await get_current_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Ajo group not found")
    member = await db.ajo_members.find_one({"group_id": group_id, "user_id": user["_id"]})
    if not member:
        raise HTTPException(403, "You are not a member of this group")
    detail = await _build_ajo_detail(group, user["_id"])
    detail["my_payout_position"] = member.get("payout_position")
    return detail

@router.post("/ajo/{group_id}/contribute")
async def ajo_contribute(group_id: str, req: AjoContributeReq, request: Request):
    """Manual contribution for the current period."""
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Ajo group not found")
    if group["status"] not in ("ACTIVE",):
        raise HTTPException(400, f"Group is {group['status']} — contributions not accepted")
    member = await db.ajo_members.find_one({"group_id": group_id, "user_id": user["_id"]})
    if not member or member["status"] != "ACTIVE":
        raise HTTPException(403, "You are not an active member of this group")
    period_idx = _current_period_index(group["start_date"], group["frequency"])
    if period_idx < 0:
        raise HTTPException(400, "Contributions haven't started yet — wait for the start date")
    if period_idx >= group["max_members"]:
        raise HTTPException(400, "All rounds complete for this group")
    # Check if already paid this period
    existing = await db.ajo_contributions.find_one({
        "group_id": group_id, "round": group["current_round"],
        "period_index": period_idx, "user_id": user["_id"]
    })
    if existing and existing["status"] == "PAID":
        raise HTTPException(409, "You have already contributed for this period")
    amt = int(group["contribution_amount"] * 100)  # contribution in kobo
    idem = f"ajo-contrib-{group_id}-{user['_id']}-r{group['current_round']}-p{period_idx}"
    if await db.transactions.find_one({"idempotency_key": idem}):
        raise HTTPException(409, "Contribution already recorded")

    # ── Calculate contribution fee from admin config ──
    ajo_cfg_doc = await db.settings.find_one({"key": "ajo_config"})
    ajo_cfg = (ajo_cfg_doc or {}).get("value", {})
    fee_type = str(ajo_cfg.get("contribution_fee_type", "flat")).lower()
    fee_value = float(ajo_cfg.get("contribution_fee_value", 0.0))
    if fee_type == "percentage":
        fee_kobo = int(round(amt * fee_value / 100))
    else:
        fee_kobo = int(fee_value * 100)
    total_debit = amt + fee_kobo

    # ── Dual balance check: Bompay wallet AND Safe Haven virtual account ──────
    pre_wallet = await db.wallets.find_one({"user_id": user["_id"]})
    if not pre_wallet or pre_wallet.get("available_balance", 0) < total_debit:
        raise HTTPException(400,
            f"Insufficient balance. You need ₦{total_debit/100:,.2f} "
            f"(₦{group['contribution_amount']:,.2f} contribution + ₦{fee_kobo/100:,.2f} fee)"
        )
    sh_id = pre_wallet.get("sh_account_id", "")
    if sh_id:
        try:
            sh_bal = await get_sh_subaccount_balance(sh_id)
            if sh_bal * 100 < total_debit:
                raise HTTPException(400, f"Insufficient balance. Available: ₦{sh_bal:,.2f}")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"[Ajo] SH balance check failed (non-fatal): {e}")
    # ─────────────────────────────────────────────────────────────────────────
    # Atomic wallet deduction
    wallet = await db.wallets.find_one_and_update(
        {"user_id": user["_id"], "available_balance": {"$gte": total_debit}},
        {"$inc": {"available_balance": -total_debit, "ledger_balance": -total_debit}},
        return_document=True
    )
    if not wallet:
        contrib_ngn = group["contribution_amount"]
        fee_ngn = fee_kobo / 100
        total_ngn = total_debit / 100
        raise HTTPException(400,
            f"Insufficient balance. You need ₦{total_ngn:,.2f} "
            f"(₦{contrib_ngn:,.2f} contribution + ₦{fee_ngn:,.2f} fee)"
        )
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.transactions.insert_one({
        "transaction_id": txn_id, "user_id": user["_id"],
        "type": "AJO_CONTRIBUTION", "direction": "DEBIT",
        "amount": amt, "fee": fee_kobo, "vat": 0,
        "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
        "description": f"Ajo contribution — {group['name']}",
        "metadata": {
            "group_id": group_id, "period_index": period_idx,
            "round": group["current_round"],
            "contribution_fee_kobo": fee_kobo,
            "contribution_fee_type": fee_type,
        },
        "idempotency_key": idem, "created_at": now_iso, "updated_at": now_iso
    })
    due_date = _period_due_date(group["start_date"], period_idx, group["frequency"]).isoformat()
    if existing:
        await db.ajo_contributions.update_one(
            {"contribution_id": existing["contribution_id"]},
            {"$set": {"status": "PAID", "paid_at": now_iso, "transaction_id": txn_id, "days_overdue": 0}}
        )
    else:
        await db.ajo_contributions.insert_one({
            "contribution_id": str(uuid.uuid4()), "group_id": group_id, "user_id": user["_id"],
            "round": group["current_round"], "period_index": period_idx, "due_date": due_date,
            "amount": amt, "status": "PAID", "paid_at": now_iso, "transaction_id": txn_id,
            "days_overdue": 0, "idempotency_key": idem
        })
    # Reset consecutive default days
    await db.ajo_members.update_one({"group_id": group_id, "user_id": user["_id"]},
                                    {"$set": {"consecutive_default_days": 0}})
    # SH sweep of contribution amount → AJO service bucket (best-effort)
    try:
        sh_ajo_acct = await get_service_bucket_account("AJO")
        if not sh_ajo_acct:
            savings_cfg = await db.config.find_one({"key": "savings_config"})
            sh_ajo_acct = (savings_cfg or {}).get("value", {}).get("savings_sh_account", "")
        user_sh = (wallet or {}).get("sh_account_number", "")
        if sh_ajo_acct and user_sh:
            await call_sh("POST", "/transfers", body={
                "debitAccountNumber": user_sh,
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": sh_ajo_acct,
                "amount": group["contribution_amount"], "saveBeneficiary": False,
                "narration": f"Ajo contribution — {group['name']}",
                "paymentReference": txn_id
            })
        else:
            logger.info(f"[Ajo] No AJO SH bucket configured — contribution tracked internally only")
    except Exception as e:
        logger.warning(f"[Ajo] SH contribution sweep failed for {txn_id}: {e}")
    # ── Sweep contribution fee to AJO_CONTRIBUTION_FEES charge account (best-effort) ──
    if fee_kobo > 0:
        asyncio.create_task(_sweep_ajo_contribution_fee(txn_id, user_sh, fee_kobo, group["name"]))
    # Check if all members paid this period → create payout record
    paid_count = await db.ajo_contributions.count_documents({
        "group_id": group_id, "round": group["current_round"], "period_index": period_idx, "status": "PAID"
    })
    total_members = await db.ajo_members.count_documents({"group_id": group_id, "status": {"$ne": "LEFT"}})
    if paid_count >= total_members:
        payout_order = group.get("payout_order", [])
        if len(payout_order) > period_idx:
            recipient_id = payout_order[period_idx]
            existing_payout = await db.ajo_payouts.find_one(
                {"group_id": group_id, "round": group["current_round"], "period_index": period_idx})
            if not existing_payout:
                payout_amount = group["contribution_amount"] * total_members
                await db.ajo_payouts.insert_one({
                    "payout_id": str(uuid.uuid4()), "group_id": group_id,
                    "round": group["current_round"], "period_index": period_idx,
                    "recipient_user_id": recipient_id, "amount": payout_amount,
                    "status": "PENDING", "claimed_at": None, "transaction_id": None
                })
                await notify(recipient_id, "Your Ajo Collection is Ready!",
                             f"₦{payout_amount:,.2f} is ready to collect from '{group['name']}'!", "success")
                asyncio.create_task(send_event_notification(recipient_id, "AJO_PAYOUT_READY", {
                    "amount": payout_amount, "group": group["name"]
                }))
                asyncio.create_task(send_event_sms(recipient_id, "AJO_PAYOUT_READY", {
                    "amount": payout_amount / 100, "group": group["name"]
                }))


async def _sweep_ajo_contribution_fee(txn_id: str, user_sh: str, fee_kobo: int, group_name: str) -> None:
    """Sweep Ajo contribution fee to AJO_CONTRIBUTION_FEES charge account (best-effort)."""
    if fee_kobo <= 0:
        return
    fee_ngn = fee_kobo / 100
    category = "AJO_CONTRIBUTION_FEES"
    fee_txn_id = f"FEE{txn_id}"
    try:
        charge_doc = await db.charge_accounts.find_one({"category": category})
        charge_acct_num = (charge_doc or {}).get("sh_account_number", "").strip()
        now_iso = datetime.now(timezone.utc).isoformat()
        # Record fee sweep transaction (platform-side accounting)
        await db.transactions.insert_one({
            "transaction_id": fee_txn_id, "user_id": "PLATFORM",
            "type": "FEE_SWEEP", "direction": "CREDIT",
            "amount": fee_kobo, "fee": 0, "currency": "NGN",
            "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"Ajo contribution fee — {group_name}",
            "metadata": {"source_txn": txn_id, "category": category, "charge_account": charge_acct_num},
            "created_at": now_iso, "updated_at": now_iso,
        })
        # Update cumulative balance on charge account
        await db.charge_accounts.update_one(
            {"category": category},
            {"$inc": {"total_swept_kobo": fee_kobo},
             "$set": {"updated_at": now_iso}},
            upsert=True
        )
        # If charge account has an SH account and user has SH account, do real bank transfer
        if charge_acct_num and user_sh:
            try:
                await call_sh("POST", "/transfers", body={
                    "debitAccountNumber": user_sh,
                    "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                    "beneficiaryAccountNumber": charge_acct_num,
                    "amount": fee_ngn,
                    "saveBeneficiary": False,
                    "narration": f"Ajo fee — {group_name}",
                    "paymentReference": fee_txn_id
                })
                logger.info(f"[AjoFee] SH transfer ₦{fee_ngn:.2f} for {txn_id} → {charge_acct_num}")
            except Exception as sh_err:
                logger.warning(f"[AjoFee] SH transfer failed for {txn_id}: {sh_err} — fee tracked internally")
        logger.info(f"[AjoFee] Swept ₦{fee_ngn:.2f} contribution fee for {txn_id}")
    except Exception as e:
        logger.error(f"[AjoFee] Fee sweep failed for {txn_id}: {e}")

@router.post("/ajo/{group_id}/set-order")
async def ajo_set_order(group_id: str, req: AjoSetOrderReq, request: Request):
    """Creator assigns payout order (CREATOR method)."""
    user = await get_current_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id})
    if not group:
        raise HTTPException(404, "Group not found")
    if group["creator_id"] != user["_id"]:
        raise HTTPException(403, "Only the group creator can set the payout order")
    if group["payout_order_method"] != "CREATOR":
        raise HTTPException(400, "This group uses a different payout order method")
    if group["status"] != "ORDERING":
        raise HTTPException(400, "Payout order can only be set while group is in ORDERING state")
    members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
    member_ids = {m["user_id"] for m in members_raw}
    if set(req.order) != member_ids or len(req.order) != group["max_members"]:
        raise HTTPException(400, "Order must include all members exactly once")
    now_iso = datetime.now(timezone.utc).isoformat()
    for i, uid in enumerate(req.order):
        await db.ajo_members.update_one({"group_id": group_id, "user_id": uid}, {"$set": {"payout_position": i + 1}})
    await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
        "payout_order": req.order, "status": "ACTIVE", "updated_at": now_iso
    }})
    for m_uid in member_ids:
        await notify(m_uid, f"Ajo '{group['name']}' is Active!", "Payout order is set. Contributions start on the start date.", "success")
    return {"message": "Payout order set and group is now active!"}

@router.post("/ajo/{group_id}/bid-slot")
async def ajo_bid_slot(group_id: str, req: AjoBidSlotReq, request: Request):
    """Member claims a payout slot (BIDDING method)."""
    user = await get_current_user(request)
    group = await db.ajo_groups.find_one({"group_id": group_id})
    if not group:
        raise HTTPException(404, "Group not found")
    if group["payout_order_method"] != "BIDDING":
        raise HTTPException(400, "This group does not use bidding")
    if group["status"] != "ORDERING":
        raise HTTPException(400, "Slot selection is only available while group is in ORDERING state")
    member = await db.ajo_members.find_one({"group_id": group_id, "user_id": user["_id"]})
    if not member or member["status"] != "ACTIVE":
        raise HTTPException(403, "Not an active member")
    if member.get("payout_position") is not None:
        raise HTTPException(409, f"You already have slot #{member['payout_position']}")
    if not (1 <= req.position <= group["max_members"]):
        raise HTTPException(400, f"Position must be between 1 and {group['max_members']}")
    # Check slot availability (atomic)
    taken = await db.ajo_members.find_one({"group_id": group_id, "payout_position": req.position})
    if taken:
        raise HTTPException(409, f"Slot #{req.position} is already taken")
    await db.ajo_members.update_one({"group_id": group_id, "user_id": user["_id"]}, {"$set": {"payout_position": req.position}})
    # Check if all slots are filled
    members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"payout_position": 1, "user_id": 1}).to_list(50)
    all_filled = all(m.get("payout_position") is not None for m in members_raw)
    now_iso = datetime.now(timezone.utc).isoformat()
    if all_filled:
        ordered_ids = [m["user_id"] for m in sorted(members_raw, key=lambda x: x["payout_position"])]
        await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
            "payout_order": ordered_ids, "status": "ACTIVE", "updated_at": now_iso
        }})
        for m_uid in [m["user_id"] for m in members_raw]:
            await notify(m_uid, f"Ajo '{group['name']}' is Active!", "All slots claimed! Contributions start on the start date.", "success")
    return {"message": f"Slot #{req.position} claimed!", "position": req.position, "group_active": all_filled}

@router.post("/ajo/{group_id}/collect")
async def ajo_collect(group_id: str, req: AjoContributeReq, request: Request):
    """Recipient claims their Ajo payout."""
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    payout = await db.ajo_payouts.find_one(
        {"group_id": group_id, "recipient_user_id": user["_id"], "status": "PENDING"})
    if not payout:
        raise HTTPException(404, "No pending payout found for you in this group")
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Group not found")
    amt = int(payout["amount"] * 100)
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    # Credit wallet
    await db.wallets.update_one({"user_id": user["_id"]}, {"$inc": {"available_balance": amt, "ledger_balance": amt}})
    await db.transactions.insert_one({
        "transaction_id": txn_id, "user_id": user["_id"],
        "type": "AJO_PAYOUT", "direction": "CREDIT", "amount": amt, "fee": 0, "vat": 0,
        "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
        "description": f"Ajo payout — {group['name']}",
        "metadata": {"group_id": group_id, "period_index": payout["period_index"], "payout_id": payout["payout_id"]},
        "created_at": now_iso, "updated_at": now_iso
    })
    await db.ajo_payouts.update_one({"payout_id": payout["payout_id"]}, {"$set": {
        "status": "CLAIMED", "claimed_at": now_iso, "transaction_id": txn_id
    }})
    # Check if this was the last payout in the round
    round_payouts_pending = await db.ajo_payouts.count_documents(
        {"group_id": group_id, "round": payout["round"], "status": "PENDING"})
    if round_payouts_pending == 0:
        if group.get("one_round_only", True):
            await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
                "status": "COMPLETED", "updated_at": now_iso
            }, "$inc": {"total_rounds_completed": 1}})
            # Notify all members
            members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
            for m in members_raw:
                await notify(m["user_id"], f"Ajo '{group['name']}' Complete!", "All members have collected. The group is now closed.", "info")
        else:
            # Start new round
            new_round = group.get("current_round", 1) + 1
            await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
                "current_round": new_round, "updated_at": now_iso
            }, "$inc": {"total_rounds_completed": 1}})
            members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
            for m in members_raw:
                await notify(m["user_id"], f"Ajo '{group['name']}' — Round {new_round} Starts!", "A new round of contributions has started.", "info")
    await notify(user["_id"], "Ajo Payout Collected!", f"₦{payout['amount']:,.2f} added to your wallet.", "success")
    # SH sweep: AJO bucket → user's SH account (best-effort)
    try:
        sh_ajo_src = await get_service_bucket_account("AJO")
        user_wallet = await db.wallets.find_one({"user_id": user["_id"]})
        user_sh = (user_wallet or {}).get("sh_account_number", "")
        if sh_ajo_src and user_sh:
            await call_sh("POST", "/transfers", body={
                "debitAccountNumber": sh_ajo_src,
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": user_sh,
                "amount": payout["amount"], "saveBeneficiary": False,
                "narration": f"Ajo payout — {group['name']}",
                "paymentReference": txn_id
            })
        else:
            logger.info(f"[Ajo] No AJO SH bucket configured — payout tracked internally only")
    except Exception as e:
        logger.warning(f"[Ajo] SH payout sweep failed (wallet already credited): {e}")
    return {"message": f"₦{payout['amount']:,.2f} collected successfully!", "transaction_id": txn_id}

@router.post("/ajo/{group_id}/pay-arrears")
async def ajo_pay_arrears(group_id: str, req: AjoContributeReq, request: Request):
    """Member pays all outstanding contributions + defaulter fees to resume a paused group."""
    user = await get_current_user(request)
    await verify_transaction_pin(user["_id"], req.transaction_pin)
    group = await db.ajo_groups.find_one({"group_id": group_id}, {"_id": 0})
    if not group:
        raise HTTPException(404, "Group not found")
    if group["status"] != "PAUSED":
        raise HTTPException(400, "Group is not paused")
    member = await db.ajo_members.find_one({"group_id": group_id, "user_id": user["_id"]})
    if not member or member["status"] != "ACTIVE":
        raise HTTPException(403, "Not an active member")
    # Collect all DUE/DEFAULTED contributions for this member
    due_contribs = await db.ajo_contributions.find({
        "group_id": group_id, "user_id": user["_id"], "status": {"$in": ["DUE", "DEFAULTED"]}
    }, {"_id": 0}).to_list(50)
    # Calculate total: missed contributions + accumulated fees
    total_contributions = sum(c["amount"] for c in due_contribs)
    total_fees = sum(c.get("days_overdue", 0) * int(group.get("defaulter_fee_amount", 200) * 100) for c in due_contribs)
    total_due = total_contributions + total_fees
    if total_due == 0:
        # No arrears — mark member as cleared
        await db.ajo_members.update_one({"group_id": group_id, "user_id": user["_id"]},
                                        {"$set": {"consecutive_default_days": 0}})
    else:
        wallet = await db.wallets.find_one_and_update(
            {"user_id": user["_id"], "available_balance": {"$gte": total_due}},
            {"$inc": {"available_balance": -total_due, "ledger_balance": -total_due}},
            return_document=True
        )
        if not wallet:
            raise HTTPException(400, f"Insufficient balance. You owe ₦{total_due/100:,.2f} (contributions + defaulter fees)")
        txn_id = f"TXN{secrets.token_hex(12).upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        await db.transactions.insert_one({
            "transaction_id": txn_id, "user_id": user["_id"],
            "type": "AJO_ARREARS", "direction": "DEBIT", "amount": total_due, "fee": 0, "vat": 0,
            "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"Ajo arrears payment — {group['name']}",
            "metadata": {"group_id": group_id}, "created_at": now_iso, "updated_at": now_iso
        })
        for c in due_contribs:
            await db.ajo_contributions.update_one({"contribution_id": c["contribution_id"]},
                                                   {"$set": {"status": "PAID", "paid_at": now_iso, "transaction_id": txn_id, "days_overdue": 0}})
        await db.ajo_members.update_one({"group_id": group_id, "user_id": user["_id"]},
                                        {"$set": {"consecutive_default_days": 0}})
    # Resume group
    await db.ajo_groups.update_one({"group_id": group_id}, {"$set": {
        "status": "ACTIVE", "pause_reason": None, "paused_at": None,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }})
    members_raw = await db.ajo_members.find({"group_id": group_id, "status": {"$ne": "LEFT"}}, {"user_id": 1}).to_list(50)
    for m in members_raw:
        await notify(m["user_id"], f"Ajo '{group['name']}' Resumed!", "All arrears have been settled. Contributions continue.", "success")
    return {"message": "Arrears paid. Group has resumed.", "total_paid": total_due / 100}

# ===== ADMIN =====
