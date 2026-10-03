"""Bompay — Webhooks routes."""
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
    # fee helpers
    calculate_nip_inward_commission,
    # SH balance helper
    get_sh_subaccount_balance,
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
    _complete_epos_txn_bg,
    _handle_sh_transfer_reversal,
    _handle_sh_transfer_failure,
)

import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)


async def _track_nip_inward_cost(txn_id: str, user_id: str, amount_ngn: float):
    """Track NIP Inward Commission cost absorbed by Bompay for nightly auto-balance."""
    try:
        cost_ngn = await calculate_nip_inward_commission(amount_ngn)
        if cost_ngn <= 0:
            return
        await db.nip_inward_costs.insert_one({
            "txn_id": txn_id,
            "user_id": user_id,
            "amount_ngn": amount_ngn,
            "cost_ngn": cost_ngn,
            "cost_kobo": int(cost_ngn * 100),
            "status": "PENDING_BALANCE",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        # Flag on the transaction record for user visibility
        await db.transactions.update_one(
            {"transaction_id": txn_id},
            {"$set": {"metadata.nip_inward_cost_kobo": int(cost_ngn * 100)}}
        )
        logger.info(f"[NIPInward] tracked ₦{cost_ngn:.2f} cost for txn={txn_id}")
    except Exception as e:
        logger.error(f"[NIPInward] failed to track cost for {txn_id}: {e}")

@router.post("/webhooks/safehaven")
async def safehaven_webhook(request: Request):
    event = await request.json()
    event_type = event.get("eventType") or event.get("type", "")
    data = event.get("data", {})
    eid = data.get("_id") or str(uuid.uuid4())

    # ── Full payload log ──────────────────────────────────────────────
    logger.info(f"[SH-WEBHOOK] eventType={event_type!r} eid={eid} "
                f"acct={data.get('creditAccountNumber')} amt={data.get('amount')} "
                f"status={data.get('status')!r} sessionId={data.get('sessionId')}")

    # ── Idempotent store ──────────────────────────────────────────────
    await db.webhooks.update_one({"event_id": eid},
        {"$setOnInsert": {"event_id": eid, "event": event, "event_type": event_type,
                          "received_at": datetime.now(timezone.utc).isoformat()}}, upsert=True)

    # ── Forward to production server (Safe Haven callbackUrl still points here) ──
    prod_url = os.environ.get("WEBHOOK_FORWARD_URL", "")
    if prod_url:
        try:
            async with httpx.AsyncClient(timeout=8) as fwd:
                fwd_r = await fwd.post(f"{prod_url}/api/webhooks/safehaven",
                                       json=event,
                                       headers={"Content-Type": "application/json",
                                                "X-Forwarded-From": "bompay-preview"})
                logger.info(f"[SH-WEBHOOK] Forwarded to {prod_url} → {fwd_r.status_code}")
        except Exception as fe:
            logger.warning(f"[SH-WEBHOOK] Forward failed: {fe}")

    # ── Incoming credit to user virtual account ───────────────────────
    # Safe Haven sends eventType="account.credit" OR type="virtualAccount.transfer"
    credit_events = {"account.credit", "virtualaccount.transfer", "virtualAccount.transfer",
                     "account_credit", "credit", "wallet.credit"}
    if event_type.lower() in {e.lower() for e in credit_events}:
        credit_acct_num = data.get("creditAccountNumber")
        amount_raw = data.get("amount", 0)
        try:
            amount = float(amount_raw)
        except (TypeError, ValueError):
            amount = 0.0
        status = (data.get("status") or "").strip()
        response_code = (data.get("responseCode") or data.get("responseCode") or "").strip()
        session_id = data.get("sessionId") or data.get("paymentReference") or eid

        # Accept "Completed", "completed", "SUCCESS", "success", or responseCode "00"
        is_success = status.lower() in ("completed", "success", "successful") or response_code == "00"

        logger.info(f"[SH-WEBHOOK] credit branch: acct={credit_acct_num} amt={amount} "
                    f"is_success={is_success} isReversed={data.get('isReversed')}")

        if is_success and not data.get("isReversed") and amount > 0 and credit_acct_num:
            wallet = await db.wallets.find_one({"sh_account_number": credit_acct_num})
            logger.info(f"[SH-WEBHOOK] wallet lookup for {credit_acct_num}: found={wallet is not None}")
            if wallet:
                dup = await db.transactions.find_one({"provider_reference": session_id})
                if not dup:
                    amt_kobo = int(amount * 100)
                    txn_id = f"TXN{secrets.token_hex(12).upper()}"
                    # Safe Haven sends either debitAccountName or senderName
                    debit_name = (data.get("debitAccountName") or data.get("senderName")
                                  or data.get("debitName") or "External Transfer")
                    narration = data.get("narration") or f"Transfer from {debit_name}"
                    w_before = await get_wallet(wallet["user_id"])
                    bal_before = w_before["available_balance"]
                    await db.transactions.insert_one({
                        "transaction_id": txn_id, "user_id": wallet["user_id"],
                        "type": "WALLET_FUNDING", "direction": "CREDIT", "amount": amt_kobo,
                        "fee": int(float(data.get("fees", 0) or data.get("fee", 0)) * 100),
                        "vat": 0, "currency": "NGN",
                        "status": "COMPLETED", "provider": "SAFEHAVEN",
                        "description": narration,
                        "provider_reference": session_id,
                        "metadata": {"event_type": event_type,
                                     "debit_account": data.get("debitAccountNumber"),
                                     "debit_name": debit_name},
                        "balance_before_kobo": bal_before,
                        "balance_after_kobo": bal_before + amt_kobo,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    })
                    await db.wallets.update_one({"user_id": wallet["user_id"]},
                        {"$inc": {"available_balance": amt_kobo, "ledger_balance": amt_kobo}})
                    w = await get_wallet(wallet["user_id"])
                    # Use live SH balance in notification (primary account)
                    sh_id_w = wallet.get("sh_account_id")
                    notif_balance = w["available_balance"] / 100  # shadow fallback
                    if sh_id_w:
                        try:
                            notif_balance = await get_sh_subaccount_balance(sh_id_w)
                        except Exception:
                            pass  # keep shadow fallback
                    await ledger_entry(wallet["user_id"], w["_id"], txn_id, "CREDIT", amt_kobo, narration)
                    try:
                        user_doc = await db.users.find_one({"_id": ObjectId(wallet["user_id"])})
                        uname = f"{(user_doc or {}).get('first_name','')} {(user_doc or {}).get('last_name','')}".strip()
                        await pg_ledger.record_wallet_funding(
                            user_id=wallet["user_id"], user_name=uname,
                            amount_ngn=amount, reference=txn_id, mongo_txn_id=txn_id
                        )
                    except Exception as le:
                        logger.error(f"[Ledger] webhook credit mirror failed: {le}")
                    await notify(wallet["user_id"], "Credit Alert",
                                 f"₦{amount:,.2f} received from {debit_name}. New balance: ₦{notif_balance:,.2f}", "success")
                    asyncio.create_task(send_event_notification(wallet["user_id"], "TRANSFER_CREDIT", {
                        "amount": amount, "sender": debit_name, "balance": notif_balance
                    }))
                    asyncio.create_task(_complete_epos_txn_bg(wallet["user_id"], amt_kobo, "BANK"))
                    # ── Track NIP Inward Commission (absorbed by Bompay, NOT deducted from user) ──
                    asyncio.create_task(_track_nip_inward_cost(txn_id, wallet["user_id"], amount))
                    logger.info(f"[SH-WEBHOOK] ✅ credited ₦{amount} to user {wallet['user_id']} txn={txn_id}")
                else:
                    logger.info(f"[SH-WEBHOOK] duplicate skipped session_id={session_id}")
            else:
                logger.warning(f"[SH-WEBHOOK] ⚠️ no wallet found for creditAccountNumber={credit_acct_num!r}")
                # ── Check if this is a business sub-account credit ─────────────
                biz = await db.businesses.find_one(
                    {"sh_account_number": credit_acct_num, "status": "active"}
                )
                if biz:
                    biz_id = str(biz["_id"])
                    dup = await db.transactions.find_one(
                        {"provider_reference": session_id, "business_id": biz_id}
                    )
                    if not dup:
                        amt_kobo = int(amount * 100)
                        biz_txn_id = f"BTXN{secrets.token_hex(12).upper()}"
                        debit_name = (data.get("debitAccountName") or data.get("senderName")
                                      or data.get("debitName") or "External Transfer")
                        narration = data.get("narration") or f"Transfer from {debit_name}"

                        await db.transactions.insert_one({
                            "transaction_id": biz_txn_id,
                            "business_id": biz_id,
                            "user_id": biz.get("owner_id", ""),
                            "type": "WALLET_FUNDING", "direction": "CREDIT", "amount": amt_kobo,
                            "fee": 0, "vat": 0, "currency": "NGN",
                            "status": "COMPLETED", "provider": "SAFEHAVEN",
                            "description": narration,
                            "provider_reference": session_id,
                            "metadata": {"event_type": event_type,
                                         "debit_account": data.get("debitAccountNumber"),
                                         "debit_name": debit_name},
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "updated_at": datetime.now(timezone.utc).isoformat(),
                        })
                        await db.business_wallets.update_one(
                            {"business_id": biz_id},
                            {"$inc": {"available_balance": amt_kobo, "ledger_balance": amt_kobo}},
                            upsert=True,
                        )
                        owner_id = biz.get("owner_id", "")
                        biz_name = biz.get("name", "Your Business")
                        if owner_id:
                            await notify(owner_id, f"Business Credit — {biz_name}",
                                         f"₦{amount:,.2f} received into {biz_name} from {debit_name}.", "success")
                            # Live SH balance for business account
                            biz_sh_bal = None
                            biz_sh_id = biz.get("sh_subaccount_id")
                            if biz_sh_id:
                                try:
                                    biz_sh_bal = await get_sh_subaccount_balance(biz_sh_id)
                                except Exception:
                                    pass
                            if biz_sh_bal is None:
                                biz_w = await db.business_wallets.find_one({"business_id": biz_id}) or {}
                                biz_sh_bal = biz_w.get("available_balance", 0) / 100
                            # SMS + email to business owner on inbound credit
                            asyncio.create_task(send_event_sms(owner_id, "BUSINESS_TRANSFER_CREDIT", {
                                "amount": amount, "sender_biz": debit_name,
                                "ref": session_id,
                                "balance": biz_sh_bal,
                            }))
                            async def _send_biz_credit_email(oid=owner_id, bn=biz_name, amt=amount, dn=debit_name, sid=session_id):
                                try:
                                    owner_doc = await db.users.find_one({"_id": ObjectId(oid)})
                                    owner_email = (owner_doc or {}).get("email", "")
                                    owner_name  = f"{(owner_doc or {}).get('first_name','')} {(owner_doc or {}).get('last_name','')}".strip() or "Customer"
                                    if owner_email:
                                        html = _email_html(
                                            f"Business Credit — ₦{amt:,.2f}",
                                            [
                                                f"Hi {owner_name}, your business <strong>{bn}</strong> received a credit.",
                                                f"Amount: <strong>₦{amt:,.2f}</strong> from <strong>{dn}</strong>",
                                                f"Reference: {sid}",
                                            ],
                                            "Log in to BOMPAY Business to view your balance and transactions."
                                        )
                                        await send_email(to=owner_email, subject=f"[BOMPAY] Business Credit — {bn}", html=html)
                                except Exception as ex:
                                    logger.warning(f"[BIZ-CREDIT-EMAIL] {ex}")
                            asyncio.create_task(_send_biz_credit_email())
                        logger.info(f"[SH-WEBHOOK] ✅ business credit ₦{amount} → {biz_name} ({biz_id})")
                    else:
                        logger.info(f"[SH-WEBHOOK] business duplicate skipped session_id={session_id}")
                else:
                    logger.warning(f"[SH-WEBHOOK] ⚠️ no business found for account={credit_acct_num!r}")
        else:
            logger.info(f"[SH-WEBHOOK] credit conditions not met: is_success={is_success} "
                        f"isReversed={data.get('isReversed')} amount={amount} acct={credit_acct_num}")

    # ── Transfer reversal ─────────────────────────────────────────────
    elif event_type.lower() in ("transfer.reversal", "transfer.reversed", "debit.reversal",
                                "account.debit.reversal"):
        await _handle_sh_transfer_reversal(data, eid)

    # ── Transfer failed ───────────────────────────────────────────────
    elif event_type.lower() in ("transfer.failed", "transfer.declined"):
        await _handle_sh_transfer_failure(data, eid)

    else:
        logger.warning(f"[SH-WEBHOOK] unhandled eventType={event_type!r} — full event: {json.dumps(event)[:500]}")

    return {"received": True}

# ===== PAIRGATE WEBHOOK =====
@router.post("/webhooks/pairgate")
async def pairgate_webhook(request: Request):
    """Receive async PairGate electricity token (pin) via webhook and update transaction."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    logger.info(f"[PG] webhook received: event={payload.get('event')} ref={payload.get('reference_code')} status={payload.get('status')}")
    event = payload.get("event", "")
    pg_status = payload.get("status", "")
    # PairGate reference_code echoes back what we sent as "reference" in the purchase request (our txn_id)
    ref = payload.get("reference_code", payload.get("reference", ""))
    pin = payload.get("pin", "")

    if pin and pg_status in ("successful", "success") and ref:
        # Match by provider_reference (PairGate ref we stored) OR our txn_id (which we sent as reference)
        txn = await db.transactions.find_one(
            {"$or": [{"provider_reference": ref}, {"transaction_id": ref}, {"metadata.pg_ref": ref}]}
        )
        if txn and txn.get("metadata", {}).get("token") in (None, "", "N/A"):
            user_id = txn.get("user_id", "")
            meter = txn.get("metadata", {}).get("meter_number", "")
            units = txn.get("metadata", {}).get("units", "")
            await db.transactions.update_one(
                {"transaction_id": txn["transaction_id"]},
                {"$set": {"metadata.token": pin}}
            )
            logger.info(f"[PG] webhook: token '{pin}' stored for txn {txn['transaction_id']}")
            # Send SMS with the token now that it's available
            asyncio.create_task(send_event_sms(user_id, "ELECTRICITY", {
                "token": pin, "units": units, "meter": meter
            }))
    return {"received": True}


