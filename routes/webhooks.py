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

@router.post("/webhooks/safehaven")
async def safehaven_webhook(request: Request):
    event = await request.json()
    event_type = event.get("eventType") or event.get("type", "")
    data = event.get("data", {})
    eid = data.get("_id") or str(uuid.uuid4())

    # Idempotent store
    await db.webhooks.update_one({"event_id": eid},
        {"$setOnInsert": {"event_id": eid, "event": event, "event_type": event_type,
                          "received_at": datetime.now(timezone.utc).isoformat()}}, upsert=True)

    # ── Incoming credit to user virtual account ───────────────────────
    if event_type in ("account.credit", "virtualAccount.transfer"):
        credit_acct_num = data.get("creditAccountNumber")
        amount = float(data.get("amount", 0))
        status = data.get("status", "")
        response_code = data.get("responseCode", "")
        session_id = data.get("sessionId") or data.get("paymentReference") or eid
        if (status == "Completed" or response_code == "00") and not data.get("isReversed") and amount > 0 and credit_acct_num:
            wallet = await db.wallets.find_one({"sh_account_number": credit_acct_num})
            if wallet:
                dup = await db.transactions.find_one({"provider_reference": session_id})
                if not dup:
                    amt_kobo = int(amount * 100)
                    txn_id = f"TXN{secrets.token_hex(12).upper()}"
                    debit_name = data.get("debitAccountName", "External Transfer")
                    narration = data.get("narration") or f"Transfer from {debit_name}"
                    w_before = await get_wallet(wallet["user_id"])
                    bal_before = w_before["available_balance"]
                    await db.transactions.insert_one({
                        "transaction_id": txn_id, "user_id": wallet["user_id"],
                        "type": "WALLET_FUNDING", "direction": "CREDIT", "amount": amt_kobo,
                        "fee": int(float(data.get("fees", 0)) * 100), "vat": 0, "currency": "NGN",
                        "status": "COMPLETED", "provider": "SAFEHAVEN",
                        "description": narration,
                        "provider_reference": session_id,
                        "metadata": {"event_type": event_type, "debit_account": data.get("debitAccountNumber"), "debit_name": debit_name},
                        "balance_before_kobo": bal_before,
                        "balance_after_kobo": bal_before + amt_kobo,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    })
                    await db.wallets.update_one({"user_id": wallet["user_id"]},
                        {"$inc": {"available_balance": amt_kobo, "ledger_balance": amt_kobo}})
                    w = await get_wallet(wallet["user_id"])
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
                                 f"₦{amount:,.2f} received from {debit_name}. New balance: ₦{(w['available_balance']/100):,.2f}", "success")
                    asyncio.create_task(send_event_notification(wallet["user_id"], "TRANSFER_CREDIT", {
                        "amount": amount, "sender": debit_name, "balance": w["available_balance"] / 100
                    }))
                    asyncio.create_task(_complete_epos_txn_bg(wallet["user_id"], amt_kobo, "BANK"))

    # ── Transfer reversal (Safe Haven reversed an outgoing transfer) ──
    elif event_type in ("transfer.reversal", "transfer.reversed", "debit.reversal", "account.debit.reversal"):
        await _handle_sh_transfer_reversal(data, eid)

    # ── Transfer failed (async failure after initial accept) ─────────
    elif event_type in ("transfer.failed", "transfer.declined"):
        await _handle_sh_transfer_failure(data, eid)

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


