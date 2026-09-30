"""Bompay — Transactions routes."""
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
    vas_debit, vas_complete, vas_refund,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/transactions")
async def get_transactions(request: Request, page: int = 1, limit: int = 20,
                            txn_type: str = None, txn_status: str = None):
    user = await get_current_user(request)
    # BALANCE_ADJUSTMENT is an admin-only internal correction — never visible to users
    query: dict = {"user_id": user["_id"], "type": {"$ne": "BALANCE_ADJUSTMENT"}}
    if txn_type:
        query["type"] = txn_type
    if txn_status:
        query["status"] = txn_status
    skip = (page - 1) * limit
    txns = await db.transactions.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.transactions.count_documents(query)
    return {"transactions": txns, "total": total, "page": page, "limit": limit}

@router.get("/transactions/{txn_id}")
async def get_transaction(txn_id: str, request: Request):
    user = await get_current_user(request)
    txn = await db.transactions.find_one({"transaction_id": txn_id, "user_id": user["_id"]}, {"_id": 0})
    if not txn:
        raise HTTPException(404, "Transaction not found")
    return txn

@router.get("/transactions/export/csv")
async def export_transactions_csv(request: Request, txn_type: str = None):
    user = await get_current_user(request)
    query = {"user_id": user["_id"]}
    if txn_type:
        query["type"] = txn_type
    txns = await db.transactions.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Reference", "Type", "Description", "Direction", "Amount (₦)", "Fee (₦)", "Status", "Provider"])
    for t in txns:
        writer.writerow([
            t.get("created_at", "")[:10],
            t.get("transaction_id", ""),
            t.get("type", "").replace("_", " "),
            t.get("description", ""),
            t.get("direction", ""),
            f"{t.get('amount', 0) / 100:.2f}",
            f"{t.get('fee', 0) / 100:.2f}",
            t.get("status", ""),
            t.get("provider", ""),
        ])
    output.seek(0)
    fname = f"bompay_transactions_{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )

@router.get("/transactions/export/pdf")
async def export_transactions_pdf(request: Request, txn_type: str = None):
    user = await get_current_user(request)
    query = {"user_id": user["_id"]}
    if txn_type:
        query["type"] = txn_type
    txns = await db.transactions.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "BOMPAY - Transaction History", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).strftime('%d %b %Y')}  |  Account: {user.get('first_name','')} {user.get('last_name','')}", ln=True, align="C")
    pdf.ln(4)

    # Table header
    pdf.set_fill_color(6, 75, 203)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    cols = [("Date", 22), ("Reference", 42), ("Type", 32), ("Direction", 20), ("Amount (NGN)", 30), ("Status", 24)]
    for col, w in cols:
        pdf.cell(w, 7, col, border=1, fill=True)
    pdf.ln()

    # Rows
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(30, 30, 30)
    for i, t in enumerate(txns):
        fill = i % 2 == 0
        pdf.set_fill_color(238, 244, 255) if fill else pdf.set_fill_color(255, 255, 255)
        amt = f"{t.get('amount', 0) / 100:,.2f}"
        row = [
            t.get("created_at", "")[:10],
            t.get("transaction_id", "")[:20],
            t.get("type", "").replace("_", " ")[:18],
            t.get("direction", ""),
            amt,
            t.get("status", ""),
        ]
        widths = [22, 42, 32, 20, 30, 24]
        for val, w in zip(row, widths):
            pdf.cell(w, 6, str(val), border=1, fill=fill)
        pdf.ln()

    buf = io.BytesIO(pdf.output())
    fname = f"bompay_transactions_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )

