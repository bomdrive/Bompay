"""Bompay — Support routes."""
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
from pydantic import BaseModel
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
    SupportMessageReq, AdminReplyReq, get_savings_config,
)
import ledger as pg_ledger

router = APIRouter()
logger = logging.getLogger(__name__)


# ─── Guest (unauthenticated) chat endpoints ─────────────────────────────────

class GuestChatStartReq(BaseModel):
    name: str
    phone: str
    message: str

class GuestChatMessageReq(BaseModel):
    message: str

@router.post("/support/guest-chat/start")
async def guest_chat_start(req: GuestChatStartReq):
    """Create a support ticket from an unauthenticated guest visitor."""
    if not req.name.strip() or not req.phone.strip() or not req.message.strip():
        raise HTTPException(400, "name, phone, and message are required")
    ticket_id = f"TICKET-{uuid.uuid4().hex[:10].upper()}"
    session_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()
    await db.support_tickets.insert_one({
        "ticket_id":     ticket_id,
        "user_id":       None,
        "user_type":     "GUEST",
        "guest_name":    req.name.strip(),
        "guest_phone":   req.phone.strip(),
        "subject":       f"Guest enquiry from {req.name.strip()}",
        "status":        "OPEN",
        "session_token": session_token,
        "unread_admin":  1,
        "unread_user":   0,
        "created_at":    now,
        "updated_at":    now,
    })
    await db.support_messages.insert_one({
        "ticket_id":   ticket_id,
        "sender":      "USER",
        "sender_name": req.name.strip(),
        "message":     req.message.strip(),
        "created_at":  now,
    })
    return {"ticket_id": ticket_id, "session_token": session_token}


@router.get("/support/guest-chat/{ticket_id}")
async def guest_chat_get(ticket_id: str, token: str):
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id, "user_type": "GUEST"})
    if not ticket or ticket.get("session_token") != token:
        raise HTTPException(403, "Invalid session")
    msgs = await db.support_messages.find(
        {"ticket_id": ticket_id}, {"_id": 0}
    ).sort("created_at", 1).to_list(100)
    # Mark admin messages as read
    await db.support_tickets.update_one({"ticket_id": ticket_id}, {"$set": {"unread_user": 0}})
    return {"messages": msgs, "status": ticket.get("status"), "guest_name": ticket.get("guest_name")}


@router.post("/support/guest-chat/{ticket_id}/message")
async def guest_chat_send(ticket_id: str, req: GuestChatMessageReq, token: str):
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id, "user_type": "GUEST"})
    if not ticket or ticket.get("session_token") != token:
        raise HTTPException(403, "Invalid session")
    if ticket.get("status") == "CLOSED":
        raise HTTPException(400, "This conversation is closed")
    now = datetime.now(timezone.utc).isoformat()
    await db.support_messages.insert_one({
        "ticket_id":   ticket_id,
        "sender":      "USER",
        "sender_name": ticket.get("guest_name", "Guest"),
        "message":     req.message.strip(),
        "created_at":  now,
    })
    await db.support_tickets.update_one(
        {"ticket_id": ticket_id},
        {"$set": {"updated_at": now}, "$inc": {"unread_admin": 1}}
    )
    return {"ok": True}


@router.post("/support/tickets/{ticket_id}/message")
async def user_reply_to_ticket(ticket_id: str, request: Request):
    """Let the owner of a ticket send a follow-up message (reply) on an open dispute."""
    user = await get_current_user(request)
    body = await request.json()
    message = (body.get("message") or "").strip()
    if not message:
        raise HTTPException(400, "Message cannot be empty")
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id, "user_id": user["_id"]})
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if ticket.get("status") == "RESOLVED":
        raise HTTPException(400, "This dispute has been resolved. Please open a new dispute if needed.")
    now_iso = datetime.now(timezone.utc).isoformat()
    msg_doc = {
        "message_id": str(uuid.uuid4()),
        "ticket_id":  ticket_id,
        "sender":     str(user["_id"]),
        "text":       message,
        "created_at": now_iso,
    }
    await db.support_messages.insert_one(msg_doc)
    await db.support_tickets.update_one(
        {"ticket_id": ticket_id},
        {"$set": {"updated_at": now_iso}, "$inc": {"unread_admin": 1}}
    )
    msg_doc.pop("_id", None)
    return {"success": True, "message": msg_doc}


@router.post("/support/send")
async def send_support_message(req: SupportMessageReq, request: Request):
    user = await get_current_user(request)
    if not req.message.strip():
        raise HTTPException(400, "Message cannot be empty")

    # Disputes always create a fresh ticket (never appended to general open ticket)
    if req.ticket_type == "dispute":
        ticket_id = str(uuid.uuid4())
        subject = req.subject or "Card Transaction Dispute"
        await db.support_tickets.insert_one({
            "ticket_id": ticket_id, "user_id": user["_id"],
            "user_name": f"{user.get('first_name','')} {user.get('last_name','')}".strip(),
            "user_email": user.get("email", ""), "status": "OPEN",
            "ticket_type": "dispute", "subject": subject,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "unread_admin": 1, "unread_user": 0,
        })
    else:
        ticket = await db.support_tickets.find_one({"user_id": user["_id"], "status": "OPEN", "ticket_type": {"$ne": "dispute"}})
        if not ticket:
            ticket_id = str(uuid.uuid4())
            await db.support_tickets.insert_one({
                "ticket_id": ticket_id, "user_id": user["_id"],
                "user_name": f"{user.get('first_name','')} {user.get('last_name','')}".strip(),
                "user_email": user.get("email", ""), "status": "OPEN",
                "ticket_type": "general", "subject": req.subject or "Support Request",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "unread_admin": 1, "unread_user": 0
            })
        else:
            ticket_id = ticket["ticket_id"]
            await db.support_tickets.update_one({"ticket_id": ticket_id},
                {"$set": {"updated_at": datetime.now(timezone.utc).isoformat()}, "$inc": {"unread_admin": 1}})

    msg_id = str(uuid.uuid4())
    await db.support_messages.insert_one({
        "message_id": msg_id, "ticket_id": ticket_id, "user_id": user["_id"],
        "sender": "user", "text": req.message.strip(),
        "read": False, "created_at": datetime.now(timezone.utc).isoformat()
    })
    return {"message_id": msg_id, "ticket_id": ticket_id}


@router.get("/support/tickets")
async def list_user_tickets(request: Request, ticket_type: str = ""):
    """List all support tickets for the logged-in user. Optional ?ticket_type=dispute filter."""
    user = await get_current_user(request)
    q: dict = {"user_id": user["_id"]}
    if ticket_type:
        q["ticket_type"] = ticket_type
    tickets = await db.support_tickets.find(q, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"tickets": tickets}

@router.get("/support/messages")
async def get_support_messages(request: Request):
    user = await get_current_user(request)
    ticket = await db.support_tickets.find_one({"user_id": user["_id"], "status": "OPEN"})
    if not ticket:
        return {"ticket_id": None, "status": "no_ticket", "messages": [], "unread": 0}
    msgs = await db.support_messages.find({"ticket_id": ticket["ticket_id"]}, {"_id": 0}).sort("created_at", 1).to_list(200)
    await db.support_messages.update_many(
        {"ticket_id": ticket["ticket_id"], "sender": "admin", "read": False}, {"$set": {"read": True}})
    await db.support_tickets.update_one({"ticket_id": ticket["ticket_id"]}, {"$set": {"unread_user": 0}})
    return {"ticket_id": ticket["ticket_id"], "status": ticket["status"], "messages": msgs, "unread": 0}


# ===== BLOG API =====

@router.get("/support/tickets/{ticket_id}/messages")
async def get_support_ticket_messages(ticket_id: str, request: Request):
    """Return messages for a specific ticket belonging to the current user."""
    user = await get_current_user(request)
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id, "user_id": user["_id"]})
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    msgs = await db.support_messages.find({"ticket_id": ticket_id}, {"_id": 0}).sort("created_at", 1).to_list(200)
    # Reset unread_user count now that user has opened the conversation
    await db.support_tickets.update_one({"ticket_id": ticket_id}, {"$set": {"unread_user": 0}})
    return {
        "messages": msgs,
        "status": ticket.get("status"),
        "ticket_type": ticket.get("ticket_type", "general"),
        "created_at": ticket.get("created_at"),
    }


async def get_support_unread(request: Request):
    user = await get_current_user(request)
    ticket = await db.support_tickets.find_one({"user_id": user["_id"], "status": "OPEN"})
    if not ticket:
        return {"unread": 0}
    count = await db.support_messages.count_documents({"ticket_id": ticket["ticket_id"], "sender": "admin", "read": False})
    return {"unread": count}

@router.get("/admin/support")
async def admin_get_tickets(request: Request, page: int = 1, limit: int = 20, status_filter: str = None):
    await get_admin_user(request)
    query = {}
    if status_filter:
        query["status"] = status_filter
    skip = (page - 1) * limit
    tickets_raw = await db.support_tickets.find(query, {"_id": 0, "session_token": 0}).sort("updated_at", -1).skip(skip).limit(limit).to_list(limit)
    # Surface guest tickets with a clear label
    tickets = []
    for t in tickets_raw:
        if t.get("user_type") == "GUEST":
            t["display_name"] = f"Guest — {t.get('guest_name', 'Unknown')} ({t.get('guest_phone', '')})"
        else:
            t.setdefault("display_name", t.get("user_name", "User"))
        tickets.append(t)
    total = await db.support_tickets.count_documents(query)
    return {"tickets": tickets, "total": total,
            "open_count": await db.support_tickets.count_documents({"status": "OPEN"})}

@router.get("/admin/support/{ticket_id}/messages")
async def admin_get_ticket_messages(ticket_id: str, request: Request):
    await get_admin_user(request)
    msgs = await db.support_messages.find({"ticket_id": ticket_id}, {"_id": 0}).sort("created_at", 1).to_list(200)
    await db.support_messages.update_many(
        {"ticket_id": ticket_id, "sender": "user", "read": False}, {"$set": {"read": True}})
    await db.support_tickets.update_one({"ticket_id": ticket_id}, {"$set": {"unread_admin": 0}})
    return {"messages": msgs}

@router.post("/admin/support/{ticket_id}/reply")
async def admin_reply_ticket(ticket_id: str, req: AdminReplyReq, request: Request):
    await get_admin_user(request)
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id})
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    if not req.message.strip():
        raise HTTPException(400, "Reply cannot be empty")
    msg_id = str(uuid.uuid4())
    await db.support_messages.insert_one({
        "message_id": msg_id, "ticket_id": ticket_id, "user_id": ticket["user_id"],
        "sender": "ADMIN", "message": req.message.strip(), "text": req.message.strip(),
        "sender_name": "Bompay Support",
        "read": False, "created_at": datetime.now(timezone.utc).isoformat()
    })
    await db.support_tickets.update_one({"ticket_id": ticket_id},
        {"$set": {"updated_at": datetime.now(timezone.utc).isoformat()}, "$inc": {"unread_user": 1}})
    if ticket.get("user_id"):
        await notify(ticket["user_id"], "Support Reply", "You have a new reply from Bompay support.", "info")
    return {"message_id": msg_id}

async def _send_dispute_resolution_email(ticket: dict):
    """Send a dispute resolution email when admin closes a dispute ticket."""
    try:
        user_id = ticket.get("user_id")
        if not user_id:
            return
        from bson import ObjectId as _OID
        user = await db.users.find_one({"_id": _OID(user_id)}, {"email": 1, "first_name": 1})
        if not user or not user.get("email"):
            return
        email = user["email"]
        name = user.get("first_name", "Customer")
        subject_ticket = ticket.get("subject", "Card Dispute")
        # Get last admin reply for outcome summary
        last_admin = await db.support_messages.find_one(
            {"ticket_id": ticket["ticket_id"], "sender": {"$in": ["ADMIN", "admin"]}},
            sort=[("created_at", -1)]
        )
        outcome = (last_admin or {}).get("text") or (last_admin or {}).get("message") or \
                  "Your dispute has been reviewed and closed by our team."
        html = _email_html(
            f"Hi {name}, Your Dispute Has Been Resolved",
            [
                ("Reference", ticket["ticket_id"][:8].upper()),
                ("Subject", subject_ticket),
                ("Status", "RESOLVED"),
                ("Outcome", outcome),
            ],
            "If you have further questions, please open a new support ticket in the BOMPAY app."
        )
        await send_email(to=email, subject=f"BOMPAY: Dispute Resolved — {subject_ticket}", html=html)
        logger.info("[Support] Dispute resolution email sent ticket=%s to=%s", ticket["ticket_id"], email)
    except Exception as e:
        logger.error("[Support] Dispute resolution email failed: %s", e)


@router.patch("/admin/support/{ticket_id}/close")
async def admin_close_ticket(ticket_id: str, request: Request):
    await get_admin_user(request)
    ticket = await db.support_tickets.find_one({"ticket_id": ticket_id})
    if not ticket:
        raise HTTPException(404, "Ticket not found")
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.support_tickets.update_one({"ticket_id": ticket_id},
        {"$set": {"status": "RESOLVED", "resolved_at": now_iso}})
    # Send resolution email for dispute tickets
    if ticket.get("ticket_type") == "dispute" and ticket.get("user_id"):
        asyncio.create_task(_send_dispute_resolution_email(ticket))
    return {"status": "RESOLVED"}

# ===== CRON ENDPOINTS =====
def _verify_cron(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth[7:]
    if not WEBHOOK_CRON_SECRET or not secrets.compare_digest(token.encode(), WEBHOOK_CRON_SECRET.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")

async def _run_auto_save(run_id: str):
    now = datetime.now(timezone.utc)
    goals = await db.savings_goals.find({"auto_save": True, "auto_save_amount": {"$gt": 0}, "status": "ACTIVE"}).to_list(2000)
    cfg = await get_savings_config()
    for goal in goals:
        freq = goal.get("auto_save_frequency", "WEEKLY")
        last_auto = goal.get("last_auto_save")
        if last_auto:
            try:
                last_dt = datetime.fromisoformat(last_auto)
                days = (now - last_dt).days
                if (freq == "WEEKLY" and days < 7) or (freq == "MONTHLY" and days < 28):
                    continue
            except (ValueError, TypeError):
                pass
        amt = goal.get("auto_save_amount", 0)
        user_id = goal["user_id"]
        idem = f"autosave-{goal['goal_id']}-{run_id}"
        if await db.transactions.find_one({"idempotency_key": idem}):
            continue
        # ─── Atomic debit ───
        updated_w = await db.wallets.find_one_and_update(
            {"user_id": user_id, "available_balance": {"$gte": amt}},
            {"$inc": {"available_balance": -amt, "ledger_balance": -amt}},
            return_document=True
        )
        if not updated_w:
            # ─── Defaulter fee ───
            fee_type = cfg.get("defaulter_fee_type", "FLAT")
            fee_amt = int(cfg.get("defaulter_fee_amount", 200.0) * 100) if fee_type == "FLAT" \
                else int(amt * cfg.get("defaulter_fee_percentage", 2.0) / 100)
            if fee_amt > 0:
                fee_deducted = await db.wallets.find_one_and_update(
                    {"user_id": user_id, "available_balance": {"$gte": fee_amt}},
                    {"$inc": {"available_balance": -fee_amt, "ledger_balance": -fee_amt}},
                    return_document=True
                )
                if fee_deducted:
                    fee_txn_id = f"TXN{secrets.token_hex(12).upper()}"
                    await db.transactions.insert_one({
                        "transaction_id": fee_txn_id, "idempotency_key": f"fee-{idem}",
                        "user_id": user_id, "type": "SAVINGS_DEFAULTER_FEE", "direction": "DEBIT",
                        "amount": fee_amt, "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED",
                        "provider": "INTERNAL", "description": f"Missed auto-save defaulter fee: {goal['name']}",
                        "metadata": {"goal_id": goal["goal_id"]},
                        "created_at": now.isoformat(), "updated_at": now.isoformat()
                    })
            await notify(user_id, "Auto-Save Missed", f"Insufficient balance for '{goal['name']}'. Defaulter fee applied.", "warning")
            continue
        txn_id = f"TXN{secrets.token_hex(12).upper()}"
        await db.transactions.insert_one({
            "transaction_id": txn_id, "idempotency_key": idem, "user_id": user_id,
            "type": "SAVINGS_CONTRIBUTION", "direction": "DEBIT", "amount": amt,
            "fee": 0, "vat": 0, "currency": "NGN", "status": "COMPLETED", "provider": "INTERNAL",
            "description": f"Auto-save: {goal['name']}", "metadata": {"goal_id": goal["goal_id"], "auto": True},
            "created_at": now.isoformat(), "updated_at": now.isoformat()
        })
        await db.savings_goals.update_one({"goal_id": goal["goal_id"]},
            {"$inc": {"current_amount": amt}, "$set": {"last_auto_save": now.isoformat()}})
        # SH sweep
        try:
            savings_acct = await db.charge_accounts.find_one({"category": "SAVINGS_PROCEEDS"})
            sh_dest = (savings_acct or {}).get("sh_account_number", "")
            wallet_doc = await db.wallets.find_one({"user_id": user_id})
            user_sh = (wallet_doc or {}).get("sh_account_number", "")
            if sh_dest and user_sh:
                await call_sh("POST", "/transfers", body={
                    "debitAccountNumber": user_sh, "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                    "beneficiaryAccountNumber": sh_dest, "amount": amt / 100,
                    "saveBeneficiary": False, "narration": f"BOMPAY auto-save {goal['name'][:20]}",
                    "paymentReference": txn_id
                })
        except Exception as e:
            logger.warning(f"[AutoSave] SH sweep failed: {e}")
        await notify(user_id, "Auto-Save Complete", f"₦{amt/100:,.2f} auto-saved to '{goal['name']}'.", "success")

async def _run_loan_reminders(run_id: str):
    now = datetime.now(timezone.utc)
    loans = await db.loan_applications.find({"status": "DISBURSED", "due_date": {"$exists": True}}).to_list(2000)
    for loan in loans:
        due = loan.get("due_date")
        if not due:
            continue
        try:
            due_dt = datetime.fromisoformat(due)
            days_left = (due_dt - now).days
            if 0 <= days_left <= 3:
                idem = f"loanrem-{loan['loan_id']}-{due[:10]}"
                if await db.notifications.find_one({"metadata.idempotency_key": idem}):
                    continue
                day_word = "today" if days_left == 0 else (f"in {days_left} day{'s' if days_left > 1 else ''}")
                await db.notifications.insert_one({
                    "notification_id": str(uuid.uuid4()), "user_id": loan["user_id"],
                    "title": "Loan Payment Due Soon",
                    "message": f"Your repayment of ₦{loan.get('monthly_payment',0):,.2f} is due {day_word}.",
                    "type": "warning", "read": False,
                    "metadata": {"idempotency_key": idem, "loan_id": loan["loan_id"]},
                    "created_at": now.isoformat()
                })
        except (ValueError, TypeError):
            continue

