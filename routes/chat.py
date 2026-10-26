"""
Bompay Support Chat — Website guest live chat
/api/support/chat  — public (guest) endpoints
/api/admin/chat    — admin + staff endpoints
"""
import os, secrets
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from database import db
from core import logger, send_email, _email_html

router = APIRouter()

def _now():
    return datetime.now(timezone.utc).isoformat()

# Admin email → friendly display name mapping
ADMIN_NAME_MAP = {
    "console@bompay.app": "Bibi",
}
BOMPAY_LOGO = "https://customer-assets-eiarnc6j.emergentagent.net/job_bompay-ledger/artifacts/v92480gb_BomPay.png"

def _agent_display_name(admin: dict) -> str:
    """Return friendly agent name, mapping known admin emails to personas."""
    email = admin.get("email", "")
    if email in ADMIN_NAME_MAP:
        return ADMIN_NAME_MAP[email]
    name = admin.get("name", "").strip()
    # If stored name is just the email address, return Support Agent
    if name and "@" not in name:
        return name
    return "Support Agent"

CHAT_TOPICS = ["General Enquiry", "Account & Registration", "Transfers & Payments",
               "ePOS & Merchant", "Ajo & Savings", "Cards", "Security & Fraud",
               "API & Developer", "Other"]

# ── MODELS ───────────────────────────────────────────────────────────────────

class StartChatReq(BaseModel):
    guest_name: str
    guest_email: Optional[str] = ""
    topic: Optional[str] = "General Enquiry"
    initial_message: str

class SendMessageReq(BaseModel):
    message: str
    sender_name: Optional[str] = ""

class AssignChatReq(BaseModel):
    agent_id: str
    agent_name: str

class CloseSessionReq(BaseModel):
    reason: Optional[str] = ""

# ── GUEST ENDPOINTS ───────────────────────────────────────────────────────────

@router.post("/support/chat/sessions")
async def start_chat(req: StartChatReq):
    """Guest starts a new chat session."""
    if not req.guest_name.strip() or not req.initial_message.strip():
        raise HTTPException(400, "Name and initial message are required")

    session_id = f"chat_{secrets.token_urlsafe(10)}"
    now = _now()
    session = {
        "session_id": session_id,
        "guest_name": req.guest_name.strip(),
        "guest_email": req.guest_email.strip() if req.guest_email else "",
        "topic": req.topic or "General Enquiry",
        "status": "open",          # open | assigned | resolved | closed
        "assigned_to": None,
        "assigned_name": None,
        "assigned_at": None,
        "created_at": now,
        "updated_at": now,
        "last_message_at": now,
        "resolved_at": None,
        "guest_rating": None,
    }
    await db.chat_sessions.insert_one(session)

    # Insert initial guest message
    await db.chat_messages.insert_one({
        "session_id": session_id,
        "sender_type": "guest",
        "sender_name": req.guest_name.strip(),
        "message": req.initial_message.strip(),
        "created_at": now,
        "read_by_agent": False,
    })

    # Auto-reply
    await db.chat_messages.insert_one({
        "session_id": session_id,
        "sender_type": "system",
        "sender_name": "Bompay Support",
        "message": f"Hi {req.guest_name.strip()}! Thanks for reaching out. A support agent will be with you shortly. Average response time is under 2 minutes.",
        "created_at": _now(),
        "read_by_agent": True,
    })

    logger.info(f"[CHAT] New session {session_id} from '{req.guest_name}' topic='{req.topic}'")
    return {"session_id": session_id, "status": "open", "guest_name": req.guest_name.strip()}


@router.get("/support/chat/sessions/{session_id}")
async def get_chat_session(session_id: str):
    """Get session status (for guest polling)."""
    s = await db.chat_sessions.find_one({"session_id": session_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Chat session not found")
    return {
        "session_id": s["session_id"],
        "status": s["status"],
        "assigned_name": s.get("assigned_name"),
        "topic": s.get("topic"),
        "guest_name": s.get("guest_name"),
    }


@router.get("/support/chat/sessions/{session_id}/messages")
async def get_chat_messages(session_id: str, since: str = ""):
    """Poll for messages. `since` = ISO timestamp to get only newer messages."""
    s = await db.chat_sessions.find_one({"session_id": session_id}, {"_id": 0, "status": 1})
    if not s:
        raise HTTPException(404, "Chat session not found")

    query = {"session_id": session_id}
    if since:
        query["created_at"] = {"$gt": since}

    msgs = await db.chat_messages.find(query, {"_id": 0}).sort("created_at", 1).to_list(100)
    return {"messages": msgs, "session_status": s["status"]}


@router.post("/support/chat/sessions/{session_id}/messages")
async def send_guest_message(session_id: str, req: SendMessageReq):
    """Guest sends a message."""
    s = await db.chat_sessions.find_one({"session_id": session_id})
    if not s:
        raise HTTPException(404, "Chat session not found")
    if s.get("status") in ("closed", "resolved"):
        raise HTTPException(410, "This chat session has ended")
    if not req.message.strip():
        raise HTTPException(400, "Message cannot be empty")

    now = _now()
    msg = {
        "session_id": session_id,
        "sender_type": "guest",
        "sender_name": s.get("guest_name", req.sender_name or "Guest"),
        "message": req.message.strip(),
        "created_at": now,
        "read_by_agent": False,
    }
    await db.chat_messages.insert_one(msg)
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"last_message_at": now, "updated_at": now}}
    )
    return {"sent": True}


@router.post("/support/chat/sessions/{session_id}/close")
async def close_chat_guest(session_id: str, req: CloseSessionReq):
    """Guest closes the chat."""
    s = await db.chat_sessions.find_one({"session_id": session_id})
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"status": "closed", "resolved_at": _now(), "updated_at": _now()}}
    )
    # Send transcript if guest provided email
    if s and s.get("guest_email"):
        import asyncio
        asyncio.create_task(_send_transcript_email(s))
    return {"closed": True}


async def _send_transcript_email(session: dict):
    """Send the chat transcript to the guest's email address."""
    try:
        guest_email = session.get("guest_email", "")
        if not guest_email:
            return
        guest_name = session.get("guest_name", "Guest")
        session_id = session["session_id"]
        msgs = await db.chat_messages.find(
            {"session_id": session_id, "sender_type": {"$ne": "system"}},
            {"_id": 0}
        ).sort("created_at", 1).to_list(200)

        if not msgs:
            return

        # Build message rows for the email
        def fmt_time(iso):
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
                return dt.strftime("%d %b %Y, %H:%M")
            except Exception:
                return iso[:16]

        rows = []
        for m in msgs:
            sender = m.get("sender_name", "Support")
            who = "You" if m.get("sender_type") == "guest" else sender
            rows.append(f"<b style='color:{'#064BCB' if m.get('sender_type')!='guest' else '#333'}'>{who}</b> "
                        f"<span style='color:#999;font-size:11px'>{fmt_time(m.get('created_at',''))}</span><br>"
                        f"{m.get('message','')}")

        topic = session.get("topic", "General Enquiry")
        html = _email_html(
            f"Your Bompay Support Transcript",
            [f"Hi {guest_name}, here is a copy of your chat with Bompay Support.",
             f"<b>Topic:</b> {topic}",
             ""] + rows + ["",
             "If you need further assistance please start a new chat at <a href='https://bompay.ng/support'>bompay.ng/support</a>."],
            "Thank you for choosing Bompay."
        )
        await send_email(
            to=guest_email,
            subject=f"Your Bompay Support Chat Transcript — {topic}",
            html=html
        )
        logger.info(f"[CHAT] Transcript sent to {guest_email} for session {session_id}")
    except Exception as e:
        logger.warning(f"[CHAT] Transcript email failed: {e}")


@router.post("/support/chat/sessions/{session_id}/rate")
async def rate_chat(session_id: str, request: Request):
    """Guest rates the chat session (1–5 stars)."""
    body = await request.json()
    rating = int(body.get("rating", 0))
    if rating < 1 or rating > 5:
        raise HTTPException(400, "Rating must be 1–5")
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"guest_rating": rating, "updated_at": _now()}}
    )
    return {"rated": True}


# ── PUBLIC FEES ENDPOINT ──────────────────────────────────────────────────────

@router.get("/public/merchant-fees")
async def public_merchant_fees():
    """Public read-only fee schedule for the website."""
    fees = await db.merchant_fee_rules.find({"is_active": True}, {"_id": 0, "updated_by": 0, "updated_at": 0}).to_list(20)
    return {"fees": fees}


# ── ADMIN / AGENT ENDPOINTS ───────────────────────────────────────────────────

@router.get("/admin/chat/sessions")
async def admin_list_sessions(request: Request, status: str = "", page: int = 1):
    from routes.merchant.legacy import _get_admin
    await _get_admin(request)
    query = {}
    if status:
        query["status"] = status
    skip = (page - 1) * 30
    sessions = await db.chat_sessions.find(query, {"_id": 0}).sort("last_message_at", -1).skip(skip).limit(30).to_list(30)
    total = await db.chat_sessions.count_documents(query)
    # Unread count per session
    for s in sessions:
        s["unread_count"] = await db.chat_messages.count_documents(
            {"session_id": s["session_id"], "sender_type": "guest", "read_by_agent": False}
        )
    stats = {
        "open": await db.chat_sessions.count_documents({"status": "open"}),
        "assigned": await db.chat_sessions.count_documents({"status": "assigned"}),
        "resolved": await db.chat_sessions.count_documents({"status": "resolved"}),
        "total": await db.chat_sessions.count_documents({}),
    }
    return {"sessions": sessions, "total": total, "page": page, "stats": stats}


@router.get("/admin/chat/sessions/{session_id}/messages")
async def admin_get_messages(session_id: str, request: Request):
    from routes.merchant.legacy import _get_admin
    await _get_admin(request)
    msgs = await db.chat_messages.find(
        {"session_id": session_id}, {"_id": 0}
    ).sort("created_at", 1).to_list(500)
    # Mark all guest messages as read
    await db.chat_messages.update_many(
        {"session_id": session_id, "sender_type": "guest", "read_by_agent": False},
        {"$set": {"read_by_agent": True}}
    )
    return {"messages": msgs}


@router.post("/admin/chat/sessions/{session_id}/messages")
async def admin_send_message(session_id: str, req: SendMessageReq, request: Request):
    from routes.merchant.legacy import _get_admin
    admin = await _get_admin(request)
    s = await db.chat_sessions.find_one({"session_id": session_id})
    if not s:
        raise HTTPException(404, "Session not found")
    if s.get("status") in ("closed",):
        raise HTTPException(410, "Session is closed")
    now = _now()
    agent_name = req.sender_name.strip() if req.sender_name and req.sender_name.strip() else _agent_display_name(admin)
    await db.chat_messages.insert_one({
        "session_id": session_id,
        "sender_type": "agent",
        "sender_name": agent_name,
        "message": req.message.strip(),
        "created_at": now,
        "read_by_agent": True,
    })
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"last_message_at": now, "updated_at": now,
                  "status": "assigned" if s.get("status") == "open" else s.get("status")}}
    )
    return {"sent": True}


@router.put("/admin/chat/sessions/{session_id}/assign")
async def assign_chat(session_id: str, req: AssignChatReq, request: Request):
    from routes.merchant.legacy import _get_admin
    admin = await _get_admin(request)
    now = _now()
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {
            "assigned_to": req.agent_id,
            "assigned_name": req.agent_name,
            "assigned_at": now,
            "status": "assigned",
            "updated_at": now,
        }}
    )
    # System message to guest
    await db.chat_messages.insert_one({
        "session_id": session_id,
        "sender_type": "system",
        "sender_name": "Bompay Support",
        "message": f"Your chat has been assigned to {req.agent_name}.",
        "created_at": now,
        "read_by_agent": True,
    })
    logger.info(f"[CHAT] Session {session_id} assigned to {req.agent_name} by admin {admin.get('email')}")
    return {"assigned": True}


@router.put("/admin/chat/sessions/{session_id}/resolve")
async def resolve_chat(session_id: str, request: Request):
    from routes.merchant.legacy import _get_admin
    await _get_admin(request)
    now = _now()
    s = await db.chat_sessions.find_one({"session_id": session_id})
    await db.chat_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"status": "resolved", "resolved_at": now, "updated_at": now}}
    )
    await db.chat_messages.insert_one({
        "session_id": session_id,
        "sender_type": "system",
        "sender_name": "Bompay Support",
        "message": "This chat has been marked as resolved. Thank you for contacting Bompay Support! Please rate your experience.",
        "created_at": now,
        "read_by_agent": True,
    })
    # Send transcript to guest if email provided
    if s and s.get("guest_email"):
        import asyncio
        asyncio.create_task(_send_transcript_email(s))
    return {"resolved": True}
