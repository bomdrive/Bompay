"""Investor Centre — invitation tokens and magic-link access."""
import os
import secrets
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import get_admin_user, send_email

router = APIRouter()
logger = logging.getLogger(__name__)

APP_BASE = os.environ.get("APP_BASE_URL", "https://bompay.app")
IR_EMAIL = os.environ.get("INVESTOR_ADMIN_EMAIL", "investors@bompay.app")
TIER_LABELS = {1: "Tier 1 — Public Materials", 2: "Tier 2 — Verified Investor Pack", 3: "Tier 3 — NDA Materials"}
INVITE_EXPIRY_DAYS = 7


# ── Email helpers ──────────────────────────────────────────────────────────────

def _base_email(body_html: str) -> str:
    return f"""<!DOCTYPE html><html>
<head><meta charset="utf-8"/>
<style>
  body {{ font-family:'Helvetica Neue',Arial,sans-serif; background:#F5F7FB; margin:0; padding:32px 16px; }}
  .card {{ background:#fff; border-radius:16px; max-width:560px; margin:0 auto; padding:40px; }}
  .logo {{ font-size:20px; font-weight:800; color:#071426; letter-spacing:-0.5px; margin-bottom:32px; }}
  h1 {{ font-size:22px; font-weight:700; color:#071426; margin:0 0 12px; }}
  p {{ font-size:14px; color:#475569; line-height:1.7; margin:0 0 16px; }}
  .btn {{ display:inline-block; background:#1769FF; color:#fff !important; text-decoration:none; padding:13px 28px; border-radius:10px; font-weight:600; font-size:14px; margin:8px 0 24px; }}
  .doc-item {{ background:#F5F7FB; border-radius:10px; padding:12px 16px; margin-bottom:8px; font-size:13px; color:#1E293B; }}
  .doc-item a {{ color:#1769FF; text-decoration:none; font-weight:600; }}
  .footer {{ margin-top:32px; padding-top:20px; border-top:1px solid #E2E8F0; font-size:11px; color:#94A3B8; }}
  .badge {{ display:inline-block; font-size:11px; padding:3px 8px; border-radius:20px; font-weight:600; margin-bottom:16px; }}
  .badge-blue {{ background:#EFF6FF; color:#1769FF; }}
  .badge-green {{ background:#ECFDF5; color:#10B981; }}
</style>
</head>
<body><div class="card">{body_html}</div></body></html>"""


async def _send_enquiry_confirmation(name: str, email: str, tier1_docs: list):
    """Send investor enquiry confirmation with Tier 1 download links."""
    doc_links_html = ""
    if tier1_docs:
        lines = "".join(
            f'<div class="doc-item">📄 {d["title"]} '
            f'<a href="{APP_BASE}/investors/dataroom/download/{d["id"]}">Download</a></div>'
            for d in tier1_docs
        )
        doc_links_html = f"""
        <p><strong>Instant Access — Tier 1 Materials:</strong></p>
        {lines}
        <p style="font-size:12px;color:#94A3B8;margin-top:4px;">Links expire in 7 days. Downloads are logged for confidentiality.</p>
        """

    html = _base_email(f"""
        <div class="logo">BOMPAY</div>
        <span class="badge badge-green">Enquiry Received</span>
        <h1>Thank you, {name.split()[0]}.</h1>
        <p>We've received your investor enquiry and our IR team will be in touch within <strong>24–48 hours</strong>.</p>
        {doc_links_html}
        <p>In the meantime, you can explore our public investor materials:</p>
        <a class="btn" href="{APP_BASE}/investors">View Investor Portal →</a>
        <p>Questions? Reply directly to this email or reach us at <a href="mailto:{IR_EMAIL}">{IR_EMAIL}</a>.</p>
        <div class="footer">
          BOMPAY Financial Services · Investor Relations<br/>
          This email was sent because you submitted an enquiry at bompay.app/investors.<br/>
          All document downloads are watermarked and access-logged.
        </div>
    """)
    await send_email(to=email, subject="BOMPAY Investor Relations — Enquiry Received", html=html)
    logger.info(f"[InvestorEmail] Confirmation sent to {email}")


async def _notify_ir_new_enquiry(name: str, email: str, org: str, inv_type: str, inv_range: str, message: str):
    """Notify IR admin about new enquiry."""
    html = _base_email(f"""
        <div class="logo">BOMPAY</div>
        <span class="badge badge-blue">New Investor Enquiry</span>
        <h1>New Enquiry</h1>
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;">
          <tr><td style="padding:6px 0;color:#94A3B8;width:120px;">Name</td><td style="color:#1E293B;font-weight:600;">{name}</td></tr>
          <tr><td style="padding:6px 0;color:#94A3B8;">Email</td><td style="color:#1769FF;">{email}</td></tr>
          <tr><td style="padding:6px 0;color:#94A3B8;">Organisation</td><td style="color:#1E293B;">{org or "—"}</td></tr>
          <tr><td style="padding:6px 0;color:#94A3B8;">Type</td><td style="color:#1E293B;">{inv_type or "—"}</td></tr>
          <tr><td style="padding:6px 0;color:#94A3B8;">Range</td><td style="color:#1E293B;">{inv_range or "—"}</td></tr>
        </table>
        {"<p style='background:#F5F7FB;border-radius:8px;padding:12px;font-size:13px;color:#475569;'>" + message + "</p>" if message else ""}
        <a class="btn" href="{APP_BASE}/investors/admin">Manage Enquiries →</a>
        <div class="footer">BOMPAY Investor Relations Admin · {datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")}</div>
    """)
    try:
        await send_email(to=IR_EMAIL, subject=f"[BOMPAY IR] New Enquiry: {name} ({org or email})", html=html)
    except Exception as e:
        logger.warning(f"[InvestorEmail] IR notification failed: {e}")


# ── Invitation endpoints ───────────────────────────────────────────────────────

class InviteIn(BaseModel):
    email: str
    name: str
    organisation: str = ""
    tier: int = 2
    personal_note: str = ""


async def _send_invitation_email(invite: dict, docs: list):
    """Send magic-link access email to invited investor."""
    tier = invite["tier"]
    token = invite["token"]
    access_url = f"{APP_BASE}/investors/access?token={token}"
    expiry_str = invite["expires_at"][:10]  # YYYY-MM-DD

    doc_lines = "".join(
        f'<div class="doc-item">📄 {d["title"]} <span style="color:#94A3B8;font-size:12px;">({d["category"].title()})</span></div>'
        for d in docs
    ) if docs else '<div class="doc-item" style="color:#94A3B8;">Documents will be available at the access link below.</div>'

    note_html = f'<p style="background:#EFF6FF;border-left:3px solid #1769FF;padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#1E293B;">{invite["personal_note"]}</p>' if invite.get("personal_note") else ""

    html = _base_email(f"""
        <div class="logo">BOMPAY</div>
        <span class="badge badge-blue">{TIER_LABELS.get(tier,'Investor Access')}</span>
        <h1>You've been granted investor access.</h1>
        <p>Hi {invite['name'].split()[0]},</p>
        <p>The Bompay Investor Relations team has granted you access to our <strong>{TIER_LABELS.get(tier,'')}</strong> materials.</p>
        {note_html}
        <p><strong>Your access includes:</strong></p>
        {doc_lines}
        <a class="btn" href="{access_url}">Open Data Room →</a>
        <p style="font-size:12px;color:#94A3B8;">This link is personalised for <strong>{invite['email']}</strong> and expires on <strong>{expiry_str}</strong>. Please do not share it.</p>
        <div class="footer">
          BOMPAY Financial Services · Investor Relations<br/>
          This is a confidential communication. All access is logged and watermarked.<br/>
          Questions? <a href="mailto:{IR_EMAIL}">{IR_EMAIL}</a>
        </div>
    """)
    await send_email(
        to=invite["email"],
        subject=f"BOMPAY Investor Relations — Your {TIER_LABELS.get(tier,'')} Access",
        html=html,
    )
    logger.info(f"[InvestorInvite] Sent to {invite['email']} (tier {tier})")


@router.post("/investors/invitations")
async def send_invitation(request: Request, body: InviteIn):
    """Admin: create invitation token and send access email."""
    await get_admin_user(request)

    if body.tier not in (1, 2, 3):
        raise HTTPException(400, "tier must be 1, 2 or 3")

    email = body.email.strip().lower()
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=INVITE_EXPIRY_DAYS)

    invite_doc = {
        "email": email,
        "name": body.name,
        "organisation": body.organisation,
        "tier": body.tier,
        "token": token,
        "personal_note": body.personal_note,
        "used": False,
        "used_at": None,
        "expires_at": expires.isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.investor_invitations.insert_one(invite_doc)

    # Load docs for that tier (to list in email)
    docs = await db.investor_documents.find(
        {"tier": {"$lte": body.tier}, "is_active": True},
        {"_id": 1, "title": 1, "category": 1}
    ).to_list(20)
    for d in docs:
        d["id"] = str(d.pop("_id"))

    asyncio.create_task(_send_invitation_email(invite_doc, docs))
    return {"ok": True, "email": email, "tier": body.tier, "expires_at": expires.isoformat()}


@router.get("/investors/invitations")
async def list_invitations(request: Request):
    """Admin: list all invitations."""
    await get_admin_user(request)
    items = await db.investor_invitations.find(
        {}, {"_id": 1, "email": 1, "name": 1, "organisation": 1, "tier": 1,
             "used": 1, "used_at": 1, "expires_at": 1, "created_at": 1}
    ).sort("created_at", -1).to_list(100)
    for i in items:
        i["id"] = str(i.pop("_id"))
        # Check if expired
        exp = datetime.fromisoformat(i["expires_at"].replace("Z", "+00:00"))
        i["expired"] = exp < datetime.now(timezone.utc)
    return {"invitations": items}


@router.get("/investors/access")
async def validate_access_token(token: str, request: Request):
    """Public: validate magic-link token and return tier + documents."""
    if not token:
        raise HTTPException(400, "Token required")

    invite = await db.investor_invitations.find_one({"token": token})
    if not invite:
        raise HTTPException(404, "Invalid or expired access link")

    exp = datetime.fromisoformat(invite["expires_at"].replace("Z", "+00:00"))
    if exp < datetime.now(timezone.utc):
        raise HTTPException(410, "This access link has expired. Please contact investors@bompay.app for a new link.")

    # Mark as used (first time only)
    if not invite.get("used"):
        await db.investor_invitations.update_one(
            {"_id": invite["_id"]},
            {"$set": {"used": True, "used_at": datetime.now(timezone.utc).isoformat()}}
        )

    tier = invite["tier"]
    docs = await db.investor_documents.find(
        {"tier": {"$lte": tier}, "is_active": True}
    ).to_list(50)

    result_docs = []
    for d in docs:
        result_docs.append({
            "id": str(d["_id"]),
            "title": d.get("title", ""),
            "description": d.get("description", ""),
            "filename": d.get("filename", ""),
            "mime_type": d.get("mime_type", ""),
            "size_mb": round(d.get("size_bytes", 0) / 1024 / 1024, 2),
            "tier": d.get("tier", 1),
            "category": d.get("category", "general"),
        })

    return {
        "valid": True,
        "name": invite["name"],
        "email": invite["email"],
        "organisation": invite.get("organisation", ""),
        "tier_granted": tier,
        "tier_label": TIER_LABELS.get(tier, ""),
        "expires_at": invite["expires_at"],
        "documents": result_docs,
    }


@router.get("/investors/access/download/{doc_id}")
async def access_download(doc_id: str, token: str, request: Request):
    """Public: download a document via magic-link token (proxied through backend)."""
    if not token:
        raise HTTPException(400, "Token required")

    invite = await db.investor_invitations.find_one({"token": token})
    if not invite:
        raise HTTPException(404, "Invalid access link")

    exp = datetime.fromisoformat(invite["expires_at"].replace("Z", "+00:00"))
    if exp < datetime.now(timezone.utc):
        raise HTTPException(410, "Access link expired")

    try:
        oid = ObjectId(doc_id)
    except Exception:
        raise HTTPException(400, "Invalid document ID")

    doc = await db.investor_documents.find_one({"_id": oid, "is_active": True})
    if not doc:
        raise HTTPException(404, "Document not found")

    if doc.get("tier", 1) > invite["tier"]:
        raise HTTPException(403, "Your access tier does not include this document")

    # NDA gate for Tier 3
    if doc.get("tier", 1) >= 3:
        agreement = await db.investor_nda_agreements.find_one({"token": token})
        if not agreement:
            raise HTTPException(403, "This document requires NDA acceptance first.")

    # Live traction report
    if doc.get("source_type") == "traction":
        from routes.investors.exports import _generate_traction_pdf
        pdf_bytes = await _generate_traction_pdf()
        await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
        from fastapi.responses import Response as FR
        return FR(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="BOMPAY_Traction_Report.pdf"'},
        )

    # Proxy from Cloudinary (or MongoDB-stored bytes for PDFs)
    filename = doc.get("filename") or doc["title"]
    mime = doc.get("mime_type", "application/octet-stream")

    if doc.get("content_b64"):
        import base64 as _b64
        content = _b64.b64decode(doc["content_b64"])
        await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
        from fastapi.responses import Response as FR
        return FR(
            content=content,
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Proxy from Cloudinary
    file_url = doc.get("cloudinary_url", "")
    if not file_url:
        raise HTTPException(502, "Document URL not available")

    import httpx
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(file_url)
        if resp.status_code != 200:
            raise HTTPException(502, f"Document temporarily unavailable (upstream {resp.status_code})")
    except httpx.RequestError as exc:
        raise HTTPException(502, "Document temporarily unavailable")

    await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
    from fastapi.responses import Response as FR
    return FR(
        content=resp.content,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
