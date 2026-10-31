"""Investor Centre — Data Room document storage & access (Cloudinary-backed)."""
import io
import logging
import base64
import mimetypes
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import RedirectResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import get_admin_user, APP_NAME
import cloudinary
import cloudinary.uploader
import httpx

router = APIRouter()
logger = logging.getLogger(__name__)

ALLOWED_MIME = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
    "application/vnd.ms-excel",
    "image/png", "image/jpeg", "image/webp",
}

MAX_SIZE = 20 * 1024 * 1024  # 20 MB

TIER_LABELS = {1: "Public (after enquiry)", 2: "Verified Investor", 3: "NDA Required"}


# ── Cloudinary raw upload helper ───────────────────────────────────────────────

def _upload_investor_doc(data: bytes, public_id: str, resource_type: str = "raw") -> str:
    """Upload document bytes to Cloudinary (public type, access controlled via backend)."""
    result = cloudinary.uploader.upload(
        data,
        public_id=public_id,
        resource_type=resource_type,
        overwrite=True,
        invalidate=True,
    )
    return result["secure_url"]


def _delete_investor_doc(public_id: str, resource_type: str = "raw") -> None:
    try:
        cloudinary.uploader.destroy(public_id, resource_type=resource_type, invalidate=True)
    except Exception as e:
        logger.warning(f"[DataRoom] Cloudinary delete failed for {public_id}: {e}")


# ── Signed download URL via Cloudinary ────────────────────────────────────────

def _signed_url(public_id: str, resource_type: str = "raw", expires: int = 3600) -> str:
    """Generate a signed (expiring) download URL."""
    from cloudinary.utils import cloudinary_url
    url, _ = cloudinary_url(
        public_id,
        resource_type=resource_type,
        sign_url=True,
        secure=True,
        expires_at=int(datetime.now(timezone.utc).timestamp()) + expires,
    )
    return url


# ── Admin upload ───────────────────────────────────────────────────────────────

@router.post("/investors/dataroom/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str = Form(""),
    tier: int = Form(1),
    category: str = Form("general"),
):
    """Admin: upload a document to the investor data room."""
    admin_user = await get_admin_user(request)

    if tier not in (1, 2, 3):
        raise HTTPException(400, "tier must be 1, 2 or 3")

    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(413, f"File too large (max {MAX_SIZE // 1024 // 1024} MB)")

    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    if mime not in ALLOWED_MIME:
        raise HTTPException(415, f"File type {mime} not allowed")

    ext = (file.filename or "file").rsplit(".", 1)[-1].lower()
    resource_type = "image" if mime.startswith("image/") else "raw"
    doc_id = str(ObjectId())
    public_id = f"{APP_NAME}_investor_docs/{doc_id}/{title.replace(' ', '_')[:40]}.{ext}"

    try:
        url = _upload_investor_doc(content, public_id, resource_type)
    except Exception as e:
        logger.error(f"[DataRoom] Cloudinary upload error: {e}")
        raise HTTPException(502, "Document upload failed — storage error")

    doc = {
        "_id": ObjectId(doc_id),
        "title": title,
        "description": description,
        "filename": file.filename,
        "mime_type": mime,
        "size_bytes": len(content),
        "tier": tier,
        "category": category,
        "cloudinary_public_id": public_id,
        "cloudinary_url": url,
        "resource_type": resource_type,
        "is_active": True,
        "download_count": 0,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": admin_user.get("email", "admin"),
    }
    await db.investor_documents.insert_one(doc)
    return {"ok": True, "doc_id": doc_id, "tier": tier, "title": title}


# ── List documents ─────────────────────────────────────────────────────────────

@router.get("/investors/dataroom")
async def list_documents(tier: Optional[int] = None, category: Optional[str] = None):
    """Public: list documents. Tier 1 only — higher tiers return metadata but no download URL."""
    query = {"is_active": True}
    if tier:
        query["tier"] = tier
    if category:
        query["category"] = category

    docs = await db.investor_documents.find(query).sort("tier", 1).sort("uploaded_at", -1).to_list(100)

    result = []
    for d in docs:
        result.append({
            "id": str(d["_id"]),
            "title": d.get("title", ""),
            "description": d.get("description", ""),
            "filename": d.get("filename", ""),
            "mime_type": d.get("mime_type", ""),
            "size_bytes": d.get("size_bytes", 0),
            "size_mb": round(d.get("size_bytes", 0) / 1024 / 1024, 2),
            "tier": d.get("tier", 1),
            "category": d.get("category", "general"),
            "uploaded_at": d.get("uploaded_at", ""),
            "download_count": d.get("download_count", 0),
            "tier_label": TIER_LABELS.get(d.get("tier", 1), ""),
            "can_download": d.get("tier", 1) == 1,
        })

    return {"documents": result, "total": len(result)}


@router.get("/investors/admin/dataroom")
async def admin_list_documents(request: Request):
    """Admin: list all documents including inactive."""
    await get_admin_user(request)
    docs = await db.investor_documents.find({}).sort("uploaded_at", -1).to_list(200)

    result = []
    for d in docs:
        result.append({
            "id": str(d["_id"]),
            "title": d.get("title", ""),
            "description": d.get("description", ""),
            "filename": d.get("filename", ""),
            "mime_type": d.get("mime_type", ""),
            "size_bytes": d.get("size_bytes", 0),
            "size_mb": round(d.get("size_bytes", 0) / 1024 / 1024, 2),
            "tier": d.get("tier", 1),
            "category": d.get("category", "general"),
            "uploaded_at": d.get("uploaded_at", ""),
            "download_count": d.get("download_count", 0),
            "is_active": d.get("is_active", True),
            "tier_label": TIER_LABELS.get(d.get("tier", 1), ""),
        })
    return {"documents": result}


# ── Download (backend proxy — forces real file download, hides Cloudinary URL) ──

@router.get("/investors/dataroom/download/{doc_id}")
async def download_document(doc_id: str, request: Request):
    """
    Download a document. Tier 1: no auth needed.
    Tier 2/3: requires admin auth or valid invitation token.
    The file is proxied through the backend so the browser triggers a real download.
    """
    try:
        oid = ObjectId(doc_id)
    except Exception:
        raise HTTPException(400, "Invalid document ID")

    doc = await db.investor_documents.find_one({"_id": oid, "is_active": True})
    if not doc:
        raise HTTPException(404, "Document not found")

    # Auth gate for Tier 2/3
    if doc["tier"] in (2, 3):
        # Check invitation token (query param or header)
        inv_token = request.query_params.get("token") or request.headers.get("X-Investor-Token")
        authed = False
        if inv_token:
            inv = await db.investor_invitations.find_one({"token": inv_token, "used": False})
            if inv and inv.get("tier", 1) >= doc["tier"]:
                import datetime as _dt
                expires = inv.get("expires_at")
                if expires and _dt.datetime.fromisoformat(expires) > _dt.datetime.now(_dt.timezone.utc):
                    authed = True
        if not authed:
            try:
                await get_admin_user(request)
                authed = True
            except Exception:
                pass
        if not authed:
            raise HTTPException(403, "Access to this document requires verified investor status.")

    # Live-generated traction report
    if doc.get("source_type") == "traction":
        from routes.investors.exports import _generate_traction_pdf
        pdf_bytes = await _generate_traction_pdf()
        await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="BOMPAY_Traction_Report.pdf"'},
        )

    filename = doc.get("filename") or doc.get("title", "document")
    mime     = doc.get("mime_type", "application/octet-stream")

    # PDF stored directly in MongoDB — serve without Cloudinary
    if doc.get("content_b64"):
        import base64
        content = base64.b64decode(doc["content_b64"])
        await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
        return Response(
            content=content,
            media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Proxy file from Cloudinary (for XLSX / PPTX)
    file_url = doc.get("cloudinary_url", "")
    if not file_url:
        raise HTTPException(502, "Document URL not available")

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(file_url)
        if resp.status_code != 200:
            raise HTTPException(502, f"Document temporarily unavailable (upstream {resp.status_code})")
    except httpx.RequestError as exc:
        logger.error(f"[DataRoom] Proxy fetch failed: {exc}")
        raise HTTPException(502, "Document temporarily unavailable")

    await db.investor_documents.update_one({"_id": oid}, {"$inc": {"download_count": 1}})
    return Response(
        content=resp.content,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Admin: toggle active / delete ─────────────────────────────────────────────

@router.patch("/investors/admin/dataroom/{doc_id}")
async def admin_update_document(request: Request, doc_id: str, body: dict):
    """Admin: update title, description, tier, is_active."""
    await get_admin_user(request)
    try:
        oid = ObjectId(doc_id)
    except Exception:
        raise HTTPException(400, "Invalid document ID")

    allowed = {"title", "description", "tier", "is_active", "category"}
    update = {k: v for k, v in body.items() if k in allowed}
    if not update:
        raise HTTPException(400, "No valid fields")

    result = await db.investor_documents.update_one({"_id": oid}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(404, "Document not found")
    return {"ok": True}


@router.delete("/investors/admin/dataroom/{doc_id}")
async def admin_delete_document(request: Request, doc_id: str):
    """Admin: permanently delete a document from Cloudinary + DB."""
    await get_admin_user(request)
    try:
        oid = ObjectId(doc_id)
    except Exception:
        raise HTTPException(400, "Invalid document ID")

    doc = await db.investor_documents.find_one({"_id": oid})
    if not doc:
        raise HTTPException(404, "Document not found")

    _delete_investor_doc(doc["cloudinary_public_id"], doc.get("resource_type", "raw"))
    await db.investor_documents.delete_one({"_id": oid})
    return {"ok": True}
