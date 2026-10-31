"""Investor Centre — NDA Gate: records investor NDA acceptance before Tier 3 access."""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import get_admin_user

router = APIRouter()
logger = logging.getLogger(__name__)


class NDAAcceptBody(BaseModel):
    token: str
    signer_name: str


def _serialize(doc):
    if not doc:
        return None
    out = {k: (str(v) if isinstance(v, ObjectId) else v) for k, v in doc.items()}
    out["id"] = out.pop("_id", None)
    return out


@router.get("/investors/nda/status")
async def get_nda_status(token: str):
    """Check if the investor holding this token has accepted the NDA."""
    inv = await db.investor_invitations.find_one({"token": token})
    if not inv:
        raise HTTPException(404, "Invalid access token")

    agreement = await db.investor_nda_agreements.find_one({"token": token})
    if agreement:
        return {
            "accepted": True,
            "accepted_at": agreement.get("accepted_at"),
            "signer_name": agreement.get("signer_name"),
        }
    return {"accepted": False, "accepted_at": None, "signer_name": None}


@router.post("/investors/nda/accept")
async def accept_nda(body: NDAAcceptBody, request: Request):
    """Record NDA acceptance for the investor holding this token."""
    inv = await db.investor_invitations.find_one({"token": body.token})
    if not inv:
        raise HTTPException(404, "Invalid access token")

    existing = await db.investor_nda_agreements.find_one({"token": body.token})
    if existing:
        return {"ok": True, "already_accepted": True}

    client_ip = request.client.host if request.client else "unknown"
    await db.investor_nda_agreements.insert_one({
        "token": body.token,
        "investor_email": inv.get("email", ""),
        "investor_name": inv.get("name", ""),
        "signer_name": body.signer_name.strip(),
        "signer_ip": client_ip,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "invitation_id": str(inv["_id"]),
    })
    logger.info("[NDA] Accepted by %s (%s)", body.signer_name, inv.get("email"))
    return {"ok": True, "already_accepted": False}


@router.get("/investors/admin/nda")
async def admin_list_nda(request: Request):
    """Admin: list all NDA agreements."""
    await get_admin_user(request)
    agreements = await db.investor_nda_agreements.find(
        {}, {"_id": 1, "investor_email": 1, "investor_name": 1, "signer_name": 1,
              "signer_ip": 1, "accepted_at": 1}
    ).sort("accepted_at", -1).to_list(200)
    return {"agreements": [_serialize(a) for a in agreements]}
