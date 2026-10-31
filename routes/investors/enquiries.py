"""Investor Centre — enquiry management."""
import logging
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import get_admin_user as require_admin

router = APIRouter()
logger = logging.getLogger(__name__)


class EnquiryIn(BaseModel):
    full_name:       str
    organisation:    str = ""
    email:           str
    country:         str = ""
    investor_type:   str = ""
    investment_interest: str = ""
    investment_range: str = ""
    message:         str = ""

class EnquiryUpdateIn(BaseModel):
    status:  str = ""
    notes:   str = ""
    category: str = ""


@router.post("/investors/enquiries")
async def submit_enquiry(body: EnquiryIn, request: Request):
    # Basic rate-limit: max 3 enquiries per IP per hour
    ip  = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc)
    recent = await db.investor_enquiries.count_documents({
        "ip": ip,
        "created_at": {"$gte": (now.timestamp() - 3600)},
    })
    if recent >= 3:
        raise HTTPException(429, "Too many enquiries — please try again later")
    
    doc = {
        **body.dict(),
        "email":      body.email.strip().lower(),
        "status":     "new",
        "notes":      "",
        "category":   "",
        "ip":         ip,
        "created_at": now.timestamp(),
        "created_at_str": now.isoformat(),
    }
    result = await db.investor_enquiries.insert_one(doc)
    logger.info(f"[InvestorEnquiry] New from {body.email} ({body.country})")

    # Fire-and-forget: confirmation email to investor + notification to IR team
    async def _post_enquiry_emails():
        try:
            from routes.investors.invitations import _send_enquiry_confirmation, _notify_ir_new_enquiry
            # Get active Tier 1 documents for the confirmation email
            tier1_docs = await db.investor_documents.find(
                {"tier": 1, "is_active": True}, {"_id": 1, "title": 1, "category": 1}
            ).to_list(10)
            for d in tier1_docs:
                d["id"] = str(d.pop("_id"))
            await _send_enquiry_confirmation(body.full_name, body.email, tier1_docs)
            await _notify_ir_new_enquiry(
                body.full_name, body.email, body.organisation,
                body.investor_type, body.investment_range, body.message
            )
        except Exception as e:
            logger.warning(f"[InvestorEnquiry] Post-enquiry emails failed: {e}")

    asyncio.create_task(_post_enquiry_emails())
    return {"ok": True, "id": str(result.inserted_id)}


@router.get("/investors/enquiries")
async def list_enquiries(request: Request, page: int = 1, limit: int = 50, status: str = ""):
    await require_admin(request)
    q = {}
    if status in ("new", "contacted", "qualified", "not_suitable", "closed"):
        q["status"] = status
    skip = (page - 1) * limit
    items = await db.investor_enquiries.find(q, {"_id": 1, "full_name": 1, "email": 1, "organisation": 1,
                                                  "country": 1, "investor_type": 1, "investment_range": 1,
                                                  "message": 1, "status": 1, "notes": 1, "category": 1,
                                                  "created_at_str": 1}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    for i in items:
        i["id"] = str(i.pop("_id"))
    total = await db.investor_enquiries.count_documents(q)
    return {"enquiries": items, "total": total, "page": page}


@router.patch("/investors/enquiries/{enquiry_id}")
async def update_enquiry(request: Request, enquiry_id: str, body: EnquiryUpdateIn):
    await require_admin(request)
    update = {}
    if body.status:   update["status"]   = body.status
    if body.notes:    update["notes"]     = body.notes
    if body.category: update["category"] = body.category
    if update:
        await db.investor_enquiries.update_one({"_id": ObjectId(enquiry_id)}, {"$set": update})
    return {"ok": True}


@router.delete("/investors/enquiries/{enquiry_id}")
async def delete_enquiry(request: Request, enquiry_id: str):
    await require_admin(request)
    await db.investor_enquiries.delete_one({"_id": ObjectId(enquiry_id)})
    return {"ok": True}
