"""
Payment Links routes — creation, management, public payment page.
Types: fixed | variable | invoice | product
"""
import secrets, uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from database import db
import asyncio
from core import logger, send_email, _email_html, FRONTEND_URL
from .legacy import get_current_merchant, _get_admin
from .common import _mk_checkout_session, _now

router = APIRouter()

LINK_TYPES = {"fixed", "variable", "invoice", "product"}


def _gen_lid() -> str:
    return "lnk_" + uuid.uuid4().hex[:12]


def _gen_code() -> str:
    """Generate short unpredictable public code (10 chars)."""
    return secrets.token_urlsafe(8)[:10]


# ─── MODELS ────────────────────────────────────────────────────────────────────

class CreateLink(BaseModel):
    title: str
    description: Optional[str] = ""
    link_type: str = "fixed"                  # fixed/variable/invoice/product
    amount_kobo: Optional[int] = None         # required for fixed/invoice
    min_amount_kobo: Optional[int] = None     # for variable
    max_amount_kobo: Optional[int] = None     # for variable
    currency: Optional[str] = "NGN"
    redirect_url: Optional[str] = ""
    collect_name: Optional[bool] = True
    collect_email: Optional[bool] = True
    collect_phone: Optional[bool] = True
    collect_note: Optional[bool] = False
    usage_limit: Optional[int] = None         # None = unlimited
    expires_in_days: Optional[int] = None     # None = no expiry


class UpdateLink(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    amount_kobo: Optional[int] = None
    min_amount_kobo: Optional[int] = None
    max_amount_kobo: Optional[int] = None
    redirect_url: Optional[str] = None
    collect_name: Optional[bool] = None
    collect_email: Optional[bool] = None
    collect_phone: Optional[bool] = None
    collect_note: Optional[bool] = None
    usage_limit: Optional[int] = None
    image_url: Optional[str] = None


class PayLinkInitiate(BaseModel):
    customer_name: Optional[str] = ""
    customer_email: Optional[str] = ""
    customer_phone: Optional[str] = ""
    customer_note: Optional[str] = ""
    amount_kobo: Optional[int] = None         # required for variable links


# ─── HELPERS ──────────────────────────────────────────────────────────────────

async def _get_merchant_ctx(request: Request) -> dict:
    m = await get_current_merchant(request)
    if not m:
        raise HTTPException(401, "Not authenticated")
    return m


def _validate_link(req_type: str, amount_kobo, min_amount_kobo, max_amount_kobo):
    if req_type not in LINK_TYPES:
        raise HTTPException(400, f"link_type must be one of: {', '.join(LINK_TYPES)}")
    if req_type in ("fixed", "invoice"):
        if not amount_kobo or amount_kobo < 100:
            raise HTTPException(400, "Fixed/invoice links require amount_kobo >= 100 (₦1 minimum)")
    if req_type == "variable":
        if min_amount_kobo and max_amount_kobo and min_amount_kobo >= max_amount_kobo:
            raise HTTPException(400, "min_amount_kobo must be less than max_amount_kobo")
        if min_amount_kobo and min_amount_kobo < 100:
            raise HTTPException(400, "min_amount_kobo must be >= 100 (₦1 minimum)")


# ─── MERCHANT: PAYMENT LINK CRUD ──────────────────────────────────────────────

@router.post("/v1/payment-links")
async def create_payment_link(req: CreateLink, request: Request):
    merchant = await _get_merchant_ctx(request)
    mid = merchant["merchant_id"]
    env = merchant.get("environment", "sandbox")

    if not req.title or len(req.title.strip()) < 2:
        raise HTTPException(400, "Title must be at least 2 characters")
    _validate_link(req.link_type, req.amount_kobo, req.min_amount_kobo, req.max_amount_kobo)

    # Limit: 100 active links per merchant
    count = await db.payment_links.count_documents({"merchant_id": mid, "is_deleted": {"$ne": True}})
    if count >= 100:
        raise HTTPException(400, "Maximum 100 payment links per merchant")

    expires_at = None
    if req.expires_in_days and req.expires_in_days > 0:
        from datetime import timedelta
        expires_at = (datetime.now(timezone.utc) + timedelta(days=req.expires_in_days)).isoformat()

    link_id = _gen_lid()
    code = _gen_code()
    # Ensure code is unique
    while await db.payment_links.find_one({"code": code}):
        code = _gen_code()

    now = _now()
    doc = {
        "link_id": link_id,
        "merchant_id": mid,
        "environment": env,
        "code": code,
        "link_type": req.link_type,
        "title": req.title.strip(),
        "description": req.description or "",
        "amount_kobo": req.amount_kobo,
        "min_amount_kobo": req.min_amount_kobo,
        "max_amount_kobo": req.max_amount_kobo,
        "currency": req.currency or "NGN",
        "image_url": "",
        "status": "draft",
        "redirect_url": req.redirect_url or "",
        "collect_name": req.collect_name if req.collect_name is not None else True,
        "collect_email": req.collect_email if req.collect_email is not None else True,
        "collect_phone": req.collect_phone if req.collect_phone is not None else True,
        "collect_note": req.collect_note or False,
        "usage_limit": req.usage_limit,
        "usage_count": 0,
        "expires_at": expires_at,
        "is_deleted": False,
        "created_at": now,
        "updated_at": now,
    }
    await db.payment_links.insert_one({**doc, "_id": link_id})
    logger.info(f"[PAYLINK] Created {link_id} code={code} type={req.link_type}")
    return doc


@router.get("/v1/payment-links")
async def list_payment_links(request: Request, page: int = 1, limit: int = 20,
                               status: str = "", link_type: str = ""):
    merchant = await _get_merchant_ctx(request)
    filt: dict = {"merchant_id": merchant["merchant_id"], "is_deleted": {"$ne": True}}
    if status:
        filt["status"] = status
    if link_type:
        filt["link_type"] = link_type
    skip = (page - 1) * limit
    links = await db.payment_links.find(filt, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.payment_links.count_documents(filt)
    return {"links": links, "total": total, "page": page,
            "pages": (total + limit - 1) // limit}


@router.get("/v1/payment-links/{link_id}")
async def get_payment_link(link_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}, {"_id": 0}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")
    return lnk


@router.patch("/v1/payment-links/{link_id}")
async def update_payment_link(link_id: str, req: UpdateLink, request: Request):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")
    if lnk.get("status") == "inactive":
        raise HTTPException(400, "Cannot update an inactive link. Duplicate it instead.")

    update = {k: v for k, v in req.dict(exclude_none=True).items()}
    if "amount_kobo" in update and update["amount_kobo"] is not None and update["amount_kobo"] < 100:
        raise HTTPException(400, "amount_kobo must be >= 100")
    update["updated_at"] = _now()
    await db.payment_links.update_one({"link_id": link_id}, {"$set": update})
    return {"updated": True}


@router.post("/v1/payment-links/{link_id}/publish")
async def publish_payment_link(link_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")
    await db.payment_links.update_one(
        {"link_id": link_id},
        {"$set": {"status": "active", "updated_at": _now()}}
    )
    return {
        "published": True,
        "url": f"{FRONTEND_URL.rstrip('/')}/pay/{lnk['code']}",
        "code": lnk["code"],
    }


@router.post("/v1/payment-links/{link_id}/deactivate")
async def deactivate_payment_link(link_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")
    await db.payment_links.update_one(
        {"link_id": link_id},
        {"$set": {"status": "inactive", "updated_at": _now()}}
    )
    return {"deactivated": True}


@router.post("/v1/payment-links/{link_id}/duplicate")
async def duplicate_payment_link(link_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")

    new_id = _gen_lid()
    new_code = _gen_code()
    while await db.payment_links.find_one({"code": new_code}):
        new_code = _gen_code()

    now = _now()
    new_doc = {
        **{k: v for k, v in lnk.items() if k not in ("_id", "link_id", "code",
                                                        "usage_count", "status",
                                                        "created_at", "updated_at")},
        "link_id": new_id,
        "code": new_code,
        "title": f"Copy of {lnk['title']}",
        "status": "draft",
        "usage_count": 0,
        "created_at": now,
        "updated_at": now,
    }
    await db.payment_links.insert_one({**new_doc, "_id": new_id})
    return new_doc


@router.get("/v1/payment-links/{link_id}/analytics")
async def payment_link_analytics(link_id: str, request: Request, days: int = 30):
    merchant = await _get_merchant_ctx(request)
    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")

    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    attempts = await db.payment_link_attempts.find(
        {"link_id": link_id, "created_at": {"$gte": since}}, {"_id": 0}
    ).sort("updated_at", -1).to_list(1000)

    paid = [a for a in attempts if a.get("status") == "paid"]
    total_revenue = sum(a.get("amount_kobo", 0) for a in paid)

    statuses = {}
    for a in attempts:
        st = a.get("status", "pending")
        statuses[st] = statuses.get(st, 0) + 1

    # Return most recent 20 — paid first (sorted by updated_at DESC so just-paid appear at top)
    return {
        "link_id": link_id,
        "days": days,
        "total_attempts": len(attempts),
        "paid_count": len(paid),
        "conversion_rate": round(len(paid) / len(attempts) * 100, 1) if attempts else 0,
        "total_revenue_kobo": total_revenue,
        "avg_amount_kobo": total_revenue // len(paid) if paid else 0,
        "status_breakdown": statuses,
        "recent_attempts": attempts[:20],
    }


# ─── PUBLIC: PAYMENT LINK PAGE ─────────────────────────────────────────────────

@router.get("/pay/{code}")
async def public_get_payment_link(code: str):
    """Public: fetch link info for the payment page. No auth required."""
    lnk = await db.payment_links.find_one(
        {"code": code, "is_deleted": {"$ne": True}}, {"_id": 0}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")

    # Check expiry
    if lnk.get("expires_at") and lnk["expires_at"] < _now():
        await db.payment_links.update_one({"code": code},
                                           {"$set": {"status": "expired"}})
        lnk["status"] = "expired"

    if lnk.get("status") == "inactive":
        raise HTTPException(410, "This payment link has been deactivated")
    if lnk.get("status") == "expired":
        raise HTTPException(410, "This payment link has expired")

    # Check usage limit
    usage_limit = lnk.get("usage_limit")
    if usage_limit is not None and lnk.get("usage_count", 0) >= usage_limit:
        raise HTTPException(410, "This payment link has reached its usage limit")

    # Get merchant business name
    merchant = await db.merchants.find_one({"merchant_id": lnk["merchant_id"]}, {"_id": 0})
    bname = (merchant or {}).get("business_name", "")

    return {
        "link_id": lnk["link_id"],
        "code": code,
        "link_type": lnk["link_type"],
        "title": lnk["title"],
        "description": lnk.get("description", ""),
        "amount_kobo": lnk.get("amount_kobo"),
        "min_amount_kobo": lnk.get("min_amount_kobo"),
        "max_amount_kobo": lnk.get("max_amount_kobo"),
        "currency": lnk.get("currency", "NGN"),
        "image_url": lnk.get("image_url", ""),
        "status": lnk.get("status", "active"),
        "collect_name": lnk.get("collect_name", True),
        "collect_email": lnk.get("collect_email", True),
        "collect_phone": lnk.get("collect_phone", True),
        "collect_note": lnk.get("collect_note", False),
        "business_name": bname,
        "usage_count": lnk.get("usage_count", 0),
        "usage_limit": usage_limit,
        "expires_at": lnk.get("expires_at"),
    }


@router.post("/pay/{code}/initiate")
async def public_initiate_payment(code: str, req: PayLinkInitiate):
    """
    Public: customer initiates payment for a payment link.
    Creates a checkout session and returns the checkout URL.
    """
    lnk = await db.payment_links.find_one({"code": code, "is_deleted": {"$ne": True}})
    if not lnk:
        raise HTTPException(404, "Payment link not found")

    # Re-validate status
    if lnk.get("expires_at") and lnk["expires_at"] < _now():
        raise HTTPException(410, "Payment link has expired")
    if lnk.get("status") not in ("active",):
        raise HTTPException(410, "Payment link is not active")

    # Atomic usage-limit check and increment
    usage_limit = lnk.get("usage_limit")
    if usage_limit is not None:
        result = await db.payment_links.find_one_and_update(
            {"code": code, "usage_count": {"$lt": usage_limit}},
            {"$inc": {"usage_count": 1}},
        )
        if not result:
            raise HTTPException(410, "Payment link has reached its usage limit")

    # Determine amount
    link_type = lnk.get("link_type", "fixed")
    if link_type in ("fixed", "invoice"):
        amount_kobo = lnk["amount_kobo"]
    elif link_type == "variable":
        if not req.amount_kobo:
            raise HTTPException(400, "amount_kobo is required for variable payment links")
        amount_kobo = req.amount_kobo
        min_k = lnk.get("min_amount_kobo")
        max_k = lnk.get("max_amount_kobo")
        if min_k and amount_kobo < min_k:
            raise HTTPException(400, f"Amount must be at least ₦{min_k/100:,.2f}")
        if max_k and amount_kobo > max_k:
            raise HTTPException(400, f"Amount cannot exceed ₦{max_k/100:,.2f}")
    else:
        amount_kobo = lnk.get("amount_kobo") or req.amount_kobo
        if not amount_kobo:
            raise HTTPException(400, "Amount is required")

    if amount_kobo < 100:
        raise HTTPException(400, "Minimum payment is ₦1.00")

    # Create attempt record
    attempt_id = "att_" + uuid.uuid4().hex[:12]
    now = _now()
    attempt = {
        "attempt_id": attempt_id,
        "link_id": lnk["link_id"],
        "merchant_id": lnk["merchant_id"],
        "environment": lnk.get("environment", "sandbox"),
        "checkout_session_id": "",
        "amount_kobo": amount_kobo,
        "customer_name": req.customer_name or "",
        "customer_email": req.customer_email or "",
        "customer_phone": req.customer_phone or "",
        "customer_note": req.customer_note or "",
        "status": "pending",
        "created_at": now,
        "updated_at": now,
    }
    await db.payment_link_attempts.insert_one({**attempt, "_id": attempt_id})

    # Create checkout session
    checkout = await _mk_checkout_session(
        merchant_id=lnk["merchant_id"],
        environment=lnk.get("environment", "sandbox"),
        amount_kobo=amount_kobo,
        customer_info={"name": req.customer_name or "Customer", "email": req.customer_email or ""},
        source_type="payment_link",
        source_id=attempt_id,
        redirect_url=lnk.get("redirect_url", ""),
        description=lnk["title"],
    )

    # Link checkout session to attempt
    await db.payment_link_attempts.update_one(
        {"attempt_id": attempt_id},
        {"$set": {"checkout_session_id": checkout["session_id"], "updated_at": _now()}}
    )

    logger.info(f"[PAYLINK] Initiated attempt={attempt_id} link={lnk['link_id']} amt=₦{amount_kobo/100:.2f}")
    return {
        "attempt_id": attempt_id,
        "checkout_session_id": checkout["session_id"],
        "checkout_url": checkout["checkout_url"],
        "bank_transfer": checkout["bank_transfer"],
        "expires_at": checkout["expires_at"],
    }


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@router.post("/v1/payment-links/{link_id}/send-reminder")
async def send_payment_reminder(link_id: str, request: Request):
    """Send a payment reminder email to the most recent non-paid customer for this link."""
    merchant = await get_current_merchant(request)
    if not merchant:
        raise HTTPException(401, "Not authenticated")

    lnk = await db.payment_links.find_one(
        {"link_id": link_id, "merchant_id": merchant["merchant_id"]}, {"_id": 0}
    )
    if not lnk:
        raise HTTPException(404, "Payment link not found")

    # Find the most recent non-paid attempt with a customer email
    attempts = await db.payment_link_attempts.find(
        {"link_id": link_id, "status": {"$ne": "paid"}, "customer_email": {"$nin": ["", None]}},
    ).sort("created_at", -1).limit(1).to_list(1)

    if not attempts:
        raise HTTPException(404, "No pending attempts with an email address found for this link")

    attempt = attempts[0]
    customer_email = attempt["customer_email"]
    customer_name = attempt.get("customer_name") or "Customer"
    amount_kobo = lnk.get("amount_kobo", 0)
    pay_url = f"{FRONTEND_URL.rstrip('/')}/pay/{lnk['code']}"

    html = _email_html(
        f"Payment Reminder — {lnk['title']}",
        [
            ("To", customer_name),
            ("Amount Due", f"₦{amount_kobo / 100:,.2f}"),
            ("Description", lnk.get("description") or lnk["title"]),
        ],
        f"Click to complete payment: {pay_url}"
    )

    asyncio.create_task(send_email(
        to=customer_email,
        subject=f"Payment Reminder: {lnk['title']}",
        html=html,
    ))

    logger.info(f"[PAYLINK] Reminder sent to {customer_email} for link {link_id}")
    return {"sent": True, "email": customer_email, "message": f"Reminder sent to {customer_email}"}


@router.get("/admin/payment-links")
async def admin_list_links(request: Request, page: int = 1):
    await _get_admin(request)
    limit = 30
    skip = (page - 1) * limit
    links = await db.payment_links.find({}, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.payment_links.count_documents({})
    return {"links": links, "total": total}
