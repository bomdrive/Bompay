"""
Discount Codes — merchant promo code management and public validation.
Supports: percentage off and flat kobo off.
"""
import uuid, re
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from database import db
from core import logger
from .legacy import get_current_merchant, _get_admin

router = APIRouter()

DISCOUNT_TYPES = {"percentage", "flat"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_merchant_ctx(request: Request) -> dict:
    m = await get_current_merchant(request)
    if not m:
        raise HTTPException(401, "Not authenticated")
    return m


async def _own_store(store_id: str, merchant_id: str):
    s = await db.stores.find_one({"store_id": store_id, "merchant_id": merchant_id, "is_deleted": {"$ne": True}})
    if not s:
        raise HTTPException(404, "Store not found")
    return s


# ─── MODELS ────────────────────────────────────────────────────────────────────

class CreateDiscount(BaseModel):
    code: str                           # e.g. SAVE10 — will be uppercased
    discount_type: str                  # "percentage" or "flat"
    value: int                          # percentage (1–100) OR flat amount in kobo
    description: Optional[str] = ""
    min_order_kobo: Optional[int] = 0
    max_discount_kobo: Optional[int] = None  # cap for percentage discounts
    max_uses: Optional[int] = None           # None = unlimited
    expires_in_days: Optional[int] = None    # None = no expiry


class UpdateDiscount(BaseModel):
    description: Optional[str] = None
    min_order_kobo: Optional[int] = None
    max_discount_kobo: Optional[int] = None
    max_uses: Optional[int] = None
    is_active: Optional[bool] = None


# ─── MERCHANT CRUD ─────────────────────────────────────────────────────────────

@router.post("/v1/stores/{store_id}/discounts")
async def create_discount(store_id: str, req: CreateDiscount, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])

    code = re.sub(r"[^A-Z0-9]", "", req.code.upper().strip())[:20]
    if not code or len(code) < 2:
        raise HTTPException(400, "Discount code must be at least 2 alphanumeric characters")
    if req.discount_type not in DISCOUNT_TYPES:
        raise HTTPException(400, "discount_type must be 'percentage' or 'flat'")
    if req.discount_type == "percentage" and not (1 <= req.value <= 100):
        raise HTTPException(400, "Percentage value must be between 1 and 100")
    if req.discount_type == "flat" and req.value < 100:
        raise HTTPException(400, "Flat discount must be at least ₦1 (100 kobo)")

    # Unique within store
    existing = await db.discount_codes.find_one({"store_id": store_id, "code": code})
    if existing:
        raise HTTPException(400, f"Discount code '{code}' already exists in this store")

    count = await db.discount_codes.count_documents({"store_id": store_id})
    if count >= 100:
        raise HTTPException(400, "Maximum 100 discount codes per store")

    expires_at = None
    if req.expires_in_days and req.expires_in_days > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=req.expires_in_days)).isoformat()

    discount_id = "disc_" + uuid.uuid4().hex[:10]
    now = _now()
    doc = {
        "discount_id": discount_id,
        "store_id": store_id,
        "merchant_id": merchant["merchant_id"],
        "code": code,
        "discount_type": req.discount_type,
        "value": req.value,
        "description": req.description or "",
        "min_order_kobo": req.min_order_kobo or 0,
        "max_discount_kobo": req.max_discount_kobo,
        "max_uses": req.max_uses,
        "uses_count": 0,
        "expires_at": expires_at,
        "is_active": True,
        "created_at": now,
        "updated_at": now,
    }
    await db.discount_codes.insert_one({**doc, "_id": discount_id})
    logger.info(f"[DISCOUNT] Created {code} for store {store_id}")
    return doc


@router.get("/v1/stores/{store_id}/discounts")
async def list_discounts(store_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    discounts = await db.discount_codes.find(
        {"store_id": store_id}, {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    return {"discounts": discounts, "total": len(discounts)}


@router.patch("/v1/stores/{store_id}/discounts/{discount_id}")
async def update_discount(store_id: str, discount_id: str, req: UpdateDiscount, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    d = await db.discount_codes.find_one({"discount_id": discount_id, "store_id": store_id})
    if not d:
        raise HTTPException(404, "Discount not found")
    update = {k: v for k, v in req.dict(exclude_none=True).items()}
    update["updated_at"] = _now()
    await db.discount_codes.update_one({"discount_id": discount_id}, {"$set": update})
    return {"updated": True}


@router.delete("/v1/stores/{store_id}/discounts/{discount_id}")
async def delete_discount(store_id: str, discount_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    d = await db.discount_codes.find_one({"discount_id": discount_id, "store_id": store_id})
    if not d:
        raise HTTPException(404, "Discount not found")
    await db.discount_codes.delete_one({"discount_id": discount_id})
    return {"deleted": True}


# ─── PUBLIC: VALIDATE DISCOUNT ─────────────────────────────────────────────────

@router.post("/store/{slug}/validate-discount")
async def validate_discount(slug: str, body: dict):
    """
    Public: validate a discount code for a cart.
    Returns: {valid, discount_kobo, message}
    """
    code = (body.get("code") or "").upper().strip()
    subtotal_kobo = int(body.get("subtotal_kobo") or 0)

    if not code:
        raise HTTPException(400, "Code is required")

    store = await db.stores.find_one({"slug": slug, "status": "published"})
    if not store:
        raise HTTPException(404, "Store not found")

    d = await db.discount_codes.find_one({
        "store_id": store["store_id"],
        "code": code,
        "is_active": True,
    })
    if not d:
        raise HTTPException(400, "Invalid or inactive discount code")

    # Check expiry
    if d.get("expires_at") and d["expires_at"] < _now():
        raise HTTPException(400, "This discount code has expired")

    # Check usage limit
    if d.get("max_uses") is not None and d.get("uses_count", 0) >= d["max_uses"]:
        raise HTTPException(400, "This discount code has reached its usage limit")

    # Check minimum order
    min_order = d.get("min_order_kobo") or 0
    if subtotal_kobo < min_order and min_order > 0:
        raise HTTPException(400, f"Minimum order ₦{min_order/100:,.0f} required for this code")

    # Calculate discount
    if d["discount_type"] == "percentage":
        raw_discount = int(subtotal_kobo * d["value"] / 100)
        max_cap = d.get("max_discount_kobo")
        discount_kobo = min(raw_discount, max_cap) if max_cap else raw_discount
    else:  # flat
        discount_kobo = min(d["value"], subtotal_kobo)

    return {
        "valid": True,
        "discount_id": d["discount_id"],
        "code": d["code"],
        "discount_type": d["discount_type"],
        "value": d["value"],
        "discount_kobo": discount_kobo,
        "description": d.get("description", ""),
        "message": f"{d['value']}% off" if d["discount_type"] == "percentage" else f"₦{discount_kobo/100:,.0f} off",
    }
