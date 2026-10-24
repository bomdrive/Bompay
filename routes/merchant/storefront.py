"""
Storefront routes — store creation, management, and public catalogue.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from pydantic import BaseModel
from database import db
from core import logger, _cloudinary_upload
from .legacy import _get_admin

router = APIRouter()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _gen_store_id() -> str:
    return "store_" + uuid.uuid4().hex[:12]

def _gen_product_id() -> str:
    return "prod_" + uuid.uuid4().hex[:12]

async def _get_merchant_ctx(request: Request) -> dict:
    """Re-use merchant auth from legacy module."""
    from .legacy import get_current_merchant
    merchant = await get_current_merchant(request)
    if not merchant:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return merchant

def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:60] or "store"


# ─── MODELS ────────────────────────────────────────────────────────────────────

class CreateStore(BaseModel):
    name: str
    description: Optional[str] = ""
    category: Optional[str] = "general"
    contact_email: Optional[str] = ""
    contact_phone: Optional[str] = ""
    address: Optional[str] = ""
    theme_color: Optional[str] = "#064BCB"
    currency: Optional[str] = "NGN"
    slug: Optional[str] = None

class UpdateStore(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    theme_color: Optional[str] = None
    logo_url: Optional[str] = None
    banner_url: Optional[str] = None
    announcement: Optional[str] = None
    store_policies: Optional[str] = None
    shipping_policy: Optional[str] = None
    return_policy: Optional[str] = None
    social_links: Optional[dict] = None
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None


# ─── MERCHANT: STORE CRUD ──────────────────────────────────────────────────────

@router.post("/v1/stores")
async def create_store(req: CreateStore, request: Request):
    merchant = await _get_merchant_ctx(request)
    mid = merchant["merchant_id"]
    env = merchant.get("environment", "sandbox")

    # Limit: 3 stores per merchant
    count = await db.stores.count_documents({"merchant_id": mid, "is_deleted": {"$ne": True}})
    if count >= 3:
        raise HTTPException(status_code=400, detail="Maximum 3 stores allowed per merchant")

    raw_slug = req.slug or _slugify(req.name)
    # Ensure uniqueness
    slug = raw_slug
    suffix = 0
    while await db.stores.find_one({"slug": slug}):
        suffix += 1
        slug = f"{raw_slug}-{suffix}"

    store = {
        "store_id": _gen_store_id(),
        "merchant_id": mid,
        "environment": env,
        "name": req.name.strip(),
        "slug": slug,
        "description": req.description or "",
        "category": req.category or "general",
        "contact_email": req.contact_email or "",
        "contact_phone": req.contact_phone or "",
        "address": req.address or "",
        "theme_color": req.theme_color or "#064BCB",
        "currency": req.currency or "NGN",
        "logo_url": "",
        "banner_url": "",
        "announcement": "",
        "store_policies": "",
        "shipping_policy": "",
        "return_policy": "",
        "social_links": {},
        "seo_title": req.name,
        "seo_description": req.description or "",
        "status": "draft",
        "total_products": 0,
        "is_deleted": False,
        "created_at": _now(),
        "updated_at": _now(),
    }
    await db.stores.insert_one({**store, "_id": store["store_id"]})
    logger.info(f"[STORE] Created {store['store_id']} for merchant {mid}")
    return store


@router.get("/v1/stores")
async def list_stores(request: Request):
    merchant = await _get_merchant_ctx(request)
    mid = merchant["merchant_id"]
    stores = await db.stores.find(
        {"merchant_id": mid, "is_deleted": {"$ne": True}}, {"_id": 0}
    ).to_list(100)
    for s in stores:
        s["product_count"] = await db.products.count_documents(
            {"store_id": s["store_id"], "status": {"$ne": "archived"}}
        )
        s["order_count"] = await db.store_orders.count_documents(
            {"store_id": s["store_id"]}
        )
    return {"stores": stores, "total": len(stores)}


@router.get("/v1/stores/{store_id}")
async def get_store(store_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"]}, {"_id": 0}
    )
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    s["product_count"] = await db.products.count_documents({"store_id": store_id, "status": {"$ne": "archived"}})
    s["order_count"] = await db.store_orders.count_documents({"store_id": store_id})
    s["revenue_kobo"] = 0
    pipeline = [
        {"$match": {"store_id": store_id, "payment_status": "paid"}},
        {"$group": {"_id": None, "total": {"$sum": "$total_kobo"}}}
    ]
    agg = await db.store_orders.aggregate(pipeline).to_list(1)
    if agg:
        s["revenue_kobo"] = agg[0]["total"]
    return s


@router.patch("/v1/stores/{store_id}")
async def update_store(store_id: str, req: UpdateStore, request: Request):
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"]}
    )
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    update = {k: v for k, v in req.dict(exclude_none=True).items()}
    if "theme_color" in update:
        # Validate basic hex color format
        import re as _re
        if not _re.match(r"^#[0-9A-Fa-f]{6}$", update["theme_color"]):
            raise HTTPException(400, "theme_color must be a valid hex color like #064BCB")
    update["updated_at"] = _now()
    await db.stores.update_one({"store_id": store_id}, {"$set": update})
    return {"updated": True}


@router.post("/v1/stores/{store_id}/banner")
async def upload_store_banner(store_id: str, request: Request, file: UploadFile = File(...)):
    """Upload a banner image for the store (Cloudinary). Max 3 MB, JPEG/PNG/WebP only."""
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"], "is_deleted": {"$ne": True}}
    )
    if not s:
        raise HTTPException(404, "Store not found")
    data = await file.read()
    if len(data) > 3 * 1024 * 1024:
        raise HTTPException(400, "Banner image must be under 3 MB")
    if file.content_type not in ("image/jpeg", "image/png", "image/webp"):
        raise HTTPException(400, "Only JPEG, PNG or WebP images are allowed")
    public_id = f"bompay/store_banners/{store_id}"
    url = _cloudinary_upload(data, public_id)
    await db.stores.update_one(
        {"store_id": store_id},
        {"$set": {"banner_url": url, "updated_at": _now()}}
    )
    logger.info(f"[STORE] Banner uploaded for {store_id}")
    return {"banner_url": url}


@router.post("/v1/stores/{store_id}/publish")
async def publish_store(store_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"]}
    )
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    await db.stores.update_one(
        {"store_id": store_id},
        {"$set": {"status": "published", "updated_at": _now()}}
    )
    return {"published": True, "url": f"/store/{s['slug']}"}


@router.post("/v1/stores/{store_id}/unpublish")
async def unpublish_store(store_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"]}
    )
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    await db.stores.update_one(
        {"store_id": store_id},
        {"$set": {"status": "draft", "updated_at": _now()}}
    )
    return {"unpublished": True}


@router.get("/v1/stores/{store_id}/analytics")
async def store_analytics(store_id: str, request: Request, days: int = 30):
    merchant = await _get_merchant_ctx(request)
    s = await db.stores.find_one(
        {"store_id": store_id, "merchant_id": merchant["merchant_id"]}
    )
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")

    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    orders = await db.store_orders.find(
        {"store_id": store_id, "created_at": {"$gte": since}}, {"_id": 0}
    ).to_list(1000)

    paid = [o for o in orders if o.get("payment_status") == "paid"]
    gross = sum(o.get("total_kobo", 0) for o in paid)
    pending = [o for o in orders if o.get("payment_status") == "pending"]

    # Status breakdown
    statuses = {}
    for o in orders:
        st = o.get("order_status", "pending")
        statuses[st] = statuses.get(st, 0) + 1

    # Product breakdown
    product_sales = {}
    for o in paid:
        for item in o.get("items", []):
            pid = item.get("product_id")
            if pid:
                ps = product_sales.setdefault(pid, {"name": item.get("product_name", "?"), "qty": 0, "revenue_kobo": 0})
                ps["qty"] += item.get("quantity", 1)
                ps["revenue_kobo"] += item.get("unit_price_kobo", 0) * item.get("quantity", 1)

    top_products = sorted(product_sales.values(), key=lambda x: x["revenue_kobo"], reverse=True)[:5]

    # Daily breakdown for charts
    daily: dict = {}
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        daily[d] = {"date": d, "revenue_kobo": 0, "orders": 0, "paid_orders": 0}
    for o in orders:
        d = o.get("created_at", "")[:10]
        if d in daily:
            daily[d]["orders"] += 1
            if o.get("payment_status") == "paid":
                daily[d]["revenue_kobo"] += o.get("total_kobo", 0)
                daily[d]["paid_orders"] += 1
    daily_stats = list(daily.values())

    return {
        "store_id": store_id,
        "days": days,
        "gross_revenue_kobo": gross,
        "paid_orders": len(paid),
        "pending_orders": len(pending),
        "total_orders": len(orders),
        "order_statuses": statuses,
        "top_products": top_products,
        "avg_order_kobo": gross // len(paid) if paid else 0,
        "daily_stats": daily_stats,
    }


# ─── PUBLIC STORE ──────────────────────────────────────────────────────────────

@router.get("/store/{slug}")
async def public_store(slug: str):
    s = await db.stores.find_one({"slug": slug, "status": "published"}, {"_id": 0})
    if not s:
        raise HTTPException(status_code=404, detail="Store not found or not published")
    # Strip private fields
    s.pop("merchant_id", None)
    return s


@router.get("/store/{slug}/products")
async def public_store_products(slug: str, page: int = 1, limit: int = 20,
                                 category: str = None, sort: str = "newest"):
    s = await db.stores.find_one({"slug": slug, "status": "published"})
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    filt: dict = {"store_id": s["store_id"], "status": "active"}
    if category:
        filt["category"] = category
    sort_field = "created_at" if sort == "newest" else "price_kobo" if "price" in sort else "created_at"
    sort_dir = -1 if sort != "price_asc" else 1
    skip = (page - 1) * limit
    products = await db.products.find(filt, {"_id": 0, "cost_kobo": 0}) \
        .sort(sort_field, sort_dir).skip(skip).limit(limit).to_list(limit)
    total = await db.products.count_documents(filt)
    return {"products": products, "total": total, "page": page, "pages": (total + limit - 1) // limit}


@router.get("/store/{slug}/product/{product_slug}")
async def public_store_product(slug: str, product_slug: str):
    s = await db.stores.find_one({"slug": slug, "status": "published"})
    if not s:
        raise HTTPException(status_code=404, detail="Store not found")
    p = await db.products.find_one(
        {"store_id": s["store_id"], "slug": product_slug, "status": "active"},
        {"_id": 0, "cost_kobo": 0}
    )
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    # Related products
    related = await db.products.find(
        {"store_id": s["store_id"], "category": p.get("category"), "status": "active",
         "product_id": {"$ne": p["product_id"]}},
        {"_id": 0, "cost_kobo": 0}
    ).limit(4).to_list(4)
    return {"product": p, "related": related, "store": {k: s[k] for k in ["name", "slug", "logo_url", "theme_color"]}}


# ─── ADMIN ─────────────────────────────────────────────────────────────────────

@router.get("/admin/stores")
async def admin_list_stores(request: Request, status: str = "", page: int = 1):
    await _get_admin(request)
    filt: dict = {"is_deleted": {"$ne": True}}
    if status:
        filt["status"] = status
    limit = 20
    skip = (page - 1) * limit
    stores = await db.stores.find(filt, {"_id": 0}) \
        .sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.stores.count_documents(filt)
    return {"stores": stores, "total": total, "page": page}


@router.put("/admin/stores/{store_id}/status")
async def admin_update_store_status(store_id: str, body: dict, request: Request):
    await _get_admin(request)
    new_status = body.get("status")
    if new_status not in ("published", "draft", "suspended", "archived"):
        raise HTTPException(status_code=400, detail="Invalid status")
    await db.stores.update_one({"store_id": store_id}, {"$set": {"status": new_status, "updated_at": _now()}})
    return {"updated": True}
