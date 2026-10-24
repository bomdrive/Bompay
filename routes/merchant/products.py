"""
Products routes — CRUD, variants, inventory, and Cloudinary image upload.
Prefix: all routes registered under /api (from server.py include_router prefix="/api")
"""
import re, uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from pydantic import BaseModel
from database import db
from core import logger, _cloudinary_upload, _cloudinary_delete, APP_NAME
from .legacy import get_current_merchant, _get_admin

router = APIRouter()

ALLOWED_IMG_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_IMG_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_IMAGES = 6  # per product


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_pid() -> str:
    return "prod_" + uuid.uuid4().hex[:12]


def _gen_vid() -> str:
    return "var_" + uuid.uuid4().hex[:8]


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80] or "product"


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


async def _own_product(product_id: str, merchant_id: str):
    p = await db.products.find_one({"product_id": product_id, "merchant_id": merchant_id, "is_deleted": {"$ne": True}})
    if not p:
        raise HTTPException(404, "Product not found")
    return p


# ─── MODELS ────────────────────────────────────────────────────────────────────

class CreateProduct(BaseModel):
    name: str
    description: Optional[str] = ""
    category: Optional[str] = "general"
    price_kobo: int                            # selling price in kobo (integer only)
    compare_at_price_kobo: Optional[int] = 0  # crossed-out/original price
    cost_kobo: Optional[int] = 0              # internal cost (not exposed publicly)
    sku: Optional[str] = ""
    track_inventory: Optional[bool] = True
    inventory_quantity: Optional[int] = 0
    low_stock_threshold: Optional[int] = 5
    allow_backorder: Optional[bool] = False
    product_type: Optional[str] = "physical"  # physical/digital/service
    weight_grams: Optional[int] = 0
    tags: Optional[List[str]] = []
    seo_title: Optional[str] = ""
    seo_description: Optional[str] = ""


class UpdateProduct(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    price_kobo: Optional[int] = None
    compare_at_price_kobo: Optional[int] = None
    cost_kobo: Optional[int] = None
    sku: Optional[str] = None
    track_inventory: Optional[bool] = None
    inventory_quantity: Optional[int] = None
    low_stock_threshold: Optional[int] = None
    allow_backorder: Optional[bool] = None
    product_type: Optional[str] = None
    weight_grams: Optional[int] = None
    tags: Optional[List[str]] = None
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None


class CreateVariant(BaseModel):
    name: str                           # e.g. "Red / Large"
    options: Optional[dict] = {}        # e.g. {"color": "Red", "size": "Large"}
    price_kobo: int                     # variant price in kobo
    sku: Optional[str] = ""
    inventory_quantity: Optional[int] = 0
    is_available: Optional[bool] = True


class UpdateVariant(BaseModel):
    name: Optional[str] = None
    options: Optional[dict] = None
    price_kobo: Optional[int] = None
    sku: Optional[str] = None
    inventory_quantity: Optional[int] = None
    is_available: Optional[bool] = None


class StockAdjust(BaseModel):
    quantity: int           # absolute new quantity (can be 0)
    reason: Optional[str] = ""


# ─── PRODUCT CRUD ──────────────────────────────────────────────────────────────

@router.post("/v1/stores/{store_id}/products")
async def create_product(store_id: str, req: CreateProduct, request: Request):
    merchant = await _get_merchant_ctx(request)
    mid = merchant["merchant_id"]
    await _own_store(store_id, mid)

    if req.price_kobo <= 0:
        raise HTTPException(400, "price_kobo must be positive")

    # Limit: 500 products per store
    count = await db.products.count_documents({"store_id": store_id, "is_deleted": {"$ne": True}})
    if count >= 500:
        raise HTTPException(400, "Maximum 500 products per store")

    raw_slug = _slugify(req.name)
    slug = raw_slug
    n = 0
    while await db.products.find_one({"store_id": store_id, "slug": slug}):
        n += 1
        slug = f"{raw_slug}-{n}"

    product_id = _gen_pid()
    now = _now()
    doc = {
        "product_id": product_id,
        "store_id": store_id,
        "merchant_id": mid,
        "environment": merchant.get("environment", "sandbox"),
        "name": req.name.strip(),
        "slug": slug,
        "description": req.description or "",
        "category": req.category or "general",
        "price_kobo": req.price_kobo,
        "compare_at_price_kobo": req.compare_at_price_kobo or 0,
        "cost_kobo": req.cost_kobo or 0,
        "currency": "NGN",
        "sku": req.sku or "",
        "track_inventory": req.track_inventory if req.track_inventory is not None else True,
        "inventory_quantity": max(0, req.inventory_quantity or 0),
        "reserved_quantity": 0,
        "low_stock_threshold": req.low_stock_threshold or 5,
        "allow_backorder": req.allow_backorder or False,
        "product_type": req.product_type or "physical",
        "weight_grams": req.weight_grams or 0,
        "tags": req.tags or [],
        "images": [],
        "has_variants": False,
        "variants": [],
        "status": "draft",
        "seo_title": req.seo_title or req.name,
        "seo_description": req.seo_description or "",
        "is_deleted": False,
        "created_at": now,
        "updated_at": now,
    }
    await db.products.insert_one({**doc, "_id": product_id})
    # Update store product count
    await db.stores.update_one({"store_id": store_id}, {"$inc": {"total_products": 1}})
    doc.pop("cost_kobo", None)  # don't expose cost
    logger.info(f"[PRODUCT] Created {product_id} in store {store_id}")
    return doc


@router.get("/v1/stores/{store_id}/products")
async def list_products(store_id: str, request: Request,
                         page: int = 1, limit: int = 50,
                         status: str = "", category: str = ""):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    filt: dict = {"store_id": store_id, "is_deleted": {"$ne": True}}
    if status:
        filt["status"] = status
    if category:
        filt["category"] = category
    skip = (page - 1) * limit
    products = await db.products.find(filt, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.products.count_documents(filt)
    return {"products": products, "total": total, "page": page, "pages": (total + limit - 1) // limit}


@router.get("/v1/stores/{store_id}/products/{product_id}")
async def get_product(store_id: str, product_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id}, {"_id": 0})
    if not p:
        raise HTTPException(404, "Product not found")
    return p


@router.patch("/v1/stores/{store_id}/products/{product_id}")
async def update_product(store_id: str, product_id: str, req: UpdateProduct, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")

    update = {k: v for k, v in req.dict(exclude_none=True).items()}
    if "price_kobo" in update and update["price_kobo"] <= 0:
        raise HTTPException(400, "price_kobo must be positive")
    if "name" in update:
        update["name"] = update["name"].strip()
    update["updated_at"] = _now()
    await db.products.update_one({"product_id": product_id}, {"$set": update})
    return {"updated": True}


@router.post("/v1/stores/{store_id}/products/{product_id}/publish")
async def publish_product(store_id: str, product_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    await db.products.update_one({"product_id": product_id},
                                  {"$set": {"status": "active", "updated_at": _now()}})
    return {"published": True}


@router.post("/v1/stores/{store_id}/products/{product_id}/archive")
async def archive_product(store_id: str, product_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    await db.products.update_one({"product_id": product_id},
                                  {"$set": {"status": "archived", "updated_at": _now()}})
    return {"archived": True}


@router.delete("/v1/stores/{store_id}/products/{product_id}")
async def delete_product(store_id: str, product_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    await db.products.update_one({"product_id": product_id},
                                  {"$set": {"is_deleted": True, "status": "archived", "updated_at": _now()}})
    await db.stores.update_one({"store_id": store_id}, {"$inc": {"total_products": -1}})
    return {"deleted": True}


# ─── PRODUCT IMAGES ───────────────────────────────────────────────────────────

@router.post("/v1/stores/{store_id}/products/{product_id}/images")
async def upload_product_image(store_id: str, product_id: str, request: Request,
                                file: UploadFile = File(...)):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    if len(p.get("images", [])) >= MAX_IMAGES:
        raise HTTPException(400, f"Maximum {MAX_IMAGES} images per product")
    if file.content_type not in ALLOWED_IMG_TYPES:
        raise HTTPException(400, "Only JPEG, PNG, WebP images are allowed")

    data = await file.read()
    if len(data) > MAX_IMG_SIZE:
        raise HTTPException(400, "Image must be under 5 MB")
    if len(data) < 100:
        raise HTTPException(400, "Invalid image file")

    mid = merchant["merchant_id"]
    img_idx = len(p.get("images", []))
    public_id = f"{APP_NAME}/stores/{store_id}/products/{product_id}/img_{img_idx}_{uuid.uuid4().hex[:6]}"
    url = _cloudinary_upload(data, public_id)

    image_entry = {
        "url": url,
        "public_id": public_id,
        "alt": p["name"],
        "is_primary": img_idx == 0,
    }
    await db.products.update_one(
        {"product_id": product_id},
        {"$push": {"images": image_entry}, "$set": {"updated_at": _now()}}
    )
    logger.info(f"[PRODUCT] Image uploaded for {product_id}: {url}")
    return {"image": image_entry, "url": url}


@router.delete("/v1/stores/{store_id}/products/{product_id}/images/{img_public_id:path}")
async def delete_product_image(store_id: str, product_id: str, img_public_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    try:
        _cloudinary_delete(img_public_id)
    except Exception as e:
        logger.warning(f"[PRODUCT] Cloudinary delete failed: {e}")
    await db.products.update_one(
        {"product_id": product_id},
        {"$pull": {"images": {"public_id": img_public_id}}, "$set": {"updated_at": _now()}}
    )
    return {"deleted": True}


# ─── VARIANTS ─────────────────────────────────────────────────────────────────

@router.post("/v1/stores/{store_id}/products/{product_id}/variants")
async def add_variant(store_id: str, product_id: str, req: CreateVariant, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    if req.price_kobo <= 0:
        raise HTTPException(400, "price_kobo must be positive")

    variant = {
        "variant_id": _gen_vid(),
        "name": req.name.strip(),
        "options": req.options or {},
        "price_kobo": req.price_kobo,
        "sku": req.sku or "",
        "inventory_quantity": max(0, req.inventory_quantity or 0),
        "reserved_quantity": 0,
        "is_available": req.is_available if req.is_available is not None else True,
        "created_at": _now(),
    }
    await db.products.update_one(
        {"product_id": product_id},
        {"$push": {"variants": variant}, "$set": {"has_variants": True, "updated_at": _now()}}
    )
    return variant


@router.patch("/v1/stores/{store_id}/products/{product_id}/variants/{variant_id}")
async def update_variant(store_id: str, product_id: str, variant_id: str,
                          req: UpdateVariant, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    variants = p.get("variants", [])
    idx = next((i for i, v in enumerate(variants) if v["variant_id"] == variant_id), None)
    if idx is None:
        raise HTTPException(404, "Variant not found")

    update_fields = {k: v for k, v in req.dict(exclude_none=True).items()}
    if "price_kobo" in update_fields and update_fields["price_kobo"] <= 0:
        raise HTTPException(400, "price_kobo must be positive")
    set_ops = {f"variants.{idx}.{k}": v for k, v in update_fields.items()}
    set_ops["updated_at"] = _now()
    await db.products.update_one({"product_id": product_id}, {"$set": set_ops})
    return {"updated": True}


@router.delete("/v1/stores/{store_id}/products/{product_id}/variants/{variant_id}")
async def delete_variant(store_id: str, product_id: str, variant_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    await db.products.update_one(
        {"product_id": product_id},
        {"$pull": {"variants": {"variant_id": variant_id}}, "$set": {"updated_at": _now()}}
    )
    # If no variants remain, clear has_variants
    p_updated = await db.products.find_one({"product_id": product_id})
    if p_updated and not p_updated.get("variants"):
        await db.products.update_one({"product_id": product_id}, {"$set": {"has_variants": False}})
    return {"deleted": True}


# ─── STOCK MANAGEMENT ─────────────────────────────────────────────────────────

@router.post("/v1/stores/{store_id}/products/{product_id}/stock")
async def update_stock(store_id: str, product_id: str, req: StockAdjust, request: Request):
    merchant = await _get_merchant_ctx(request)
    await _own_store(store_id, merchant["merchant_id"])
    p = await db.products.find_one({"product_id": product_id, "store_id": store_id})
    if not p:
        raise HTTPException(404, "Product not found")
    if req.quantity < 0:
        raise HTTPException(400, "quantity must be >= 0")
    await db.products.update_one(
        {"product_id": product_id},
        {"$set": {"inventory_quantity": req.quantity, "updated_at": _now()}}
    )
    return {"inventory_quantity": req.quantity}


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@router.get("/admin/products")
async def admin_list_products(request: Request, store_id: str = "", page: int = 1):
    await _get_admin(request)
    filt: dict = {"is_deleted": {"$ne": True}}
    if store_id:
        filt["store_id"] = store_id
    limit = 50
    skip = (page - 1) * limit
    products = await db.products.find(filt, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.products.count_documents(filt)
    return {"products": products, "total": total}
