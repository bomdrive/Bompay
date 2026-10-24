"""
Orders routes — storefront order management and public cart checkout.
"""
import secrets, uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from database import db
from core import logger, send_email
from .legacy import get_current_merchant, _get_admin
from .common import _mk_checkout_session, _now

router = APIRouter()


def _gen_oid() -> str:
    return "ord_" + uuid.uuid4().hex[:12]


def _order_number(store_id: str) -> str:
    """Generate human-readable order number."""
    return f"BOM-{secrets.token_hex(3).upper()}"


# ─── MODELS ────────────────────────────────────────────────────────────────────

class OrderStatusUpdate(BaseModel):
    status: str                          # processing/fulfilling/shipped/delivered/cancelled
    notes: Optional[str] = ""
    tracking_number: Optional[str] = ""
    courier: Optional[str] = ""


class CartItem(BaseModel):
    product_id: str
    variant_id: Optional[str] = ""
    quantity: int


class CustomerInfo(BaseModel):
    name: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    address: Optional[str] = ""
    city: Optional[str] = ""
    state: Optional[str] = ""


class CartCheckout(BaseModel):
    items: List[CartItem]
    customer: CustomerInfo
    notes: Optional[str] = ""
    discount_code: Optional[str] = ""   # optional promo code


VALID_TRANSITIONS = {
    "processing": {"fulfilling", "cancelled"},
    "fulfilling": {"shipped", "cancelled"},
    "shipped": {"delivered"},
    "delivered": set(),
    "cancelled": set(),
    "pending": {"processing", "cancelled"},
}


# ─── EMAIL HELPERS ─────────────────────────────────────────────────────────────

def _fmt(k):
    return "{:,.2f}".format(k / 100)


def _order_confirmation_html(order: dict, store_name: str) -> str:
    rows = []
    for i in order.get("items", []):
        vname = f' ({i["variant_name"]})' if i.get("variant_name") else ""
        rows.append(
            f'<tr><td style="padding:6px 0;font-size:13px;color:#334155">'
            f'{i.get("product_name","")}{vname} x{i.get("quantity",1)}</td>'
            f'<td style="padding:6px 0;font-size:13px;color:#0f172a;font-weight:600;text-align:right">'
            f'&#8358;{_fmt(i.get("subtotal_kobo",0))}</td></tr>'
        )
    items_rows = "".join(rows)
    discount_row = ""
    if order.get("discount_kobo", 0) > 0:
        discount_row = (
            f'<tr><td style="font-size:13px;color:#16a34a">Discount</td>'
            f'<td style="font-size:13px;color:#16a34a;font-weight:700;text-align:right">'
            f'&minus;&#8358;{_fmt(order["discount_kobo"])}</td></tr>'
        )
    cname = order.get("customer", {}).get("name", "there")
    caddr = order.get("customer", {}).get("address", "")
    ccity = order.get("customer", {}).get("city", "")
    cstate = order.get("customer", {}).get("state", "")
    onum = order.get("order_number", "")
    total = _fmt(order.get("total_kobo", 0))
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr><td style="background:#064BCB;padding:28px 24px 20px;border-radius:12px 12px 0 0">
    <h2 style="margin:0;color:#fff;font-size:20px;font-family:sans-serif">{store_name}</h2>
    <p style="margin:6px 0 0;color:#bfdbfe;font-size:13px;font-family:sans-serif">Order Confirmation</p>
  </td></tr>
  <tr><td style="background:#fff;padding:24px;border-radius:0 0 12px 12px;font-family:sans-serif">
    <p style="margin:0 0 4px;font-size:15px;color:#0f172a;font-weight:600">Hi {cname},</p>
    <p style="margin:0 0 20px;font-size:13px;color:#64748b">Thanks for your order! Here's a summary:</p>
    <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em">Order {onum}</p>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #e2e8f0;margin-bottom:16px">
      {items_rows}
      {discount_row}
      <tr><td style="padding:10px 0 0;font-size:14px;font-weight:700;color:#0f172a;border-top:1px solid #e2e8f0">Total</td>
          <td style="padding:10px 0 0;font-size:14px;font-weight:700;color:#064BCB;text-align:right;border-top:1px solid #e2e8f0">&#8358;{total}</td></tr>
    </table>
    <p style="margin:0 0 4px;font-size:12px;color:#94a3b8">Delivery to: {caddr} {ccity} {cstate}</p>
    <p style="font-size:11px;color:#cbd5e1;margin-top:20px">Questions? Contact {store_name}. Secured by BOMPAY.</p>
  </td></tr>
</table>"""


def _shipping_html(order: dict, store_name: str) -> str:
    tracking = order.get("tracking_number", "")
    courier = order.get("courier", "")
    onum = order.get("order_number", "")
    cname = order.get("customer", {}).get("name", "there")
    tracking_row = f'<p style="font-size:13px;color:#0f172a"><strong>Tracking Number:</strong> {tracking}</p>' if tracking else ""
    courier_row = f'<p style="font-size:13px;color:#0f172a"><strong>Courier:</strong> {courier}</p>' if courier else ""
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr><td style="background:#064BCB;padding:28px 24px 20px;border-radius:12px 12px 0 0">
    <h2 style="margin:0;color:#fff;font-size:20px;font-family:sans-serif">{store_name}</h2>
    <p style="margin:6px 0 0;color:#bfdbfe;font-size:13px;font-family:sans-serif">Your order has shipped!</p>
  </td></tr>
  <tr><td style="background:#fff;padding:24px;border-radius:0 0 12px 12px;font-family:sans-serif">
    <p style="margin:0 0 4px;font-size:15px;color:#0f172a;font-weight:600">Hi {cname},</p>
    <p style="margin:0 0 20px;font-size:13px;color:#64748b">Great news — order <strong>{onum}</strong> is on its way!</p>
    {tracking_row}
    {courier_row}
    <p style="margin-top:20px;font-size:11px;color:#cbd5e1">Secured by BOMPAY.</p>
  </td></tr>
</table>"""


# ─── MERCHANT: ORDER MANAGEMENT ───────────────────────────────────────────────

@router.get("/v1/orders")
async def list_all_orders(request: Request, page: int = 1, limit: int = 20,
                            status: str = "", store_id: str = ""):
    merchant = await _get_merchant_ctx(request)
    filt: dict = {"merchant_id": merchant["merchant_id"], "is_deleted": {"$ne": True}}
    if status:
        filt["order_status"] = status
    if store_id:
        filt["store_id"] = store_id
    skip = (page - 1) * limit
    orders = await db.store_orders.find(filt, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.store_orders.count_documents(filt)
    return {"orders": orders, "total": total, "page": page,
            "pages": (total + limit - 1) // limit}


@router.get("/v1/stores/{store_id}/orders")
async def list_store_orders(store_id: str, request: Request, page: int = 1,
                              limit: int = 20, status: str = ""):
    merchant = await _get_merchant_ctx(request)
    filt: dict = {"store_id": store_id, "merchant_id": merchant["merchant_id"],
                  "is_deleted": {"$ne": True}}
    if status:
        filt["order_status"] = status
    skip = (page - 1) * limit
    orders = await db.store_orders.find(filt, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.store_orders.count_documents(filt)
    return {"orders": orders, "total": total, "page": page,
            "pages": (total + limit - 1) // limit}


@router.get("/v1/orders/{order_id}")
async def get_order(order_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    o = await db.store_orders.find_one(
        {"order_id": order_id, "merchant_id": merchant["merchant_id"]}, {"_id": 0}
    )
    if not o:
        raise HTTPException(404, "Order not found")
    return o


@router.patch("/v1/orders/{order_id}/status")
async def update_order_status(order_id: str, req: OrderStatusUpdate, request: Request):
    merchant = await _get_merchant_ctx(request)
    o = await db.store_orders.find_one(
        {"order_id": order_id, "merchant_id": merchant["merchant_id"]}
    )
    if not o:
        raise HTTPException(404, "Order not found")
    current = o.get("order_status", "pending")
    allowed = VALID_TRANSITIONS.get(current, set())
    if req.status not in allowed:
        raise HTTPException(400, f"Cannot transition from '{current}' to '{req.status}'")

    update: dict = {"order_status": req.status, "updated_at": _now()}
    if req.notes:
        update["fulfillment_notes"] = req.notes
    if req.tracking_number:
        update["tracking_number"] = req.tracking_number
    if req.courier:
        update["courier"] = req.courier
    if req.status == "delivered":
        update["delivered_at"] = _now()
    if req.status == "cancelled":
        update["cancelled_at"] = _now()
        # Release inventory reservation if order was never paid
        if o.get("payment_status") == "pending":
            for item in o.get("items", []):
                pid = item.get("product_id")
                qty = item.get("quantity", 1)
                vid = item.get("variant_id")
                if vid:
                    await db.products.update_one(
                        {"product_id": pid, "variants.variant_id": vid},
                        {"$inc": {"variants.$.reserved_quantity": -qty}}
                    )
                else:
                    await db.products.update_one(
                        {"product_id": pid},
                        {"$inc": {"reserved_quantity": -qty}}
                    )

    await db.store_orders.update_one({"order_id": order_id}, {"$set": update})

    # Fire shipping notification email
    if req.status == "shipped":
        o_updated = await db.store_orders.find_one({"order_id": order_id})
        if o_updated:
            customer_email = (o_updated.get("customer") or {}).get("email", "")
            if customer_email:
                import asyncio
                asyncio.create_task(send_email(
                    to=customer_email,
                    subject=f"Your order {o_updated.get('order_number', '')} has shipped — {o_updated.get('store_name', '')}",
                    html=_shipping_html(o_updated, o_updated.get("store_name", "Store")),
                ))

    return {"updated": True, "order_status": req.status}


@router.get("/v1/orders/{order_id}/status")
async def get_order_status_public(order_id: str):
    """Public endpoint for order status polling after checkout."""
    o = await db.store_orders.find_one({"order_id": order_id}, {"_id": 0})
    if not o:
        raise HTTPException(404, "Order not found")
    return {
        "order_id": order_id,
        "order_number": o.get("order_number", ""),
        "payment_status": o.get("payment_status", "pending"),
        "order_status": o.get("order_status", "pending"),
        "total_kobo": o.get("total_kobo", 0),
        "created_at": o.get("created_at", ""),
    }


# ─── PUBLIC: CART CHECKOUT ─────────────────────────────────────────────────────

@router.post("/store/{slug}/cart/checkout")
async def cart_checkout(slug: str, req: CartCheckout):
    """
    Public cart checkout — validates cart, reserves inventory,
    creates store_order + checkout session, returns checkout URL.
    No merchant auth required (customer-facing).
    """
    # 1. Load store
    store = await db.stores.find_one({"slug": slug, "status": "published", "is_deleted": {"$ne": True}})
    if not store:
        raise HTTPException(404, "Store not found or not published")

    if not req.items:
        raise HTTPException(400, "Cart is empty")
    if not req.customer.name or len(req.customer.name.strip()) < 2:
        raise HTTPException(400, "Customer name is required")

    # 2. Validate each item: load product from DB, check status, check inventory
    order_items = []
    subtotal_kobo = 0

    for ci in req.items:
        if ci.quantity < 1:
            raise HTTPException(400, "Quantity must be at least 1")
        if ci.quantity > 100:
            raise HTTPException(400, "Quantity cannot exceed 100 per item")

        p = await db.products.find_one({
            "product_id": ci.product_id,
            "store_id": store["store_id"],
            "status": "active",
            "is_deleted": {"$ne": True}
        })
        if not p:
            raise HTTPException(400, f"Product {ci.product_id} is not available")

        unit_price_kobo = p["price_kobo"]
        variant_name = ""

        if ci.variant_id:
            # Find variant
            variants = p.get("variants", [])
            variant = next((v for v in variants if v["variant_id"] == ci.variant_id), None)
            if not variant:
                raise HTTPException(400, f"Variant {ci.variant_id} not found")
            if not variant.get("is_available", True):
                raise HTTPException(400, f"Variant '{variant['name']}' is not available")
            unit_price_kobo = variant["price_kobo"]
            variant_name = variant["name"]
            # Check variant inventory
            if p.get("track_inventory"):
                avail = variant.get("inventory_quantity", 0) - variant.get("reserved_quantity", 0)
                if not p.get("allow_backorder") and avail < ci.quantity:
                    raise HTTPException(400, f"Insufficient stock for variant '{variant['name']}'")
        else:
            if p.get("track_inventory"):
                avail = p.get("inventory_quantity", 0) - p.get("reserved_quantity", 0)
                if not p.get("allow_backorder") and avail < ci.quantity:
                    raise HTTPException(400, f"Insufficient stock for '{p['name']}'")

        item_subtotal = unit_price_kobo * ci.quantity
        order_items.append({
            "product_id": ci.product_id,
            "variant_id": ci.variant_id or "",
            "product_name": p["name"],
            "variant_name": variant_name,
            "quantity": ci.quantity,
            "unit_price_kobo": unit_price_kobo,
            "subtotal_kobo": item_subtotal,
            "product_image": p["images"][0]["url"] if p.get("images") else "",
        })
        subtotal_kobo += item_subtotal

    if subtotal_kobo < 100:
        raise HTTPException(400, "Order total must be at least ₦1.00")

    # 3a. Apply discount code if provided
    discount_kobo = 0
    applied_discount_code = ""
    discount_id = ""
    if req.discount_code:
        code = req.discount_code.upper().strip()
        disc = await db.discount_codes.find_one({
            "store_id": store["store_id"], "code": code, "is_active": True
        })
        if not disc:
            raise HTTPException(400, f"Discount code '{code}' is invalid or inactive")
        if disc.get("expires_at") and disc["expires_at"] < _now():
            raise HTTPException(400, "Discount code has expired")
        if disc.get("max_uses") is not None and disc.get("uses_count", 0) >= disc["max_uses"]:
            raise HTTPException(400, "Discount code has reached its usage limit")
        min_order = disc.get("min_order_kobo") or 0
        if subtotal_kobo < min_order and min_order > 0:
            raise HTTPException(400, f"Minimum order ₦{min_order/100:,.0f} required for code '{code}'")
        if disc["discount_type"] == "percentage":
            raw = int(subtotal_kobo * disc["value"] / 100)
            cap = disc.get("max_discount_kobo")
            discount_kobo = min(raw, cap) if cap else raw
        else:
            discount_kobo = min(disc["value"], subtotal_kobo)
        applied_discount_code = code
        discount_id = disc["discount_id"]

    total_kobo = max(0, subtotal_kobo - discount_kobo)

    # 3. Atomically reserve inventory (best effort; exact commit on payment confirmation)
    for ci in req.items:
        p = await db.products.find_one({"product_id": ci.product_id})
        if p and p.get("track_inventory"):
            if ci.variant_id:
                await db.products.update_one(
                    {"product_id": ci.product_id, "variants.variant_id": ci.variant_id},
                    {"$inc": {"variants.$.reserved_quantity": ci.quantity}}
                )
            else:
                await db.products.update_one(
                    {"product_id": ci.product_id},
                    {"$inc": {"reserved_quantity": ci.quantity}}
                )

    # 4. Create order
    order_id = _gen_oid()
    now = _now()
    order = {
        "order_id": order_id,
        "order_number": _order_number(store["store_id"]),
        "store_id": store["store_id"],
        "store_name": store["name"],
        "merchant_id": store["merchant_id"],
        "environment": store.get("environment", "sandbox"),
        "payment_status": "pending",
        "order_status": "pending",
        "customer": {
            "name": req.customer.name.strip(),
            "email": req.customer.email or "",
            "phone": req.customer.phone or "",
            "address": req.customer.address or "",
            "city": req.customer.city or "",
            "state": req.customer.state or "",
        },
        "items": order_items,
        "subtotal_kobo": subtotal_kobo,
        "shipping_kobo": 0,
        "discount_kobo": discount_kobo,
        "discount_code": applied_discount_code,
        "total_kobo": total_kobo,
        "checkout_session_id": "",
        "payment_reference": "",
        "notes": req.notes or "",
        "fulfillment_notes": "",
        "tracking_number": "",
        "courier": "",
        "is_deleted": False,
        "created_at": now,
        "updated_at": now,
    }
    await db.store_orders.insert_one({**order, "_id": order_id})

    # 5. Create checkout session (central engine)
    try:
        checkout = await _mk_checkout_session(
            merchant_id=store["merchant_id"],
            environment=store.get("environment", "sandbox"),
            amount_kobo=total_kobo,
            customer_info={"name": req.customer.name, "email": req.customer.email or ""},
            source_type="storefront",
            source_id=order_id,
            redirect_url="",
            description=f"Order from {store['name']}",
        )
    except Exception as e:
        # Rollback inventory reservation on checkout creation failure
        for ci in req.items:
            p = await db.products.find_one({"product_id": ci.product_id})
            if p and p.get("track_inventory"):
                if ci.variant_id:
                    await db.products.update_one(
                        {"product_id": ci.product_id, "variants.variant_id": ci.variant_id},
                        {"$inc": {"variants.$.reserved_quantity": -ci.quantity}}
                    )
                else:
                    await db.products.update_one(
                        {"product_id": ci.product_id},
                        {"$inc": {"reserved_quantity": -ci.quantity}}
                    )
        await db.store_orders.delete_one({"order_id": order_id})
        raise HTTPException(500, f"Failed to create checkout session: {e}")

    # 6. Link checkout session to order
    await db.store_orders.update_one(
        {"order_id": order_id},
        {"$set": {"checkout_session_id": checkout["session_id"], "updated_at": _now()}}
    )

    # 7. Upsert customer record
    customer_email = req.customer.email or ""
    if customer_email:
        await db.storefront_customers.update_one(
            {"merchant_id": store["merchant_id"], "email": customer_email},
            {"$setOnInsert": {
                "customer_id": "cust_" + uuid.uuid4().hex[:10],
                "merchant_id": store["merchant_id"],
                "environment": store.get("environment", "sandbox"),
                "email": customer_email,
                "created_at": now,
            }, "$set": {
                "name": req.customer.name.strip(),
                "phone": req.customer.phone or "",
                "last_order_at": now,
            }, "$inc": {"total_orders": 1}},
            upsert=True
        )

    logger.info(f"[ORDER] Created {order_id} for store {store['store_id']} total=₦{total_kobo/100:.2f}")

    # Increment discount usage
    if discount_id:
        await db.discount_codes.update_one({"discount_id": discount_id}, {"$inc": {"uses_count": 1}})

    # Send order confirmation email (fire-and-forget)
    customer_email = req.customer.email or ""
    if customer_email:
        import asyncio as _asyncio
        full_order = {**order, "checkout_session_id": checkout["session_id"]}
        _asyncio.create_task(send_email(
            to=customer_email,
            subject=f"Order confirmed — {order['order_number']} from {store['name']}",
            html=_order_confirmation_html(full_order, store["name"]),
        ))

    return {
        "order_id": order_id,
        "order_number": order["order_number"],
        "subtotal_kobo": subtotal_kobo,
        "discount_kobo": discount_kobo,
        "total_kobo": total_kobo,
        "checkout_session_id": checkout["session_id"],
        "checkout_url": checkout["checkout_url"],
        "bank_transfer": checkout["bank_transfer"],
        "expires_at": checkout["expires_at"],
    }


async def _get_merchant_ctx(request: Request) -> dict:
    m = await get_current_merchant(request)
    if not m:
        raise HTTPException(401, "Not authenticated")
    return m


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@router.get("/admin/orders")
async def admin_list_orders(request: Request, page: int = 1):
    await _get_admin(request)
    limit = 30
    skip = (page - 1) * limit
    orders = await db.store_orders.find({}, {"_id": 0}).sort("created_at", -1) \
        .skip(skip).limit(limit).to_list(limit)
    total = await db.store_orders.count_documents({})
    return {"orders": orders, "total": total}
