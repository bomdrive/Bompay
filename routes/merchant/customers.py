"""
Customers routes — merchant's storefront customer records.
"""
from fastapi import APIRouter, Request, HTTPException
from database import db
from .legacy import get_current_merchant, _get_admin

router = APIRouter()


async def _get_merchant_ctx(request: Request) -> dict:
    m = await get_current_merchant(request)
    if not m:
        raise HTTPException(401, "Not authenticated")
    return m


@router.get("/v1/customers")
async def list_customers(request: Request, page: int = 1, limit: int = 20,
                          search: str = ""):
    merchant = await _get_merchant_ctx(request)
    mid = merchant["merchant_id"]
    filt: dict = {"merchant_id": mid}
    if search:
        filt["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
            {"phone": {"$regex": search, "$options": "i"}},
        ]
    skip = (page - 1) * limit
    customers = await db.storefront_customers.find(filt, {"_id": 0}) \
        .sort("last_order_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.storefront_customers.count_documents(filt)
    return {"customers": customers, "total": total, "page": page,
            "pages": (total + limit - 1) // limit}


@router.get("/v1/customers/{customer_id}")
async def get_customer(customer_id: str, request: Request):
    merchant = await _get_merchant_ctx(request)
    c = await db.storefront_customers.find_one(
        {"customer_id": customer_id, "merchant_id": merchant["merchant_id"]}, {"_id": 0}
    )
    if not c:
        raise HTTPException(404, "Customer not found")
    return c


@router.get("/v1/customers/{customer_id}/orders")
async def customer_orders(customer_id: str, request: Request, page: int = 1):
    merchant = await _get_merchant_ctx(request)
    c = await db.storefront_customers.find_one(
        {"customer_id": customer_id, "merchant_id": merchant["merchant_id"]}
    )
    if not c:
        raise HTTPException(404, "Customer not found")
    limit = 20
    skip = (page - 1) * limit
    orders = await db.store_orders.find(
        {"merchant_id": merchant["merchant_id"], "customer.email": c.get("email", "")},
        {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.store_orders.count_documents(
        {"merchant_id": merchant["merchant_id"], "customer.email": c.get("email", "")}
    )
    return {"orders": orders, "total": total}


@router.get("/admin/customers")
async def admin_list_customers(request: Request, page: int = 1):
    await _get_admin(request)
    limit = 30
    skip = (page - 1) * limit
    customers = await db.storefront_customers.find({}, {"_id": 0}) \
        .sort("last_order_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.storefront_customers.count_documents({})
    return {"customers": customers, "total": total}
