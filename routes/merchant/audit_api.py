"""
BOMPAY Merchant Audit Logs API.
"""
from fastapi import APIRouter, HTTPException, Request

from database import db
from .context import get_merchant_context, require_permission

router = APIRouter()


@router.get("/v1/merchant/audit-logs")
async def list_audit_logs(
    request: Request,
    page: int = 1,
    limit: int = 50,
    actor_id: str = "",
    action: str = "",
    resource: str = "",
):
    """List audit log entries for the merchant. Requires audit.read permission."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "audit.read")

    query: dict = {"merchant_id": ctx.merchant_id}
    if actor_id:
        query["actor_id"] = actor_id
    if action:
        query["action"] = {"$regex": action, "$options": "i"}
    if resource:
        query["resource"] = resource

    skip = (max(page, 1) - 1) * limit
    total = await db.merchant_audit_logs.count_documents(query)
    logs = await db.merchant_audit_logs.find(query).sort(
        "created_at", -1
    ).skip(skip).limit(limit).to_list(limit)

    for log in logs:
        log["_id"] = str(log["_id"])

    return {
        "logs": logs,
        "total": total,
        "page": page,
        "pages": max(1, (total + limit - 1) // limit),
    }
