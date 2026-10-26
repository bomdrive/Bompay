"""
BOMPAY Merchant Role Management API.

System roles are read-only. Merchants can create, update, and delete custom roles.
"""
import secrets
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from database import db
from .context import MerchantContext, get_merchant_context, require_permission, merchant_audit
from .permissions import SYSTEM_ROLES, ALL_PERMISSIONS, PERMISSIONS

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CreateRoleReq(BaseModel):
    name: str
    description: Optional[str] = ""
    permissions: List[str] = []


class UpdateRoleReq(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None


# ─── LIST ALL ROLES ──────────────────────────────────────────────────────────

@router.get("/v1/merchant/roles")
async def list_roles(request: Request):
    """List all available roles (system + merchant custom)."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.roles.read")

    # System roles
    system = []
    for rid, rdata in SYSTEM_ROLES.items():
        system.append({
            "role_id": rid,
            "name": rdata["name"],
            "description": rdata["description"],
            "permissions": rdata["permissions"],
            "is_system": True,
            "protected": rdata.get("protected", False),
        })

    # Custom roles for this merchant
    custom_cursor = await db.merchant_roles.find(
        {"merchant_id": ctx.merchant_id, "is_system": False}
    ).to_list(100)
    custom = []
    for r in custom_cursor:
        custom.append({
            "role_id": r["role_id"],
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "permissions": r.get("permissions", []),
            "is_system": False,
            "protected": False,
        })

    return {
        "system_roles": system,
        "custom_roles": custom,
        "all_permissions": [
            {"key": k, "description": v} for k, v in PERMISSIONS.items()
        ],
    }


# ─── GET SINGLE ROLE ─────────────────────────────────────────────────────────

@router.get("/v1/merchant/roles/{role_id}")
async def get_role(role_id: str, request: Request):
    """Get a single role by ID."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.roles.read")

    if role_id in SYSTEM_ROLES:
        rdata = SYSTEM_ROLES[role_id]
        return {
            "role_id": role_id,
            "name": rdata["name"],
            "description": rdata["description"],
            "permissions": rdata["permissions"],
            "is_system": True,
            "protected": rdata.get("protected", False),
        }

    role = await db.merchant_roles.find_one(
        {"role_id": role_id, "merchant_id": ctx.merchant_id}
    )
    if not role:
        raise HTTPException(404, "Role not found")
    role["_id"] = str(role["_id"])
    return role


# ─── CREATE CUSTOM ROLE ──────────────────────────────────────────────────────

@router.post("/v1/merchant/roles")
async def create_role(req: CreateRoleReq, request: Request):
    """Create a custom role for this merchant."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.roles.create")

    # Validate permissions
    invalid = [p for p in req.permissions if p not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(400, f"Unknown permissions: {', '.join(invalid)}")

    # Anti-escalation: cannot create a role with permissions exceeding your own
    if not ctx.is_owner:
        excess = [p for p in req.permissions if p not in ctx.permissions]
        if excess:
            raise HTTPException(403, f"You cannot grant permissions you don't have: {', '.join(excess)}")

    # Name must be unique within the merchant
    existing = await db.merchant_roles.find_one(
        {"merchant_id": ctx.merchant_id, "name": req.name, "is_system": False}
    )
    if existing:
        raise HTTPException(409, "A role with this name already exists")

    role_id = f"role_{secrets.token_hex(8)}"
    now = _now()
    await db.merchant_roles.insert_one({
        "role_id": role_id,
        "merchant_id": ctx.merchant_id,
        "name": req.name,
        "description": req.description or "",
        "permissions": sorted(req.permissions),
        "is_system": False,
        "created_by": ctx.actor_id,
        "created_at": now,
        "updated_at": now,
    })
    await merchant_audit(ctx, "team.role.create", "merchant_roles",
                         {"role_id": role_id, "name": req.name}, request)
    return {
        "role_id": role_id,
        "name": req.name,
        "description": req.description or "",
        "permissions": sorted(req.permissions),
        "is_system": False,
    }


# ─── UPDATE CUSTOM ROLE ──────────────────────────────────────────────────────

@router.patch("/v1/merchant/roles/{role_id}")
async def update_role(role_id: str, req: UpdateRoleReq, request: Request):
    """Update a custom role."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.roles.update")

    if role_id in SYSTEM_ROLES:
        raise HTTPException(403, "System roles cannot be modified")

    role = await db.merchant_roles.find_one(
        {"role_id": role_id, "merchant_id": ctx.merchant_id}
    )
    if not role:
        raise HTTPException(404, "Role not found")

    updates: dict = {"updated_at": _now()}
    if req.name is not None:
        updates["name"] = req.name
    if req.description is not None:
        updates["description"] = req.description
    if req.permissions is not None:
        invalid = [p for p in req.permissions if p not in ALL_PERMISSIONS]
        if invalid:
            raise HTTPException(400, f"Unknown permissions: {', '.join(invalid)}")
        if not ctx.is_owner:
            excess = [p for p in req.permissions if p not in ctx.permissions]
            if excess:
                raise HTTPException(403, f"You cannot grant permissions you don't have: {', '.join(excess)}")
        updates["permissions"] = sorted(req.permissions)

    await db.merchant_roles.update_one({"role_id": role_id}, {"$set": updates})
    await merchant_audit(ctx, "team.role.update", "merchant_roles",
                         {"role_id": role_id, "updates": list(updates.keys())}, request)

    updated = await db.merchant_roles.find_one({"role_id": role_id})
    updated["_id"] = str(updated["_id"])
    return updated


# ─── DELETE CUSTOM ROLE ──────────────────────────────────────────────────────

@router.delete("/v1/merchant/roles/{role_id}")
async def delete_role(role_id: str, reassign_to: Optional[str] = None, request: Request = None):
    """
    Delete a custom role.  If members use it, they are reassigned to
    `reassign_to` (required when members exist with this role).
    """
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.roles.delete")

    if role_id in SYSTEM_ROLES:
        raise HTTPException(403, "System roles cannot be deleted")

    role = await db.merchant_roles.find_one(
        {"role_id": role_id, "merchant_id": ctx.merchant_id}
    )
    if not role:
        raise HTTPException(404, "Role not found")

    # Check if any active members have this role
    affected = await db.merchant_members.count_documents(
        {"merchant_id": ctx.merchant_id, "role_id": role_id, "status": {"$ne": "deactivated"}}
    )
    if affected > 0:
        if not reassign_to:
            raise HTTPException(409, {
                "message": f"{affected} team member(s) use this role. Provide reassign_to query param.",
                "affected": affected,
            })
        # Validate target role
        target_valid = (reassign_to in SYSTEM_ROLES) or bool(
            await db.merchant_roles.find_one(
                {"role_id": reassign_to, "merchant_id": ctx.merchant_id}
            )
        )
        if not target_valid:
            raise HTTPException(400, "Reassignment role not found")
        await db.merchant_members.update_many(
            {"merchant_id": ctx.merchant_id, "role_id": role_id},
            {"$set": {"role_id": reassign_to}}
        )

    await db.merchant_roles.delete_one({"role_id": role_id})
    await merchant_audit(ctx, "team.role.delete", "merchant_roles",
                         {"role_id": role_id, "reassigned_to": reassign_to}, request)
    return {"message": "Role deleted", "role_id": role_id, "members_reassigned": affected if affected else 0}
