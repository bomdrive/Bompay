"""
BOMPAY Merchant RBAC — Unified Auth Context.

Provides:
  - MerchantContext  dataclass (actor identity + resolved permissions)
  - get_merchant_context(request)  — handles both merchant_access (owner)
    and member_access (team member) JWT tokens.
  - require_permission(ctx, *perms)  — raises 403 when any perm is missing.
  - merchant_audit(ctx, action, resource, details, request)  — writes an
    audit log record, never raising.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Set

import jwt as pyjwt
from fastapi import HTTPException, Request

from core import JWT_SECRET, JWT_ALGORITHM
from database import db
from .permissions import ALL_PERMISSIONS

logger = logging.getLogger(__name__)


# ─── CONTEXT DATACLASS ───────────────────────────────────────────────────────

@dataclass
class MerchantContext:
    merchant_id: str
    merchant: dict                      # full merchant document (password fields stripped)
    actor_id: str                       # merchant_id (owner) or member_id (team)
    actor_email: str
    actor_name: str
    is_owner: bool
    permissions: Set[str] = field(default_factory=set)
    member: Optional[dict] = None       # merchant_members doc; None for owner


# ─── MAIN AUTH DEPENDENCY ────────────────────────────────────────────────────

async def get_merchant_context(request: Request) -> MerchantContext:
    """
    Resolve the authenticated merchant context from cookie or Bearer header.
    Supports both `merchant_access` (business owner) and `member_access`
    (team member) token types.  Checks DB status on every call so that
    suspend/deactivate takes effect immediately without waiting for token expiry.
    """
    token = request.cookies.get("merchant_access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")

    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

    token_type = payload.get("type")

    # ── Business owner token (existing flow) ──────────────────────────────
    if token_type == "merchant_access":
        merchant_id = payload["sub"]
        m = await db.merchants.find_one({"merchant_id": merchant_id})
        if not m:
            raise HTTPException(401, "Merchant not found")
        if m.get("status") == "suspended":
            raise HTTPException(403, "Merchant account suspended")
        m["_id"] = str(m["_id"])
        m.pop("password_hash", None)
        m.pop("pin_hash", None)
        return MerchantContext(
            merchant_id=merchant_id,
            merchant=m,
            actor_id=merchant_id,
            actor_email=payload.get("email", m.get("email", "")),
            actor_name=m.get("owner_name", m.get("business_name", "")),
            is_owner=True,
            permissions=ALL_PERMISSIONS,
            member=None,
        )

    # ── Team member token (new flow) ───────────────────────────────────────
    if token_type == "member_access":
        member_id = payload.get("sub", "")
        merchant_id = payload.get("merchant_id", "")

        member = await db.merchant_members.find_one(
            {"member_id": member_id, "merchant_id": merchant_id}
        )
        if not member:
            raise HTTPException(401, "Team member not found")
        if member.get("status") != "active":
            raise HTTPException(403, "Team member account is not active")

        m = await db.merchants.find_one({"merchant_id": merchant_id})
        if not m:
            raise HTTPException(401, "Merchant not found")
        if m.get("status") == "suspended":
            raise HTTPException(403, "Merchant account suspended")
        m["_id"] = str(m["_id"])
        m.pop("password_hash", None)
        m.pop("pin_hash", None)

        # Resolve permissions from role (system or custom)
        role_id = member.get("role_id", "")
        role = await db.merchant_roles.find_one(
            {"role_id": role_id, "$or": [
                {"merchant_id": merchant_id},
                {"is_system": True},
            ]}
        )
        permissions: Set[str] = set(role.get("permissions", [])) if role else set()

        member_out = {k: v for k, v in member.items()}
        member_out["_id"] = str(member_out["_id"])
        member_out.pop("password_hash", None)

        return MerchantContext(
            merchant_id=merchant_id,
            merchant=m,
            actor_id=member_id,
            actor_email=member.get("email", ""),
            actor_name=(
                f"{member.get('first_name', '')} {member.get('last_name', '')}".strip()
                or member.get("email", "")
            ),
            is_owner=False,
            permissions=permissions,
            member=member_out,
        )

    raise HTTPException(401, "Invalid token type")


# ─── PERMISSION GUARD ─────────────────────────────────────────────────────────

async def require_permission(ctx: MerchantContext, *perms: str) -> None:
    """
    Raise 403 when the actor is missing ANY of the supplied permissions.
    Business owners (is_owner=True) always pass — they hold ALL_PERMISSIONS.
    """
    if ctx.is_owner:
        return
    missing = [p for p in perms if p not in ctx.permissions]
    if missing:
        raise HTTPException(403, f"Insufficient permissions: {', '.join(missing)}")


# ─── AUDIT LOGGING ───────────────────────────────────────────────────────────

async def merchant_audit(
    ctx: MerchantContext,
    action: str,
    resource: str,
    details: Optional[dict] = None,
    request: Optional[Request] = None,
) -> None:
    """
    Write an audit log entry.  Never raises — failures are logged and swallowed
    so they don't break the main request flow.
    """
    try:
        ip = ""
        if request and request.client:
            ip = request.client.host or ""
        await db.merchant_audit_logs.insert_one({
            "merchant_id": ctx.merchant_id,
            "actor_id": ctx.actor_id,
            "actor_email": ctx.actor_email,
            "actor_name": ctx.actor_name,
            "is_owner": ctx.is_owner,
            "action": action,
            "resource": resource,
            "details": details or {},
            "ip_address": ip,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.warning(f"[AUDIT] Failed to write audit log: {exc}")
