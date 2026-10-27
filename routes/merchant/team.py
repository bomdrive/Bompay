"""
BOMPAY Merchant Team Management API.

Endpoints (all under /api/v1/merchant/team):
  POST   /invite                 — Invite a team member
  GET    /members                — List team members
  PATCH  /members/{member_id}    — Update member role / status
  DELETE /members/{member_id}    — Deactivate (soft-remove) a member
  GET    /invitations            — List pending invitations
  DELETE /invitations/{invite_id} — Revoke an invitation
  POST   /login                  — Team member login (separate from owner login)
  GET    /me                     — Current member identity

Public:
  GET  /accept-invite            — Info about an invitation (by raw token)
  POST /accept-invite            — Accept an invitation

Transfer Approvals (maker-checker):
  POST  /transfer-requests           — Create a pending transfer approval
  GET   /transfer-requests           — List pending / recent transfer approvals
  POST  /transfer-requests/{id}/approve — Approve and execute
  POST  /transfer-requests/{id}/reject  — Reject
"""
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from core import (
    db, hash_password, verify_password,
    JWT_SECRET, JWT_ALGORITHM, send_email, FRONTEND_URL,
)
from .context import MerchantContext, get_merchant_context, require_permission, merchant_audit
from .permissions import SYSTEM_ROLES, ALL_PERMISSIONS, ASSIGNABLE_ROLE_IDS

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _member_token(member_id: str, merchant_id: str) -> str:
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "sub": member_id,
            "merchant_id": merchant_id,
            "type": "member_access",
            "exp": now + timedelta(hours=12),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def _member_refresh_token(member_id: str, merchant_id: str) -> str:
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "sub": member_id,
            "merchant_id": merchant_id,
            "type": "member_refresh",
            "exp": now + timedelta(days=30),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def _set_member_cookies(response: Response, access: str, refresh: str) -> None:
    kw = dict(httponly=True, secure=True, samesite="none", path="/")
    response.set_cookie("merchant_access_token", access, max_age=43200, **kw)
    response.set_cookie("merchant_refresh_token", refresh, max_age=2592000, **kw)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _safe_member(m: dict) -> dict:
    out = {k: v for k, v in m.items()}
    out["_id"] = str(out.get("_id", ""))
    out.pop("password_hash", None)
    return out


async def _resolve_role_permissions(role_id: str, merchant_id: str) -> set:
    """Return the permission set for a role (system or custom)."""
    role = await db.merchant_roles.find_one(
        {"role_id": role_id, "$or": [
            {"is_system": True},
            {"merchant_id": merchant_id},
        ]}
    )
    return set(role.get("permissions", [])) if role else set()


async def _actor_can_assign_role(ctx: MerchantContext, role_id: str) -> bool:
    """
    An actor can only assign a role whose permission set is a subset
    of their own permissions. Prevents privilege escalation.
    """
    if ctx.is_owner:
        return True
    role_perms = await _resolve_role_permissions(role_id, ctx.merchant_id)
    return role_perms.issubset(ctx.permissions)


def _invite_email_html(
    invitee_email: str,
    merchant_name: str,
    invited_by: str,
    role_name: str,
    invite_url: str,
    expires_hours: int = 72,
) -> str:
    """Rich branded BOMPAY invitation email with logo header and styled CTA."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>You're invited to join {merchant_name} on BOMPAY</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 16px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">

        <!-- ── HEADER ── -->
        <tr><td style="background:#064BCB;border-radius:16px 16px 0 0;padding:28px 32px 24px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <span style="color:#fff;font-size:22px;font-weight:800;letter-spacing:-0.5px;font-family:Arial,sans-serif">BOMPAY</span>
                <p style="margin:4px 0 0;color:#bfdbfe;font-size:12px;font-family:Arial,sans-serif">Team Invitation</p>
              </td>
              <td align="right">
                <div style="width:44px;height:44px;background:rgba(255,255,255,0.15);border-radius:12px;display:inline-block;text-align:center;line-height:44px">
                  <span style="font-size:22px">&#128101;</span>
                </div>
              </td>
            </tr>
          </table>
        </td></tr>

        <!-- ── BODY ── -->
        <tr><td style="background:#ffffff;padding:32px;border-radius:0 0 16px 16px">

          <!-- Greeting -->
          <p style="margin:0 0 6px;font-size:20px;font-weight:800;color:#0f172a;font-family:Arial,sans-serif">
            You're invited!
          </p>
          <p style="margin:0 0 24px;font-size:14px;color:#64748b;line-height:1.6;font-family:Arial,sans-serif">
            <strong style="color:#334155">{invited_by}</strong> has invited you to join
            the team at <strong style="color:#334155">{merchant_name}</strong> on BOMPAY.
          </p>

          <!-- Details card -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
            style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;margin-bottom:24px">
            <tr><td style="padding:20px 20px 4px">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">

                <tr>
                  <td style="padding:7px 0;font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;font-family:Arial,sans-serif;width:40%">Your Role</td>
                  <td style="padding:7px 0;font-size:13px;font-weight:700;color:#064BCB;text-align:right;font-family:Arial,sans-serif">
                    <span style="background:#EEF4FF;border-radius:6px;padding:3px 10px">{role_name}</span>
                  </td>
                </tr>

                <tr><td colspan="2" style="border-top:1px solid #e2e8f0;padding:0"></td></tr>

                <tr>
                  <td style="padding:7px 0;font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;font-family:Arial,sans-serif">Merchant</td>
                  <td style="padding:7px 0;font-size:13px;font-weight:600;color:#0f172a;text-align:right;font-family:Arial,sans-serif">{merchant_name}</td>
                </tr>

                <tr><td colspan="2" style="border-top:1px solid #e2e8f0;padding:0"></td></tr>

                <tr>
                  <td style="padding:7px 0;font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;font-family:Arial,sans-serif">Invited by</td>
                  <td style="padding:7px 0;font-size:13px;font-weight:600;color:#0f172a;text-align:right;font-family:Arial,sans-serif">{invited_by}</td>
                </tr>

                <tr><td colspan="2" style="border-top:1px solid #e2e8f0;padding:0"></td></tr>

                <tr>
                  <td style="padding:7px 0 14px;font-size:12px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;font-family:Arial,sans-serif">Expires in</td>
                  <td style="padding:7px 0 14px;font-size:13px;font-weight:600;color:#f59e0b;text-align:right;font-family:Arial,sans-serif">{expires_hours} hours</td>
                </tr>

              </table>
            </td></tr>
          </table>

          <!-- CTA Button -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px">
            <tr><td align="center">
              <a href="{invite_url}"
                style="display:inline-block;background:#064BCB;color:#ffffff;text-decoration:none;font-size:15px;font-weight:800;padding:14px 40px;border-radius:12px;font-family:Arial,sans-serif;letter-spacing:-0.2px">
                Accept Invitation &rarr;
              </a>
            </td></tr>
          </table>

          <!-- Fallback URL -->
          <p style="margin:0 0 20px;font-size:11px;color:#94a3b8;word-break:break-all;font-family:Arial,sans-serif;line-height:1.5">
            Button not working? Copy and paste this link into your browser:<br>
            <span style="color:#064BCB">{invite_url}</span>
          </p>

          <!-- Security notice -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
            style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;margin-bottom:20px">
            <tr><td style="padding:12px 16px">
              <p style="margin:0;font-size:12px;color:#92400e;line-height:1.5;font-family:Arial,sans-serif">
                <strong>Didn't expect this?</strong> You can safely ignore this email.
                BOMPAY will never ask for your PIN or password via email.
              </p>
            </td></tr>
          </table>

        </td></tr>

        <!-- ── FOOTER ── -->
        <tr><td style="padding:20px 0 8px" align="center">
          <p style="margin:0;font-size:11px;color:#94a3b8;font-family:Arial,sans-serif">
            &copy; 2025 BOMPAY &mdash; Trusted Nigerian Fintech &nbsp;&middot;&nbsp;
            <a href="https://bompay.app" style="color:#94a3b8;text-decoration:none">bompay.app</a>
          </p>
          <p style="margin:4px 0 0;font-size:10px;color:#cbd5e1;font-family:Arial,sans-serif">
            This invitation was sent to {invitee_email}
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ─── MODELS ──────────────────────────────────────────────────────────────────

class InviteReq(BaseModel):
    email: EmailStr
    role_id: str
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""


class UpdateMemberReq(BaseModel):
    role_id: Optional[str] = None
    status: Optional[str] = None   # "active" | "suspended" | "deactivated"


class TeamLoginReq(BaseModel):
    email: str
    password: str
    merchant_id: Optional[str] = None   # Required when member belongs to >1 merchant


class AcceptInviteReq(BaseModel):
    token: str
    first_name: str
    last_name: str
    password: str


class TransferRequestReq(BaseModel):
    account_number: str
    bank_code: str
    amount: float        # naira
    narration: Optional[str] = "Merchant Transfer"
    pin: str
    from_account_id: Optional[str] = None


class TransferApprovalAction(BaseModel):
    rejection_reason: Optional[str] = ""


# ─── TEAM MEMBER LOGIN ────────────────────────────────────────────────────────

@router.post("/v1/merchant/team/login")
async def team_login(req: TeamLoginReq, response: Response):
    """
    Authenticate a team member.  Returns a `member_access` JWT cookie.
    If the member belongs to multiple active merchants and merchant_id is
    not supplied, returns 409 with the list so the caller can retry.
    """
    email = req.email.lower().strip()
    # Find all active memberships for this email
    memberships = await db.merchant_members.find(
        {"email": email, "status": {"$in": ["active", "suspended"]}}
    ).to_list(20)
    if not memberships:
        raise HTTPException(401, "Invalid email or password")

    # Verify password against the first matching membership
    member = None
    for m in memberships:
        if verify_password(req.password, m.get("password_hash", "")):
            member = m
            break
    if not member:
        raise HTTPException(401, "Invalid email or password")

    if member.get("status") == "suspended":
        raise HTTPException(403, "Your account has been suspended. Contact the business owner.")
    if member.get("status") == "deactivated":
        raise HTTPException(403, "Your account has been deactivated.")

    # Determine merchant
    active_memberships = [m for m in memberships if m.get("email") == email]
    if req.merchant_id:
        # Verify the requested merchant_id belongs to this member
        target = await db.merchant_members.find_one(
            {"member_id": member["member_id"], "merchant_id": req.merchant_id, "status": "active"}
        )
        if not target:
            raise HTTPException(400, "You do not have an active membership for this merchant")
        member = target
        merchant_id = req.merchant_id
    elif len(memberships) > 1:
        # Multiple merchants — caller must specify
        merchants_info = []
        for mem in memberships:
            m = await db.merchants.find_one({"merchant_id": mem["merchant_id"]})
            merchants_info.append({
                "merchant_id": mem["merchant_id"],
                "business_name": (m or {}).get("business_name", ""),
                "role_id": mem.get("role_id", ""),
            })
        raise HTTPException(409, {
            "message": "This account belongs to multiple merchants. Please specify merchant_id.",
            "merchants": merchants_info,
        })
    else:
        merchant_id = member["merchant_id"]

    # Check merchant status
    merchant = await db.merchants.find_one({"merchant_id": merchant_id})
    if not merchant or merchant.get("status") == "suspended":
        raise HTTPException(403, "Merchant account is suspended")

    access = _member_token(member["member_id"], merchant_id)
    refresh = _member_refresh_token(member["member_id"], merchant_id)
    _set_member_cookies(response, access, refresh)

    # Resolve role for response
    role = await db.merchant_roles.find_one(
        {"role_id": member.get("role_id", ""), "$or": [
            {"is_system": True}, {"merchant_id": merchant_id}
        ]}
    )
    # Determine whether the member still needs to set up their PIN
    needs_pin_setup = not bool(member.get("pin_hash"))
    return {
        **_safe_member(member),
        "merchant": {k: v for k, v in merchant.items()
                     if k not in ("_id", "password_hash", "pin_hash")},
        "role": {"role_id": (role or {}).get("role_id"), "name": (role or {}).get("name")},
        "is_owner": False,
        "needs_pin_setup": needs_pin_setup,
    }


# ─── CURRENT MEMBER ───────────────────────────────────────────────────────────

@router.get("/v1/merchant/team/me")
async def team_me(request: Request):
    """Return the current team member's identity and permissions."""
    ctx = await get_merchant_context(request)
    if ctx.is_owner:
        return {
            "actor_id": ctx.actor_id,
            "actor_email": ctx.actor_email,
            "actor_name": ctx.actor_name,
            "is_owner": True,
            "permissions": sorted(ctx.permissions),
        }
    return {
        "actor_id": ctx.actor_id,
        "actor_email": ctx.actor_email,
        "actor_name": ctx.actor_name,
        "is_owner": False,
        "role_id": ctx.member.get("role_id") if ctx.member else None,
        "permissions": sorted(ctx.permissions),
        "member": ctx.member,
    }


# ─── TEAM MEMBER PIN SETUP & VERIFICATION ─────────────────────────────────────

class MemberPinReq(BaseModel):
    pin: str
    confirm_pin: Optional[str] = None

@router.post("/v1/merchant/team/set-pin")
async def team_set_pin(req: MemberPinReq, request: Request):
    """
    Called immediately after a team member's first login to set their 4-digit PIN.
    Requires the member_access cookie (set during team login).
    Once set, the PIN is required on subsequent logins.
    """
    ctx = await get_merchant_context(request)
    if ctx.is_owner:
        raise HTTPException(400, "Business owners set their PIN during registration")

    pin = req.pin.strip()
    if not pin.isdigit() or len(pin) != 4:
        raise HTTPException(400, "PIN must be exactly 4 digits")
    if req.confirm_pin is not None and req.confirm_pin != pin:
        raise HTTPException(400, "PINs do not match")

    member_id = ctx.actor_id
    await db.merchant_members.update_one(
        {"member_id": member_id},
        {"$set": {"pin_hash": hash_password(pin), "pin_set_at": _now()}}
    )
    return {"message": "PIN set successfully"}


@router.post("/v1/merchant/team/verify-pin")
async def team_verify_pin(req: MemberPinReq, request: Request):
    """Verify a team member's PIN. Called after password login to complete authentication."""
    ctx = await get_merchant_context(request)
    if ctx.is_owner:
        raise HTTPException(400, "Use /v1/merchant/verify-pin for business owner PIN")

    member = await db.merchant_members.find_one({"member_id": ctx.actor_id})
    if not member or not member.get("pin_hash"):
        raise HTTPException(400, "PIN not set. Please set your PIN first.")

    if not verify_password(req.pin.strip(), member["pin_hash"]):
        raise HTTPException(401, "Incorrect PIN. Please try again.")

    return {"message": "PIN verified"}


# ─── ACCOUNT ACCESS ASSIGNMENT ────────────────────────────────────────────────

class AccountAssignmentReq(BaseModel):
    assigned_accounts: list  # [] = all accounts; ["acct_id1", ...] = specific accounts

@router.patch("/v1/merchant/team/members/{member_id}/accounts")
async def assign_member_accounts(member_id: str, req: AccountAssignmentReq, request: Request):
    """
    Assign which sub-accounts a team member can access.
    [] means access to ALL accounts (default).
    ["acct_id1", "acct_id2"] restricts access to only those accounts.
    Requires team.members.update permission.
    """
    ctx = await get_merchant_context(request)
    require_permission(ctx, "team.members.update")

    member = await db.merchant_members.find_one({
        "member_id": member_id, "merchant_id": ctx.merchant_id
    })
    if not member:
        raise HTTPException(404, "Team member not found")
    if member.get("is_owner"):
        raise HTTPException(400, "Cannot restrict account access for the business owner")

    # Validate account IDs belong to this merchant
    if req.assigned_accounts:
        valid = await db.merchant_accounts.find(
            {"merchant_id": ctx.merchant_id, "account_id": {"$in": req.assigned_accounts}},
            {"account_id": 1}
        ).to_list(50)
        valid_ids = {a["account_id"] for a in valid}
        invalid = [a for a in req.assigned_accounts if a not in valid_ids]
        if invalid:
            raise HTTPException(400, f"Unknown account IDs: {invalid}")

    await db.merchant_members.update_one(
        {"member_id": member_id},
        {"$set": {"assigned_accounts": req.assigned_accounts, "accounts_updated_at": _now()}}
    )
    await merchant_audit(ctx, "member.accounts.updated", "merchant_members",
                         {"member_id": member_id, "assigned_accounts": req.assigned_accounts})

    label = "All accounts" if not req.assigned_accounts else f"{len(req.assigned_accounts)} account(s)"
    return {"message": f"Account access updated: {label}", "assigned_accounts": req.assigned_accounts}


@router.get("/v1/merchant/team/members/{member_id}/accounts")
async def get_member_accounts(member_id: str, request: Request):
    """Return the account assignment for a specific team member."""
    ctx = await get_merchant_context(request)
    require_permission(ctx, "team.members.update")

    member = await db.merchant_members.find_one({
        "member_id": member_id, "merchant_id": ctx.merchant_id
    }, {"_id": 0})
    if not member:
        raise HTTPException(404, "Team member not found")

    all_accounts = await db.merchant_accounts.find(
        {"merchant_id": ctx.merchant_id}, {"_id": 0, "account_id": 1,
         "name": 1, "type": 1, "sh_account_number": 1, "sh_account_name": 1, "status": 1}
    ).to_list(50)

    assigned = member.get("assigned_accounts", [])
    return {
        "assigned_accounts": assigned,
        "all_access": len(assigned) == 0,
        "accounts": all_accounts,
    }


# ─── INVITE ────────────────────────────────────────────────────────────────────

@router.post("/v1/merchant/team/invite")
async def invite_member(req: InviteReq, request: Request):
    """Invite a team member by email. Sends an invitation email with a secure link."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.invite")

    email = req.email.lower().strip()
    role_id = req.role_id

    # Validate role exists and is assignable
    if role_id == "business_owner":
        raise HTTPException(400, "Cannot invite a member as Business Owner. Use ownership transfer.")
    role = await db.merchant_roles.find_one(
        {"role_id": role_id, "$or": [
            {"is_system": True}, {"merchant_id": ctx.merchant_id}
        ]}
    )
    if not role:
        raise HTTPException(400, "Role not found")

    # Anti-escalation: inviter cannot grant permissions they don't have
    if not await _actor_can_assign_role(ctx, role_id):
        raise HTTPException(403, "You cannot assign a role with permissions exceeding your own")

    # Check if already a member
    existing_member = await db.merchant_members.find_one(
        {"merchant_id": ctx.merchant_id, "email": email, "status": {"$ne": "deactivated"}}
    )
    if existing_member:
        raise HTTPException(409, "This email is already a team member for this merchant")

    # Revoke any existing pending invitation for the same email+merchant
    await db.merchant_invitations.update_many(
        {"merchant_id": ctx.merchant_id, "email": email, "status": "pending"},
        {"$set": {"status": "revoked", "updated_at": _now()}}
    )

    # Generate invitation token
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)
    invitation_id = f"INV_{secrets.token_hex(6).upper()}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=72)).isoformat()

    await db.merchant_invitations.insert_one({
        "invitation_id": invitation_id,
        "merchant_id": ctx.merchant_id,
        "email": email,
        "role_id": role_id,
        "first_name": req.first_name or "",
        "last_name": req.last_name or "",
        "token_hash": token_hash,
        "expires_at": expires_at,
        "status": "pending",
        "invited_by": ctx.actor_id,
        "invited_by_email": ctx.actor_email,
        "created_at": _now(),
        "updated_at": _now(),
    })

    # Send invitation email
    invite_url = (FRONTEND_URL or "").rstrip("/") + f"/accept-invite?token={raw_token}"
    merchant_name = ctx.merchant.get("business_name", "BOMPAY Merchant")
    html = _invite_email_html(
        invitee_email=email,
        merchant_name=merchant_name,
        invited_by=ctx.actor_name or ctx.actor_email,
        role_name=role.get("name", role_id),
        invite_url=invite_url,
        expires_hours=72,
    )
    try:
        await send_email(to=email, subject=f"You're invited to join {merchant_name} on BOMPAY", html=html)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(f"[TEAM] Invite email failed: {exc}")

    await merchant_audit(ctx, "team.invite", "merchant_invitations",
                         {"email": email, "role_id": role_id}, request)

    return {
        "invitation_id": invitation_id,
        "email": email,
        "role_id": role_id,
        "expires_at": expires_at,
        "invite_url": invite_url,   # returned for manual sharing as fallback
    }


# ─── LIST / GET INVITATION INFO (public) ─────────────────────────────────────

@router.get("/v1/merchant/team/invite/info")
async def get_invite_info(token: str):
    """Public endpoint — returns invitation metadata given the raw token."""
    token_hash = _hash_token(token)
    inv = await db.merchant_invitations.find_one({"token_hash": token_hash, "status": "pending"})
    if not inv:
        raise HTTPException(404, "Invitation not found or already used")
    # Check expiry
    try:
        exp = datetime.fromisoformat(inv["expires_at"])
        if exp < datetime.now(timezone.utc):
            await db.merchant_invitations.update_one(
                {"token_hash": token_hash},
                {"$set": {"status": "expired", "updated_at": _now()}}
            )
            raise HTTPException(410, "Invitation has expired")
    except ValueError:
        pass

    merchant = await db.merchants.find_one({"merchant_id": inv["merchant_id"]}) or {}
    role = await db.merchant_roles.find_one(
        {"role_id": inv["role_id"], "$or": [
            {"is_system": True}, {"merchant_id": inv["merchant_id"]}
        ]}
    ) or {}
    return {
        "invitation_id": inv["invitation_id"],
        "email": inv["email"],
        "merchant_id": inv["merchant_id"],
        "business_name": merchant.get("business_name", ""),
        "role_id": inv["role_id"],
        "role_name": role.get("name", inv["role_id"]),
        "expires_at": inv["expires_at"],
        "first_name": inv.get("first_name", ""),
        "last_name": inv.get("last_name", ""),
    }


# ─── ACCEPT INVITATION ────────────────────────────────────────────────────────

@router.post("/v1/merchant/team/invite/accept")
async def accept_invite(req: AcceptInviteReq, response: Response):
    """
    Accept an invitation and create (or activate) the team member account.
    Sets a member_access cookie so the user is immediately logged in.
    """
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    token_hash = _hash_token(req.token)
    inv = await db.merchant_invitations.find_one({"token_hash": token_hash, "status": "pending"})
    if not inv:
        raise HTTPException(404, "Invitation not found or already used")

    # Check expiry
    try:
        exp = datetime.fromisoformat(inv["expires_at"])
        if exp < datetime.now(timezone.utc):
            await db.merchant_invitations.update_one(
                {"token_hash": token_hash},
                {"$set": {"status": "expired", "updated_at": _now()}}
            )
            raise HTTPException(410, "Invitation has expired")
    except ValueError:
        pass

    merchant_id = inv["merchant_id"]
    email = inv["email"]

    # Mark invitation as accepted (single-use token)
    await db.merchant_invitations.update_one(
        {"token_hash": token_hash},
        {"$set": {"status": "accepted", "updated_at": _now()}}
    )

    # Create or activate member
    existing = await db.merchant_members.find_one(
        {"merchant_id": merchant_id, "email": email}
    )
    now = _now()
    member_id = f"MBR_{secrets.token_hex(6).upper()}"

    if existing:
        # Reactivate with new credentials
        member_id = existing["member_id"]
        await db.merchant_members.update_one(
            {"member_id": member_id},
            {"$set": {
                "password_hash": hash_password(req.password),
                "first_name": req.first_name,
                "last_name": req.last_name,
                "role_id": inv["role_id"],
                "status": "active",
                "invited_by": inv["invited_by"],
                "joined_at": now,
                "updated_at": now,
            }}
        )
    else:
        await db.merchant_members.insert_one({
            "member_id": member_id,
            "merchant_id": merchant_id,
            "email": email,
            "password_hash": hash_password(req.password),
            "first_name": req.first_name,
            "last_name": req.last_name,
            "role_id": inv["role_id"],
            "is_owner": False,
            "status": "active",
            "invited_by": inv["invited_by"],
            "joined_at": now,
            "created_at": now,
            "updated_at": now,
        })

    access = _member_token(member_id, merchant_id)
    refresh = _member_refresh_token(member_id, merchant_id)
    _set_member_cookies(response, access, refresh)

    merchant = await db.merchants.find_one({"merchant_id": merchant_id}) or {}
    role = await db.merchant_roles.find_one(
        {"role_id": inv["role_id"], "$or": [
            {"is_system": True}, {"merchant_id": merchant_id}
        ]}
    ) or {}

    await db.merchant_audit_logs.insert_one({
        "merchant_id": merchant_id,
        "actor_id": member_id,
        "actor_email": email,
        "actor_name": f"{req.first_name} {req.last_name}".strip(),
        "is_owner": False,
        "action": "team.invite.accepted",
        "resource": "merchant_members",
        "details": {"invitation_id": inv["invitation_id"], "role_id": inv["role_id"]},
        "ip_address": "",
        "created_at": now,
    })

    return {
        "member_id": member_id,
        "email": email,
        "first_name": req.first_name,
        "last_name": req.last_name,
        "role_id": inv["role_id"],
        "role_name": role.get("name", inv["role_id"]),
        "merchant_id": merchant_id,
        "business_name": merchant.get("business_name", ""),
        "is_owner": False,
    }


# ─── LIST MEMBERS ─────────────────────────────────────────────────────────────

@router.get("/v1/merchant/team/members")
async def list_members(request: Request):
    """List all team members for the authenticated merchant."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.read")

    members = await db.merchant_members.find(
        {"merchant_id": ctx.merchant_id}
    ).sort("created_at", -1).to_list(200)

    result = []
    for m in members:
        role = await db.merchant_roles.find_one(
            {"role_id": m.get("role_id", ""), "$or": [
                {"is_system": True}, {"merchant_id": ctx.merchant_id}
            ]}
        ) or {}
        result.append({
            **_safe_member(m),
            "role_name": role.get("name", m.get("role_id", "")),
        })

    return {"members": result, "total": len(result)}


# ─── UPDATE MEMBER ────────────────────────────────────────────────────────────

@router.patch("/v1/merchant/team/members/{member_id}")
async def update_member(member_id: str, req: UpdateMemberReq, request: Request):
    """Update a team member's role or status."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.update")

    member = await db.merchant_members.find_one(
        {"member_id": member_id, "merchant_id": ctx.merchant_id}
    )
    if not member:
        raise HTTPException(404, "Team member not found")

    # Cannot modify the owner record
    if member.get("is_owner"):
        raise HTTPException(403, "Cannot modify the Business Owner's team record")

    # Self-modification of role prevention (member cannot elevate themselves)
    if not ctx.is_owner and member_id == ctx.actor_id and req.role_id:
        raise HTTPException(403, "You cannot change your own role")

    updates: dict = {"updated_at": _now()}

    if req.role_id:
        if req.role_id == "business_owner":
            raise HTTPException(400, "Cannot assign Business Owner role via team management")
        role = await db.merchant_roles.find_one(
            {"role_id": req.role_id, "$or": [
                {"is_system": True}, {"merchant_id": ctx.merchant_id}
            ]}
        )
        if not role:
            raise HTTPException(400, "Role not found")
        if not await _actor_can_assign_role(ctx, req.role_id):
            raise HTTPException(403, "You cannot assign a role with permissions exceeding your own")
        updates["role_id"] = req.role_id

    if req.status:
        if req.status not in ("active", "suspended", "deactivated"):
            raise HTTPException(400, "Invalid status")
        updates["status"] = req.status

    await db.merchant_members.update_one(
        {"member_id": member_id}, {"$set": updates}
    )

    await merchant_audit(ctx, "team.member.update", "merchant_members",
                         {"member_id": member_id, "updates": updates}, request)

    updated = await db.merchant_members.find_one({"member_id": member_id})
    return _safe_member(updated)


# ─── REMOVE MEMBER ────────────────────────────────────────────────────────────

@router.delete("/v1/merchant/team/members/{member_id}")
async def remove_member(member_id: str, request: Request):
    """Deactivate (soft-remove) a team member."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.remove")

    member = await db.merchant_members.find_one(
        {"member_id": member_id, "merchant_id": ctx.merchant_id}
    )
    if not member:
        raise HTTPException(404, "Team member not found")
    if member.get("is_owner"):
        raise HTTPException(403, "Cannot remove the Business Owner")
    if member_id == ctx.actor_id:
        raise HTTPException(403, "You cannot remove yourself")

    await db.merchant_members.update_one(
        {"member_id": member_id},
        {"$set": {"status": "deactivated", "updated_at": _now()}}
    )
    await merchant_audit(ctx, "team.member.remove", "merchant_members",
                         {"member_id": member_id, "email": member.get("email")}, request)
    return {"message": "Team member deactivated", "member_id": member_id}


# ─── LIST INVITATIONS ────────────────────────────────────────────────────────

@router.get("/v1/merchant/team/invitations")
async def list_invitations(request: Request, status: str = "pending"):
    """List invitations for the authenticated merchant."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.invite")

    query: dict = {"merchant_id": ctx.merchant_id}
    if status:
        query["status"] = status
    invitations = await db.merchant_invitations.find(query).sort("created_at", -1).to_list(100)
    result = []
    for inv in invitations:
        inv["_id"] = str(inv["_id"])
        inv.pop("token_hash", None)   # never expose the hash
        result.append(inv)
    return {"invitations": result, "total": len(result)}


# ─── REVOKE INVITATION ────────────────────────────────────────────────────────

@router.delete("/v1/merchant/team/invitations/{invitation_id}")
async def revoke_invitation(invitation_id: str, request: Request):
    """Revoke a pending invitation."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "team.members.invite")

    inv = await db.merchant_invitations.find_one(
        {"invitation_id": invitation_id, "merchant_id": ctx.merchant_id}
    )
    if not inv:
        raise HTTPException(404, "Invitation not found")
    if inv.get("status") != "pending":
        raise HTTPException(400, f"Invitation is already {inv.get('status')}")

    await db.merchant_invitations.update_one(
        {"invitation_id": invitation_id},
        {"$set": {"status": "revoked", "updated_at": _now()}}
    )
    await merchant_audit(ctx, "team.invite.revoke", "merchant_invitations",
                         {"invitation_id": invitation_id, "email": inv.get("email")}, request)
    return {"message": "Invitation revoked", "invitation_id": invitation_id}


# ─── TRANSFER APPROVAL REQUESTS (MAKER-CHECKER) ───────────────────────────────

@router.post("/v1/merchant/transfer-requests")
async def create_transfer_request(req: TransferRequestReq, request: Request):
    """
    Create a transfer approval request (for actors with transfers.initiate
    but NOT transfers.approve).  Business owners and Finance Managers bypass
    this and can call /v1/merchant/services/transfer directly.
    """
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "transfers.initiate")

    # PIN check: owner uses merchant pin_hash; team member uses their own pin_hash
    if ctx.is_owner:
        if not verify_password(req.pin, ctx.merchant.get("pin_hash", "")):
            raise HTTPException(401, "Invalid PIN")
    else:
        member_doc = await db.merchant_members.find_one({"member_id": ctx.actor_id})
        member_pin_hash = (member_doc or {}).get("pin_hash", "")
        if member_pin_hash and not verify_password(req.pin, member_pin_hash):
            raise HTTPException(401, "Invalid PIN")

    approval_id = f"TAPPR_{secrets.token_hex(6).upper()}"
    now = _now()
    doc = {
        "approval_id": approval_id,
        "merchant_id": ctx.merchant_id,
        "requested_by_id": ctx.actor_id,
        "requested_by_email": ctx.actor_email,
        "requested_by_name": ctx.actor_name,
        "transfer_data": {
            "account_number": req.account_number,
            "bank_code": req.bank_code,
            "amount": req.amount,
            "narration": req.narration,
            "from_account_id": req.from_account_id,
        },
        "status": "pending",
        "reviewed_by_id": None,
        "reviewed_by_email": None,
        "rejection_reason": None,
        "created_at": now,
        "reviewed_at": None,
    }
    await db.merchant_transfer_approvals.insert_one(doc)
    await merchant_audit(ctx, "transfer.request.created", "merchant_transfer_approvals",
                         {"approval_id": approval_id, "amount": req.amount}, request)
    return {
        "approval_id": approval_id,
        "status": "pending",
        "message": "Transfer request created. Awaiting approval from an authorized approver.",
    }


@router.get("/v1/merchant/transfer-requests")
async def list_transfer_requests(request: Request, status: str = ""):
    """List transfer approval requests for the merchant."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "transfers.initiate")

    query: dict = {"merchant_id": ctx.merchant_id}
    if status:
        query["status"] = status
    approvals = await db.merchant_transfer_approvals.find(
        query
    ).sort("created_at", -1).to_list(100)
    for a in approvals:
        a["_id"] = str(a["_id"])
    return {"approvals": approvals, "total": len(approvals)}


@router.post("/v1/merchant/transfer-requests/{approval_id}/approve")
async def approve_transfer_request(approval_id: str, request: Request):
    """Approve a pending transfer request and execute it."""
    from core import call_sh
    import os
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "transfers.approve")

    appr = await db.merchant_transfer_approvals.find_one(
        {"approval_id": approval_id, "merchant_id": ctx.merchant_id}
    )
    if not appr:
        raise HTTPException(404, "Transfer request not found")
    if appr.get("status") != "pending":
        raise HTTPException(400, f"Transfer request is already {appr['status']}")
    if appr["requested_by_id"] == ctx.actor_id and not ctx.is_owner:
        raise HTTPException(403, "You cannot approve your own transfer request")

    td = appr["transfer_data"]
    now = _now()

    # Get merchant account
    from_acct_id = td.get("from_account_id")
    if from_acct_id:
        acct = await db.merchant_accounts.find_one(
            {"account_id": from_acct_id, "merchant_id": ctx.merchant_id}
        )
    else:
        acct = await db.merchant_accounts.find_one(
            {"merchant_id": ctx.merchant_id, "type": "primary"}
        )
    if not acct:
        raise HTTPException(400, "Source account not found")

    amount_naira = float(td["amount"])
    amount_kobo = int(amount_naira * 100)

    try:
        sh_resp = await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": "",
            "debitAccountNumber": acct["sh_account_number"],
            "beneficiaryBankCode": td["bank_code"],
            "beneficiaryAccountNumber": td["account_number"],
            "amount": amount_naira,
            "saveBeneficiary": False,
            "narration": td.get("narration", "Merchant Transfer"),
        })
    except Exception as exc:
        await db.merchant_transfer_approvals.update_one(
            {"approval_id": approval_id},
            {"$set": {
                "status": "failed",
                "reviewed_by_id": ctx.actor_id,
                "reviewed_by_email": ctx.actor_email,
                "reviewed_at": now,
                "failure_reason": str(exc),
            }}
        )
        raise HTTPException(400, f"Transfer failed: {exc}")

    await db.merchant_transfer_approvals.update_one(
        {"approval_id": approval_id},
        {"$set": {
            "status": "approved",
            "reviewed_by_id": ctx.actor_id,
            "reviewed_by_email": ctx.actor_email,
            "reviewed_at": now,
        }}
    )
    await merchant_audit(ctx, "transfer.request.approved", "merchant_transfer_approvals",
                         {"approval_id": approval_id, "amount": amount_naira}, request)
    return {"message": "Transfer approved and executed", "approval_id": approval_id}


@router.post("/v1/merchant/transfer-requests/{approval_id}/reject")
async def reject_transfer_request(
    approval_id: str, body: TransferApprovalAction, request: Request
):
    """Reject a pending transfer request."""
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "transfers.approve")

    appr = await db.merchant_transfer_approvals.find_one(
        {"approval_id": approval_id, "merchant_id": ctx.merchant_id}
    )
    if not appr:
        raise HTTPException(404, "Transfer request not found")
    if appr.get("status") != "pending":
        raise HTTPException(400, f"Transfer request is already {appr['status']}")
    if appr["requested_by_id"] == ctx.actor_id and not ctx.is_owner:
        raise HTTPException(403, "You cannot reject your own transfer request")

    now = _now()
    await db.merchant_transfer_approvals.update_one(
        {"approval_id": approval_id},
        {"$set": {
            "status": "rejected",
            "reviewed_by_id": ctx.actor_id,
            "reviewed_by_email": ctx.actor_email,
            "rejection_reason": body.rejection_reason or "",
            "reviewed_at": now,
        }}
    )
    await merchant_audit(ctx, "transfer.request.rejected", "merchant_transfer_approvals",
                         {"approval_id": approval_id, "reason": body.rejection_reason}, request)
    return {"message": "Transfer request rejected", "approval_id": approval_id}
