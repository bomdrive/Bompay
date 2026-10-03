"""Bompay — Family Module routes.

Family is a controlled spending + allocation layer that sits on top of the
owner's existing Bompay wallet.  No new bank accounts or SH accounts are created.

Money architecture:
  Owner's wallet (available_balance reduced by allocation)
       ↓  ring-fenced allocation
  Family Wallet (family_groups.available_kobo)
       ↓  per-member allocation
  Member spending balance (family_members.allocated_kobo – spent_kobo)
       ↓  actual payment through existing Bompay payment rails
  External service / merchant
"""

import asyncio
import secrets
import uuid
from datetime import datetime, timezone
from bson import ObjectId

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

from database import db
from core import (
    get_current_user,
    verify_transaction_pin,
    notify,
    logger,
    get_sh_subaccount_balance,
    send_event_sms,
    send_email,
    _email_html,
    get_sms_provider,
    _send_via_bulksms,
    _send_via_sendora,
)

router = APIRouter()


# ─── Request models ────────────────────────────────────────────────────────────

class CreateFamilyReq(BaseModel):
    name: str = Field(..., min_length=2, max_length=60)

class FundFamilyReq(BaseModel):
    amount: float          # naira
    transaction_pin: str

class WithdrawFamilyReq(BaseModel):
    amount: float
    transaction_pin: str

class AddMemberReq(BaseModel):
    user_id: str
    role: str = "member"           # owner | parent | child | member
    allocated_amount: float = 0.0  # naira — initial allocation
    daily_limit: float = 0.0
    monthly_limit: float = 0.0
    allowance_amount: float = 0.0
    allowance_frequency: str = "monthly"  # daily | weekly | monthly | none

class UpdateMemberReq(BaseModel):
    allocated_amount: Optional[float] = None
    daily_limit: Optional[float] = None
    monthly_limit: Optional[float] = None
    allowance_amount: Optional[float] = None
    allowance_frequency: Optional[str] = None

class MoneyRequestReq(BaseModel):
    amount: float
    reason: str = ""

class RespondRequestReq(BaseModel):
    action: str              # "approve" | "reject"
    approved_amount: Optional[float] = None  # override amount on approve
    transaction_pin: str     # only required on approve


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

async def _get_family_or_404(family_id: str):
    fam = await db.family_groups.find_one({"family_id": family_id})
    if not fam:
        raise HTTPException(404, "Family not found")
    return fam

async def _require_owner(family, user_id: str):
    if str(family["owner_user_id"]) != str(user_id):
        raise HTTPException(403, "Only the family owner can perform this action")

async def _ledger(family_id: str, member_id: Optional[str], entry_type: str,
                  amount_kobo: int, description: str, ref_txn: str = ""):
    await db.family_ledger.insert_one({
        "entry_id": str(uuid.uuid4()),
        "family_id": family_id,
        "member_id": member_id,
        "type": entry_type,
        "amount_kobo": amount_kobo,
        "description": description,
        "ref_txn_id": ref_txn,
        "created_at": _now(),
    })

async def _check_family_module_ban(uid: str):
    """Raise 403 if user is banned from the Family module."""
    ban = await db.user_module_bans.find_one({"user_id": str(uid), "module": "family", "active": True})
    if ban:
        reason = ban.get("reason", "")
        msg = "Your access to the Family module has been restricted."
        if reason:
            msg += f" Reason: {reason}"
        msg += " Please contact support."
        raise HTTPException(403, msg)

async def _get_owner_sh_balance(owner_uid: str) -> float:
    """Fetch owner's Safe Haven virtual account balance. Returns -1.0 if unavailable."""
    w = await db.wallets.find_one({"user_id": owner_uid})
    if not w:
        return -1.0
    sh_id = w.get("sh_account_id")
    if not sh_id:
        return -1.0
    try:
        return await get_sh_subaccount_balance(sh_id)
    except Exception:
        return -1.0


# ─── Routes ────────────────────────────────────────────────────────────────────

@router.post("/family")
async def create_family(req: CreateFamilyReq, request: Request):
    """Create a new family group and its wallet (owner only)."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    await _check_family_module_ban(uid)

    # One family per owner for now
    existing = await db.family_groups.find_one({"owner_user_id": uid})
    if existing:
        raise HTTPException(409, "You already have a family. Manage it from your Family page.")

    family_id = str(uuid.uuid4())
    now = _now()
    await db.family_groups.insert_one({
        "family_id": family_id,
        "name": req.name.strip(),
        "owner_user_id": uid,
        "allocated_kobo": 0,
        "available_kobo": 0,
        "status": "ACTIVE",
        "created_at": now,
        "updated_at": now,
    })
    # Auto-add owner as first member with role "owner"
    await db.family_members.insert_one({
        "member_id": str(uuid.uuid4()),
        "family_id": family_id,
        "user_id": uid,
        "role": "owner",
        "allocated_kobo": 0,
        "spent_kobo": 0,
        "daily_limit_kobo": 0,
        "monthly_limit_kobo": 0,
        "allowance_kobo": 0,
        "allowance_frequency": "none",
        "status": "ACTIVE",
        "created_at": now,
    })
    await _ledger(family_id, None, "FAMILY_CREATED", 0, f"Family '{req.name}' created")
    logger.info(f"[Family] {uid} created family {family_id} '{req.name}'")
    return {"family_id": family_id, "message": f"Family '{req.name}' created successfully"}


@router.get("/family")
async def get_family(request: Request):
    """Return the user's family — as owner or as a member."""
    user = await get_current_user(request)
    uid = str(user["_id"])

    # Check if user is an owner
    fam = await db.family_groups.find_one({"owner_user_id": uid})
    if not fam:
        # Check if user is a member in any family
        membership = await db.family_members.find_one({"user_id": uid, "status": {"$ne": "REMOVED"}})
        if membership:
            fam = await db.family_groups.find_one({"family_id": membership["family_id"]})
    if not fam:
        return {"family": None}

    members_raw = await db.family_members.find(
        {"family_id": fam["family_id"], "status": {"$ne": "REMOVED"}},
        {"_id": 0}
    ).to_list(100)

    # Enrich members with user display info
    members = []
    for m in members_raw:
        try:
            u = await db.users.find_one({"_id": ObjectId(m["user_id"])}, {"first_name": 1, "last_name": 1, "phone_number": 1})
        except Exception:
            u = None
        if u:
            m["display_name"] = f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone_number", "Member")
        else:
            m["display_name"] = "Member"
        # Convert kobo → naira for API
        m["allocated_amount"] = m.get("allocated_kobo", 0) / 100
        m["spent_amount"] = m.get("spent_kobo", 0) / 100
        m["remaining_amount"] = (m.get("allocated_kobo", 0) - m.get("spent_kobo", 0)) / 100
        m["daily_limit"] = m.get("daily_limit_kobo", 0) / 100
        m["monthly_limit"] = m.get("monthly_limit_kobo", 0) / 100
        m["allowance_amount"] = m.get("allowance_kobo", 0) / 100
        members.append(m)

    pending_count = await db.family_requests.count_documents(
        {"family_id": fam["family_id"], "status": "PENDING"}
    ) if fam["owner_user_id"] == uid else 0

    return {
        "family": {
            "family_id": fam["family_id"],
            "name": fam["name"],
            "owner_user_id": fam["owner_user_id"],
            "is_owner": fam["owner_user_id"] == uid,
            "allocated_amount": fam.get("allocated_kobo", 0) / 100,
            "available_amount": fam.get("available_kobo", 0) / 100,
            "status": fam.get("status", "ACTIVE"),
            "created_at": fam.get("created_at", ""),
            "members": members,
            "pending_requests_count": pending_count,
        }
    }


@router.post("/family/{family_id}/fund")
async def fund_family_wallet(family_id: str, req: FundFamilyReq, request: Request):
    """
    Ring-fence funds from the owner's wallet into the Family Wallet.
    Safe Haven mirror check only — SH is NOT debited here.
    When members spend their allocation, the owner's SH is debited then.
    """
    user = await get_current_user(request)
    uid = str(user["_id"])
    await _check_family_module_ban(uid)
    await verify_transaction_pin(uid, req.transaction_pin)

    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    amount_kobo = int(req.amount * 100)

    # Safe Haven mirror check — both BOMPAY wallet and SH must have equivalent funds
    sh_bal = await _get_owner_sh_balance(uid)
    if sh_bal >= 0 and sh_bal * 100 < amount_kobo:
        raise HTTPException(400,
            f"Safe Haven balance insufficient. Available: ₦{sh_bal:,.2f}. "
            "Both your BOMPAY wallet and Safe Haven account must have equivalent funds.")

    # Debit owner's available_balance (ring-fence — ledger_balance unchanged, SH not touched yet)
    wallet = await db.wallets.find_one_and_update(
        {"user_id": uid, "available_balance": {"$gte": amount_kobo}},
        {"$inc": {"available_balance": -amount_kobo}},
        return_document=True,
    )
    if not wallet:
        raise HTTPException(400, f"Insufficient balance. You need ₦{req.amount:,.2f} to fund the Family Wallet.")

    # Credit family wallet
    await db.family_groups.update_one(
        {"family_id": family_id},
        {"$inc": {"allocated_kobo": amount_kobo, "available_kobo": amount_kobo},
         "$set": {"updated_at": _now()}},
    )

    txn_id = f"FAM{secrets.token_hex(10).upper()}"
    await _ledger(family_id, None, "OWNER_FUND", amount_kobo,
                  f"₦{req.amount:,.2f} allocated to Family Wallet", txn_id)

    new_fam_bal = (fam.get("available_kobo", 0) + amount_kobo) / 100
    asyncio.create_task(notify(uid, "Family Wallet Funded",
                 f"₦{req.amount:,.2f} added to {fam['name']} Family Wallet.", "success"))

    # SMS + email to owner
    asyncio.create_task(send_event_sms(uid, "FAMILY_FUND", {
        "amount": req.amount, "family": fam["name"], "balance": new_fam_bal,
    }))
    async def _email_owner():
        try:
            owner_email = (user.get("email") or user.get("email_address") or "").strip()
            owner_name  = f"{user.get('first_name','')} {user.get('last_name','')}".strip() or "Customer"
            if owner_email:
                html = _email_html(
                    f"Family Wallet Funded — ₦{req.amount:,.2f}",
                    [
                        f"Hi {owner_name}, you funded your <strong>{fam['name']}</strong> Family Wallet with <strong>₦{req.amount:,.2f}</strong>.",
                        f"Family Wallet balance: ₦{new_fam_bal:,.2f}",
                        "Your Safe Haven account will be debited when family members make purchases.",
                    ],
                    "Manage your family in the BOMPAY app."
                )
                await send_email(to=owner_email,
                                 subject=f"[BOMPAY] Family Wallet Funded — {fam['name']}", html=html)
        except Exception as ex:
            logger.warning(f"[FAMILY-FUND] email failed: {ex}")
    asyncio.create_task(_email_owner())

    logger.info(f"[Family] {uid} funded family {family_id} ₦{req.amount:,.2f}")
    return {
        "message": f"₦{req.amount:,.2f} allocated to Family Wallet",
        "family_available": new_fam_bal,
    }


@router.post("/family/{family_id}/withdraw")
async def withdraw_family_wallet(family_id: str, req: WithdrawFamilyReq, request: Request):
    """Pull unallocated funds back from Family Wallet into owner's wallet."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    await _check_family_module_ban(uid)
    await verify_transaction_pin(uid, req.transaction_pin)

    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    amount_kobo = int(req.amount * 100)
    if amount_kobo <= 0:
        raise HTTPException(400, "Withdrawal amount must be greater than zero.")
    if fam.get("available_kobo", 0) < amount_kobo:
        raise HTTPException(400, "Insufficient Family Wallet balance for withdrawal.")

    # Safe Haven mirror check — verify both sides are in sync
    sh_bal = await _get_owner_sh_balance(uid)
    if sh_bal >= 0 and sh_bal * 100 < amount_kobo:
        raise HTTPException(400,
            f"Safe Haven balance insufficient. Available: ₦{sh_bal:,.2f}. "
            "Wallet and Safe Haven must be equivalent.")

    await db.family_groups.update_one(
        {"family_id": family_id},
        {"$inc": {"allocated_kobo": -amount_kobo, "available_kobo": -amount_kobo},
         "$set": {"updated_at": _now()}},
    )
    await db.wallets.update_one(
        {"user_id": uid},
        {"$inc": {"available_balance": amount_kobo}},
    )
    await _ledger(family_id, None, "OWNER_WITHDRAW", amount_kobo,
                  f"₦{req.amount:,.2f} returned to owner wallet")

    asyncio.create_task(notify(uid, "Family Wallet Withdrawal",
        f"₦{req.amount:,.2f} returned from {fam['name']} to your main wallet."))
    asyncio.create_task(send_event_sms(uid, "FAMILY_WITHDRAW", {
        "amount": req.amount, "family": fam["name"],
    }))
    return {"message": f"₦{req.amount:,.2f} returned to your wallet"}


@router.post("/family/{family_id}/members")
async def add_family_member(family_id: str, req: AddMemberReq, request: Request):
    """Add a member to the family and optionally set allocation + limits."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    await _check_family_module_ban(uid)

    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    # Validate target user exists
    try:
        target = await db.users.find_one({"_id": ObjectId(req.user_id)})
    except Exception:
        target = None
    if not target:
        raise HTTPException(404, "User not found. Ask them to sign up for BOMPAY first.")

    # Prevent duplicate membership
    existing_m = await db.family_members.find_one(
        {"family_id": family_id, "user_id": req.user_id, "status": {"$ne": "REMOVED"}}
    )
    if existing_m:
        raise HTTPException(409, "This user is already a member of the family.")

    allocated_kobo = int(req.allocated_amount * 100)
    if allocated_kobo > 0 and allocated_kobo > fam.get("available_kobo", 0):
        raise HTTPException(400, "Insufficient Family Wallet balance to allocate this amount.")

    member_id = str(uuid.uuid4())
    now = _now()
    await db.family_members.insert_one({
        "member_id": member_id,
        "family_id": family_id,
        "user_id": req.user_id,
        "role": req.role,
        "allocated_kobo": allocated_kobo,
        "spent_kobo": 0,
        "daily_limit_kobo": int(req.daily_limit * 100),
        "monthly_limit_kobo": int(req.monthly_limit * 100),
        "allowance_kobo": int(req.allowance_amount * 100),
        "allowance_frequency": req.allowance_frequency,
        "status": "ACTIVE",
        "created_at": now,
    })

    if allocated_kobo > 0:
        await db.family_groups.update_one(
            {"family_id": family_id},
            {"$inc": {"available_kobo": -allocated_kobo}, "$set": {"updated_at": now}},
        )
        await _ledger(family_id, member_id, "MEMBER_ALLOCATION", allocated_kobo,
                      f"₦{req.allocated_amount:,.2f} allocated to new member")

    target_name = f"{target.get('first_name', '')} {target.get('last_name', '')}".strip() or target.get("phone_number", "")
    asyncio.create_task(notify(req.user_id, "You've been added to a Family",
                               f"You're now part of {fam['name']} on BOMPAY.", "info"))
    # SMS/notify member if they received an initial allocation
    if allocated_kobo > 0:
        asyncio.create_task(send_event_sms(req.user_id, "FAMILY_ALLOCATION", {
            "amount": req.allocated_amount, "family": fam["name"],
            "balance": allocated_kobo / 100,
        }))
    return {"member_id": member_id, "message": f"{target_name} added to {fam['name']}"}


@router.put("/family/{family_id}/members/{member_id}")
async def update_family_member(family_id: str, member_id: str,
                                req: UpdateMemberReq, request: Request):
    """Update a member's allocation, limits, or allowance."""
    user = await get_current_user(request)
    uid = str(user["_id"])

    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    mem = await db.family_members.find_one({"member_id": member_id, "family_id": family_id})
    if not mem:
        raise HTTPException(404, "Member not found")

    updates: dict = {"updated_at": _now()}

    if req.allocated_amount is not None:
        new_alloc = int(req.allocated_amount * 100)
        old_alloc = mem.get("allocated_kobo", 0)
        delta = new_alloc - old_alloc   # positive = more allocation

        if delta > 0 and delta > fam.get("available_kobo", 0):
            raise HTTPException(400, "Insufficient Family Wallet balance for this allocation.")

        updates["allocated_kobo"] = new_alloc
        if delta != 0:
            await db.family_groups.update_one(
                {"family_id": family_id},
                {"$inc": {"available_kobo": -delta}, "$set": {"updated_at": _now()}},
            )
            await _ledger(family_id, member_id, "ALLOCATION_UPDATE", abs(delta),
                          f"Allocation {'increased' if delta > 0 else 'decreased'} by ₦{abs(delta/100):,.2f}")

    if req.daily_limit is not None:
        updates["daily_limit_kobo"] = int(req.daily_limit * 100)
    if req.monthly_limit is not None:
        updates["monthly_limit_kobo"] = int(req.monthly_limit * 100)
    if req.allowance_amount is not None:
        updates["allowance_kobo"] = int(req.allowance_amount * 100)
    if req.allowance_frequency is not None:
        updates["allowance_frequency"] = req.allowance_frequency

    await db.family_members.update_one({"member_id": member_id}, {"$set": updates})
    return {"message": "Member updated successfully"}


@router.put("/family/{family_id}/members/{member_id}/freeze")
async def freeze_family_member(family_id: str, member_id: str, request: Request):
    """Toggle freeze/unfreeze for a member."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    mem = await db.family_members.find_one({"member_id": member_id, "family_id": family_id})
    if not mem:
        raise HTTPException(404, "Member not found")
    if mem.get("role") == "owner":
        raise HTTPException(400, "Cannot freeze the family owner")

    new_status = "ACTIVE" if mem.get("status") == "FROZEN" else "FROZEN"
    await db.family_members.update_one(
        {"member_id": member_id},
        {"$set": {"status": new_status, "updated_at": _now()}},
    )
    action = "unfrozen" if new_status == "ACTIVE" else "frozen"
    return {"status": new_status, "message": f"Member {action} successfully"}


@router.delete("/family/{family_id}/members/{member_id}")
async def remove_family_member(family_id: str, member_id: str, request: Request):
    """Remove a member and return their remaining allocation to the family pool."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    mem = await db.family_members.find_one({"member_id": member_id, "family_id": family_id})
    if not mem or mem.get("status") == "REMOVED":
        raise HTTPException(404, "Member not found")
    if mem.get("role") == "owner":
        raise HTTPException(400, "Cannot remove the family owner")

    remaining = mem.get("allocated_kobo", 0) - mem.get("spent_kobo", 0)
    await db.family_members.update_one(
        {"member_id": member_id},
        {"$set": {"status": "REMOVED", "updated_at": _now()}},
    )
    if remaining > 0:
        await db.family_groups.update_one(
            {"family_id": family_id},
            {"$inc": {"available_kobo": remaining}, "$set": {"updated_at": _now()}},
        )
    await _ledger(family_id, member_id, "MEMBER_REMOVED", remaining,
                  "Member removed — remaining allocation returned to family pool")
    return {"message": "Member removed and remaining allocation returned to Family Wallet"}


@router.post("/family/{family_id}/requests")
async def create_money_request(family_id: str, req: MoneyRequestReq, request: Request):
    """Member requests more spending allocation from the family owner."""
    user = await get_current_user(request)
    uid = str(user["_id"])

    fam = await _get_family_or_404(family_id)
    mem = await db.family_members.find_one(
        {"family_id": family_id, "user_id": uid, "status": "ACTIVE", "role": {"$ne": "owner"}}
    )
    if not mem:
        raise HTTPException(403, "Only non-owner family members can send money requests")

    request_id = str(uuid.uuid4())
    now = _now()
    await db.family_requests.insert_one({
        "request_id": request_id,
        "family_id": family_id,
        "requester_member_id": mem["member_id"],
        "requester_user_id": uid,
        "amount_kobo": int(req.amount * 100),
        "reason": req.reason,
        "status": "PENDING",
        "response_amount_kobo": 0,
        "created_at": now,
        "updated_at": now,
    })
    member_name = {}
    try:
        member_name = await db.users.find_one({"_id": ObjectId(uid)}) or {}
    except Exception:
        pass
    name_str = f"{member_name.get('first_name', '')} {member_name.get('last_name', '')}".strip() or "A member"
    asyncio.create_task(notify(
        fam["owner_user_id"], "Money Request",
        f"{name_str} is requesting ₦{req.amount:,.2f} from {fam['name']}.", "info",
    ))
    return {"request_id": request_id, "message": "Request sent to family owner"}


@router.get("/family/{family_id}/requests")
async def get_family_requests(family_id: str, request: Request):
    """Get all money requests for the family (owner only)."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    reqs = await db.family_requests.find(
        {"family_id": family_id}, {"_id": 0}
    ).sort("created_at", -1).to_list(50)

    for r in reqs:
        try:
            u = await db.users.find_one({"_id": ObjectId(r["requester_user_id"])}, {"first_name": 1, "last_name": 1})
        except Exception:
            u = None
        r["requester_name"] = f"{(u or {}).get('first_name', '')} {(u or {}).get('last_name', '')}".strip() or "Member"
        r["amount"] = r.get("amount_kobo", 0) / 100
        r["response_amount"] = r.get("response_amount_kobo", 0) / 100

    return {"requests": reqs}


@router.put("/family/{family_id}/requests/{request_id}")
async def respond_to_request(family_id: str, request_id: str,
                              req: RespondRequestReq, request: Request):
    """Owner approves or rejects a member money request."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    if req.action not in ("approve", "reject"):
        raise HTTPException(400, "action must be 'approve' or 'reject'")

    mon_req = await db.family_requests.find_one(
        {"request_id": request_id, "family_id": family_id, "status": "PENDING"}
    )
    if not mon_req:
        raise HTTPException(404, "Request not found or already processed")

    if req.action == "reject":
        await db.family_requests.update_one(
            {"request_id": request_id},
            {"$set": {"status": "REJECTED", "updated_at": _now()}},
        )
        asyncio.create_task(notify(mon_req["requester_user_id"], "Request Declined",
                                   f"Your money request was declined.", "error"))
        return {"message": "Request rejected"}

    # Approve
    await verify_transaction_pin(uid, req.transaction_pin)
    approved_kobo = int((req.approved_amount or (mon_req["amount_kobo"] / 100)) * 100)

    if approved_kobo > fam.get("available_kobo", 0):
        raise HTTPException(400, "Insufficient Family Wallet balance to approve this request.")

    # Safe Haven mirror check
    sh_bal = await _get_owner_sh_balance(uid)
    if sh_bal >= 0 and sh_bal * 100 < approved_kobo:
        raise HTTPException(400,
            f"Safe Haven balance insufficient. Available: ₦{sh_bal:,.2f}. "
            "Both wallet and Safe Haven must have equivalent funds.")

    mem = await db.family_members.find_one({"member_id": mon_req["requester_member_id"]})
    if not mem or mem.get("status") != "ACTIVE":
        raise HTTPException(400, "Member is not active")

    await db.family_members.update_one(
        {"member_id": mem["member_id"]},
        {"$inc": {"allocated_kobo": approved_kobo}},
    )
    await db.family_groups.update_one(
        {"family_id": family_id},
        {"$inc": {"available_kobo": -approved_kobo}, "$set": {"updated_at": _now()}},
    )
    await db.family_requests.update_one(
        {"request_id": request_id},
        {"$set": {"status": "APPROVED", "response_amount_kobo": approved_kobo, "updated_at": _now()}},
    )
    await _ledger(family_id, mem["member_id"], "REQUEST_APPROVED", approved_kobo,
                  f"₦{approved_kobo / 100:,.2f} approved from money request")

    member_new_bal = (mem.get("allocated_kobo", 0) + approved_kobo) / 100
    asyncio.create_task(notify(mon_req["requester_user_id"], "Request Approved!",
                               f"₦{approved_kobo / 100:,.2f} added to your Family spending balance.", "success"))
    # SMS to member
    asyncio.create_task(send_event_sms(mon_req["requester_user_id"], "FAMILY_REQUEST_APPROVED", {
        "amount": approved_kobo / 100, "family": fam["name"], "balance": member_new_bal,
    }))
    # Notify + SMS to owner too
    asyncio.create_task(notify(uid, "Request Approved",
        f"You approved ₦{approved_kobo/100:,.2f} for a family member in {fam['name']}."))
    asyncio.create_task(send_event_sms(uid, "FAMILY_ALLOCATION", {
        "amount": approved_kobo / 100, "family": fam["name"], "balance": fam.get("available_kobo", 0) / 100,
    }))
    return {"message": f"₦{approved_kobo / 100:,.2f} approved"}


@router.get("/family/{family_id}/members/search")
async def search_users_for_family(family_id: str, phone: str, request: Request):
    """Search for a BOMPAY user by phone number to add as a family member."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    clean_phone = phone.strip()
    found = await db.users.find_one(
        {"phone_number": clean_phone},
        {"first_name": 1, "last_name": 1, "phone_number": 1},
    )
    if not found:
        raise HTTPException(404, "No Bompay user found with this phone number. Ask them to sign up first.")

    found_uid = str(found["_id"])
    existing = await db.family_members.find_one(
        {"family_id": family_id, "user_id": found_uid, "status": {"$ne": "REMOVED"}}
    )

    return {
        "user": {
            "user_id": found_uid,
            "name": f"{found.get('first_name', '')} {found.get('last_name', '')}".strip() or found.get("phone_number", ""),
            "phone": found.get("phone_number", ""),
            "is_already_member": existing is not None,
            "is_owner": found_uid == uid,
        }
    }


@router.get("/family/{family_id}/members/{member_id}")
async def get_family_member(family_id: str, member_id: str, request: Request):
    """Get details for a single family member (owner only)."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)
    await _require_owner(fam, uid)

    mem = await db.family_members.find_one(
        {"member_id": member_id, "family_id": family_id}, {"_id": 0}
    )
    if not mem or mem.get("status") == "REMOVED":
        raise HTTPException(404, "Member not found")

    try:
        u = await db.users.find_one(
            {"_id": ObjectId(mem["user_id"])},
            {"first_name": 1, "last_name": 1, "phone_number": 1},
        )
    except Exception:
        u = None

    if u:
        mem["display_name"] = f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone_number", "Member")
    else:
        mem["display_name"] = "Member"

    mem["allocated_amount"] = mem.get("allocated_kobo", 0) / 100
    mem["spent_amount"] = mem.get("spent_kobo", 0) / 100
    mem["remaining_amount"] = (mem.get("allocated_kobo", 0) - mem.get("spent_kobo", 0)) / 100
    mem["daily_limit"] = mem.get("daily_limit_kobo", 0) / 100
    mem["monthly_limit"] = mem.get("monthly_limit_kobo", 0) / 100
    mem["allowance_amount"] = mem.get("allowance_kobo", 0) / 100
    return {"member": mem}


@router.get("/family/{family_id}/ledger")
async def get_family_ledger(
    family_id: str, request: Request,
    member_id: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
):
    """Get the family's activity ledger with optional filters."""
    user = await get_current_user(request)
    uid = str(user["_id"])
    fam = await _get_family_or_404(family_id)

    # Owner or active member can view
    is_member = await db.family_members.find_one(
        {"family_id": family_id, "user_id": uid, "status": {"$ne": "REMOVED"}}
    )
    if not is_member and fam["owner_user_id"] != uid:
        raise HTTPException(403, "Access denied")

    query: dict = {"family_id": family_id}
    if member_id:
        query["member_id"] = member_id
    if from_date or to_date:
        date_filter: dict = {}
        if from_date:
            date_filter["$gte"] = from_date
        if to_date:
            date_filter["$lte"] = to_date + "T23:59:59.999Z"
        query["created_at"] = date_filter

    entries = await db.family_ledger.find(query, {"_id": 0}).sort("created_at", -1).to_list(200)

    for e in entries:
        e["amount"] = e.get("amount_kobo", 0) / 100

    return {"ledger": entries}


# ─── ADMIN: FAMILY MODULE BAN ─────────────────────────────────────────────────
@router.post("/admin/family/users/{user_id}/ban")
async def admin_ban_family_user(user_id: str, request: Request):
    """Ban or unban a user from the Family module."""
    admin = await get_current_user(request)
    if admin.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    try:
        body = await request.json()
    except Exception:
        body = {}
    action = body.get("action", "ban")   # "ban" | "unban"
    reason = body.get("reason", "")
    if action == "ban":
        await db.user_module_bans.update_one(
            {"user_id": user_id, "module": "family"},
            {"$set": {"user_id": user_id, "module": "family", "active": True,
                      "reason": reason, "banned_at": _now(),
                      "banned_by": str(admin["_id"])}},
            upsert=True,
        )
        asyncio.create_task(notify(user_id, "Family Module Restricted",
            "Your access to Family has been restricted. Contact support for details."))
        return {"message": "User banned from Family module"}
    else:
        await db.user_module_bans.update_one(
            {"user_id": user_id, "module": "family"},
            {"$set": {"active": False, "unbanned_at": _now(),
                      "unbanned_by": str(admin["_id"])}},
        )
        asyncio.create_task(notify(user_id, "Family Module Restored",
            "Your access to the Family module has been restored."))
        return {"message": "User unbanned from Family module"}
