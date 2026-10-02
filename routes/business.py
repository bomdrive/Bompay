"""BOMPAY Business — corporate subaccounts, staff, payroll, CRM, expenses."""
from __future__ import annotations
import asyncio, logging, os, re, uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import (
    get_current_user, call_sh, SAFEHAVEN_OWN_BANK_CODE,
    send_email, _email_html, notify, get_sms_provider,
    _send_via_bulksms, _send_via_sendora,
)

WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", "")

logger = logging.getLogger(__name__)
router = APIRouter()

# ─── helpers ────────────────────────────────────────────────────────────────
def now_utc(): return datetime.now(timezone.utc)
def oid(v): return ObjectId(v) if isinstance(v, str) else v

def clean(doc):
    if not doc: return None
    doc = dict(doc); doc["id"] = str(doc.pop("_id", "")); return doc

async def _get_business(business_id: str, user_id):
    b = await db.businesses.find_one({"_id": oid(business_id), "owner_id": str(user_id)})
    if not b: raise HTTPException(404, "Business not found")
    return b

async def _biz_wallet(business_id: str):
    w = await db.business_wallets.find_one({"business_id": str(business_id)})
    if not w: raise HTTPException(404, "Business wallet not found")
    return w

async def _max_businesses() -> int:
    cfg = await db.admin_settings.find_one({"key": "business_config"}) or {}
    return cfg.get("max_per_user", 0)          # 0 = not set yet → block creation

async def _record_biz_txn(business_id: str, direction: str, category: str,
                           amount_kobo: int, description: str, metadata: dict = None):
    await db.business_transactions.insert_one({
        "business_id": str(business_id), "direction": direction,
        "category": category, "amount": amount_kobo,
        "description": description, "metadata": metadata or {},
        "created_at": now_utc(),
    })

# ─── MODELS ─────────────────────────────────────────────────────────────────
class CreateBusinessReq(BaseModel):
    name: str
    business_type: str          # sole_proprietorship | limited_liability | partnership | ngo
    rc_number: str              # RC or BN number
    phone: str                  # with country code e.g. +234...
    email: str
    address: str
    description: Optional[str] = ""
    # Director KYB fields
    director_is_applicant: bool = True
    director_name: Optional[str] = ""
    director_bvn: Optional[str] = ""
    director_position: Optional[str] = "Director"

class AddStaffReq(BaseModel):
    account_number: str         # Bompay/SH account number
    department: str
    role: str
    gross_pay: float            # in naira
    net_pay: float              # in naira

class TerminateStaffReq(BaseModel):
    reason: Optional[str] = ""

class PayrollConfigReq(BaseModel):
    pay_day: int                # day of month 1-28

class TransferFromBusinessReq(BaseModel):
    amount: float
    beneficiary_account: str
    beneficiary_bank_code: str
    narration: Optional[str] = "Business transfer"
    transaction_pin: str

class CRMCustomerReq(BaseModel):
    name: str
    email: Optional[str] = ""
    phone: Optional[str] = ""
    address: Optional[str] = ""
    notes: Optional[str] = ""

class CRMSaleReq(BaseModel):
    customer_id: Optional[str] = None
    amount: float
    description: str
    status: Optional[str] = "completed"

class InvoiceItem(BaseModel):
    description: str
    qty: int
    unit_price: float

class InvoiceReq(BaseModel):
    customer_id: Optional[str] = None
    customer_name: Optional[str] = ""
    items: list[InvoiceItem]
    tax_percent: Optional[float] = 0
    due_days: Optional[int] = 7
    notes: Optional[str] = ""

class ExpenseReq(BaseModel):
    category: str
    amount: float
    description: str
    date: Optional[str] = None

class StaffLoanReq(BaseModel):
    amount: float
    repayment_months: int

class RejectLoanReq(BaseModel):
    reason: Optional[str] = ""


class RejectBusinessReq(BaseModel):
    reason: Optional[str] = ""

class SendInvoiceEmailReq(BaseModel):
    email: str

class ExpenseBudgetReq(BaseModel):
    budgets: dict   # {category_name: monthly_limit_ngn}


# ─── PUBLIC: GET BUSINESS CONFIG (for all authenticated users) ───────────────
@router.get("/business/config")
async def get_business_config(request: Request):
    """Returns business creation settings readable by any authenticated user."""
    await get_current_user(request)
    cfg = await db.admin_settings.find_one({"key": "business_config"}) or {}
    return {"max_per_user": cfg.get("max_per_user", 0)}


# ─── BUSINESS LOOKUP (recipient discovery) ────────────────────────────────────
@router.get("/business/lookup")
async def lookup_business(query: str = "", request: Request = None):
    """Search active businesses by name — for use as transfer recipients."""
    await get_current_user(request)
    q = query.strip()
    if len(q) < 2:
        return {"businesses": []}
    results = await db.businesses.find({
        "status": "active",
        "sh_account_number": {"$exists": True, "$ne": ""},
        "name": {"$regex": q, "$options": "i"},
    }).limit(6).to_list(None)
    return {"businesses": [
        {
            "id":           str(b["_id"]),
            "name":         b["name"],
            "account_number": b.get("sh_account_number", ""),
            "bank_name":    b.get("sh_bank_name", "Safe Haven MFB"),
            "bank_code":    "090286",   # Safe Haven MFB code
            "business_type": (b.get("business_type") or "").replace("_", " ").title(),
        }
        for b in results
    ]}



@router.post("/business/create")
async def create_business(req: CreateBusinessReq, request: Request):
    user = await get_current_user(request)
    uid_str = str(user["_id"])

    max_biz = await _max_businesses()
    if max_biz == 0:
        raise HTTPException(403, "Business accounts are not yet enabled. Please contact support.")
    count = await db.businesses.count_documents(
        {"owner_id": uid_str, "status": {"$nin": ["deleted", "rejected"]}}
    )
    if count >= max_biz:
        raise HTTPException(400, f"Maximum of {max_biz} business account(s) allowed per user.")

    # Block new application if one is already pending review
    pending = await db.businesses.find_one({"owner_id": uid_str, "status": "pending_approval"})
    if pending:
        raise HTTPException(400, "You already have a business application under review. Please wait for it to be approved or rejected before applying again.")

    # KYC gate — require at least Tier 1 (BVN/NIN verified + virtual account created)
    kyc_tier = user.get("kyc_tier", 0)
    if kyc_tier < 1:
        raise HTTPException(400, "Please complete your personal KYC (BVN verification) before applying for a business account.")

    phone = req.phone.strip()
    if not phone.startswith("+"):
        phone = "+234" + phone.lstrip("0")

    now = now_utc()
    external_ref = f"bompay-biz-{uid_str[:8]}-{uuid.uuid4().hex[:8]}"
    biz_doc = {
        "owner_id": uid_str,
        "name": req.name.strip(),
        "business_type": req.business_type,
        "rc_number": req.rc_number.strip(),
        "phone": phone,
        "email": req.email,
        "address": req.address,
        "description": req.description or "",
        "status": "pending_approval",
        "external_ref": external_ref,
        # Director KYB info
        "director_is_applicant": req.director_is_applicant,
        "director_name": req.director_name.strip() if req.director_name else "",
        "director_bvn": req.director_bvn.strip() if req.director_bvn else "",
        "director_position": req.director_position or "Director",
        "director_identity_id": None,
        "director_kyb_status": "pending",  # pending | initiated | verified
        "created_at": now,
        "updated_at": now,
    }
    result = await db.businesses.insert_one(biz_doc)
    biz_id = str(result.inserted_id)

    await db.business_wallets.insert_one({
        "business_id": biz_id, "owner_id": uid_str,
        "available_balance": 0, "ledger_balance": 0,
        "created_at": now,
    })

    return {
        "message": "Business application submitted. Our team will review and activate your account within 24–48 hours.",
        "business_id": biz_id,
        "status": "pending_approval",
    }


# ─── 2. GET MY BUSINESSES ────────────────────────────────────────────────────
@router.get("/business/my")
async def get_my_businesses(request: Request):
    user = await get_current_user(request)
    businesses = await db.businesses.find(
        {"owner_id": str(user["_id"]), "status": {"$ne": "deleted"}}
    ).to_list(None)
    result = []
    for b in businesses:
        w = await db.business_wallets.find_one({"business_id": str(b["_id"])}) or {}
        bc = clean(b)
        bc["wallet_balance"] = (w.get("available_balance", 0)) / 100
        result.append(bc)
    return {"businesses": result}


# ─── 2b. GET MY STAFF LOANS (current user as employee) ───────────────────────
@router.get("/business/my-loans")
async def get_my_staff_loans(request: Request):
    """Returns all staff loans for the currently logged-in user (across all businesses)."""
    user = await get_current_user(request)
    loans = await db.business_staff_loans.find(
        {"user_id": str(user["_id"])}
    ).sort("created_at", -1).to_list(None)
    result = []
    for loan in loans:
        biz = await db.businesses.find_one({"_id": oid(loan["business_id"])})
        created = loan.get("created_at")
        result.append({
            "id":                     str(loan["_id"]),
            "business_name":          biz["name"] if biz else "Unknown Business",
            "amount_ngn":             loan.get("amount", 0) / 100,
            "monthly_deduction_ngn":  loan.get("monthly_deduction", 0) / 100,
            "outstanding_balance_ngn": loan.get("outstanding_balance", 0) / 100,
            "status":                 loan.get("status", ""),
            "reason":                 loan.get("reason", ""),
            "created_at":             created.isoformat() if hasattr(created, "isoformat") else "",
        })
    return {"loans": result}


# ─── 3. GET SINGLE BUSINESS ──────────────────────────────────────────────────
@router.get("/business/{business_id}")
async def get_business(business_id: str, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])
    w = await db.business_wallets.find_one({"business_id": business_id}) or {}
    staff_count = await db.business_staff.count_documents({"business_id": business_id, "status": "active"})
    staff = await db.business_staff.find({"business_id": business_id, "status": "active"}).to_list(None)
    total_net = sum(s.get("net_pay", 0) for s in staff)
    bc = clean(b)
    bc["wallet_balance"] = w.get("available_balance", 0) / 100
    bc["staff_count"] = staff_count
    bc["total_net_pay"] = total_net / 100
    return bc


# ─── 4. BUSINESS WALLET BALANCE (live from SH) ───────────────────────────────
@router.get("/business/{business_id}/wallet")
async def business_wallet(business_id: str, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])
    w = await _biz_wallet(business_id)
    sh_balance = None

    # Try by subaccount ID first
    if b.get("sh_subaccount_id"):
        try:
            r = await call_sh("GET", f"/accounts/{b['sh_subaccount_id']}")
            acc = r.get("data", r)
            sh_balance = float(acc.get("availableBalance", acc.get("balance", -1)))
            if sh_balance < 0:
                sh_balance = None
        except Exception as e:
            logger.warning(f"[BIZ-WALLET] SH fetch by id failed: {e}")

    # Fallback: look up by account number
    if sh_balance is None and b.get("sh_account_number"):
        try:
            r = await call_sh("GET", f"/accounts", params={"accountNumber": b["sh_account_number"]})
            items = r.get("data", r)
            if isinstance(items, list) and items:
                items = items[0]
            elif isinstance(items, dict):
                pass
            sh_balance = float(items.get("availableBalance", items.get("balance", -1)))
            if sh_balance < 0:
                sh_balance = None
        except Exception as e:
            logger.warning(f"[BIZ-WALLET] SH fetch by acct_num failed: {e}")

    # Final fallback: use internal ledger
    if sh_balance is None:
        sh_balance = w.get("available_balance", 0) / 100

    return {
        "available_balance": sh_balance,
        "ledger_balance": w.get("ledger_balance", 0) / 100,
        "account_number": b.get("sh_account_number", ""),
        "bank_name": b.get("sh_bank_name", "Safe Haven MFB"),
    }


# ─── 5. STAFF — VALIDATE ACCOUNT ────────────────────────────────────────────
@router.get("/business/{business_id}/staff/validate")
async def validate_staff_account(business_id: str, account_number: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    # Look up user by account number
    target = await db.wallets.find_one({"account_number": account_number})
    if not target:
        raise HTTPException(404, "Account not found on BOMPAY. Staff must have a BOMPAY account.")
    target_user = await db.users.find_one({"_id": oid(target["user_id"])})
    if not target_user:
        raise HTTPException(404, "User not found")
    return {
        "valid": True,
        "user_id": str(target_user["_id"]),
        "name": f"{target_user.get('first_name','')} {target_user.get('last_name','')}".strip(),
        "account_number": account_number,
    }


# ─── 6. STAFF — ADD ─────────────────────────────────────────────────────────
@router.post("/business/{business_id}/staff/add")
async def add_staff(business_id: str, req: AddStaffReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])

    # Validate account
    target_wallet = await db.wallets.find_one({"account_number": req.account_number})
    if not target_wallet:
        raise HTTPException(404, "Staff must have an active BOMPAY account")
    target_user = await db.users.find_one({"_id": oid(target_wallet["user_id"])})
    if not target_user:
        raise HTTPException(404, "User not found")

    # Check if already added
    existing = await db.business_staff.find_one({
        "business_id": business_id,
        "account_number": req.account_number,
        "status": "active"
    })
    if existing:
        raise HTTPException(400, "Staff member already exists in this business")

    doc = {
        "business_id": business_id,
        "owner_id": str(user["_id"]),
        "user_id": str(target_user["_id"]),
        "account_number": req.account_number,
        "name": f"{target_user.get('first_name','')} {target_user.get('last_name','')}".strip(),
        "phone": target_user.get("phone", ""),
        "department": req.department,
        "role": req.role,
        "gross_pay": int(req.gross_pay * 100),
        "net_pay": int(req.net_pay * 100),
        "status": "active",
        "created_at": now_utc(),
    }
    await db.business_staff.insert_one(doc)
    return {"message": "Staff added successfully"}


# ─── 7. STAFF — LIST ────────────────────────────────────────────────────────
@router.get("/business/{business_id}/staff")
async def list_staff(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    staff = await db.business_staff.find({"business_id": business_id}).sort("created_at", -1).to_list(None)
    return {"staff": [clean(s) for s in staff]}


# ─── 8. STAFF — TERMINATE ───────────────────────────────────────────────────
@router.put("/business/{business_id}/staff/{staff_id}/terminate")
async def terminate_staff(business_id: str, staff_id: str, req: TerminateStaffReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    r = await db.business_staff.update_one(
        {"_id": oid(staff_id), "business_id": business_id},
        {"$set": {"status": "terminated", "termination_reason": req.reason, "terminated_at": now_utc()}}
    )
    if r.matched_count == 0:
        raise HTTPException(404, "Staff not found")
    return {"message": "Staff terminated"}


# ─── 9. PAYROLL CONFIG ───────────────────────────────────────────────────────
@router.post("/business/{business_id}/payroll/configure")
async def configure_payroll(business_id: str, req: PayrollConfigReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    if not 1 <= req.pay_day <= 28:
        raise HTTPException(400, "Pay day must be between 1 and 28")
    await db.businesses.update_one(
        {"_id": oid(business_id)},
        {"$set": {"pay_day": req.pay_day, "updated_at": now_utc()}}
    )
    return {"message": f"Pay day set to the {req.pay_day} of every month"}


# ─── 10. PAYROLL — AUTHORIZE (bulk salary run) ───────────────────────────────
@router.get("/business/{business_id}/payroll/preview")
async def get_payroll_preview(business_id: str, request: Request):
    """Returns per-staff payroll breakdown including any active loan deductions, without executing anything."""
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])

    active_staff = await db.business_staff.find(
        {"business_id": business_id, "status": "active"}
    ).to_list(None)

    w = await _biz_wallet(business_id)
    available = w.get("available_balance", 0)

    staff_rows = []
    total_gross = 0
    total_net = 0
    total_loan_ded = 0
    total_payout = 0

    for s in active_staff:
        gross   = s.get("gross_pay", 0)
        net     = s.get("net_pay",   0)
        active_loans = await db.business_staff_loans.find(
            {"business_id": business_id, "staff_id": str(s["_id"]), "status": "active"}
        ).to_list(None)
        loan_ded   = sum(min(l.get("monthly_deduction", 0), l.get("outstanding_balance", 0)) for l in active_loans)
        adj_net    = max(0, net - loan_ded)
        total_gross  += gross
        total_net    += net
        total_loan_ded += loan_ded
        total_payout += adj_net
        staff_rows.append({
            "id": str(s["_id"]),
            "name": s.get("name", ""),
            "department": s.get("department", ""),
            "role": s.get("role", ""),
            "gross_pay_ngn": gross / 100,
            "net_pay_ngn": net / 100,
            "loan_deduction_ngn": loan_ded / 100,
            "adjusted_net_ngn": adj_net / 100,
            "active_loans": len(active_loans),
        })

    return {
        "staff": staff_rows,
        "summary": {
            "staff_count": len(staff_rows),
            "total_gross_ngn": total_gross / 100,
            "total_net_before_deductions_ngn": total_net / 100,
            "total_loan_deductions_ngn": total_loan_ded / 100,
            "total_payout_ngn": total_payout / 100,
            "available_balance_ngn": available / 100,
            "can_run": available >= total_payout,
            "shortfall_ngn": max(0, total_payout - available) / 100,
        }
    }


@router.post("/business/{business_id}/payroll/run")
async def run_payroll(business_id: str, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])

    active_staff = await db.business_staff.find(
        {"business_id": business_id, "status": "active"}
    ).to_list(None)
    if not active_staff:
        raise HTTPException(400, "No active staff to pay")

    # ── Calculate total payout after loan deductions ──────────────────────────
    staff_with_loans = []
    for s in active_staff:
        active_loans = await db.business_staff_loans.find(
            {"business_id": business_id, "staff_id": str(s["_id"]), "status": "active"}
        ).to_list(None)
        loan_ded = sum(min(l.get("monthly_deduction", 0), l.get("outstanding_balance", 0)) for l in active_loans)
        adj_net  = max(0, s.get("net_pay", 0) - loan_ded)
        staff_with_loans.append((s, active_loans, loan_ded, adj_net))

    total_payout = sum(adj for _, _, _, adj in staff_with_loans)
    w = await _biz_wallet(business_id)
    if w["available_balance"] < total_payout:
        raise HTTPException(400, f"Insufficient balance. Need ₦{total_payout/100:,.2f}, have ₦{w['available_balance']/100:,.2f}")

    errors = []
    paid   = []

    for staff, active_loans, loan_ded, adj_net in staff_with_loans:
        try:
            staff_wallet = await db.wallets.find_one({"user_id": staff.get("user_id")})
            if not staff_wallet:
                errors.append(f"{staff['name']}: wallet not found"); continue

            # Debit business, credit staff (adj_net only — loan deduction stays in biz)
            await db.business_wallets.update_one(
                {"business_id": business_id},
                {"$inc": {"available_balance": -adj_net, "ledger_balance": -adj_net}}
            )
            await db.wallets.update_one(
                {"user_id": staff.get("user_id")},
                {"$inc": {"available_balance": adj_net, "ledger_balance": adj_net}}
            )

            # SH transfer
            if b.get("sh_subaccount_id") and adj_net > 0:
                try:
                    await call_sh("POST", "/transfers", body={
                        "nameEnquiryReference": "",
                        "debitAccountNumber": b["sh_account_number"],
                        "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                        "beneficiaryAccountNumber": staff_wallet.get("account_number", ""),
                        "amount": adj_net,
                        "saveBeneficiary": False,
                        "narration": f"Salary – {b['name']}",
                        "paymentReference": f"SAL-{business_id[:8]}-{staff['_id']}",
                    })
                except Exception as e:
                    logger.warning(f"[PAYROLL] SH transfer failed for {staff['name']}: {e}")

            await _record_biz_txn(business_id, "DEBIT", "SALARY", adj_net,
                                  f"Salary to {staff['name']}" + (f" (loan deducted: ₦{loan_ded/100:,.2f})" if loan_ded else ""),
                                  {"staff_id": str(staff["_id"])})

            # ── Process loan repayments ───────────────────────────────────────
            for loan in active_loans:
                instalment  = min(loan.get("monthly_deduction", 0), loan.get("outstanding_balance", 0))
                new_balance = max(0, loan.get("outstanding_balance", 0) - instalment)
                new_status  = "completed" if new_balance == 0 else "active"
                await db.business_staff_loans.update_one(
                    {"_id": loan["_id"]},
                    {"$set": {"outstanding_balance": new_balance, "status": new_status,
                              "last_deduction_at": now_utc()},
                     "$push": {"repayments": {"amount": instalment, "date": now_utc().isoformat(),
                                              "remaining": new_balance}}}
                )

            paid.append(staff["name"])
        except Exception as e:
            errors.append(f"{staff['name']}: {e}")

    await db.business_payroll.insert_one({
        "business_id": business_id,
        "owner_id": str(user["_id"]),
        "total_amount": total_payout,
        "staff_paid": paid,
        "errors": errors,
        "status": "completed" if not errors else "partial",
        "run_at": now_utc(),
        "auto": False,
    })
    return {"message": f"Payroll completed. {len(paid)} paid, {len(errors)} errors.",
            "paid": paid, "errors": errors}


# ─── 11. PAYROLL HISTORY ────────────────────────────────────────────────────
@router.get("/business/{business_id}/payroll/history")
async def payroll_history(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    runs = await db.business_payroll.find({"business_id": business_id}).sort("run_at", -1).limit(20).to_list(None)
    return {"history": [clean(r) for r in runs]}


# ─── 12. BUSINESS TRANSACTIONS ───────────────────────────────────────────────
@router.get("/business/{business_id}/transactions")
async def business_transactions(business_id: str, page: int = 1, limit: int = 20, request: Request = None):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    skip = (page - 1) * limit
    txns = await db.business_transactions.find({"business_id": business_id})\
        .sort("created_at", -1).skip(skip).limit(limit).to_list(None)
    return {"transactions": [clean(t) for t in txns]}


# ─── 13. TRANSFER FROM BUSINESS ──────────────────────────────────────────────
@router.post("/business/{business_id}/transfer")
async def business_transfer(business_id: str, req: TransferFromBusinessReq, request: Request):
    from core import verify_pin_hash
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])
    if b["status"] != "active":
        raise HTTPException(400, "Business account is not active")

    # Verify PIN
    if not user.get("pin_hash"):
        raise HTTPException(400, "Transaction PIN not set")
    if not verify_pin_hash(req.transaction_pin, user["pin_hash"]):
        raise HTTPException(401, "Incorrect transaction PIN")

    amount_kobo = int(req.amount * 100)
    w = await _biz_wallet(business_id)
    if w["available_balance"] < amount_kobo:
        raise HTTPException(400, "Insufficient business balance")

    # Name enquiry
    try:
        ne = await call_sh("POST", "/transfers/name-enquiry", body={
            "accountNumber": req.beneficiary_account,
            "bankCode": req.beneficiary_bank_code,
        })
        ne_data = ne.get("data", ne)
        beneficiary_name = ne_data.get("accountName", "")
        ne_ref = ne_data.get("sessionId") or ne_data.get("nameEnquiryReference", "")
    except Exception as e:
        raise HTTPException(502, f"Name enquiry failed: {e}")

    # Bompay money movement: debit business wallet
    await db.business_wallets.update_one(
        {"business_id": business_id},
        {"$inc": {"available_balance": -amount_kobo, "ledger_balance": -amount_kobo}}
    )

    # SH transfer from business subaccount
    try:
        await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": ne_ref,
            "debitAccountNumber": b["sh_account_number"],
            "beneficiaryBankCode": req.beneficiary_bank_code,
            "beneficiaryAccountNumber": req.beneficiary_account,
            "amount": amount_kobo,
            "saveBeneficiary": False,
            "narration": req.narration,
            "paymentReference": f"BIZTXN-{uuid.uuid4().hex[:12]}",
        })
    except Exception as e:
        # Reverse wallet debit on SH failure
        await db.business_wallets.update_one(
            {"business_id": business_id},
            {"$inc": {"available_balance": amount_kobo, "ledger_balance": amount_kobo}}
        )
        raise HTTPException(502, f"Transfer failed: {e}")

    await _record_biz_txn(business_id, "DEBIT", "TRANSFER", amount_kobo,
                          f"Transfer to {beneficiary_name}",
                          {"account": req.beneficiary_account, "narration": req.narration})
    return {"message": "Transfer successful", "beneficiary_name": beneficiary_name}


# ─── 14. CRM — CUSTOMERS ─────────────────────────────────────────────────────
@router.post("/business/{business_id}/crm/customers")
async def add_customer(business_id: str, req: CRMCustomerReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    doc = {"business_id": business_id, **req.dict(), "created_at": now_utc()}
    r = await db.business_crm_customers.insert_one(doc)
    return {"message": "Customer added", "id": str(r.inserted_id)}

@router.get("/business/{business_id}/crm/customers")
async def get_customers(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    customers = await db.business_crm_customers.find({"business_id": business_id}).sort("created_at", -1).to_list(None)
    return {"customers": [clean(c) for c in customers]}


# ─── 15. CRM — SALES ─────────────────────────────────────────────────────────
@router.post("/business/{business_id}/crm/sales")
async def add_sale(business_id: str, req: CRMSaleReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    doc = {"business_id": business_id, **req.dict(), "amount": int(req.amount * 100), "created_at": now_utc()}
    r = await db.business_crm_sales.insert_one(doc)
    return {"message": "Sale recorded", "id": str(r.inserted_id)}

@router.get("/business/{business_id}/crm/sales")
async def get_sales(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    sales = await db.business_crm_sales.find({"business_id": business_id}).sort("created_at", -1).to_list(None)
    result = []
    for s in sales:
        sc = clean(s); sc["amount"] = sc["amount"] / 100; result.append(sc)
    return {"sales": result}


# ─── 16. INVOICES ────────────────────────────────────────────────────────────
@router.post("/business/{business_id}/crm/invoices")
async def create_invoice(business_id: str, req: InvoiceReq, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])
    items = [{"description": i.description, "qty": i.qty,
              "unit_price": i.unit_price, "total": i.qty * i.unit_price} for i in req.items]
    subtotal = sum(i["total"] for i in items)
    tax = subtotal * (req.tax_percent / 100)
    total = subtotal + tax
    count = await db.business_invoices.count_documents({"business_id": business_id})
    invoice_number = f"INV-{str(count + 1).zfill(4)}"
    customer_name = req.customer_name
    if req.customer_id:
        cust = await db.business_crm_customers.find_one({"_id": oid(req.customer_id)})
        if cust: customer_name = cust.get("name", customer_name)
    doc = {
        "business_id": business_id,
        "owner_id": str(user["_id"]),
        "invoice_number": invoice_number,
        "customer_id": req.customer_id,
        "customer_name": customer_name,
        "business_name": b["name"],
        "items": items,
        "subtotal": subtotal,
        "tax_percent": req.tax_percent,
        "tax": tax,
        "total": total,
        "notes": req.notes,
        "status": "draft",
        "due_date": (now_utc() + timedelta(days=req.due_days)).isoformat(),
        "created_at": now_utc(),
    }
    r = await db.business_invoices.insert_one(doc)
    return {
        "message": "Invoice created",
        "id": str(r.inserted_id),
        "invoice_number": invoice_number,
        "business_id": business_id,
        "customer_name": customer_name,
        "business_name": b["name"],
        "items": items,
        "subtotal": subtotal,
        "tax_percent": req.tax_percent,
        "tax": tax,
        "total": total,
        "notes": req.notes,
        "status": "draft",
        "due_date": (now_utc() + timedelta(days=req.due_days)).isoformat(),
    }

@router.get("/business/{business_id}/crm/invoices")
async def get_invoices(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    invoices = await db.business_invoices.find({"business_id": business_id}).sort("created_at", -1).to_list(None)
    return {"invoices": [clean(i) for i in invoices]}

@router.put("/business/{business_id}/crm/invoices/{invoice_id}/status")
async def update_invoice_status(business_id: str, invoice_id: str, status: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    await db.business_invoices.update_one(
        {"_id": oid(invoice_id), "business_id": business_id},
        {"$set": {"status": status}}
    )
    return {"message": "Invoice updated"}


# ─── 16c. EXPENSE BUDGETS ─────────────────────────────────────────────────────
@router.get("/business/{business_id}/budgets")
async def get_expense_budgets(business_id: str, request: Request):
    """Returns monthly expense budgets with current-month spend per category."""
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    budget_doc = await db.business_budgets.find_one({"business_id": business_id}) or {}
    budgets_kobo = budget_doc.get("budgets", {})

    now = now_utc()
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    expenses = await db.business_expenses.find({
        "business_id": business_id,
        "created_at": {"$gte": start},
    }).to_list(None)
    spend_kobo = {}
    for e in expenses:
        cat = e.get("category") or "Other"
        spend_kobo[cat] = spend_kobo.get(cat, 0) + (e.get("amount") or 0)

    all_cats = sorted(set(list(budgets_kobo.keys()) + list(spend_kobo.keys())))
    result = {}
    for cat in all_cats:
        lim  = budgets_kobo.get(cat, 0)
        sp   = spend_kobo.get(cat, 0)
        pct  = round((sp / lim * 100) if lim > 0 else 0, 1)
        result[cat] = {"limit_ngn": lim / 100, "spent_ngn": sp / 100, "percent": pct}
    return {"budgets": result}


@router.post("/business/{business_id}/budgets")
async def set_expense_budgets(business_id: str, req: ExpenseBudgetReq, request: Request):
    """Set monthly expense budgets by category (amounts in NGN)."""
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    budgets_kobo = {
        cat: int(float(limit) * 100)
        for cat, limit in req.budgets.items()
        if float(limit) > 0
    }
    await db.business_budgets.update_one(
        {"business_id": business_id},
        {"$set": {"budgets": budgets_kobo, "updated_at": now_utc()}},
        upsert=True,
    )
    return {"message": "Budgets updated"}


# ─── 16b. SEND INVOICE BY EMAIL ───────────────────────────────────────────────
@router.post("/business/{business_id}/crm/invoices/{invoice_id}/send-email")
async def send_invoice_email(
    business_id: str, invoice_id: str, req: SendInvoiceEmailReq, request: Request
):
    """Sends an invoice PDF-quality HTML email to the specified email address."""
    user = await get_current_user(request)
    b    = await _get_business(business_id, user["_id"])
    inv  = await db.business_invoices.find_one(
        {"_id": oid(invoice_id), "business_id": business_id}
    )
    if not inv:
        raise HTTPException(404, "Invoice not found")

    items_html = "".join([
        f'<tr style="border-bottom:1px solid #f1f5f9">'
        f'<td style="padding:8px 12px;font-size:13px;color:#334155">{item.get("description","")}</td>'
        f'<td style="padding:8px 12px;font-size:13px;color:#334155;text-align:center">{item.get("qty",1)}</td>'
        f'<td style="padding:8px 12px;font-size:13px;color:#334155;text-align:right">'
        f'&#8358;{float(item.get("unit_price",0)):,.2f}</td>'
        f'<td style="padding:8px 12px;font-size:13px;font-weight:600;color:#0f172a;text-align:right">'
        f'&#8358;{float(item.get("qty",1)) * float(item.get("unit_price",0)):,.2f}</td>'
        f'</tr>'
        for item in inv.get("items", [])
    ])
    tax_row = (
        f'<tr><td style="text-align:right;padding:3px 12px 3px 0;font-size:12px;color:#64748b">'
        f'Tax ({inv.get("tax_percent",0)}%):</td>'
        f'<td style="text-align:right;padding:3px 0;font-size:12px;font-weight:600;color:#0f172a">'
        f'&#8358;{float(inv.get("tax",0)):,.2f}</td></tr>'
    ) if inv.get("tax_percent") else ""
    notes_block = (
        f'<p style="font-size:12px;color:#64748b;padding:12px;background:#f8fafc;border-radius:8px;margin-top:12px">'
        f'<strong>Notes:</strong> {inv.get("notes","")}</p>'
    ) if inv.get("notes") else ""

    html = f"""
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
           style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
      <tr><td style="background:#064BCB;padding:24px;border-radius:12px 12px 0 0">
        <span style="color:#fff;font-size:20px;font-weight:800">BOMPAY</span>
        <span style="color:rgba(255,255,255,0.7);font-size:13px;float:right;margin-top:4px">TAX INVOICE</span>
      </td></tr>
      <tr><td style="background:#fff;padding:24px;border-radius:0 0 12px 12px">
        <p style="font-size:18px;font-weight:700;color:#0f172a;margin:0 0 4px">{b['name']}</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px">
          <tr>
            <td><p style="font-size:13px;color:#64748b;margin:0">Billed to</p>
                <p style="font-size:15px;font-weight:700;color:#0f172a;margin:2px 0">{inv.get('customer_name','')}</p></td>
            <td style="text-align:right">
              <p style="font-size:12px;font-weight:700;color:#064BCB;margin:0">{inv.get('invoice_number','')}</p>
              <p style="font-size:11px;color:#64748b;margin:2px 0">Due: {str(inv.get('due_date',''))[:10]}</p>
              <p style="font-size:11px;color:#64748b;margin:0">Status: {inv.get('status','unpaid').upper()}</p>
            </td>
          </tr>
        </table>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin-bottom:16px">
          <tr style="background:#f8fafc">
            <th style="padding:8px 12px;font-size:11px;color:#64748b;font-weight:600;text-align:left">Description</th>
            <th style="padding:8px 12px;font-size:11px;color:#64748b;font-weight:600;text-align:center">Qty</th>
            <th style="padding:8px 12px;font-size:11px;color:#64748b;font-weight:600;text-align:right">Unit Price</th>
            <th style="padding:8px 12px;font-size:11px;color:#64748b;font-weight:600;text-align:right">Amount</th>
          </tr>
          {items_html}
        </table>
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:280px;margin-left:auto">
          <tr><td style="text-align:right;padding:3px 12px 3px 0;font-size:12px;color:#64748b">Subtotal:</td>
              <td style="text-align:right;padding:3px 0;font-size:12px;font-weight:600;color:#0f172a">
              &#8358;{float(inv.get('subtotal',0)):,.2f}</td></tr>
          {tax_row}
          <tr style="border-top:2px solid #e2e8f0">
            <td style="text-align:right;padding:8px 12px 0 0;font-size:15px;font-weight:700;color:#064BCB">Total:</td>
            <td style="text-align:right;padding:8px 0 0;font-size:15px;font-weight:800;color:#064BCB">
            &#8358;{float(inv.get('total',0)):,.2f}</td>
          </tr>
        </table>
        {notes_block}
        <p style="font-size:11px;color:#94a3b8;margin-top:20px">
          This invoice was sent via BOMPAY Business Banking. Please make payment before the due date.</p>
      </td></tr>
    </table>
    """
    await send_email(
        to=req.email,
        subject=f"Invoice {inv.get('invoice_number','')} from {b['name']} — &#8358;{float(inv.get('total',0)):,.2f}",
        html=html,
    )
    return {"ok": True, "message": f"Invoice sent to {req.email}"}


# ─── 17. EXPENSES ────────────────────────────────────────────────────────────
@router.post("/business/{business_id}/expenses")
async def add_expense(business_id: str, req: ExpenseReq, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    doc = {
        "business_id": business_id,
        "owner_id": str(user["_id"]),
        "category": req.category,
        "amount": int(req.amount * 100),
        "description": req.description,
        "date": req.date or now_utc().date().isoformat(),
        "created_at": now_utc(),
    }
    r = await db.business_expenses.insert_one(doc)
    return {"message": "Expense recorded", "id": str(r.inserted_id)}

@router.get("/business/{business_id}/expenses")
async def get_expenses(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    expenses = await db.business_expenses.find({"business_id": business_id}).sort("created_at", -1).to_list(None)
    result = []
    for e in expenses:
        ec = clean(e); ec["amount"] = ec["amount"] / 100; result.append(ec)
    return {"expenses": result}


# ─── 18. STAFF LOAN ──────────────────────────────────────────────────────────
@router.post("/business/{business_id}/staff/{staff_id}/loan/request")
async def request_staff_loan(business_id: str, staff_id: str, req: StaffLoanReq, request: Request):
    user = await get_current_user(request)
    staff = await db.business_staff.find_one(
        {"_id": oid(staff_id), "business_id": business_id, "user_id": str(user["_id"]), "status": "active"}
    )
    if not staff:
        raise HTTPException(404, "Staff record not found")
    if req.amount <= 0 or req.repayment_months <= 0:
        raise HTTPException(400, "Invalid loan amount or repayment period")
    monthly_deduction = round(req.amount / req.repayment_months, 2)
    doc = {
        "business_id": business_id,
        "staff_id": staff_id,
        "user_id": str(user["_id"]),
        "amount": int(req.amount * 100),
        "repayment_months": req.repayment_months,
        "monthly_deduction": int(monthly_deduction * 100),
        "months_paid": 0,
        "status": "pending",
        "requested_at": now_utc(),
    }
    r = await db.business_staff_loans.insert_one(doc)
    return {"message": "Loan request submitted for approval", "id": str(r.inserted_id), "monthly_deduction": monthly_deduction}

@router.put("/business/{business_id}/staff/{staff_id}/loan/{loan_id}/approve")
async def approve_staff_loan(business_id: str, staff_id: str, loan_id: str, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])

    loan = await db.business_staff_loans.find_one({"_id": oid(loan_id), "business_id": business_id})
    if not loan:
        raise HTTPException(404, "Loan not found")
    if loan["status"] != "pending":
        raise HTTPException(400, f"Loan is already '{loan['status']}'")

    amount_kobo = loan["amount"]
    w = await _biz_wallet(business_id)
    if w["available_balance"] < amount_kobo:
        raise HTTPException(400, f"Insufficient business balance. Need ₦{amount_kobo/100:,.2f}, have ₦{w['available_balance']/100:,.2f}")

    staff = await db.business_staff.find_one({"_id": oid(staff_id), "business_id": business_id})
    if not staff:
        raise HTTPException(404, "Staff member not found")

    staff_wallet = await db.wallets.find_one({"user_id": staff.get("user_id")})
    if not staff_wallet:
        raise HTTPException(400, "Staff member's wallet not found")

    # Disburse: debit business wallet, credit staff Bompay wallet
    await db.business_wallets.update_one(
        {"business_id": business_id},
        {"$inc": {"available_balance": -amount_kobo, "ledger_balance": -amount_kobo}}
    )
    await db.wallets.update_one(
        {"user_id": staff.get("user_id")},
        {"$inc": {"available_balance": amount_kobo, "ledger_balance": amount_kobo}}
    )

    # SH transfer from business sub-account → staff's account
    if b.get("sh_subaccount_id") and b.get("sh_account_number"):
        try:
            await call_sh("POST", "/transfers", body={
                "nameEnquiryReference": "",
                "debitAccountNumber": b["sh_account_number"],
                "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
                "beneficiaryAccountNumber": staff_wallet.get("account_number", ""),
                "amount": amount_kobo,
                "saveBeneficiary": False,
                "narration": f"Staff Loan — {b['name']}",
                "paymentReference": f"LOAN-{loan_id[:12]}",
            })
        except Exception as e:
            logger.warning(f"[LOAN-APPROVE] SH transfer failed: {e}")

    await _record_biz_txn(business_id, "DEBIT", "STAFF_LOAN", amount_kobo,
                          f"Loan disbursement to {staff['name']}", {"loan_id": loan_id})

    await db.business_staff_loans.update_one(
        {"_id": oid(loan_id)},
        {"$set": {"status": "active",           # active = approved + disbursed, repayments in progress
                  "outstanding_balance": amount_kobo,
                  "approved_at": now_utc(),
                  "approved_by": str(user["_id"]),
                  "disbursed_at": now_utc()}}
    )

    # Notify staff: in-app + SMS
    async def _notify():
        await notify(staff["user_id"], "Salary Advance Approved",
                     f"Your loan request of ₦{amount_kobo/100:,.2f} from {b['name']} has been approved and credited!")
        staff_phone = staff.get("phone", "")
        if staff_phone:
            ph = staff_phone.strip()
            if ph.startswith("0"): ph = "+234" + ph[1:]
            elif not ph.startswith("+"): ph = "+234" + ph
            sms = (f"BOMPAY: Your salary advance of ₦{amount_kobo/100:,.2f} from {b['name']} "
                   "has been APPROVED and credited to your account!")
            try:
                provider = await get_sms_provider()
                if provider == "BULKSMSLIVE": await _send_via_bulksms(ph, sms)
                else: await _send_via_sendora(ph, sms)
            except Exception as e:
                logger.warning(f"[LOAN] Staff SMS failed: {e}")
    asyncio.create_task(_notify())

    return {"message": f"Loan of ₦{amount_kobo/100:,.2f} approved and disbursed to {staff['name']}"}


@router.put("/business/{business_id}/staff/{staff_id}/loan/{loan_id}/reject")
async def reject_staff_loan(business_id: str, staff_id: str, loan_id: str,
                            req: RejectLoanReq, request: Request):
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])

    loan = await db.business_staff_loans.find_one({"_id": oid(loan_id), "business_id": business_id})
    if not loan:
        raise HTTPException(404, "Loan not found")
    if loan["status"] != "pending":
        raise HTTPException(400, f"Loan is already '{loan['status']}'")

    await db.business_staff_loans.update_one(
        {"_id": oid(loan_id)},
        {"$set": {"status": "rejected", "rejection_reason": req.reason or "",
                  "rejected_at": now_utc(), "rejected_by": str(user["_id"])}}
    )

    staff = await db.business_staff.find_one({"_id": oid(staff_id)})
    if staff:
        amount_kobo = loan["amount"]
        asyncio.create_task(notify(staff["user_id"], "Salary Advance Declined",
            f"Your loan request of ₦{amount_kobo/100:,.2f} from {b['name']} has been declined."
            + (f" Reason: {req.reason}" if req.reason else "")))
        staff_phone = staff.get("phone", "")
        if staff_phone:
            async def _sms():
                ph = staff_phone.strip()
                if ph.startswith("0"): ph = "+234" + ph[1:]
                elif not ph.startswith("+"): ph = "+234" + ph
                sms = (f"BOMPAY: Your salary advance of ₦{amount_kobo/100:,.2f} from {b['name']} "
                       "has been declined." + (f" Reason: {req.reason}" if req.reason else ""))
                try:
                    provider = await get_sms_provider()
                    if provider == "BULKSMSLIVE": await _send_via_bulksms(ph, sms)
                    else: await _send_via_sendora(ph, sms)
                except Exception as e:
                    logger.warning(f"[LOAN] Staff SMS failed: {e}")
            asyncio.create_task(_sms())

    return {"message": "Loan request declined"}

@router.get("/business/{business_id}/staff/{staff_id}/loans")
async def get_staff_loans(business_id: str, staff_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    loans = await db.business_staff_loans.find({"business_id": business_id, "staff_id": staff_id}).to_list(None)
    return {"loans": [clean(l) for l in loans]}


# ─── GET ALL LOANS FOR BUSINESS (owner view) ─────────────────────────────────
@router.get("/business/{business_id}/loans")
async def get_business_loans(business_id: str, request: Request):
    user = await get_current_user(request)
    await _get_business(business_id, user["_id"])
    loans = await db.business_staff_loans.find({"business_id": business_id}).sort("requested_at", -1).to_list(None)
    result = []
    for loan in loans:
        lc = clean(loan)
        lc["amount_ngn"] = lc.get("amount", 0) / 100
        lc["monthly_deduction_ngn"] = lc.get("monthly_deduction", 0) / 100
        staff = None
        if loan.get("staff_id"):
            staff = await db.business_staff.find_one({"_id": oid(loan["staff_id"])})
        lc["staff_name"] = (staff or {}).get("name", "Unknown")
        lc["staff_department"] = (staff or {}).get("department", "")
        lc["staff_role"] = (staff or {}).get("role", "")
        result.append(lc)
    return {"loans": result}


# ─── ADMIN ROUTES ───────────────────────────────────────────────────────────
@router.get("/admin/businesses")
async def admin_list_businesses(request: Request, page: int = 1, limit: int = 30):
    user = await get_current_user(request)
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")
    skip = (page - 1) * limit
    businesses = await db.businesses.find({}).sort("created_at", -1).skip(skip).limit(limit).to_list(None)
    result = []
    for b in businesses:
        w = await db.business_wallets.find_one({"business_id": str(b["_id"])}) or {}
        owner = await db.users.find_one({"_id": oid(b["owner_id"])}, {"first_name": 1, "last_name": 1, "phone": 1}) or {}
        bc = clean(b)
        bc["wallet_balance"] = w.get("available_balance", 0) / 100
        bc["owner_name"] = f"{owner.get('first_name','')} {owner.get('last_name','')}".strip()
        bc["owner_phone"] = owner.get("phone", "")
        result.append(bc)
    total = await db.businesses.count_documents({})
    return {"businesses": result, "total": total}

@router.put("/admin/businesses/{business_id}/status")
async def admin_update_business_status(business_id: str, status: str, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")
    if status not in ("active", "disabled", "suspended"):
        raise HTTPException(400, "Invalid status")
    await db.businesses.update_one({"_id": oid(business_id)}, {"$set": {"status": status, "updated_at": now_utc()}})
    return {"message": f"Business {status}"}

@router.get("/admin/settings/business")
async def admin_get_business_settings(request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")
    cfg = await db.admin_settings.find_one({"key": "business_config"}) or {}
    return {"max_per_user": cfg.get("max_per_user", 0)}

@router.post("/admin/settings/business")
async def admin_update_business_settings(max_per_user: int, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")
    if max_per_user < 0: raise HTTPException(400, "Invalid value")
    await db.admin_settings.update_one(
        {"key": "business_config"},
        {"$set": {"key": "business_config", "max_per_user": max_per_user, "updated_at": now_utc()}},
        upsert=True
    )
    return {"message": f"Max businesses per user set to {max_per_user}"}

@router.get("/admin/businesses/{business_id}/transactions")
async def admin_business_transactions(business_id: str, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin": raise HTTPException(403, "Admin only")
    txns = await db.business_transactions.find({"business_id": business_id}).sort("created_at", -1).limit(50).to_list(None)
    return {"transactions": [clean(t) for t in txns]}



# ─── ADMIN: DIRECTOR KYB INITIATION ─────────────────────────────────────────
@router.post("/admin/businesses/{business_id}/director-kyb/init")
async def admin_init_director_kyb(business_id: str, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")

    b = await db.businesses.find_one({"_id": oid(business_id)})
    if not b:
        raise HTTPException(404, "Business not found")

    # Parse optional body (admin may supply owner BVN when identity_id is missing)
    try:
        body = await request.json()
    except Exception:
        body = {}
    supplied_bvn = (body.get("bvn") or "").strip()

    if b.get("director_is_applicant", True):
        # Try stored identity first
        owner = await db.users.find_one({"_id": oid(b["owner_id"])})
        kyc = await db.kyc_records.find_one({"user_id": b["owner_id"]})
        identity_id = (owner or {}).get("kyc_identity_id") or (kyc or {}).get("identity_id")

        if identity_id:
            await db.businesses.update_one(
                {"_id": oid(business_id)},
                {"$set": {"director_identity_id": identity_id, "director_kyb_status": "verified", "updated_at": now_utc()}}
            )
            return {"message": "Director identity sourced from applicant's verified KYC", "status": "verified"}

        # identity_id not stored — admin must supply owner's BVN
        if not supplied_bvn:
            raise HTTPException(400, "Owner identity not found. Please enter the owner's BVN to verify their identity.")

        director_bvn = supplied_bvn
    else:
        # Different director — use BVN from business doc, or supplied BVN
        director_bvn = supplied_bvn or b.get("director_bvn", "").strip()
        if not director_bvn:
            raise HTTPException(400, "Director BVN is missing from the business application")

    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    platform_acct = (settings or {}).get("account_number", "").strip()

    sh_body = {"type": "BVN", "number": director_bvn, "async": False}
    if platform_acct:
        sh_body["debitAccountNumber"] = platform_acct

    try:
        r = await call_sh("POST", "/identity/v2", body=sh_body)
        data = r.get("data") or {}
        identity_id = data.get("_id")
        if not identity_id:
            raise HTTPException(400, r.get("message", "Safe Haven returned no identity ID for this BVN"))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Director BVN verification failed: {e}")

    await db.businesses.update_one(
        {"_id": oid(business_id)},
        {"$set": {
            "director_identity_id": identity_id,
            "director_kyb_status": "initiated",
            "updated_at": now_utc(),
        }}
    )
    return {
        "message": "Director KYB initiated. An OTP has been sent to the director's BVN-registered phone number.",
        "status": "initiated",
        "identity_id": identity_id,
    }


# ─── ADMIN: APPROVE BUSINESS (creates SH corporate sub-account + notifies owner) ──
@router.post("/admin/businesses/{business_id}/approve")
async def admin_approve_business(business_id: str, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")

    b = await db.businesses.find_one({"_id": oid(business_id)})
    if not b:
        raise HTTPException(404, "Business not found")
    if b["status"] != "pending_approval":
        raise HTTPException(400, f"Business is already '{b['status']}', not pending approval")

    owner = await db.users.find_one({"_id": oid(b["owner_id"])})
    if not owner:
        raise HTTPException(404, "Business owner not found")

    kyc = await db.kyc_records.find_one({"user_id": b["owner_id"]})
    # Prefer director_identity_id (from Director KYB), fall back to owner's persisted KYC identity
    identity_id = (b.get("director_identity_id")
                   or owner.get("kyc_identity_id")
                   or (kyc or {}).get("identity_id"))

    # Only block if a *different* director was submitted but KYB was never run for them
    if not identity_id and not (b.get("director_is_applicant", True)):
        raise HTTPException(400, "Director identity not verified. Use 'Initiate Director KYB' to verify the director's BVN before approving.")

    external_ref = b.get("external_ref") or f"bompay-biz-{b['owner_id'][:8]}-{uuid.uuid4().hex[:8]}"
    sh_payload = {
        "phoneNumber": b.get("phone", ""),
        "emailAddress": b.get("email", ""),
        "externalReference": external_ref,
        "companyRegistrationNumber": b.get("rc_number", ""),
        "callbackUrl": f"{WEBHOOK_BASE_URL}/api/webhooks/safehaven",
        "autoSweep": False,
    }
    # Include identity fields only when available (existing KYC-verified users may not have it stored)
    if identity_id:
        sh_payload["identityType"] = "vID"
        sh_payload["identityId"] = identity_id
    try:
        sh_resp = await call_sh("POST", "/accounts/v2/subaccount/", body=sh_payload)
    except Exception as e:
        logger.error(f"[BIZ APPROVE] SH create failed: {e}")
        raise HTTPException(502, f"Could not create Safe Haven corporate account: {e}")

    sh_data = sh_resp.get("data", sh_resp)
    # Safe Haven may return the account ID in various fields — try them all
    sh_account_id  = (sh_data.get("_id") or sh_data.get("id") or sh_data.get("accountId")
                      or sh_data.get("subAccountId") or sh_data.get("subaccount_id") or "")
    sh_account_num = (sh_data.get("accountNumber") or sh_data.get("virtualAccountNumber")
                      or sh_data.get("account_number") or "")
    sh_bank_name   = sh_data.get("bankName") or sh_data.get("bank") or "Safe Haven MFB"

    logger.info(f"[BIZ APPROVE] SH response keys: {list(sh_data.keys())} → id={sh_account_id} acct={sh_account_num}")

    now = now_utc()
    await db.businesses.update_one(
        {"_id": oid(business_id)},
        {"$set": {
            "status": "active",
            "sh_subaccount_id": sh_account_id,
            "sh_account_number": sh_account_num,
            "sh_bank_name": sh_bank_name,
            "external_ref": external_ref,
            "approved_at": now,
            "approved_by": str(user["_id"]),
            "updated_at": now,
        }}
    )

    # Fire-and-forget: in-app notification + SMS + email
    owner_id_str = b["owner_id"]
    biz_name     = b["name"]
    owner_phone  = owner.get("phone", "")
    owner_email  = owner.get("email", "") or owner.get("email_address", "")
    owner_name   = f"{owner.get('first_name','')} {owner.get('last_name','')}".strip() or "Customer"

    async def _notify_owner():
        try:
            await notify(owner_id_str, "Business Account Approved",
                         f"Your {biz_name} business account is now active! "
                         f"Account: {sh_account_num} ({sh_bank_name})")
        except Exception as e:
            logger.warning(f"[BIZ APPROVE] in-app notify failed: {e}")
        if owner_phone:
            phone_e164 = owner_phone.strip()
            if phone_e164.startswith("0"): phone_e164 = "+234" + phone_e164[1:]
            elif not phone_e164.startswith("+"): phone_e164 = "+234" + phone_e164
            sms = (f"BOMPAY: Your {biz_name} business account is APPROVED! "
                   f"Acct: {sh_account_num} ({sh_bank_name}). "
                   "Open the Bompay app to get started.")
            try:
                provider = await get_sms_provider()
                if provider == "BULKSMSLIVE":
                    await _send_via_bulksms(phone_e164, sms)
                else:
                    await _send_via_sendora(phone_e164, sms)
            except Exception as e:
                logger.warning(f"[BIZ APPROVE] SMS failed: {e}")
        if owner_email:
            html = _email_html(
                f"Hi {owner_name}, your business account is approved!",
                [
                    f"Your business <strong>{biz_name}</strong> has been reviewed and approved.",
                    f"<strong>Account Number:</strong> {sh_account_num}",
                    f"<strong>Bank:</strong> {sh_bank_name}",
                    "You can now fund your business wallet, add staff, run payroll, and more.",
                    "Open the BOMPAY app and tap <strong>Business</strong> from the bottom navigation.",
                ],
                "Questions? Reach us through the app's support chat."
            )
            try:
                await send_email(
                    to=owner_email,
                    subject=f"[BOMPAY] Business Account Approved — {biz_name}",
                    html=html
                )
            except Exception as e:
                logger.warning(f"[BIZ APPROVE] email failed: {e}")

    asyncio.create_task(_notify_owner())

    return {
        "message": "Business approved and Safe Haven account created",
        "sh_account_number": sh_account_num,
        "sh_bank_name": sh_bank_name,
    }


# ─── ADMIN: REJECT BUSINESS ──────────────────────────────────────────────────
@router.post("/admin/businesses/{business_id}/reject")
async def admin_reject_business(business_id: str, req: RejectBusinessReq, request: Request):
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    b = await db.businesses.find_one({"_id": oid(business_id)})
    if not b:
        raise HTTPException(404, "Business not found")

    now = now_utc()
    await db.businesses.update_one(
        {"_id": oid(business_id)},
        {"$set": {
            "status": "rejected",
            "rejection_reason": req.reason or "",
            "rejected_at": now,
            "rejected_by": str(user["_id"]),
            "updated_at": now,
        }}
    )

    owner = await db.users.find_one({"_id": oid(b["owner_id"])})
    if owner:
        owner_id_str = b["owner_id"]
        biz_name     = b["name"]
        owner_email  = owner.get("email", "") or owner.get("email_address", "")
        owner_name   = f"{owner.get('first_name','')} {owner.get('last_name','')}".strip() or "Customer"

        asyncio.create_task(notify(owner_id_str, "Business Application Update",
            f"Your application for {biz_name} needs additional review. Please contact support."))

        if owner_email:
            reason_line = f"<strong>Reason:</strong> {req.reason}" if req.reason else "Please contact our support team for more information."
            html = _email_html(
                f"Hi {owner_name}, update on your business application",
                [
                    f"We were unable to approve your application for <strong>{biz_name}</strong> at this time.",
                    reason_line,
                    "If you believe this is an error, contact support through the BOMPAY app.",
                ],
                "We're here to help — tap Support in the app."
            )
            asyncio.create_task(send_email(
                to=owner_email,
                subject=f"[BOMPAY] Business Application Update — {biz_name}",
                html=html
            ))

    return {"message": "Business application rejected"}


# ─── BUSINESS STATEMENT ──────────────────────────────────────────────────────
@router.get("/business/{business_id}/statement")
async def get_business_statement(business_id: str, year: int = 0, month: int = 0, request: Request = None):
    """Returns a complete financial statement for a given month/year for PDF generation."""
    user = await get_current_user(request)
    b = await _get_business(business_id, user["_id"])

    from calendar import monthrange
    now = now_utc()
    y = year  or now.year
    m = month or now.month
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    end   = datetime(y, m, monthrange(y, m)[1], 23, 59, 59, tzinfo=timezone.utc)
    q     = {"business_id": business_id, "created_at": {"$gte": start, "$lte": end}}

    # Transactions
    txns = await db.business_transactions.find(q).sort("created_at", 1).to_list(None)
    # Payroll runs
    payrolls = await db.business_payroll.find({"business_id": business_id,
        "run_at": {"$gte": start, "$lte": end}}).sort("run_at", 1).to_list(None)
    # Expenses
    expenses = await db.business_expenses.find(q).sort("created_at", 1).to_list(None)
    # Sales
    sales = await db.business_crm_sales.find(q).sort("created_at", 1).to_list(None)

    total_credits  = sum(t.get("amount", 0) for t in txns if t.get("direction") == "CREDIT")
    total_debits   = sum(t.get("amount", 0) for t in txns if t.get("direction") == "DEBIT")
    total_payroll  = sum(p.get("total_amount", 0) for p in payrolls)
    total_expenses = sum(e.get("amount", 0) for e in expenses)   # stored in kobo
    total_sales    = sum(s.get("amount", 0) for s in sales)      # stored in kobo

    # Wallet balance (current)
    w = await db.business_wallets.find_one({"business_id": business_id}) or {}

    def fmt_txn(t):
        return {
            "date": t.get("created_at", "").isoformat()[:10] if hasattr(t.get("created_at", ""), "isoformat") else str(t.get("created_at", ""))[:10],
            "description": t.get("description", ""),
            "category": t.get("category", ""),
            "type": t.get("direction", ""),
            "amount_ngn": t.get("amount", 0) / 100,
        }

    return {
        "business": {
            "name": b["name"],
            "account_number": b.get("sh_account_number", "N/A"),
            "bank_name": b.get("sh_bank_name", "Safe Haven MFB"),
            "business_type": (b.get("business_type") or "").replace("_", " ").title(),
            "period": f"{start.strftime('%B %Y')}",
            "period_start": start.isoformat()[:10],
            "period_end": end.isoformat()[:10],
        },
        "summary": {
            "current_balance_ngn": w.get("available_balance", 0) / 100,
            "total_credits_ngn": total_credits / 100,
            "total_debits_ngn": total_debits / 100,
            "total_payroll_ngn": total_payroll / 100,
            "total_expenses_ngn": total_expenses / 100,
            "total_sales_ngn": total_sales / 100,
            "transaction_count": len(txns),
        },
        "transactions": [fmt_txn(t) for t in txns],
        "payroll_runs": [
            {
                "date": p.get("run_at", "").isoformat()[:10] if hasattr(p.get("run_at", ""), "isoformat") else "",
                "staff_paid": p.get("staff_paid", []),
                "total_ngn": p.get("total_amount", 0) / 100,
                "status": p.get("status", ""),
                "auto": p.get("auto", False),
            }
            for p in payrolls
        ],
        "expenses": [
            {
                "date": e.get("date", "")[:10] if e.get("date") else "",
                "category": e.get("category", ""),
                "description": e.get("description", ""),
                "amount_ngn": e.get("amount", 0) / 100,
            }
            for e in expenses
        ],
        "sales": [
            {
                "date": s.get("created_at", "").isoformat()[:10] if hasattr(s.get("created_at", ""), "isoformat") else "",
                "description": s.get("description", ""),
                "amount_ngn": s.get("amount", 0) / 100,
            }
            for s in sales
        ],
    }
