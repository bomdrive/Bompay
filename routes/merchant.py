"""
Bompay Merchant / Developer Platform routes
Prefix: /api/v1/merchant  (merchant-facing)
Prefix: /api/admin/merchants (admin-facing)
"""
import os, secrets, uuid, asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
import jwt as pyjwt  # noqa: F401 — used via 'pyjwt' alias below
from fastapi import APIRouter, Request, HTTPException, Response, UploadFile, File
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import cloudinary
import cloudinary.uploader

from core import (
    db, hash_password, verify_password, JWT_SECRET, JWT_ALGORITHM,
    call_sh, logger,
    call_cdh, call_pg, get_service_provider, get_sh_vas_cat_id,
    CDH_AIRTIME_NETWORK_IDS, CDH_ELECTRICITY_DISCO_IDS, CDH_DATA_PLANS, CDH_CABLE_PLANS,
    PG_DISCO_SLUGS, get_service_bucket_account, NIGERIAN_BANKS, SAFEHAVEN_OWN_BANK_CODE,
    send_otp_sms, send_email, _email_html, FRONTEND_URL,
)

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

router = APIRouter()
WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", "")


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _gen_key(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(24)}"

def _merchant_tokens(merchant_id: str, email: str):
    now = datetime.now(timezone.utc)
    access = pyjwt.encode(
        {"sub": merchant_id, "email": email, "type": "merchant_access",
         "exp": now + timedelta(hours=12)},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    refresh = pyjwt.encode(
        {"sub": merchant_id, "type": "merchant_refresh",
         "exp": now + timedelta(days=30)},
        JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    return access, refresh

def _set_merchant_cookies(response: Response, access: str, refresh: str):
    kw = dict(httponly=True, secure=True, samesite="none", path="/")
    response.set_cookie("merchant_access_token", access, max_age=43200, **kw)
    response.set_cookie("merchant_refresh_token", refresh, max_age=2592000, **kw)

async def get_current_merchant(request: Request) -> dict:
    token = request.cookies.get("merchant_access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "merchant_access":
            raise HTTPException(401, "Invalid token")
        m = await db.merchants.find_one({"merchant_id": payload["sub"]})
        if not m:
            raise HTTPException(401, "Merchant not found")
        if m.get("status") == "suspended":
            raise HTTPException(403, "Merchant account suspended")
        m["_id"] = str(m["_id"])
        m.pop("password_hash", None)
        m.pop("pin_hash", None)
        return m
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def _safe_merchant(m: dict) -> dict:
    m = {k: v for k, v in m.items()}
    m["_id"] = str(m["_id"])
    m.pop("password_hash", None)
    m.pop("pin_hash", None)
    return m

async def _get_admin(request: Request):
    from core import get_current_user
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    return user

def _fmt_phone(phone: str) -> str:
    """Normalise Nigerian phone number to +234XXXXXXXXXX format."""
    p = (phone or "").strip().replace(" ", "").replace("-", "")
    if p.startswith("0"):
        p = "+234" + p[1:]
    elif p.startswith("234") and not p.startswith("+"):
        p = "+" + p
    elif not p.startswith("+"):
        p = "+234" + p
    return p


async def _initiate_sh_identity_verify(identity_type: str, identity_number: str) -> str:
    """
    Initiate Safe Haven /identity/v2 BVN/NIN verification.
    Correct payload uses 'type', 'number', 'debitAccountNumber' (required), and 'async'.
    Safe Haven debits the debitAccountNumber for the verification fee.
    Safe Haven then sends OTP to the director's BVN/NIN-registered phone.
    Returns the initiation `_id` to be used in the OTP validation step.
    """
    if not identity_number:
        return ""
    # Get BOMPAY's Safe Haven operational account number for the verification fee debit
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    debit_acct = (settings or {}).get("account_number", "") or os.environ.get("SAFEHAVEN_DEBIT_ACCOUNT", "")
    try:
        payload: dict = {
            "type": identity_type.upper(),     # Required: "BVN" or "NIN"
            "number": identity_number.strip(), # Required: the BVN/NIN string
            "async": False,
        }
        if debit_acct:
            payload["debitAccountNumber"] = debit_acct  # Required by Safe Haven for fee debit
        resp = await call_sh("POST", "/identity/v2", body=payload)
        # Response may be top-level or nested under "data"
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        init_id = (data or {}).get("_id", "") or resp.get("_id", "")
        if init_id:
            logger.info(f"[MERCHANT] SH identity initiation ({identity_type}) → initID starts with {str(init_id)[:12]}…")
            return init_id
        logger.warning(f"[MERCHANT] SH identity initiation: no _id in response statusCode={resp.get('statusCode')}")
    except Exception as e:
        logger.warning(f"[MERCHANT] SH identity initiation failed ({identity_type}): {e}")
    return ""


async def _validate_sh_identity(init_id: str, identity_type: str, otp: str) -> str:
    """
    Validate Safe Haven identity OTP at /identity/v2/validate.
    Returns the validated vID (_id) on success — used as identityId for corporate sub-account.
    """
    if not init_id or not otp:
        return ""
    try:
        resp = await call_sh("POST", "/identity/v2/validate", body={
            "identityId": init_id,
            "type": identity_type.upper(),
            "otp": otp,
        })
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        vid = (data or {}).get("_id", "") or resp.get("_id", "")
        if vid:
            logger.info(f"[MERCHANT] SH identity validated → vID starts with {str(vid)[:12]}…")
            return vid
        logger.warning(f"[MERCHANT] SH identity validate: no vID in response: statusCode={resp.get('statusCode')}")
    except Exception as e:
        logger.warning(f"[MERCHANT] SH identity validate failed: {e}")
    return ""


async def _create_sh_corporate_subaccount(merchant: dict, kyb: dict, label: str) -> dict:
    """
    Create a Safe Haven virtual sub-account.
    Flow:
      1. If director_vid (pre-validated via OTP flow in KYB) + rc_number → corporate /accounts/v2/subaccount
      2. Fallback → individual /accounts/subaccount with BVN or NIN directly
         (individual endpoint accepts identityType=BVN/NIN + identityNumber, no prior OTP needed)
    Returns dict with sh_account_id, sh_account_number, external_reference, etc.
    NOTE: Corporate endpoint requires a vID from the 2-step initiate→validate OTP flow.
          For merchants who completed BVN verification in KYB, this is populated as director_vid.
    """
    external_ref = f"bp-m-{merchant['merchant_id']}-{uuid.uuid4().hex[:8]}"
    phone = _fmt_phone(merchant.get("phone", ""))
    bvn = (kyb or {}).get("director_bvn", "")
    nin = (kyb or {}).get("director_nin", "")
    rc_number = (kyb or {}).get("rc_number") or merchant.get("rc_number") or ""
    # Pre-validated vID stored during KYB BVN verification (initiate→OTP→validate flow)
    vid = (kyb or {}).get("director_vid", "")
    identity_id = bvn or nin or ""
    identity_type = "BVN" if bvn else ("NIN" if nin else "BVN")

    async def _parse(sh_resp: dict, fallback_label: str) -> dict:
        sh_data = sh_resp.get("data") if isinstance(sh_resp.get("data"), dict) else sh_resp
        return {
            "sh_account_id": ((sh_data or {}).get("_id") or (sh_data or {}).get("id") or (sh_data or {}).get("accountId") or ""),
            "sh_account_number": ((sh_data or {}).get("accountNumber") or (sh_data or {}).get("virtualAccountNumber") or ""),
            "sh_account_name": (sh_data or {}).get("accountName") or f"{merchant.get('business_name', '')} — {fallback_label}",
            "bank_name": (sh_data or {}).get("bankName") or "Safe Haven MFB",
            "bank_code": "090286",
            "external_reference": external_ref,
        }

    cb_url = (
        os.environ.get("MERCHANT_PROVISION_CALLBACK_URL")
        or WEBHOOK_BASE_URL
        or FRONTEND_URL.rstrip("/")
    ) + "/api/webhooks/safehaven"

    # ── Step 1: Corporate v2 with pre-validated vID (requires OTP-verified director) ──
    if vid and rc_number:
        payload: dict = {
            "externalReference": external_ref,
            "phoneNumber": phone,
            "emailAddress": merchant.get("email", ""),
            "identityType": "vID",
            "identityId": vid,
            "companyRegistrationNumber": rc_number,
            "autoSweep": False,
        }
        if cb_url:
            payload["callbackUrl"] = cb_url
        try:
            result = await _parse(await call_sh("POST", "/accounts/v2/subaccount", body=payload), label)
            logger.info(f"[MERCHANT] Corporate SH v2 (vID) → {merchant['merchant_id']}: acct={result['sh_account_number'] or 'pending/async'}")
            return result
        except Exception as e:
            logger.warning(f"[MERCHANT] Corporate v2 (vID) failed: {e} — falling back to individual endpoint")

    # ── Step 2: Individual endpoint (BVN/NIN direct — no prior OTP required) ─────────
    parts = (merchant.get("owner_name") or merchant.get("business_name") or "Business Owner").split()
    payload2: dict = {
        "externalReference": external_ref,
        "firstName": parts[0],
        "lastName": " ".join(parts[1:]) or "Owner",
        "emailAddress": merchant.get("email", ""),
        "phoneNumber": phone,
        "autoSweep": False,
    }
    if cb_url:
        payload2["callbackUrl"] = cb_url
    if identity_id:
        payload2["identityType"] = identity_type
        payload2["identityNumber"] = identity_id
        # Do NOT add identityId for BVN/NIN type — identityId is only for vID type
    try:
        result = await _parse(await call_sh("POST", "/accounts/subaccount", body=payload2), label)
        logger.info(f"[MERCHANT] Individual SH → {merchant['merchant_id']}: acct={result['sh_account_number'] or 'pending/async'}")
        return result
    except Exception as e:
        logger.warning(f"[MERCHANT] All SH sub-account attempts failed: {e}")
        return {
            "sh_account_id": "", "sh_account_number": "",
            "sh_account_name": label, "bank_name": "Safe Haven MFB",
            "bank_code": "090286", "external_reference": external_ref,
        }


async def _create_sh_subaccount(merchant: dict, label: str) -> dict:
    """Backward-compatible wrapper — no KYB data available (registration time)."""
    return await _create_sh_corporate_subaccount(merchant, {}, label)


# ─── MODELS ──────────────────────────────────────────────────────────────────

class MerchantRegister(BaseModel):
    email: str
    password: str
    pin: str
    business_name: str
    owner_name: str
    phone: str

class MerchantLogin(BaseModel):
    email: str
    password: str
    pin: Optional[str] = None

class CreateAccount(BaseModel):
    name: str

class SubmitKYB(BaseModel):
    business_name: str
    rc_number: str
    business_phone: str
    business_address: str
    director_name: str
    director_id_type: str
    director_id_number: str
    director_bvn: Optional[str] = ""
    director_nin: Optional[str] = ""
    director_vid: Optional[str] = ""   # Pre-validated Safe Haven vID from OTP flow
    cac_document_url: Optional[str] = ""
    director_id_url: Optional[str] = ""

class VerifyBVNRequest(BaseModel):
    identity_type: str  # "BVN" or "NIN"
    identity_number: str

class ValidateBVNRequest(BaseModel):
    init_id: str        # _id returned from initiation
    identity_type: str  # "BVN" or "NIN"
    otp: str

class WebhookConfig(BaseModel):
    url: str
    events: list[str] = []

class ModeSwitch(BaseModel):
    mode: str  # "sandbox" | "live"

class NotifPrefs(BaseModel):
    preferences: dict

class DisputeCreate(BaseModel):
    title: str
    description: str
    transaction_id: Optional[str] = ""
    amount: Optional[float] = 0

class KYBAdminAction(BaseModel):
    status: str  # "approved" | "rejected"
    note: Optional[str] = ""

class MerchantStatusUpdate(BaseModel):
    status: str  # "active" | "suspended"

class MerchantTransfer(BaseModel):
    account_number: str
    bank_code: str
    amount: float
    narration: Optional[str] = "Merchant Transfer"
    pin: str
    from_account_id: Optional[str] = None  # if None, uses primary account

class MerchantAirtimeReq(BaseModel):
    phone_number: str
    network: str            # MTN, GLO, AIRTEL, 9MOBILE
    amount: float
    pin: str
    from_account_id: Optional[str] = None

class MerchantDataReq(BaseModel):
    phone_number: str
    network: str
    plan_id: int
    amount: float
    pin: str
    from_account_id: Optional[str] = None

class MerchantElectricityReq(BaseModel):
    meter_number: str
    disco: str              # AEDC, EKEDC, IBEDC, IKEDC, EEDC, etc.
    meter_type: str         # PREPAID / POSTPAID
    amount: float
    pin: str
    from_account_id: Optional[str] = None

class MerchantCableReq(BaseModel):
    provider: str           # DSTV, GOTV, STARTIMES
    smartcard_number: str
    package_id: int
    amount: float
    pin: str
    from_account_id: Optional[str] = None

class MerchantCableValidate(BaseModel):
    provider: str
    smartcard_number: str

class MerchantMeterValidate(BaseModel):
    disco: str
    meter_number: str
    meter_type: str = "PREPAID"


# ─── AUTH ─────────────────────────────────────────────────────────────────────

@router.post("/v1/merchant/register")
async def merchant_register(req: MerchantRegister, response: Response):
    if len(req.pin) != 4 or not req.pin.isdigit():
        raise HTTPException(400, "PIN must be exactly 4 digits")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    email = req.email.lower().strip()
    if await db.merchants.find_one({"email": email}):
        raise HTTPException(409, "Email already registered")

    merchant_id = f"MERCHANT_{secrets.token_hex(6).upper()}"
    now = now_utc()
    merchant_doc = {
        "merchant_id": merchant_id,
        "email": email,
        "password_hash": hash_password(req.password),
        "pin_hash": hash_password(req.pin),
        "business_name": req.business_name,
        "owner_name": req.owner_name,
        "phone": req.phone,
        "mode": "sandbox",
        "status": "active",
        "kyb_status": "pending",
        "test_public_key": _gen_key("bptest_pub"),
        "test_secret_key": _gen_key("bptest_sec"),
        "live_public_key": _gen_key("bplive_pub"),
        "live_secret_key": _gen_key("bplive_sec"),
        "webhook_url": "",
        "webhook_events": ["transfer.success", "transfer.failed", "account.credited"],
        "notifications": {
            "email": True, "sms": True,
            "transfer": True, "account_credit": True, "kyb": True
        },
        "created_at": now,
        "updated_at": now,
    }
    await db.merchants.insert_one(merchant_doc)

    # Create primary Safe Haven virtual account
    sh = await _create_sh_subaccount(merchant_doc, req.business_name)
    acct_id = f"MACCT_{secrets.token_hex(4).upper()}"
    await db.merchant_accounts.insert_one({
        "account_id": acct_id,
        "merchant_id": merchant_id,
        "name": f"{req.business_name} — Primary",
        "type": "primary",
        "status": "active",
        "sh_account_id": sh["sh_account_id"],
        "sh_account_number": sh["sh_account_number"],
        "sh_account_name": sh["sh_account_name"],
        "bank_name": sh["bank_name"],
        "created_at": now,
    })

    access, refresh = _merchant_tokens(merchant_id, email)
    _set_merchant_cookies(response, access, refresh)
    return _safe_merchant(merchant_doc)


@router.post("/v1/merchant/login")
async def merchant_login(req: MerchantLogin, response: Response):
    email = req.email.lower().strip()
    m = await db.merchants.find_one({"email": email})
    if not m or not verify_password(req.password, m["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if m.get("status") == "suspended":
        raise HTTPException(403, "Account suspended. Contact support.")
    if req.pin:
        if not verify_password(req.pin, m["pin_hash"]):
            raise HTTPException(401, "Invalid PIN")
    access, refresh = _merchant_tokens(m["merchant_id"], email)
    _set_merchant_cookies(response, access, refresh)
    return _safe_merchant(m)


@router.post("/v1/merchant/logout")
async def merchant_logout(response: Response):
    response.delete_cookie("merchant_access_token", path="/", samesite="none", secure=True)
    response.delete_cookie("merchant_refresh_token", path="/", samesite="none", secure=True)
    return {"message": "Logged out"}


@router.get("/v1/merchant/me")
async def merchant_me(request: Request):
    m = await get_current_merchant(request)
    return m


@router.post("/v1/merchant/refresh")
async def merchant_refresh(request: Request, response: Response):
    token = request.cookies.get("merchant_refresh_token")
    if not token:
        raise HTTPException(401, "No refresh token")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "merchant_refresh":
            raise HTTPException(401, "Invalid token")
        m = await db.merchants.find_one({"merchant_id": payload["sub"]})
        if not m:
            raise HTTPException(401, "Not found")
        access, refresh = _merchant_tokens(m["merchant_id"], m["email"])
        _set_merchant_cookies(response, access, refresh)
        return {"message": "Refreshed"}
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


# ─── DASHBOARD ─────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/dashboard")
async def merchant_dashboard(request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    accounts = await db.merchant_accounts.find({"merchant_id": mid}).to_list(50)
    acct_ids = [a["account_id"] for a in accounts]
    total_txns = await db.merchant_transactions.count_documents({"merchant_id": mid})
    total_vol_agg = await db.merchant_transactions.aggregate([
        {"$match": {"merchant_id": mid, "status": "success"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    total_vol = (total_vol_agg[0]["total"] if total_vol_agg else 0)
    disputes_open = await db.merchant_disputes.count_documents({"merchant_id": mid, "status": "open"})
    kyb = await db.merchant_kyb.find_one({"merchant_id": mid})
    # Recent 7 days daily volume
    from datetime import date
    today = datetime.now(timezone.utc).date()
    daily = []
    for i in range(6, -1, -1):
        d = today.replace() if i == 0 else date.fromordinal(today.toordinal() - i)
        start = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        vol = await db.merchant_transactions.aggregate([
            {"$match": {"merchant_id": mid, "status": "success",
                        "created_at": {"$gte": start.isoformat(), "$lt": end.isoformat()}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]).to_list(1)
        daily.append({"date": d.strftime("%b %d"), "volume": vol[0]["total"] if vol else 0})

    return {
        "merchant": m,
        "stats": {
            "total_accounts": len(accounts),
            "total_transactions": total_txns,
            "total_volume_ngn": total_vol / 100,
            "open_disputes": disputes_open,
            "kyb_status": (kyb or {}).get("status", "pending"),
        },
        "chart": daily,
    }


# ─── ACCOUNTS ────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/accounts")
async def list_merchant_accounts(request: Request):
    m = await get_current_merchant(request)
    accounts = await db.merchant_accounts.find(
        {"merchant_id": m["merchant_id"]}, {"_id": 0}
    ).to_list(20)
    return {"accounts": accounts}


@router.post("/v1/merchant/accounts")
async def create_merchant_account(req: CreateAccount, request: Request):
    m = await get_current_merchant(request)
    count = await db.merchant_accounts.count_documents({"merchant_id": m["merchant_id"]})
    if count >= 10:
        raise HTTPException(400, "Maximum 10 business accounts per merchant")
    sh = await _create_sh_subaccount(m, req.name)
    acct_id = f"MACCT_{secrets.token_hex(4).upper()}"
    doc = {
        "account_id": acct_id,
        "merchant_id": m["merchant_id"],
        "name": req.name,
        "type": "secondary",
        "status": "active",
        **sh,
        "created_at": now_utc(),
    }
    await db.merchant_accounts.insert_one(doc)
    doc.pop("_id", None)
    return doc


@router.get("/v1/merchant/accounts/{account_id}")
async def get_merchant_account(account_id: str, request: Request):
    m = await get_current_merchant(request)
    acct = await db.merchant_accounts.find_one(
        {"account_id": account_id, "merchant_id": m["merchant_id"]}, {"_id": 0}
    )
    if not acct:
        raise HTTPException(404, "Account not found")
    # Fetch live balance if SH account exists
    balance = 0.0
    if acct.get("sh_account_number"):
        try:
            r = await call_sh("GET", "/accounts", params={"accountNumber": acct["sh_account_number"]})
            data = r.get("data", [])
            if isinstance(data, list) and data:
                balance = float(data[0].get("balance", 0))
            elif isinstance(data, dict):
                balance = float(data.get("balance", 0))
        except Exception:
            pass
    txns = await db.merchant_transactions.find(
        {"merchant_id": m["merchant_id"], "account_id": account_id},
        {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    return {"account": acct, "balance_ngn": balance, "transactions": txns}


# ─── TRANSACTIONS ─────────────────────────────────────────────────────────────

@router.get("/v1/merchant/transactions")
async def merchant_transactions(request: Request, page: int = 1, limit: int = 20):
    m = await get_current_merchant(request)
    skip = (page - 1) * limit
    txns = await db.merchant_transactions.find(
        {"merchant_id": m["merchant_id"]}, {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.merchant_transactions.count_documents({"merchant_id": m["merchant_id"]})
    return {"transactions": txns, "total": total, "page": page, "pages": -(-total // limit)}


# ─── KYB ──────────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/kyb")
async def get_merchant_kyb(request: Request):
    m = await get_current_merchant(request)
    kyb = await db.merchant_kyb.find_one({"merchant_id": m["merchant_id"]}, {"_id": 0})
    return {"kyb": kyb, "kyb_status": m.get("kyb_status", "pending")}


@router.post("/v1/merchant/kyb")
async def submit_merchant_kyb(req: SubmitKYB, request: Request):
    m = await get_current_merchant(request)
    if m.get("kyb_status") == "approved":
        raise HTTPException(400, "KYB already approved")
    now = now_utc()
    doc = {
        "merchant_id": m["merchant_id"],
        **req.dict(),
        "status": "submitted",
        "admin_note": "",
        "submitted_at": now,
        "reviewed_at": None,
    }
    await db.merchant_kyb.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": doc},
        upsert=True
    )
    await db.merchants.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {"kyb_status": "submitted", "rc_number": req.rc_number, "updated_at": now}}
    )
    return {"message": "KYB submitted successfully", "status": "submitted"}


# ─── API KEYS ─────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/api-keys")
async def get_api_keys(request: Request):
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    return {
        "test_public_key": raw.get("test_public_key", ""),
        "test_secret_key": raw.get("test_secret_key", ""),
        "live_public_key": raw.get("live_public_key", "") if m.get("kyb_status") == "approved" else None,
        "live_secret_key": raw.get("live_secret_key", "") if m.get("kyb_status") == "approved" else None,
        "mode": m.get("mode", "sandbox"),
    }


@router.post("/v1/merchant/api-keys/regenerate")
async def regenerate_api_keys(request: Request, key_type: str = "test"):
    m = await get_current_merchant(request)
    if key_type == "live" and m.get("kyb_status") != "approved":
        raise HTTPException(400, "KYB must be approved to regenerate live keys")
    patch = {}
    if key_type == "test":
        patch = {"test_public_key": _gen_key("bptest_pub"), "test_secret_key": _gen_key("bptest_sec")}
    else:
        patch = {"live_public_key": _gen_key("bplive_pub"), "live_secret_key": _gen_key("bplive_sec")}
    patch["updated_at"] = now_utc()
    await db.merchants.update_one({"merchant_id": m["merchant_id"]}, {"$set": patch})
    return {"message": "Keys regenerated", **patch}


# ─── WEBHOOK ──────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/webhook")
async def get_webhook(request: Request):
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    return {"url": raw.get("webhook_url", ""), "events": raw.get("webhook_events", [])}


@router.put("/v1/merchant/webhook")
async def update_webhook(req: WebhookConfig, request: Request):
    m = await get_current_merchant(request)
    await db.merchants.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {"webhook_url": req.url, "webhook_events": req.events, "updated_at": now_utc()}}
    )
    return {"message": "Webhook updated"}


# ─── MODE ────────────────────────────────────────────────────────────────────

@router.put("/v1/merchant/mode")
async def switch_mode(req: ModeSwitch, request: Request):
    m = await get_current_merchant(request)
    if req.mode == "live" and m.get("kyb_status") != "approved":
        raise HTTPException(400, "Complete KYB verification to switch to Live mode")
    await db.merchants.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {"mode": req.mode, "updated_at": now_utc()}}
    )
    return {"message": f"Switched to {req.mode} mode", "mode": req.mode}


# ─── NOTIFICATIONS ───────────────────────────────────────────────────────────

@router.get("/v1/merchant/notifications/preferences")
async def get_notif_prefs(request: Request):
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    return raw.get("notifications", {})


@router.put("/v1/merchant/notifications/preferences")
async def update_notif_prefs(req: NotifPrefs, request: Request):
    m = await get_current_merchant(request)
    await db.merchants.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {"notifications": req.preferences, "updated_at": now_utc()}}
    )
    return {"message": "Preferences updated"}


# ─── DISPUTES ─────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/disputes")
async def list_disputes(request: Request):
    m = await get_current_merchant(request)
    disputes = await db.merchant_disputes.find(
        {"merchant_id": m["merchant_id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    return {"disputes": disputes}


@router.post("/v1/merchant/disputes")
async def create_dispute(req: DisputeCreate, request: Request):
    m = await get_current_merchant(request)
    doc = {
        "dispute_id": f"DSP_{secrets.token_hex(6).upper()}",
        "merchant_id": m["merchant_id"],
        "title": req.title,
        "description": req.description,
        "transaction_id": req.transaction_id,
        "amount": req.amount,
        "status": "open",
        "admin_response": "",
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    await db.merchant_disputes.insert_one(doc)
    doc.pop("_id", None)
    return doc


# ─── SERVICES (Transfer from Dashboard) ──────────────────────────────────────

@router.post("/v1/merchant/services/transfer")
async def merchant_transfer(req: MerchantTransfer, request: Request):
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 100:
        raise HTTPException(400, "Minimum transfer amount is ₦100")

    m = await get_current_merchant(request)
    raw_merch = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw_merch["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")

    # Name enquiry
    try:
        ne = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": req.bank_code,
            "accountNumber": req.account_number,
        })
        account_name = ne.get("data", {}).get("accountName") or ne.get("accountName", "Unknown")
        ne_ref = ne.get("data", {}).get("sessionId") or f"NEQ{secrets.token_hex(8).upper()}"
    except Exception as e:
        raise HTTPException(502, f"Name enquiry failed: {e}")

    # Get selected account (or primary)
    if req.from_account_id:
        acct = await db.merchant_accounts.find_one({
            "merchant_id": m["merchant_id"], "account_id": req.from_account_id
        })
    else:
        acct = await db.merchant_accounts.find_one({
            "merchant_id": m["merchant_id"], "type": "primary"
        })
    if not acct or not acct.get("sh_account_number"):
        raise HTTPException(400, "Business account not set up. Please create an account first.")

    amount_kobo = int(req.amount * 100)
    txn_ref = f"MTRXN_{secrets.token_hex(8).upper()}"
    try:
        sh_resp = await call_sh("POST", "/transfers", body={
            "nameEnquiryReference": ne_ref,
            "debitAccountNumber": acct["sh_account_number"],
            "beneficiaryBankCode": req.bank_code,
            "beneficiaryAccountNumber": req.account_number,
            "amount": req.amount,
            "saveBeneficiary": False,
            "narration": req.narration or "Merchant Transfer",
            "paymentReference": txn_ref,
        })
    except Exception as e:
        raise HTTPException(502, f"Transfer failed: {e}")

    txn_doc = {
        "transaction_id": txn_ref,
        "merchant_id": m["merchant_id"],
        "account_id": acct["account_id"],
        "type": "TRANSFER",
        "direction": "DEBIT",
        "amount": amount_kobo,
        "currency": "NGN",
        "status": "success",
        "beneficiary_account": req.account_number,
        "beneficiary_name": account_name,
        "beneficiary_bank": req.bank_code,
        "narration": req.narration,
        "mode": m.get("mode", "sandbox"),
        "provider_response": str(sh_resp)[:500],
        "created_at": now_utc(),
    }
    await db.merchant_transactions.insert_one(txn_doc)
    txn_doc.pop("_id", None)
    return {"message": "Transfer initiated", "transaction": txn_doc, "beneficiary_name": account_name}


# ─── NAME ENQUIRY & BANKS (merchant-auth wrappers) ────────────────────────────

@router.get("/v1/merchant/services/banks")
async def merchant_banks(request: Request):
    await get_current_merchant(request)
    try:
        r = await call_sh("GET", "/transfers/banks")
        raw = r.get("data", NIGERIAN_BANKS)
        normalized = []
        for b in raw:
            if isinstance(b, dict):
                normalized.append({
                    "name": b.get("name", b.get("bankName", "")),
                    "code": b.get("bankCode", b.get("code", b.get("routingKey", ""))),
                })
        return normalized if normalized else NIGERIAN_BANKS
    except Exception:
        return NIGERIAN_BANKS


@router.post("/v1/merchant/services/name-enquiry")
async def merchant_name_enquiry(request: Request, body: dict):
    await get_current_merchant(request)
    bank_code = body.get("bank_code", "")
    account_number = body.get("account_number", "")
    try:
        r = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": bank_code, "accountNumber": account_number
        })
        data = r.get("data", {})
        sid = data.get("sessionId") or f"NEQ{secrets.token_hex(8).upper()}"
        account_name = data.get("accountName", "")
        return {"account_name": account_name, "account_number": account_number,
                "bank_code": bank_code, "session_id": sid}
    except Exception as e:
        raise HTTPException(502, f"Name enquiry failed: {e}")


# ─── VAS CATALOGUE ────────────────────────────────────────────────────────────

@router.get("/v1/merchant/services/data-plans/{network}")
async def merchant_data_plans(network: str, request: Request):
    await get_current_merchant(request)
    plans = CDH_DATA_PLANS.get(network.upper(), [])
    return {"network": network.upper(), "plans": plans}


@router.get("/v1/merchant/services/cable-plans/{provider}")
async def merchant_cable_plans(provider: str, request: Request):
    await get_current_merchant(request)
    plans = CDH_CABLE_PLANS.get(provider.upper(), [])
    return {"provider": provider.upper(), "plans": plans}


# ─── VAS HELPER ───────────────────────────────────────────────────────────────

async def _get_merch_acct_for_vas(merchant_id: str, account_id: Optional[str]) -> dict:
    """Resolve merchant account for VAS debit. Raises 400 if not ready."""
    if account_id:
        acct = await db.merchant_accounts.find_one({"merchant_id": merchant_id, "account_id": account_id})
    else:
        acct = await db.merchant_accounts.find_one({"merchant_id": merchant_id, "type": "primary"})
    if not acct or not acct.get("sh_account_number"):
        raise HTTPException(400, "Business account not found or not fully set up")
    return acct

async def _record_merch_vas_txn(merchant_id: str, account_id: str, txn_id: str,
                                  vas_type: str, amount_kobo: int, status: str,
                                  mode: str, metadata: dict) -> dict:
    doc = {
        "transaction_id": txn_id, "merchant_id": merchant_id,
        "account_id": account_id, "type": vas_type, "direction": "DEBIT",
        "amount": amount_kobo, "currency": "NGN", "status": status, "mode": mode,
        "created_at": now_utc(), "metadata": metadata,
    }
    await db.merchant_transactions.insert_one(doc)
    doc.pop("_id", None)
    return doc


# ─── VALIDATE SMARTCARD / METER ───────────────────────────────────────────────

@router.post("/v1/merchant/services/validate/cable")
async def merchant_validate_cable(req: MerchantCableValidate, request: Request):
    await get_current_merchant(request)
    CABLE_IDS = {"DSTV": "multichoice-dstv", "GOTV": "multichoice-gotv", "STARTIMES": "startimes"}
    svc_id = CABLE_IDS.get(req.provider.upper(), req.provider.lower())
    try:
        r = await call_sh("POST", "/vas/verify", body={
            "serviceCategoryId": svc_id, "entityNumber": req.smartcard_number
        })
        return r.get("data", {"name": "Validated", "customer_name": ""})
    except Exception:
        return {"name": "", "customer_name": ""}


@router.post("/v1/merchant/services/validate/meter")
async def merchant_validate_meter(req: MerchantMeterValidate, request: Request):
    await get_current_merchant(request)
    disco_ids = CDH_ELECTRICITY_DISCO_IDS
    disco_upper = req.disco.upper()
    try:
        r = await call_sh("POST", "/vas/verify", body={
            "serviceCategoryId": disco_upper.lower(), "entityNumber": req.meter_number
        })
        return r.get("data", {"name": ""})
    except Exception:
        return {"name": ""}


# ─── VAS AIRTIME ─────────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/airtime")
async def merchant_buy_airtime(req: MerchantAirtimeReq, request: Request):
    m = await get_current_merchant(request)
    raw_merch = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw_merch["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 50 or req.amount > 50000:
        raise HTTPException(400, "Amount must be ₦50–₦50,000")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)

    provider = await get_service_provider("AIRTIME")
    pref = txn_ref
    try:
        if provider == "SAFEHAVEN":
            cat_id = await get_sh_vas_cat_id("AIRTIME", req.network)
            r = await call_sh("POST", "/vas/pay/airtime", body={
                "serviceCategoryId": cat_id, "amount": req.amount, "channel": "WEB",
                "debitAccountNumber": acct["sh_account_number"],
                "phoneNumber": req.phone_number, "externalReference": txn_ref,
            })
            pref = r.get("data", {}).get("reference") or txn_ref
        elif provider == "CHEAPDATAHUB":
            pid = CDH_AIRTIME_NETWORK_IDS.get(req.network.upper(), 1)
            r = await call_cdh("POST", "/airtime/purchase/", body={
                "provider_id": pid, "phone_number": req.phone_number, "amount": req.amount
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_ref)))
        elif provider == "PAIRGATE":
            r = await call_pg("POST", "/airtime/purchase", body={
                "provider_id": req.network.upper(), "amount": req.amount,
                "recipient": req.phone_number, "reference": txn_ref,
            })
            pref = str(r.get("reference", txn_ref))
        else:
            raise HTTPException(503, "No provider configured for AIRTIME")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Airtime purchase failed: {e}")

    txn = await _record_merch_vas_txn(
        m["merchant_id"], acct["account_id"], txn_ref, "AIRTIME", amt, "success",
        m.get("mode", "sandbox"),
        {"network": req.network, "phone": req.phone_number, "provider_ref": pref, "provider": provider}
    )
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "network": req.network, "phone": req.phone_number}


# ─── VAS DATA ─────────────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/data")
async def merchant_buy_data(req: MerchantDataReq, request: Request):
    m = await get_current_merchant(request)
    raw_merch = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw_merch["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)

    provider = await get_service_provider("DATA")
    pref = txn_ref
    try:
        if provider == "SAFEHAVEN":
            cat_id = await get_sh_vas_cat_id("DATA", req.network)
            r = await call_sh("POST", "/vas/pay/data", body={
                "serviceCategoryId": cat_id, "amount": req.amount, "channel": "WEB",
                "debitAccountNumber": acct["sh_account_number"],
                "phoneNumber": req.phone_number, "planId": str(req.plan_id),
                "externalReference": txn_ref,
            })
            pref = r.get("data", {}).get("reference") or txn_ref
        elif provider == "CHEAPDATAHUB":
            r = await call_cdh("POST", "/data/purchase/", body={
                "provider_id": req.plan_id, "phone_number": req.phone_number, "amount": req.amount
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_ref)))
        elif provider == "PAIRGATE":
            r = await call_pg("POST", "/data/purchase", body={
                "provider_id": req.network.upper(), "plan_id": req.plan_id,
                "recipient": req.phone_number, "reference": txn_ref,
            })
            pref = str(r.get("reference", txn_ref))
        else:
            raise HTTPException(503, "No provider configured for DATA")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Data purchase failed: {e}")

    await _record_merch_vas_txn(
        m["merchant_id"], acct["account_id"], txn_ref, "DATA", amt, "success",
        m.get("mode", "sandbox"),
        {"network": req.network, "phone": req.phone_number, "plan_id": req.plan_id, "provider_ref": pref, "provider": provider}
    )
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "network": req.network, "phone": req.phone_number, "plan_id": req.plan_id}


# ─── VAS ELECTRICITY ──────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/electricity")
async def merchant_pay_electricity(req: MerchantElectricityReq, request: Request):
    m = await get_current_merchant(request)
    raw_merch = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw_merch["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 1000:
        raise HTTPException(400, "Minimum electricity payment is ₦1,000")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)

    provider = await get_service_provider("ELECTRICITY")
    pref = txn_ref
    token = "N/A"
    units = ""
    try:
        if provider == "SAFEHAVEN":
            cat_id = await get_sh_vas_cat_id("ELECTRICITY", req.disco)
            r = await call_sh("POST", "/vas/pay/utility", body={
                "serviceCategoryId": cat_id, "amount": req.amount, "channel": "WEB",
                "debitAccountNumber": acct["sh_account_number"],
                "meterNumber": req.meter_number, "vendType": req.meter_type.upper(),
                "externalReference": txn_ref,
            })
            data = r.get("data", {})
            pref = data.get("reference") or txn_ref
            token = data.get("utilityToken", data.get("token", "N/A"))
            units = str(data.get("units", ""))
        elif provider == "CHEAPDATAHUB":
            disco_id = CDH_ELECTRICITY_DISCO_IDS.get(req.disco.upper(), 1)
            r = await call_cdh("POST", "/electricity/purchase/", body={
                "disco_id": disco_id, "meter_number": req.meter_number,
                "amount": req.amount, "meter_type": req.meter_type.lower(), "phone": ""
            })
            data = r.get("data") or r
            pref = str(r.get("reference", txn_ref))
            token = data.get("token", "N/A") if isinstance(data, dict) else "N/A"
            units = str(data.get("units", "")) if isinstance(data, dict) else ""
        elif provider == "PAIRGATE":
            meter_type_int = 1 if req.meter_type.upper() == "PREPAID" else 2
            pg_disco = PG_DISCO_SLUGS.get(req.disco.upper(), req.disco.lower())
            r = await call_pg("POST", "/electricity/purchase", body={
                "provider_id": pg_disco, "meter_number": req.meter_number,
                "meter_type": meter_type_int, "amount": int(req.amount), "reference": txn_ref,
            })
            pref = str(r.get("reference_code", r.get("reference", txn_ref)))
            token = r.get("pin", r.get("token", "N/A"))
            units = str(r.get("units", ""))
        else:
            raise HTTPException(503, "No provider configured for ELECTRICITY")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Electricity payment failed: {e}")

    await _record_merch_vas_txn(
        m["merchant_id"], acct["account_id"], txn_ref, "ELECTRICITY", amt, "success",
        m.get("mode", "sandbox"),
        {"disco": req.disco, "meter": req.meter_number, "token": token, "units": units,
         "provider_ref": pref, "provider": provider}
    )

    # Send electricity token SMS to customer (non-blocking)
    phone = raw_merch.get("phone", "")
    if phone and token and token != "N/A":
        sms_body = (
            f"Bompay Electricity Token\n"
            f"Meter: {req.meter_number}\n"
            f"Token: {token}\n"
            f"Units: {units or 'N/A'}\n"
            f"Amount: NGN{req.amount:,.2f}\n"
            f"Ref: {txn_ref}"
        )
        try:
            await send_otp_sms(phone, sms_body)
        except Exception as sms_err:
            logger.warning(f"[MERCHANT ELEC SMS] {sms_err}")

    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "token": token, "units": units, "meter_number": req.meter_number}


# ─── VAS CABLE TV ─────────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/cable")
async def merchant_pay_cable(req: MerchantCableReq, request: Request):
    m = await get_current_merchant(request)
    raw_merch = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw_merch["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)

    provider = await get_service_provider("CABLE")
    pref = txn_ref
    try:
        if provider == "SAFEHAVEN":
            cat_id = await get_sh_vas_cat_id("CABLE", req.provider)
            r = await call_sh("POST", "/vas/pay/cable-tv", body={
                "serviceCategoryId": cat_id, "amount": req.amount, "channel": "WEB",
                "debitAccountNumber": acct["sh_account_number"],
                "smartCardNumber": req.smartcard_number, "packageId": str(req.package_id),
                "externalReference": txn_ref,
            })
            pref = r.get("data", {}).get("reference") or txn_ref
        elif provider == "CHEAPDATAHUB":
            r = await call_cdh("POST", "/cable/purchase/", body={
                "provider_id": req.package_id, "smartcard_number": req.smartcard_number, "amount": req.amount
            })
            pref = str(r.get("reference", r.get("transaction_id", txn_ref)))
        elif provider == "PAIRGATE":
            r = await call_pg("POST", "/cable/purchase", body={
                "provider_id": req.provider.lower(), "plan_id": req.package_id,
                "customer_id": req.smartcard_number, "reference": txn_ref,
            })
            pref = str(r.get("reference", txn_ref))
        else:
            raise HTTPException(503, "No provider configured for CABLE")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Cable TV payment failed: {e}")

    await _record_merch_vas_txn(
        m["merchant_id"], acct["account_id"], txn_ref, "CABLE", amt, "success",
        m.get("mode", "sandbox"),
        {"provider": req.provider, "smartcard": req.smartcard_number,
         "package_id": req.package_id, "provider_ref": pref}
    )
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "provider": req.provider, "smartcard": req.smartcard_number}


# ─── SETTINGS ─────────────────────────────────────────────────────────────────

class UpdateProfile(BaseModel):
    business_name: Optional[str] = None
    owner_name: Optional[str] = None
    phone: Optional[str] = None

class ChangePin(BaseModel):
    old_pin: str
    new_pin: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

class VerifyPin(BaseModel):
    pin: str

@router.post("/v1/merchant/verify-pin")
async def verify_merchant_pin(req: VerifyPin, request: Request):
    """Verify PIN for already-authenticated merchant (2-step login step 2)."""
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.pin, raw["pin_hash"]):
        raise HTTPException(401, "Invalid PIN")
    return {"message": "PIN verified", "merchant_id": m["merchant_id"]}


@router.post("/v1/merchant/kyb/upload")
async def upload_kyb_document(
    request: Request,
    file: UploadFile = File(...),
    doc_type: str = "document",
):
    """Upload a KYB document (CAC cert, director ID) to Cloudinary."""
    m = await get_current_merchant(request)
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(400, "File must be under 10 MB")
    public_id = f"bompay/kyb/{m['merchant_id']}/{doc_type}_{secrets.token_hex(4)}"
    try:
        result = cloudinary.uploader.upload(
            data,
            public_id=public_id,
            resource_type="auto",
            overwrite=True,
            invalidate=True,
        )
        url = result["secure_url"]
    except Exception as e:
        logger.error(f"[KYB Upload] {e}")
        raise HTTPException(500, "Document upload failed. Please try again.")
    return {"url": url, "doc_type": doc_type}


@router.post("/v1/merchant/kyb/verify-identity")
async def kyb_verify_identity(req: VerifyBVNRequest, request: Request):
    """
    Step 1 of BVN/NIN verification: Initiate Safe Haven identity check.
    Safe Haven sends an OTP to the director's BVN/NIN-registered phone.
    Returns initiation _id to be used in the validation step.
    """
    m = await get_current_merchant(request)
    id_type = req.identity_type.upper()
    if id_type not in ("BVN", "NIN"):
        raise HTTPException(400, "identity_type must be BVN or NIN")
    if not req.identity_number or len(req.identity_number.strip()) < 10:
        raise HTTPException(400, "A valid 11-digit BVN or NIN is required")
    init_id = await _initiate_sh_identity_verify(id_type, req.identity_number.strip())
    if not init_id:
        raise HTTPException(502, "Identity verification initiation failed. Check your BVN/NIN and try again.")
    logger.info(f"[KYB] Identity verification initiated for merchant {m['merchant_id']} type={id_type}")
    return {"init_id": init_id, "message": f"OTP sent to your {id_type}-registered phone number"}


@router.post("/v1/merchant/kyb/validate-identity")
async def kyb_validate_identity(req: ValidateBVNRequest, request: Request):
    """
    Step 2 of BVN/NIN verification: Validate the OTP received on the director's phone.
    On success, stores the validated vID in the merchant's KYB record.
    This vID is used during corporate sub-account creation on KYB approval.
    """
    m = await get_current_merchant(request)
    if not req.init_id or not req.otp:
        raise HTTPException(400, "init_id and otp are required")
    vid = await _validate_sh_identity(req.init_id, req.identity_type.upper(), req.otp)
    if not vid:
        raise HTTPException(400, "OTP validation failed. Check the code and try again.")
    # Store vID in KYB record for later use during account provisioning
    now = now_utc()
    await db.merchant_kyb.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {"director_vid": vid, "director_vid_type": req.identity_type.upper(), "vid_verified_at": now}},
        upsert=True
    )
    logger.info(f"[KYB] vID stored for merchant {m['merchant_id']}")
    return {"verified": True, "message": "Identity verified successfully. Your BVN has been validated."}


@router.get("/v1/merchant/logs")
async def merchant_api_logs(request: Request, page: int = 1, limit: int = 30):
    """Return recent merchant activity log (transactions + webhook events)."""
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    skip = (page - 1) * limit
    # Pull from merchant_transactions as audit log
    txns = await db.merchant_transactions.find(
        {"merchant_id": mid}, {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.merchant_transactions.count_documents({"merchant_id": mid})
    # Build log-style entries
    logs = []
    for t in txns:
        logs.append({
            "ref": t.get("transaction_id", ""),
            "event": f"{t.get('type', 'UNKNOWN')} ({t.get('direction', '')})",
            "status": t.get("status", "unknown"),
            "amount": t.get("amount", 0),
            "mode": t.get("mode", "sandbox"),
            "created_at": t.get("created_at", ""),
        })
    return {"logs": logs, "total": total, "page": page, "pages": -(-total // limit)}


@router.put("/v1/merchant/settings/profile")
async def update_profile(req: UpdateProfile, request: Request):
    m = await get_current_merchant(request)
    patch = {k: v for k, v in req.dict().items() if v}
    patch["updated_at"] = now_utc()
    await db.merchants.update_one({"merchant_id": m["merchant_id"]}, {"$set": patch})
    return {"message": "Profile updated"}

@router.put("/v1/merchant/settings/pin")
async def change_pin(req: ChangePin, request: Request):
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.old_pin, raw["pin_hash"]):
        raise HTTPException(400, "Old PIN is incorrect")
    if len(req.new_pin) != 4 or not req.new_pin.isdigit():
        raise HTTPException(400, "New PIN must be 4 digits")
    await db.merchants.update_one({"merchant_id": m["merchant_id"]},
        {"$set": {"pin_hash": hash_password(req.new_pin), "updated_at": now_utc()}})
    return {"message": "PIN updated"}

@router.put("/v1/merchant/settings/password")
async def change_password(req: ChangePassword, request: Request):
    m = await get_current_merchant(request)
    raw = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    if not verify_password(req.old_password, raw["password_hash"]):
        raise HTTPException(400, "Old password is incorrect")
    await db.merchants.update_one({"merchant_id": m["merchant_id"]},
        {"$set": {"password_hash": hash_password(req.new_password), "updated_at": now_utc()}})
    return {"message": "Password updated"}


# ─── ADMIN: MERCHANT PANEL ────────────────────────────────────────────────────

@router.get("/admin/merchants")
async def admin_list_merchants(request: Request, page: int = 1, status: str = "", search: str = ""):
    await _get_admin(request)
    query = {}
    if status:
        query["status"] = status
    if search:
        query["$or"] = [
            {"business_name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}},
        ]
    skip = (page - 1) * 20
    merchants = await db.merchants.find(query, {"password_hash": 0, "pin_hash": 0}).sort(
        "created_at", -1).skip(skip).limit(20).to_list(20)
    for m in merchants:
        m["_id"] = str(m["_id"])
    total = await db.merchants.count_documents(query)
    return {"merchants": merchants, "total": total, "page": page, "pages": -(-total // 20)}


@router.get("/admin/merchants/stats")
async def admin_merchant_stats(request: Request):
    await _get_admin(request)
    total = await db.merchants.count_documents({})
    active = await db.merchants.count_documents({"status": "active"})
    sandbox = await db.merchants.count_documents({"mode": "sandbox"})
    live = await db.merchants.count_documents({"mode": "live"})
    kyb_submitted = await db.merchants.count_documents({"kyb_status": "submitted"})
    kyb_approved = await db.merchants.count_documents({"kyb_status": "approved"})
    return {
        "total": total, "active": active, "suspended": total - active,
        "sandbox": sandbox, "live": live,
        "kyb_pending": kyb_submitted, "kyb_approved": kyb_approved,
    }


@router.get("/admin/merchants/revenue")
async def admin_merchant_revenue(request: Request, merchant_id: str = None, days: int = 30):
    """Aggregate merchant platform revenue by service type. Optionally filter by merchant_id."""
    await _get_admin(request)
    from datetime import datetime, timezone, timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    match_query: dict = {"created_at": {"$gte": cutoff}, "status": "success"}
    if merchant_id:
        match_query["merchant_id"] = merchant_id

    by_type = await db.merchant_transactions.aggregate([
        {"$match": match_query},
        {"$group": {
            "_id": "$type",
            "count": {"$sum": 1},
            "total_kobo": {"$sum": "$amount"},
        }},
        {"$project": {"type": "$_id", "_id": 0, "count": 1, "total_kobo": 1,
                      "total_ngn": {"$divide": ["$total_kobo", 100]}}},
        {"$sort": {"total_kobo": -1}},
    ]).to_list(20)

    totals_agg = await db.merchant_transactions.aggregate([
        {"$match": match_query},
        {"$group": {"_id": None, "total_count": {"$sum": 1}, "total_volume_kobo": {"$sum": "$amount"}}},
    ]).to_list(1)
    totals = totals_agg[0] if totals_agg else {"total_count": 0, "total_volume_kobo": 0}
    totals.pop("_id", None)

    top_merchants = []
    if not merchant_id:
        raw_top = await db.merchant_transactions.aggregate([
            {"$match": match_query},
            {"$group": {"_id": "$merchant_id", "count": {"$sum": 1}, "volume_kobo": {"$sum": "$amount"}}},
            {"$sort": {"volume_kobo": -1}},
            {"$limit": 10},
        ]).to_list(10)
        for entry in raw_top:
            m = await db.merchants.find_one({"merchant_id": entry["_id"]}, {"business_name": 1, "_id": 0})
            top_merchants.append({
                "merchant_id": entry["_id"],
                "business_name": (m or {}).get("business_name", entry["_id"]),
                "count": entry["count"],
                "volume_kobo": entry["volume_kobo"],
                "volume_ngn": round(entry["volume_kobo"] / 100, 2),
            })

    return {
        "by_type": by_type,
        "totals": {**totals, "total_volume_ngn": round(totals.get("total_volume_kobo", 0) / 100, 2)},
        "top_merchants": top_merchants,
        "days": days,
        "merchant_id": merchant_id,
    }


@router.get("/admin/merchants/{merchant_id}")
async def admin_get_merchant(merchant_id: str, request: Request):
    await _get_admin(request)
    m = await db.merchants.find_one({"merchant_id": merchant_id}, {"password_hash": 0, "pin_hash": 0})
    if not m:
        raise HTTPException(404, "Merchant not found")
    m["_id"] = str(m["_id"])
    accounts = await db.merchant_accounts.find({"merchant_id": merchant_id}, {"_id": 0}).to_list(20)
    kyb = await db.merchant_kyb.find_one({"merchant_id": merchant_id}, {"_id": 0})
    txns = await db.merchant_transactions.find(
        {"merchant_id": merchant_id}, {"_id": 0}
    ).sort("created_at", -1).limit(20).to_list(20)
    disputes = await db.merchant_disputes.find(
        {"merchant_id": merchant_id}, {"_id": 0}
    ).sort("created_at", -1).limit(10).to_list(10)
    return {"merchant": m, "accounts": accounts, "kyb": kyb, "recent_transactions": txns, "disputes": disputes}


async def _send_kyb_decision_email(email: str, business_name: str, status: str, admin_note: str, account_number: str):
    """Send KYB approval/rejection email to merchant."""
    if not email:
        return
    try:
        frontend = FRONTEND_URL.rstrip("/")
        if status == "approved":
            subject = f"[BOMPAY] Your KYB has been Approved — {business_name}"
            cta_label, cta_url = "Log in to your Dashboard", f"{frontend}/v1/dashboard"
            rows = [
                ("Business", business_name),
                ("KYB Status", "Approved ✓"),
                ("Mode", "Live"),
            ]
            if account_number:
                rows.append(("Primary Account", account_number))
            if admin_note:
                rows.append(("Note", admin_note))
        else:
            subject = f"[BOMPAY] KYB Application Update — {business_name}"
            cta_label, cta_url = "Update KYB Documents", f"{frontend}/v1/kyb"
            rows = [
                ("Business", business_name),
                ("KYB Status", "Not Approved"),
            ]
            if admin_note:
                rows.append(("Reason", admin_note))
            rows.append(("Next Step", "Please review and re-submit your KYB documents"))

        footer_html = (f'<a href="{cta_url}" style="background:#064BCB;color:#fff;padding:10px 20px;'
                       f'border-radius:8px;text-decoration:none;font-size:13px;font-weight:700">'
                       f'{cta_label} →</a>')
        html = _email_html(subject.replace("[BOMPAY] ", ""), rows, footer_html)
        await send_email(to=email, subject=subject, html=html)
        logger.info(f"[MERCHANT] KYB decision email sent to {email} — {status}")
    except Exception as e:
        logger.warning(f"[MERCHANT] KYB decision email failed for {email}: {e}")


@router.put("/admin/merchants/{merchant_id}/kyb")
async def admin_review_kyb(merchant_id: str, req: KYBAdminAction, request: Request):
    await _get_admin(request)
    if req.status not in ("approved", "rejected"):
        raise HTTPException(400, "Status must be approved or rejected")
    m = await db.merchants.find_one({"merchant_id": merchant_id})
    if not m:
        raise HTTPException(404, "Not found")
    now = now_utc()
    await db.merchant_kyb.update_one(
        {"merchant_id": merchant_id},
        {"$set": {"status": req.status, "admin_note": req.note, "reviewed_at": now}}
    )
    new_mode = "live" if req.status == "approved" else m.get("mode", "sandbox")
    await db.merchants.update_one(
        {"merchant_id": merchant_id},
        {"$set": {"kyb_status": req.status, "mode": new_mode, "updated_at": now}}
    )

    # Auto-provision primary virtual account on approval
    account_provisioned = False
    if req.status == "approved":
        kyb_doc = await db.merchant_kyb.find_one({"merchant_id": merchant_id}, {"_id": 0})
        existing = await db.merchant_accounts.find_one({"merchant_id": merchant_id, "type": "primary"})
        sh = await _create_sh_corporate_subaccount(m, kyb_doc or {}, m.get("business_name", "Primary"))
        acct_update = {
            "sh_account_id": sh["sh_account_id"],
            "sh_account_number": sh["sh_account_number"],
            "sh_account_name": sh["sh_account_name"],
            "bank_name": sh["bank_name"],
            "bank_code": sh["bank_code"],
            "external_reference": sh.get("external_reference", ""),
            "provisioned_at": now,
        }
        if existing:
            await db.merchant_accounts.update_one(
                {"merchant_id": merchant_id, "type": "primary"},
                {"$set": acct_update}
            )
        else:
            acct_id = f"MACCT_{secrets.token_hex(4).upper()}"
            await db.merchant_accounts.insert_one({
                "account_id": acct_id,
                "merchant_id": merchant_id,
                "name": f"{m.get('business_name', 'Primary')} — Primary",
                "type": "primary",
                "status": "active",
                **acct_update,
                "created_at": now,
            })
        account_provisioned = bool(sh.get("sh_account_number"))

    # KYB email notification to merchant (fire-and-forget)
    asyncio.create_task(_send_kyb_decision_email(
        email=m.get("email", ""),
        business_name=m.get("business_name", ""),
        status=req.status,
        admin_note=req.note or "",
        account_number=sh.get("sh_account_number", "") if req.status == "approved" else "",
    ))

    return {"message": f"KYB {req.status}", "mode": new_mode, "account_provisioned": account_provisioned}


@router.post("/admin/merchants/{merchant_id}/provision-account")
async def admin_provision_merchant_account(merchant_id: str, request: Request):
    """
    Admin: (Re-)provision the primary Safe Haven corporate virtual account.
    Works for already-approved merchants so admin can regenerate if provisioning failed.
    """
    await _get_admin(request)
    m = await db.merchants.find_one({"merchant_id": merchant_id})
    if not m:
        raise HTTPException(404, "Merchant not found")
    if m.get("kyb_status") != "approved":
        raise HTTPException(400, "Merchant KYB must be approved before provisioning a live account")
    kyb = await db.merchant_kyb.find_one({"merchant_id": merchant_id}, {"_id": 0})
    sh = await _create_sh_corporate_subaccount(m, kyb or {}, m.get("business_name", "Primary"))
    now = now_utc()
    acct_update = {
        "sh_account_id": sh["sh_account_id"],
        "sh_account_number": sh["sh_account_number"],
        "sh_account_name": sh["sh_account_name"],
        "bank_name": sh["bank_name"],
        "bank_code": sh["bank_code"],
        "external_reference": sh.get("external_reference", ""),
        "provisioned_at": now,
    }
    existing = await db.merchant_accounts.find_one({"merchant_id": merchant_id, "type": "primary"})
    if existing:
        await db.merchant_accounts.update_one(
            {"merchant_id": merchant_id, "type": "primary"},
            {"$set": acct_update}
        )
    else:
        acct_id = f"MACCT_{secrets.token_hex(4).upper()}"
        await db.merchant_accounts.insert_one({
            "account_id": acct_id,
            "merchant_id": merchant_id,
            "name": f"{m.get('business_name', 'Primary')} — Primary",
            "type": "primary",
            "status": "active",
            **acct_update,
            "created_at": now,
        })
    return {
        "message": "Primary account provisioned",
        "account_number": sh["sh_account_number"],
        "account_name": sh["sh_account_name"],
        "bank": sh["bank_name"],
    }


@router.put("/admin/merchants/{merchant_id}/status")
async def admin_update_merchant_status(merchant_id: str, req: MerchantStatusUpdate, request: Request):
    await _get_admin(request)
    await db.merchants.update_one(
        {"merchant_id": merchant_id},
        {"$set": {"status": req.status, "updated_at": now_utc()}}
    )
    return {"message": f"Merchant status set to {req.status}"}


class MerchantModeToggle(BaseModel):
    mode: str  # "sandbox" | "live"

@router.put("/admin/merchants/{merchant_id}/mode")
async def admin_toggle_merchant_mode(merchant_id: str, req: MerchantModeToggle, request: Request):
    """Toggle merchant between sandbox and live mode (admin only)."""
    await _get_admin(request)
    m = await db.merchants.find_one({"merchant_id": merchant_id})
    if not m:
        raise HTTPException(404, "Merchant not found")
    if req.mode not in ("sandbox", "live"):
        raise HTTPException(400, "Mode must be 'sandbox' or 'live'")
    if req.mode == "live" and m.get("kyb_status") != "approved":
        raise HTTPException(400, "KYB must be approved before enabling Live mode")
    await db.merchants.update_one(
        {"merchant_id": merchant_id},
        {"$set": {"mode": req.mode, "updated_at": now_utc()}}
    )
    return {"message": f"Mode set to {req.mode}", "mode": req.mode}


@router.get("/admin/merchants/{merchant_id}/accounts")
async def admin_merchant_accounts(merchant_id: str, request: Request):
    await _get_admin(request)
    accounts = await db.merchant_accounts.find({"merchant_id": merchant_id}, {"_id": 0}).to_list(20)
    return {"accounts": accounts}


@router.get("/admin/merchants-kyb")
async def admin_list_kyb(request: Request, status: str = "submitted"):
    await _get_admin(request)
    kybs = await db.merchant_kyb.find({"status": status}, {"_id": 0}).sort("submitted_at", -1).to_list(50)
    for k in kybs:
        m = await db.merchants.find_one({"merchant_id": k["merchant_id"]}, {"business_name": 1, "email": 1, "_id": 0})
        k["merchant"] = m or {}
    return {"kybs": kybs, "total": len(kybs)}


@router.get("/admin/merchant-disputes")
async def admin_list_disputes(request: Request):
    await _get_admin(request)
    disputes = await db.merchant_disputes.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"disputes": disputes}


@router.put("/admin/merchant-disputes/{dispute_id}/respond")
async def admin_respond_dispute(dispute_id: str, request: Request):
    await _get_admin(request)
    body = await request.json()
    await db.merchant_disputes.update_one(
        {"dispute_id": dispute_id},
        {"$set": {"admin_response": body.get("response", ""), "status": body.get("status", "under_review"), "updated_at": now_utc()}}
    )
    return {"message": "Response sent"}
