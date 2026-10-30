"""
Bompay Merchant / Developer Platform routes
Prefix: /api/v1/merchant  (merchant-facing)
Prefix: /api/admin/merchants (admin-facing)
"""
import os, secrets, uuid, asyncio, logging, base64, json as _json
from datetime import datetime, timezone, timedelta
from html import escape as _escape
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
    send_otp_sms, send_email, _email_html, FRONTEND_URL, get_rewards_config,
    send_merchant_alert,
    calculate_fee, get_nip_fee, calculate_stamp_duty,
)

# Import RBAC helpers (lazy-imported inside functions to avoid circular imports at module load)
def _rbac_ctx():
    from .context import get_merchant_context, require_permission, merchant_audit
    return get_merchant_context, require_permission, merchant_audit

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

router = APIRouter()


# ─── MERCHANT FEE HELPERS ─────────────────────────────────────────────────────

async def _collect_merchant_fee_bg(
    merchant_sh_acct: str, fee_ngn: float, txn_id: str, bucket_category: str
) -> None:
    """Fire-and-forget: sweep BOMPAY fee from merchant SH account → fee bucket.
    Mirrors _vas_sweep_to_bucket_bg for merchant accounts.
    Failure is logged but never blocks the completed service."""
    if fee_ngn <= 0:
        return
    try:
        bucket = await get_service_bucket_account(bucket_category)
        if not bucket:
            acct_doc = await db.charge_accounts.find_one({"category": f"{bucket_category}_FEES"})
            bucket = (acct_doc or {}).get("sh_account_number", "")
        if not bucket or not merchant_sh_acct:
            logger.warning(f"[MerchFee] No bucket for {bucket_category} — fee skipped txn={txn_id}")
            return
        await call_sh("POST", "/transfers", body={
            "debitAccountNumber": merchant_sh_acct,
            "beneficiaryBankCode": SAFEHAVEN_OWN_BANK_CODE,
            "beneficiaryAccountNumber": bucket,
            "amount": fee_ngn,
            "saveBeneficiary": False,
            "narration": f"BMPAY {bucket_category} fee",
            "paymentReference": f"MFEE_{txn_id}",
        })
        logger.info(f"[MerchFee] ✅ Collected ₦{fee_ngn:.2f} {bucket_category} fee txn={txn_id}")
    except Exception as e:
        logger.warning(f"[MerchFee] ⚠️ Fee sweep failed txn={txn_id}: {e}")
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
    """
    Backward-compatible auth resolver.
    Supports both merchant_access (owner) and member_access (team member) tokens.
    Returns the merchant document. For permission-aware code use get_merchant_context().
    """
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    return ctx.merchant


async def _verify_actor_pin(ctx, pin: str) -> None:
    """Raise 401/400 if pin doesn't match the authenticated actor's PIN hash.
    Owners → merchants.pin_hash; team members → merchant_members.pin_hash."""
    if ctx.is_owner:
        raw = await db.merchants.find_one({"merchant_id": ctx.merchant_id}, {"pin_hash": 1})
        pin_hash = (raw or {}).get("pin_hash", "")
        if not pin_hash or not verify_password(pin, pin_hash):
            raise HTTPException(401, "Invalid PIN")
    else:
        member = await db.merchant_members.find_one({"member_id": ctx.actor_id}, {"pin_hash": 1})
        if not member or not member.get("pin_hash"):
            raise HTTPException(400, "PIN not configured. Please set your PIN first.")
        if not verify_password(pin, member["pin_hash"]):
            raise HTTPException(401, "Invalid PIN")

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


async def _create_sh_corporate_subaccount(merchant: dict, kyb: dict, label: str, force_identity_id: str = "") -> dict:
    """
    Create a Safe Haven corporate virtual sub-account.

    Identity lookup order (NEVER re-validate BVN if already validated):
      1. force_identity_id  — admin-supplied override
      2. kyb.sh_identity_id — saved from a prior successful Step 1 (permanent)
      3. merchant_accounts  — existing individual account _id on record
      4. Step 1 call        — ONLY if none of the above exist; result saved to kyb immediately

    Step 2: POST /accounts/v2/subaccount  { identityType:"vID", identityId, companyRegistrationNumber }
    """
    merchant_id  = merchant["merchant_id"]
    external_ref = f"bp-m-{merchant_id}-{uuid.uuid4().hex[:8]}"
    phone     = _fmt_phone(merchant.get("phone", ""))
    email     = merchant.get("email", "")
    bvn       = (kyb or {}).get("director_bvn", "")
    nin       = (kyb or {}).get("director_nin", "")
    dob       = (kyb or {}).get("director_dob", "")
    rc_number = (kyb or {}).get("rc_number") or merchant.get("rc_number") or ""
    identity_number = bvn or nin or ""
    identity_type   = "BVN" if bvn else "NIN"

    async def _parse(sh_resp: dict) -> dict:
        raw = sh_resp.get("data") if isinstance(sh_resp.get("data"), dict) else sh_resp
        return {
            "sh_account_id":     (raw or {}).get("_id") or (raw or {}).get("id") or "",
            "sh_account_number": (raw or {}).get("accountNumber") or (raw or {}).get("virtualAccountNumber") or "",
            "sh_account_name":   (raw or {}).get("accountName") or f"{merchant.get('business_name','')} — {label}",
            "bank_name": (raw or {}).get("bankName") or "Safe Haven MFB",
            "bank_code": "090286",
            "external_reference": external_ref,
        }

    cb_url = (
        os.environ.get("MERCHANT_PROVISION_CALLBACK_URL")
        or WEBHOOK_BASE_URL
        or FRONTEND_URL.rstrip("/")
    ) + "/api/webhooks/safehaven"

    # ── Resolve step1_vid — BVN is validated at most ONCE per merchant ──────────────
    step1_vid: str = ""

    # 1. Admin-supplied override (highest priority)
    if force_identity_id:
        step1_vid = force_identity_id.strip()
        logger.info(f"[MERCHANT] Using admin-supplied identity ID for {merchant_id}")

    # 2. Stored in KYB as sh_identity_id (from prior provisioning or from KYB OTP validation)
    if not step1_vid:
        stored = (kyb or {}).get("sh_identity_id", "").strip()
        if stored:
            step1_vid = stored
            logger.info(f"[MERCHANT] Reusing stored KYB sh_identity_id for {merchant_id}: {step1_vid[:16]}…")

    # 2b. director_vid — stored by kyb_validate_identity OTP flow (same Safe Haven vID type)
    if not step1_vid:
        dvid = (kyb or {}).get("director_vid", "").strip()
        if dvid:
            step1_vid = dvid
            # Persist to sh_identity_id so future lookups are consistent
            await db.merchant_kyb.update_one(
                {"merchant_id": merchant_id},
                {"$set": {"sh_identity_id": dvid}},
                upsert=True
            )
            logger.info(f"[MERCHANT] Reusing director_vid as identityId for {merchant_id}: {step1_vid[:16]}… (saved to sh_identity_id)")

    # 3. Existing merchant account _id
    if not step1_vid:
        existing = await db.merchant_accounts.find_one(
            {"merchant_id": merchant_id, "sh_account_id": {"$nin": ["", None]}}
        )
        if existing and existing.get("sh_account_id"):
            step1_vid = existing["sh_account_id"].strip()
            logger.info(f"[MERCHANT] Reusing existing account _id as vID for {merchant_id}: {step1_vid[:16]}…")

    # 4. Last resort — call Safe Haven Step 1 (BVN validation) once and SAVE the result
    if not step1_vid and identity_number:
        payload1: dict = {
            "phoneNumber":       phone,
            "emailAddress":      email,
            "externalReference": external_ref,
            "identityType":      identity_type,
            "identityNumber":    identity_number,
            "autoSweep":         False,
        }
        if dob:
            payload1["dateOfBirth"] = dob
            payload1["booleanMatch"] = True
        if cb_url:
            payload1["callbackUrl"] = cb_url
        try:
            resp1     = await call_sh("POST", "/accounts/subaccount", body=payload1)
            raw1      = resp1.get("data") if isinstance(resp1.get("data"), dict) else resp1
            step1_vid = (raw1 or {}).get("_id", "").strip()
            acct_no   = (raw1 or {}).get("accountNumber", "")
            if step1_vid:
                # ── CRITICAL: persist identityId so BVN is NEVER re-validated ──────
                await db.merchant_kyb.update_one(
                    {"merchant_id": merchant_id},
                    {"$set": {"sh_identity_id": step1_vid}},
                    upsert=True
                )
                logger.info(f"[MERCHANT] Step1 BVN validated ✅ → saved sh_identity_id for {merchant_id}: {step1_vid[:16]}… acct={acct_no or 'pending'}")
        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "validated" in err_str.lower():
                raise HTTPException(429, (
                    "BVN has been validated too many times today (Safe Haven rate limit). "
                    "Please wait 24 hours and retry — the identity ID will be reused from that point on. "
                    "Alternatively, enter the Safe Haven account _id manually in the Identity ID field."
                ))
            logger.warning(f"[MERCHANT] Step1 BVN validation failed for {merchant_id}: {e}")

    # ── Step 2: Corporate sub-account using the resolved vID ─────────────────────────
    if not rc_number:
        raise HTTPException(400, "RC / BN number is required to create a corporate Safe Haven account.")

    if not step1_vid:
        raise HTTPException(429, (
            "No identity ID available and BVN cannot be re-validated (rate limited). "
            "Wait 24 hours for the rate limit to reset, then retry — "
            "or enter the Safe Haven account _id manually in the provision modal."
        ))

    corp_ref = f"{external_ref}-corp"
    payload2: dict = {
        "phoneNumber":               phone,
        "emailAddress":              email,
        "externalReference":         corp_ref,
        "identityType":              "vID",
        "identityId":                step1_vid,
        "companyRegistrationNumber": rc_number,
        "autoSweep":                 False,
    }
    if cb_url:
        payload2["callbackUrl"] = cb_url

    try:
        resp2       = await call_sh("POST", "/accounts/v2/subaccount", body=payload2)
        corp_result = await _parse(resp2)
        corp_result["external_reference"] = corp_ref

        # Detect silent failure: Safe Haven returned statusCode 200 but no account data
        # e.g. {"statusCode": 200, "message": "No director match provided details"}
        if not corp_result.get("sh_account_number") and not corp_result.get("sh_account_id"):
            sh_msg = resp2.get("message") or ""
            resp_data = resp2.get("data")
            # If there is no data at all, this is a rejection, not async processing
            if not resp_data:
                logger.error(f"[MERCHANT] Step2 corporate REJECTED for {merchant_id}: {sh_msg} | full: {resp2}")
                raise HTTPException(400,
                    f"Safe Haven rejected corporate account creation: {sh_msg or 'No account data returned'}. "
                    "This usually means the BVN does not match any director listed for this RC number. "
                    "Please verify the RC number and director BVN with the merchant."
                )
            # Data present but no account number yet → genuine async
            logger.info(f"[MERCHANT] Step2 async response for {merchant_id} — full body: {resp2}")

        logger.info(f"[MERCHANT] Step2 corporate ✅ → {merchant_id}: acct={corp_result['sh_account_number'] or 'pending (async)'}, id={corp_result.get('sh_account_id') or 'none'}")
        return corp_result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[MERCHANT] Step2 corporate FAILED for {merchant_id} rc={rc_number}: {e}")
        raise HTTPException(400, f"Corporate account creation failed: {e}")


async def _create_sh_subaccount(merchant: dict, label: str) -> dict:
    """Create a new sub-account. Loads stored KYB data so BVN/NIN/DOB are available."""
    kyb = await db.merchant_kyb.find_one({"merchant_id": merchant["merchant_id"]}, {"_id": 0}) or {}
    return await _create_sh_corporate_subaccount(merchant, kyb, label)


# ─── MODELS ──────────────────────────────────────────────────────────────────

class MerchantRegister(BaseModel):
    email: str
    password: str
    pin: str
    business_name: str
    owner_name: str
    phone: str
    rc_number: Optional[str] = ""

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
    director_dob: Optional[str] = ""   # Date of birth YYYY-MM-DD for BVN boolean match
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
        "rc_number": (req.rc_number or "").strip(),
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

    # Persist RC number to merchant_kyb immediately so it's available during provisioning
    if (req.rc_number or "").strip():
        await db.merchant_kyb.update_one(
            {"merchant_id": merchant_id},
            {"$set": {"merchant_id": merchant_id, "rc_number": req.rc_number.strip()}},
            upsert=True
        )

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
    # Include _rbac in login response so the frontend has owner context immediately
    # (merchant/me also returns this, but is called on page mount, not after fresh login)
    from .context import ALL_PERMISSIONS
    safe = _safe_merchant(m)
    safe["_rbac"] = {
        "actor_id": m["merchant_id"],
        "actor_email": m.get("email", ""),
        "actor_name": m.get("business_name", ""),
        "is_owner": True,
        "permissions": sorted(ALL_PERMISSIONS),
        "role_id": "business_owner",
    }
    return safe


@router.post("/v1/merchant/logout")
async def merchant_logout(response: Response):
    response.delete_cookie("merchant_access_token", path="/", samesite="none", secure=True)
    response.delete_cookie("merchant_refresh_token", path="/", samesite="none", secure=True)
    return {"message": "Logged out"}


@router.get("/v1/merchant/me")
async def merchant_me(request: Request):
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    out = {**ctx.merchant}
    out["_rbac"] = {
        "actor_id": ctx.actor_id,
        "actor_email": ctx.actor_email,
        "actor_name": ctx.actor_name,
        "is_owner": ctx.is_owner,
        "permissions": sorted(ctx.permissions),
        "role_id": ctx.member.get("role_id") if ctx.member else "business_owner",
    }
    return out


@router.post("/v1/merchant/refresh")
async def merchant_refresh(request: Request, response: Response):
    token = request.cookies.get("merchant_refresh_token")
    if not token:
        raise HTTPException(401, "No refresh token")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_type = payload.get("type")

        if token_type == "merchant_refresh":
            m = await db.merchants.find_one({"merchant_id": payload["sub"]})
            if not m:
                raise HTTPException(401, "Not found")
            access, refresh = _merchant_tokens(m["merchant_id"], m["email"])
            _set_merchant_cookies(response, access, refresh)
            return {"message": "Refreshed"}

        if token_type == "member_refresh":
            member_id = payload["sub"]
            merchant_id = payload.get("merchant_id", "")
            member = await db.merchant_members.find_one(
                {"member_id": member_id, "merchant_id": merchant_id, "status": "active"}
            )
            if not member:
                raise HTTPException(401, "Not found or inactive")
            from .team import _member_token, _member_refresh_token, _set_member_cookies
            access = _member_token(member_id, merchant_id)
            new_refresh = _member_refresh_token(member_id, merchant_id)
            _set_member_cookies(response, access, new_refresh)
            return {"message": "Refreshed"}

        raise HTTPException(401, "Invalid token")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


# ─── DASHBOARD ─────────────────────────────────────────────────────────────────

@router.get("/v1/merchant/dashboard")
async def merchant_dashboard(request: Request):
    get_merchant_context, require_permission, merchant_audit = _rbac_ctx()
    ctx = await get_merchant_context(request)
    await require_permission(ctx, "dashboard.read")
    m = ctx.merchant
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

    # For team members, filter to their assigned accounts only
    account_filter: dict = {"merchant_id": m["merchant_id"]}
    try:
        from .context import get_merchant_context
        ctx = await get_merchant_context(request)
        if not ctx.is_owner:
            member = await db.merchant_members.find_one({"member_id": ctx.actor_id})
            assigned = (member or {}).get("assigned_accounts", [])
            if assigned:  # non-empty = restricted access
                account_filter["account_id"] = {"$in": assigned}
    except Exception:
        pass  # business owner or context unavailable — show all

    raw_accounts = await db.merchant_accounts.find(account_filter, {"_id": 0}).to_list(20)

    # Build response list with live balances included
    result = []
    for acct in raw_accounts:
        bal = 0.0
        if acct.get("sh_account_number"):
            try:
                sh_id = acct.get("sh_account_id", "")
                if sh_id:
                    r = await call_sh("GET", f"/accounts/{sh_id}")
                    data = r.get("data") or r
                else:
                    r = await call_sh("GET", "/accounts", params={"accountNumber": acct["sh_account_number"]})
                    data = r.get("data", [])
                    if isinstance(data, list) and data:
                        data = data[0]
                    elif isinstance(data, list):
                        data = {}
                bal = float(
                    data.get("availableBalance") or
                    data.get("accountBalance") or
                    data.get("bookBalance") or 0
                )
            except Exception as e:
                logger.warning(f"[MERCHANT] Balance fetch for {acct.get('account_id')}: {e}")
        result.append({**acct, "balance_ngn": bal})

    return {"accounts": result}


class RetryProvisionRequest(BaseModel):
    director_dob: Optional[str] = ""   # Provide if not already in KYB record


@router.post("/v1/merchant/accounts/{account_id}/retry")
async def retry_account_provision(account_id: str, req: RetryProvisionRequest, request: Request):
    """Retry Safe Haven provisioning for an account still stuck in Provisioning state."""
    m = await get_current_merchant(request)
    acct = await db.merchant_accounts.find_one({"account_id": account_id, "merchant_id": m["merchant_id"]})
    if not acct:
        raise HTTPException(404, "Account not found")
    if acct.get("sh_account_number"):
        return {"message": "Account already provisioned", "sh_account_number": acct["sh_account_number"]}
    # Only allow one attempt — if already submitted to Safe Haven, block further retries
    if acct.get("external_reference"):
        raise HTTPException(400, "Provisioning already submitted to Safe Haven. Your account number will arrive shortly via webhook. Please wait.")

    # Load KYB, optionally patch in a newly-provided DOB
    kyb = await db.merchant_kyb.find_one({"merchant_id": m["merchant_id"]}, {"_id": 0}) or {}
    if req.director_dob and not kyb.get("director_dob"):
        kyb["director_dob"] = req.director_dob
        await db.merchant_kyb.update_one(
            {"merchant_id": m["merchant_id"]},
            {"$set": {"director_dob": req.director_dob}},
            upsert=True,
        )
        logger.info(f"[MERCHANT] Stored director_dob from retry for {m['merchant_id']}")

    label = acct.get("name") or m.get("business_name", "Primary")
    sh = await _create_sh_corporate_subaccount(m, kyb, label)
    now = now_utc()
    await db.merchant_accounts.update_one(
        {"account_id": account_id},
        {"$set": {
            "sh_account_id":      sh["sh_account_id"],
            "sh_account_number":  sh["sh_account_number"],
            "sh_account_name":    sh["sh_account_name"],
            "bank_name":          sh["bank_name"],
            "bank_code":          sh["bank_code"],
            "external_reference": sh.get("external_reference", ""),
            "provisioned_at":     now,
        }}
    )
    logger.info(f"[MERCHANT] Account retry provision: {account_id} → acct={sh['sh_account_number'] or 'pending/async'}")
    return {
        "message": "Provisioning re-initiated",
        "sh_account_number": sh.get("sh_account_number", ""),
        "needs_dob": not kyb.get("director_dob"),
    }


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

    # For team members, enforce account-level access restriction
    try:
        from .context import get_merchant_context
        ctx = await get_merchant_context(request)
        if not ctx.is_owner:
            member = await db.merchant_members.find_one({"member_id": ctx.actor_id})
            assigned = (member or {}).get("assigned_accounts", [])
            if assigned and account_id not in assigned:
                raise HTTPException(403, "You do not have access to this account")
    except HTTPException:
        raise
    except Exception:
        pass
    # Fetch live balance from Safe Haven
    balance = 0.0
    if acct.get("sh_account_number"):
        try:
            sh_id = acct.get("sh_account_id", "")
            if sh_id:
                # Preferred: direct single-account endpoint by Safe Haven internal ID
                r = await call_sh("GET", f"/accounts/{sh_id}")
                data = r.get("data") or r
            else:
                # Fallback: list query by account number, then take first result
                r = await call_sh("GET", "/accounts", params={"accountNumber": acct["sh_account_number"]})
                data = r.get("data", [])
                if isinstance(data, list) and data:
                    data = data[0]
                elif isinstance(data, list):
                    data = {}
            # Safe Haven returns availableBalance / accountBalance / bookBalance (not "balance")
            balance = float(
                data.get("availableBalance") or
                data.get("accountBalance") or
                data.get("bookBalance") or 0
            )
        except Exception as e:
            logger.warning(f"[MERCHANT] Balance fetch failed for account {account_id}: {e}")
    txns = await db.merchant_transactions.find(
        {"merchant_id": m["merchant_id"], "account_id": account_id},
        {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    return {"account": acct, "balance_ngn": balance, "transactions": txns}


# ─── TRANSACTIONS ─────────────────────────────────────────────────────────────

@router.get("/v1/merchant/transactions")
async def merchant_transactions(
    request: Request,
    page: int = 1,
    limit: int = 50,
    status: str = "",
    direction: str = "",
    date_from: str = "",
    date_to: str = "",
    search: str = "",
    all_records: bool = False,   # export: fetch all without pagination
):
    m = await get_current_merchant(request)
    skip = (page - 1) * limit
    filt: dict = {"merchant_id": m["merchant_id"]}

    # Scope to assigned accounts for team members
    try:
        from .context import get_merchant_context
        ctx = await get_merchant_context(request)
        if not ctx.is_owner:
            member = await db.merchant_members.find_one({"member_id": ctx.actor_id})
            assigned = (member or {}).get("assigned_accounts", [])
            if assigned:
                filt["account_id"] = {"$in": assigned}
    except Exception:
        pass
    if status:
        filt["status"] = status
    if direction:
        filt["direction"] = direction
    # Date range (ISO strings or YYYY-MM-DD)
    if date_from or date_to:
        date_filt: dict = {}
        if date_from:
            date_filt["$gte"] = date_from
        if date_to:
            # Include up to end of that day
            date_filt["$lte"] = date_to + "T23:59:59"
        filt["created_at"] = date_filt
    # Text search: narration, description, beneficiary_name, metadata.debit_name
    if search:
        search_rx = {"$regex": search, "$options": "i"}
        filt["$or"] = [
            {"narration": search_rx},
            {"description": search_rx},
            {"beneficiary_name": search_rx},
            {"metadata.debit_name": search_rx},
        ]
    total = await db.merchant_transactions.count_documents(filt)
    # Aggregate totals (credit / debit) for the filtered set
    agg = await db.merchant_transactions.aggregate([
        {"$match": filt},
        {"$group": {
            "_id": "$direction",
            "total": {"$sum": "$amount"},
        }}
    ]).to_list(10)
    total_credit = next((int(x["total"]) for x in agg if x["_id"] == "CREDIT"), 0)
    total_debit  = next((int(x["total"]) for x in agg if x["_id"] == "DEBIT"),  0)

    fetch_limit = total if all_records else limit
    fetch_skip  = 0     if all_records else skip
    txns = await db.merchant_transactions.find(
        filt, {"_id": 0}
    ).sort("created_at", -1).skip(fetch_skip).limit(fetch_limit).to_list(fetch_limit)
    return {
        "transactions": txns,
        "total": total,
        "page": page,
        "pages": -(-total // limit),
        "total_credit_kobo": total_credit,
        "total_debit_kobo": total_debit,
    }


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

async def _record_bank_health_event(bank_code: str, bank_name: str, merchant_id: str, txn_ref: str, event_type: str):
    """Fire-and-forget: record a bank transfer health event (TRANSFER_SUCCESS or TRANSFER_FAILED)."""
    try:
        await db.bank_health_events.insert_one({
            "bank_code": bank_code,
            "bank_name": bank_name,
            "merchant_id": merchant_id,
            "txn_ref": txn_ref,
            "event_type": event_type,
            "created_at": now_utc(),
        })
    except Exception as e:
        logger.warning(f"[BankHealth] Failed to record event: {e}")


@router.get("/v1/merchant/bank-health")
async def merchant_bank_health(bank_code: str, request: Request):
    """Return health status for a specific bank based on recent transfer outcomes."""
    await get_current_merchant(request)
    cfg = await db.bank_network_config.find_one({}) or {}
    threshold = int(cfg.get("failure_threshold", 3))
    window = int(cfg.get("time_window_hours", 2))
    mode = cfg.get("mode", "warn")

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat()
    failures = await db.bank_health_events.count_documents({
        "bank_code": bank_code, "event_type": "TRANSFER_FAILED", "created_at": {"$gte": cutoff}
    })
    successes = await db.bank_health_events.count_documents({
        "bank_code": bank_code, "event_type": "TRANSFER_SUCCESS", "created_at": {"$gte": cutoff}
    })
    total = failures + successes
    health_pct = round(successes / total * 100, 1) if total > 0 else 100.0
    is_flagged = failures >= threshold

    return {
        "bank_code": bank_code,
        "failures": failures,
        "successes": successes,
        "health_pct": health_pct,
        "is_flagged": is_flagged,
        "mode": mode,
        "threshold": threshold,
        "window_hours": window,
    }



# ─── SAVED BENEFICIARIES ──────────────────────────────────────────────────────

class BeneficiaryIn(BaseModel):
    account_number: str
    bank_code: str
    bank_name: str
    account_name: str
    nickname: Optional[str] = None

@router.get("/v1/merchant/beneficiaries")
async def list_beneficiaries(request: Request):
    m = await get_current_merchant(request)
    bens = await db.merchant_beneficiaries.find(
        {"merchant_id": m["merchant_id"]}, {"_id": 0}
    ).sort("used_count", -1).to_list(50)
    return {"beneficiaries": bens}

@router.post("/v1/merchant/beneficiaries")
async def save_beneficiary(req: BeneficiaryIn, request: Request):
    m = await get_current_merchant(request)
    existing = await db.merchant_beneficiaries.find_one({
        "merchant_id": m["merchant_id"], "account_number": req.account_number, "bank_code": req.bank_code
    })
    if existing:
        await db.merchant_beneficiaries.update_one(
            {"_id": existing["_id"]},
            {"$set": {"account_name": req.account_name, "nickname": req.nickname, "updated_at": now_utc()},
             "$inc": {"used_count": 1}}
        )
        return {"message": "Beneficiary updated"}
    await db.merchant_beneficiaries.insert_one({
        "merchant_id": m["merchant_id"], "account_number": req.account_number,
        "bank_code": req.bank_code, "bank_name": req.bank_name,
        "account_name": req.account_name, "nickname": req.nickname,
        "used_count": 1, "created_at": now_utc(), "updated_at": now_utc()
    })
    return {"message": "Beneficiary saved"}

@router.delete("/v1/merchant/beneficiaries/{account_number}")
async def delete_beneficiary(account_number: str, request: Request):
    m = await get_current_merchant(request)
    await db.merchant_beneficiaries.delete_one(
        {"merchant_id": m["merchant_id"], "account_number": account_number}
    )
    return {"message": "Removed"}


@router.post("/v1/merchant/services/transfer")
async def merchant_transfer(req: MerchantTransfer, request: Request):
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 100:
        raise HTTPException(400, "Minimum transfer amount is ₦100")

    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    m = ctx.merchant
    await _verify_actor_pin(ctx, req.pin)

    # Name enquiry
    try:
        ne = await call_sh("POST", "/transfers/name-enquiry", body={
            "bankCode": req.bank_code,
            "accountNumber": req.account_number,
        })
        account_name = ne.get("data", {}).get("accountName") or ne.get("accountName", "Unknown")
        ne_ref = ne.get("data", {}).get("sessionId") or f"NEQ{secrets.token_hex(8).upper()}"
    except HTTPException:
        raise
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

    # ── Calculate BOMPAY fee (same model as user app) ──────────────────────────
    bompay_fee   = await calculate_fee("TRANSFER", req.amount)
    sh_nip_fee   = await get_nip_fee(req.amount)
    stamp_duty   = await calculate_stamp_duty(req.amount)
    # BOMPAY margin: the portion above raw NIP fee; SH collects NIP from merchant's account
    bompay_margin = round(max(bompay_fee - sh_nip_fee, 0.0), 2)
    fee_kobo = int(bompay_margin * 100)

    # Resolve bank name for health tracking
    bank_name = req.bank_code
    try:
        from core import NIGERIAN_BANKS as _BANKS
        _b = next((b for b in _BANKS if b.get("code") == req.bank_code), None)
        if _b:
            bank_name = _b.get("name", req.bank_code)
    except Exception:
        pass

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
    except HTTPException:
        raise
    except Exception as e:
        asyncio.create_task(_record_bank_health_event(req.bank_code, bank_name, m["merchant_id"], txn_ref, "TRANSFER_FAILED"))
        raise HTTPException(502, f"Transfer failed: {e}")

    # Derive status from Safe Haven's actual response — SH returns PENDING for NIP transfers
    # that complete asynchronously; do not hardcode "success"
    sh_data = sh_resp.get("data") or {}
    sh_status_raw = (sh_data.get("status") or sh_resp.get("status") or "").upper()
    sh_session = sh_data.get("sessionId") or sh_data.get("transactionReference") or ""
    if sh_status_raw in ("COMPLETED", "SUCCESS", "SUCCESSFUL"):
        txn_status = "success"
        asyncio.create_task(_record_bank_health_event(req.bank_code, bank_name, m["merchant_id"], txn_ref, "TRANSFER_SUCCESS"))
    elif sh_status_raw in ("FAILED", "FAILURE", "REVERSED", "REJECTED"):
        txn_status = "failed"
        asyncio.create_task(_record_bank_health_event(req.bank_code, bank_name, m["merchant_id"], txn_ref, "TRANSFER_FAILED"))
    else:
        # PENDING, PROCESSING, or unknown — Safe Haven will confirm via webhook
        txn_status = "pending"
        asyncio.create_task(_record_bank_health_event(req.bank_code, bank_name, m["merchant_id"], txn_ref, "TRANSFER_SUCCESS"))
    logger.info(f"[MERCHANT] Transfer {txn_ref} SH status={sh_status_raw!r} → recorded as {txn_status}")

    txn_doc = {
        "transaction_id": txn_ref,
        "merchant_id": m["merchant_id"],
        "account_id": acct["account_id"],
        "type": "TRANSFER",
        "direction": "DEBIT",
        "amount": amount_kobo,
        "fee": fee_kobo,
        "stamp_duty": int(stamp_duty * 100),
        "currency": "NGN",
        "status": txn_status,
        "sh_session_id": sh_session,
        "beneficiary_account": req.account_number,
        "beneficiary_name": account_name,
        "beneficiary_bank": bank_name,
        "beneficiary_bank_code": req.bank_code,
        "narration": req.narration,
        "description": f"Transfer to {account_name}",
        "metadata": {
            "beneficiary_name": account_name,
            "beneficiary_account_number": req.account_number,
            "beneficiary_bank": bank_name,
        },
        "mode": m.get("mode", "sandbox"),
        "provider_response": str(sh_resp)[:500],
        "created_at": now_utc(),
    }
    await db.merchant_transactions.insert_one(txn_doc)
    txn_doc.pop("_id", None)
    if txn_status in ("success", "pending"):
        asyncio.create_task(send_merchant_alert(m["merchant_id"], "MERCHANT_TRANSFER", {
            "amount": req.amount, "beneficiary": account_name,
            "account": req.account_number, "bank": bank_name, "ref": txn_ref,
        }))
        # ── Collect BOMPAY margin (fire-and-forget, same as user app) ──────────
        if bompay_margin > 0:
            asyncio.create_task(_collect_merchant_fee_bg(
                acct["sh_account_number"], bompay_margin, txn_ref, "TRANSFER"
            ))
    return {"message": "Transfer initiated", "transaction": txn_doc, "beneficiary_name": account_name,
            "sh_status": sh_status_raw, "sh_session_id": sh_session,
            "fee": bompay_fee, "stamp_duty": stamp_duty, "total": req.amount + bompay_fee + stamp_duty}


# ─── NAME ENQUIRY & BANKS (merchant-auth wrappers) ────────────────────────────

@router.get("/v1/merchant/transfers/fee-preview")
async def merchant_transfer_fee_preview(amount: float, request: Request):
    """Return itemised fee breakdown for a merchant bank transfer — mirrors /api/transfers/fee-preview."""
    await get_current_merchant(request)
    if amount <= 0:
        raise HTTPException(400, "Amount must be positive")
    bompay_fee   = await calculate_fee("TRANSFER", amount)
    sh_nip_fee   = await get_nip_fee(amount)
    stamp_duty   = await calculate_stamp_duty(amount)
    # Bompay margin = bompay_fee − sh_nip_fee (SH collects the raw NIP fee; we collect only our margin)
    bompay_margin = round(max(bompay_fee - sh_nip_fee, 0.0), 2)
    return {
        "amount":         amount,
        "fee":            bompay_fee,          # alias for frontend compatibility
        "bompay_fee":     bompay_fee,
        "sh_nip_fee":     sh_nip_fee,
        "stamp_duty":     stamp_duty,
        "bompay_margin":  bompay_margin,
        "total":          round(amount + bompay_fee + stamp_duty, 2),
    }


@router.get("/v1/merchant/services/fee-preview")
async def merchant_vas_fee_preview(service: str, amount: float, request: Request):
    """Return the BOMPAY service fee for a given VAS type and amount."""
    await get_current_merchant(request)
    if amount <= 0:
        raise HTTPException(400, "Amount must be positive")
    svc_map = {"AIRTIME": "AIRTIME", "DATA": "DATA",
               "ELECTRICITY": "ELECTRICITY", "CABLE": "CABLE_TV", "CABLE_TV": "CABLE_TV"}
    svc = svc_map.get(service.upper())
    if not svc:
        raise HTTPException(400, f"Unknown service: {service}")
    fee = await calculate_fee(svc, amount)
    return {"service": svc, "amount": amount, "fee": fee, "total": round(amount + fee, 2)}


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
                                  mode: str, metadata: dict, fee_kobo: int = 0) -> dict:
    doc = {
        "transaction_id": txn_id, "merchant_id": merchant_id,
        "account_id": account_id, "type": vas_type, "direction": "DEBIT",
        "amount": amount_kobo, "fee": fee_kobo, "currency": "NGN", "status": status, "mode": mode,
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
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    m = ctx.merchant
    await _verify_actor_pin(ctx, req.pin)
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 50 or req.amount > 50000:
        raise HTTPException(400, "Amount must be ₦50–₦50,000")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)
    fee_ngn  = await calculate_fee("AIRTIME", req.amount)
    fee_kobo = int(fee_ngn * 100)

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
        {"network": req.network, "phone": req.phone_number, "provider_ref": pref, "provider": provider},
        fee_kobo=fee_kobo,
    )
    asyncio.create_task(_credit_merchant_cashback_bg(m["merchant_id"], req.amount, "AIRTIME", f"{req.network} airtime"))
    asyncio.create_task(send_merchant_alert(m["merchant_id"], "MERCHANT_AIRTIME", {
        "amount": req.amount, "network": req.network, "phone": req.phone_number, "ref": txn_ref,
    }))
    if fee_ngn > 0:
        asyncio.create_task(_collect_merchant_fee_bg(acct["sh_account_number"], fee_ngn, txn_ref, "VAS"))
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "fee": fee_ngn, "total": req.amount + fee_ngn,
            "network": req.network, "phone": req.phone_number}


# ─── VAS DATA ─────────────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/data")
async def merchant_buy_data(req: MerchantDataReq, request: Request):
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    m = ctx.merchant
    await _verify_actor_pin(ctx, req.pin)
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)
    fee_ngn  = await calculate_fee("DATA", req.amount)
    fee_kobo = int(fee_ngn * 100)

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
        {"network": req.network, "phone": req.phone_number, "plan_id": req.plan_id, "provider_ref": pref, "provider": provider},
        fee_kobo=fee_kobo,
    )
    asyncio.create_task(_credit_merchant_cashback_bg(m["merchant_id"], req.amount, "DATA", f"{req.network} data"))
    asyncio.create_task(send_merchant_alert(m["merchant_id"], "MERCHANT_DATA", {
        "amount": req.amount, "network": req.network, "phone": req.phone_number,
        "plan": req.plan_id, "ref": txn_ref,
    }))
    if fee_ngn > 0:
        asyncio.create_task(_collect_merchant_fee_bg(acct["sh_account_number"], fee_ngn, txn_ref, "VAS"))
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "fee": fee_ngn, "total": req.amount + fee_ngn,
            "network": req.network, "phone": req.phone_number, "plan_id": req.plan_id}


# ─── VAS ELECTRICITY ──────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/electricity")
async def merchant_pay_electricity(req: MerchantElectricityReq, request: Request):
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    m = ctx.merchant
    await _verify_actor_pin(ctx, req.pin)
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if req.amount < 1000:
        raise HTTPException(400, "Minimum electricity payment is ₦1,000")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)
    fee_ngn  = await calculate_fee("ELECTRICITY", req.amount)
    fee_kobo = int(fee_ngn * 100)

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
         "provider_ref": pref, "provider": provider},
        fee_kobo=fee_kobo,
    )

    # Send electricity token SMS to customer (non-blocking)
    phone = m.get("phone", "")
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

    asyncio.create_task(_credit_merchant_cashback_bg(m["merchant_id"], req.amount, "ELECTRICITY", f"{req.disco} electricity"))
    asyncio.create_task(send_merchant_alert(m["merchant_id"], "MERCHANT_ELECTRICITY", {
        "amount": req.amount, "meter": req.meter_number, "disco": req.disco,
        "token": token, "units": units or "N/A", "ref": txn_ref,
    }))
    if fee_ngn > 0:
        asyncio.create_task(_collect_merchant_fee_bg(acct["sh_account_number"], fee_ngn, txn_ref, "VAS"))
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "fee": fee_ngn, "total": req.amount + fee_ngn,
            "token": token, "units": units, "meter_number": req.meter_number}


# ─── VAS CABLE TV ─────────────────────────────────────────────────────────────

@router.post("/v1/merchant/services/cable")
async def merchant_pay_cable(req: MerchantCableReq, request: Request):
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    m = ctx.merchant
    await _verify_actor_pin(ctx, req.pin)
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    acct = await _get_merch_acct_for_vas(m["merchant_id"], req.from_account_id)
    txn_ref = f"MVAS_{secrets.token_hex(8).upper()}"
    amt = int(req.amount * 100)
    fee_ngn  = await calculate_fee("CABLE_TV", req.amount)
    fee_kobo = int(fee_ngn * 100)

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
         "package_id": req.package_id, "provider_ref": pref},
        fee_kobo=fee_kobo,
    )
    asyncio.create_task(_credit_merchant_cashback_bg(m["merchant_id"], req.amount, "CABLE_TV", f"{req.provider} cable TV"))
    asyncio.create_task(send_merchant_alert(m["merchant_id"], "MERCHANT_CABLE", {
        "amount": req.amount, "provider": req.provider,
        "smartcard": req.smartcard_number, "ref": txn_ref,
    }))
    if fee_ngn > 0:
        asyncio.create_task(_collect_merchant_fee_bg(acct["sh_account_number"], fee_ngn, txn_ref, "VAS"))
    return {"transaction_id": txn_ref, "status": "success", "amount": req.amount,
            "fee": fee_ngn, "total": req.amount + fee_ngn,
            "provider": req.provider, "smartcard": req.smartcard_number}


# ─── NOTIFICATION SETTINGS ────────────────────────────────────────────────────

class NotifToggle(BaseModel):
    sms_enabled: Optional[bool] = None
    email_enabled: Optional[bool] = None

class AddContactItem(BaseModel):
    value: str  # phone number or email

@router.get("/v1/merchant/notification-settings")
async def get_notification_settings(request: Request):
    m = await get_current_merchant(request)
    doc = await db.merchant_notification_settings.find_one({"merchant_id": m["merchant_id"]})
    if not doc:
        return {"merchant_id": m["merchant_id"], "phones": [], "emails": [],
                "sms_enabled": True, "email_enabled": True}
    doc.pop("_id", None)
    return doc

@router.put("/v1/merchant/notification-settings")
async def update_notification_settings(req: NotifToggle, request: Request):
    m = await get_current_merchant(request)
    update = {}
    if req.sms_enabled is not None:
        update["sms_enabled"] = req.sms_enabled
    if req.email_enabled is not None:
        update["email_enabled"] = req.email_enabled
    if not update:
        raise HTTPException(400, "Nothing to update")
    await db.merchant_notification_settings.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {**update, "updated_at": now_utc()},
         "$setOnInsert": {"merchant_id": m["merchant_id"], "phones": [], "emails": [], "created_at": now_utc()}},
        upsert=True
    )
    return {"message": "Settings updated"}

@router.post("/v1/merchant/notification-settings/phones")
async def add_notification_phone(req: AddContactItem, request: Request):
    m = await get_current_merchant(request)
    phone = req.value.strip()
    if not phone:
        raise HTTPException(400, "Phone number is required")
    doc = await db.merchant_notification_settings.find_one({"merchant_id": m["merchant_id"]})
    phones = (doc or {}).get("phones", [])
    if phone in phones:
        return {"message": "Already added", "phones": phones}
    if len(phones) >= 5:
        raise HTTPException(400, "Maximum 5 phone numbers allowed")
    await db.merchant_notification_settings.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$addToSet": {"phones": phone}, "$set": {"updated_at": now_utc()},
         "$setOnInsert": {"merchant_id": m["merchant_id"], "emails": [],
                          "sms_enabled": True, "email_enabled": True, "created_at": now_utc()}},
        upsert=True
    )
    return {"message": "Phone added", "phones": phones + [phone]}

@router.delete("/v1/merchant/notification-settings/phones/{phone}")
async def remove_notification_phone(phone: str, request: Request):
    m = await get_current_merchant(request)
    await db.merchant_notification_settings.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$pull": {"phones": phone}, "$set": {"updated_at": now_utc()}}
    )
    return {"message": "Phone removed"}

@router.post("/v1/merchant/notification-settings/emails")
async def add_notification_email(req: AddContactItem, request: Request):
    m = await get_current_merchant(request)
    email = req.value.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email is required")
    doc = await db.merchant_notification_settings.find_one({"merchant_id": m["merchant_id"]})
    emails = (doc or {}).get("emails", [])
    if email in emails:
        return {"message": "Already added", "emails": emails}
    if len(emails) >= 5:
        raise HTTPException(400, "Maximum 5 email addresses allowed")
    await db.merchant_notification_settings.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$addToSet": {"emails": email}, "$set": {"updated_at": now_utc()},
         "$setOnInsert": {"merchant_id": m["merchant_id"], "phones": [],
                          "sms_enabled": True, "email_enabled": True, "created_at": now_utc()}},
        upsert=True
    )
    return {"message": "Email added", "emails": emails + [email]}

@router.delete("/v1/merchant/notification-settings/emails/{email}")
async def remove_notification_email(email: str, request: Request):
    m = await get_current_merchant(request)
    await db.merchant_notification_settings.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$pull": {"emails": email}, "$set": {"updated_at": now_utc()}}
    )
    return {"message": "Email removed"}


# ─── SETTINGS ─────────────────────────────────────────────────────────────────

class UpdateProfile(BaseModel):
    business_name: Optional[str] = None
    owner_name: Optional[str] = None
    phone: Optional[str] = None

class ChangePin(BaseModel):
    current_pin: str
    new_pin: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

class VerifyPin(BaseModel):
    pin: str

@router.post("/v1/merchant/verify-pin")
async def verify_merchant_pin(req: VerifyPin, request: Request):
    """Verify PIN for the authenticated actor (owner or team member)."""
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    await _verify_actor_pin(ctx, req.pin)
    return {"message": "PIN verified", "merchant_id": ctx.merchant_id}


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
    # Store vID in KYB record for later use during account provisioning.
    # Saved as both director_vid (legacy field) AND sh_identity_id so provisioning
    # can reuse it without re-validating BVN.
    now = now_utc()
    await db.merchant_kyb.update_one(
        {"merchant_id": m["merchant_id"]},
        {"$set": {
            "director_vid": vid,
            "director_vid_type": req.identity_type.upper(),
            "vid_verified_at": now,
            "sh_identity_id": vid,  # canonical field used by account provisioning
        }},
        upsert=True
    )
    logger.info(f"[KYB] vID stored (sh_identity_id + director_vid) for merchant {m['merchant_id']}")
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
    from .context import get_merchant_context as _get_ctx
    ctx = await _get_ctx(request)
    if len(req.new_pin) != 4 or not req.new_pin.isdigit():
        raise HTTPException(400, "New PIN must be 4 digits")
    if ctx.is_owner:
        raw = await db.merchants.find_one({"merchant_id": ctx.merchant_id}, {"pin_hash": 1})
        if not verify_password(req.current_pin, (raw or {}).get("pin_hash", "")):
            raise HTTPException(400, "Current PIN is incorrect")
        await db.merchants.update_one(
            {"merchant_id": ctx.merchant_id},
            {"$set": {"pin_hash": hash_password(req.new_pin), "updated_at": now_utc()}}
        )
    else:
        member = await db.merchant_members.find_one({"member_id": ctx.actor_id}, {"pin_hash": 1})
        if not member or not member.get("pin_hash"):
            raise HTTPException(400, "PIN not set. Please set your PIN first.")
        if not verify_password(req.current_pin, member["pin_hash"]):
            raise HTTPException(400, "Current PIN is incorrect")
        await db.merchant_members.update_one(
            {"member_id": ctx.actor_id},
            {"$set": {"pin_hash": hash_password(req.new_pin), "updated_at": now_utc()}}
        )
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



# ─── WEBAUTHN / BIOMETRIC LOCK ────────────────────────────────────────────────

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)

def _webauthn_rp(request: Request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    host_no_port = host.split(":")[0]
    proto = request.headers.get("x-forwarded-proto", "https")
    origin = f"{proto}://{host}"
    return host_no_port, origin

@router.get("/v1/merchant/webauthn/has-credential")
async def webauthn_has_credential(request: Request):
    """Return whether the merchant has a registered biometric credential."""
    m = await get_current_merchant(request)
    cred = await db.merchant_webauthn_credentials.find_one({"merchant_id": m["merchant_id"]})
    return {"has_credential": bool(cred)}

@router.get("/v1/merchant/webauthn/register-options")
async def webauthn_register_options(request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    rp_id, _origin = _webauthn_rp(request)
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name="Bompay Business",
        user_id=mid.encode()[:64],
        user_name=m.get("email", mid),
        user_display_name=m.get("business_name", "Merchant"),
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
    )
    challenge_b64 = base64.b64encode(opts.challenge).decode()
    await db.merchant_webauthn_challenges.replace_one(
        {"merchant_id": mid, "type": "registration"},
        {"merchant_id": mid, "type": "registration",
         "challenge": challenge_b64, "created_at": now_utc()},
        upsert=True,
    )
    return _json.loads(options_to_json(opts))

@router.post("/v1/merchant/webauthn/register")
async def webauthn_register(body: dict, request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    rp_id, origin = _webauthn_rp(request)
    row = await db.merchant_webauthn_challenges.find_one(
        {"merchant_id": mid, "type": "registration"})
    if not row:
        raise HTTPException(400, "No pending registration challenge")
    challenge_bytes = base64.b64decode(row["challenge"])
    try:
        v = verify_registration_response(
            credential=body,
            expected_challenge=challenge_bytes,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(400, f"Registration failed: {exc}")
    await db.merchant_webauthn_credentials.replace_one(
        {"merchant_id": mid},
        {
            "merchant_id": mid,
            "credential_id": base64.b64encode(v.credential_id).decode(),
            "public_key": base64.b64encode(v.credential_public_key).decode(),
            "sign_count": v.sign_count,
            "rp_id": rp_id,
            "created_at": now_utc(),
        },
        upsert=True,
    )
    await db.merchant_webauthn_challenges.delete_one(
        {"merchant_id": mid, "type": "registration"})
    return {"success": True}

@router.get("/v1/merchant/webauthn/auth-options")
async def webauthn_auth_options(request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    rp_id, _origin = _webauthn_rp(request)
    cred_doc = await db.merchant_webauthn_credentials.find_one({"merchant_id": mid})
    allow_creds = (
        [PublicKeyCredentialDescriptor(
            id=base64.b64decode(cred_doc["credential_id"]))]
        if cred_doc else []
    )
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_creds,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_b64 = base64.b64encode(opts.challenge).decode()
    await db.merchant_webauthn_challenges.replace_one(
        {"merchant_id": mid, "type": "authentication"},
        {"merchant_id": mid, "type": "authentication",
         "challenge": challenge_b64, "created_at": now_utc()},
        upsert=True,
    )
    return _json.loads(options_to_json(opts))

@router.post("/v1/merchant/webauthn/authenticate")
async def webauthn_authenticate(body: dict, request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    rp_id, origin = _webauthn_rp(request)
    row = await db.merchant_webauthn_challenges.find_one(
        {"merchant_id": mid, "type": "authentication"})
    if not row:
        raise HTTPException(400, "No pending authentication challenge")
    cred_doc = await db.merchant_webauthn_credentials.find_one({"merchant_id": mid})
    if not cred_doc:
        raise HTTPException(400, "No biometric registered for this account")
    challenge_bytes = base64.b64decode(row["challenge"])
    try:
        v = verify_authentication_response(
            credential=body,
            expected_challenge=challenge_bytes,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64.b64decode(cred_doc["public_key"]),
            credential_current_sign_count=cred_doc["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(401, f"Authentication failed: {exc}")
    await db.merchant_webauthn_credentials.update_one(
        {"merchant_id": mid},
        {"$set": {"sign_count": v.new_sign_count}})
    await db.merchant_webauthn_challenges.delete_one(
        {"merchant_id": mid, "type": "authentication"})
    return {"success": True, "unlocked": True}

@router.post("/v1/merchant/webauthn/public-auth-options")
async def webauthn_public_auth_options(body: dict, request: Request):
    """Public endpoint (no session required): get WebAuthn auth options for login page."""
    email = (body.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(400, "email required")
    m = await db.merchants.find_one({"email": email})
    rp_id, _ = _webauthn_rp(request)
    allow_creds = []
    store_id = None
    if m:
        cred_doc = await db.merchant_webauthn_credentials.find_one({"merchant_id": m["merchant_id"]})
        if cred_doc:
            allow_creds = [PublicKeyCredentialDescriptor(id=base64.b64decode(cred_doc["credential_id"]))]
            store_id = m["merchant_id"]
    opts = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_creds,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_b64 = base64.b64encode(opts.challenge).decode()
    if store_id:
        await db.merchant_webauthn_challenges.replace_one(
            {"merchant_id": store_id, "type": "public_auth"},
            {"merchant_id": store_id, "type": "public_auth",
             "challenge": challenge_b64, "created_at": now_utc()},
            upsert=True,
        )
    return _json.loads(options_to_json(opts))


@router.post("/v1/merchant/webauthn/public-login")
async def webauthn_public_login(body: dict, request: Request, response: Response):
    """Public endpoint (no session required): complete biometric login."""
    email = (body.pop("email", "") or "").lower().strip()
    if not email:
        raise HTTPException(400, "email required")
    m = await db.merchants.find_one({"email": email})
    if not m:
        raise HTTPException(401, "Authentication failed")
    mid = m["merchant_id"]
    rp_id, origin = _webauthn_rp(request)
    row = await db.merchant_webauthn_challenges.find_one(
        {"merchant_id": mid, "type": "public_auth"})
    if not row:
        raise HTTPException(400, "No pending challenge. Restart biometric login.")
    cred_doc = await db.merchant_webauthn_credentials.find_one({"merchant_id": mid})
    if not cred_doc:
        raise HTTPException(401, "No biometric registered for this account")
    challenge_bytes = base64.b64decode(row["challenge"])
    try:
        v = verify_authentication_response(
            credential=body,
            expected_challenge=challenge_bytes,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64.b64decode(cred_doc["public_key"]),
            credential_current_sign_count=cred_doc["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(401, f"Biometric verification failed: {exc}")
    await db.merchant_webauthn_credentials.update_one(
        {"merchant_id": mid}, {"$set": {"sign_count": v.new_sign_count}})
    await db.merchant_webauthn_challenges.delete_one(
        {"merchant_id": mid, "type": "public_auth"})
    access, refresh = _merchant_tokens(mid, email)
    _set_merchant_cookies(response, access, refresh)
    return _safe_merchant(m)
    """Remove a merchant's registered biometric credential."""
    m = await get_current_merchant(request)
    await db.merchant_webauthn_credentials.delete_one(
        {"merchant_id": m["merchant_id"]})
    return {"success": True}

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


@router.get("/admin/merchants/daily-volume")
async def admin_merchant_daily_volume(request: Request, days: int = 14):
    """Daily transaction volume across the merchant platform for the chart."""
    await _get_admin(request)
    from datetime import datetime, timezone, timedelta
    today = datetime.now(timezone.utc)
    results = []
    for i in range(days - 1, -1, -1):
        d = today - timedelta(days=i)
        date_prefix = d.strftime("%Y-%m-%d")
        agg = await db.merchant_transactions.aggregate([
            {"$match": {
                "created_at": {"$gte": f"{date_prefix}T00:00:00", "$lt": f"{date_prefix}T23:59:59.999"},
            }},
            {"$group": {"_id": None, "volume": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        ]).to_list(1)
        v = agg[0] if agg else {"volume": 0, "count": 0}
        results.append({
            "date": d.strftime("%b %d"),
            "volume_ngn": round(v["volume"] / 100, 2),
            "count": v["count"],
        })
    return {"data": results, "days": days}


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
    """Send KYB approval/rejection email to merchant with a working CTA button."""
    if not email:
        return
    try:
        # HTML-escape all user-controlled inputs to prevent rendering issues
        safe_biz = _escape(business_name or "")
        safe_note = _escape(admin_note or "")
        safe_acct = _escape(account_number or "")

        # Ensure the frontend URL is always HTTPS — fall back to bompay.app if not
        raw_frontend = (FRONTEND_URL or "").rstrip("/")
        if not raw_frontend.startswith("https://"):
            raw_frontend = "https://bompay.app"
        frontend = raw_frontend

        if status == "approved":
            subject = f"[BOMPAY] Your KYB has been Approved — {business_name}"
            cta_label = "Log in to your Dashboard"
            cta_url   = f"{frontend}/v1/dashboard"
            status_color = "#059669"
            status_text  = "Approved"
            extra_rows = ""
            if safe_acct:
                extra_rows += (f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">Primary Account</td>'
                               f'<td style="padding:4px 0;color:#0f172a;font-size:13px;font-weight:700;text-align:right;font-family:monospace">{safe_acct}</td></tr>')
            if safe_note:
                extra_rows += (f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">Note</td>'
                               f'<td style="padding:4px 0;color:#0f172a;font-size:13px;font-weight:600;text-align:right">{safe_note}</td></tr>')
        else:
            subject = f"[BOMPAY] KYB Application Update — {business_name}"
            cta_label = "Update KYB Documents"
            cta_url   = f"{frontend}/v1/kyb"
            status_color = "#dc2626"
            status_text  = "Not Approved"
            extra_rows = ""
            if safe_note:
                extra_rows += (f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">Reason</td>'
                               f'<td style="padding:4px 0;color:#0f172a;font-size:13px;font-weight:600;text-align:right">{safe_note}</td></tr>')

        html = (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td style="background:#064BCB;padding:24px 24px 16px;border-radius:12px 12px 0 0">'
            f'<span style="color:#fff;font-size:18px;font-weight:800;letter-spacing:-0.5px">BOMPAY</span></td></tr>'
            f'<tr><td style="background:#fff;padding:20px 24px;border-radius:0 0 12px 12px;font-family:Arial,sans-serif">'
            f'<p style="font-size:16px;font-weight:700;color:#0f172a;margin-bottom:16px">KYB Verification Update</p>'
            f'<table width="100%" cellpadding="0" cellspacing="0">'
            f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">Business</td>'
            f'<td style="padding:4px 0;color:#0f172a;font-size:13px;font-weight:600;text-align:right">{safe_biz}</td></tr>'
            f'<tr><td style="padding:4px 0;color:#64748b;font-size:13px">KYB Status</td>'
            f'<td style="padding:4px 0;font-size:13px;font-weight:700;text-align:right;color:{status_color}">{status_text}</td></tr>'
            f'{extra_rows}'
            f'</table>'
            f'<p style="margin-top:20px">'
            f'<a href="{cta_url}" style="background:#064BCB;color:#fff;padding:10px 20px;'
            f'border-radius:8px;text-decoration:none;font-size:13px;font-weight:700">'
            f'{cta_label}</a></p>'
            f'<p style="font-size:11px;color:#94a3b8;margin-top:16px">BOMPAY &mdash; Your trusted Nigerian fintech. '
            f'We never ask for your PIN or password by email.</p>'
            f'</td></tr></table>'
        )
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
    Admin: (Re-)provision the primary Safe Haven CORPORATE virtual account.
    Accepts optional body: { rc_number, identity_id } to override stored values.
    """
    await _get_admin(request)
    m = await db.merchants.find_one({"merchant_id": merchant_id})
    if not m:
        raise HTTPException(404, "Merchant not found")
    if m.get("kyb_status") != "approved":
        raise HTTPException(400, "Merchant KYB must be approved before provisioning a live account")

    # Accept optional overrides from admin
    body_data: dict = {}
    try:
        body_data = await request.json()
    except Exception:
        pass
    rc_override          = (body_data.get("rc_number") or "").strip()
    identity_id_override = (body_data.get("identity_id") or "").strip()

    kyb = await db.merchant_kyb.find_one({"merchant_id": merchant_id}, {"_id": 0}) or {}

    # Apply RC number override if admin provided one
    if rc_override:
        kyb["rc_number"] = rc_override
        await db.merchants.update_one({"merchant_id": merchant_id}, {"$set": {"rc_number": rc_override}})
        await db.merchant_kyb.update_one({"merchant_id": merchant_id}, {"$set": {"rc_number": rc_override}})
        logger.info(f"[ADMIN] RC number override for {merchant_id}: {rc_override}")

    # If admin supplied an identity_id override, persist it to KYB so it's reused forever
    if identity_id_override and not kyb.get("sh_identity_id"):
        await db.merchant_kyb.update_one(
            {"merchant_id": merchant_id},
            {"$set": {"sh_identity_id": identity_id_override}},
            upsert=True
        )
        kyb["sh_identity_id"] = identity_id_override
        logger.info(f"[ADMIN] Identity ID saved to KYB for {merchant_id}: {identity_id_override[:16]}…")

    sh = await _create_sh_corporate_subaccount(m, kyb, m.get("business_name", "Primary"), force_identity_id=identity_id_override)
    now = now_utc()

    # If call_sh raised, the exception already propagated above.
    # Here we only reject a completely empty response with no external_reference
    # (means Safe Haven never acknowledged the request at all).
    ext_ref = sh.get("external_reference", "")
    if not sh.get("sh_account_number") and not sh.get("sh_account_id") and not ext_ref:
        raise HTTPException(400, "Provisioning failed — Safe Haven returned no acknowledgment. Check RC number and retry.")

    # Safe Haven may process corporate accounts asynchronously (acct number arrives via webhook).
    # Save the record NOW so the webhook can match by external_reference and fill in the account number.
    is_async = not sh.get("sh_account_number") and not sh.get("sh_account_id")
    if is_async:
        logger.info(f"[ADMIN] Corporate account accepted by Safe Haven (async). Saving pending record ext_ref={ext_ref}")

    acct_update = {
        "sh_account_id":      sh.get("sh_account_id", ""),
        "sh_account_number":  sh.get("sh_account_number", ""),
        "sh_account_name":    sh.get("sh_account_name", f"{m.get('business_name', '')} — Primary"),
        "bank_name":          sh.get("bank_name", "Safe Haven MFB"),
        "bank_code":          sh.get("bank_code", "090286"),
        "external_reference": ext_ref,
        "provisioned_at":     now,
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

    if is_async:
        return {
            "message": "Corporate account request accepted by Safe Haven. Account number will be delivered shortly via webhook.",
            "account_number": "",
            "account_name": acct_update["sh_account_name"],
            "bank": acct_update["bank_name"],
            "pending": True,
        }
    return {
        "message": "Corporate account provisioned",
        "account_number": sh["sh_account_number"],
        "account_name": sh["sh_account_name"],
        "bank": sh["bank_name"],
        "pending": False,
    }



@router.post("/admin/merchants/{merchant_id}/sync-account")
async def admin_sync_merchant_account(merchant_id: str, request: Request):
    """
    Sync a pending merchant account from Safe Haven.
    1. Calls Safe Haven account list to find any account matching this merchant.
    2. If found, updates the pending record in DB.
    Also accepts body { account_number, account_id } for manual admin override.
    """
    await _get_admin(request)
    m = await db.merchants.find_one({"merchant_id": merchant_id})
    if not m:
        raise HTTPException(404, "Merchant not found")

    # Accept optional manual override from admin
    body_data: dict = {}
    try:
        body_data = await request.json()
    except Exception:
        pass
    manual_acct_number = (body_data.get("account_number") or "").strip()
    manual_acct_id     = (body_data.get("account_id") or "").strip()

    # Find the pending merchant account record
    pending = await db.merchant_accounts.find_one({"merchant_id": merchant_id, "type": "primary"})
    if not pending:
        raise HTTPException(404, "No primary account record found. Provision first.")
    if pending.get("sh_account_number"):
        return {
            "message": "Account already has a number",
            "account_number": pending["sh_account_number"],
            "synced": False,
        }

    now = now_utc()

    # ── Manual override: admin pasted the account number/ID directly ────────────
    if manual_acct_number:
        await db.merchant_accounts.update_one(
            {"merchant_id": merchant_id, "type": "primary"},
            {"$set": {
                "sh_account_number": manual_acct_number,
                "sh_account_id":     manual_acct_id or pending.get("sh_account_id", ""),
                "provisioned_at":    now,
            }}
        )
        logger.info(f"[ADMIN] Manual account number set for {merchant_id}: {manual_acct_number}")
        return {
            "message": f"Account number set manually: {manual_acct_number}",
            "account_number": manual_acct_number,
            "synced": True,
            "source": "manual",
        }

    # ── Auto-sync: poll Safe Haven account list ──────────────────────────────────
    ext_ref = pending.get("external_reference", "")
    business_name = (m.get("business_name") or "").lower().strip()

    try:
        result = await call_sh("GET", "/accounts?page=1&limit=100")
        accounts_raw = result.get("data", [])
        if not isinstance(accounts_raw, list):
            accounts_raw = (result.get("data") or {}).get("data", []) if isinstance(result.get("data"), dict) else []

        # Build search keywords: email prefix, business name words
        email = (m.get("email") or "").lower()
        email_prefix = email.split("@")[0] if "@" in email else email  # e.g. "brivo360"
        biz_words = [w.lower() for w in business_name.split() if len(w) > 3]  # e.g. ["elcalssico"]

        found = None
        for a in accounts_raw:
            sh_ext = (a.get("externalReference") or a.get("external_reference") or "").strip()
            sh_name = (a.get("accountName") or a.get("account_name") or "").lower()
            acct_no = a.get("accountNumber") or a.get("virtualAccountNumber") or ""
            if not acct_no:
                continue
            # Priority 1: external reference (most reliable)
            if ext_ref and sh_ext and (sh_ext == ext_ref or ext_ref in sh_ext or sh_ext in ext_ref):
                found = a
                logger.info(f"[ADMIN] SH sync: matched by ext_ref for {merchant_id}: {acct_no}")
                break
            # Priority 2: email prefix in account name (e.g. "brivo360" in "BRIVO360")
            if email_prefix and len(email_prefix) >= 4 and email_prefix in sh_name:
                found = a
                logger.info(f"[ADMIN] SH sync: matched by email prefix '{email_prefix}' for {merchant_id}: {acct_no}")
            # Priority 3: business name words
            elif biz_words and any(w in sh_name for w in biz_words):
                if not found:
                    found = a
                    logger.info(f"[ADMIN] SH sync: matched by biz name for {merchant_id}: {acct_no}")

        if found:
            acct_no  = found.get("accountNumber") or found.get("virtualAccountNumber") or ""
            acct_id  = found.get("_id") or found.get("id") or pending.get("sh_account_id", "")
            acct_nm  = found.get("accountName") or pending.get("sh_account_name", "")
            await db.merchant_accounts.update_one(
                {"merchant_id": merchant_id, "type": "primary"},
                {"$set": {
                    "sh_account_number": acct_no,
                    "sh_account_id":     acct_id,
                    "sh_account_name":   acct_nm,
                    "provisioned_at":    now,
                }}
            )
            logger.info(f"[ADMIN] SH sync successful for {merchant_id}: {acct_no}")
            return {
                "message": f"Account synced from Safe Haven: {acct_no}",
                "account_number": acct_no,
                "synced": True,
                "source": "safehaven_api",
            }

        return {
            "message": "Account not found in Safe Haven yet. Safe Haven may still be processing. Try again in a minute or enter the account number manually.",
            "account_number": "",
            "synced": False,
            "source": "safehaven_api",
        }
    except Exception as e:
        logger.error(f"[ADMIN] SH sync error for {merchant_id}: {e}")
        raise HTTPException(502, f"Safe Haven sync failed: {e}")


@router.get("/admin/merchants/{merchant_id}/identity-info")
async def admin_get_merchant_identity_info(merchant_id: str, request: Request):
    """
    Return the stored Safe Haven identity ID (sh_identity_id) for a merchant.
    Used by admin panel to auto-fill the provision modal and avoid re-entering it.
    """
    await _get_admin(request)
    kyb = await db.merchant_kyb.find_one(
        {"merchant_id": merchant_id},
        {"_id": 0, "sh_identity_id": 1, "director_vid": 1, "rc_number": 1}
    )
    acct = await db.merchant_accounts.find_one(
        {"merchant_id": merchant_id, "type": "primary", "sh_account_id": {"$nin": ["", None]}},
        {"_id": 0, "sh_account_id": 1}
    )
    # Return sh_identity_id (canonical) falling back to director_vid (from KYB OTP flow)
    identity_id = (
        (kyb or {}).get("sh_identity_id", "").strip()
        or (kyb or {}).get("director_vid", "").strip()
    )
    return {
        "sh_identity_id":   identity_id,
        "rc_number":        (kyb or {}).get("rc_number", ""),
        "existing_acct_id": (acct or {}).get("sh_account_id", ""),
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


# ─── MERCHANT REWARDS ─────────────────────────────────────────────────────────

async def _credit_merchant_cashback_bg(merchant_id: str, amount_naira: float, txn_type: str, description: str):
    """Mirror of consumer _credit_cashback_bg but for the merchants collection."""
    try:
        cfg = await get_rewards_config()
        if not cfg.get("cashback_enabled"):
            return
        rate_key = {
            "AIRTIME": "airtime_cashback_pct", "DATA": "data_cashback_pct",
            "ELECTRICITY": "electricity_cashback_pct", "CABLE_TV": "cable_cashback_pct",
        }.get(txn_type)
        if not rate_key:
            return
        rate = cfg.get(rate_key, 1.0)
        cashback_naira = min(round(amount_naira * rate / 100, 2), cfg.get("max_cashback_per_txn_naira", 500))
        if cashback_naira < 0.01:
            return
        cashback_kobo = int(cashback_naira * 100)
        await db.merchants.update_one(
            {"merchant_id": merchant_id},
            {"$inc": {"cashback_balance": cashback_kobo}}
        )
        await db.cashback_history.insert_one({
            "merchant_id": merchant_id, "amount_kobo": cashback_kobo, "type": txn_type,
            "description": description, "cashback_naira": cashback_naira,
            "created_at": now_utc()
        })
    except Exception as e:
        logger.warning(f"Merchant cashback credit failed: {e}")


@router.get("/v1/merchant/rewards")
async def get_merchant_rewards(request: Request):
    m = await get_current_merchant(request)
    full = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    cashback_kobo = (full or {}).get("cashback_balance", 0)
    referral_kobo = (full or {}).get("referral_balance", 0)
    referral_code = (full or {}).get("referral_code", "")
    # Auto-generate referral code if missing
    if not referral_code:
        referral_code = f"BIZ{secrets.token_hex(4).upper()}"
        await db.merchants.update_one(
            {"merchant_id": m["merchant_id"]},
            {"$set": {"referral_code": referral_code}}
        )
    cfg = await get_rewards_config()
    cashback_hist = await db.cashback_history.find(
        {"merchant_id": m["merchant_id"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(20)
    return {
        "cashback_balance": round(cashback_kobo / 100, 2),
        "referral_balance": round(referral_kobo / 100, 2),
        "referral_code": referral_code,
        "cashback_history": cashback_hist,
        "config": {
            "cashback_enabled": cfg.get("cashback_enabled", True),
            "airtime_cashback_pct": cfg.get("airtime_cashback_pct", 1.5),
            "data_cashback_pct": cfg.get("data_cashback_pct", 1.5),
            "electricity_cashback_pct": cfg.get("electricity_cashback_pct", 1.0),
            "cable_cashback_pct": cfg.get("cable_cashback_pct", 1.0),
        }
    }


@router.post("/v1/merchant/rewards/withdraw-cashback")
async def merchant_withdraw_cashback(request: Request):
    m = await get_current_merchant(request)
    full = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    kobo = (full or {}).get("cashback_balance", 0)
    if kobo < 100:
        raise HTTPException(400, "Minimum withdrawal is ₦1.00")
    naira = round(kobo / 100, 2)
    txn_ref = f"CBW_{secrets.token_hex(8).upper()}"
    await db.merchants.update_one({"merchant_id": m["merchant_id"]}, {"$set": {"cashback_balance": 0}})
    await db.cashback_history.insert_one({
        "merchant_id": m["merchant_id"], "amount_kobo": -kobo, "type": "WITHDRAWAL",
        "description": "Cashback withdrawn", "cashback_naira": -naira,
        "created_at": now_utc()
    })
    await db.merchant_transactions.insert_one({
        "merchant_id": m["merchant_id"], "transaction_id": txn_ref, "type": "CASHBACK_WITHDRAWAL",
        "direction": "CREDIT", "amount": kobo, "status": "completed",
        "description": f"Cashback withdrawal — ₦{naira:,.2f}", "created_at": now_utc()
    })
    return {"message": f"₦{naira:,.2f} applied to your next bill!", "amount": naira}


@router.post("/v1/merchant/rewards/withdraw-referral")
async def merchant_withdraw_referral(request: Request):
    m = await get_current_merchant(request)
    full = await db.merchants.find_one({"merchant_id": m["merchant_id"]})
    kobo = (full or {}).get("referral_balance", 0)
    if kobo < 100:
        raise HTTPException(400, "Minimum withdrawal is ₦1.00")
    naira = round(kobo / 100, 2)
    txn_ref = f"RFW_{secrets.token_hex(8).upper()}"
    await db.merchants.update_one({"merchant_id": m["merchant_id"]}, {"$set": {"referral_balance": 0}})
    await db.merchant_transactions.insert_one({
        "merchant_id": m["merchant_id"], "transaction_id": txn_ref, "type": "REFERRAL_WITHDRAWAL",
        "direction": "CREDIT", "amount": kobo, "status": "completed",
        "description": f"Referral bonus withdrawal — ₦{naira:,.2f}", "created_at": now_utc()
    })
    return {"message": f"₦{naira:,.2f} applied to your account!", "amount": naira}


# ─── MERCHANT ePOS ────────────────────────────────────────────────────────────
# All endpoints under /v1/merchant/epos/* use merchant auth

class MerchantEposActivateReq(BaseModel):
    business_name: str
    business_type: str = "retail"

class MerchantEposPaymentReq(BaseModel):
    amount: float
    note: str = ""


@router.get("/v1/merchant/epos/status")
async def merchant_epos_status(request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    acct = await db.epos_accounts.find_one({"merchant_id": mid}, {"_id": 0})
    if not acct:
        return {"activated": False}
    # today's stats
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    agg = await db.epos_transactions.aggregate([
        {"$match": {"merchant_id": mid, "status": "COMPLETED", "created_at": {"$gte": today}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
    ]).to_list(1)
    today_kobo  = (agg[0]["total"]  if agg else 0)
    today_count = (agg[0]["count"]  if agg else 0)
    return {
        "activated":            True,
        "account":              acct,
        "today_received_naira": round(today_kobo / 100, 2),
        "today_count":          today_count,
        "total_received":       (await db.epos_transactions.aggregate([
            {"$match": {"merchant_id": mid, "status": "COMPLETED"}},
            {"$group": {"_id": None, "t": {"$sum": "$amount_kobo"}}}
        ]).to_list(1) or [{"t": 0}])[0]["t"] / 100,
    }


@router.post("/v1/merchant/epos/activate")
async def merchant_epos_activate(req: MerchantEposActivateReq, request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    biz_name = req.business_name.strip() or m.get("business_name", "My Business")
    await db.epos_accounts.update_one(
        {"merchant_id": mid},
        {"$set": {
            "merchant_id":   mid,
            "business_name": biz_name,
            "business_type": req.business_type,
            "status":        "ACTIVE",
            "activated_at":  now_utc(),
        }},
        upsert=True
    )
    return {"message": "e-POS activated!", "activated": True}


@router.post("/v1/merchant/epos/request-payment")
async def merchant_epos_request_payment(req: MerchantEposPaymentReq, request: Request):
    m = await get_current_merchant(request)
    mid = m["merchant_id"]
    acct = await db.epos_accounts.find_one({"merchant_id": mid})
    if not acct:
        raise HTTPException(400, "Activate e-POS first")
    if req.amount < 1:
        raise HTTPException(400, "Minimum amount is ₦1.00")
    ref        = f"MEPOS-{secrets.token_hex(6).upper()}"
    amount_kobo = int(req.amount * 100)
    # Build QR value: encodes merchant account number + ref for Bompay customer app
    accounts = await db.merchant_accounts.find({"merchant_id": mid}, {"_id": 0}).to_list(5)
    primary  = next((a for a in accounts if a.get("is_primary")), accounts[0] if accounts else {})
    qr_data  = (
        f"bompay://epos/pay?merchant_id={mid}"
        f"&reference={ref}"
        f"&amount={amount_kobo}"
        f"&business_name={acct['business_name'].replace(' ', '+')}"
    )
    await db.epos_transactions.insert_one({
        "merchant_id":   mid,
        "reference":     ref,
        "amount_kobo":   amount_kobo,
        "note":          req.note,
        "status":        "PENDING",
        "created_at":    now_utc(),
        "business_name": acct["business_name"],
    })
    return {
        "reference":    ref,
        "amount":       req.amount,
        "qr_data":      qr_data,
        "merchant_name": acct["business_name"],
        "account_number": primary.get("sh_account_number") or primary.get("account_number"),
        "bank_name":    primary.get("bank_name", "Bompay"),
    }


@router.get("/v1/merchant/epos/check/{reference}")
async def merchant_epos_check(reference: str, request: Request):
    m   = await get_current_merchant(request)
    txn = await db.epos_transactions.find_one(
        {"merchant_id": m["merchant_id"], "reference": reference},
        {"_id": 0, "status": 1, "completed_at": 1, "amount_kobo": 1}
    )
    if not txn:
        raise HTTPException(404, "Transaction not found")
    return txn


@router.post("/v1/merchant/epos/complete/{reference}")
async def merchant_epos_complete(reference: str, request: Request):
    m   = await get_current_merchant(request)
    mid = m["merchant_id"]
    txn = await db.epos_transactions.find_one({"merchant_id": mid, "reference": reference})
    if not txn:
        raise HTTPException(404, "Transaction not found")
    if txn.get("status") == "COMPLETED":
        return {"message": "Already completed"}
    amount_kobo = txn.get("amount_kobo", 0)
    await db.epos_transactions.update_one(
        {"merchant_id": mid, "reference": reference},
        {"$set": {"status": "COMPLETED", "channel": "MANUAL", "completed_at": now_utc()}}
    )
    # Credit merchant wallet (via merchant_transactions for record-keeping)
    await db.merchant_transactions.insert_one({
        "merchant_id":   mid,
        "transaction_id": f"MEPOS_{reference}",
        "type":          "EPOS_RECEIPT",
        "direction":     "CREDIT",
        "amount":        amount_kobo,
        "status":        "completed",
        "description":   f"ePOS cash/manual — {txn.get('note', 'Payment')}",
        "created_at":    now_utc(),
    })
    return {"message": "Marked as completed", "amount": round(amount_kobo / 100, 2)}


@router.get("/v1/merchant/epos/transactions")
async def merchant_epos_transactions(request: Request, page: int = 1, limit: int = 20):
    m   = await get_current_merchant(request)
    mid = m["merchant_id"]
    skip = (page - 1) * limit
    txns = await db.epos_transactions.find(
        {"merchant_id": mid}, {"_id": 0}
    ).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.epos_transactions.count_documents({"merchant_id": mid})
    return {"transactions": txns, "total": total, "pages": -(-total // limit)}


@router.get("/v1/merchant/epos/reports")
async def merchant_epos_reports(request: Request):
    m   = await get_current_merchant(request)
    mid = m["merchant_id"]
    now_dt = datetime.now(timezone.utc)

    # Daily (last 7 days)
    daily = []
    for i in range(6, -1, -1):
        day   = now_dt - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        end   = day.replace(hour=23, minute=59, second=59, microsecond=999999).isoformat()
        agg   = await db.epos_transactions.aggregate([
            {"$match": {"merchant_id": mid, "status": "COMPLETED",
                        "created_at": {"$gte": start, "$lte": end}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
        ]).to_list(1)
        daily.append({
            "label":  day.strftime("%a"),
            "amount": round((agg[0]["total"] if agg else 0) / 100, 2),
            "count":  agg[0]["count"] if agg else 0,
        })

    # Weekly (last 4 weeks)
    weekly = []
    for i in range(3, -1, -1):
        week_end   = now_dt - timedelta(weeks=i)
        week_start = week_end - timedelta(weeks=1)
        agg = await db.epos_transactions.aggregate([
            {"$match": {"merchant_id": mid, "status": "COMPLETED",
                        "created_at": {"$gte": week_start.isoformat(), "$lte": week_end.isoformat()}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}, "count": {"$sum": 1}}}
        ]).to_list(1)
        weekly.append({
            "label":  f"Wk {4 - i}",
            "amount": round((agg[0]["total"] if agg else 0) / 100, 2),
            "count":  agg[0]["count"] if agg else 0,
        })

    return {"daily": daily, "weekly": weekly}
