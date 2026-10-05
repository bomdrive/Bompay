"""
BOMPAY Virtual Cards
  - Strowallet  → Naira Verve & Mastercard
  - Ziiropay   → USD Reusable (NFC) & One-Time (Lite)

Webhook URLs (set these in provider dashboards):
  Strowallet Naira: {BACKEND_URL}/api/webhooks/strowallet-cards
  Ziiropay USD:     {BACKEND_URL}/api/webhooks/ziiropay-cards

Funding always goes through Safe Haven virtual account balance.
"""

import os, uuid, logging
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Request, HTTPException, Response
from pydantic import BaseModel

from database import db
from core import (
    get_current_user, verify_transaction_pin,
    get_sh_subaccount_balance, sh_name_enquiry, sh_internal_transfer,
    send_event_notification, send_event_sms,
    get_service_bucket_account,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# ── provider base URLs ─────────────────────────────────────────────────────────
STROW_BASE   = "https://strowallet.com/api"
ZIIRO_BASE   = "https://ziiropay.com/api/bitvcard"

# ── env defaults (overridable from DB admin config) ────────────────────────────
def _env_strow_pub()  -> str: return os.environ.get("STROWALLET_PUBLIC_KEY", "")
def _env_strow_sec()  -> str: return os.environ.get("STROWALLET_SECRET_KEY", "")
def _env_ziiro_pub()  -> str: return os.environ.get("ZIIROPAY_PUBLIC_KEY", "")


async def _card_cfg() -> dict:
    doc = await db.card_config.find_one({"_id": "global"})
    return doc or {}


async def strow_pub() -> str:
    cfg = await _card_cfg()
    return cfg.get("strowallet_public_key") or _env_strow_pub()


async def ziiro_pub() -> str:
    cfg = await _card_cfg()
    return cfg.get("ziiropay_public_key") or _env_ziiro_pub()


async def _exchange_rate_ngn_usd() -> float:
    """Fetch live NGN→USD rate from Strowallet."""
    try:
        pub = await strow_pub()
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{STROW_BASE}/exchange-rate/NGN/USD/",
                            params={"public_key": pub})
            data = r.json()
            # Response: {"rate": 1650.0} or similar
            rate = data.get("rate") or data.get("exchange_rate") or data.get("data", {}).get("rate")
            if rate:
                return float(rate)
    except Exception as e:
        logger.warning("Exchange rate fetch failed: %s", e)
    return 1650.0  # safe fallback


# ── helper: call Strowallet ─────────────────────────────────────────────────────
async def _strow(method: str, path: str, params: dict) -> dict:
    pub = await strow_pub()
    params["public_key"] = pub
    url = f"{STROW_BASE}/{path}"
    async with httpx.AsyncClient(timeout=30) as c:
        if method == "GET":
            r = await c.get(url, params=params)
        elif method == "POST":
            r = await c.post(url, params=params)
        elif method == "PUT":
            r = await c.put(url, params=params)
        else:
            raise ValueError(f"Unknown method {method}")
    logger.info("Strowallet %s /%s → HTTP %s | body: %s", method, path, r.status_code, r.text[:400])
    if r.status_code >= 500:
        raise HTTPException(502, f"Card provider error (HTTP {r.status_code}): {r.text[:200]}")
    data = r.json()
    if not data.get("success", True) and data.get("message"):
        raise HTTPException(400, f"Card provider: {data['message']} (code: {r.status_code})")
    return data


# ── helper: call Ziiropay ───────────────────────────────────────────────────────
async def _ziiro(method: str, path: str, params: dict) -> dict:
    pub = await ziiro_pub()
    params["public_key"] = pub
    url = f"{ZIIRO_BASE}/{path}"
    async with httpx.AsyncClient(timeout=30) as c:
        if method == "GET":
            r = await c.get(url, params=params)
        elif method == "POST":
            r = await c.post(url, params=params)
    logger.info("Ziiropay %s /%s → HTTP %s | body: %s", method, path, r.status_code, r.text[:800])
    if r.status_code >= 500:
        raise HTTPException(502, f"Card provider error (HTTP {r.status_code}): {r.text[:200]}")
    data = r.json()
    if not data.get("success", True) and data.get("message"):
        import json as _json
        raise HTTPException(400, _json.dumps({
            "provider": "ziiropay",
            "http_status": r.status_code,
            "message": data.get("message"),
            "errors": data.get("errors"),
        }))
    return data


# ── helper: deduct from Safe Haven (funding source) ────────────────────────────
async def _sh_deduct(user: dict, amount_ngn: float, narration: str):
    """Deduct from user Safe Haven virtual account."""
    wallet = await db.wallets.find_one({"user_id": str(user["_id"])})
    if not wallet or not wallet.get("sh_account_id"):
        raise HTTPException(400, "No linked Safe Haven account")
    balance = await get_sh_subaccount_balance(wallet["sh_account_id"])
    if balance < amount_ngn:
        raise HTTPException(400, f"Insufficient balance. Available: ₦{balance:,.2f}")
    # Get CARD service bucket account number (set in Admin → Service Accounts → Card)
    bucket_acct_num = await get_service_bucket_account("CARD")
    if not bucket_acct_num:
        raise HTTPException(400, "CARD service account not configured. Go to Admin → Service Accounts → Card to set it up.")
    name_enquiry_ref = ""
    try:
        name_enquiry_ref = await sh_name_enquiry(bucket_acct_num, "090286")
    except Exception:
        pass
    await sh_internal_transfer(
        from_account_number=wallet.get("sh_account_number", ""),
        to_account_number=bucket_acct_num,
        amount_ngn=amount_ngn,
        narration=narration,
        ref=f"CARD_{uuid.uuid4().hex[:12]}",
        name_enquiry_ref=name_enquiry_ref,
    )
    # Mirror shadow wallet
    await db.wallets.update_one(
        {"user_id": str(user["_id"])},
        {"$inc": {"available_balance": -int(amount_ngn * 100), "ledger_balance": -int(amount_ngn * 100)}}
    )


async def _sh_refund_to_user(user: dict, amount_ngn: float, narration: str):
    """Refund from CARD service bucket back to user — used when provider fails after debit."""
    wallet = await db.wallets.find_one({"user_id": str(user["_id"])})
    if not wallet:
        return
    bucket_acct_num = await get_service_bucket_account("CARD")
    if not bucket_acct_num:
        return
    user_acct_num = wallet.get("sh_account_number", "")
    name_enquiry_ref = ""
    try:
        name_enquiry_ref = await sh_name_enquiry(user_acct_num, "090286")
    except Exception:
        pass
    try:
        await sh_internal_transfer(
            from_account_number=bucket_acct_num,
            to_account_number=user_acct_num,
            amount_ngn=amount_ngn,
            narration=f"REFUND: {narration}",
            ref=f"REFUND_{uuid.uuid4().hex[:12]}",
            name_enquiry_ref=name_enquiry_ref,
        )
        await db.wallets.update_one(
            {"user_id": str(user["_id"])},
            {"$inc": {"available_balance": int(amount_ngn * 100), "ledger_balance": int(amount_ngn * 100)}}
        )
    except Exception:
        pass  # Log and handle manually via admin


# ── Pydantic schemas ───────────────────────────────────────────────────────────
class CreateNairaCardReq(BaseModel):
    brand: str          # "Verve" or "Mastercard"
    initial_load: float = 0.0
    transaction_pin: str
    address: Optional[str] = "Lagos, Nigeria"
    city: Optional[str] = "Lagos"
    state: Optional[str] = "lg"
    # Identity override — for users who completed KYC before these fields were persisted
    nin: Optional[str] = None
    date_of_birth: Optional[str] = None   # YYYY-MM-DD

class CreateUSDCardReq(BaseModel):
    card_type: str      # "reusable" or "onetime"
    initial_load_usd: float = 3.0
    transaction_pin: str
    # Identity override — for users who completed KYC before these fields were persisted
    nin: Optional[str] = None
    bvn: Optional[str] = None
    date_of_birth: Optional[str] = None   # YYYY-MM-DD
    # Ziiropay KYC fields — required for reusable card customer creation
    occupation: Optional[str] = "Employee"
    employment_status: Optional[str] = "employed"
    account_purpose: Optional[str] = "personal"
    annual_salary: Optional[str] = "1200000"
    expected_monthly_volume: Optional[str] = "100000"
    place_of_birth: Optional[str] = "Lagos"

class FundCardReq(BaseModel):
    amount: float
    transaction_pin: str

class CardPinReq(BaseModel):
    new_pin: str
    transaction_pin: str


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  USER ENDPOINTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@router.get("/cards")
async def list_cards(request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    cards = await db.virtual_cards.find(
        {"user_id": uid, "status": {"$ne": "TERMINATED"}},
        {"_id": 0}
    ).to_list(20)
    return {"cards": cards}


@router.get("/cards/identity-status")
async def get_identity_status(request: Request):
    """Returns what identity data is stored — frontend uses this to decide if it must collect NIN/BVN."""
    user = await get_current_user(request)
    id_type   = user.get("kyc_identity_type", "")
    id_number = user.get("kyc_identity_number", "")
    has_nin = bool(user.get("nin") or (id_number and id_type == "NIN"))
    has_bvn = bool(user.get("bvn") or (id_number and id_type == "BVN"))
    has_dob = bool(user.get("date_of_birth"))
    return {
        "has_nin": has_nin,
        "has_bvn": has_bvn,
        "has_dob": has_dob,
        "has_identity": has_nin or has_bvn,
        "identity_type": "NIN" if has_nin else ("BVN" if has_bvn else None),
    }


@router.get("/cards/config/public")
async def get_card_config_public(request: Request):
    """Return non-sensitive card fee config for display in the app (no admin required)."""
    await get_current_user(request)  # must be logged in
    cfg = await _card_cfg()
    return {
        "naira_creation_fee":  cfg.get("naira_creation_fee", 0.0),
        "naira_fund_fee":      cfg.get("naira_fund_fee", 0.0),
        "naira_spend_fee_pct": cfg.get("naira_spend_fee_pct", 0.0),
        "usd_creation_fee_usd": cfg.get("usd_creation_fee_usd", 2.0),
        "usd_initial_load_usd": cfg.get("usd_initial_load_usd", 3.0),
        "usd_fund_fee_usd":    cfg.get("usd_fund_fee_usd", 0.0),
        "usd_spend_fee_pct":   cfg.get("usd_spend_fee_pct", 0.0),
    }


@router.post("/cards/naira")
async def create_naira_card(req: CreateNairaCardReq, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    await verify_transaction_pin(uid, req.transaction_pin)

    brand = req.brand.strip().title()  # "Verve" or "Mastercard"
    if brand not in ("Verve", "Mastercard"):
        raise HTTPException(400, "Brand must be Verve or Mastercard")

    # Enforce one active card per brand per user
    existing = await db.virtual_cards.find_one({
        "user_id": uid, "currency": "NGN",
        "brand": brand.upper(),
        "status": {"$in": ["active", "processing"]}
    })
    if existing:
        raise HTTPException(400, f"You already have an active {brand} Naira card")

    # Config / fees
    cfg = await _card_cfg()
    creation_fee = cfg.get("naira_creation_fee", 0.0)
    total_ngn = creation_fee + req.initial_load

    # Pull KYC identity data — request body overrides (for pre-fix users), then stored fields
    id_type   = user.get("kyc_identity_type", "")
    id_number = user.get("kyc_identity_number", "")
    nin = req.nin or user.get("nin") or (id_number if id_type == "NIN" else "")
    dob = req.date_of_birth or user.get("date_of_birth") or "1990-01-01"
    _raw = user.get("phone", "").strip().lstrip("+").lstrip("0")
    if not _raw.startswith("234"):
        _raw = "234" + _raw
    phone = _raw   # 2348034010891 — for Strowallet
    first = (user.get("first_name") or user.get("fullname", "User").split()[0])
    last  = (user.get("last_name")  or (user.get("fullname", "User User").split() + [""])[1])

    if not nin:
        if user.get("bvn") or (id_type == "BVN" and not req.nin):
            raise HTTPException(400, "Naira card creation requires NIN. Your account was set up with BVN. Please complete KYC with your NIN to get a Naira virtual card.")
        raise HTTPException(400, "NIN is required for Naira card. Please provide your NIN to continue.")

    # Persist identity fields for future use if they were supplied in this request
    if req.nin and not user.get("nin"):
        update: dict = {"nin": req.nin}
        if req.date_of_birth and not user.get("date_of_birth"):
            update["date_of_birth"] = req.date_of_birth
        from bson import ObjectId as _OID
        await db.users.update_one({"_id": _OID(uid)}, {"$set": update})

    # Step 1 – Get or create Strowallet customer
    sw_cust_id = None
    cust_doc = await db.card_customers.find_one({"user_id": uid, "provider": "strowallet"})
    if cust_doc:
        sw_cust_id = cust_doc["provider_customer_id"]
    else:
        resp = await _strow("POST", "naira_carduser", {
            "firstname": first, "lastname": last,
            "email": user["email"],
            "phone": phone,
            "nin": nin,
            "dob": dob.replace("-", "/"),
            "name": f"bompay_{uid[:10]}",
            "line1": req.address,
            "city": req.city,
            "state": req.state,
            "provider": "black",
        })
        sw_cust_id = (resp.get("data") or {}).get("customer_id")
        if not sw_cust_id:
            raise HTTPException(502, "Failed to create card profile with provider")
        await db.card_customers.insert_one({
            "user_id": uid, "provider": "strowallet",
            "provider_customer_id": sw_cust_id,
            "created_at": datetime.now(timezone.utc),
        })

    # Step 2 – Create card FIRST (before any debit — avoid charge without card)
    resp = await _strow("POST", "naira_createcard", {
        "customerId": sw_cust_id,
        "type": "virtual",
        "brand": brand,
        "provider": "black",
    })
    card_data = resp.get("data") or {}
    card_id   = card_data.get("card_id") or card_data.get("id")
    if not card_id:
        raise HTTPException(502, "Card creation failed with provider. You have NOT been charged.")

    # Step 3 – Deduct ONLY after provider confirms card created
    if total_ngn > 0:
        try:
            await _sh_deduct(user, total_ngn, f"BOMPAY {brand} Card creation fee")
        except Exception as debit_err:
            # Card was issued but debit failed — flag for admin, still give card
            await db.virtual_cards.insert_one({
                **{
                    "card_id": card_id, "user_id": uid, "provider": "strowallet",
                    "card_type": f"naira_{brand.lower()}", "currency": "NGN",
                    "brand": brand.upper(),
                    "masked_pan": card_data.get("maskedPan", ""),
                    "last4": (card_data.get("maskedPan") or "")[-4:] or "****",
                    "expiry_month": card_data.get("expiryMonth", ""),
                    "expiry_year": card_data.get("expiryYear", ""),
                    "status": card_data.get("status", "processing"),
                    "balance": 0.0,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                "debit_failed": True, "debit_error": str(debit_err),
            })
            raise HTTPException(400, f"Card was created but debit failed: {debit_err}. Contact support.")

    doc = {
        "card_id": card_id,
        "user_id": uid,
        "provider": "strowallet",
        "card_type": f"naira_{brand.lower()}",
        "currency": "NGN",
        "brand": brand.upper(),
        "masked_pan": card_data.get("maskedPan", ""),
        "last4": (card_data.get("maskedPan") or "")[-4:] or "****",
        "expiry_month": card_data.get("expiryMonth", ""),
        "expiry_year": card_data.get("expiryYear", ""),
        "status": card_data.get("status", "processing"),
        "balance": 0.0,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.virtual_cards.insert_one(doc)
    doc.pop("_id", None)
    return {"success": True, "card": doc}


@router.post("/cards/usd")
async def create_usd_card(req: CreateUSDCardReq, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    await verify_transaction_pin(uid, req.transaction_pin)

    if req.card_type not in ("reusable", "onetime"):
        raise HTTPException(400, "card_type must be reusable or onetime")

    cfg = await _card_cfg()
    # Use USD-denominated config fields (fall back to legacy NGN field for existing deployments)
    creation_fee_usd = cfg.get("usd_creation_fee_usd", 2.0)
    initial_load_usd = cfg.get("usd_initial_load_usd", 3.0)
    rate = await _exchange_rate_ngn_usd()
    total_usd = creation_fee_usd + initial_load_usd
    total_ngn = total_usd * rate

    # Pull KYC identity data — request body overrides (for pre-fix users), then stored fields
    stored_id_type   = user.get("kyc_identity_type", "")
    stored_id_number = user.get("kyc_identity_number", "")
    nin = req.nin or user.get("nin") or (stored_id_number if stored_id_type == "NIN" else "")
    bvn = req.bvn or user.get("bvn") or (stored_id_number if stored_id_type == "BVN" else "")
    dob = req.date_of_birth or user.get("date_of_birth") or "1990-01-01"
    _raw = user.get("phone", "").strip().lstrip("+").lstrip("0")
    if not _raw.startswith("234"):
        _raw = "234" + _raw
    phone       = _raw          # full intl: 2348034010891 (Strowallet)
    phone_local = _raw[3:]      # local 10-digit: 8034010891 (Ziiropay — dial_code sent separately)
    first = (user.get("first_name") or user.get("fullname", "User").split()[0])
    last  = (user.get("last_name")  or (user.get("fullname", "User User").split() + [""])[1])
    name_on_card = f"{first} {last}".upper()
    id_number = nin or bvn
    id_type   = "nin" if nin else "bvn"

    if not id_number:
        raise HTTPException(400, "NIN or BVN is required for USD card. Please provide your NIN or BVN to continue.")

    # Persist identity fields for future use if they were supplied in this request
    if (req.nin or req.bvn) and not user.get("nin") and not user.get("bvn"):
        update: dict = {}
        if req.nin:
            update["nin"] = req.nin
        if req.bvn:
            update["bvn"] = req.bvn
        if req.date_of_birth and not user.get("date_of_birth"):
            update["date_of_birth"] = req.date_of_birth
        if update:
            from bson import ObjectId as _OID
            await db.users.update_one({"_id": _OID(uid)}, {"$set": update})

    # ── Provider call FIRST (no debit yet) ──────────────────────────────────
    if req.card_type == "onetime":
        # Lite card – no KYC customer needed
        resp = await _ziiro("POST", "create_litecard", {
            "amount": str(initial_load_usd),
            "brand": "VISA",
            "name_on_card": name_on_card,
            "id_number": id_number,
            "id_type": id_type,
        })
        card_data = resp.get("response") or {}
        card_id   = card_data.get("card_id")
    else:
        # Reusable – need KYC customer first
        ziiro_cust_id = None
        cust_doc = await db.card_customers.find_one({"user_id": uid, "provider": "ziiropay"})
        if cust_doc and cust_doc.get("kyc_status") == "approved":
            ziiro_cust_id = cust_doc["provider_customer_id"]
        elif cust_doc and cust_doc.get("kyc_status") == "pending":
            raise HTTPException(400, "Your USD card KYC is pending review (usually 24h). Try again soon.")
        else:
            PLACEHOLDER_IMG = (
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
            )
            resp_kyc = await _ziiro("POST", "cardkyc", {
                "first_name": first, "last_name": last,
                "id_number": id_number, "id_type": id_type,
                "email": user["email"],
                "phone_number": phone_local,
                "dial_code": "+234",
                "date_of_birth": dob,
                "id_front_image": PLACEHOLDER_IMG,
                "line1": "Lagos Nigeria",
                "city": "Lagos",
                "state": "Lagos",
                "postal_code": "100001",
                "country": "NGA",
                # Required KYC compliance fields
                "occupation": req.occupation or "Employee",
                "employment_status": req.employment_status or "employed",
                "account_purpose": req.account_purpose or "personal",
                "annual_salary": req.annual_salary or "1200000",
                "expected_monthly_volume": req.expected_monthly_volume or "100000",
                "place_of_birth": req.place_of_birth or "Lagos",
            })
            kyc_data = resp_kyc.get("data") or {}
            ziiro_cust_id = kyc_data.get("customer_id")
            await db.card_customers.update_one(
                {"user_id": uid, "provider": "ziiropay"},
                {"$set": {
                    "user_id": uid, "provider": "ziiropay",
                    "provider_customer_id": ziiro_cust_id,
                    "kyc_status": kyc_data.get("status", "pending"),
                    "updated_at": datetime.now(timezone.utc),
                }},
                upsert=True
            )
            if kyc_data.get("status") != "approved":
                # KYC pending — no debit, no card yet
                raise HTTPException(202, "KYC submitted successfully! Review takes up to 24 hours. "
                                         "Come back to create your card once approved.")

        resp = await _ziiro("POST", "create-nfc-card", {
            "name": name_on_card,
            "customer_id": ziiro_cust_id,
            "amount": str(initial_load_usd),
        })
        card_data = resp.get("response") or {}
        card_id   = card_data.get("card_id")

    if not card_id:
        raise HTTPException(502, "Card creation failed with provider. You have NOT been charged.")

    # ── Deduct ONLY after provider confirms card created ─────────────────────
    await _sh_deduct(user, total_ngn, f"BOMPAY USD {req.card_type.title()} Card creation")

    doc = {
        "card_id": card_id,
        "user_id": uid,
        "provider": "ziiropay",
        "card_type": f"usd_{req.card_type}",
        "currency": "USD",
        "brand": (card_data.get("card_brand") or "VISA").upper(),
        "masked_pan": "",
        "last4": "****",
        "expiry": "",
        "status": card_data.get("card_status", "processing"),
        "balance": initial_load_usd,
        "name_on_card": name_on_card,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.virtual_cards.insert_one(doc)
    doc.pop("_id", None)
    return {"success": True, "card": doc}


@router.get("/cards/{card_id}/details")
async def get_card_details(card_id: str, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")

    try:
        if rec["provider"] == "strowallet":
            data = await _strow("GET", "naira_viewcard", {"card_id": card_id})
            details = data.get("data") or data
        else:
            data = await _ziiro("GET", "fetch-nfccard-detail", {"card_id": card_id})
            details = (data.get("response") or {}).get("card_detail") or {}
        # patch last4 if available now
        if details.get("last4") and rec.get("last4") == "****":
            await db.virtual_cards.update_one(
                {"card_id": card_id},
                {"$set": {"last4": details["last4"], "masked_pan": details.get("maskedPan") or details.get("card_number", "")}}
            )
        return {"success": True, "details": details}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))


@router.get("/cards/{card_id}/history")
async def get_card_history(card_id: str, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")

    if rec["provider"] == "strowallet":
        data = await _strow("GET", "naira_cardhistory", {"card_id": card_id})
        txns = data.get("data") or []
    else:
        data = await _ziiro("GET", "nfc-card-transactions", {"card_id": card_id})
        txns = (data.get("response") or {}).get("card_transactions") or []
    return {"success": True, "transactions": txns}


@router.post("/cards/{card_id}/fund")
async def fund_card(card_id: str, req: FundCardReq, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    await verify_transaction_pin(uid, req.transaction_pin)
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")
    if rec["status"] not in ("active",):
        raise HTTPException(400, "Card is not active")

    cfg = await _card_cfg()
    if rec["currency"] == "NGN":
        amount_ngn = req.amount
        fund_fee   = cfg.get("naira_fund_fee", 0.0)
        total_ngn  = amount_ngn + fund_fee
        await _sh_deduct(user, total_ngn, f"Naira card funding ****{rec.get('last4','')}")
        await _strow("POST", "naira_fundcard", {"card_id": card_id, "amount": str(int(amount_ngn * 100))})
    else:
        # USD card – convert NGN to USD
        rate = await _exchange_rate_ngn_usd()
        amount_usd = req.amount
        amount_ngn = amount_usd * rate
        fund_fee_usd = cfg.get("usd_fund_fee_usd", 0.0)
        fund_fee_ngn = fund_fee_usd * rate
        total_ngn  = amount_ngn + fund_fee_ngn
        await _sh_deduct(user, total_ngn, f"USD card funding ****{rec.get('last4','')}")
        await _ziiro("POST", "fund-withdraw-nfccard", {
            "card_id": card_id, "amount": str(amount_usd), "type": "fund"
        })
        await db.virtual_cards.update_one(
            {"card_id": card_id},
            {"$inc": {"balance": amount_usd}}
        )
    return {"success": True, "message": "Card funded successfully"}


@router.post("/cards/{card_id}/withdraw")
async def withdraw_card(card_id: str, req: FundCardReq, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    await verify_transaction_pin(uid, req.transaction_pin)
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")
    if rec["currency"] != "USD":
        raise HTTPException(400, "Withdrawal only available for USD cards")

    await _ziiro("POST", "fund-withdraw-nfccard", {
        "card_id": card_id, "amount": str(req.amount), "type": "withdraw"
    })
    await db.virtual_cards.update_one(
        {"card_id": card_id},
        {"$inc": {"balance": -req.amount}}
    )
    return {"success": True, "message": "Withdrawal initiated"}


@router.post("/cards/{card_id}/block")
async def block_card(card_id: str, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")
    await _toggle_card_status(rec, "blocked")
    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "inactive"}})
    return {"success": True, "message": "Card blocked"}


@router.post("/cards/{card_id}/unblock")
async def unblock_card(card_id: str, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")
    await _toggle_card_status(rec, "active")
    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "active"}})
    return {"success": True, "message": "Card unblocked"}


async def _toggle_card_status(rec: dict, target: str):
    if rec["provider"] == "strowallet":
        status = "active" if target == "active" else "inactive"
        await _strow("PUT", "naira_ChangeStatus", {"card_id": rec["card_id"], "status": status})
    else:
        status = "active" if target == "active" else "frozen"
        await _ziiro("POST", "nfc-cards/status", {"card_id": rec["card_id"], "status": status})


@router.post("/cards/{card_id}/terminate")
async def terminate_card(card_id: str, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")

    if rec["provider"] == "strowallet":
        # Strowallet Naira: use status=terminated or inactive – check provider support
        await _strow("PUT", "naira_ChangeStatus", {"card_id": card_id, "status": "inactive"})
    else:
        await _ziiro("POST", "cards/terminate", {"card_id": card_id})

    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "TERMINATED"}})
    return {"success": True, "message": "Card terminated"}


@router.post("/cards/{card_id}/reset-pin")
async def reset_card_pin(card_id: str, req: CardPinReq, request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    await verify_transaction_pin(uid, req.transaction_pin)
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")
    if rec["provider"] != "strowallet":
        raise HTTPException(400, "PIN reset is only available for Naira cards")
    await _strow("POST", "naira_resetpin", {
        "card_id": card_id, "new_pin": req.new_pin
    })
    return {"success": True, "message": "Card PIN reset successfully"}


@router.get("/cards/exchange-rate")
async def get_exchange_rate(request: Request):
    await get_current_user(request)
    rate = await _exchange_rate_ngn_usd()
    return {"rate": rate, "base": "USD", "quote": "NGN"}


@router.get("/cards/{card_id}/balance")
async def refresh_card_balance(card_id: str, request: Request):
    """Fetch live balance from provider and update stored record."""
    user = await get_current_user(request)
    uid  = str(user["_id"])
    rec  = await db.virtual_cards.find_one({"card_id": card_id, "user_id": uid})
    if not rec:
        raise HTTPException(404, "Card not found")

    balance = float(rec.get("balance", 0.0))
    try:
        if rec["provider"] == "strowallet":
            data = await _strow("GET", "naira_viewcard", {"card_id": card_id})
            live = (data.get("data") or {}).get("balance")
            if live is not None:
                balance = float(live)
        else:
            # Ziiropay — try nfc-card-balance endpoint
            data = await _ziiro("GET", "nfc-card-balance", {"card_id": card_id})
            live = (data.get("response") or {}).get("balance")
            if live is not None:
                balance = float(live)
    except Exception as e:
        logger.warning("Balance refresh failed card=%s: %s", card_id, e)

    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"balance": balance}})
    return {"card_id": card_id, "balance": balance, "currency": rec["currency"]}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ADMIN ENDPOINTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _require_admin(request: Request):
    user = await get_current_user(request)
    if user.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin access required")
    return user


@router.get("/admin/cards")
async def admin_list_cards(request: Request, currency: Optional[str] = None, page: int = 1):
    await _require_admin(request)
    q = {}
    if currency:
        q["currency"] = currency.upper()
    skip = (page - 1) * 50
    cards = await db.virtual_cards.find(q, {"_id": 0}).sort("created_at", -1).skip(skip).limit(50).to_list(50)
    # Enrich with user info
    for card in cards:
        u = await db.users.find_one({"_id": __import__("bson").ObjectId(card["user_id"])}, {"email": 1, "fullname": 1, "phone": 1})
        if u:
            card["user_email"] = u.get("email", "")
            card["user_name"]  = u.get("fullname", "")
            card["user_phone"] = u.get("phone", "")
    total = await db.virtual_cards.count_documents(q)
    return {"cards": cards, "total": total, "page": page}


@router.post("/admin/cards/{card_id}/block")
async def admin_block_card(card_id: str, request: Request):
    await _require_admin(request)
    rec = await db.virtual_cards.find_one({"card_id": card_id})
    if not rec:
        raise HTTPException(404, "Card not found")
    await _toggle_card_status(rec, "blocked")
    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "inactive", "admin_blocked": True}})
    return {"success": True}


@router.post("/admin/cards/{card_id}/unblock")
async def admin_unblock_card(card_id: str, request: Request):
    await _require_admin(request)
    rec = await db.virtual_cards.find_one({"card_id": card_id})
    if not rec:
        raise HTTPException(404, "Card not found")
    await _toggle_card_status(rec, "active")
    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "active", "admin_blocked": False}})
    return {"success": True}


@router.post("/admin/cards/{card_id}/terminate")
async def admin_terminate_card(card_id: str, request: Request):
    await _require_admin(request)
    rec = await db.virtual_cards.find_one({"card_id": card_id})
    if not rec:
        raise HTTPException(404, "Card not found")
    if rec["provider"] == "strowallet":
        await _strow("PUT", "naira_ChangeStatus", {"card_id": card_id, "status": "inactive"})
    else:
        await _ziiro("POST", "cards/terminate", {"card_id": card_id})
    await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "TERMINATED"}})
    return {"success": True}


@router.get("/admin/cards/config")
async def admin_get_card_config(request: Request):
    await _require_admin(request)
    doc = await db.card_config.find_one({"_id": "global"}) or {}
    doc.pop("_id", None)
    # Mask secret keys
    if doc.get("strowallet_secret_key"):
        sk = doc["strowallet_secret_key"]
        doc["strowallet_secret_key"] = sk[:8] + "..." + sk[-4:]
    # Fill defaults for new USD fields
    doc.setdefault("usd_creation_fee_usd", 2.0)
    doc.setdefault("usd_initial_load_usd", 3.0)
    doc.setdefault("usd_fund_fee_usd", 0.0)
    doc.setdefault("usd_spend_fee_pct", 0.0)
    doc.setdefault("naira_creation_fee", 0.0)
    doc.setdefault("naira_fund_fee", 0.0)
    doc.setdefault("naira_spend_fee_pct", 0.0)
    return doc


@router.put("/admin/cards/config")
async def admin_update_card_config(request: Request):
    await _require_admin(request)
    body = await request.json()
    allowed = {
        "strowallet_public_key", "strowallet_secret_key",
        "ziiropay_public_key",
        "naira_creation_fee", "naira_fund_fee", "naira_spend_fee_pct",
        "usd_creation_fee_usd", "usd_initial_load_usd",
        "usd_fund_fee_usd", "usd_spend_fee_pct",
        # legacy fields kept for backward compat
        "usd_creation_fee_ngn", "usd_fund_fee_ngn",
    }
    update = {k: v for k, v in body.items() if k in allowed}
    if not update:
        raise HTTPException(400, "No valid fields provided")
    await db.card_config.update_one(
        {"_id": "global"},
        {"$set": update},
        upsert=True
    )
    return {"success": True}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WEBHOOK HANDLERS
#  Strowallet (Naira):  POST /api/webhooks/strowallet-cards
#  Ziiropay   (USD):    POST /api/webhooks/ziiropay-cards
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _notify_card_user(card_id: str, title: str, body_text: str, meta: dict):
    """Look up the card owner and send push + SMS notification."""
    try:
        rec = await db.virtual_cards.find_one({"card_id": card_id})
        if not rec:
            return
        uid = rec["user_id"]
        await send_event_notification(uid, "CARD_EVENT", {"title": title, "body": body_text, **meta})
        await send_event_sms(uid, "CARD_EVENT", {"title": title, "body": body_text, **meta})
    except Exception as e:
        logger.warning("Card notification failed card=%s: %s", card_id, e)


async def _record_card_txn(card_id: str, event: str, amount: float, currency: str,
                           merchant: str, reference: str, status: str):
    """Persist a card transaction record to MongoDB."""
    await db.card_transactions.insert_one({
        "card_id": card_id,
        "event": event,
        "amount": amount,
        "currency": currency,
        "merchant": merchant,
        "reference": reference,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


# ── Strowallet Naira Card Webhook ─────────────────────────────────────────────
@router.post("/webhooks/strowallet-cards")
async def strowallet_card_webhook(request: Request):
    """
    Handles ALL Strowallet Naira card webhook events.
    Must always return HTTP 200.

    Special cases (require specific JSON response):
      - authorization.request  → {"APPROVE": "YES"} or {"APPROVE": "NO", "reason": "..."}
      - card.balance           → {"balance": <current_balance>}
    """
    try:
        payload = await request.json()
    except Exception:
        return Response(content='{"status":"ok"}', media_type="application/json")

    logger.info("[STROW WEBHOOK] %s", payload)

    # ── 1. Balance check request ─────────────────────────────────────────────
    if "card.balance" in payload:
        card_id = payload.get("card_Id") or payload.get("card_id", "")
        try:
            card = await _strow("GET", "naira_viewcard", {"card_id": card_id})
            bal = (card.get("data") or {}).get("balance", 0)
        except Exception:
            bal = 0
        return Response(content=f'{{"balance": {float(bal)}}}', media_type="application/json")

    # ── 2. Authorization request (APPROVE / DECLINE) ─────────────────────────
    if "authorization.request" in payload:
        card_id   = payload.get("card_Id", "")
        amount    = float(payload.get("merchantAmount", 0))
        merchant  = (payload.get("merchant") or {}).get("name", "Unknown")
        currency  = payload.get("currency", "NGN")

        rec = await db.virtual_cards.find_one({"card_id": card_id})
        # Decline if card is blocked/terminated/not found
        if not rec or rec.get("status") not in ("active",):
            reason = "Card is not active" if rec else "Card not found"
            logger.info("[STROW AUTH] DECLINED card=%s reason=%s", card_id, reason)
            return Response(
                content=f'{{"APPROVE":"NO","reason":"{reason}"}}',
                media_type="application/json"
            )

        # All good — approve
        logger.info("[STROW AUTH] APPROVED card=%s amount=%.2f%s merchant=%s", card_id, amount, currency, merchant)
        # Fire-and-forget notification
        await _notify_card_user(
            card_id, "Card Authorization",
            f"₦{amount:,.2f} authorization request at {merchant}",
            {"amount": amount, "merchant": merchant}
        )
        return Response(content='{"APPROVE":"YES"}', media_type="application/json")

    # ── 3. Standard event dispatch ───────────────────────────────────────────
    event   = payload.get("event", "")
    card_id = payload.get("cardId") or payload.get("card_Id", "")
    amount  = float(payload.get("amount", 0))
    ref     = payload.get("reference", "")
    status  = payload.get("status", "")

    if event == "virtualcard.created.complete":
        last4 = payload.get("lastFour", "")
        brand = payload.get("cardBrand", "")
        await db.virtual_cards.update_one(
            {"card_id": card_id},
            {"$set": {
                "status": "active",
                "last4": last4,
                "brand": brand.upper() if brand else None,
                "provider_ref": ref,
            }}
        )
        logger.info("[STROW WEBHOOK] card created card=%s last4=%s", card_id, last4)
        await _notify_card_user(card_id, "Card Ready", f"Your virtual card ending ****{last4} is now active!", {})

    elif event == "virtualcard.created.failed":
        reason = payload.get("failureReason", "Creation failed")
        refund  = float(payload.get("refundAmount", 0))
        await db.virtual_cards.update_one(
            {"card_id": card_id}, {"$set": {"status": "failed", "failure_reason": reason}}
        )
        logger.warning("[STROW WEBHOOK] card creation failed card=%s reason=%s", card_id, reason)
        await _notify_card_user(card_id, "Card Creation Failed", reason, {"refund": refund})

    elif event == "virtualcard.transaction.authorization":
        narrative = payload.get("narrative", "")
        merchant  = payload.get("merchant", narrative)
        await _record_card_txn(card_id, event, amount, payload.get("currency", "NGN"), merchant, ref, "authorized")
        await _notify_card_user(card_id, "Card Transaction", f"${amount:.2f} authorized at {merchant}", {"amount": amount})

    elif event in ("virtualcard.transaction.declined", "virtualcard.transaction.declined.terminated"):
        reason   = payload.get("reason", "Declined")
        narrative = payload.get("narrative", "")
        if event.endswith(".terminated"):
            await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "TERMINATED"}})
        await _record_card_txn(card_id, event, amount, "NGN", narrative, ref, "declined")
        await _notify_card_user(card_id, "Card Declined", f"Transaction declined: {reason}", {"reason": reason})

    elif event == "virtualcard.topup.complete":
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": amount}})
        await _record_card_txn(card_id, event, amount, "NGN", "Card Topup", ref, "success")
        await _notify_card_user(card_id, "Card Funded", f"₦{amount:,.2f} added to your card", {"amount": amount})

    elif event == "virtualcard.topup.failed":
        await _record_card_txn(card_id, event, amount, payload.get("currency","NGN"), "Card Topup", ref, "failed")
        await _notify_card_user(card_id, "Card Funding Failed",
                                "Card top-up failed. Your balance has been refunded.", {"amount": amount})

    elif event == "virtualcard.withdrawal.success":
        credited = float(payload.get("credited", 0))
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": -amount}})
        await _record_card_txn(card_id, event, amount, "NGN", "Withdrawal", ref, "success")
        await _notify_card_user(card_id, "Card Withdrawal", f"₦{credited:,.2f} withdrawn from card", {"amount": credited})

    elif event == "otp.code":
        otp  = payload.get("authorizationCode", "")
        last4 = payload.get("last4", "")
        await _notify_card_user(card_id, "Card OTP", f"Your card OTP is: {otp} (****{last4})", {"otp": otp})

    elif event == "transaction.created":
        card_id = payload.get("card_Id", card_id)
        merchant_name = (payload.get("merchant") or {}).get("name", "")
        fee  = float(payload.get("fee", 0))
        amt  = float(payload.get("merchantAmount", amount))
        await _record_card_txn(card_id, event, amt, payload.get("currency","NGN"), merchant_name, ref, "success")
        await _notify_card_user(card_id, "Card Debit",
                                f"₦{amt:,.2f} spent at {merchant_name}", {"amount": amt, "fee": fee})
        # Apply admin-configured spend fee (% of transaction amount)
        cfg_local = await _card_cfg()
        spend_fee_pct = cfg_local.get("naira_spend_fee_pct", 0.0)
        if spend_fee_pct > 0 and amt > 0:
            fee_ngn = round(amt * spend_fee_pct / 100, 2)
            try:
                rec_card = await db.virtual_cards.find_one({"card_id": card_id})
                if rec_card:
                    from bson import ObjectId as _BID
                    user_doc = await db.users.find_one({"_id": _BID(rec_card["user_id"])})
                    if user_doc:
                        await _sh_deduct(user_doc, fee_ngn,
                                         f"Card spend fee {spend_fee_pct}% on ₦{amt:.2f} at {merchant_name}")
                        await _record_card_txn(card_id, "spend_fee", fee_ngn, "NGN", "BOMPAY Fee", ref, "success")
            except Exception as _e:
                logger.warning("Spend fee deduction failed card=%s: %s", card_id, _e)

    elif event == "transaction.refund":
        card_id  = payload.get("card_Id", card_id)
        merchant_name = (payload.get("merchant") or {}).get("name", "Merchant")
        amt = float(payload.get("merchantAmount", amount))
        await _record_card_txn(card_id, event, amt, payload.get("currency","NGN"), merchant_name, ref, "refund")
        await _notify_card_user(card_id, "Card Refund",
                                f"₦{amt:,.2f} refunded from {merchant_name}", {"amount": amt})

    else:
        logger.info("[STROW WEBHOOK] unhandled event=%s card=%s", event, card_id)

    return {"status": "ok"}


# ── Ziiropay USD Card Webhook ─────────────────────────────────────────────────
@router.post("/webhooks/ziiropay-cards")
async def ziiropay_card_webhook(request: Request):
    """
    Handles ALL Ziiropay USD card webhook events.
    Must always return HTTP 200.

    Special case:
      - virtualcard.transaction.authorization → {"APPROVE": "YES"} or {"APPROVE": "NO", "reason": "..."}
    """
    try:
        payload = await request.json()
    except Exception:
        return Response(content='{"status":"ok"}', media_type="application/json")

    logger.info("[ZIIRO WEBHOOK] %s", payload)

    event   = payload.get("event", "")
    card_id = payload.get("cardId") or payload.get("card_Id", "")
    amount  = float(payload.get("amount", 0))
    ref     = payload.get("reference", "")

    # ── Authorization request ────────────────────────────────────────────────
    if event == "virtualcard.transaction.authorization":
        merchant = payload.get("merchant", payload.get("narrative", "Unknown"))
        currency = payload.get("currency", "USD")
        rec = await db.virtual_cards.find_one({"card_id": card_id})

        if not rec or rec.get("status") not in ("active",):
            reason = "Card is not active" if rec else "Card not found"
            logger.info("[ZIIRO AUTH] DECLINED card=%s reason=%s", card_id, reason)
            return Response(
                content=f'{{"APPROVE":"NO","reason":"{reason}"}}',
                media_type="application/json"
            )

        logger.info("[ZIIRO AUTH] APPROVED card=%s amount=%.2f%s", card_id, amount, currency)
        await _notify_card_user(
            card_id, "Card Authorization",
            f"${amount:.2f} authorization at {merchant}",
            {"amount": amount, "merchant": merchant}
        )
        return Response(content='{"APPROVE":"YES"}', media_type="application/json")

    # ── Standard events ──────────────────────────────────────────────────────
    if event == "virtualcard.created.complete":
        last4 = payload.get("lastFour", "")
        brand = payload.get("cardBrand", "VISA")
        await db.virtual_cards.update_one(
            {"card_id": card_id},
            {"$set": {
                "status": "active",
                "last4": last4,
                "brand": brand.upper() if brand else "VISA",
                "balance": amount,
            }}
        )
        await _notify_card_user(card_id, "USD Card Ready",
                                f"Your USD card ending ****{last4} is active!", {})

    elif event == "virtualcard.created.failed":
        reason = payload.get("failureReason", "Creation failed")
        await db.virtual_cards.update_one({"card_id": card_id}, {"$set": {"status": "failed"}})
        await _notify_card_user(card_id, "USD Card Failed", reason, {})

    elif event == "virtualcard.transaction.declined":
        reason = payload.get("reason", "Declined")
        narrative = payload.get("narrative", "")
        await _record_card_txn(card_id, event, amount, "USD", narrative, ref, "declined")
        await _notify_card_user(card_id, "Card Declined", f"Transaction declined: {reason}", {"reason": reason})

    elif event == "virtualcard.topup.complete":
        credited = float(payload.get("credited", amount))
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": credited}})
        await _record_card_txn(card_id, event, credited, "USD", "Card Topup", ref, "success")
        await _notify_card_user(card_id, "USD Card Funded", f"${credited:.2f} added to your card", {"amount": credited})

    elif event == "virtualcard.topup.failed":
        await _record_card_txn(card_id, event, amount, "USD", "Card Topup", ref, "failed")
        await _notify_card_user(card_id, "Funding Failed",
                                "USD card top-up failed. Your balance has been refunded.", {"amount": amount})

    elif event == "virtualcard.withdrawal.success":
        credited = float(payload.get("credited", 0))
        fee_amt  = float(payload.get("fee", 0))
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": -amount}})
        await _record_card_txn(card_id, event, amount, "USD", "Withdrawal", ref, "success")
        await _notify_card_user(card_id, "USD Card Withdrawal",
                                f"${credited:.2f} withdrawn (fee ${fee_amt:.2f})", {"amount": credited})

    elif event == "transaction.created":
        card_id   = payload.get("card_Id", card_id)
        merchant_name = (payload.get("merchant") or {}).get("name", "Merchant")
        fee_amt   = float(payload.get("fee", 0))
        amt       = float(payload.get("merchantAmount", amount))
        # Deduct from shadow USD balance
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": -(amt + fee_amt)}})
        await _record_card_txn(card_id, event, amt, payload.get("currency","USD"), merchant_name, ref, "success")
        await _notify_card_user(card_id, "USD Card Debit",
                                f"${amt:.2f} spent at {merchant_name}", {"amount": amt})

    elif event == "transaction.refund":
        card_id   = payload.get("card_Id", card_id)
        merchant_name = (payload.get("merchant") or {}).get("name", "Merchant")
        amt = float(payload.get("merchantAmount", amount))
        await db.virtual_cards.update_one({"card_id": card_id}, {"$inc": {"balance": amt}})
        await _record_card_txn(card_id, event, amt, payload.get("currency","USD"), merchant_name, ref, "refund")
        await _notify_card_user(card_id, "USD Card Refund",
                                f"${amt:.2f} refunded from {merchant_name}", {"amount": amt})

    elif event == "otp.code":
        otp  = payload.get("authorizationCode", "")
        last4 = payload.get("last4", "")
        await _notify_card_user(card_id, "Card OTP",
                                f"Your USD card OTP: {otp} (****{last4})", {"otp": otp})

    else:
        logger.info("[ZIIRO WEBHOOK] unhandled event=%s card=%s", event, card_id)

    return {"status": "ok"}



@router.post("/admin/cards/refund-user")
async def admin_refund_card_debit(request: Request):
    """Admin: manually refund a user who was debited but card creation failed."""
    admin = await get_current_user(request)
    if admin.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    body = await request.json()
    phone   = body.get("phone", "").strip()
    amount  = float(body.get("amount", 0))
    reason  = body.get("reason", "Card creation failed — manual refund")
    if not phone or amount <= 0:
        raise HTTPException(400, "phone and amount required")
    # Find user
    norm = phone.lstrip("+").lstrip("234").lstrip("0")
    target = await db.users.find_one({"phone": {"$regex": norm}})
    if not target:
        raise HTTPException(404, "User not found")
    await _sh_refund_to_user(target, amount, reason)
    return {"success": True, "message": f"Refunded ₦{amount:,.2f} to {phone}"}
