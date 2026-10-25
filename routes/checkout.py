"""
Bompay Checkout — Hosted Payment Sessions
Prefix: /api/v1/checkout  (merchant API key auth — public read)
Prefix: /api/admin/checkout  (admin-only)
"""
import os, secrets, uuid, hashlib, asyncio
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from typing import Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from bson import ObjectId

from core import call_sh, logger, send_otp_sms
from database import db

router = APIRouter()

WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", "")
SAFEHAVEN_BANK_CODE = os.environ.get("SAFEHAVEN_BANK_CODE", "090286")

# ─── MODELS ──────────────────────────────────────────────────────────────────

class CreateSessionReq(BaseModel):
    amount: float                          # Naira, e.g. 5000.00
    currency: str = "NGN"
    email: Optional[str] = ""
    name: Optional[str] = ""
    reference: Optional[str] = ""         # merchant's own order reference
    success_url: Optional[str] = ""
    cancel_url: Optional[str] = ""
    metadata: Optional[dict] = {}
    expires_in: Optional[int] = 900       # seconds; default 15 min


# ─── API KEY AUTH ─────────────────────────────────────────────────────────────

async def _get_merchant_by_api_key(request: Request) -> dict:
    """Authenticate request via Bearer API key (test or live secret key)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header. Use: Bearer <secret_key>")
    key = auth[7:].strip()
    m = await db.merchants.find_one({
        "$or": [{"test_secret_key": key}, {"live_secret_key": key}]
    })
    if not m:
        raise HTTPException(401, "Invalid API key")
    if m.get("status") == "suspended":
        raise HTTPException(403, "Merchant account suspended")
    # Determine mode from which key was used
    mode = "live" if m.get("live_secret_key") == key else "sandbox"
    m["_resolved_mode"] = mode
    m["_id"] = str(m["_id"])
    return m


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_settlement_account_id() -> str:
    """Get the configured settlement account number/id from provider settings."""
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    return (settings or {}).get("settlement_account_id", "") or os.environ.get("SAFEHAVEN_SETTLEMENT_ACCOUNT_ID", "")


async def _build_settlement_account(merchant_id: str = "") -> dict:
    """
    Build the settlementAccount for a checkout virtual account.

    Settlement goes to the MERCHANT's own Safe Haven primary account so the customer's
    payment lands directly in the merchant's wallet. BOMPAY's fee is collected separately
    via the fee engine.

    Falls back to the platform's configured settlement account only when the merchant
    has no Safe Haven account yet (e.g. pending KYB).
    """
    # 1. Look up the merchant's own Safe Haven account number from their wallet
    if merchant_id:
        wallet = await db.wallets.find_one(
            {"user_id": merchant_id, "account_type": {"$in": ["corporate", "individual", "primary", None]}},
            sort=[("created_at", 1)]
        )
        if not wallet:
            # Try without account_type filter
            wallet = await db.wallets.find_one({"user_id": merchant_id})

        merchant_sh_acct = (wallet or {}).get("sh_account_number", "").strip()
        merchant_bank_code = (wallet or {}).get("sh_bank_code", SAFEHAVEN_BANK_CODE).strip() or SAFEHAVEN_BANK_CODE

        if merchant_sh_acct:
            logger.info(f"[CHECKOUT] Settlement → merchant account {merchant_sh_acct} (user={merchant_id[:8]}...)")
            return {"bankCode": merchant_bank_code, "accountNumber": merchant_sh_acct}

        logger.warning(f"[CHECKOUT] Merchant {merchant_id[:8]} has no Safe Haven account — falling back to platform settlement")

    # 2. Fallback: platform-level settlement account from provider_settings
    settings = await db.provider_settings.find_one({"provider": "safehaven"}) or {}
    raw_settlement = (settings.get("settlement_account_id") or "").strip()
    main_acct = (settings.get("account_number") or "").strip() or \
                os.environ.get("SAFEHAVEN_SETTLEMENT_ACCOUNT_ID", "").strip()

    # Accept only 10-digit account numbers; discard ObjectId-style cached values
    if raw_settlement.isdigit() and 7 <= len(raw_settlement) <= 12:
        account_number = raw_settlement
    else:
        if raw_settlement:
            await db.provider_settings.update_one(
                {"provider": "safehaven"}, {"$unset": {"settlement_account_id": ""}}
            )
        account_number = main_acct

    if not account_number:
        return {}

    bank_code = (settings.get("settlement_bank_code") or "").strip() or \
                os.environ.get("SAFEHAVEN_BANK_CODE", SAFEHAVEN_BANK_CODE)

    return {"bankCode": bank_code, "accountNumber": account_number}


async def _resolve_settlement_account(raw_value: str) -> dict:
    """Legacy helper kept for safety — now delegates to _build_settlement_account."""
    return await _build_settlement_account()


def _validate_amount(amount_naira: float) -> int:
    """Convert Naira float to integer kobo, rejecting invalid values."""
    try:
        d = Decimal(str(amount_naira))
    except InvalidOperation:
        raise HTTPException(400, "Invalid amount")
    if d <= 0:
        raise HTTPException(400, "Amount must be greater than zero")
    if d > Decimal("10000000"):
        raise HTTPException(400, "Amount exceeds maximum (₦10,000,000 per checkout)")
    # Check precision — accept up to 2 decimal places only
    quantized = d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    kobo = int(quantized * 100)
    if kobo < 100:
        raise HTTPException(400, "Minimum checkout amount is ₦1.00")
    return kobo


async def _create_sh_virtual_account(
    session_id: str,
    amount_naira: float,
    expires_in: int,
    merchant_id: str,
) -> dict:
    """
    Create a temporary Safe Haven virtual account for this checkout session.
    Uses /virtual-accounts with Fixed amountControl so payer must send exact amount.
    Falls back to mock if Safe Haven is not configured.
    """
    external_ref = f"cs-{session_id}"
    cb_url = (WEBHOOK_BASE_URL or "").rstrip("/") + "/api/webhooks/safehaven"

    payload = {
        "validFor": max(60, min(expires_in, 86400)),  # clamp to Safe Haven allowed range
        "amount": amount_naira,                        # Safe Haven accepts Naira
        "amountControl": "Fixed",
        "externalReference": external_ref,
    }
    if cb_url and cb_url != "/api/webhooks/safehaven":
        payload["callbackUrl"] = cb_url

    sa = await _build_settlement_account(merchant_id)
    if sa:
        payload["settlementAccount"] = sa
        logger.info(f"[CHECKOUT] Using settlementAccount bankCode={sa.get('bankCode')} acct={sa.get('accountNumber')}")

    try:
        resp = await call_sh("POST", "/virtual-accounts", body=payload)
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        return {
            "sh_virtual_account_id": (data or {}).get("_id", ""),
            "sh_account_number": (data or {}).get("accountNumber", ""),
            "sh_bank_name": (data or {}).get("bankName", "Safe Haven MFB"),
            "sh_bank_code": SAFEHAVEN_BANK_CODE,
            "sh_account_name": (data or {}).get("accountName", "Bompay Checkout"),
            "external_reference": external_ref,
        }
    except Exception as e:
        logger.warning(f"[CHECKOUT] SH virtual account creation failed: {e} — session={session_id}")
        # Return empty — session will be in pending_provision state
        return {
            "sh_virtual_account_id": "",
            "sh_account_number": "",
            "sh_bank_name": "Safe Haven MFB",
            "sh_bank_code": SAFEHAVEN_BANK_CODE,
            "sh_account_name": "Bompay Checkout",
            "external_reference": external_ref,
        }


def _session_public(s: dict) -> dict:
    """Strip internal fields before returning to merchant or payer."""
    return {k: v for k, v in s.items() if k not in ("_id", "merchant_id", "webhook_payload")}


# ─── SHARED POST-PAYMENT HELPERS ─────────────────────────────────────────────

async def _inline_confirm_payment_link_attempt(attempt_id: str, session_id: str):
    """Mark a payment link attempt as paid. Idempotent."""
    try:
        attempt = await db.payment_link_attempts.find_one({"attempt_id": attempt_id})
        if not attempt or attempt.get("status") == "paid":
            return
        now_ts = _now()
        await db.payment_link_attempts.update_one(
            {"attempt_id": attempt_id, "status": {"$ne": "paid"}},
            {"$set": {"status": "paid", "checkout_session_id": session_id,
                      "paid_at": now_ts, "updated_at": now_ts}}
        )
        link_id = attempt.get("link_id")
        if link_id:
            await db.payment_links.update_one({"link_id": link_id}, {"$inc": {"usage_count": 1}})
        logger.info(f"[CHECKOUT] PayLink attempt {attempt_id} confirmed paid via session={session_id}")
    except Exception as e:
        logger.error(f"[CHECKOUT] confirm payment link attempt failed: {e}")


async def _inline_confirm_storefront_order(order_id: str, session_id: str):
    """Mark a storefront order as paid. Idempotent."""
    try:
        order = await db.store_orders.find_one({"order_id": order_id})
        if not order or order.get("payment_status") == "paid":
            return
        now_ts = _now()
        await db.store_orders.update_one(
            {"order_id": order_id},
            {"$set": {
                "payment_status": "paid",
                "order_status": "processing",
                "paid_at": now_ts,
                "updated_at": now_ts,
            }}
        )
        logger.info(f"[CHECKOUT] Storefront order {order_id} confirmed paid via session={session_id}")
    except Exception as e:
        logger.error(f"[CHECKOUT] confirm storefront order failed: {e}")


async def _record_merchant_credit(session: dict, payment_method: str):
    """
    Record a CREDIT transaction entry for the merchant when payment is confirmed.
    Used for Pay-with-Bompay and any other non-Safe-Haven payment path.
    Idempotent via idempotency_key.
    """
    try:
        session_id = session["session_id"]
        merchant_id = session.get("merchant_id", "")
        amount_kobo = session.get("amount_kobo", 0)
        if not merchant_id or not amount_kobo:
            return
        idem_key = f"MERCHANT_CREDIT_{session_id}"
        if await db.merchant_transactions.find_one({"idempotency_key": idem_key}):
            logger.info(f"[CHECKOUT] Merchant credit already recorded for session={session_id}")
            return
        now_ts = _now()
        _meta = session.get("metadata") or {}
        await db.merchant_transactions.insert_one({
            "transaction_id": f"TXN{secrets.token_hex(12).upper()}",
            "idempotency_key": idem_key,
            "merchant_id": merchant_id,
            "type": "CHECKOUT_PAYMENT",
            "direction": "CREDIT",
            "amount": amount_kobo,
            "fee": 0,
            "currency": "NGN",
            "status": "success",
            "provider": payment_method,
            "description": f"Payment received — {session.get('reference', session_id)}",
            "metadata": {
                "session_id": session_id,
                "source_type": _meta.get("source_type", ""),
                "source_id": _meta.get("source_id", ""),
                "payment_method": payment_method,
                "customer": session.get("customer_info", {}),
            },
            "created_at": now_ts,
            "updated_at": now_ts,
        })
        logger.info(f"[CHECKOUT] Merchant credit ₦{amount_kobo/100:.2f} recorded merchant={merchant_id} session={session_id}")
    except Exception as e:
        logger.error(f"[CHECKOUT] record_merchant_credit failed: {e}")


async def _post_payment_tasks(session: dict, payment_method: str = "bompay_wallet"):
    """
    Fire-and-forget tasks after any payment confirmation.
    1. Confirm storefront order or payment link attempt.
    2. Record merchant credit transaction.
    """
    _meta = (session.get("metadata") or {})
    src_type = _meta.get("source_type", "")
    src_id = _meta.get("source_id", "")
    session_id = session["session_id"]
    if src_type == "storefront" and src_id:
        await _inline_confirm_storefront_order(src_id, session_id)
    elif src_type == "payment_link" and src_id:
        await _inline_confirm_payment_link_attempt(src_id, session_id)
    await _record_merchant_credit(session, payment_method)


# ─── CHECKOUT SESSION ROUTES ──────────────────────────────────────────────────

@router.post("/v1/checkout/sessions")
async def create_checkout_session(req: CreateSessionReq, request: Request):
    """
    Create a new hosted checkout session.
    Authentication: Bearer <secret_key> (test or live API key).
    Returns session_id and redirect_url for the hosted checkout page.
    """
    merchant = await _get_merchant_by_api_key(request)
    amount_kobo = _validate_amount(req.amount)
    session_id = f"cs_{secrets.token_urlsafe(16)}"
    now = _now()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=req.expires_in)).isoformat()

    # Create Safe Haven temporary virtual account
    sh = await _create_sh_virtual_account(
        session_id=session_id,
        amount_naira=req.amount,
        expires_in=req.expires_in,
        merchant_id=merchant["merchant_id"],
    )

    doc = {
        "session_id": session_id,
        "merchant_id": merchant["merchant_id"],
        "business_name": merchant.get("business_name", ""),
        "mode": merchant["_resolved_mode"],
        "amount_kobo": amount_kobo,
        "amount_naira": req.amount,
        "currency": req.currency.upper(),
        "email": req.email or "",
        "customer_name": req.name or "",
        "reference": req.reference or "",
        "success_url": req.success_url or "",
        "cancel_url": req.cancel_url or "",
        "metadata": req.metadata or {},
        "expires_in": req.expires_in,
        "expires_at": expires_at,
        "status": "pending",
        **sh,
        "created_at": now,
        "updated_at": now,
        "paid_at": None,
        "webhook_payload": None,
    }
    await db.checkout_sessions.insert_one(doc)

    checkout_url = (
        os.environ.get("FRONTEND_URL", "").rstrip("/") + f"/checkout/{session_id}"
    )
    logger.info(f"[CHECKOUT] Session created: {session_id} amt=₦{req.amount} merchant={merchant['merchant_id']}")

    return {
        "session_id": session_id,
        "checkout_url": checkout_url,
        "amount_kobo": amount_kobo,
        "amount_naira": req.amount,
        "currency": doc["currency"],
        "expires_at": expires_at,
        "bank_transfer": {
            "account_number": sh["sh_account_number"],
            "bank_name": sh["sh_bank_name"],
            "bank_code": sh["sh_bank_code"],
            "account_name": sh["sh_account_name"],
            "amount": req.amount,
            "note": "Transfer exact amount. Any other amount requires manual review.",
        },
        "reference": doc["reference"],
        "status": "pending",
    }


@router.post("/v1/checkout/sessions/{session_id}/reprovision")
async def reprovision_bank_transfer(session_id: str):
    """
    Retry Safe Haven virtual account creation for a pending session whose
    bank_transfer account number is empty. Safe to call multiple times — idempotent.
    """
    s = await db.checkout_sessions.find_one({"session_id": session_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Checkout session not found")
    if s.get("status") != "pending":
        return {"account_number": s.get("sh_account_number", ""), "already_active": True}
    if s.get("sh_account_number"):
        return {"account_number": s["sh_account_number"], "bank_name": s.get("sh_bank_name"), "account_name": s.get("sh_account_name")}

    # Retry VA creation
    amount_naira = s.get("amount_naira", s.get("amount_kobo", 0) / 100.0)
    external_ref = s.get("external_reference") or f"cs-{session_id}"
    expires_in = 3600
    cb_url = (WEBHOOK_BASE_URL or "").rstrip("/") + "/api/webhooks/safehaven"
    payload = {
        "validFor": expires_in,
        "amount": amount_naira,
        "amountControl": "Fixed",
        "externalReference": external_ref,
    }
    if cb_url and cb_url != "/api/webhooks/safehaven":
        payload["callbackUrl"] = cb_url
    sa = await _build_settlement_account(s.get("merchant_id", ""))
    if sa:
        payload["settlementAccount"] = sa
        logger.info(f"[CHECKOUT] Reprovision settlementAccount bankCode={sa.get('bankCode')} acct={sa.get('accountNumber')}")
    try:
        resp = await call_sh("POST", "/virtual-accounts", body=payload)
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        if data and data.get("accountNumber"):
            update = {
                "sh_virtual_account_id": data.get("_id", ""),
                "sh_account_number": data.get("accountNumber", ""),
                "sh_bank_name": data.get("bankName", "Safe Haven MFB"),
                "sh_account_name": data.get("accountName", "Bompay Checkout"),
                "external_reference": external_ref,
                "updated_at": _now(),
            }
            await db.checkout_sessions.update_one({"session_id": session_id}, {"$set": update})
            logger.info(f"[CHECKOUT] Reprovision success session={session_id} acct={update['sh_account_number']}")
            return {"account_number": update["sh_account_number"], "bank_name": update["sh_bank_name"],
                    "account_name": update["sh_account_name"]}
        else:
            logger.warning(f"[CHECKOUT] Reprovision: SH returned no accountNumber data={data}")
            raise HTTPException(503, "Bank transfer is currently unavailable. Please use Pay with Bompay.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[CHECKOUT] Reprovision exception: {e}")
        raise HTTPException(503, "Bank transfer provisioning failed. Please use Pay with Bompay.")


@router.get("/v1/checkout/sessions/{session_id}")
async def get_checkout_session(session_id: str):
    """
    Public status endpoint — no auth required.
    Used by the hosted checkout page to poll for payment confirmation.
    Never exposes sensitive merchant or webhook data.
    """
    s = await db.checkout_sessions.find_one({"session_id": session_id}, {"_id": 0})
    if not s:
        raise HTTPException(404, "Checkout session not found")

    # Mark expired automatically
    if s.get("status") == "pending" and s.get("expires_at"):
        if s["expires_at"] < _now():
            await db.checkout_sessions.update_one(
                {"session_id": session_id},
                {"$set": {"status": "expired", "updated_at": _now()}}
            )
            s["status"] = "expired"

    return {
        "session_id": s["session_id"],
        "business_name": s.get("business_name", ""),
        "amount_kobo": s.get("amount_kobo", 0),
        "amount_naira": s.get("amount_naira", 0),
        "currency": s.get("currency", "NGN"),
        "email": s.get("email", ""),
        "customer_name": s.get("customer_name", ""),
        "reference": s.get("reference", ""),
        "status": s.get("status", "pending"),
        "expires_at": s.get("expires_at", ""),
        "paid_at": s.get("paid_at"),
        "success_url": s.get("success_url", ""),
        "cancel_url": s.get("cancel_url", ""),
        "bank_transfer": {
            "account_number": s.get("sh_account_number", ""),
            "bank_name": s.get("sh_bank_name", "Safe Haven MFB"),
            "bank_code": s.get("sh_bank_code", "090286"),
            "account_name": s.get("sh_account_name", "Bompay Checkout"),
            "amount": s.get("amount_naira", 0),
        },
        "mode": s.get("mode", "sandbox"),
    }


# ─── PAY WITH BOMPAY ─────────────────────────────────────────────────────────

class BompayLookupReq(BaseModel):
    identifier: str   # email or phone number of the payer


class BompayConfirmReq(BaseModel):
    otp_code: str     # 6-digit OTP


def _mask_phone(phone: str) -> str:
    """Return masked phone for display e.g. 0801***4321"""
    p = phone.strip()
    if len(p) >= 7:
        return p[:4] + "***" + p[-4:]
    return p[:2] + "***"


def _mask_email(email: str) -> str:
    """Return masked email e.g. to**@gmail.com"""
    parts = email.split("@")
    if len(parts) == 2:
        local = parts[0]
        return local[:2] + "***@" + parts[1]
    return email[:3] + "***"


async def _get_open_session(session_id: str) -> dict:
    """Fetch session, raise 404 if not found, 410 if not payable."""
    s = await db.checkout_sessions.find_one({"session_id": session_id})
    if not s:
        raise HTTPException(404, "Checkout session not found")
    # Auto-expire
    if s.get("status") == "pending" and s.get("expires_at") and s["expires_at"] < _now():
        await db.checkout_sessions.update_one(
            {"session_id": session_id}, {"$set": {"status": "expired", "updated_at": _now()}}
        )
        s["status"] = "expired"
    if s.get("status") != "pending":
        raise HTTPException(410, f"Session is {s.get('status')} — payment cannot proceed")
    return s


@router.post("/v1/checkout/sessions/{session_id}/bompay-lookup")
async def bompay_lookup(session_id: str, req: BompayLookupReq):
    """
    Step 1 — Look up a Bompay account by email or phone.
    Returns masked balance and masked contact details.
    Does NOT deduct any money; does NOT send OTP yet.
    Public endpoint (no auth) — intentionally returns limited info only.
    """
    session = await _get_open_session(session_id)
    identifier = req.identifier.strip()
    if not identifier:
        raise HTTPException(400, "Email or phone number is required")

    # Lookup user
    user = None
    lookup_by = "phone"
    if "@" in identifier:
        lookup_by = "email"
        user = await db.users.find_one(
            {"email": identifier.lower()},
            {"_id": 1, "first_name": 1, "last_name": 1, "phone": 1, "email": 1, "status": 1}
        )
    else:
        # Normalise phone: strip leading zeros, ensure +234 prefix
        phone = identifier.strip()
        if phone.startswith("0"):
            phone = "+234" + phone[1:]
        elif phone.startswith("234") and not phone.startswith("+"):
            phone = "+" + phone
        user = await db.users.find_one(
            {"phone": phone},
            {"_id": 1, "first_name": 1, "last_name": 1, "phone": 1, "email": 1, "status": 1}
        )
        if not user:
            # Also try as-is
            user = await db.users.find_one(
                {"phone": identifier},
                {"_id": 1, "first_name": 1, "last_name": 1, "phone": 1, "email": 1, "status": 1}
            )

    if not user:
        raise HTTPException(404, "No Bompay account found for that email or phone number")
    if user.get("status") == "SUSPENDED":
        raise HTTPException(403, "Bompay account is suspended")

    user_id = str(user["_id"])
    wallet = await db.wallets.find_one({"user_id": user_id})
    if not wallet:
        raise HTTPException(404, "Bompay wallet not found for this account")

    available_kobo = wallet.get("available_balance", 0)
    amount_kobo = session["amount_kobo"]

    if available_kobo < amount_kobo:
        raise HTTPException(400, (
            f"Insufficient Bompay balance. "
            f"This payment requires ₦{amount_kobo/100:,.2f} but your available balance is "
            f"₦{available_kobo/100:,.2f}. Please top up your Bompay wallet."
        ))

    # Store the resolved user_id in session context (temporary, before OTP confirm)
    await db.checkout_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"_bompay_pending_user_id": user_id, "updated_at": _now()}}
    )

    contact = user.get("phone", "")
    masked = _mask_phone(contact) if contact else _mask_email(user.get("email", ""))
    name_parts = [user.get("first_name", ""), user.get("last_name", "")]
    display_name = " ".join(p for p in name_parts if p).strip() or "Bompay User"

    return {
        "found": True,
        "display_name": display_name,
        "masked_contact": masked,
        "balance_sufficient": True,
        "message": f"Account found. OTP will be sent to {masked}",
    }


@router.post("/v1/checkout/sessions/{session_id}/bompay-send-otp")
async def bompay_send_otp(session_id: str):
    """
    Step 2 — Send OTP to the Bompay account owner's registered phone.
    Requires that bompay-lookup was called first (session must have pending user ID).
    Rate-limited to 3 OTP sends per session.
    """
    session = await _get_open_session(session_id)
    user_id = session.get("_bompay_pending_user_id")
    if not user_id:
        raise HTTPException(400, "Please look up your Bompay account first")

    # Rate limit: max 3 OTP sends per session
    otp_send_count = session.get("_bompay_otp_sends", 0)
    if otp_send_count >= 3:
        raise HTTPException(429, "Too many OTP requests for this session. Please cancel and try again.")

    user = await db.users.find_one({"_id": ObjectId(user_id)}, {"phone": 1, "first_name": 1})
    if not user:
        raise HTTPException(404, "Bompay account not found")

    phone = user.get("phone", "")
    if not phone:
        raise HTTPException(400, "No phone number on file for this Bompay account")

    # Generate OTP
    otp_code = "".join(secrets.choice("0123456789") for _ in range(6))
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    # Store OTP (delete old ones for this session first)
    await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})
    await db.otp_sessions.insert_one({
        "phone": phone,
        "type": "CHECKOUT_PAY",
        "scope": session_id,
        "otp_hash": otp_hash,
        "user_id": user_id,
        "amount_kobo": session["amount_kobo"],
        "created_at": _now(),
        "expires_at": expires_at,
        "attempts": 0,
    })

    # Update send count
    await db.checkout_sessions.update_one(
        {"session_id": session_id},
        {"$inc": {"_bompay_otp_sends": 1}, "$set": {"updated_at": _now()}}
    )

    # Send SMS
    name = user.get("first_name", "")
    amount_naira = session["amount_kobo"] / 100
    sms_body = (
        f"Hi {name}, your BOMPAY payment code is: {otp_code}. "
        f"This authorises payment of ₦{amount_naira:,.2f}. "
        f"Valid for 10 minutes. Do NOT share this code."
    )
    sms_result = await send_otp_sms(phone, sms_body)
    logger.info(f"[CHECKOUT PAY-BOMPAY] OTP sent to {_mask_phone(phone)} for session={session_id} sms_ok={sms_result.get('ok')}")

    return {
        "sent": True,
        "masked_phone": _mask_phone(phone),
        "message": f"OTP sent to {_mask_phone(phone)}. Enter it below to confirm payment.",
        "expires_in": 600,
    }


@router.post("/v1/checkout/sessions/{session_id}/bompay-confirm")
async def bompay_confirm(session_id: str, req: BompayConfirmReq):
    """
    Step 3 — Verify OTP and execute the Bompay wallet debit.
    On success: marks session as paid, debits the payer's wallet.
    """
    session = await _get_open_session(session_id)
    user_id = session.get("_bompay_pending_user_id")
    if not user_id:
        raise HTTPException(400, "Please complete the account lookup step first")

    otp_code = req.otp_code.strip()
    if len(otp_code) != 6 or not otp_code.isdigit():
        raise HTTPException(400, "Invalid OTP format — must be 6 digits")

    # Fetch OTP session
    otp_session = await db.otp_sessions.find_one({
        "type": "CHECKOUT_PAY",
        "scope": session_id,
        "user_id": user_id,
    })
    if not otp_session:
        raise HTTPException(400, "No active OTP found. Please request a new OTP.")

    # Check expiry
    if otp_session.get("expires_at", "") < _now():
        await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    # Check attempt limit (max 5)
    attempts = otp_session.get("attempts", 0)
    if attempts >= 5:
        await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")

    # Verify hash
    entered_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    if entered_hash != otp_session.get("otp_hash", ""):
        await db.otp_sessions.update_one(
            {"_id": otp_session["_id"]}, {"$inc": {"attempts": 1}}
        )
        remaining = 4 - attempts
        raise HTTPException(400, f"Incorrect OTP. {remaining} attempt(s) remaining.")

    # ── OTP verified — execute payment atomically ─────────────────────────────
    amount_kobo = session["amount_kobo"]
    now_ts = _now()

    # Re-check balance (guard against concurrent payments)
    wallet = await db.wallets.find_one({"user_id": user_id})
    if not wallet:
        raise HTTPException(400, "Wallet not found")
    if wallet.get("available_balance", 0) < amount_kobo:
        await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})
        raise HTTPException(400, "Insufficient balance — please top up your Bompay wallet and try again")

    # Idempotency: check for existing payment transaction
    idem_key = f"CHECKOUT_PAY_{session_id}"
    existing_txn = await db.transactions.find_one({"idempotency_key": idem_key})
    if existing_txn:
        logger.info(f"[CHECKOUT PAY-BOMPAY] Duplicate confirm for session={session_id}, returning existing")
        await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})
        await db.checkout_sessions.update_one(
            {"session_id": session_id, "status": "pending"},
            {"$set": {"status": "paid", "paid_at": now_ts, "updated_at": now_ts,
                      "payment_method": "bompay_wallet", "payer_user_id": user_id}}
        )
        asyncio.create_task(_post_payment_tasks(session, "bompay_wallet"))
        return {"paid": True, "message": "Payment confirmed", "redirect_url": session.get("success_url", "")}

    # Debit wallet
    result = await db.wallets.update_one(
        {"user_id": user_id, "available_balance": {"$gte": amount_kobo}},
        {"$inc": {"available_balance": -amount_kobo, "ledger_balance": -amount_kobo}}
    )
    if result.modified_count == 0:
        raise HTTPException(400, "Insufficient balance — payment declined")

    # Record transaction
    txn_id = f"TXN{secrets.token_hex(12).upper()}"
    bal_before = wallet.get("available_balance", 0)
    await db.transactions.insert_one({
        "transaction_id": txn_id,
        "idempotency_key": idem_key,
        "user_id": user_id,
        "type": "CHECKOUT_PAYMENT",
        "direction": "DEBIT",
        "amount": amount_kobo,
        "fee": 0,
        "currency": "NGN",
        "status": "COMPLETED",
        "provider": "BOMPAY_WALLET",
        "description": f"Checkout payment to {session.get('business_name', 'merchant')}",
        "metadata": {
            "session_id": session_id,
            "merchant_id": session.get("merchant_id", ""),
            "reference": session.get("reference", ""),
        },
        "balance_before_kobo": bal_before,
        "balance_after_kobo": bal_before - amount_kobo,
        "created_at": now_ts,
        "updated_at": now_ts,
    })

    # Mark session paid
    await db.checkout_sessions.update_one(
        {"session_id": session_id},
        {"$set": {
            "status": "paid",
            "paid_at": now_ts,
            "updated_at": now_ts,
            "payment_method": "bompay_wallet",
            "payer_user_id": user_id,
            "payer_txn_id": txn_id,
        }}
    )

    # Clean up OTP
    await db.otp_sessions.delete_many({"type": "CHECKOUT_PAY", "scope": session_id})

    logger.info(f"[CHECKOUT PAY-BOMPAY] ✅ Paid session={session_id} ₦{amount_kobo/100:.2f} by user={user_id} txn={txn_id}")

    # ── Post-payment tasks (confirm source record + merchant credit) ──────
    asyncio.create_task(_post_payment_tasks(session, "bompay_wallet"))

    redirect_url = session.get("success_url", "")
    if redirect_url:
        redirect_url += f"?session_id={session_id}&status=paid&method=bompay"

    return {
        "paid": True,
        "message": "Payment successful!",
        "txn_id": txn_id,
        "redirect_url": redirect_url,
    }



async def merchant_checkout_sessions(request: Request, page: int = 1, status: str = ""):
    """List checkout sessions for the authenticated merchant (cookie auth)."""
    # Accept both cookie auth (dashboard) and API key (developer)
    try:
        from routes.merchant import get_current_merchant
        merchant = await get_current_merchant(request)
        mid = merchant["merchant_id"]
    except HTTPException:
        merchant = await _get_merchant_by_api_key(request)
        mid = merchant["merchant_id"]

    query: dict = {"merchant_id": mid}
    if status:
        query["status"] = status
    skip = (page - 1) * 20
    sessions = await db.checkout_sessions.find(query, {"_id": 0, "webhook_payload": 0}).sort(
        "created_at", -1
    ).skip(skip).limit(20).to_list(20)
    total = await db.checkout_sessions.count_documents(query)
    return {"sessions": sessions, "total": total, "page": page, "pages": -(-total // 20)}


# ─── ADMIN ────────────────────────────────────────────────────────────────────

@router.get("/admin/checkout/sessions")
async def admin_checkout_sessions(
    request: Request,
    page: int = 1,
    status: str = "",
    merchant_id: str = "",
):
    from routes.merchant import _get_admin
    await _get_admin(request)
    query: dict = {}
    if status:
        query["status"] = status
    if merchant_id:
        query["merchant_id"] = merchant_id
    skip = (page - 1) * 30
    sessions = await db.checkout_sessions.find(query, {"_id": 0, "webhook_payload": 0}).sort(
        "created_at", -1
    ).skip(skip).limit(30).to_list(30)
    total = await db.checkout_sessions.count_documents(query)

    # Stats
    total_paid = await db.checkout_sessions.count_documents({"status": "paid"})
    total_pending = await db.checkout_sessions.count_documents({"status": "pending"})
    vol_agg = await db.checkout_sessions.aggregate([
        {"$match": {"status": "paid"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}}
    ]).to_list(1)
    total_volume_kobo = vol_agg[0]["total"] if vol_agg else 0

    return {
        "sessions": sessions, "total": total, "page": page,
        "pages": -(-total // 30),
        "stats": {
            "total_paid": total_paid,
            "total_pending": total_pending,
            "total_volume_ngn": round(total_volume_kobo / 100, 2),
        }
    }


# ─── MERCHANT FEE RULES (admin) ───────────────────────────────────────────────

@router.get("/admin/merchant-fees")
async def list_merchant_fees(request: Request):
    """List all merchant platform fee rules."""
    from routes.merchant import _get_admin
    await _get_admin(request)
    fees = await db.merchant_fee_rules.find({}, {"_id": 0}).to_list(50)
    return {"fees": fees}


class FeeRule(BaseModel):
    service: str                       # CHECKOUT, TRANSFER, AIRTIME, etc.
    fee_type: str = "FLAT_PLUS_PCT"    # FLAT, PERCENTAGE, FLAT_PLUS_PCT
    flat_kobo: int = 0                 # flat component in kobo
    percentage: float = 0.0            # percentage component (0–100)
    min_fee_kobo: int = 0
    max_fee_kobo: int = 0              # 0 = no cap
    is_active: bool = True
    description: str = ""


@router.put("/admin/merchant-fees/{service}")
async def update_merchant_fee(service: str, req: FeeRule, request: Request):
    """Create or update a merchant platform fee rule."""
    from routes.merchant import _get_admin
    admin = await _get_admin(request)
    if req.percentage < 0 or req.percentage > 100:
        raise HTTPException(400, "Percentage must be between 0 and 100")
    if req.flat_kobo < 0 or req.min_fee_kobo < 0 or req.max_fee_kobo < 0:
        raise HTTPException(400, "Fee amounts must be non-negative")
    now = _now()
    doc = {
        "service": service.upper(),
        "fee_type": req.fee_type.upper(),
        "flat_kobo": req.flat_kobo,
        "percentage": req.percentage,
        "min_fee_kobo": req.min_fee_kobo,
        "max_fee_kobo": req.max_fee_kobo,
        "is_active": req.is_active,
        "description": req.description,
        "updated_at": now,
        "updated_by": admin.get("email", "admin"),
    }
    await db.merchant_fee_rules.update_one(
        {"service": service.upper()}, {"$set": doc}, upsert=True
    )
    return {"message": f"Fee rule for {service.upper()} updated", "rule": doc}


@router.get("/admin/merchant-fees/{service}")
async def get_merchant_fee(service: str, request: Request):
    """Get fee rule for a specific service."""
    from routes.merchant import _get_admin
    await _get_admin(request)
    rule = await db.merchant_fee_rules.find_one({"service": service.upper()}, {"_id": 0})
    if not rule:
        raise HTTPException(404, f"No fee rule for service {service.upper()}")
    return rule


@router.get("/v1/merchant/fees")
async def merchant_fees(request: Request):
    """List active fee rules visible to merchants."""
    try:
        from routes.merchant import get_current_merchant
        await get_current_merchant(request)
    except HTTPException:
        await _get_merchant_by_api_key(request)
    fees = await db.merchant_fee_rules.find({"is_active": True}, {"_id": 0, "updated_by": 0}).to_list(50)
    return {"fees": fees}
