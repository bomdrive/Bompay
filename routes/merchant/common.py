"""
Shared helpers for Merchant service modules (storefront + payment links).
"""
import os, secrets as _secrets
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from database import db
from core import call_sh, logger

SAFEHAVEN_BANK_CODE = os.environ.get("SAFEHAVEN_BANK_CODE", "090286")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_merchant_name(merchant_id: str, merchant_doc: dict) -> str:
    """
    Resolve the merchant's display business name.
    Priority: merchants.business_name → users.business_name → users.company_name → users.full_name
    """
    name = (merchant_doc or {}).get("business_name", "").strip()
    if name:
        return name
    # Fall back to the users collection
    user = await db.users.find_one({"merchant_id": merchant_id}) or \
           await db.users.find_one({"_id": merchant_id}) or {}
    return (
        user.get("business_name") or
        user.get("company_name") or
        user.get("full_name") or
        user.get("email") or
        "Merchant"
    ).strip()


async def _build_settlement_account_for_merchant(merchant_id: str) -> dict:
    """
    Build the Safe Haven settlementAccount payload for a checkout virtual account.
    Funds settle to the merchant's own Safe Haven account (primary wallet).
    Falls back to the platform-configured settlement account.
    """
    # 1. Merchant's own Safe Haven account
    wallet = await db.wallets.find_one({"user_id": merchant_id}) or \
             await db.wallets.find_one({"merchant_id": merchant_id})
    merchant_sh_acct = (wallet or {}).get("sh_account_number", "").strip()
    merchant_bank_code = (wallet or {}).get("sh_bank_code", SAFEHAVEN_BANK_CODE).strip() or SAFEHAVEN_BANK_CODE

    if merchant_sh_acct:
        logger.info(f"[MK-CHECKOUT] Settlement → merchant acct {merchant_sh_acct} (mid={merchant_id[:8]}...)")
        return {"bankCode": merchant_bank_code, "accountNumber": merchant_sh_acct}

    # 2. Platform fallback
    settings = await db.provider_settings.find_one({"provider": "safehaven"}) or {}
    raw = (settings.get("settlement_account_id") or "").strip()
    fallback = (settings.get("account_number") or "").strip() or \
               os.environ.get("SAFEHAVEN_SETTLEMENT_ACCOUNT_ID", "").strip()
    account_number = raw if (raw.isdigit() and 7 <= len(raw) <= 12) else fallback
    if not account_number:
        return {}
    bank_code = (settings.get("settlement_bank_code") or "").strip() or SAFEHAVEN_BANK_CODE
    logger.warning(f"[MK-CHECKOUT] Merchant {merchant_id[:8]} has no SH wallet — using platform fallback {account_number}")
    return {"bankCode": bank_code, "accountNumber": account_number}


async def _resolve_merchant_mode(merchant_id: str, requested_environment: str) -> str:
    """
    Determine the correct checkout mode (live/sandbox).
    If the merchant has a live-approved account, use 'live' regardless of the stored
    payment link environment default.  This prevents live merchants seeing TEST MODE.
    """
    if requested_environment == "live":
        return "live"
    # Check if the merchant's account is KYB-approved / live-enabled
    merchant = await db.merchants.find_one({"merchant_id": merchant_id}) or {}
    merchant_mode = merchant.get("mode") or merchant.get("account_mode") or ""
    if merchant_mode == "live":
        return "live"
    # Also check users collection for live status
    user = await db.users.find_one({"merchant_id": merchant_id}) or {}
    if user.get("kyb_status") == "approved" or user.get("mode") == "live":
        return "live"
    return "sandbox"


async def _mk_checkout_session(
    merchant_id: str,
    environment: str,
    amount_kobo: int,
    customer_info: dict,
    source_type: str,
    source_id: str,
    redirect_url: str = "",
    description: str = "",
) -> dict:
    """
    Create a hosted checkout session for a storefront order or payment link attempt.
    Reuses the existing checkout_sessions collection and Safe Haven virtual account flow.
    Returns: {session_id, checkout_url, bank_transfer{...}, expires_at}
    """
    merchant = await db.merchants.find_one({"merchant_id": merchant_id})
    if not merchant:
        raise HTTPException(400, "Merchant not found")

    FRONTEND_URL = os.environ.get("FRONTEND_URL", "")
    WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", "")

    # Resolve mode — never show TEST MODE to live merchants
    resolved_mode = await _resolve_merchant_mode(merchant_id, environment)

    # Resolve business name
    business_name = await _get_merchant_name(merchant_id, merchant)

    amount_naira = amount_kobo / 100.0
    session_id = f"cs_{_secrets.token_urlsafe(16)}"
    expires_in = 3600  # 1 hour
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
    external_ref = f"cs-{session_id}"

    # Safe Haven settlement account — uses merchant's own account
    sa = await _build_settlement_account_for_merchant(merchant_id)

    cb_url = (WEBHOOK_BASE_URL or "").rstrip("/") + "/api/webhooks/safehaven"
    sh_payload = {
        "validFor": expires_in,
        "amount": amount_naira,
        "amountControl": "Fixed",
        "externalReference": external_ref,
    }
    if cb_url and cb_url != "/api/webhooks/safehaven":
        sh_payload["callbackUrl"] = cb_url
    if sa:
        sh_payload["settlementAccount"] = sa
        logger.info(f"[MK-CHECKOUT] settlementAccount bankCode={sa.get('bankCode')} acct={sa.get('accountNumber')}")

    sh = {
        "sh_virtual_account_id": "",
        "sh_account_number": "",
        "sh_bank_name": "Safe Haven MFB",
        "sh_bank_code": SAFEHAVEN_BANK_CODE,
        "sh_account_name": f"{business_name} Payment",
        "external_reference": external_ref,
    }
    try:
        resp = await call_sh("POST", "/virtual-accounts", body=sh_payload)
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        if data:
            sh.update({
                "sh_virtual_account_id": data.get("_id", ""),
                "sh_account_number": data.get("accountNumber", ""),
                "sh_bank_name": data.get("bankName", "Safe Haven MFB"),
                "sh_account_name": data.get("accountName", f"{business_name} Payment"),
            })
    except Exception as e:
        logger.warning(f"[MK-CHECKOUT] SH VA creation failed {source_type}/{source_id}: {e}")

    now = _now()
    doc = {
        "session_id": session_id,
        "merchant_id": merchant_id,
        "business_name": business_name,
        "mode": resolved_mode,
        "amount_kobo": amount_kobo,
        "amount_naira": amount_naira,
        "currency": "NGN",
        "email": customer_info.get("email", ""),
        "customer_name": customer_info.get("name", ""),
        "reference": source_id,
        "success_url": redirect_url,
        "cancel_url": "",
        "metadata": {
            "source_type": source_type,
            "source_id": source_id,
            "description": description,
        },
        "expires_in": expires_in,
        "expires_at": expires_at,
        "status": "pending",
        **sh,
        "created_at": now,
        "updated_at": now,
        "paid_at": None,
        "webhook_payload": None,
    }
    await db.checkout_sessions.insert_one(doc)

    checkout_url = (FRONTEND_URL or "").rstrip("/") + f"/checkout/{session_id}"
    logger.info(f"[MK-CHECKOUT] session={session_id} mode={resolved_mode} {source_type}/{source_id}")
    return {
        "session_id": session_id,
        "checkout_url": checkout_url,
        "bank_transfer": {
            "account_number": sh["sh_account_number"],
            "bank_name": sh["sh_bank_name"],
            "bank_code": sh["sh_bank_code"],
            "account_name": sh["sh_account_name"],
            "amount": amount_naira,
        },
        "expires_at": expires_at,
    }
