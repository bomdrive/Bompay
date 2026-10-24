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

    amount_naira = amount_kobo / 100.0
    session_id = f"cs_{_secrets.token_urlsafe(16)}"
    expires_in = 3600  # 1 hour
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat()
    external_ref = f"cs-{session_id}"

    # Safe Haven settlement account
    settings = await db.provider_settings.find_one({"provider": "safehaven"})
    settlement_id = (settings or {}).get("settlement_account_id", "") or \
                    os.environ.get("SAFEHAVEN_SETTLEMENT_ACCOUNT_ID", "")

    cb_url = (WEBHOOK_BASE_URL or "").rstrip("/") + "/api/webhooks/safehaven"
    sh_payload = {
        "validFor": expires_in,
        "amount": amount_naira,
        "amountControl": "Fixed",
        "externalReference": external_ref,
    }
    if cb_url and cb_url != "/api/webhooks/safehaven":
        sh_payload["callbackUrl"] = cb_url
    if settlement_id:
        sh_payload["settlementAccount"] = {"_id": settlement_id}

    sh = {
        "sh_virtual_account_id": "",
        "sh_account_number": "",
        "sh_bank_name": "Safe Haven MFB",
        "sh_bank_code": SAFEHAVEN_BANK_CODE,
        "sh_account_name": "Bompay Checkout",
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
                "sh_account_name": data.get("accountName", "Bompay Checkout"),
            })
    except Exception as e:
        logger.warning(f"[MK-CHECKOUT] SH VA creation failed {source_type}/{source_id}: {e}")

    now = _now()
    doc = {
        "session_id": session_id,
        "merchant_id": merchant_id,
        "business_name": merchant.get("business_name", ""),
        "mode": environment,
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
    logger.info(f"[MK-CHECKOUT] session={session_id} {source_type}/{source_id}")
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
