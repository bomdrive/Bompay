"""
Strowallet Provider Module
Helpers for: Bank Transfer, Airtime, Data, Cable TV
All functions read the API key from DB (admin-configurable) or env fallback.
"""

import os, logging
import httpx
from fastapi import HTTPException
from database import db

logger = logging.getLogger(__name__)
STROW_BASE = "https://strowallet.com/api"


async def _strow_pub() -> str:
    """Get Strowallet public key — DB override takes precedence over env."""
    cfg = await db.card_config.find_one({"_id": "global"})
    return (cfg or {}).get("strowallet_public_key") or os.environ.get("STROWALLET_PUBLIC_KEY", "")


async def _call(method: str, path: str, *, params: dict = None, body: dict = None) -> dict:
    pub = await _strow_pub()
    if not pub:
        raise HTTPException(503, "Strowallet API key not configured. Set it in Admin → Virtual Cards → Config.")
    p = {**(params or {}), "public_key": pub}
    url = f"{STROW_BASE}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=30) as c:
        if method == "GET":
            r = await c.get(url, params=p)
        elif method == "POST":
            bd = {**(body or {}), "public_key": pub}
            r = await c.post(url, json=bd, params=params)
        else:
            raise ValueError(f"Unsupported method {method}")
    if r.status_code >= 500:
        logger.error("[STROW] %s %s → %d %s", method, path, r.status_code, r.text[:400])
        raise HTTPException(502, f"Strowallet error (HTTP {r.status_code})")
    try:
        data = r.json()
    except Exception:
        raise HTTPException(502, "Strowallet returned non-JSON")
    if not data.get("success", True):
        msg = data.get("message") or data.get("msg") or "Strowallet request failed"
        logger.warning("[STROW] fail path=%s msg=%s", path, msg)
        raise HTTPException(400, msg)
    return data


# ── Transfer ─────────────────────────────────────────────────────────────────

async def strow_name_enquiry(bank_code: str, account_number: str) -> dict:
    """
    Returns {"account_name": str, "session_id": str}
    """
    data = await _call("GET", "banks/get-customer-name", params={
        "bank_code": bank_code,
        "account_number": account_number,
    })
    # Strowallet returns: {"status": true, "account_name": "JOHN DOE", "account_number": "..."}
    name = data.get("account_name") or data.get("name") or data.get("data", {}).get("account_name", "")
    return {
        "account_name": name,
        "session_id": data.get("session_id") or f"STROW_{account_number}",
    }


async def strow_bank_transfer(
    amount: float,
    bank_code: str,
    account_number: str,
    narration: str,
    payment_reference: str,
    sender_name: str = "BOMPAY",
    name_enquiry_ref: str = "",
) -> dict:
    """
    Execute a bank transfer via Strowallet.
    Returns {"reference": str, "raw": dict}
    """
    body = {
        "amount": str(int(amount)),
        "bank_code": bank_code,
        "account_number": account_number,
        "narration": narration[:60] if narration else "BOMPAY Transfer",
        "SenderName": sender_name[:40],
        "payment_reference": payment_reference,
    }
    if name_enquiry_ref:
        body["name_enquiry_reference"] = name_enquiry_ref
    data = await _call("POST", "banks/request", body=body)
    ref = (
        data.get("data", {}).get("transaction_reference")
        or data.get("reference")
        or data.get("transaction_id")
        or payment_reference
    )
    return {"reference": str(ref), "raw": data}


# ── VAS: Airtime ──────────────────────────────────────────────────────────────

# Strowallet network slugs
STROW_AIRTIME_NETWORKS = {
    "MTN": "mtn", "GLO": "glo", "AIRTEL": "airtel", "ETISALAT": "etisalat", "9MOBILE": "etisalat",
}


async def strow_buy_airtime(phone: str, amount: float, network: str) -> dict:
    """Returns {"reference": str}"""
    net = STROW_AIRTIME_NETWORKS.get(network.upper(), network.lower())
    data = await _call("POST", "buyairtime/request", body={
        "amount": str(int(amount)),
        "phone": phone,
        "service_name": net,
    })
    ref = data.get("reference") or data.get("transaction_id") or "STROW_ATM"
    return {"reference": str(ref), "raw": data}


# ── VAS: Data ─────────────────────────────────────────────────────────────────

# Strowallet data service_id slugs
STROW_DATA_SERVICE_IDS = {
    "MTN": "mtn-data", "GLO": "glo-data", "AIRTEL": "airtel-data",
    "ETISALAT": "etisalat-data", "9MOBILE": "etisalat-data",
    "SPECTRANET": "spectranet", "SMILE": "smile-direct",
}


async def strow_get_data_plans(network: str) -> list:
    """Fetch available data plans for a network."""
    service_id = STROW_DATA_SERVICE_IDS.get(network.upper(), f"{network.lower()}-data")
    try:
        data = await _call("GET", f"get-data-plans/{service_id}", params={})
        return data.get("data") or data.get("plans") or []
    except Exception as e:
        logger.warning("[STROW] get_data_plans failed: %s", e)
        return []


async def strow_buy_data(
    phone: str, amount: float, network: str,
    variation_code: str, service_name: str = ""
) -> dict:
    """Returns {"reference": str}"""
    service_id = STROW_DATA_SERVICE_IDS.get(network.upper(), f"{network.lower()}-data")
    sname = service_name or f"{network} Data"
    data = await _call("POST", "buydata/request", body={
        "amount": str(int(amount)),
        "phone": phone,
        "service_name": sname,
        "service_id": service_id,
        "variation_code": variation_code,
    })
    ref = data.get("reference") or data.get("transaction_id") or "STROW_DATA"
    return {"reference": str(ref), "raw": data}


# ── VAS: Cable TV ─────────────────────────────────────────────────────────────

STROW_CABLE_SERVICE_IDS = {
    "DSTV": "dstv", "GOTV": "gotv", "STARTIMES": "startimes", "SHOWMAX": "showmax",
}


async def strow_get_cable_plans(provider: str) -> list:
    """Fetch available cable plans."""
    service_id = STROW_CABLE_SERVICE_IDS.get(provider.upper(), provider.lower())
    try:
        data = await _call("GET", f"get-cabletv-plans/{service_id}", params={})
        return data.get("data") or data.get("plans") or []
    except Exception as e:
        logger.warning("[STROW] get_cable_plans failed: %s", e)
        return []


async def strow_verify_smartcard(provider: str, smartcard_number: str) -> str:
    """Returns account holder name for a smartcard number."""
    service_id = STROW_CABLE_SERVICE_IDS.get(provider.upper(), provider.lower())
    data = await _call("GET", "verify-smartcard-number", params={
        "service_id": service_id,
        "customer_id": smartcard_number,
    })
    name = (
        data.get("customer_name")
        or data.get("name")
        or (data.get("data") or {}).get("customer_name", "")
    )
    return name


async def strow_buy_cable(
    phone: str, amount: float, provider: str,
    variation_code: str, smartcard_number: str,
    service_name: str = ""
) -> dict:
    """Returns {"reference": str}"""
    service_id = STROW_CABLE_SERVICE_IDS.get(provider.upper(), provider.lower())
    sname = service_name or provider
    data = await _call("POST", "cable-subscription/request", body={
        "amount": str(int(amount)),
        "phone": phone,
        "service_name": sname,
        "service_id": service_id,
        "variation_code": variation_code,
        "customer_id": smartcard_number,
    })
    ref = data.get("reference") or data.get("transaction_id") or "STROW_CABLE"
    return {"reference": str(ref), "raw": data}


# ── Education ─────────────────────────────────────────────────────────────────

EDUCATION_PRODUCTS = [
    {
        "id": "waec-direct",
        "exam_body": "WAEC",
        "label": "WAEC Result Checker",
        "description": "Purchase WAEC scratch card to check your result",
        "service_name": "waec",
        "variation_code": "waecdirect",
        "default_amount": 3700,
        "icon": "waec",
    },
    {
        "id": "jamb-utme",
        "exam_body": "JAMB",
        "label": "JAMB UTME Mock Test",
        "description": "JAMB Unified Tertiary Matriculation Examination mock test",
        "service_name": "jamb",
        "variation_code": "utme",
        "default_amount": 3500,
        "icon": "jamb",
    },
    {
        "id": "jamb-de",
        "exam_body": "JAMB",
        "label": "JAMB Direct Entry",
        "description": "JAMB Direct Entry examination",
        "service_name": "jamb",
        "variation_code": "de-original",
        "default_amount": 3500,
        "icon": "jamb",
    },
    {
        "id": "neco-checker",
        "exam_body": "NECO",
        "label": "NECO Result Checker",
        "description": "NECO result checker scratch card",
        "service_name": "neco",
        "variation_code": "neco-result-checker",
        "default_amount": 1500,
        "icon": "neco",
    },
    {
        "id": "nabteb-checker",
        "exam_body": "NABTEB",
        "label": "NABTEB Result Checker",
        "description": "NABTEB result checker scratch card",
        "service_name": "nabteb",
        "variation_code": "nabteb",
        "default_amount": 1500,
        "icon": "nabteb",
    },
]


async def strow_buy_education(
    phone: str,
    amount: float,
    service_name: str,
    variation_code: str,
) -> dict:
    """Purchase education scratch card (WAEC, JAMB, NECO, NABTEB) via Strowallet."""
    data = await _call("POST", "educational/request", body={
        "amount": str(int(amount)),
        "phone": phone,
        "service_name": service_name,
        "variation_code": variation_code,
    })
    ref = data.get("reference") or data.get("transaction_id") or data.get("requestId") or f"EDU_{service_name.upper()}"
    return {"reference": str(ref), "raw": data}
