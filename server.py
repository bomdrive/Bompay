"""Bompay — Production-grade Nigerian Fintech API (Entry Point)"""
from dotenv import load_dotenv
import re
load_dotenv()

import os, uuid, logging, asyncio
from datetime import datetime, timezone
from pathlib import Path
from bson import ObjectId
import cloudinary

from fastapi import FastAPI, APIRouter, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
import ledger as pg_ledger

from database import db, db_client
from core import (
    hash_password, verify_password, gen_account_number,
    ADMIN_EMAIL, ADMIN_PASSWORD, SAFEHAVEN_BASE_URL, FRONTEND_URL,
    WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN, WEBAUTHN_RP_NAME,
    APP_NAME, EMERGENT_LLM_KEY, get_current_user,
)
from rate_limit import limiter

# ===== APP SETUP =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
ROOT_DIR = Path(__file__).parent

_API_DESCRIPTION = """
## Bompay — Nigerian Financial Super-App & Merchant Services Platform

BOMPAY provides virtual accounts, bank transfers, bill payments, hosted checkout, and a full 
commerce suite for merchants in Nigeria.

---

### Authentication
Bompay uses **cookie-based JWT authentication**. Every protected endpoint expects one of the 
following cookies to be present in the request:

| Cookie | Scope |
|---|---|
| `access_token` | Consumer user endpoints (`/api/auth/*`, `/api/transfers/*`, etc.) |
| `merchant_access_token` | Merchant dashboard endpoints (`/api/v1/merchant/*`) |
| `access_token` (admin role) | Admin console endpoints (`/api/admin/*`) |

To authenticate from a REST client, first call the relevant login endpoint and capture the 
`Set-Cookie` header, then replay the cookie on subsequent requests.

---

### Base URLs
| Environment | Base URL |
|---|---|
| Production | `https://bompay.app` |
| Preview | `https://bompay-ledger.preview.emergentagent.com` |

---

### Amounts
All monetary amounts are expressed in **kobo** (1 NGN = 100 kobo) as integers.  
Never use floating-point values for money fields.
"""

_OPENAPI_TAGS = [
    {"name": "Auth",          "description": "Consumer user registration, login, token refresh, MFA"},
    {"name": "Wallet",        "description": "Virtual accounts, balances, funding, account management"},
    {"name": "Transfers",     "description": "Bank transfers, name-enquiry, beneficiaries, bank health"},
    {"name": "Transactions",  "description": "Transaction history, receipts, disputes"},
    {"name": "VAS",           "description": "Value-Added Services — airtime, data, electricity, cable TV"},
    {"name": "Merchant",      "description": "Merchant auth, dashboard, settings, team members, KYB"},
    {"name": "Checkout",      "description": "Hosted checkout sessions and payment processing"},
    {"name": "Storefront",    "description": "E-commerce stores, products, inventory, orders"},
    {"name": "Payment Links", "description": "Fixed, variable, and invoice payment links"},
    {"name": "Fraud",         "description": "Risk assessment, consumer disputes, velocity rules"},
    {"name": "KYC",           "description": "Identity verification (BVN/NIN/Gov ID) and face liveness"},
    {"name": "Admin",         "description": "Admin-only platform management, KYB decisions, fee rules"},
    {"name": "Notifications", "description": "Push subscriptions and in-app notification feeds"},
    {"name": "Webhooks",      "description": "Webhook endpoint management and delivery logs"},
    {"name": "Support",       "description": "Customer support tickets, live chat sessions"},
    {"name": "ePOS",          "description": "Electronic Point-of-Sale activation and QR payments"},
    {"name": "Savings",       "description": "Savings plans and goals"},
    {"name": "Rewards",       "description": "Cashback, referral rewards, points redemption"},
    {"name": "Cards",         "description": "Virtual card issuance and management"},
    {"name": "Blog",          "description": "Public blog posts and articles"},
    {"name": "Health",        "description": "Service health and readiness checks"},
]

app = FastAPI(
    title="Bompay API",
    version="1.0.0",
    description=_API_DESCRIPTION,
    contact={"name": "Bompay Developer Support", "url": "https://bompay.app/developers", "email": "developers@bompay.app"},
    license_info={"name": "Proprietary", "url": "https://bompay.app/legal"},
    docs_url=None, redoc_url=None, openapi_url=None,  # disabled — protected endpoints below
)
api_router = APIRouter(prefix="/api")

# ===== RATE LIMITER =====
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please try again later."})

app.add_middleware(SlowAPIMiddleware)

# ===== CORS =====
# EXTRA_ORIGINS: comma-separated list of additional allowed origins (set in Railway env)
_extra = [o.strip() for o in os.environ.get("EXTRA_ORIGINS", "").split(",") if o.strip()]
allowed_origins = list({
    FRONTEND_URL,
    "http://localhost:3000",
    "https://bompay-ledger.preview.emergentagent.com",
    "https://bompay.app",
    "https://www.bompay.app",
    *_extra,
})
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)

# ===== SECURITY HEADERS =====
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    response.headers.setdefault("Cache-Control", "no-store")
    # Prevent server fingerprinting
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ===== RBAC MIDDLEWARE =====
@app.middleware("http")
async def rbac_permission_middleware(request: Request, call_next):
    """
    Enforce route-level permissions for team members (member_access tokens).
    Business owners (merchant_access tokens) pass through immediately.
    Public routes, admin routes, and non-merchant routes are not affected.
    """
    path = request.url.path
    method = request.method

    # Fully public routes that must never be gated by RBAC — even if a stale
    # member_access cookie is present (e.g. invite accept, team login, PIN setup)
    PUBLIC_MERCHANT_PATHS = (
        "/api/v1/merchant/team/invite/accept",
        "/api/v1/merchant/team/login",
        "/api/v1/merchant/team/set-pin",
        "/api/v1/merchant/team/verify-pin",
        "/api/v1/merchant/login",
        "/api/v1/merchant/verify-pin",
        "/api/v1/merchant/refresh",
        "/api/v1/merchant/team/invite/info",
    )
    if any(path.startswith(p) for p in PUBLIC_MERCHANT_PATHS):
        return await call_next(request)

    # Only enforce on merchant-facing API routes
    merchant_prefixes = (
        "/api/v1/merchant/",
        "/api/v1/stores",
        "/api/v1/payment-links",
        "/api/v1/orders",
        "/api/v1/customers",
    )
    if not any(path.startswith(pfx) for pfx in merchant_prefixes):
        return await call_next(request)

    # Only enforce for non-public routes (public routes have no auth cookie)
    token = request.cookies.get("merchant_access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return await call_next(request)  # let the route handler raise 401

    # Only check team member tokens; owners bypass all permission checks
    try:
        import jwt as pyjwt
        from core import JWT_SECRET, JWT_ALGORITHM
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return await call_next(request)  # invalid/expired token — route handler handles it

    if payload.get("type") != "member_access":
        return await call_next(request)  # business owner — no permission check needed

    # Resolve required permissions for this route
    from routes.merchant.route_permissions import get_required_permissions
    required = get_required_permissions(method, path)
    if not required:
        return await call_next(request)  # no restriction defined

    # Fetch member's permissions from DB
    try:
        member_id = payload.get("sub", "")
        merchant_id = payload.get("merchant_id", "")
        member = await db.merchant_members.find_one(
            {"member_id": member_id, "merchant_id": merchant_id}
        )
        if not member or member.get("status") != "active":
            return JSONResponse(status_code=403, content={"detail": "Team member account not active"})

        role_id = member.get("role_id", "")
        role = await db.merchant_roles.find_one(
            {"role_id": role_id, "$or": [
                {"is_system": True}, {"merchant_id": merchant_id}
            ]}
        )
        member_perms = set(role.get("permissions", [])) if role else set()
        missing = [p for p in required if p not in member_perms]
        if missing:
            return JSONResponse(
                status_code=403,
                content={"detail": f"Insufficient permissions: {', '.join(missing)}"}
            )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(f"[RBAC middleware] Error: {exc}")

    return await call_next(request)

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    msgs = [f"{'.'.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": "; ".join(msgs)})

# ===== CUSTOM OPENAPI SCHEMA =====
from fastapi.openapi.utils import get_openapi

def _build_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        contact=app.contact,
        license_info=app.license_info,
        routes=app.routes,
        tags=_OPENAPI_TAGS,
    )
    schema.setdefault("components", {})
    schema["components"]["securitySchemes"] = {
        "UserCookie": {
            "type": "apiKey",
            "in": "cookie",
            "name": "access_token",
            "description": "JWT issued on consumer login (`POST /api/auth/login`)",
        },
        "MerchantCookie": {
            "type": "apiKey",
            "in": "cookie",
            "name": "merchant_access_token",
            "description": "JWT issued on merchant login (`POST /api/v1/merchant/login`)",
        },
    }
    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = _build_openapi

# ===== PROTECTED API DOCS (admin only) =====
ENABLE_DOCS = os.environ.get("ENABLE_DOCS", "false").lower() == "true"

_DOCS_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bompay API — Admin Sign In</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0B1F3A;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
  .card{background:#fff;border-radius:16px;padding:40px 36px;width:100%;max-width:380px;
        box-shadow:0 24px 64px rgba(0,0,0,.35)}
  .logo{display:flex;align-items:center;gap:10px;margin-bottom:28px}
  .logo-icon{width:38px;height:38px;background:#1240AB;border-radius:10px;display:flex;
             align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:16px}
  .logo-text{font-size:17px;font-weight:700;color:#0B1F3A}
  .logo-sub{font-size:11px;color:#64748B;margin-top:1px}
  h1{font-size:20px;font-weight:700;color:#0B1F3A;margin-bottom:6px}
  p{font-size:13px;color:#64748B;margin-bottom:28px}
  label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px;letter-spacing:.4px}
  input{width:100%;padding:12px 14px;border:1.5px solid #E5E7EB;border-radius:10px;
        font-size:14px;color:#111;outline:none;transition:border-color .15s}
  input:focus{border-color:#1240AB}
  .field{margin-bottom:18px}
  .btn{width:100%;padding:13px;background:#1240AB;color:#fff;border:none;border-radius:10px;
       font-size:15px;font-weight:700;cursor:pointer;margin-top:8px;transition:background .15s}
  .btn:hover{background:#0f3590}
  .btn:disabled{background:#93a8d6;cursor:not-allowed}
  .err{background:#FEF2F2;color:#B91C1C;border:1px solid #FECACA;border-radius:8px;
       padding:10px 14px;font-size:13px;margin-top:14px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">B</div>
    <div>
      <div class="logo-text">Bompay API</div>
      <div class="logo-sub">Admin access required</div>
    </div>
  </div>
  <h1>Sign in to continue</h1>
  <p>Use your Bompay admin credentials to access the API documentation.</p>
  <form id="f">
    <div class="field">
      <label for="email">EMAIL ADDRESS</label>
      <input id="email" type="email" placeholder="admin@bompay.app" autocomplete="username" required>
    </div>
    <div class="field">
      <label for="pass">PASSWORD</label>
      <input id="pass" type="password" placeholder="Enter your password" autocomplete="current-password" required>
    </div>
    <button class="btn" id="btn" type="submit">Sign In</button>
    <div class="err" id="err"></div>
  </form>
</div>
<script>
document.getElementById('f').addEventListener('submit', async function(e){
  e.preventDefault();
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  btn.disabled = true; btn.textContent = 'Signing in…'; err.style.display = 'none';
  try {
    const res = await fetch('/api/auth/login', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({email: document.getElementById('email').value,
                            password: document.getElementById('pass').value})
    });
    const data = await res.json();
    if (res.ok && data.role === 'admin') {
      window.location.href = '/api/docs';
    } else if (res.ok && data.role && data.role !== 'admin') {
      err.textContent = 'Access denied — admin account required.';
      err.style.display = 'block';
    } else {
      err.textContent = data.detail || 'Invalid email or password.';
      err.style.display = 'block';
    }
  } catch(ex) {
    err.textContent = 'Network error. Please try again.';
    err.style.display = 'block';
  }
  btn.disabled = false; btn.textContent = 'Sign In';
});
</script>
</body>
</html>"""


@app.get("/api/docs/login", include_in_schema=False)
async def docs_login_page(request: Request):
    if not ENABLE_DOCS:
        raise HTTPException(404, "Not found")
    # If already authenticated as admin, redirect straight to docs
    try:
        user = await get_current_user(request)
        if user.get("role") == "admin":
            return RedirectResponse("/api/docs")
    except Exception:
        pass
    return HTMLResponse(_DOCS_LOGIN_HTML)

@app.get("/api/docs", include_in_schema=False)
async def admin_swagger(request: Request):
    if not ENABLE_DOCS:
        raise HTTPException(404, "Not found")
    try:
        user = await get_current_user(request)
    except Exception:
        return RedirectResponse("/api/docs/login")
    if user.get("role") != "admin":
        return RedirectResponse("/api/docs/login")
    return get_swagger_ui_html(openapi_url="/api/openapi.json", title="Bompay API Docs")

@app.get("/api/redoc", include_in_schema=False)
async def admin_redoc(request: Request):
    if not ENABLE_DOCS:
        raise HTTPException(404, "Not found")
    try:
        user = await get_current_user(request)
    except Exception:
        return RedirectResponse("/api/docs/login")
    if user.get("role") != "admin":
        return RedirectResponse("/api/docs/login")
    return get_redoc_html(openapi_url="/api/openapi.json", title="Bompay API ReDoc")

@app.get("/api/openapi.json", include_in_schema=False)
async def admin_openapi(request: Request):
    if not ENABLE_DOCS:
        raise HTTPException(404, "Not found")
    try:
        user = await get_current_user(request)
    except Exception:
        raise HTTPException(401, "Not authenticated")
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin access required")
    return JSONResponse(app.openapi())

# ===== REGISTER ROUTERS =====
from routes import (
    auth, wallet, transfers, transactions, vas,
    savings, loans, rewards, notifications, ajo,
    admin, webhooks, blog, support, cron,
    push, epos, promotions, family, business, cards, merchant, checkout, chat,
    kyc_liveness, fraud,
)

_router_tags: dict = {
    auth:         ["Auth"],
    wallet:       ["Wallet"],
    transfers:    ["Transfers"],
    transactions: ["Transactions"],
    vas:          ["VAS"],
    savings:      ["Savings"],
    loans:        ["Savings"],
    rewards:      ["Rewards"],
    notifications:["Notifications"],
    ajo:          ["Savings"],
    admin:        ["Admin"],
    webhooks:     ["Webhooks"],
    blog:         ["Blog"],
    support:      ["Support"],
    cron:         ["Health"],
    push:         ["Notifications"],
    epos:         ["ePOS"],
    promotions:   ["Rewards"],
    family:       ["Wallet"],
    business:     ["Merchant"],
    cards:        ["Cards"],
    merchant:     ["Merchant"],
    checkout:     ["Checkout"],
    chat:         ["Support"],
    kyc_liveness: ["KYC"],
    fraud:        ["Fraud"],
}

for mod in _router_tags:
    app.include_router(mod.router, prefix="/api", tags=_router_tags[mod])

# ===== HEALTH CHECK =====
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "bompay-api"}

# ===== STARTUP / SHUTDOWN =====
@app.on_event("startup")
async def startup():
    # Indexes
    await db.users.create_index("email", unique=True)
    await db.wallets.create_index("user_id", unique=True)
    await db.wallets.create_index("account_number", unique=True)
    await db.transactions.create_index("idempotency_key", unique=True, sparse=True)
    await db.transactions.create_index([("user_id", 1), ("created_at", -1)])
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.audit_logs.create_index([("user_id", 1), ("timestamp", -1)])
    await db.login_attempts.create_index("identifier")
    await db.name_enquiries.create_index("session_id", unique=True, sparse=True)
    await db.wallets.create_index("sh_account_number", sparse=True)
    await db.support_tickets.create_index([("user_id", 1), ("status", 1)])
    # Checkout sessions
    await db.checkout_sessions.create_index("session_id", unique=True)
    await db.checkout_sessions.create_index("external_reference", unique=True, sparse=True)
    await db.checkout_sessions.create_index([("merchant_id", 1), ("created_at", -1)])
    await db.checkout_sessions.create_index("sh_virtual_account_id", sparse=True)
    # Merchant fee rules
    await db.merchant_fee_rules.create_index("service", unique=True)
    # Chat sessions
    await db.chat_sessions.create_index("session_id", unique=True)
    await db.chat_sessions.create_index([("status", 1), ("last_message_at", -1)])
    await db.chat_messages.create_index([("session_id", 1), ("created_at", 1)])
    await db.support_messages.create_index([("ticket_id", 1), ("created_at", 1)])
    # Storefront
    await db.stores.create_index("store_id", unique=True)
    await db.stores.create_index([("merchant_id", 1), ("is_deleted", 1)])
    await db.stores.create_index("slug", unique=True, sparse=True)
    await db.products.create_index("product_id", unique=True)
    await db.products.create_index([("store_id", 1), ("status", 1)])
    await db.products.create_index([("store_id", 1), ("slug", 1)], unique=True, sparse=True)
    await db.store_orders.create_index("order_id", unique=True)
    await db.store_orders.create_index([("merchant_id", 1), ("created_at", -1)])
    await db.store_orders.create_index([("store_id", 1), ("payment_status", 1)])
    await db.store_orders.create_index("checkout_session_id", sparse=True)
    # Payment Links
    await db.payment_links.create_index("link_id", unique=True)
    await db.payment_links.create_index("code", unique=True)
    await db.payment_links.create_index([("merchant_id", 1), ("status", 1)])
    await db.payment_link_attempts.create_index("attempt_id", unique=True)
    await db.payment_link_attempts.create_index([("link_id", 1), ("status", 1)])
    await db.payment_link_attempts.create_index("checkout_session_id", sparse=True)
    # Storefront customers
    await db.storefront_customers.create_index([("merchant_id", 1), ("email", 1)], unique=True, sparse=True)
    # Discount codes
    await db.discount_codes.create_index([("store_id", 1), ("code", 1)], unique=True)
    await db.discount_codes.create_index([("store_id", 1), ("is_active", 1)])
    await db.ajo_groups.create_index("invite_code", unique=True, sparse=True)
    await db.ajo_groups.create_index([("creator_id", 1), ("status", 1)])
    await db.ajo_members.create_index([("group_id", 1), ("user_id", 1)], unique=True)
    await db.ajo_members.create_index([("user_id", 1), ("status", 1)])
    await db.ajo_contributions.create_index(
        [("group_id", 1), ("round", 1), ("period_index", 1), ("user_id", 1)], unique=True)
    await db.ajo_contributions.create_index("idempotency_key", unique=True, sparse=True)
    await db.ajo_payouts.create_index(
        [("group_id", 1), ("round", 1), ("period_index", 1)], unique=True, sparse=True)
    await db.otp_sessions.create_index("phone")
    await db.otp_sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.biometric_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.webauthn_challenges.create_index("expires_at", expireAfterSeconds=0)

    # ── Fraud & Risk collections ──────────────────────────────────────────────
    await db.risk_assessments.create_index([("user_id", 1), ("created_at", -1)])
    await db.risk_assessments.create_index([("score", -1)])
    await db.risk_assessments.create_index("transaction_id", sparse=True)
    await db.disputes.create_index("dispute_id", unique=True)
    await db.disputes.create_index([("user_id", 1), ("created_at", -1)])
    await db.disputes.create_index([("status", 1), ("created_at", -1)])
    await db.fraud_rules.create_index("rule_id", unique=True)
    await db.reversal_records.create_index("transaction_id", unique=True, sparse=True)
    await db.reversal_records.create_index([("status", 1), ("created_at", -1)])
    await db.revoked_devices.create_index([("user_id", 1), ("device_id", 1)], unique=True)

    # Seed default fraud rules if none exist
    from routes.fraud import seed_default_rules
    await seed_default_rules()

    # ── RBAC collections ──────────────────────────────────────────────────────
    await db.merchant_members.create_index(
        [("merchant_id", 1), ("email", 1)], unique=True, sparse=True
    )
    await db.merchant_members.create_index("member_id", unique=True)
    await db.merchant_members.create_index([("merchant_id", 1), ("status", 1)])
    await db.merchant_roles.create_index("role_id", unique=True, sparse=True)
    await db.merchant_roles.create_index([("merchant_id", 1), ("is_system", 1)])
    await db.merchant_invitations.create_index("token_hash", unique=True, sparse=True)
    await db.merchant_invitations.create_index("invitation_id", unique=True)
    await db.merchant_invitations.create_index([("merchant_id", 1), ("status", 1)])
    await db.merchant_audit_logs.create_index([("merchant_id", 1), ("created_at", -1)])
    await db.merchant_transfer_approvals.create_index("approval_id", unique=True)
    await db.merchant_transfer_approvals.create_index([("merchant_id", 1), ("status", 1)])

    # ── Seed system roles ─────────────────────────────────────────────────────
    from routes.merchant.permissions import SYSTEM_ROLES
    now_str = datetime.now(timezone.utc).isoformat()
    for role_id, rdata in SYSTEM_ROLES.items():
        existing_role = await db.merchant_roles.find_one({"role_id": role_id, "is_system": True})
        if not existing_role:
            await db.merchant_roles.insert_one({
                "role_id": role_id,
                "merchant_id": None,
                "name": rdata["name"],
                "description": rdata["description"],
                "permissions": rdata["permissions"],
                "is_system": True,
                "protected": rdata.get("protected", False),
                "created_at": now_str,
                "updated_at": now_str,
            })
        else:
            # Keep permissions up to date with code
            await db.merchant_roles.update_one(
                {"role_id": role_id, "is_system": True},
                {"$set": {
                    "permissions": rdata["permissions"],
                    "name": rdata["name"],
                    "description": rdata["description"],
                    "updated_at": now_str,
                }}
            )

    # Clear legacy WebAuthn credentials registered with wrong RP_ID (old Railway URL)
    # Safe to run repeatedly — only deletes credentials tied to old RP origins
    if os.environ.get("WEBAUTHN_CLEAR_LEGACY") == "true":
        result = await db.webauthn_credentials.delete_many({})
        await db.webauthn_challenges.delete_many({})
        print(f"[startup] Cleared {result.deleted_count} legacy WebAuthn credentials")

    # Seed admin
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if not existing:
        res = await db.users.insert_one({
            "email": ADMIN_EMAIL, "password_hash": hash_password(ADMIN_PASSWORD),
            "first_name": "Bompay", "last_name": "Admin", "phone": "+2348000000000",
            "role": "admin", "status": "ACTIVE", "kyc_tier": 3, "kyc_status": "VERIFIED",
            "reward_points": 0, "referral_code": "BOMPAY",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        uid = str(res.inserted_id)
        acct = gen_account_number()
        await db.wallets.insert_one({
            "user_id": uid, "account_number": acct, "available_balance": 1_000_000_00,
            "ledger_balance": 1_000_000_00, "pending_balance": 0, "held_balance": 0,
            "currency": "NGN", "status": "ACTIVE", "tier": 3,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
    elif not verify_password(ADMIN_PASSWORD, existing.get("password_hash", "")):
        await db.users.update_one({"email": ADMIN_EMAIL}, {"$set": {"password_hash": hash_password(ADMIN_PASSWORD)}})

    # Seed provider settings
    if not await db.provider_settings.find_one({"provider": "safehaven"}):
        await db.provider_settings.insert_one({
            "provider": "safehaven", "client_id": os.environ.get("SAFEHAVEN_CLIENT_ID", ""),
            "client_secret": os.environ.get("SAFEHAVEN_CLIENT_SECRET", ""),
            "base_url": SAFEHAVEN_BASE_URL, "mode": "sandbox", "status": "ACTIVE",
            "updated_at": datetime.now(timezone.utc).isoformat()
        })

    # Seed fee configs
    default_fees = [
        {
            "service": "TRANSFER", "fee_type": "TIERED", "flat_amount": 0, "percentage": 0,
            "min_fee": 10, "max_fee": 5000, "is_active": True,
            "tiers": [
                {"min": 0, "max": 5000, "fee": 10},
                {"min": 5000, "max": 50000, "fee": 25},
                {"min": 50000, "max": 200000, "fee": 50},
                {"min": 200000, "max": 10000000, "fee": 100}
            ],
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "service": "BETTING", "fee_type": "FLAT", "flat_amount": 0, "percentage": 0,
            "min_fee": 0, "max_fee": 0, "is_active": False, "tiers": [],
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "service": "BOMPAY_TRANSFER", "fee_type": "TIERED", "flat_amount": 0, "percentage": 0,
            "min_fee": 0, "max_fee": 100, "is_active": True,
            "tiers": [
                {"min": 0, "max": 5000, "fee": 0},
                {"min": 5000, "max": 50000, "fee": 10},
                {"min": 50000, "max": 200000, "fee": 25},
                {"min": 200000, "max": 10000000, "fee": 50}
            ],
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
    ]
    for fc in default_fees:
        if not await db.fee_configs.find_one({"service": fc["service"]}):
            await db.fee_configs.insert_one(fc)

    # Seed default merchant platform fee rules (all services)
    default_merchant_fees = [
        {
            "service": "CHECKOUT",
            "fee_type": "FLAT_PLUS_PCT",
            "flat_kobo": 10000,     # ₦100
            "percentage": 1.5,
            "min_fee_kobo": 10000,
            "max_fee_kobo": 500000, # ₦5,000 cap
            "is_active": True,
            "description": "Hosted checkout session — bank transfer or Pay with Bompay",
        },
        {
            "service": "PAY_WITH_BOMPAY",
            "fee_type": "FLAT_PLUS_PCT",
            "flat_kobo": 0,
            "percentage": 0.5,
            "min_fee_kobo": 0,
            "max_fee_kobo": 200000,  # ₦2,000 cap
            "is_active": True,
            "description": "Checkout paid via Bompay wallet OTP debit",
        },
        {
            "service": "MERCHANT_TRANSFER",
            "fee_type": "FLAT",
            "flat_kobo": 5300,      # ₦53 NIP fee
            "percentage": 0.0,
            "min_fee_kobo": 5300,
            "max_fee_kobo": 5300,
            "is_active": True,
            "description": "NIP outward bank transfer",
        },
        {
            "service": "VIRTUAL_ACCOUNT",
            "fee_type": "FLAT",
            "flat_kobo": 0,
            "percentage": 0.0,
            "min_fee_kobo": 0,
            "max_fee_kobo": 0,
            "is_active": False,
            "description": "Merchant virtual account provisioning (no fee by default)",
        },
        {
            "service": "AIRTIME",
            "fee_type": "PERCENTAGE",
            "flat_kobo": 0,
            "percentage": 2.0,
            "min_fee_kobo": 0,
            "max_fee_kobo": 100000,
            "is_active": False,
            "description": "Airtime top-up (inactive by default)",
        },
        {
            "service": "DATA",
            "fee_type": "PERCENTAGE",
            "flat_kobo": 0,
            "percentage": 2.0,
            "min_fee_kobo": 0,
            "max_fee_kobo": 100000,
            "is_active": False,
            "description": "Mobile data bundle purchase (inactive by default)",
        },
        {
            "service": "ELECTRICITY",
            "fee_type": "FLAT_PLUS_PCT",
            "flat_kobo": 10000,     # ₦100
            "percentage": 0.5,
            "min_fee_kobo": 10000,
            "max_fee_kobo": 200000,
            "is_active": False,
            "description": "Electricity token/bill payment (inactive by default)",
        },
        {
            "service": "CABLE_TV",
            "fee_type": "FLAT",
            "flat_kobo": 10000,     # ₦100
            "percentage": 0.0,
            "min_fee_kobo": 10000,
            "max_fee_kobo": 10000,
            "is_active": False,
            "description": "Cable TV subscription (DSTV, GOtv, StarTimes — inactive by default)",
        },
        {
            "service": "BANK_VERIFICATION",
            "fee_type": "FLAT",
            "flat_kobo": 5000,      # ₦50
            "percentage": 0.0,
            "min_fee_kobo": 5000,
            "max_fee_kobo": 5000,
            "is_active": False,
            "description": "BVN/account name enquiry (inactive by default)",
        },
        {
            "service": "MERCHANT_WALLET_FUNDING",
            "fee_type": "PERCENTAGE",
            "flat_kobo": 0,
            "percentage": 0.0,
            "min_fee_kobo": 0,
            "max_fee_kobo": 0,
            "is_active": False,
            "description": "Inbound credit to merchant virtual account (no fee by default)",
        },
        {
            "service": "STOREFRONT",
            "fee_type": "FLAT_PLUS_PCT",
            "flat_kobo": 5000,       # ₦50 flat
            "percentage": 1.0,
            "min_fee_kobo": 5000,
            "max_fee_kobo": 300000,  # ₦3,000 cap
            "is_active": True,
            "description": "BOMPAY Storefront — per order checkout fee",
        },
        {
            "service": "PAYMENT_LINK",
            "fee_type": "FLAT_PLUS_PCT",
            "flat_kobo": 0,
            "percentage": 1.5,
            "min_fee_kobo": 10000,   # ₦100 min
            "max_fee_kobo": 500000,  # ₦5,000 cap
            "is_active": True,
            "description": "BOMPAY Payment Links — per transaction fee",
        },
    ]
    for fee in default_merchant_fees:
        if not await db.merchant_fee_rules.find_one({"service": fee["service"]}):
            await db.merchant_fee_rules.insert_one({
                **fee,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "updated_by": "system",
            })
    try:
        cld_doc = await db.admin_settings.find_one({"key": "cloudinary"})
        if cld_doc and cld_doc.get("cloud_name"):
            cloudinary.config(
                cloud_name=cld_doc["cloud_name"],
                api_key=cld_doc["api_key"],
                api_secret=cld_doc.get("api_secret", ""),
                secure=True
            )
        cloudinary_ok = bool(os.environ.get("CLOUDINARY_CLOUD_NAME") or (cld_doc and cld_doc.get("cloud_name")))
        logger.info(f"Cloudinary storage {'configured' if cloudinary_ok else 'NOT configured'}")
    except Exception as e:
        logger.error(f"[Cloudinary] Init check failed: {e}")

    # Seed KYC tier configs
    default_kyc_configs = [
        {"tier": 0, "name": "Unverified", "description": "Phone registration only. No transfers.", "daily_transfer_limit_naira": 0, "single_transfer_limit_naira": 0},
        {"tier": 1, "name": "Tier 1 — Basic", "description": "BVN/NIN verified via Safe Haven. Virtual account created.", "daily_transfer_limit_naira": 50000, "single_transfer_limit_naira": 10000},
        {"tier": 2, "name": "Tier 2 — Verified", "description": "Government-issued ID uploaded and verified.", "daily_transfer_limit_naira": 500000, "single_transfer_limit_naira": 100000},
        {"tier": 3, "name": "Tier 3 — Premium", "description": "Passport + liveness selfie face-matched by AI.", "daily_transfer_limit_naira": 5000000, "single_transfer_limit_naira": 1000000},
    ]
    for cfg in default_kyc_configs:
        if not await db.kyc_tier_configs.find_one({"tier": cfg["tier"]}):
            await db.kyc_tier_configs.insert_one({**cfg, "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": "system"})

    # Seed default admin roles
    default_roles = [
        {"name": "super_admin", "description": "Full access to all console features", "permissions": ["all"], "is_system": True},
        {"name": "kyc_officer", "description": "Manage KYC submissions and verifications", "permissions": ["kyc", "users"], "is_system": True},
        {"name": "support", "description": "View users and transactions, handle disputes", "permissions": ["users", "transactions", "reports"], "is_system": True},
        {"name": "finance", "description": "Financial operations, charge accounts, fee settings", "permissions": ["transactions", "reports", "financial"], "is_system": True},
        {"name": "fraud_analyst", "description": "Fraud management and investigation tools", "permissions": ["fraud", "users", "transactions", "reports"], "is_system": True},
    ]
    for role in default_roles:
        if not await db.admin_roles.find_one({"name": role["name"]}):
            await db.admin_roles.insert_one({**role, "created_at": datetime.now(timezone.utc).isoformat()})

    await db.users.update_many({"role": "admin", "admin_role": {"$exists": False}}, {"$set": {"admin_role": "super_admin"}})

    # Migrate old admin email
    old_admin_email = "percosoerp@gmail.com"
    if ADMIN_EMAIL != old_admin_email:
        old_doc = await db.users.find_one({"email": old_admin_email, "role": "admin"})
        if old_doc:
            new_exists = await db.users.find_one({"email": ADMIN_EMAIL})
            if not new_exists:
                await db.users.update_one(
                    {"email": old_admin_email, "role": "admin"},
                    {"$set": {"email": ADMIN_EMAIL}}
                )
            else:
                await db.users.delete_one({"email": old_admin_email, "role": "admin"})

    # Init MongoDB ledger
    try:
        await pg_ledger.init_schema()
    except Exception as e:
        logger.error(f"[Ledger] MongoDB init failed: {e}")

    # Write test credentials
    creds_path = Path("/app/memory/test_credentials.md")
    creds_path.parent.mkdir(exist_ok=True)
    creds_path.write_text(f"""# Bompay Test Credentials\n\n## Admin Account\n- Email: {ADMIN_EMAIL}\n- Password: {ADMIN_PASSWORD}\n- Role: admin\n\n## Auth Endpoints\n- POST /api/auth/register\n- POST /api/auth/login\n- POST /api/auth/logout\n- GET /api/auth/me\n- POST /api/auth/refresh\n\n## Test Flow\n1. Login at /auth\n2. Dashboard at /dashboard\n3. Admin panel at /admin (admin only)\n""")

    logger.info("Bompay API started successfully")

    # Seed blog posts
    try:
        from routes.blog import seed_blogs
        await seed_blogs()
    except Exception as e:
        logger.error(f"[Blog] Seed failed: {e}")


@app.on_event("shutdown")
async def shutdown():
    db_client.close()
