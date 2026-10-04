"""Bompay — Production-grade Nigerian Fintech API (Entry Point)"""
from dotenv import load_dotenv
import re
load_dotenv()

import os, uuid, logging, asyncio
from datetime import datetime, timezone
from pathlib import Path
from bson import ObjectId
import cloudinary

from fastapi import FastAPI, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import ledger as pg_ledger

from database import db, db_client
from core import (
    hash_password, verify_password, gen_account_number,
    ADMIN_EMAIL, ADMIN_PASSWORD, SAFEHAVEN_BASE_URL, FRONTEND_URL,
    WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN, WEBAUTHN_RP_NAME,
    APP_NAME, EMERGENT_LLM_KEY,
)

# ===== APP SETUP =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
ROOT_DIR = Path(__file__).parent

app = FastAPI(title="Bompay API", version="1.0.0")
api_router = APIRouter(prefix="/api")

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
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    msgs = [f"{'.'.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": "; ".join(msgs)})

# ===== REGISTER ROUTERS =====
from routes import (
    auth, wallet, transfers, transactions, vas,
    savings, loans, rewards, notifications, ajo,
    admin, webhooks, blog, support, cron,
    push, epos, promotions, family, business, cards,
)

for mod in [
    auth, wallet, transfers, transactions, vas,
    savings, loans, rewards, notifications, ajo,
    admin, webhooks, blog, support, cron,
    push, epos, promotions, family, business, cards,
]:
    app.include_router(mod.router, prefix="/api")

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
    await db.support_messages.create_index([("ticket_id", 1), ("created_at", 1)])
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

    # Init Cloudinary
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
