"""Investor Centre — authentication (separate from main BOMPAY auth)."""
import os, bcrypt, jwt, logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from bson import ObjectId
from database import db

router = APIRouter()
logger = logging.getLogger(__name__)

ALG   = "HS256"
COOKIE = "investor_token"
TYPE   = "investor_access"

# ── helpers ────────────────────────────────────────────────────────────────────

def _secret():   return os.environ["JWT_SECRET"]

def _hash(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def _verify(pw, hashed):
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

def _make_token(uid: str, email: str, role: str) -> str:
    payload = {
        "sub":  uid,
        "email": email,
        "role": role,
        "type": TYPE,
        "exp":  datetime.now(timezone.utc) + timedelta(hours=12),
    }
    return jwt.encode(payload, _secret(), algorithm=ALG)

def _set_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE, value=token,
        httponly=True, secure=True, samesite="none",
        max_age=43200, path="/",
    )

async def get_investor_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        ah = request.headers.get("Authorization", "")
        if ah.startswith("Bearer "):
            token = ah[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, _secret(), algorithms=[ALG])
        if payload.get("type") != TYPE:
            raise HTTPException(401, "Invalid token")
        doc = await db.investor_users.find_one({"_id": ObjectId(payload["sub"])})
        if not doc:
            raise HTTPException(401, "User not found")
        doc["id"] = str(doc.pop("_id"))
        doc.pop("password_hash", None)
        return doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

async def require_admin(request: Request) -> dict:
    user = await get_investor_user(request)
    if user.get("role") not in ("super_admin", "ir_admin", "finance_admin", "compliance_admin"):
        raise HTTPException(403, "Admin access required")
    return user

# ── startup seed ───────────────────────────────────────────────────────────────

async def seed_investor_admin():
    email    = os.environ.get("INVESTOR_ADMIN_EMAIL", "investors@bompay.app")
    password = os.environ.get("INVESTOR_ADMIN_PASSWORD", "BompayIR@2024!")
    existing = await db.investor_users.find_one({"email": email})
    if not existing:
        await db.investor_users.insert_one({
            "email":         email,
            "password_hash": _hash(password),
            "name":          "Bompay IR Admin",
            "role":          "super_admin",
            "created_at":    datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"[InvestorAuth] Seeded super_admin: {email}")
    await db.investor_users.create_index("email", unique=True)

# ── request models ─────────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    email:    str
    password: str

class CreateUserIn(BaseModel):
    email:    str
    name:     str
    password: str
    role:     str = "investor"

# ── routes ─────────────────────────────────────────────────────────────────────

@router.post("/investors/auth/login")
async def investor_login(body: LoginIn, response: Response):
    email = body.email.strip().lower()
    user  = await db.investor_users.find_one({"email": email})
    if not user or not _verify(body.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid email or password")
    token = _make_token(str(user["_id"]), email, user.get("role", "investor"))
    _set_cookie(response, token)
    return {
        "id":    str(user["_id"]),
        "email": user["email"],
        "name":  user.get("name", ""),
        "role":  user.get("role", "investor"),
    }

@router.post("/investors/auth/logout")
async def investor_logout(response: Response):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}

@router.get("/investors/auth/me")
async def investor_me(request: Request):
    return await get_investor_user(request)

@router.post("/investors/auth/users")
async def create_investor_user(request: Request, body: CreateUserIn):
    await require_admin(request)
    email = body.email.strip().lower()
    if await db.investor_users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    await db.investor_users.insert_one({
        "email":         email,
        "password_hash": _hash(body.password),
        "name":          body.name,
        "role":          body.role,
        "created_at":    datetime.now(timezone.utc).isoformat(),
    })
    return {"ok": True, "email": email}

@router.get("/investors/auth/users")
async def list_investor_users(request: Request):
    await require_admin(request)
    users = await db.investor_users.find({}, {"_id": 1, "email": 1, "name": 1, "role": 1, "created_at": 1}).to_list(100)
    for u in users:
        u["id"] = str(u.pop("_id"))
    return {"users": users}

@router.delete("/investors/auth/users/{user_id}")
async def delete_investor_user(request: Request, user_id: str):
    await require_admin(request)
    await db.investor_users.delete_one({"_id": ObjectId(user_id)})
    return {"ok": True}
