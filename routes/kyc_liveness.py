"""
BOMPAY — Tier 2 KYC Liveness Face Verification
Backend routes: session management, evidence upload, admin review.
"""
import os, secrets, asyncio, logging, random, requests
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import Response
from bson import ObjectId

from database import db
from core import get_current_user, APP_NAME

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Emergent Object Storage ───────────────────────────────────────────────────
EMERGENT_KEY  = os.environ.get("EMERGENT_LLM_KEY", "")
STORAGE_BASE  = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL   = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
_storage_key: Optional[str] = None

def _init_storage(force: bool = False) -> str:
    global _storage_key
    if _storage_key and not force:
        return _storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
    resp.raise_for_status()
    _storage_key = resp.json()["storage_key"]
    return _storage_key

def _put_object(path: str, data: bytes, content_type: str = "image/jpeg") -> dict:
    key = _init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data, timeout=60,
    )
    if resp.status_code == 404:
        key = _init_storage(force=True)
        resp = requests.put(
            f"{STORAGE_URL}/objects/{path}",
            headers={"X-Storage-Key": key, "Content-Type": content_type},
            data=data, timeout=60,
        )
    resp.raise_for_status()
    return resp.json()

def _get_object(path: str) -> tuple:
    key = _init_storage()
    resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    if resp.status_code == 404:
        key = _init_storage(force=True)
        resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "image/jpeg")

# ── Challenge definitions ─────────────────────────────────────────────────────
ALL_CHALLENGES = [
    {"id": "straight",    "instruction": "Look straight at the camera", "type": "pose"},
    {"id": "turn_left",   "instruction": "Turn your head to the left",  "type": "pose"},
    {"id": "turn_right",  "instruction": "Turn your head to the right", "type": "pose"},
    {"id": "look_up",     "instruction": "Look up",                     "type": "pose"},
    {"id": "look_down",   "instruction": "Look down",                   "type": "pose"},
    {"id": "smile",       "instruction": "Smile naturally",             "type": "expression"},
    {"id": "blink",       "instruction": "Blink both eyes slowly",      "type": "expression"},
]

def _make_challenge_sequence() -> list:
    """Always start with 'straight', then pick 3 random others."""
    rest     = [c for c in ALL_CHALLENGES if c["id"] != "straight"]
    selected = random.sample(rest, min(3, len(rest)))
    return [{"id": c["id"], "instruction": c["instruction"], "type": c["type"]}
            for c in [ALL_CHALLENGES[0]] + selected]

# ── Auto-approval logic ───────────────────────────────────────────────────────
def _evaluate_session(challenge_results: list, retry_count: int) -> tuple:
    """Returns (auto_approve: bool, confidence_score: float, liveness_result: str)."""
    if not challenge_results:
        return False, 0.0, "inconclusive"
    passed = sum(1 for r in challenge_results if r.get("result") == "passed")
    total  = len(challenge_results)
    rate   = passed / total if total else 0.0
    confidence = round(rate * 100, 1)
    if rate == 1.0 and retry_count == 0:
        return True, confidence, "passed"
    elif rate >= 0.75:
        return False, confidence, "flagged"
    else:
        return False, confidence, "failed"

# ── Audit helper ──────────────────────────────────────────────────────────────
async def _audit(verification_id: str, user_id: str, actor: str, action: str,
                 outcome: str = "ok", meta: dict = None):
    await db.kyc_liveness_audit.insert_one({
        "audit_id": f"KYC_A_{secrets.token_hex(5).upper()}",
        "verification_id": verification_id,
        "user_id": user_id,
        "actor": actor,
        "action": action,
        "outcome": outcome,
        "meta": meta or {},
        "ts": _now(),
    })

# ─────────────────────────────────────────────────────────────────────────────
# USER ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/kyc/liveness/session")
async def create_liveness_session(request: Request):
    """Create (or resume) a liveness verification session."""
    user = await get_current_user(request)
    uid  = str(user["_id"])

    if user.get("kyc_tier", 0) >= 2:
        raise HTTPException(400, "Tier 2 already completed")
    if user.get("kyc_tier", 0) < 1:
        raise HTTPException(400, "Complete Tier 1 first before starting face verification")

    now = datetime.now(timezone.utc)
    # Resume active session if it hasn't expired
    active = await db.kyc_liveness_sessions.find_one({
        "user_id": uid, "status": "in_progress",
        "expires_at": {"$gt": now.isoformat()},
    })
    if active:
        active.pop("_id", None)
        return active

    verification_id = f"KYC_V_{secrets.token_hex(8).upper()}"
    session_id      = f"KYC_S_{secrets.token_hex(8).upper()}"
    challenges      = _make_challenge_sequence()
    attempt_no      = await db.kyc_liveness_verifications.count_documents({"user_id": uid}) + 1

    session = {
        "session_id":      session_id,
        "verification_id": verification_id,
        "user_id":         uid,
        "status":          "in_progress",
        "challenges":      challenges,
        "current_index":   0,
        "challenge_results": [],
        "retry_count":     0,
        "attempt_number":  attempt_no,
        "created_at":      now.isoformat(),
        "expires_at":      (now + timedelta(minutes=15)).isoformat(),
        "evidence_ids":    [],
    }
    await db.kyc_liveness_sessions.insert_one(session)
    session.pop("_id", None)
    await _audit(verification_id, uid, uid, "session_created",
                 meta={"attempt_number": attempt_no, "challenges": [c["id"] for c in challenges]})
    return session


@router.get("/kyc/liveness/session/{session_id}")
async def get_liveness_session(session_id: str, request: Request):
    user    = await get_current_user(request)
    session = await db.kyc_liveness_sessions.find_one({"session_id": session_id, "user_id": str(user["_id"])})
    if not session:
        raise HTTPException(404, "Session not found")
    session.pop("_id", None)
    return session


@router.post("/kyc/liveness/session/{session_id}/upload-frame")
async def upload_challenge_frame(
    session_id:       str,
    request:          Request,
    challenge_id:     str   = Form(...),
    challenge_result: str   = Form(...),   # "passed" | "failed"
    confidence:       float = Form(0.0),
    retry_count:      int   = Form(0),
    duration_ms:      int   = Form(0),
    frame:            UploadFile = File(...),
):
    user    = await get_current_user(request)
    uid     = str(user["_id"])
    session = await db.kyc_liveness_sessions.find_one({"session_id": session_id, "user_id": uid})
    if not session:
        raise HTTPException(404, "Session not found")
    if session["status"] != "in_progress":
        raise HTTPException(400, "Session is not active")
    if (session.get("expires_at") or "") < datetime.now(timezone.utc).isoformat():
        await db.kyc_liveness_sessions.update_one({"session_id": session_id}, {"$set": {"status": "expired"}})
        raise HTTPException(410, "Session expired — please start again")

    ct = frame.content_type or "image/jpeg"
    if ct not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(400, "Frame must be JPEG, PNG or WebP")
    data = await frame.read()
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(400, "Frame too large — max 5 MB")

    evidence_id  = f"KYC_E_{secrets.token_hex(6).upper()}"
    storage_path = f"{APP_NAME}/kyc/liveness/{uid}/{session['verification_id']}/{challenge_id}_{evidence_id}.jpg"
    try:
        result = _put_object(storage_path, data, "image/jpeg")
    except Exception as e:
        logger.error(f"[KYC Liveness] Frame upload failed: {e}")
        raise HTTPException(500, "Frame upload failed — please try again")

    await db.kyc_liveness_evidence.insert_one({
        "evidence_id":        evidence_id,
        "verification_id":    session["verification_id"],
        "user_id":            uid,
        "session_id":         session_id,
        "challenge_id":       challenge_id,
        "storage_path":       result["path"],
        "content_type":       "image/jpeg",
        "size":               len(data),
        "challenge_result":   challenge_result,
        "confidence":         confidence,
        "captured_at":        _now(),
        "is_deleted":         False,
    })

    await db.kyc_liveness_sessions.update_one(
        {"session_id": session_id},
        {
            "$push": {
                "challenge_results": {
                    "challenge_id":    challenge_id,
                    "result":          challenge_result,
                    "confidence":      confidence,
                    "retry_count":     retry_count,
                    "duration_ms":     duration_ms,
                    "evidence_id":     evidence_id,
                    "recorded_at":     _now(),
                },
                "evidence_ids": evidence_id,
            },
            "$set": {"current_index": session["current_index"] + 1},
        },
    )
    await _audit(session["verification_id"], uid, uid, "challenge_frame_uploaded",
                 meta={"challenge_id": challenge_id, "result": challenge_result, "confidence": round(confidence, 3)})
    return {"ok": True, "evidence_id": evidence_id}


@router.post("/kyc/liveness/session/{session_id}/complete")
async def complete_liveness_session(session_id: str, request: Request):
    """Finalise the session: evaluate challenges and set verification status."""
    user    = await get_current_user(request)
    uid     = str(user["_id"])
    session = await db.kyc_liveness_sessions.find_one({"session_id": session_id, "user_id": uid})
    if not session:
        raise HTTPException(404, "Session not found")
    if session["status"] != "in_progress":
        raise HTTPException(400, "Session already finalised")
    if (session.get("expires_at") or "") < datetime.now(timezone.utc).isoformat():
        await db.kyc_liveness_sessions.update_one({"session_id": session_id}, {"$set": {"status": "expired"}})
        raise HTTPException(410, "Session expired — please start again")

    results     = session.get("challenge_results", [])
    retry_total = sum(r.get("retry_count", 0) for r in results)
    auto_ok, confidence, liveness_result = _evaluate_session(results, retry_total)
    final_status = "approved" if auto_ok else "pending_admin_review"
    now_ts = _now()

    passed = sum(1 for r in results if r.get("result") == "passed")
    total  = len(session["challenges"])

    verification = {
        "verification_id":   session["verification_id"],
        "user_id":           uid,
        "session_id":        session_id,
        "kyc_tier":          2,
        "attempt_number":    session.get("attempt_number", 1),
        "challenges":        session["challenges"],
        "challenge_results": results,
        "evidence_ids":      session.get("evidence_ids", []),
        "total_challenges":  total,
        "passed_challenges": passed,
        "failed_challenges": total - passed,
        "confidence_score":  confidence,
        "liveness_result":   liveness_result,
        "retry_count":       retry_total,
        "status":            final_status,
        "auto_approved":     auto_ok,
        "submitted_at":      now_ts,
        "reviewed_at":       now_ts if auto_ok else None,
        "reviewed_by":       "system" if auto_ok else None,
        "admin_notes":       [],
        "rejection_reason":  None,
    }
    await db.kyc_liveness_verifications.insert_one(verification)
    await db.kyc_liveness_sessions.update_one(
        {"session_id": session_id},
        {"$set": {"status": "completed", "completed_at": now_ts}},
    )

    if auto_ok:
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"kyc_tier": 2, "kyc_status": "TIER_2_VERIFIED", "kyc_tier2_at": now_ts}},
        )
        try:
            from routes.admin import _send_tier_approval_email
            asyncio.create_task(_send_tier_approval_email(uid, 2))
        except Exception as e:
            logger.warning(f"[KYC Liveness] Approval email task failed: {e}")

    await _audit(session["verification_id"], uid, uid, "session_completed",
                 outcome=final_status,
                 meta={"auto_approved": auto_ok, "confidence": confidence,
                       "passed": passed, "total": total})
    return {
        "ok":              True,
        "verification_id": session["verification_id"],
        "status":          final_status,
        "auto_approved":   auto_ok,
        "confidence_score": confidence,
        "message":         "Verification approved!" if auto_ok else
                           "Submitted for review. We'll notify you within 24 hours.",
    }


@router.get("/kyc/liveness/my-status")
async def my_liveness_status(request: Request):
    user = await get_current_user(request)
    uid  = str(user["_id"])
    latest = await db.kyc_liveness_verifications.find_one(
        {"user_id": uid}, sort=[("submitted_at", -1)]
    )
    if latest:
        latest.pop("_id", None)
        latest.pop("evidence_ids", None)
    active = await db.kyc_liveness_sessions.find_one({
        "user_id": uid, "status": "in_progress",
        "expires_at": {"$gt": datetime.now(timezone.utc).isoformat()},
    })
    if active:
        active.pop("_id", None)
    return {
        "kyc_tier":             user.get("kyc_tier", 0),
        "kyc_status":           user.get("kyc_status", "PENDING"),
        "latest_verification":  latest,
        "active_session":       active,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

async def _get_admin_user(request: Request):
    from routes.merchant.legacy import _get_admin
    return await _get_admin(request)


@router.get("/admin/kyc-liveness/list")
async def admin_list_liveness(
    request:         Request,
    page:            int = 1,
    per_page:        int = 20,
    status:          str = "",
    liveness_result: str = "",
):
    await _get_admin_user(request)
    query: dict = {}
    if status:
        query["status"] = status
    if liveness_result:
        query["liveness_result"] = liveness_result

    total = await db.kyc_liveness_verifications.count_documents(query)
    skip  = (page - 1) * per_page
    docs  = await db.kyc_liveness_verifications.find(query)\
        .sort("submitted_at", -1).skip(skip).limit(per_page).to_list(per_page)

    rows = []
    for doc in docs:
        u = await db.users.find_one({"_id": ObjectId(doc["user_id"])},
                                    {"name": 1, "email": 1, "phone": 1})
        rows.append({
            "verification_id":   doc["verification_id"],
            "user_id":           doc["user_id"],
            "user_name":         (u or {}).get("name", ""),
            "user_email":        (u or {}).get("email", ""),
            "user_phone":        (u or {}).get("phone", ""),
            "status":            doc["status"],
            "liveness_result":   doc.get("liveness_result", ""),
            "confidence_score":  doc.get("confidence_score", 0),
            "auto_approved":     doc.get("auto_approved", False),
            "attempt_number":    doc.get("attempt_number", 1),
            "passed_challenges": doc.get("passed_challenges", 0),
            "total_challenges":  doc.get("total_challenges", 0),
            "submitted_at":      doc.get("submitted_at", ""),
        })

    stats = {
        "total":          await db.kyc_liveness_verifications.count_documents({}),
        "pending_review": await db.kyc_liveness_verifications.count_documents({"status": "pending_admin_review"}),
        "approved":       await db.kyc_liveness_verifications.count_documents({"status": "approved"}),
        "rejected":       await db.kyc_liveness_verifications.count_documents({"status": "rejected"}),
        "retry_required": await db.kyc_liveness_verifications.count_documents({"status": "retry_required"}),
    }
    return {
        "verifications": rows,
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "stats": stats,
    }


@router.get("/admin/kyc-liveness/{verification_id}/detail")
async def admin_get_liveness_detail(verification_id: str, request: Request):
    await _get_admin_user(request)
    doc = await db.kyc_liveness_verifications.find_one({"verification_id": verification_id})
    if not doc:
        raise HTTPException(404, "Verification not found")
    doc.pop("_id", None)

    u = await db.users.find_one(
        {"_id": ObjectId(doc["user_id"])},
        {"name": 1, "email": 1, "phone": 1, "kyc_tier": 1, "kyc_status": 1, "created_at": 1},
    )
    if u:
        u.pop("_id", None)

    evidence = await db.kyc_liveness_evidence.find(
        {"verification_id": verification_id, "is_deleted": False}
    ).to_list(50)
    for e in evidence:
        e.pop("_id", None)
        e.pop("storage_path", None)   # serve via /admin/kyc-liveness/evidence/{id}

    audit = await db.kyc_liveness_audit.find(
        {"verification_id": verification_id}
    ).sort("ts", 1).to_list(200)
    for a in audit:
        a.pop("_id", None)

    return {**doc, "user": u, "evidence": evidence, "audit_trail": audit}


@router.get("/admin/kyc-liveness/evidence/{evidence_id}")
async def admin_serve_evidence(evidence_id: str, request: Request):
    await _get_admin_user(request)
    ev = await db.kyc_liveness_evidence.find_one({"evidence_id": evidence_id, "is_deleted": False})
    if not ev:
        raise HTTPException(404, "Evidence not found")
    try:
        data, ct = _get_object(ev["storage_path"])
    except Exception as e:
        logger.error(f"[KYC Liveness] Evidence fetch failed for {evidence_id}: {e}")
        raise HTTPException(500, "Could not retrieve evidence")
    return Response(content=data, media_type="image/jpeg",
                    headers={"Cache-Control": "no-store", "Content-Disposition": "inline"})


@router.post("/admin/kyc-liveness/{verification_id}/approve")
async def admin_approve_liveness(verification_id: str, request: Request):
    admin = await _get_admin_user(request)
    body  = await request.json()
    note  = (body.get("note") or "Manually approved by admin").strip()
    doc   = await db.kyc_liveness_verifications.find_one({"verification_id": verification_id})
    if not doc:
        raise HTTPException(404, "Verification not found")
    if doc["status"] == "approved":
        raise HTTPException(400, "Already approved")
    now_ts = _now()
    await db.kyc_liveness_verifications.update_one(
        {"verification_id": verification_id},
        {
            "$set":  {"status": "approved", "reviewed_at": now_ts, "reviewed_by": admin.get("email", "admin")},
            "$push": {"admin_notes": {"note": note, "by": admin.get("email", "admin"), "at": now_ts}},
        },
    )
    await db.users.update_one(
        {"_id": ObjectId(doc["user_id"])},
        {"$set": {"kyc_tier": 2, "kyc_status": "TIER_2_VERIFIED", "kyc_tier2_at": now_ts}},
    )
    try:
        from routes.admin import _send_tier_approval_email
        asyncio.create_task(_send_tier_approval_email(doc["user_id"], 2))
    except Exception:
        pass
    await _audit(verification_id, doc["user_id"], admin.get("email", "admin"), "admin_approved",
                 outcome="approved", meta={"note": note})
    return {"ok": True, "status": "approved"}


@router.post("/admin/kyc-liveness/{verification_id}/reject")
async def admin_reject_liveness(verification_id: str, request: Request):
    admin  = await _get_admin_user(request)
    body   = await request.json()
    reason = (body.get("reason") or "").strip()
    if not reason:
        raise HTTPException(400, "Rejection reason is required")
    doc = await db.kyc_liveness_verifications.find_one({"verification_id": verification_id})
    if not doc:
        raise HTTPException(404, "Verification not found")
    now_ts = _now()
    await db.kyc_liveness_verifications.update_one(
        {"verification_id": verification_id},
        {
            "$set": {
                "status": "rejected", "rejection_reason": reason,
                "reviewed_at": now_ts, "reviewed_by": admin.get("email", "admin"),
            },
            "$push": {"admin_notes": {"note": f"Rejected: {reason}", "by": admin.get("email", "admin"), "at": now_ts}},
        },
    )
    await _audit(verification_id, doc["user_id"], admin.get("email", "admin"), "admin_rejected",
                 outcome="rejected", meta={"reason": reason})
    return {"ok": True, "status": "rejected"}


@router.post("/admin/kyc-liveness/{verification_id}/retry")
async def admin_request_retry(verification_id: str, request: Request):
    admin  = await _get_admin_user(request)
    body   = await request.json()
    reason = (body.get("reason") or "Admin requested new attempt").strip()
    doc    = await db.kyc_liveness_verifications.find_one({"verification_id": verification_id})
    if not doc:
        raise HTTPException(404, "Verification not found")
    now_ts = _now()
    await db.kyc_liveness_verifications.update_one(
        {"verification_id": verification_id},
        {
            "$set": {"status": "retry_required", "reviewed_at": now_ts, "reviewed_by": admin.get("email", "admin")},
            "$push": {"admin_notes": {"note": f"Retry: {reason}", "by": admin.get("email", "admin"), "at": now_ts}},
        },
    )
    # Allow user to attempt again by resetting to Tier 1
    await db.users.update_one(
        {"_id": ObjectId(doc["user_id"])},
        {"$set": {"kyc_tier": 1, "kyc_status": "TIER_1_VERIFIED"}},
    )
    await _audit(verification_id, doc["user_id"], admin.get("email", "admin"), "retry_requested",
                 meta={"reason": reason})
    return {"ok": True, "status": "retry_required"}


@router.post("/admin/kyc-liveness/{verification_id}/note")
async def admin_add_note(verification_id: str, request: Request):
    admin = await _get_admin_user(request)
    body  = await request.json()
    note  = (body.get("note") or "").strip()
    if not note:
        raise HTTPException(400, "Note cannot be empty")
    doc   = await db.kyc_liveness_verifications.find_one({"verification_id": verification_id})
    if not doc:
        raise HTTPException(404, "Verification not found")
    now_ts = _now()
    await db.kyc_liveness_verifications.update_one(
        {"verification_id": verification_id},
        {"$push": {"admin_notes": {"note": note, "by": admin.get("email", "admin"), "at": now_ts}}},
    )
    await _audit(verification_id, doc["user_id"], admin.get("email", "admin"), "note_added")
    return {"ok": True}
