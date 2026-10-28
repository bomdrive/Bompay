"""
BOMPAY Fraud & Risk Management — Central Route
Covers: Risk Scoring Engine, Consumer Disputes, Admin Oversight, Rules Config,
        Device Management, Velocity Controls, Reversal Tracking
"""
from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from bson import ObjectId
import uuid

from database import db
from core import get_current_user, get_admin_user, audit, notify, send_email

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT FRAUD RULES  (seeded once into `fraud_rules` collection)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_RULES = [
    {
        "rule_id": "RULE_HIGH_VALUE",
        "name": "High-Value Transaction",
        "description": "Flag single transfers above the configured amount",
        "signal": "HIGH_VALUE_TRANSACTION",
        "condition": "amount_kobo > threshold_kobo",
        "threshold_kobo": 50_000_000,
        "risk_contribution": 30,
        "action": "alert",
        "severity": "moderate",
        "enabled": True,
    },
    {
        "rule_id": "RULE_RAPID_TRANSACTIONS",
        "name": "Rapid Transactions",
        "description": "Auto-block users sending more than N transactions per minute",
        "signal": "RAPID_TRANSACTIONS",
        "condition": "transaction_count > count_threshold within window_seconds",
        "count_threshold": 4,
        "window_seconds": 60,
        "risk_contribution": 50,
        "action": "auto_block",
        "severity": "critical",
        "enabled": True,
    },
    {
        "rule_id": "RULE_MULTIPLE_RECIPIENTS",
        "name": "Multiple Recipients",
        "description": "Flag transfers to many different bank accounts in a short window",
        "signal": "MULTIPLE_RECIPIENTS",
        "condition": "distinct_recipients >= count_threshold within window_minutes",
        "count_threshold": 3,
        "window_minutes": 5,
        "risk_contribution": 25,
        "action": "alert",
        "severity": "high",
        "enabled": True,
    },
    {
        "rule_id": "RULE_PIN_FAILURES",
        "name": "Excessive PIN Failures",
        "description": "Flag and block accounts with repeated wrong PIN entries",
        "signal": "EXCESSIVE_PIN_FAILURES",
        "condition": "pin_failed_attempts >= count_threshold",
        "count_threshold": 4,
        "risk_contribution": 40,
        "action": "alert",
        "severity": "high",
        "enabled": True,
    },
    {
        "rule_id": "RULE_RAPID_LOGIN",
        "name": "Rapid Login Attempts",
        "description": "Flag accounts with many logins from the same IP in a short window",
        "signal": "RAPID_LOGIN",
        "condition": "login_count > count_threshold within window_minutes",
        "count_threshold": 10,
        "window_minutes": 3,
        "risk_contribution": 20,
        "action": "alert",
        "severity": "moderate",
        "enabled": True,
    },
    {
        "rule_id": "RULE_HOURLY_VELOCITY",
        "name": "Hourly Transaction Velocity",
        "description": "Flag users sending more than N transactions per hour",
        "signal": "HOURLY_VELOCITY",
        "condition": "transaction_count > count_threshold within window_minutes",
        "count_threshold": 8,
        "window_minutes": 60,
        "risk_contribution": 35,
        "action": "alert",
        "severity": "high",
        "enabled": True,
    },
    {
        "rule_id": "RULE_DAILY_AMOUNT",
        "name": "Daily Transfer Cap",
        "description": "Flag when daily transfer total exceeds the configured limit",
        "signal": "DAILY_AMOUNT_EXCEEDED",
        "condition": "daily_total_kobo > threshold_kobo",
        "threshold_kobo": 50_000_000,
        "risk_contribution": 30,
        "action": "alert",
        "severity": "high",
        "enabled": True,
    },
    {
        "rule_id": "RULE_WEEKLY_AMOUNT",
        "name": "Weekly Transfer Cap",
        "description": "Flag when weekly transfer total exceeds the configured limit",
        "signal": "WEEKLY_AMOUNT_EXCEEDED",
        "condition": "weekly_total_kobo > threshold_kobo",
        "threshold_kobo": 200_000_000,
        "risk_contribution": 25,
        "action": "alert",
        "severity": "high",
        "enabled": True,
    },
]

RISK_BANDS = {
    "low":      (0,  24,  "allow",                 "text-emerald-700", "bg-emerald-50",  "border-emerald-200"),
    "moderate": (25, 49,  "allow_with_monitoring", "text-amber-700",   "bg-amber-50",    "border-amber-200"),
    "high":     (50, 74,  "require_step_up",       "text-orange-700",  "bg-orange-50",   "border-orange-200"),
    "critical": (75, 100, "block",                 "text-red-700",     "bg-red-50",      "border-red-200"),
}

async def _get_rules_map() -> dict:
    """Return {signal → rule} from DB, falling back to defaults."""
    rules = await db.fraud_rules.find({"enabled": True}).to_list(None)
    return {r["signal"]: r for r in rules} if rules else {r["signal"]: r for r in DEFAULT_RULES}

def _score_to_band(score: int) -> tuple[str, str]:
    for band, (lo, hi, decision, *_) in RISK_BANDS.items():
        if lo <= score <= hi:
            return band, decision
    return "critical", "block"

async def assess_transaction_risk(user_id: str, amount_kobo: int,
                                   txn_type: str = "TRANSFER", txn_id: str = None) -> dict:
    """
    Compute 0-100 risk score including velocity checks.
    Stores assessment in `risk_assessments` when score >= 25.
    Returns: {score, band, signals, decision, assessment_id}
    """
    from core import fraud_check_user
    signals = await fraud_check_user(user_id, amount_kobo)
    rules_map = await _get_rules_map()
    now = datetime.now(timezone.utc)

    # ── Velocity checks ──────────────────────────────────────────────────────
    try:
        uid_obj = ObjectId(user_id)
    except Exception:
        uid_obj = user_id

    # Hourly velocity
    hourly_rule = rules_map.get("HOURLY_VELOCITY") or {"count_threshold": 8, "window_minutes": 60}
    if hourly_rule.get("enabled", True):
        window_min = hourly_rule.get("window_minutes", 60)
        hourly_start = (now - timedelta(minutes=window_min)).isoformat()
        hourly_count = await db.transactions.count_documents({
            "user_id": uid_obj, "direction": "DEBIT",
            "status": {"$ne": "FAILED"}, "created_at": {"$gte": hourly_start},
        })
        if hourly_count >= hourly_rule.get("count_threshold", 8):
            signals.append("HOURLY_VELOCITY")

    # Weekly amount threshold
    weekly_rule = rules_map.get("WEEKLY_AMOUNT_EXCEEDED") or {"threshold_kobo": 200_000_000}
    if weekly_rule.get("enabled", True):
        week_start = (now - timedelta(days=7)).isoformat()
        weekly_agg = await db.transactions.aggregate([
            {"$match": {"user_id": uid_obj, "direction": "DEBIT",
                        "status": {"$ne": "FAILED"}, "created_at": {"$gte": week_start}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
        ]).to_list(1)
        weekly_total = weekly_agg[0]["total"] if weekly_agg else 0
        threshold = weekly_rule.get("threshold_kobo", 200_000_000)
        if weekly_total + amount_kobo > threshold:
            signals.append("WEEKLY_AMOUNT_EXCEEDED")

    # Daily amount threshold
    daily_rule = rules_map.get("DAILY_AMOUNT_EXCEEDED") or {"threshold_kobo": 50_000_000}
    if daily_rule.get("enabled", True):
        day_start = (now - timedelta(days=1)).isoformat()
        daily_agg = await db.transactions.aggregate([
            {"$match": {"user_id": uid_obj, "direction": "DEBIT",
                        "status": {"$ne": "FAILED"}, "created_at": {"$gte": day_start}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
        ]).to_list(1)
        daily_total = daily_agg[0]["total"] if daily_agg else 0
        if daily_total + amount_kobo > daily_rule.get("threshold_kobo", 50_000_000):
            signals.append("DAILY_AMOUNT_EXCEEDED")

    score = 0
    for signal in set(signals):
        rule = rules_map.get(signal, {})
        score += rule.get("risk_contribution", 20)
    score = min(score, 100)

    band, decision = _score_to_band(score)
    assessment_id = str(uuid.uuid4())

    if score >= 25 or signals:
        await db.risk_assessments.insert_one({
            "assessment_id": assessment_id,
            "user_id": user_id,
            "transaction_id": txn_id,
            "txn_type": txn_type,
            "amount_kobo": amount_kobo,
            "score": score,
            "band": band,
            "signals": list(set(signals)),
            "decision": decision,
            "reviewed": False,
            "created_at": now.isoformat(),
        })

    return {"assessment_id": assessment_id, "score": score, "band": band,
            "signals": list(set(signals)), "decision": decision}


# ─────────────────────────────────────────────────────────────────────────────
# SEED DEFAULT RULES
# ─────────────────────────────────────────────────────────────────────────────
async def seed_default_rules():
    """Insert default rules if collection is empty; upsert any missing rules."""
    now = datetime.now(timezone.utc).isoformat()
    count = await db.fraud_rules.count_documents({})
    if count == 0:
        docs = [{**r, "created_at": now, "updated_at": now, "version": 1,
                 "created_by": "system"} for r in DEFAULT_RULES]
        await db.fraud_rules.insert_many(docs)
    else:
        # Upsert any rules that may not yet exist (e.g. RULE_DAILY_AMOUNT added later)
        existing_ids = {r["rule_id"] async for r in db.fraud_rules.find({}, {"rule_id": 1})}
        for r in DEFAULT_RULES:
            if r["rule_id"] not in existing_ids:
                await db.fraud_rules.insert_one(
                    {**r, "created_at": now, "updated_at": now, "version": 1, "created_by": "system"}
                )


# ─────────────────────────────────────────────────────────────────────────────
# CONSUMER — DISPUTE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
DISPUTE_CATEGORIES = [
    "unauthorized_transaction",
    "transfer_failed_money_deducted",
    "wrong_recipient",
    "duplicate_charge",
    "merchant_did_not_deliver",
    "incorrect_amount",
    "refund_not_received",
    "pos_dispute",
    "card_funding_dispute",
    "other",
]

DISPUTE_CATEGORY_LABELS = {
    "unauthorized_transaction":    "I did not authorize this transaction",
    "transfer_failed_money_deducted": "Money was deducted but transfer failed",
    "wrong_recipient":             "I paid the wrong recipient",
    "duplicate_charge":            "I was charged twice",
    "merchant_did_not_deliver":    "Merchant did not deliver goods/service",
    "incorrect_amount":            "Incorrect transaction amount",
    "refund_not_received":         "Refund not received",
    "pos_dispute":                 "POS transaction issue",
    "card_funding_dispute":        "Card funding issue",
    "other":                       "Other transaction issue",
}

class DisputeCreate(BaseModel):
    transaction_id: str
    category: str
    description: str
    disputed_amount: Optional[float] = None

class DisputeAdminUpdate(BaseModel):
    status: Optional[str] = None
    note: Optional[str] = None
    resolution: Optional[str] = None
    resolution_type: Optional[str] = None   # confirmed_legitimate, refund_approved, rejected, etc.

class RuleUpdate(BaseModel):
    threshold_kobo: Optional[int] = None
    count_threshold: Optional[int] = None
    window_seconds: Optional[int] = None
    window_minutes: Optional[int] = None
    risk_contribution: Optional[int] = None
    enabled: Optional[bool] = None


@router.post("/fraud/dispute")
async def submit_dispute(req: DisputeCreate, request: Request):
    user = await get_current_user(request)
    if req.category not in DISPUTE_CATEGORIES:
        raise HTTPException(400, f"Invalid dispute category")
    if len(req.description.strip()) < 10:
        raise HTTPException(400, "Please describe the issue in at least 10 characters")

    # Find the transaction and verify ownership (handle both str and ObjectId user_id)
    txn = await db.transactions.find_one({"transaction_id": req.transaction_id})
    user_id_str = str(user["_id"])
    txn_user_id = str(txn.get("user_id","")) if txn else ""
    if not txn or txn_user_id != user_id_str:
        raise HTTPException(404, "Transaction not found")

    # Prevent duplicate active disputes
    existing = await db.disputes.find_one({
        "user_id": str(user["_id"]),
        "transaction_id": req.transaction_id,
        "status": {"$nin": ["resolved", "rejected", "closed"]},
    })
    if existing:
        raise HTTPException(409, "An active dispute already exists for this transaction")

    dispute_id = f"DSP-{str(uuid.uuid4())[:8].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "dispute_id": dispute_id,
        "user_id": str(user["_id"]),
        "user_name": f"{user.get('first_name','')} {user.get('last_name','')}".strip(),
        "user_email": user.get("email",""),
        "user_phone": user.get("phone",""),
        "transaction_id": req.transaction_id,
        "transaction_amount": txn.get("amount", 0),
        "transaction_type": txn.get("type",""),
        "transaction_date": txn.get("created_at",""),
        "category": req.category,
        "category_label": DISPUTE_CATEGORY_LABELS.get(req.category, req.category),
        "description": req.description.strip(),
        "disputed_amount": req.disputed_amount or (txn.get("amount", 0) / 100),
        "status": "submitted",
        "admin_notes": [],
        "timeline": [{"event": "Dispute submitted", "by": "user",
                       "timestamp": now, "note": req.description.strip()}],
        "created_at": now,
        "updated_at": now,
    }
    await db.disputes.insert_one(doc)
    await notify(str(user["_id"]), "Dispute Submitted",
        f"Your dispute {dispute_id} has been received. We'll review it within 24 hours.",
        "info", {"dispute_id": dispute_id})
    return {"dispute_id": dispute_id, "status": "submitted",
            "message": "Dispute submitted successfully. We'll review it within 24 hours."}


@router.get("/fraud/my-disputes")
async def my_disputes(request: Request):
    user = await get_current_user(request)
    raw = await db.disputes.find(
        {"user_id": str(user["_id"])}).sort("created_at", -1).to_list(50)
    disputes = []
    for d in raw:
        d["_id"] = str(d["_id"])
        disputes.append(d)
    return {"disputes": disputes}


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/fraud/overview")
async def fraud_overview(request: Request):
    await get_admin_user(request)
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()

    open_alerts   = await db.fraud_alerts.count_documents({"status": "OPEN"})
    blocked_users = await db.users.count_documents({"status": "SUSPENDED"})
    open_disputes = await db.disputes.count_documents({"status": {"$in": ["submitted", "under_review"]}})
    total_disputes= await db.disputes.count_documents({})
    resolved_disp = await db.disputes.count_documents({"status": "resolved"})
    auto_blocked_today = await db.fraud_alerts.count_documents({
        "auto_blocked": True, "created_at": {"$gte": today}})
    risk_queue_size = await db.risk_assessments.count_documents(
        {"score": {"$gte": 50}, "reviewed": False})

    # Risk band distribution (last 7 days)
    band_dist: dict = {"low": 0, "moderate": 0, "high": 0, "critical": 0}
    async for row in db.risk_assessments.aggregate([
        {"$match": {"created_at": {"$gte": week_ago}}},
        {"$group": {"_id": "$band", "count": {"$sum": 1}}}
    ]):
        band_dist[row["_id"]] = row["count"]

    # Total transactions assessed this week
    total_assessed = sum(band_dist.values())

    # Recent alerts (last 5)
    recent_alerts_raw = await db.fraud_alerts.find(
        {"status": "OPEN"}).sort("created_at", -1).to_list(5)
    recent_alerts = []
    for a in recent_alerts_raw:
        a["_id"] = str(a["_id"])
        if a.get("user_id"):
            u = await db.users.find_one({"_id": ObjectId(a["user_id"])},
                {"first_name":1,"last_name":1,"phone":1})
            if u:
                a["user_name"] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
                a["user_phone"] = u.get("phone","")
        recent_alerts.append(a)

    # Recent disputes (last 5)
    recent_disputes_raw = await db.disputes.find(
        {"status": {"$in": ["submitted","under_review"]}}).sort("created_at", -1).to_list(5)
    recent_disputes = [{**d, "_id": str(d["_id"])} for d in recent_disputes_raw]

    return {
        "stats": {
            "open_alerts": open_alerts,
            "blocked_users": blocked_users,
            "open_disputes": open_disputes,
            "total_disputes": total_disputes,
            "resolved_disputes": resolved_disp,
            "auto_blocked_today": auto_blocked_today,
            "risk_queue_size": risk_queue_size,
            "total_assessed_week": total_assessed,
        },
        "risk_band_distribution": band_dist,
        "recent_alerts": recent_alerts,
        "recent_disputes": recent_disputes,
        "reversal_stats": {
            "pending_count": await db.reversal_records.count_documents({"status": "pending_review"}),
            "amount_at_risk_kobo": (
                (await db.reversal_records.aggregate([
                    {"$match": {"status": "pending_review"}},
                    {"$group": {"_id": None, "total": {"$sum": "$amount_kobo"}}},
                ]).to_list(1) or [{}])[0].get("total", 0)
            ),
            "resolved_this_week": await db.reversal_records.count_documents({
                "status": {"$in": ["manual_refund", "retry", "write_off"]},
                "updated_at": {"$gte": week_ago},
            }),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — RISK ASSESSMENT QUEUE
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/fraud/risk-queue")
async def risk_queue(request: Request, band: str = "all", reviewed: str = "unreviewed",
                     limit: int = 50):
    await get_admin_user(request)
    q: dict = {}
    if band != "all" and band in ("low","moderate","high","critical"):
        q["band"] = band
    else:
        q["score"] = {"$gte": 25}       # default: moderate+
    if reviewed == "unreviewed":
        q["reviewed"] = False
    elif reviewed == "reviewed":
        q["reviewed"] = True

    raw = await db.risk_assessments.find(q).sort("score", -1).limit(limit).to_list(limit)
    results = []
    for a in raw:
        a["_id"] = str(a["_id"])
        if a.get("user_id"):
            try:
                u = await db.users.find_one({"_id": ObjectId(a["user_id"])},
                    {"first_name":1,"last_name":1,"phone":1,"email":1})
                if u:
                    a["user_name"]  = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
                    a["user_phone"] = u.get("phone","")
                    a["user_email"] = u.get("email","")
            except Exception:
                pass
        if a.get("transaction_id"):
            txn = await db.transactions.find_one({"transaction_id": a["transaction_id"]},
                {"type":1,"description":1,"status":1,"direction":1})
            if txn:
                a["txn_type"]   = txn.get("type","")
                a["txn_status"] = txn.get("status","")
                a["txn_desc"]   = txn.get("description","")
        results.append(a)
    return {"assessments": results, "total": len(results)}


@router.put("/admin/fraud/risk-queue/{assessment_id}/review")
async def mark_reviewed(assessment_id: str, request: Request):
    admin = await get_admin_user(request)
    body = await request.json()
    note = body.get("note","")
    await db.risk_assessments.update_one(
        {"assessment_id": assessment_id},
        {"$set": {"reviewed": True, "reviewed_by": str(admin["_id"]),
                  "review_note": note,
                  "reviewed_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "Marked as reviewed"}


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — DISPUTE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/fraud/disputes")
async def admin_list_disputes(request: Request, status: str = "all", limit: int = 100):
    await get_admin_user(request)
    q: dict = {}
    VALID_STATUSES = {"submitted","under_review","awaiting_info","pending_resolution",
                      "resolved","rejected","closed"}
    if status != "all" and status in VALID_STATUSES:
        q["status"] = status
    raw = await db.disputes.find(q).sort("created_at", -1).limit(limit).to_list(limit)
    return {"disputes": [{**d, "_id": str(d["_id"])} for d in raw],
            "total": len(raw)}


@router.get("/admin/fraud/disputes/{dispute_id}")
async def admin_dispute_detail(dispute_id: str, request: Request):
    await get_admin_user(request)
    d = await db.disputes.find_one({"dispute_id": dispute_id})
    if not d:
        raise HTTPException(404, "Dispute not found")
    d["_id"] = str(d["_id"])
    # Attach transaction detail
    if d.get("transaction_id"):
        txn = await db.transactions.find_one({"transaction_id": d["transaction_id"]})
        if txn:
            txn["_id"] = str(txn["_id"])
            d["transaction"] = txn
    return d


@router.put("/admin/fraud/disputes/{dispute_id}")
async def admin_update_dispute(dispute_id: str, req: DisputeAdminUpdate, request: Request):
    admin = await get_admin_user(request)
    d = await db.disputes.find_one({"dispute_id": dispute_id})
    if not d:
        raise HTTPException(404, "Dispute not found")

    VALID_STATUSES = {"submitted","under_review","awaiting_info","pending_resolution",
                      "resolved","rejected","closed"}
    if req.status and req.status not in VALID_STATUSES:
        raise HTTPException(400, "Invalid status")

    now = datetime.now(timezone.utc).isoformat()
    update: dict = {"updated_at": now}
    if req.status:
        update["status"] = req.status
    if req.resolution:
        update["resolution"] = req.resolution
    if req.resolution_type:
        update["resolution_type"] = req.resolution_type

    timeline_entry = {
        "timestamp": now,
        "by": f"admin:{str(admin.get('email',''))}",
    }
    if req.status:
        timeline_entry["event"] = f"Status changed to {req.status}"
    if req.note:
        timeline_entry["note"] = req.note
        timeline_entry["event"] = timeline_entry.get("event","") or "Admin note added"

    await db.disputes.update_one(
        {"dispute_id": dispute_id},
        {"$set": update, "$push": {"timeline": timeline_entry,
                                   "admin_notes": req.note} if req.note
                         else {"timeline": timeline_entry}},
    )

    # Notify user on status change — in-app + email
    if req.status and d.get("user_id"):
        status_msgs = {
            "under_review":  "Your dispute is now under review by our team.",
            "awaiting_info": "We need more information about your dispute. Please check the app.",
            "resolved":      f"Your dispute {dispute_id} has been resolved. {req.resolution or ''}",
            "rejected":      f"Your dispute {dispute_id} could not be upheld. {req.resolution or ''}",
        }
        msg = status_msgs.get(req.status)
        if msg:
            await notify(d["user_id"], f"Dispute Update ({dispute_id})", msg,
                         "info", {"dispute_id": dispute_id})
            # Also send email notification
            if d.get("user_email"):
                status_labels = {
                    "under_review":  "Under Review",
                    "awaiting_info": "More Information Needed",
                    "resolved":      "Resolved",
                    "rejected":      "Decision Made",
                }
                email_html = f"""
<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px">
  <div style="background:#064BCB;border-radius:12px;padding:20px 24px;margin-bottom:20px">
    <h2 style="color:#fff;margin:0;font-size:18px">BOMPAY — Dispute Update</h2>
    <p style="color:rgba(255,255,255,0.8);margin:4px 0 0;font-size:13px">Case {dispute_id}</p>
  </div>
  <p style="color:#1e293b;font-size:14px">Hi {d.get('user_name', 'Customer')},</p>
  <p style="color:#1e293b;font-size:14px">{msg}</p>
  {"<p style='color:#1e293b;font-size:14px'><strong>Resolution:</strong> " + req.resolution + "</p>" if req.resolution else ""}
  <div style="background:#f8fafc;border-radius:8px;padding:14px;margin:16px 0">
    <p style="margin:0;font-size:12px;color:#64748b">Dispute Ref: <strong>{dispute_id}</strong></p>
    <p style="margin:4px 0 0;font-size:12px;color:#64748b">Status: <strong>{status_labels.get(req.status, req.status)}</strong></p>
  </div>
  <p style="color:#64748b;font-size:12px">If you have questions, open your BOMPAY app and visit the dispute section.</p>
</div>"""
                try:
                    await send_email(
                        to=d["user_email"],
                        subject=f"BOMPAY: Dispute {dispute_id} — {status_labels.get(req.status, req.status)}",
                        html=email_html,
                    )
                except Exception:
                    pass  # Email failure must not affect the API response

    await audit(str(admin["_id"]), "DISPUTE_UPDATE", "dispute",
                {"dispute_id": dispute_id, "status": req.status, "note": req.note})
    return {"message": "Dispute updated"}


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — RISK RULES CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/fraud/rules")
async def get_rules(request: Request):
    await get_admin_user(request)
    rules = await db.fraud_rules.find({}).to_list(None)
    if not rules:
        await seed_default_rules()
        rules = await db.fraud_rules.find({}).to_list(None)
    return {"rules": [{**r, "_id": str(r["_id"])} for r in rules]}


@router.put("/admin/fraud/rules/{rule_id}")
async def update_rule(rule_id: str, req: RuleUpdate, request: Request):
    admin = await get_admin_user(request)
    rule = await db.fraud_rules.find_one({"rule_id": rule_id})
    if not rule:
        raise HTTPException(404, "Rule not found")

    update: dict = {"updated_at": datetime.now(timezone.utc).isoformat(),
                    "updated_by": str(admin["_id"]),
                    "version": rule.get("version", 1) + 1}
    for field in ("threshold_kobo","count_threshold","window_seconds",
                  "window_minutes","risk_contribution","enabled"):
        val = getattr(req, field, None)
        if val is not None:
            update[field] = val

    await db.fraud_rules.update_one({"rule_id": rule_id}, {"$set": update})
    await audit(str(admin["_id"]), "RULE_UPDATE", "fraud_rule",
                {"rule_id": rule_id, "changes": {k: v for k, v in update.items()
                                                  if k not in ("updated_at","updated_by","version")}})
    return {"message": "Rule updated"}


@router.post("/admin/fraud/rules/seed")
async def force_seed_rules(request: Request):
    await get_admin_user(request)
    await db.fraud_rules.delete_many({})
    await seed_default_rules()
    return {"message": "Default rules seeded"}



# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — USER RISK PROFILE
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/users/{user_id}/risk")
async def get_user_risk_profile(user_id: str, request: Request):
    """Return the latest risk assessment + recent history for a user."""
    await get_admin_user(request)

    # Recent assessments (last 20)
    raw = await db.risk_assessments.find(
        {"user_id": user_id}
    ).sort("created_at", -1).limit(20).to_list(20)

    assessments = [{
        "assessment_id": r.get("assessment_id", ""),
        "score":         r.get("score", 0),
        "band":          r.get("band", "low"),
        "signals":       r.get("signals", []),
        "decision":      r.get("decision", "allow"),
        "txn_type":      r.get("txn_type", ""),
        "amount_kobo":   r.get("amount_kobo", 0),
        "reviewed":      r.get("reviewed", False),
        "created_at":    r.get("created_at", ""),
    } for r in raw]

    latest = assessments[0] if assessments else None

    # Dispute count
    dispute_count = await db.disputes.count_documents({"user_id": user_id})
    open_disputes = await db.disputes.count_documents(
        {"user_id": user_id, "status": {"$in": ["submitted", "under_review"]}}
    )

    # Block status from fraud_alerts
    block = await db.fraud_alerts.find_one(
        {"user_id": user_id, "auto_blocked": True, "status": "OPEN"},
        sort=[("created_at", -1)]
    )

    return {
        "latest":          latest,
        "history":         assessments,
        "dispute_count":   dispute_count,
        "open_disputes":   open_disputes,
        "is_blocked":      block is not None,
        "block_expires":   block.get("block_expires_at") if block else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE MANAGEMENT — Consumer endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/fraud/user/devices")
async def list_devices(request: Request):
    """Return unique devices recognized for this user, grouped by device_id."""
    user = await get_current_user(request)
    uid = str(user["_id"])

    # Group login_sessions by device_id
    pipeline = [
        {"$match": {"user_id": uid}},   # user_id stored as string in login_sessions
        {"$sort": {"created_at": -1}},
        {"$group": {
            "_id": "$device_id",
            "device":      {"$first": "$device"},
            "ip":          {"$first": "$ip"},
            "user_agent":  {"$first": "$user_agent"},
            "last_seen":   {"$first": "$created_at"},
            "first_seen":  {"$last": "$created_at"},
            "session_count": {"$sum": 1},
            "failed_count":  {"$sum": {"$cond": [{"$eq": ["$success", False]}, 1, 0]}},
            "last_success":  {"$first": {"$cond": ["$success", "$created_at", None]}},
        }},
        {"$sort": {"last_seen": -1}},
    ]
    raw = await db.login_sessions.aggregate(pipeline).to_list(20)

    # Check revoked devices
    revoked = {r["device_id"] for r in
               await db.revoked_devices.find({"user_id": uid}).to_list(None)}

    devices = []
    for r in raw:
        device_id = r["_id"] or ""
        dev_str = r.get("device") or ""
        is_mobile = "Mobile" in dev_str or "Android" in dev_str or "iPhone" in dev_str
        devices.append({
            "device_id":     device_id,
            "device_name":   dev_str or "Unknown device",
            "device_type":   "mobile" if is_mobile else "desktop",
            "ip":            r.get("ip") or "—",
            "last_seen":     r.get("last_seen"),
            "first_seen":    r.get("first_seen"),
            "session_count": r.get("session_count", 0),
            "failed_count":  r.get("failed_count", 0),
            "revoked":       device_id in revoked,
        })
    return {"devices": devices}


@router.delete("/fraud/user/devices/{device_id}")
async def revoke_device(device_id: str, request: Request):
    """Revoke (remove trust from) a registered device."""
    user = await get_current_user(request)
    uid = str(user["_id"])

    # Idempotent — insert only if not already revoked
    existing = await db.revoked_devices.find_one({"user_id": uid, "device_id": device_id})
    if not existing:
        await db.revoked_devices.insert_one({
            "user_id":    uid,
            "device_id":  device_id,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
        })
    await audit(uid, "DEVICE_REVOKED", "device", {"device_id": device_id})
    return {"message": "Device removed successfully"}


@router.get("/fraud/user/login-activity")
async def login_activity(request: Request, limit: int = 20):
    """Return recent login sessions for this user."""
    user = await get_current_user(request)
    user_id_str = str(user["_id"])
    raw = await db.login_sessions.find(
        {"user_id": user_id_str},
    ).sort("created_at", -1).limit(limit).to_list(limit)

    sessions = []
    for s in raw:
        sessions.append({
            "session_id":  s.get("session_id", ""),
            "device":      s.get("device") or "Unknown",
            "ip":          s.get("ip") or "—",
            "device_id":   s.get("device_id") or "",
            "event_type":  s.get("event_type") or "LOGIN",
            "success":     s.get("success", True),
            "created_at":  s.get("created_at"),
        })
    return {"sessions": sessions, "total": len(sessions)}


# ─────────────────────────────────────────────────────────────────────────────
# REVERSALS — Admin endpoints
# ─────────────────────────────────────────────────────────────────────────────

class ReversalLog(BaseModel):
    reason: str
    note: Optional[str] = None
    resolution_type: Optional[str] = "manual_refund"   # manual_refund | retry | write_off

@router.get("/admin/fraud/reversals")
async def list_reversals(request: Request, status_filter: str = "all", limit: int = 100):
    """List failed / reversal-eligible transactions."""
    await get_admin_user(request)

    # Query from both reversal_records and failed transactions
    # First: existing reversal_records
    rr_query: dict = {}
    if status_filter != "all":
        rr_query["status"] = status_filter
    reversal_records_raw = await db.reversal_records.find(rr_query).sort(
        "created_at", -1).limit(limit).to_list(limit)

    # Second: failed DEBIT transactions not yet in reversal_records
    resolved_txn_ids = {r.get("transaction_id") for r in reversal_records_raw}
    failed_txns = await db.transactions.find({
        "direction": "DEBIT",
        "status": "FAILED",
        "transaction_id": {"$nin": list(resolved_txn_ids)},
    }).sort("created_at", -1).limit(limit).to_list(limit)

    # Enrich failed txns with user info
    reversals = []
    for r in reversal_records_raw:
        r["_id"] = str(r["_id"])
        reversals.append({**r, "source": "reversal_record"})

    for t in failed_txns:
        user_name = "—"
        try:
            u = await db.users.find_one({"_id": t["user_id"]},
                {"first_name": 1, "last_name": 1, "phone": 1, "email": 1})
            if u:
                user_name = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        except Exception:
            pass

        reversals.append({
            "_id":            str(t["_id"]),
            "transaction_id": t["transaction_id"],
            "user_name":      user_name,
            "user_id":        str(t.get("user_id", "")),
            "amount_kobo":    t.get("amount", 0),
            "fee_kobo":       t.get("fee", 0),
            "type":           t.get("type", ""),
            "description":    t.get("description", ""),
            "provider":       t.get("provider", ""),
            "provider_ref":   t.get("metadata", {}).get("session_id", ""),
            "failed_reason":  t.get("failure_reason", "Transaction failed"),
            "created_at":     t.get("created_at", ""),
            "status":         "pending_review",
            "source":         "failed_transaction",
        })

    reversals.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"reversals": reversals[:limit], "total": len(reversals)}


@router.post("/admin/fraud/reversals/{transaction_id}/log")
async def log_reversal(transaction_id: str, req: ReversalLog, request: Request):
    """Log a reversal action against a failed transaction."""
    admin = await get_admin_user(request)
    txn = await db.transactions.find_one({"transaction_id": transaction_id})
    if not txn:
        raise HTTPException(404, "Transaction not found")

    now = datetime.now(timezone.utc).isoformat()
    existing = await db.reversal_records.find_one({"transaction_id": transaction_id})
    if existing:
        # Update existing record
        await db.reversal_records.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": req.resolution_type, "note": req.note,
                      "resolved_by": str(admin["_id"]), "updated_at": now},
             "$push": {"timeline": {"event": req.reason, "note": req.note,
                                    "by": str(admin.get("email","")), "timestamp": now}}},
        )
    else:
        reversal_id = f"REV-{str(uuid.uuid4())[:8].upper()}"
        user_name = "—"
        try:
            u = await db.users.find_one({"_id": txn["user_id"]},
                {"first_name": 1, "last_name": 1, "phone": 1})
            if u: user_name = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        except Exception:
            pass

        await db.reversal_records.insert_one({
            "reversal_id":    reversal_id,
            "transaction_id": transaction_id,
            "user_id":        str(txn.get("user_id", "")),
            "user_name":      user_name,
            "amount_kobo":    txn.get("amount", 0),
            "type":           txn.get("type", ""),
            "reason":         req.reason,
            "note":           req.note,
            "status":         req.resolution_type or "pending_review",
            "initiated_by":   str(admin["_id"]),
            "timeline": [{"event": req.reason, "note": req.note,
                          "by": str(admin.get("email","")), "timestamp": now}],
            "created_at":     now,
            "updated_at":     now,
        })

        # Notify user
        try:
            if txn.get("user_id"):
                uid = str(txn["user_id"])
                await notify(uid, "Transaction Update",
                    f"We're processing an update for your transaction. {req.reason}",
                    "info", {"transaction_id": transaction_id})
        except Exception:
            pass

    await audit(str(admin["_id"]), "REVERSAL_LOGGED", "transaction",
                {"transaction_id": transaction_id, "reason": req.reason})
    return {"message": "Reversal logged successfully"}
