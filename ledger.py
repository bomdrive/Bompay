"""
BOMPAY — MongoDB Double-Entry Financial Ledger

Every money movement in the platform is mirrored here as balanced journal entries.
This ledger is immutable; entries are only ever appended, never updated or deleted.

Account types (normal balance):
  ASSET     — debit increases, credit decreases (wallets, float)
  LIABILITY — credit increases, debit decreases (customer deposits owed)
  REVENUE   — credit increases (fees, interest income)
  EXPENSE   — debit increases (operational costs)

Collections:
  ledger_accounts  — chart of accounts
  journal_entries  — one document per posting (with embedded lines for fast reads)
"""

import uuid
import logging
from datetime import datetime, timezone

from database import db

logger = logging.getLogger(__name__)


# ---- System account seeds ----

SYSTEM_ACCOUNTS = [
    {"code": "SYS-RESERVE",  "name": "Platform Reserve",  "account_type": "LIABILITY"},
    {"code": "SYS-FLOAT",    "name": "Platform Float",    "account_type": "ASSET"},
    {"code": "SYS-FEES",     "name": "Fee Revenue",       "account_type": "REVENUE"},
    {"code": "SYS-INTEREST", "name": "Interest Revenue",  "account_type": "REVENUE"},
]


async def init_schema():
    """Ensure indexes and seed system accounts."""
    await db.ledger_accounts.create_index("code", unique=True)
    await db.journal_entries.create_index("reference", unique=True)
    await db.journal_entries.create_index("user_id")
    await db.journal_entries.create_index([("created_at", -1)])
    await db.journal_entries.create_index("entry_id", unique=True)

    for acct in SYSTEM_ACCOUNTS:
        await db.ledger_accounts.update_one(
            {"code": acct["code"]},
            {"$setOnInsert": {**acct, "user_id": None, "currency": "NGN",
                              "created_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True,
        )
    logger.info("[Ledger] MongoDB schema ready")


# ---- Account helpers ----

async def ensure_wallet_account(user_id: str, name: str) -> str:
    """Get or create a wallet account for a user. Returns account code."""
    code = f"WALLET-{user_id}"
    await db.ledger_accounts.update_one(
        {"code": code},
        {"$setOnInsert": {
            "code": code,
            "name": f"Wallet — {name}",
            "account_type": "ASSET",
            "user_id": user_id,
            "currency": "NGN",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )
    return code


async def _sys_account(code: str) -> str:
    """Return system account code (validates it exists)."""
    acct = await db.ledger_accounts.find_one({"code": code})
    if not acct:
        raise RuntimeError(f"System account '{code}' not found")
    return code


# ---- Core posting function ----

async def post_journal(
    reference: str,
    description: str,
    entry_type: str,
    amount_kobo: int,
    lines: list[dict],        # [{"account_code": str, "account_name": str, "account_type": str, "debit": int, "credit": int}]
    user_id: str | None = None,
    mongo_txn_id: str | None = None,
) -> str:
    """
    Post a balanced journal entry. Raises ValueError if lines don't balance.
    Returns entry_id.
    """
    total_debit  = sum(l.get("debit",  0) for l in lines)
    total_credit = sum(l.get("credit", 0) for l in lines)
    if total_debit != total_credit:
        raise ValueError(
            f"[Ledger] Unbalanced entry '{reference}': "
            f"DR {total_debit} ≠ CR {total_credit}"
        )

    entry_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Embed lines directly into the journal entry document
    embedded_lines = [
        {
            "account_code": l.get("account_code", ""),
            "account_name": l.get("account_name", ""),
            "account_type": l.get("account_type", ""),
            "debit_kobo":   l.get("debit",  0),
            "credit_kobo":  l.get("credit", 0),
        }
        for l in lines
    ]

    await db.journal_entries.insert_one({
        "entry_id":    entry_id,
        "reference":   reference,
        "description": description,
        "amount_kobo": amount_kobo,
        "currency":    "NGN",
        "entry_type":  entry_type,
        "mongo_txn_id": mongo_txn_id,
        "user_id":     user_id,
        "lines":       embedded_lines,
        "created_at":  now,
    })
    logger.info(f"[Ledger] Posted {entry_type} ref={reference} amount={amount_kobo}k")
    return entry_id


# ---- High-level business operations ----

async def record_wallet_funding(
    user_id: str, user_name: str,
    amount_ngn: float, reference: str, mongo_txn_id: str | None = None
):
    """DR User-Wallet  CR Platform-Reserve"""
    amount_kobo = int(round(amount_ngn * 100))
    wallet_code  = await ensure_wallet_account(user_id, user_name)
    reserve_code = await _sys_account("SYS-RESERVE")
    await post_journal(
        reference=reference,
        description=f"Wallet funding ₦{amount_ngn:,.2f}",
        entry_type="WALLET_FUNDING",
        amount_kobo=amount_kobo,
        lines=[
            {"account_code": wallet_code,  "account_name": f"Wallet — {user_name}", "account_type": "ASSET",     "debit": amount_kobo, "credit": 0},
            {"account_code": reserve_code, "account_name": "Platform Reserve",       "account_type": "LIABILITY", "debit": 0, "credit": amount_kobo},
        ],
        user_id=user_id,
        mongo_txn_id=mongo_txn_id,
    )


async def record_transfer_out(
    user_id: str, user_name: str,
    amount_ngn: float, fee_ngn: float,
    reference: str, mongo_txn_id: str | None = None
):
    """DR User-Wallet (principal+fee)  CR Platform-Float (principal)  CR Platform-Fees (fee)"""
    principal_kobo = int(round(amount_ngn * 100))
    fee_kobo       = int(round(fee_ngn * 100))
    total_kobo     = principal_kobo + fee_kobo
    wallet_code = await ensure_wallet_account(user_id, user_name)
    float_code  = await _sys_account("SYS-FLOAT")
    fees_code   = await _sys_account("SYS-FEES")
    lines = [
        {"account_code": wallet_code, "account_name": f"Wallet — {user_name}", "account_type": "ASSET",   "debit": total_kobo,     "credit": 0},
        {"account_code": float_code,  "account_name": "Platform Float",        "account_type": "ASSET",   "debit": 0, "credit": principal_kobo},
    ]
    if fee_kobo > 0:
        lines.append({"account_code": fees_code, "account_name": "Fee Revenue", "account_type": "REVENUE", "debit": 0, "credit": fee_kobo})
    await post_journal(
        reference=reference,
        description=f"Transfer out ₦{amount_ngn:,.2f} + fee ₦{fee_ngn:,.2f}",
        entry_type="TRANSFER_OUT",
        amount_kobo=total_kobo,
        lines=lines,
        user_id=user_id,
        mongo_txn_id=mongo_txn_id,
    )


async def record_vas_payment(
    user_id: str, user_name: str,
    amount_ngn: float, fee_ngn: float,
    vas_type: str,
    reference: str, mongo_txn_id: str | None = None
):
    """DR User-Wallet (principal+fee)  CR Platform-Float (principal)  CR Platform-Fees (fee)"""
    principal_kobo = int(round(amount_ngn * 100))
    fee_kobo       = int(round(fee_ngn * 100))
    total_kobo     = principal_kobo + fee_kobo
    wallet_code = await ensure_wallet_account(user_id, user_name)
    float_code  = await _sys_account("SYS-FLOAT")
    fees_code   = await _sys_account("SYS-FEES")
    lines = [
        {"account_code": wallet_code, "account_name": f"Wallet — {user_name}", "account_type": "ASSET",   "debit": total_kobo,     "credit": 0},
        {"account_code": float_code,  "account_name": "Platform Float",        "account_type": "ASSET",   "debit": 0, "credit": principal_kobo},
    ]
    if fee_kobo > 0:
        lines.append({"account_code": fees_code, "account_name": "Fee Revenue", "account_type": "REVENUE", "debit": 0, "credit": fee_kobo})
    await post_journal(
        reference=reference,
        description=f"{vas_type} ₦{amount_ngn:,.2f}",
        entry_type=f"VAS_{vas_type.upper()}",
        amount_kobo=total_kobo,
        lines=lines,
        user_id=user_id,
        mongo_txn_id=mongo_txn_id,
    )


async def record_loan_disbursement(
    user_id: str, user_name: str,
    amount_ngn: float, reference: str, mongo_txn_id: str | None = None
):
    """DR User-Wallet  CR Platform-Float (loan disbursed from platform float)"""
    amount_kobo = int(round(amount_ngn * 100))
    wallet_code = await ensure_wallet_account(user_id, user_name)
    float_code  = await _sys_account("SYS-FLOAT")
    await post_journal(
        reference=reference,
        description=f"Loan disbursement ₦{amount_ngn:,.2f}",
        entry_type="LOAN_DISBURSEMENT",
        amount_kobo=amount_kobo,
        lines=[
            {"account_code": wallet_code, "account_name": f"Wallet — {user_name}", "account_type": "ASSET", "debit": amount_kobo, "credit": 0},
            {"account_code": float_code,  "account_name": "Platform Float",        "account_type": "ASSET", "debit": 0, "credit": amount_kobo},
        ],
        user_id=user_id,
        mongo_txn_id=mongo_txn_id,
    )


async def record_savings_contribution(
    user_id: str, user_name: str,
    amount_ngn: float, reference: str, mongo_txn_id: str | None = None
):
    """DR Platform-Reserve (ring-fenced savings)  CR User-Wallet (reduces available)"""
    amount_kobo = int(round(amount_ngn * 100))
    wallet_code  = await ensure_wallet_account(user_id, user_name)
    reserve_code = await _sys_account("SYS-RESERVE")
    await post_journal(
        reference=reference,
        description=f"Savings contribution ₦{amount_ngn:,.2f}",
        entry_type="SAVINGS_CONTRIBUTION",
        amount_kobo=amount_kobo,
        lines=[
            {"account_code": reserve_code, "account_name": "Platform Reserve",       "account_type": "LIABILITY", "debit": amount_kobo, "credit": 0},
            {"account_code": wallet_code,  "account_name": f"Wallet — {user_name}", "account_type": "ASSET",     "debit": 0, "credit": amount_kobo},
        ],
        user_id=user_id,
        mongo_txn_id=mongo_txn_id,
    )


# ---- Query helpers for admin console ----

async def get_recent_entries(limit: int = 50, user_id: str | None = None) -> list[dict]:
    query: dict = {}
    if user_id:
        query["user_id"] = user_id
    docs = await db.journal_entries.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)
    return [
        {
            "id":           d["entry_id"],
            "reference":    d["reference"],
            "description":  d["description"],
            "entry_type":   d["entry_type"],
            "amount_ngn":   d["amount_kobo"] / 100,
            "user_id":      d.get("user_id"),
            "mongo_txn_id": d.get("mongo_txn_id"),
            "created_at":   d["created_at"],
        }
        for d in docs
    ]


async def get_entry_lines(entry_id: str) -> list[dict]:
    doc = await db.journal_entries.find_one({"entry_id": entry_id}, {"_id": 0})
    if not doc:
        return []
    return [
        {
            "account_code": l["account_code"],
            "account_name": l["account_name"],
            "account_type": l["account_type"],
            "debit_ngn":    l["debit_kobo"]  / 100,
            "credit_ngn":   l["credit_kobo"] / 100,
        }
        for l in doc.get("lines", [])
    ]


async def get_ledger_summary() -> dict:
    """Aggregated totals per account for console dashboard."""
    total_entries = await db.journal_entries.count_documents({})

    # Aggregate debit/credit per account_code across all embedded lines
    pipeline = [
        {"$unwind": "$lines"},
        {"$group": {
            "_id": {
                "code":         "$lines.account_code",
                "name":         "$lines.account_name",
                "account_type": "$lines.account_type",
            },
            "total_debit_kobo":  {"$sum": "$lines.debit_kobo"},
            "total_credit_kobo": {"$sum": "$lines.credit_kobo"},
        }},
        {"$sort": {"_id.account_type": 1, "_id.code": 1}},
    ]
    rows = await db.journal_entries.aggregate(pipeline).to_list(200)

    # Also include system accounts with zero activity
    sys_accounts = await db.ledger_accounts.find({}, {"_id": 0}).to_list(100)
    seen_codes = {r["_id"]["code"] for r in rows}
    for acct in sys_accounts:
        if acct["code"] not in seen_codes:
            rows.append({"_id": {"code": acct["code"], "name": acct["name"], "account_type": acct["account_type"]},
                         "total_debit_kobo": 0, "total_credit_kobo": 0})

    accounts = []
    for r in rows:
        acct_type = r["_id"]["account_type"]
        dr = r["total_debit_kobo"]
        cr = r["total_credit_kobo"]
        balance = (dr - cr) / 100 if acct_type in ("ASSET", "EXPENSE") else (cr - dr) / 100
        accounts.append({
            "code":             r["_id"]["code"],
            "name":             r["_id"]["name"],
            "account_type":     acct_type,
            "total_debit_ngn":  dr / 100,
            "total_credit_ngn": cr / 100,
            "balance_ngn":      balance,
        })

    return {"total_entries": total_entries, "accounts": accounts}
