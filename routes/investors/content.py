"""Investor Centre — section content & metrics management."""
import logging
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from bson import ObjectId
from database import db
from core import get_admin_user

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Default section content (editable via admin CMS) ──────────────────────────

DEFAULT_SECTIONS = [
    {
        "section_id": "executive_summary",
        "title": "Executive Summary",
        "subtitle": "The African Fintech Infrastructure Play",
        "icon": "zap",
        "order": 1,
        "is_public": True,
        "color_accent": "#1769FF",
        "tagline": "Building Nigeria's most complete digital banking and merchant payments platform",
        "overview": "Bompay is a modern Nigerian fintech platform delivering full-stack digital banking, merchant payment infrastructure, and a consumer super-app. We provide virtual accounts, instant bank transfers, bill payments, an e-commerce checkout engine, and a complete merchant commerce suite — all under one regulated, scalable platform.",
        "key_points": [
            "Full-stack digital banking: virtual accounts, NIP bank transfers, bill payments",
            "Merchant commerce suite: storefronts, payment links, hosted checkout engine",
            "Consumer super-app: airtime, data, electricity, cable TV, savings, ePOS",
            "Built on SafeHaven MFB infrastructure — CBN-compliant and bank-grade secure",
            "Multi-tenant architecture serving consumers, merchants, and business accounts",
        ],
        "highlight_metric": {"label": "Seeking", "value": "$1M", "note": "Seed Round (indicative)"},
        "use_label": "Seed investment powering Nigeria's next digital bank",
    },
    {
        "section_id": "financial_projections",
        "title": "Financial Projections",
        "subtitle": "5-Year Indicative Model",
        "icon": "trending-up",
        "order": 2,
        "is_public": True,
        "color_accent": "#10B981",
        "tagline": "Projected path to ₦18B ARR by 2028",
        "overview": "Our financial model is built on conservative unit economics grounded in Nigeria's expanding digital payments market. Key growth drivers are merchant platform fees, transaction processing margins, VAS commissions, and enterprise API licensing.",
        "key_points": [
            "Revenue Model: Checkout fees (1.5%), transfer margins, VAS commissions",
            "Gross margin target: 42% (2024) → 68% (2028) driven by infrastructure scale",
            "Break-even projected at 18 months post-funding with disciplined cost structure",
            "Platform fee revenue from merchant suite growing 3× annually",
            "API licensing to fintechs and banks unlocks enterprise revenue stream",
        ],
        "highlight_metric": {"label": "2028 ARR Target", "value": "₦18B", "note": "Indicative"},
        "disclaimer": "All projections are forward-looking statements based on management assumptions. Actual results may differ materially.",
        "chart_data": {
            "financial_projections": [
                {"year": "Y1", "arr_m": 120, "tpv_b": 3.2, "revenue_m": 48, "gross_margin": 38},
                {"year": "Y2", "arr_m": 420, "tpv_b": 9.8, "revenue_m": 175, "gross_margin": 45},
                {"year": "Y3", "arr_m": 1200, "tpv_b": 28.5, "revenue_m": 490, "gross_margin": 54},
                {"year": "Y4", "arr_m": 3800, "tpv_b": 75.0, "revenue_m": 1400, "gross_margin": 62},
                {"year": "Y5", "arr_m": 9500, "tpv_b": 180.0, "revenue_m": 3600, "gross_margin": 68},
            ]
        },
    },
    {
        "section_id": "traction",
        "title": "Traction & Growth",
        "subtitle": "Platform Metrics & Milestones",
        "icon": "bar-chart-2",
        "order": 3,
        "is_public": True,
        "color_accent": "#8B5CF6",
        "tagline": "Growing platform with live merchant integrations",
        "overview": "Bompay's platform is live with active merchant onboarding, consumer wallet accounts, and growing transaction volume. The platform processes real NIP bank transfers, VAS transactions, and merchant checkout sessions across Nigeria.",
        "key_points": [
            "Live platform: real bank transfers, VAS, and merchant checkout processing daily",
            "Multi-vertical product: consumer + merchant + B2B API in single deployment",
            "Active merchant storefront and payment link adoption growing month-over-month",
            "Zero-downtime architecture: 99.9% SLA maintained on critical payment paths",
            "Referral and rewards program driving organic consumer acquisition",
        ],
        "kpis": [
            {"label": "Platform Status", "value": "Live", "note": "Production deployment"},
            {"label": "Virtual Account Products", "value": "3", "note": "Consumer, Merchant, Business"},
            {"label": "VAS Integrations", "value": "4+", "note": "Airtime, Data, Electricity, Cable"},
            {"label": "Uptime SLA", "value": "99.9%", "note": "Payment-critical paths"},
        ],
        "highlight_metric": {"label": "Platform", "value": "Live", "note": "Active & processing"},
    },
    {
        "section_id": "market_opportunity",
        "title": "Market Opportunity",
        "subtitle": "Nigeria & Pan-African Fintech",
        "icon": "globe",
        "order": 4,
        "is_public": True,
        "color_accent": "#F59E0B",
        "tagline": "Targeting a $127B digital payments opportunity by 2027",
        "overview": "Nigeria is Africa's largest economy with 220M+ people and a rapidly digitising financial sector. Despite a 40% unbanked population, smartphone adoption, mobile money, and CBN financial inclusion mandates are accelerating the shift to digital payments.",
        "key_points": [
            "Nigeria payments TAM: $127B by 2027 (World Bank / EFInA estimates)",
            "40M+ Nigerians still unbanked or underserved by traditional banks",
            "NIP (NIBSS Instant Payment) processes 8B+ transactions annually and growing",
            "MSME sector: 40M+ micro and small businesses needing payment infrastructure",
            "Pan-African expansion opportunity: Ghana, Kenya, Rwanda share similar dynamics",
        ],
        "market_data": [
            {"segment": "Retail Payments", "size_b": 68, "color": "#1769FF"},
            {"segment": "Merchant Commerce", "size_b": 32, "color": "#10B981"},
            {"segment": "Enterprise API", "size_b": 15, "color": "#8B5CF6"},
            {"segment": "Cross-Border", "size_b": 12, "color": "#F59E0B"},
        ],
        "highlight_metric": {"label": "TAM by 2027", "value": "$127B", "note": "Nigeria digital payments"},
    },
    {
        "section_id": "product_tech",
        "title": "Product & Technology",
        "subtitle": "Platform Architecture & Stack",
        "icon": "layers",
        "order": 5,
        "is_public": True,
        "color_accent": "#06B6D4",
        "tagline": "Cloud-native, API-first fintech infrastructure",
        "overview": "Bompay is built on a modern microservice-inspired architecture delivering bank-grade reliability. The platform spans a consumer super-app, merchant commerce suite, hosted checkout, and developer APIs — all unified on a single compliant infrastructure layer.",
        "key_points": [
            "Backend: FastAPI + MongoDB — high-throughput async payment processing",
            "Frontend: React with progressive web app capabilities for mobile-first markets",
            "Banking rails: SafeHaven MFB virtual accounts + NIP instant transfers",
            "Storage & CDN: Cloudinary for merchant/KYC documents and media",
            "Security: RBAC, JWT cookie auth, anti-fraud engine, BVN/NIN KYC",
        ],
        "product_pillars": [
            {"name": "Consumer Super-App", "description": "Wallets, transfers, bills, savings, ePOS"},
            {"name": "Merchant Commerce", "description": "Storefront, payment links, checkout, invoices"},
            {"name": "Business Banking", "description": "Virtual accounts, team RBAC, settlement"},
            {"name": "Developer APIs", "description": "Checkout SDK, webhooks, API keys"},
        ],
        "highlight_metric": {"label": "API Endpoints", "value": "565+", "note": "Documented & live"},
    },
    {
        "section_id": "use_of_funds",
        "title": "Use of Funds",
        "subtitle": "$1M Seed Round Deployment Plan",
        "icon": "pie-chart",
        "order": 6,
        "is_public": True,
        "color_accent": "#1769FF",
        "tagline": "Capital deployed for maximum growth leverage",
        "overview": "The $1M seed raise will accelerate platform scale, regulatory positioning, and merchant acquisition. The allocation prioritises the highest-leverage growth vectors: regulatory capital for expanded CBN licencing, engineering infrastructure for enterprise-grade reliability, and merchant acquisition to build the network effect.",
        "key_points": [
            "Regulatory Capital & Expansion: Strengthen CBN licence position and expand to new states",
            "Engineering & Infrastructure: Scale payment processing, security hardening, uptime",
            "Merchant Acquisition: Onboard 10,000+ MSME merchants within 18 months",
            "Reserve & Compliance: AML/KYC infrastructure, legal advisory, operating buffer",
        ],
        "funds_breakdown": [
            {"label": "Regulatory Capital & Expansion", "percentage": 40, "amount_m": 0.4, "color": "#1769FF"},
            {"label": "Engineering & Infrastructure", "percentage": 30, "amount_m": 0.3, "color": "#10B981"},
            {"label": "Merchant Acquisition", "percentage": 18, "amount_m": 0.18, "color": "#8B5CF6"},
            {"label": "Reserve & Compliance", "percentage": 12, "amount_m": 0.12, "color": "#F59E0B"},
        ],
        "highlight_metric": {"label": "Raise Target", "value": "$1M", "note": "Seed Round (indicative)"},
    },
    {
        "section_id": "unit_economics",
        "title": "Unit Economics",
        "subtitle": "CAC, LTV & Margin Analysis",
        "icon": "dollar-sign",
        "order": 7,
        "is_public": True,
        "color_accent": "#10B981",
        "tagline": "Strong unit economics with clear path to profitability",
        "overview": "Bompay's multi-product model creates compounding revenue per user: a consumer wallet generates transaction fees, VAS commissions, and cross-sell opportunities to merchant products. Merchants generate checkout fees, subscription revenue, and platform API fees.",
        "key_points": [
            "Consumer CAC: Low due to referral flywheel and WhatsApp/social organic acquisition",
            "Merchant LTV significantly higher than consumer — recurring platform subscription",
            "Transaction take-rate (blended): 0.8% — 1.5% across payment types",
            "VAS gross margin: 15%–25% per transaction depending on provider margins",
            "Merchant platform fee: ₦10,000–₦25,000/month (projected Tier 2 subscription)",
        ],
        "metrics_table": [
            {"metric": "Blended Take Rate", "value": "1.2%", "note": "Target (indicative)"},
            {"metric": "Consumer CAC", "value": "₦350", "note": "Organic + referral (indicative)"},
            {"metric": "Consumer LTV (24M)", "value": "₦4,200", "note": "12× CAC (indicative)"},
            {"metric": "Merchant CAC", "value": "₦8,500", "note": "Sales + digital (indicative)"},
            {"metric": "Merchant LTV (36M)", "value": "₦95,000", "note": "11× CAC (indicative)"},
            {"metric": "Gross Margin (target)", "value": "42% → 68%", "note": "Y1 → Y5"},
        ],
        "highlight_metric": {"label": "LTV/CAC", "value": "11–12×", "note": "Blended (indicative)"},
    },
    {
        "section_id": "regulatory",
        "title": "Regulatory & Compliance",
        "subtitle": "CBN Licensing & AML/KYC Framework",
        "icon": "shield",
        "order": 8,
        "is_public": True,
        "color_accent": "#F59E0B",
        "tagline": "Bank-grade compliance from day one",
        "overview": "Bompay operates within Nigeria's regulated financial system through a partnership with SafeHaven Microfinance Bank — a CBN-licensed institution. Our compliance architecture meets CBN KYC/AML requirements with a tiered verification system (BVN, NIN, Government ID, Face Liveness).",
        "key_points": [
            "Banking rails via SafeHaven MFB — CBN-licensed Microfinance Bank",
            "KYC: Tiered verification — Tier 1 (BVN/NIN) → Tier 2 (Gov ID) → Tier 3 (Face Liveness)",
            "AML: Transaction monitoring, fraud scoring engine, and risk-band assessments",
            "NDPR compliant: Data residency, retention policies, and user consent management",
            "Merchant KYB: CAC document verification + director identity confirmation",
        ],
        "compliance_pillars": [
            {"name": "KYC / Identity", "status": "Active", "detail": "BVN, NIN, Gov ID, Face Liveness"},
            {"name": "AML / Fraud", "status": "Active", "detail": "Real-time risk scoring + velocity rules"},
            {"name": "Data Protection", "status": "Active", "detail": "NDPR compliance framework"},
            {"name": "CBN Reporting", "status": "Via Partner", "detail": "SafeHaven MFB reporting channel"},
        ],
        "highlight_metric": {"label": "KYC Tiers", "value": "3", "note": "Fully implemented"},
    },
    {
        "section_id": "cap_table",
        "title": "Cap Table & Ownership",
        "subtitle": "Pre-Seed Ownership Structure",
        "icon": "users",
        "order": 9,
        "is_public": False,
        "color_accent": "#8B5CF6",
        "tagline": "Founder-controlled, investor-friendly structure",
        "overview": "The Bompay cap table reflects a founder-controlled structure ahead of the seed round. The indicative structure below is subject to finalisation with incoming investors. Actual share numbers, valuations, and option pool details will be shared under NDA via the Data Room.",
        "key_points": [
            "Founder team retains majority ownership pre-seed",
            "Employee stock option pool (ESOP) reserved for key hires post-round",
            "Seed valuation to be determined by lead investor negotiation",
            "No debt or convertible notes outstanding at this stage",
            "Data Room contains full shareholder register and Articles of Association",
        ],
        "cap_table": [
            {"stakeholder": "Founder(s)", "percentage": "[Confidential — Data Room]", "note": "Founding team"},
            {"stakeholder": "Investor Allocation", "percentage": "[TBD — Seed Round]", "note": "This raise"},
            {"stakeholder": "ESOP Reserve", "percentage": "[To be confirmed]", "note": "Post-round pool"},
        ],
        "note": "Full cap table, valuation, and shareholder agreement available in the Data Room under NDA. Request Data Room access via the Investor Enquiry form.",
        "highlight_metric": {"label": "Stage", "value": "Pre-Seed", "note": "Seeking lead investor"},
    },
    {
        "section_id": "data_room",
        "title": "Data Room",
        "subtitle": "Due Diligence Document Library",
        "icon": "folder",
        "order": 10,
        "is_public": True,
        "color_accent": "#06B6D4",
        "tagline": "Structured due diligence package for qualified investors",
        "overview": "The Bompay Data Room provides qualified investors with access to a structured due diligence package including financial models, legal documents, technical architecture, and compliance records. Access is granted in tiers based on investor verification status.",
        "access_tiers": [
            {"tier": "Tier 1 — Public", "label": "Available now", "documents": ["Pitch Deck (summary)", "Executive Summary PDF", "Product Overview", "Market Research Brief"]},
            {"tier": "Tier 2 — Verified Investor", "label": "Submit enquiry to request access", "documents": ["Full Financial Model (Excel)", "5-Year Projections", "Unit Economics Detail", "Platform Architecture Diagram"]},
            {"tier": "Tier 3 — Under NDA", "label": "For lead investors only", "documents": ["Full Cap Table & Shareholder Register", "Audited Accounts (if available)", "Founder Agreements", "CBN Correspondence"]},
        ],
        "key_points": [
            "Tier 1 materials available immediately via Investor Enquiry form",
            "Tier 2 access granted within 24–48 hours to verified investors",
            "Tier 3 materials shared with lead investor candidates under NDA",
            "All downloads are watermarked and access-logged for confidentiality",
        ],
        "highlight_metric": {"label": "Documents", "value": "25+", "note": "Across 3 access tiers (coming soon)"},
    },
    {
        "section_id": "team",
        "title": "Executive Team",
        "subtitle": "Leadership & Advisory Board",
        "icon": "user-check",
        "order": 11,
        "is_public": True,
        "color_accent": "#8B5CF6",
        "tagline": "Experienced operators building for the long term",
        "overview": "Bompay is led by a team with deep expertise in Nigerian fintech, banking infrastructure, and scalable software engineering. Full team biographies, LinkedIn profiles, and backgrounds are available in the Data Room.",
        "team_members": [
            {"role": "Chief Executive Officer", "description": "Fintech operator with experience in Nigerian digital banking and payments infrastructure.", "background": "Details available in Data Room"},
            {"role": "Chief Technology Officer", "description": "Senior engineer with expertise in cloud-native payment systems and API architecture.", "background": "Details available in Data Room"},
            {"role": "Chief Financial Officer", "description": "Finance professional with experience in Nigerian regulatory environments and fundraising.", "background": "Details available in Data Room"},
            {"role": "Head of Compliance", "description": "Regulatory specialist with CBN/NDPR compliance experience in Nigeria and West Africa.", "background": "Details available in Data Room"},
        ],
        "advisors": "Advisory board details available upon Data Room access request.",
        "key_points": [
            "Team has operated in regulated Nigerian financial services",
            "Engineering team experienced with high-throughput payment systems",
            "Full CVs, references, and background checks available under NDA",
            "Open roles: Head of Growth, Head of Sales, Senior Backend Engineers",
        ],
        "highlight_metric": {"label": "Team Size", "value": "Growing", "note": "Key hires post-seed"},
    },
    {
        "section_id": "enquiry",
        "title": "Investor Enquiry",
        "subtitle": "Connect with the Bompay IR Team",
        "icon": "mail",
        "order": 12,
        "is_public": True,
        "color_accent": "#1769FF",
        "tagline": "We'd love to hear from qualified investors",
        "overview": "Bompay is currently raising a $1M seed round. We welcome conversations with VCs, growth equity funds, angels, and strategic investors aligned with Nigeria's fintech opportunity. The IR team aims to respond within 24–48 hours.",
        "key_points": [
            "Seed round — $1M target (indicative)",
            "Use of capital: regulatory, engineering, merchant growth",
            "Timeline: Q2–Q3 2025 close target (indicative)",
            "Geographic focus: Nigeria primary, pan-Africa expansion 18 months post-close",
        ],
        "contact": {
            "email": "investors@bompay.app",
            "response_time": "24–48 hours",
        },
        "highlight_metric": {"label": "Response Time", "value": "24–48h", "note": "IR team response"},
    },
]

DEFAULT_METRICS = [
    {"metric_id": "raise_target", "label": "Raise Target", "value": "$1M", "note": "Seed Round", "order": 1},
    {"metric_id": "market_tam", "label": "Market TAM", "value": "$127B", "note": "Nigeria by 2027", "order": 2},
    {"metric_id": "arr_target", "label": "5-Year ARR Target", "value": "₦18B", "note": "Indicative", "order": 3},
    {"metric_id": "platform_status", "label": "Platform", "value": "Live", "note": "Production", "order": 4},
    {"metric_id": "api_endpoints", "label": "API Endpoints", "value": "565+", "note": "Documented", "order": 5},
    {"metric_id": "kyc_tiers", "label": "KYC Tiers", "value": "3", "note": "Fully implemented", "order": 6},
]


async def seed_investor_content():
    """Seed default investor content if not present."""
    for s in DEFAULT_SECTIONS:
        if not await db.investor_sections.find_one({"section_id": s["section_id"]}):
            await db.investor_sections.insert_one({**s, "updated_at": datetime.now(timezone.utc).isoformat()})
    for m in DEFAULT_METRICS:
        if not await db.investor_metrics.find_one({"metric_id": m["metric_id"]}):
            await db.investor_metrics.insert_one({**m, "updated_at": datetime.now(timezone.utc).isoformat()})
    await db.investor_sections.create_index("section_id", unique=True)
    await db.investor_metrics.create_index("metric_id", unique=True)
    await db.investor_enquiries.create_index("email")
    logger.info("[InvestorContent] Seeded investor portal content")


# ── Public endpoints ───────────────────────────────────────────────────────────

@router.get("/investors/public/overview")
async def get_public_overview():
    metrics = await db.investor_metrics.find({}, {"_id": 0}).sort("order", 1).to_list(20)
    return {"metrics": metrics}


@router.get("/investors/public/sections")
async def get_public_sections():
    sections = await db.investor_sections.find(
        {"is_public": True},
        {"_id": 0, "section_id": 1, "title": 1, "subtitle": 1, "icon": 1, "order": 1,
         "color_accent": 1, "tagline": 1, "highlight_metric": 1}
    ).sort("order", 1).to_list(20)
    return {"sections": sections}


@router.get("/investors/public/sections/{section_id}")
async def get_public_section(section_id: str):
    doc = await db.investor_sections.find_one({"section_id": section_id, "is_public": True}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Section not found")
    return doc


# ── Admin endpoints ────────────────────────────────────────────────────────────

class SectionUpdateIn(BaseModel):
    title: Optional[str] = None
    subtitle: Optional[str] = None
    tagline: Optional[str] = None
    overview: Optional[str] = None
    key_points: Optional[List[str]] = None
    is_public: Optional[bool] = None
    highlight_metric: Optional[dict] = None


class MetricUpdateIn(BaseModel):
    label: Optional[str] = None
    value: Optional[str] = None
    note: Optional[str] = None


@router.get("/investors/admin/sections")
async def admin_list_sections(request: Request):
    await get_admin_user(request)
    sections = await db.investor_sections.find({}, {"_id": 0}).sort("order", 1).to_list(20)
    return {"sections": sections}


@router.get("/investors/admin/sections/{section_id}")
async def admin_get_section(request: Request, section_id: str):
    await get_admin_user(request)
    doc = await db.investor_sections.find_one({"section_id": section_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Section not found")
    return doc


@router.put("/investors/admin/sections/{section_id}")
async def admin_update_section(request: Request, section_id: str, body: SectionUpdateIn):
    await get_admin_user(request)
    update = {k: v for k, v in body.dict().items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    update["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.investor_sections.update_one({"section_id": section_id}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(404, "Section not found")
    return {"ok": True}


@router.get("/investors/admin/metrics")
async def admin_list_metrics(request: Request):
    await get_admin_user(request)
    metrics = await db.investor_metrics.find({}, {"_id": 0}).sort("order", 1).to_list(20)
    return {"metrics": metrics}


@router.put("/investors/admin/metrics/{metric_id}")
async def admin_update_metric(request: Request, metric_id: str, body: MetricUpdateIn):
    await get_admin_user(request)
    update = {k: v for k, v in body.dict().items() if v is not None}
    if not update:
        raise HTTPException(400, "No fields to update")
    update["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.investor_metrics.update_one({"metric_id": metric_id}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(404, "Metric not found")
    return {"ok": True}


@router.get("/investors/admin/overview")
async def admin_overview(request: Request):
    await get_admin_user(request)
    total_enquiries = await db.investor_enquiries.count_documents({})
    new_enquiries = await db.investor_enquiries.count_documents({"status": "new"})
    sections_count = await db.investor_sections.count_documents({})
    recent = await db.investor_enquiries.find(
        {}, {"_id": 1, "full_name": 1, "email": 1, "organisation": 1, "status": 1, "created_at_str": 1}
    ).sort("created_at", -1).limit(5).to_list(5)
    for r in recent:
        r["id"] = str(r.pop("_id"))
    return {
        "total_enquiries": total_enquiries,
        "new_enquiries": new_enquiries,
        "sections_count": sections_count,
        "recent_enquiries": recent,
    }
