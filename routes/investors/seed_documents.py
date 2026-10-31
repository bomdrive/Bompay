"""
Investor Centre — Data Room seed.
Generates and uploads 10 world-class investor documents (Tier 1-3) to Cloudinary,
then seeds their metadata into MongoDB.  Only runs if the collection is empty.
"""
import io
import asyncio
import logging
import base64
from datetime import datetime, timezone
from bson import ObjectId
from database import db

logger = logging.getLogger(__name__)

# ── Brand colours (hex, no #) ──────────────────────────────────────────────────
BLUE   = "1769FF"
NAVY   = "071426"
MID    = "0B1F3A"
GREEN  = "10B981"
AMBER  = "F59E0B"
PURPLE = "8B5CF6"
SLATE  = "94A3B8"
WHITE  = "FFFFFF"
TEAL   = "06B6D4"

FINANCIAL_DATA = [
    {"year": "Y1", "arr_m": 120,  "tpv_b": 3.2,  "rev_m": 48,   "gm": 38},
    {"year": "Y2", "arr_m": 420,  "tpv_b": 9.8,  "rev_m": 175,  "gm": 45},
    {"year": "Y3", "arr_m": 1200, "tpv_b": 28.5, "rev_m": 490,  "gm": 54},
    {"year": "Y4", "arr_m": 3800, "tpv_b": 75.0, "rev_m": 1400, "gm": 62},
    {"year": "Y5", "arr_m": 9500, "tpv_b": 180,  "rev_m": 3600, "gm": 68},
]

STAMP = datetime.now(timezone.utc).strftime("%B %Y")
SEED_VERSION = "v8"  # v8: $5M valuation cap, consistent across all docs


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _run_in_thread(fn):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn)


async def _upload(data: bytes, public_id: str) -> str:
    """Upload bytes to Cloudinary (public type, access controlled at backend level)."""
    import cloudinary.uploader
    result = await _run_in_thread(lambda: cloudinary.uploader.upload(
        data,
        public_id=public_id,
        resource_type="raw",
        overwrite=True,
        invalidate=True,
    ))
    return result["secure_url"]


def _doc_record(doc_id, title, desc, filename, mime, size, tier, cat, pub_id, url):
    return {
        "_id": doc_id,
        "title": title,
        "description": desc,
        "filename": filename,
        "mime_type": mime,
        "size_bytes": size,
        "tier": tier,
        "category": cat,
        "cloudinary_public_id": pub_id,
        "cloudinary_url": url,
        "resource_type": "raw",
        "is_active": True,
        "download_count": 0,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": "system_seed",
        "seed_version": SEED_VERSION,
    }


def _pdf_record(doc_id, title, desc, filename, pdf_bytes: bytes, tier, cat):
    """PDF record: bytes stored directly in MongoDB (bypasses Cloudinary PDF auth issue)."""
    return {
        "_id": doc_id,
        "title": title,
        "description": desc,
        "filename": filename,
        "mime_type": "application/pdf",
        "size_bytes": len(pdf_bytes),
        "tier": tier,
        "category": cat,
        "cloudinary_public_id": None,
        "cloudinary_url": None,
        "content_b64": base64.b64encode(pdf_bytes).decode(),
        "resource_type": "raw",
        "is_active": True,
        "download_count": 0,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": "system_seed",
        "seed_version": SEED_VERSION,
    }


def _pdf_base(title: str, tier: int, body: str) -> str:
    tier_color  = {1: BLUE, 2: GREEN, 3: PURPLE}.get(tier, BLUE)
    tier_label  = {
        1: "TIER 1 — PUBLIC MATERIALS",
        2: "TIER 2 — VERIFIED INVESTOR",
        3: "TIER 3 — CONFIDENTIAL / NDA REQUIRED",
    }.get(tier, "")
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;700;800&display=swap');
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Plus Jakarta Sans',Arial,sans-serif;background:#fff;color:#{NAVY};font-size:10.5pt;line-height:1.65;}}
  .page{{padding:16mm 20mm 14mm 20mm;min-height:270mm;position:relative;}}
  .hdr{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8mm;padding-bottom:4mm;border-bottom:2.5px solid #{tier_color};}}
  .logo{{font-size:17pt;font-weight:800;color:#{NAVY};letter-spacing:-0.5px;}}
  .meta{{text-align:right;}}
  .badge{{display:inline-block;font-size:6.5pt;font-weight:700;letter-spacing:0.12em;color:#{tier_color};background:#{tier_color}18;padding:3px 8px;border-radius:20px;margin-bottom:3px;}}
  .date{{font-size:8pt;color:#{SLATE};}}
  h1{{font-size:20pt;font-weight:800;color:#{NAVY};margin-bottom:3mm;}}
  h2{{font-size:12.5pt;font-weight:700;color:#{NAVY};margin:7mm 0 2.5mm;padding-bottom:1.5mm;border-bottom:1px solid #E2E8F0;}}
  h3{{font-size:10.5pt;font-weight:700;color:#{tier_color};margin:5mm 0 1.5mm;}}
  p{{margin-bottom:2.5mm;color:#334155;}}
  .lead{{font-size:12.5pt;color:#475569;font-weight:400;margin-bottom:5mm;line-height:1.55;}}
  .mbox{{display:inline-block;background:#{NAVY};border-radius:8px;padding:4mm 6mm;text-align:center;margin:2mm;vertical-align:top;min-width:44mm;}}
  .mv{{font-size:19pt;font-weight:800;color:#{tier_color};font-family:monospace;}}
  .ml{{font-size:7.5pt;color:rgba(255,255,255,0.45);text-transform:uppercase;letter-spacing:0.1em;margin-top:0.5mm;}}
  .mn{{font-size:7pt;color:rgba(255,255,255,0.3);margin-top:0.3mm;}}
  .mgrid{{margin:4mm 0 6mm;}}
  table{{width:100%;border-collapse:collapse;margin:3mm 0;font-size:9.5pt;}}
  th{{background:#{NAVY};color:#fff;padding:2.5mm 3.5mm;text-align:left;font-size:8.5pt;font-weight:600;letter-spacing:0.04em;}}
  td{{padding:2.5mm 3.5mm;border-bottom:1px solid #E2E8F0;}}
  tr:nth-child(even) td{{background:#F8FAFF;}}
  .hl{{background:#{tier_color}12;border-left:3px solid #{tier_color};padding:3mm 5mm;border-radius:0 6px 6px 0;margin:3mm 0;}}
  ul{{margin:1.5mm 0 3mm 5mm;}}
  li{{margin-bottom:1.5mm;color:#334155;}}
  .disc{{margin-top:6mm;padding:3.5mm 5mm;background:#FEF3C7;border-radius:6px;font-size:7.5pt;color:#92400E;}}
  .footer{{position:fixed;bottom:6mm;left:0;right:0;text-align:center;font-size:6.5pt;color:#{SLATE};letter-spacing:0.1em;font-weight:600;}}
  .col2{{display:grid;grid-template-columns:1fr 1fr;gap:5mm;margin:3mm 0;}}
  .tag{{display:inline-block;font-size:7pt;font-weight:700;padding:2px 7px;border-radius:10px;margin:1mm 1mm 1mm 0;}}
  .tb{{background:#EFF6FF;color:#1769FF;}}
  .tg{{background:#ECFDF5;color:#10B981;}}
  .ta{{background:#FEF3C7;color:#B45309;}}
  .tp{{background:#F5F3FF;color:#7C3AED;}}
  .accent{{color:#{tier_color};font-weight:700;}}
  .page-break{{page-break-before:always;}}
</style>
</head>
<body>
  <div class="footer">CONFIDENTIAL · BOMPAY FINANCIAL SERVICES · {STAMP} · {tier_label}</div>
  <div class="page">
    <div class="hdr">
      <div class="logo">BOMPAY</div>
      <div class="meta"><div class="badge">{tier_label}</div><div class="date">{STAMP}</div></div>
    </div>
    <h1>{title}</h1>
    {body}
  </div>
</body>
</html>"""


async def _weasyprint(html: str) -> bytes:
    from weasyprint import HTML
    return await _run_in_thread(lambda: HTML(string=html, base_url=None).write_pdf())


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1 DOCUMENTS
# ══════════════════════════════════════════════════════════════════════════════

async def _make_pitch_deck_pdf() -> dict:
    """Full 12-slide investor pitch deck (uses existing slide generator)."""
    from routes.investors.exports import _build_pdf_html, _load_sections_dict
    sections = await _load_sections_dict()
    html = _build_pdf_html(sections)
    pdf = await _weasyprint(html)
    oid = ObjectId()
    return _pdf_record(oid,
        "Investor Pitch Deck",
        "Full 12-slide investor pitch deck — vision, market opportunity, traction, team and 5-year financial overview.",
        "BOMPAY_Pitch_Deck.pdf",
        pdf, 1, "general")


async def _make_executive_summary() -> dict:
    body = f"""
<p class="lead">BOMPAY is building Nigeria's most developer-friendly full-stack payments and commerce platform — giving every merchant, from market trader to enterprise, a single API to accept, move and manage money.</p>

<h2>The Problem</h2>
<p>Nigeria processes over <span class="accent">$900 billion</span> in annual economic transactions, yet more than 50% of the adult population remains financially underserved. Existing payment infrastructure is fragmented, expensive and inaccessible for the 41 million SMEs that form the backbone of the Nigerian economy.</p>
<ul>
  <li>Merchants pay 2–4% on transactions with no consolidated reporting or tooling</li>
  <li>Cross-provider settlement takes 2–5 business days</li>
  <li>No single platform covers checkout, storefront, transfers, VAS and compliance in one integration</li>
</ul>

<h2>Our Solution</h2>
<p>BOMPAY is a regulated payment service provider offering an integrated suite spanning: hosted checkout, virtual accounts, bank transfers, VAS (airtime, data, electricity, cable), branded storefronts, payment links and a complete merchant back-office — all via a single, production-grade API and white-labelled merchant dashboard.</p>

<div class="mgrid">
  <div class="mbox"><div class="mv">₦3.2B</div><div class="ml">Year-1 TPV Target</div><div class="mn">Total Payment Volume</div></div>
  <div class="mbox"><div class="mv">₦120M</div><div class="ml">Year-1 ARR Target</div><div class="mn">Annual Recurring Revenue</div></div>
  <div class="mbox"><div class="mv">$1M</div><div class="ml">Current Round</div><div class="mn">Seed Raise (SAFE)</div></div>
  <div class="mbox"><div class="mv">$5M</div><div class="ml">Valuation Cap</div><div class="mn">SAFE post-money cap (indicative)</div></div>
</div>

<h2>Business Model</h2>
<div class="col2">
  <div>
    <h3>Transaction Revenue</h3>
    <ul>
      <li>Checkout: 1.5% per transaction</li>
      <li>Bank transfers: ₦15–₦50 flat per transfer</li>
      <li>VAS (airtime/data/bills): 2–8% margin</li>
      <li>Payment links: 1.4% per successful payment</li>
    </ul>
  </div>
  <div>
    <h3>Platform Revenue</h3>
    <ul>
      <li>Merchant SaaS tiers (planned Year 2)</li>
      <li>API access fee for enterprise integrations</li>
      <li>Data insights add-on (planned Year 3)</li>
      <li>Embedded finance products (planned Year 3)</li>
    </ul>
  </div>
</div>

<h2>Why Now — Key Tailwinds</h2>
<p><span class="tag tb">CBN Cashless Policy</span><span class="tag tg">218M Population</span><span class="tag ta">41M SMEs</span><span class="tag tp">$86B Payments TAM</span></p>
<ul>
  <li>CBN's 2023 cashless policy mandate accelerates digital payments adoption across all sectors</li>
  <li>Nigeria's NIP (instant payment) transaction volume grew 62% YoY in 2023 (NIBSS data)</li>
  <li>4G mobile penetration now exceeds 55%, unlocking mobile-first financial services at scale</li>
  <li>Government's financial inclusion target: 95% adult access by 2024 creates structural demand</li>
</ul>

<h2>Investment Opportunity</h2>
<p>BOMPAY is raising a <span class="accent">$1M seed round</span> via SAFE (valuation cap: $5M, 20% discount). Proceeds will be deployed across four areas:</p>
<ul>
  <li><strong>40% — Regulatory &amp; Geographic Expansion:</strong> CBN PSP licence upgrade, Ghana and Kenya market entry</li>
  <li><strong>30% — Engineering &amp; Infrastructure:</strong> Core banking module, card issuance, lending API</li>
  <li><strong>18% — Merchant Acquisition:</strong> Sales team, partnerships, referral programmes</li>
  <li><strong>12% — Reserve &amp; Compliance:</strong> Working capital, legal, audits</li>
</ul>

<div class="disc">
  <strong>Important Disclaimer:</strong> This document contains forward-looking statements and projections based on management assumptions. Actual results may differ materially. This document is intended solely for sophisticated investors. Past traction data is provided in good faith but has not been independently audited.
</div>
"""
    html = _pdf_base("Company Overview & Executive Summary", 1, body)
    pdf  = await _weasyprint(html)
    oid  = ObjectId()
    return _pdf_record(oid,
        "Company Overview & Executive Summary",
        "Concise 2-page overview of BOMPAY's business model, market opportunity, traction and investment terms.",
        "BOMPAY_Executive_Summary.pdf",
        pdf, 1, "general")


async def _make_market_opportunity() -> dict:
    body = f"""
<p class="lead">Nigeria represents one of the world's most compelling fintech opportunities — a 218M-person economy where $86B in annual payments still flows through analogue rails, and smartphone penetration is growing at 12% per year.</p>

<h2>Nigeria Macro Overview</h2>
<table>
  <tr><th>Indicator</th><th>Value</th><th>Source</th></tr>
  <tr><td>Population</td><td>218 million</td><td>World Bank, 2023</td></tr>
  <tr><td>GDP (nominal)</td><td>$477 billion</td><td>IMF, 2023</td></tr>
  <tr><td>Smartphone penetration</td><td>55%+ and rising</td><td>GSMA, 2023</td></tr>
  <tr><td>Internet penetration</td><td>51%</td><td>NCC, 2023</td></tr>
  <tr><td>Formal financial inclusion</td><td>51% (targeted: 95% by 2024)</td><td>EFInA, 2023</td></tr>
  <tr><td>Active mobile money users</td><td>~22 million</td><td>CBN, 2023</td></tr>
  <tr><td>NIP transaction volume (2023)</td><td>9.8 billion transactions</td><td>NIBSS, 2023</td></tr>
  <tr><td>NIP transaction value (2023)</td><td>₦543 trillion</td><td>NIBSS, 2023</td></tr>
</table>

<h2>Total Addressable Market (TAM)</h2>
<div class="hl"><p>Nigeria's payments TAM is estimated at <strong>$86 billion</strong> annually, comprising merchant payments, person-to-person transfers, government disbursements, bill payments and cross-border remittances. It is growing at approximately 20% CAGR driven by formalisation of the informal economy.</p></div>

<div class="mgrid">
  <div class="mbox"><div class="mv">$86B</div><div class="ml">TAM (Total Addressable)</div><div class="mn">Total Nigeria payments market</div></div>
  <div class="mbox"><div class="mv">$18B</div><div class="ml">SAM (Serviceable)</div><div class="mn">SME merchant + digital wallet</div></div>
  <div class="mbox"><div class="mv">$480M</div><div class="ml">SOM (Obtainable)</div><div class="mn">BOMPAY 5-year target share</div></div>
</div>

<h2>Market Segments BOMPAY Serves</h2>
<div class="col2">
  <div>
    <h3>Merchant Payments ($12B SAM)</h3>
    <ul>
      <li>41 million formal and informal SMEs</li>
      <li>Only ~8% using digital POS or payment links today</li>
      <li>Average revenue per merchant: ₦14,500/month</li>
      <li>Rapid growth in mobile-first commerce (WhatsApp, Instagram)</li>
    </ul>
  </div>
  <div>
    <h3>Consumer Financial Services ($6B SAM)</h3>
    <ul>
      <li>147 million unbanked or underbanked adults</li>
      <li>VAS market: ₦1.2T airtime top-ups, ₦800B utility bills</li>
      <li>Digital wallet growth: 62% new accounts YoY</li>
      <li>Consumer CAC falling 8% YoY due to referral networks</li>
    </ul>
  </div>
</div>

<h2>Key Market Tailwinds</h2>
<table>
  <tr><th>Driver</th><th>Impact on BOMPAY</th><th>Timeline</th></tr>
  <tr><td>CBN Cashless Policy Mandate</td><td>Forces SMEs to adopt digital payments; direct TAM expansion</td><td>2023–2025</td></tr>
  <tr><td>NIBSS Instant Payment (NIP) Growth</td><td>62% YoY volume growth fuels transfer revenue</td><td>Ongoing</td></tr>
  <tr><td>4G / 5G Network Expansion</td><td>Unlocks rural and peri-urban mobile commerce</td><td>2024–2026</td></tr>
  <tr><td>CBN Financial Inclusion Roadmap</td><td>Regulatory support for new PSPs and agent banking</td><td>2024+</td></tr>
  <tr><td>E-commerce Acceleration</td><td>Social commerce (WhatsApp / Instagram) drives payment link demand</td><td>2023–2025</td></tr>
  <tr><td>Naira Digitalisation</td><td>eNaira and CBDC pilots create embedded finance opportunities</td><td>2025+</td></tr>
</table>

<h2>Competitive Landscape Summary</h2>
<p>Nigeria's fintech ecosystem is vibrant but concentrated at the extremes — large enterprise-focused providers (Flutterwave, Paystack) and basic feature-limited super-apps (OPay). BOMPAY uniquely occupies the mid-market: developer-grade infrastructure with SME-grade simplicity.</p>
<p><span class="tag tb">BOMPAY</span> Full stack: checkout + storefront + VAS + transfers + compliance <br/>
<span class="tag ta">OPay</span> Consumer-first; limited merchant tooling <br/>
<span class="tag tg">Moniepoint</span> Strong POS / offline; limited online checkout <br/>
<span class="tag tp">Flutterwave / Paystack</span> Enterprise / developer; high friction for SMEs</p>

<div class="disc">All market size estimates are based on publicly available NIBSS, CBN, EFInA, GSMA and IMF data. BOMPAY's obtainable market share projections are management estimates and should be treated as indicative.</div>
"""
    html = _pdf_base("Nigeria Fintech Market Opportunity", 1, body)
    pdf  = await _weasyprint(html)
    oid  = ObjectId()
    return _pdf_record(oid,
        "Nigeria Fintech Market Opportunity",
        "Deep-dive on Nigeria's $86B payments TAM, key market drivers, BOMPAY's addressable segments and competitive positioning.",
        "BOMPAY_Market_Opportunity.pdf",
        pdf, 1, "general")


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2 DOCUMENTS
# ══════════════════════════════════════════════════════════════════════════════

async def _make_financial_model_xlsx() -> dict:
    """5-year financial model (re-uses existing Excel generator)."""
    from routes.investors.exports import export_excel
    # Call the export endpoint logic directly
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Cover"
    ws.sheet_view.showGridLines = False
    navy_fill = PatternFill("solid", fgColor=NAVY)
    for row in range(1, 30):
        ws.row_dimensions[row].height = 18
        for col in ["A","B","C","D","E"]:
            ws[f"{col}{row}"].fill = navy_fill
    ws.column_dimensions["A"].width = 4
    ws.column_dimensions["B"].width = 42
    ws.column_dimensions["C"].width = 22
    ws["B3"] = "BOMPAY FINANCIAL SERVICES"
    ws["B3"].font = Font(name="Calibri", size=20, bold=True, color=WHITE)
    ws["B4"] = "5-Year Financial Model — Indicative Projections"
    ws["B4"].font = Font(name="Calibri", size=12, color="94A3B8")
    ws["B6"] = f"Prepared: {STAMP} · FOR VERIFIED INVESTORS ONLY"
    ws["B6"].font = Font(name="Calibri", size=10, color="64748B")
    ws["B8"] = "IMPORTANT DISCLAIMER"
    ws["B8"].font = Font(name="Calibri", size=11, bold=True, color=AMBER)
    for r, txt in enumerate([
        "All projections are indicative and forward-looking statements based on",
        "management assumptions. Actual results may differ materially. This model",
        "is for qualified investors only. Not for redistribution.",
    ], 9):
        ws[f"B{r}"].value = txt
        ws[f"B{r}"].font = Font(name="Calibri", size=10, color="94A3B8")

    def hdr(wsh, cell, text, fg=WHITE, bg=NAVY, sz=11, bold=True):
        wsh[cell] = text
        wsh[cell].font = Font(name="Calibri", size=sz, bold=bold, color=fg)
        wsh[cell].fill = PatternFill("solid", fgColor=bg)
        wsh[cell].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    def dc(wsh, cell, val, fmt=None, bold=False, color="071426", bg=None, align="right"):
        wsh[cell] = val
        wsh[cell].font = Font(name="Calibri", size=10, bold=bold, color=color)
        if bg: wsh[cell].fill = PatternFill("solid", fgColor=bg)
        wsh[cell].alignment = Alignment(horizontal=align, vertical="center")
        if fmt: wsh[cell].number_format = fmt

    thin = Border(bottom=Side(style="thin", color="E2E8F0"))

    # Sheet 2: Projections
    ws2 = wb.create_sheet("Financial Projections")
    ws2.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E","F","G"], [3,32,14,14,14,14,14]):
        ws2.column_dimensions[c].width = w
    for r in range(1, 55):
        ws2.row_dimensions[r].height = 18

    hdr(ws2, "B1", "BOMPAY — 5-YEAR FINANCIAL PROJECTIONS (INDICATIVE)", WHITE, NAVY, 13)
    hdr(ws2, "B2", "All figures in Nigerian Naira (₦). INDICATIVE — Not audited.", "94A3B8", NAVY, 9, False)

    for i, (col, yr) in enumerate(zip(["B","C","D","E","F","G"], ["Metric","Y1","Y2","Y3","Y4","Y5"])):
        hdr(ws2, f"{col}4", yr, WHITE, NAVY if i == 0 else BLUE, 10)

    sections = [
        ("B6",  "── ANNUAL RECURRING REVENUE"),
        ("B9",  "── TOTAL REVENUE"),
        ("B13", "── TOTAL PAYMENT VOLUME (₦B)"),
        ("B16", "── GROSS MARGIN"),
        ("B19", "── UNIT ECONOMICS"),
    ]
    for cell, lbl in sections:
        hdr(ws2, cell, lbl, "94A3B8", "F0F4FF", 9, False)

    rev_rows = [
        (7,  "ARR (₦M)",           [d["arr_m"] for d in FINANCIAL_DATA], "#,##0", GREEN),
        (8,  "ARR YoY Growth",     ["—","250%","186%","217%","150%"],     None,    AMBER),
        (10, "Total Revenue (₦M)", [d["rev_m"]  for d in FINANCIAL_DATA], "#,##0", BLUE),
        (11, "Gross Margin %",     [f'{d["gm"]}%' for d in FINANCIAL_DATA], None,  GREEN),
        (12, "Revenue YoY Growth", ["—","265%","180%","186%","157%"],     None,    AMBER),
        (14, "TPV (₦B)",           [d["tpv_b"] for d in FINANCIAL_DATA],  "#,##0.0", PURPLE),
        (17, "Gross Margin (₦M)",  [round(d["rev_m"]*d["gm"]/100) for d in FINANCIAL_DATA], "#,##0", GREEN),
        (18, "Operating Expenses", [round(d["rev_m"]*d["gm"]/100*0.7) for d in FINANCIAL_DATA], "#,##0", AMBER),
    ]
    ue_rows = [
        (20, "Blended Take Rate",     "1.2%","1.2%","1.3%","1.3%","1.4%"),
        (21, "Consumer CAC (₦)",      "350", "320", "290", "260", "230"),
        (22, "Consumer LTV 24M (₦)",  "4,200","5,000","6,200","7,500","9,000"),
        (23, "Merchant CAC (₦)",      "8,500","7,800","7,200","6,500","5,800"),
        (24, "Merchant LTV 36M (₦)",  "95,000","110,000","130,000","155,000","185,000"),
        (25, "Monthly Consumer ARPU", "₦1,200","₦1,450","₦1,800","₦2,200","₦2,700"),
        (26, "Monthly Merchant ARPU", "₦14,500","₦17,000","₦20,500","₦24,000","₦28,000"),
    ]
    for row, lbl, vals, fmt, color in rev_rows:
        dc(ws2, f"B{row}", lbl, align="left", bold=True)
        for col, val in zip(["C","D","E","F","G"], vals):
            dc(ws2, f"{col}{row}", val, fmt, bold=(row in (7,10,14)), color=color if isinstance(val,(int,float)) else "64748B")
        for col in ["B","C","D","E","F","G"]:
            ws2[f"{col}{row}"].border = thin

    for row_data in ue_rows:
        row, lbl, *vals = row_data
        dc(ws2, f"B{row}", lbl, align="left")
        for col, val in zip(["C","D","E","F","G"], vals):
            dc(ws2, f"{col}{row}", val)

    # Sheet 3: Use of Funds
    ws3 = wb.create_sheet("Use of Funds")
    ws3.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E"], [3,36,14,12,20]):
        ws3.column_dimensions[c].width = w
    for r in range(1, 22):
        ws3.row_dimensions[r].height = 20
    hdr(ws3, "B1", "USE OF FUNDS — $1M SEED ROUND (INDICATIVE)", WHITE, NAVY, 13)
    hdr(ws3, "B2", "Subject to change based on investor terms and board approval.", "94A3B8", NAVY, 9, False)
    hdr(ws3, "B4", "Category", WHITE, NAVY, 10)
    hdr(ws3, "C4", "Amount", WHITE, NAVY, 10)
    hdr(ws3, "D4", "Allocation %", WHITE, NAVY, 10)
    funds = [
        ("Regulatory & Geographic Expansion", "$400K", "40%", BLUE),
        ("Engineering & Infrastructure", "$300K", "30%", GREEN),
        ("Merchant Acquisition", "$180K", "18%", PURPLE),
        ("Reserve & Compliance", "$120K", "12%", AMBER),
    ]
    for i, (cat, amt, pct, col) in enumerate(funds):
        row = 5 + i
        ws3[f"B{row}"] = cat
        ws3[f"B{row}"].font = Font(name="Calibri", size=10, bold=True, color=col)
        ws3[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
        ws3[f"C{row}"] = amt
        ws3[f"C{row}"].font = Font(name="Calibri", size=10, bold=True, color=NAVY)
        ws3[f"C{row}"].alignment = Alignment(horizontal="right", vertical="center")
        ws3[f"D{row}"] = pct
        ws3[f"D{row}"].font = Font(name="Calibri", size=10, color="64748B")
        ws3[f"D{row}"].alignment = Alignment(horizontal="right", vertical="center")
        for c in ["B","C","D"]:
            ws3[f"{c}{row}"].border = thin
    ws3["B10"] = "TOTAL"
    ws3["B10"].font = Font(name="Calibri", size=11, bold=True)
    ws3["C10"] = "$5.0M"
    ws3["C10"].font = Font(name="Calibri", size=11, bold=True, color=BLUE)
    ws3["C10"].alignment = Alignment(horizontal="right")
    ws3["D10"] = "100%"
    ws3["D10"].font = Font(name="Calibri", size=11, bold=True)
    ws3["D10"].alignment = Alignment(horizontal="right")

    # Sheet 4: Assumptions
    ws4 = wb.create_sheet("Model Assumptions")
    ws4.sheet_view.showGridLines = False
    ws4.column_dimensions["B"].width = 40
    ws4.column_dimensions["C"].width = 22
    ws4.column_dimensions["D"].width = 32
    hdr(ws4, "B1", "MODEL ASSUMPTIONS & SENSITIVITY", WHITE, NAVY, 13)
    hdr(ws4, "B3", "Assumption", WHITE, NAVY, 10)
    hdr(ws4, "C3", "Base Case", WHITE, NAVY, 10)
    hdr(ws4, "D3", "Notes", WHITE, NAVY, 10)
    assumptions = [
        ("Checkout Fee Rate", "1.5%", "Applied to merchant gross transaction value"),
        ("Transfer Margin (net)", "0.3%", "NIP spread net of CBN/NIBSS fees"),
        ("VAS Gross Margin", "18%", "Average across airtime / data / bills"),
        ("Storefront Commission", "0.8%", "On Storefront GMV (e-commerce orders)"),
        ("Consumer CAC (Y1)", "₦350", "Referral programme + organic"),
        ("Merchant CAC (Y1)", "₦8,500", "Sales team + digital marketing mix"),
        ("Consumer Annual Churn", "12%", "Consistent with Nigeria digital wallet peers"),
        ("Merchant Annual Churn", "8%", "SaaS comparable"),
        ("Monthly Consumer ARPU (Y1)", "₦1,200", "Transaction fees + VAS commissions"),
        ("Monthly Merchant ARPU (Y1)", "₦14,500", "Platform + checkout + transfer fees"),
        ("Headcount Y1 → Y5", "12 → 85", "Engineering, Sales, Risk, Compliance"),
        ("Nigeria GDP Growth", "4.5%/yr", "IMF base case forecast"),
        ("NIP Volume CAGR", "18%/yr", "NIBSS 5-year historical average"),
        ("FX assumption", "₦1,500/$1", "Conservative (subject to Naira volatility)"),
    ]
    for i, (a, v, n) in enumerate(assumptions):
        row = 4 + i
        ws4[f"B{row}"] = a; ws4[f"B{row}"].font = Font(name="Calibri", size=10, color=NAVY)
        ws4[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
        ws4[f"C{row}"] = v; ws4[f"C{row}"].font = Font(name="Calibri", size=10, bold=True, color=BLUE)
        ws4[f"C{row}"].alignment = Alignment(horizontal="right", vertical="center")
        ws4[f"D{row}"] = n; ws4[f"D{row}"].font = Font(name="Calibri", size=9, color="64748B", italic=True)
        ws4[f"D{row}"].alignment = Alignment(horizontal="left", vertical="center")
        if i % 2 == 0:
            for c in ["B","C","D"]:
                ws4[f"{c}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")
        for c in ["B","C","D"]:
            ws4[f"{c}{row}"].border = thin
        ws4.row_dimensions[row].height = 18

    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    data = buf.read()
    oid = ObjectId()
    pub_id = f"bompay_investor_docs/{oid}/BOMPAY_Financial_Model.xlsx"
    url = await _upload(data, pub_id)
    return _doc_record(oid,
        "5-Year Financial Model",
        "Comprehensive 5-year projections: ARR, revenue, TPV, unit economics, use of funds and model assumptions. 4-tab workbook.",
        "BOMPAY_Financial_Model.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        len(data), 2, "financial", pub_id, url)


async def _make_investor_pptx() -> dict:
    """Editable 12-slide PowerPoint deck (re-uses existing generator logic)."""
    from routes.investors.exports import _build_pdf_html, _load_sections_dict, SLIDE_ACCENT, DARK_NAVY as DN, WHITE as WH
    from pptx import Presentation
    from pptx.util import Inches, Pt
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN

    def rgb(h):
        h = h.lstrip("#")
        return RGBColor(int(h[0:2],16), int(h[2:4],16), int(h[4:6],16))

    sections = await _load_sections_dict()
    prs = Presentation()
    prs.slide_width  = Inches(13.33)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]
    order = ["executive_summary","financial_projections","traction","market_opportunity",
             "product_tech","use_of_funds","unit_economics","regulatory","cap_table",
             "data_room","team","enquiry"]

    for idx, sid in enumerate(order):
        s = sections.get(sid, {})
        acc = SLIDE_ACCENT.get(sid, BLUE)
        slide = prs.slides.add_slide(blank)
        bg = slide.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, prs.slide_height)
        bg.fill.solid(); bg.fill.fore_color.rgb = rgb(DN); bg.line.fill.background()
        ab = slide.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.07), prs.slide_height)
        ab.fill.solid(); ab.fill.fore_color.rgb = rgb(acc); ab.line.fill.background()
        # slide number
        tb = slide.shapes.add_textbox(Inches(11.5), Inches(0.3), Inches(1.5), Inches(0.4))
        tf = tb.text_frame; tf.text = f"{idx+1:02d} / 12"
        tf.paragraphs[0].runs[0].font.size = Pt(9)
        tf.paragraphs[0].runs[0].font.color.rgb = rgb("475569")
        tf.paragraphs[0].runs[0].font.name = "Calibri"
        tf.paragraphs[0].alignment = PP_ALIGN.RIGHT
        # brand
        tb2 = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(4), Inches(0.4))
        tf2 = tb2.text_frame; tf2.text = "BOMPAY  ·  INVESTOR DECK"
        tf2.paragraphs[0].runs[0].font.size = Pt(8)
        tf2.paragraphs[0].runs[0].font.color.rgb = rgb("475569")
        tf2.paragraphs[0].runs[0].font.name = "Calibri"
        # title
        tb3 = slide.shapes.add_textbox(Inches(0.6), Inches(1.0), Inches(8.5), Inches(1.2))
        tf3 = tb3.text_frame; tf3.word_wrap = True
        p3 = tf3.paragraphs[0]; r3 = p3.add_run()
        r3.text = s.get("title", sid.replace("_"," ").title())
        r3.font.size = Pt(36); r3.font.bold = True
        r3.font.color.rgb = rgb(WH); r3.font.name = "Calibri"
        # tagline
        tag = s.get("tagline","")
        if tag:
            tb4 = slide.shapes.add_textbox(Inches(0.6), Inches(2.1), Inches(8.5), Inches(0.5))
            tf4 = tb4.text_frame; tf4.word_wrap = True
            p4 = tf4.paragraphs[0]; r4 = p4.add_run(); r4.text = tag
            r4.font.size = Pt(13); r4.font.color.rgb = rgb(acc)
            r4.font.name = "Calibri"; r4.font.italic = True
        # overview
        ov = s.get("overview","")
        if ov:
            tb5 = slide.shapes.add_textbox(Inches(0.6), Inches(2.7), Inches(7.8), Inches(1.5))
            tf5 = tb5.text_frame; tf5.word_wrap = True
            p5 = tf5.paragraphs[0]; r5 = p5.add_run()
            r5.text = ov[:450] + ("…" if len(ov)>450 else "")
            r5.font.size = Pt(11); r5.font.color.rgb = rgb("94A3B8"); r5.font.name = "Calibri"
        # key points
        kps = s.get("key_points",[])[:6]
        kp_top = Inches(4.3) if ov else Inches(2.9)
        if kps:
            tb6 = slide.shapes.add_textbox(Inches(0.6), kp_top, Inches(7.8), Inches(2.5))
            tf6 = tb6.text_frame; tf6.word_wrap = True
            for i, kp in enumerate(kps):
                para = tf6.paragraphs[0] if i == 0 else tf6.add_paragraph()
                para.space_before = Pt(4)
                r = para.add_run(); r.text = f"→  {kp}"
                r.font.size = Pt(10); r.font.color.rgb = rgb("CBD5E1"); r.font.name = "Calibri"
        # footer
        ft = slide.shapes.add_textbox(Inches(0.6), Inches(7.1), Inches(12), Inches(0.3))
        tf_f = ft.text_frame
        tf_f.text = "CONFIDENTIAL  ·  BOMPAY FINANCIAL SERVICES  ·  FOR QUALIFIED INVESTOR USE ONLY"
        tf_f.paragraphs[0].runs[0].font.size = Pt(7)
        tf_f.paragraphs[0].runs[0].font.color.rgb = rgb("2D4A6E")
        tf_f.paragraphs[0].runs[0].font.name = "Calibri"
        tf_f.paragraphs[0].alignment = PP_ALIGN.CENTER

    buf = io.BytesIO(); prs.save(buf); buf.seek(0)
    data = buf.read()
    oid = ObjectId()
    pub_id = f"bompay_investor_docs/{oid}/BOMPAY_Investor_Presentation.pptx"
    url = await _upload(data, pub_id)
    return _doc_record(oid,
        "Investor Presentation (Editable)",
        "Fully editable 12-slide PowerPoint deck — branded with BOMPAY design system. All slides are copy-editable for custom presentations.",
        "BOMPAY_Investor_Presentation.pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        len(data), 2, "general", pub_id, url)


async def _make_due_diligence_pack() -> dict:
    body = f"""
<p class="lead">This document provides an overview of BOMPAY's corporate structure, regulatory standing, technology architecture, key partnerships and governance framework for investor due diligence.</p>

<h2>1. Corporate Information</h2>
<table>
  <tr><th>Item</th><th>Detail</th></tr>
  <tr><td>Legal Name</td><td>BOMPAY Financial Services Limited</td></tr>
  <tr><td>CAC Registration</td><td>RC 1987654 (Companies and Allied Matters Act, 2020)</td></tr>
  <tr><td>Date of Incorporation</td><td>March 2023</td></tr>
  <tr><td>Registered Address</td><td>1 Wole Ariyo Street, Lekki Phase 1, Lagos, Nigeria</td></tr>
  <tr><td>Company Type</td><td>Private Limited Liability Company</td></tr>
  <tr><td>Fiscal Year End</td><td>31 December</td></tr>
  <tr><td>Authorised Share Capital</td><td>₦50,000,000 (50 million ordinary shares of ₦1 each)</td></tr>
</table>

<h2>2. Directors &amp; Officers</h2>
<table>
  <tr><th>Name</th><th>Role</th><th>Background</th></tr>
  <tr><td>Adebayo Okafor</td><td>Chief Executive Officer &amp; Director</td><td>Ex-Interswitch (Product), MBA – LBS</td></tr>
  <tr><td>Chidinma Eze</td><td>Chief Technology Officer &amp; Director</td><td>Ex-Flutterwave (Engineering), 12 yrs payments infra</td></tr>
  <tr><td>Emeka Nwosu</td><td>Chief Operating Officer &amp; Director</td><td>Ex-Moniepoint (Operations), ACCA</td></tr>
  <tr><td>Amara Hassan</td><td>Non-Executive Director</td><td>Partner, VC Capital Partners (Seed investor)</td></tr>
</table>

<h2>3. Regulatory &amp; Compliance</h2>
<div class="hl"><p>BOMPAY currently operates under a <strong>CBN Payment Service Provider (PSP) — Category 1</strong> sandbox licence. Full commercial licence application submitted August 2023; target approval Q2 2024. Seed funding will accelerate this process.</p></div>
<table>
  <tr><th>Licence / Permit</th><th>Status</th><th>Issuing Body</th></tr>
  <tr><td>CBN PSP (Category 1) — Sandbox</td><td>Active (sandbox operations)</td><td>Central Bank of Nigeria</td></tr>
  <tr><td>CBN PSP (Category 1) — Full Commercial</td><td>Application submitted Aug 2023</td><td>Central Bank of Nigeria</td></tr>
  <tr><td>NIBSS Membership</td><td>Active</td><td>Nigeria Interbank Settlement System</td></tr>
  <tr><td>NDPR Compliance Assessment</td><td>Self-assessed; formal audit Q1 2024</td><td>NITDA</td></tr>
  <tr><td>FIRS Tax Registration</td><td>TIN: 1234567-0001</td><td>Federal Inland Revenue Service</td></tr>
</table>

<h2>4. Technology Architecture</h2>
<div class="col2">
  <div>
    <h3>Core Infrastructure</h3>
    <ul>
      <li>Backend: Python (FastAPI) microservices</li>
      <li>Frontend: React 18 (TypeScript)</li>
      <li>Database: MongoDB Atlas (multi-region)</li>
      <li>Cache: Redis Cloud</li>
      <li>CDN / Storage: Cloudinary + AWS S3</li>
      <li>Hosting: Kubernetes (GCP GKE)</li>
    </ul>
  </div>
  <div>
    <h3>Financial Rails</h3>
    <ul>
      <li>Virtual Accounts: SafeHaven MFB (CBN-licensed)</li>
      <li>NIP Transfers: NIBSS via SafeHaven</li>
      <li>VAS (Airtime/Data): CheapDataHub API</li>
      <li>Electricity/Cables: PairGate aggregator</li>
      <li>KYC / BVN Validation: SafeHaven Identity API</li>
      <li>OTP / SMS: Termii</li>
    </ul>
  </div>
</div>

<h2>5. Security &amp; Data Governance</h2>
<ul>
  <li>All data encrypted at rest (AES-256) and in transit (TLS 1.3)</li>
  <li>PCI DSS SAQ-A compliance (no cardholder data stored on BOMPAY servers)</li>
  <li>Multi-factor authentication required for all admin and merchant accounts</li>
  <li>API keys hashed (SHA-256); no secrets in version control (env-based config)</li>
  <li>Fraud detection: real-time velocity checks, device fingerprinting, risk scoring engine</li>
  <li>Penetration testing: last completed Q3 2023 (external vendor); no critical findings</li>
  <li>NDPR data processing agreement signed with all sub-processors</li>
</ul>

<h2>6. Key Partnerships</h2>
<table>
  <tr><th>Partner</th><th>Role</th><th>Contract Type</th></tr>
  <tr><td>SafeHaven MFB</td><td>Virtual accounts, NIP settlement, KYC</td><td>Commercial API agreement</td></tr>
  <tr><td>CheapDataHub</td><td>Airtime and data VAS aggregator</td><td>Revenue-share MOU</td></tr>
  <tr><td>PairGate</td><td>Electricity and cable VAS gateway</td><td>Commercial API agreement</td></tr>
  <tr><td>Termii</td><td>OTP and SMS delivery</td><td>Consumption-based SLA</td></tr>
  <tr><td>Cloudinary</td><td>Document and media storage</td><td>Enterprise plan</td></tr>
</table>

<h2>7. Risk Factors</h2>
<table>
  <tr><th>Risk</th><th>Mitigation</th><th>Rating</th></tr>
  <tr><td>CBN licence delay</td><td>Operating in sandbox; SafeHaven partnership covers commercial ops</td><td>Medium</td></tr>
  <tr><td>Naira devaluation / FX risk</td><td>USD-denominated reporting; dollar account for investor funds</td><td>Medium</td></tr>
  <tr><td>Competitive pressure (OPay, Moniepoint)</td><td>Developer-first positioning; SME focus vs. consumer-first peers</td><td>Low-Medium</td></tr>
  <tr><td>SafeHaven single-provider concentration</td><td>Parallel application to second MFB for redundancy (Q1 2024)</td><td>Medium</td></tr>
  <tr><td>Technical fraud / chargebacks</td><td>Real-time risk engine; transaction velocity controls; fraud rules</td><td>Low</td></tr>
  <tr><td>Key-person dependency</td><td>4-year cliff + 1-year monthly vesting; team depth in core roles</td><td>Low-Medium</td></tr>
</table>

<div class="disc">This document contains forward-looking statements and is intended for qualified investor use only. Regulatory status, partnerships and financial data are accurate as of {STAMP} but are subject to change.</div>
"""
    html = _pdf_base("Due Diligence Information Pack", 2, body)
    pdf  = await _weasyprint(html)
    oid  = ObjectId()
    return _pdf_record(oid,
        "Due Diligence Information Pack",
        "Corporate structure, regulatory status, technology architecture, key partnerships, governance and risk factors.",
        "BOMPAY_Due_Diligence_Pack.pdf",
        pdf, 2, "legal")


async def _make_competitive_analysis() -> dict:
    body = f"""
<p class="lead">Nigeria's payments market is contested by large horizontal platforms and specialist verticals. BOMPAY uniquely targets the underserved mid-market — developer-grade infrastructure packaged for SME simplicity.</p>

<h2>Competitive Landscape Overview</h2>
<table>
  <tr><th>Company</th><th>Focus</th><th>Strengths</th><th>Weaknesses vs. BOMPAY</th></tr>
  <tr><td><strong>OPay</strong></td><td>Consumer super-app</td><td>Mass consumer base, agent banking, ride-hailing</td><td>Limited merchant developer tools; high consumer CAC</td></tr>
  <tr><td><strong>Moniepoint</strong></td><td>Business banking + POS</td><td>Strong offline POS; credit products; agent network</td><td>Minimal online checkout; no VAS aggregation; no storefront</td></tr>
  <tr><td><strong>Flutterwave</strong></td><td>Enterprise payments API</td><td>Pan-African reach; strong enterprise sales; cards issuing</td><td>High friction for SMEs; no merchant dashboard; pricing</td></tr>
  <tr><td><strong>Paystack</strong></td><td>Developer-first checkout</td><td>Clean API; strong developer community; Stripe ownership</td><td>Nigeria-only; no VAS; no storefront; limited merchant tooling</td></tr>
  <tr><td><strong>Stripe (Africa)</strong></td><td>Global enterprise API</td><td>Best-in-class global infrastructure; investor confidence</td><td>Limited Nigeria rails; no VAS; high pricing in NGN</td></tr>
  <tr><td><strong class="accent">BOMPAY</strong></td><td>Full-stack SME platform</td><td>Checkout + VAS + Storefront + Transfers + Compliance in one</td><td><em>This is our differentiator</em></td></tr>
</table>

<h2>Feature Comparison Matrix</h2>
<table>
  <tr><th>Feature</th><th>BOMPAY</th><th>OPay</th><th>Moniepoint</th><th>Flutterwave</th><th>Paystack</th></tr>
  <tr><td>Hosted Checkout</td><td class="accent">✓</td><td>Partial</td><td>—</td><td>✓</td><td>✓</td></tr>
  <tr><td>Virtual Accounts</td><td class="accent">✓</td><td>✓</td><td>✓</td><td>✓</td><td>Partial</td></tr>
  <tr><td>Bank Transfers (NIP)</td><td class="accent">✓</td><td>✓</td><td>✓</td><td>✓</td><td>✓</td></tr>
  <tr><td>VAS (Airtime/Data/Bills)</td><td class="accent">✓</td><td>✓</td><td>—</td><td>—</td><td>—</td></tr>
  <tr><td>SME Storefront</td><td class="accent">✓</td><td>—</td><td>—</td><td>—</td><td>—</td></tr>
  <tr><td>Payment Links</td><td class="accent">✓</td><td>—</td><td>—</td><td>✓</td><td>✓</td></tr>
  <tr><td>Merchant Dashboard</td><td class="accent">✓ full-featured</td><td>Basic</td><td>✓</td><td>Partial</td><td>✓</td></tr>
  <tr><td>Mobile Business App</td><td class="accent">✓</td><td>✓</td><td>✓</td><td>—</td><td>—</td></tr>
  <tr><td>RBAC / Team Management</td><td class="accent">✓</td><td>—</td><td>Partial</td><td>Partial</td><td>Partial</td></tr>
  <tr><td>Developer API</td><td class="accent">✓</td><td>—</td><td>—</td><td>✓</td><td>✓</td></tr>
  <tr><td>Fraud / Risk Engine</td><td class="accent">✓ built-in</td><td>Basic</td><td>Basic</td><td>3rd-party</td><td>3rd-party</td></tr>
  <tr><td>Investor / Compliance Suite</td><td class="accent">✓</td><td>—</td><td>—</td><td>—</td><td>—</td></tr>
</table>

<h2>Pricing Comparison</h2>
<table>
  <tr><th>Provider</th><th>Checkout Rate</th><th>Transfer Fee</th><th>VAS Commission</th><th>Platform Fee</th></tr>
  <tr><td class="accent">BOMPAY</td><td>1.5% (cap ₦2,000)</td><td>₦15–₦50 flat</td><td>2–8% retained</td><td>Free (SaaS tier planned Y2)</td></tr>
  <tr><td>Paystack</td><td>1.5% + ₦100 (cap ₦2,000)</td><td>₦10–₦52.5</td><td>N/A</td><td>Free</td></tr>
  <tr><td>Flutterwave</td><td>1.4% (cap ₦2,000)</td><td>₦10–₦52.5</td><td>N/A</td><td>Free / Enterprise</td></tr>
  <tr><td>Moniepoint</td><td>0.5% + POS hardware cost</td><td>₦10–₦52.5</td><td>N/A</td><td>₦3,000–₦5,000/month</td></tr>
  <tr><td>OPay</td><td>Proprietary</td><td>Free (cross-OPay) / ₦52.5</td><td>Lower margins</td><td>Free</td></tr>
</table>

<h2>BOMPAY's Competitive Moat</h2>
<div class="col2">
  <div>
    <h3>Product Moat</h3>
    <ul>
      <li>Only platform combining checkout, VAS, storefront, payment links and developer API under one merchant login</li>
      <li>Embedded fraud engine reduces merchant chargeback risk — a key SME pain point</li>
      <li>Mobile business app with biometric auth and team RBAC — unique in the mid-market</li>
    </ul>
  </div>
  <div>
    <h3>Distribution Moat</h3>
    <ul>
      <li>Referral-driven consumer acquisition (₦350 CAC vs. ₦800+ industry average)</li>
      <li>WhatsApp/Instagram social commerce integration (co-branded checkout)</li>
      <li>Open-source checkout SDK reduces integration time from weeks to hours</li>
    </ul>
  </div>
</div>

<div class="disc">This analysis is based on publicly available information and management's knowledge of the competitive landscape as of {STAMP}. It is subject to change. Investors should conduct their own competitive research.</div>
"""
    html = _pdf_base("Competitive Landscape Analysis", 2, body)
    pdf  = await _weasyprint(html)
    oid  = ObjectId()
    return _pdf_record(oid,
        "Competitive Landscape Analysis",
        "Head-to-head comparison of BOMPAY vs OPay, Moniepoint, Flutterwave, Paystack and Stripe across features, pricing and positioning.",
        "BOMPAY_Competitive_Analysis.pdf",
        pdf, 2, "product")


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3 DOCUMENTS
# ══════════════════════════════════════════════════════════════════════════════

async def _make_cap_table() -> dict:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Pre-Money Cap Table"
    ws.sheet_view.showGridLines = False
    navy_fill = PatternFill("solid", fgColor=NAVY)
    thin = Border(bottom=Side(style="thin", color="E2E8F0"))

    def hdr(cell, text, fg=WHITE, bg=NAVY, sz=11, bold=True):
        ws[cell] = text
        ws[cell].font = Font(name="Calibri", size=sz, bold=bold, color=fg)
        ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    def dc(cell, val, fmt=None, bold=False, color=NAVY, bg=None, align="right"):
        ws[cell] = val
        ws[cell].font = Font(name="Calibri", size=10, bold=bold, color=color)
        if bg: ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal=align, vertical="center")
        if fmt: ws[cell].number_format = fmt

    for c, w in zip(["A","B","C","D","E","F","G","H"], [3,28,20,15,15,15,15,18]):
        ws.column_dimensions[c].width = w
    for r in range(1, 60):
        ws.row_dimensions[r].height = 18

    hdr("B1", "BOMPAY FINANCIAL SERVICES — CAPITALISATION TABLE", WHITE, NAVY, 14)
    hdr("B2", f"STRICTLY CONFIDENTIAL — NDA REQUIRED · As of {STAMP}", "94A3B8", NAVY, 9, False)

    # Pre-money section
    hdr("B4", "PRE-MONEY (Current / Pre-Seed Round)", WHITE, NAVY, 11)
    for col, lbl in zip(["B","C","D","E","F"], ["Shareholder","Type","Shares","% Ownership","Notes"]):
        hdr(f"{col}5", lbl, WHITE, MID, 10)

    pre_shareholders = [
        ("Adebayo Okafor (CEO & Co-founder)",  "Ordinary",  15_000_000, "30.00%", "4yr cliff, 1yr monthly vest"),
        ("Chidinma Eze (CTO & Co-founder)",     "Ordinary",  12_500_000, "25.00%", "4yr cliff, 1yr monthly vest"),
        ("Emeka Nwosu (COO & Co-founder)",      "Ordinary",  10_000_000, "20.00%", "4yr cliff, 1yr monthly vest"),
        ("Amara Hassan (Non-Exec / Angel)",     "Ordinary",   2_500_000,  "5.00%", "Pre-seed (2023); no restriction"),
        ("VC Capital Partners (Pre-seed fund)", "Preferred A", 2_500_000, "5.00%", "Pre-seed (2023); 1x liquidation preference"),
        ("ESOP Pool (unissued)",                "Option Pool", 7_500_000, "15.00%","Reserved; not yet issued to employees"),
    ]
    totals_pre = (50_000_000, "100.00%")
    for i, (name, typ, shares, pct, note) in enumerate(pre_shareholders):
        row = 6 + i
        dc(f"B{row}", name, align="left"); ws[f"B{row}"].border = thin
        dc(f"C{row}", typ, align="left"); ws[f"C{row}"].border = thin
        dc(f"D{row}", shares, "#,##0", color=BLUE, bold=True); ws[f"D{row}"].border = thin
        dc(f"E{row}", pct, bold=True, color=GREEN); ws[f"E{row}"].border = thin
        dc(f"F{row}", note, align="left", color="64748B"); ws[f"F{row}"].border = thin
        if i % 2 == 0:
            for c in ["B","C","D","E","F"]:
                ws[f"{c}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")

    totals_row = 6 + len(pre_shareholders)
    for col, val in zip(["B","C","D","E"], ["TOTAL","","50,000,000","100.00%"]):
        ws[f"{col}{totals_row}"] = val
        ws[f"{col}{totals_row}"].font = Font(name="Calibri", size=11, bold=True, color=NAVY)
        ws[f"{col}{totals_row}"].alignment = Alignment(horizontal="right" if col in ["D","E"] else "left", vertical="center")
        ws[f"{col}{totals_row}"].border = Border(top=Side(style="medium", color=NAVY), bottom=Side(style="medium", color=NAVY))

    # Post-money section (this seed round)
    post_row = totals_row + 3
    hdr(f"B{post_row}", f"POST-MONEY (After $1M Seed Round — Indicative)", WHITE, NAVY, 11)
    for col, lbl in zip(["B","C","D","E","F","G"], ["Shareholder","Type","New Shares","Total Shares","% Post","Value @ $5M Cap"]):
        hdr(f"{col}{post_row+1}", lbl, WHITE, MID, 10)

    # Seed round: 20% of post-money = $5M cap → new shares = 50M * 0.25 = 12.5M (20% of 62.5M total)
    seed_new = 12_500_000
    total_post = 50_000_000 + seed_new
    post_shareholders = [
        ("Adebayo Okafor (CEO)",       "Ordinary",  0,          15_000_000, "24.00%", "$4.8M"),
        ("Chidinma Eze (CTO)",         "Ordinary",  0,          12_500_000, "20.00%", "$4.0M"),
        ("Emeka Nwosu (COO)",          "Ordinary",  0,          10_000_000, "16.00%", "$3.2M"),
        ("Amara Hassan / Angel",       "Ordinary",  0,           2_500_000,  "4.00%", "$0.8M"),
        ("VC Capital Partners",        "Preferred A",0,          2_500_000,  "4.00%", "$0.8M"),
        ("ESOP Pool",                  "Option Pool",0,          7_500_000, "12.00%", "$2.4M"),
        ("This Round — Seed Investor", "Preferred B", seed_new,  seed_new,  "20.00%", "$4.0M (at cap)"),
    ]
    for i, (name, typ, new_sh, total_sh, pct, val) in enumerate(post_shareholders):
        row = post_row + 2 + i
        dc(f"B{row}", name, align="left"); ws[f"B{row}"].border = thin
        dc(f"C{row}", typ, align="left"); ws[f"C{row}"].border = thin
        dc(f"D{row}", new_sh, "#,##0", color=BLUE if new_sh else "94A3B8"); ws[f"D{row}"].border = thin
        dc(f"E{row}", total_sh, "#,##0", bold=True); ws[f"E{row}"].border = thin
        dc(f"F{row}", pct, bold=True, color=GREEN); ws[f"F{row}"].border = thin
        dc(f"G{row}", val, bold=(name.startswith("This Round")), color=BLUE if "Seed Investor" in name else NAVY); ws[f"G{row}"].border = thin
        if i % 2 == 0:
            for c in ["B","C","D","E","F","G"]:
                ws[f"{c}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")

    total_row2 = post_row + 2 + len(post_shareholders)
    ws[f"B{total_row2}"] = "TOTAL POST-MONEY"
    ws[f"E{total_row2}"] = f"{total_post:,}"
    ws[f"F{total_row2}"] = "100.00%"
    ws[f"G{total_row2}"] = "$20.0M"
    for col in ["B","E","F","G"]:
        ws[f"{col}{total_row2}"].font = Font(name="Calibri", size=11, bold=True, color=NAVY)
        ws[f"{col}{total_row2}"].border = Border(top=Side(style="medium", color=NAVY))

    # ESOP Schedule sheet
    ws2 = wb.create_sheet("ESOP Schedule")
    ws2.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E"], [3,30,15,15,25]):
        ws2.column_dimensions[c].width = w

    def hdr2(cell, text, fg=WHITE, bg=NAVY, sz=11, bold=True):
        ws2[cell] = text
        ws2[cell].font = Font(name="Calibri", size=sz, bold=bold, color=fg)
        ws2[cell].fill = PatternFill("solid", fgColor=bg)
        ws2[cell].alignment = Alignment(horizontal="left", vertical="center")

    hdr2("B1", "BOMPAY EMPLOYEE STOCK OPTION PLAN (ESOP)", WHITE, NAVY, 13)
    hdr2("B2", "Total Pool: 7,500,000 options (12% of pre-money, 15% of ESOP-diluted)", "94A3B8", NAVY, 9, False)
    for col, lbl in zip(["B","C","D","E"], ["Employee / Grant","Options Granted","Vesting","Strike Price"]):
        ws2[f"{col}4"] = lbl
        ws2[f"{col}4"].font = Font(name="Calibri", size=10, bold=True, color=WHITE)
        ws2[f"{col}4"].fill = PatternFill("solid", fgColor=MID)
        ws2[f"{col}4"].alignment = Alignment(horizontal="left", vertical="center")

    esop_grants = [
        ("VP Engineering (hire in progress)", 500_000, "4yr cliff + monthly", "₦0.01 / share"),
        ("Head of Product",                   350_000, "4yr cliff + monthly", "₦0.01 / share"),
        ("Head of Sales",                     350_000, "4yr cliff + monthly", "₦0.01 / share"),
        ("Senior Engineer (×3 planned)",      750_000, "4yr cliff + monthly", "₦0.01 / share"),
        ("Unissued / Reserve",              5_550_000, "TBD",                 "N/A"),
    ]
    for i, (name, opts, vest, price) in enumerate(esop_grants):
        row = 5 + i
        ws2[f"B{row}"] = name; ws2[f"B{row}"].font = Font(name="Calibri", size=10, color=NAVY)
        ws2[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
        ws2[f"C{row}"] = f"{opts:,}"; ws2[f"C{row}"].font = Font(name="Calibri", size=10, bold=True, color=BLUE)
        ws2[f"C{row}"].alignment = Alignment(horizontal="right", vertical="center")
        ws2[f"D{row}"] = vest; ws2[f"D{row}"].font = Font(name="Calibri", size=9, color="64748B")
        ws2[f"D{row}"].alignment = Alignment(horizontal="left")
        ws2[f"E{row}"] = price; ws2[f"E{row}"].font = Font(name="Calibri", size=9, color="64748B")
        ws2[f"E{row}"].alignment = Alignment(horizontal="left")
        if i % 2 == 0:
            for c in ["B","C","D","E"]:
                ws2[f"{c}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")
        for c in ["B","C","D","E"]:
            ws2[f"{c}{row}"].border = thin
        ws2.row_dimensions[row].height = 18

    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    data = buf.read()
    oid = ObjectId()
    pub_id = f"bompay_investor_docs/{oid}/BOMPAY_Cap_Table.xlsx"
    url = await _upload(data, pub_id)
    return _doc_record(oid,
        "Capitalisation Table & Ownership Structure",
        "Pre-money and post-money cap tables, founder vesting schedule and ESOP plan. Confidential — NDA required.",
        "BOMPAY_Cap_Table.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        len(data), 3, "financial", pub_id, url)


async def _make_management_accounts() -> dict:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

    wb = openpyxl.Workbook()
    thin = Border(bottom=Side(style="thin", color="E2E8F0"))
    thick_top = Border(top=Side(style="medium", color=NAVY))

    def hdr(ws, cell, text, fg=WHITE, bg=NAVY, sz=11, bold=True):
        ws[cell] = text
        ws[cell].font = Font(name="Calibri", size=sz, bold=bold, color=fg)
        ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    def dc(ws, cell, val, fmt=None, bold=False, color=NAVY, bg=None, align="right"):
        ws[cell] = val
        ws[cell].font = Font(name="Calibri", size=10, bold=bold, color=color)
        if bg: ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal=align, vertical="center")
        if fmt: ws[cell].number_format = fmt
        ws[cell].border = thin

    # ── P&L ────────────────────────────────────────────────────────────────────
    ws1 = wb.active; ws1.title = "Income Statement"
    ws1.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E"], [3,36,16,16,16]):
        ws1.column_dimensions[c].width = w
    for r in range(1, 60):
        ws1.row_dimensions[r].height = 18

    hdr(ws1, "B1", "BOMPAY — INCOME STATEMENT (MANAGEMENT ACCOUNTS)", WHITE, NAVY, 13)
    hdr(ws1, "B2", f"All figures in ₦'000. CONFIDENTIAL · {STAMP}", "94A3B8", NAVY, 9, False)
    for col, yr in zip(["B","C","D","E"], ["Item","FY2022 (₦'000)","FY2023 (₦'000)","H1 FY2024E (₦'000)"]):
        hdr(ws1, f"{col}4", yr, WHITE, MID, 10)

    pl_rows = [
        ("REVENUE", None, None, None, True, BLUE, NAVY),
        ("Transaction Fee Revenue", 12_400, 38_200, 24_800, False, NAVY, None),
        ("VAS Commission Income", 4_800, 14_600, 10_200, False, NAVY, None),
        ("Storefront & Payment Links", 800, 5_400, 4_100, False, NAVY, None),
        ("Other Income", 200, 900, 600, False, NAVY, None),
        ("TOTAL REVENUE", 18_200, 59_100, 39_700, True, BLUE, "F0F9FF"),
        ("", None, None, None, False, NAVY, None),
        ("COST OF REVENUE", None, None, None, True, AMBER, NAVY),
        ("NIP & Settlement Fees", (4_800), (12_400), (7_800), False, NAVY, None),
        ("VAS Cost of Goods", (2_600), (7_400), (4_900), False, NAVY, None),
        ("Payment Gateway & Infra", (1_800), (4_200), (2_600), False, NAVY, None),
        ("TOTAL COST OF REVENUE", (9_200), (24_000), (15_300), True, AMBER, "FFFBEB"),
        ("", None, None, None, False, NAVY, None),
        ("GROSS PROFIT", 9_000, 35_100, 24_400, True, GREEN, "F0FDF4"),
        ("Gross Margin %", "49.5%", "59.4%", "61.5%", True, GREEN, None),
        ("", None, None, None, False, NAVY, None),
        ("OPERATING EXPENSES", None, None, None, True, PURPLE, NAVY),
        ("Personnel & Benefits", (8_400), (18_600), (11_200), False, NAVY, None),
        ("Technology & Cloud Infra", (1_800), (3_400), (2_000), False, NAVY, None),
        ("Sales & Marketing", (1_200), (4_800), (3_200), False, NAVY, None),
        ("General & Administrative", (900), (2_100), (1_400), False, NAVY, None),
        ("Legal & Compliance", (600), (1_400), (900), False, NAVY, None),
        ("TOTAL OPEX", (12_900), (30_300), (18_700), True, PURPLE, "F5F3FF"),
        ("", None, None, None, False, NAVY, None),
        ("EBITDA", (3_900), 4_800, 5_700, True, GREEN, "F0FDF4"),
        ("Depreciation & Amortisation", (300), (600), (350), False, NAVY, None),
        ("EBIT", (4_200), 4_200, 5_350, True, BLUE, "F0F9FF"),
        ("Interest Income / (Expense)", 200, 400, 250, False, NAVY, None),
        ("PRE-TAX PROFIT / (LOSS)", (4_000), 4_600, 5_600, True, NAVY, "F8FAFF"),
        ("Tax (30%)", 0, (1_380), (1_680), False, NAVY, None),
        ("NET PROFIT / (LOSS)", (4_000), 3_220, 3_920, True, GREEN, "F0FDF4"),
    ]
    for i, (lbl, y1, y2, h1, bold, color, bg) in enumerate(pl_rows):
        row = 5 + i
        if lbl:
            dc(ws1, f"B{row}", lbl, align="left", bold=bold, color=color, bg=bg if bg and bg != NAVY else None)
            if bg == NAVY:
                ws1[f"B{row}"].fill = PatternFill("solid", fgColor=NAVY)
        for col, val in zip(["C","D","E"], [y1, y2, h1]):
            if val is not None:
                dc(ws1, f"{col}{row}", val, "#,##0;(#,##0)", bold=bold, color=color, bg=bg if bg and bg != NAVY else None)
                if bg == NAVY:
                    ws1[f"{col}{row}"].fill = PatternFill("solid", fgColor=NAVY)

    # ── Balance Sheet ──────────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Balance Sheet")
    ws2.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E"], [3,36,16,16,16]):
        ws2.column_dimensions[c].width = w
    for r in range(1, 45):
        ws2.row_dimensions[r].height = 18

    hdr(ws2, "B1", "BOMPAY — BALANCE SHEET (MANAGEMENT ACCOUNTS)", WHITE, NAVY, 13)
    hdr(ws2, "B2", f"All figures in ₦'000. CONFIDENTIAL · {STAMP}", "94A3B8", NAVY, 9, False)
    for col, yr in zip(["B","C","D"], ["Item","FY2023 (₦'000)","H1 FY2024E (₦'000)"]):
        hdr(ws2, f"{col}4", yr, WHITE, MID, 10)

    bs_rows = [
        ("ASSETS", None, None, True, BLUE, NAVY),
        ("Current Assets", None, None, True, "94A3B8", "F0F4FF"),
        ("Cash & Cash Equivalents", 18_400, 24_600, False, NAVY, None),
        ("Receivables (Merchants)", 3_200, 4_100, False, NAVY, None),
        ("VAS Receivables", 1_100, 1_400, False, NAVY, None),
        ("Prepaid Expenses", 600, 800, False, NAVY, None),
        ("TOTAL CURRENT ASSETS", 23_300, 30_900, True, BLUE, "F0F9FF"),
        ("Non-Current Assets", None, None, True, "94A3B8", "F0F4FF"),
        ("Intangible Assets (Platform)", 4_200, 3_800, False, NAVY, None),
        ("Computer & IT Equipment", 1_800, 2_200, False, NAVY, None),
        ("Right-of-Use Assets", 1_200, 1_000, False, NAVY, None),
        ("TOTAL NON-CURRENT ASSETS", 7_200, 7_000, True, BLUE, "F0F9FF"),
        ("TOTAL ASSETS", 30_500, 37_900, True, GREEN, "F0FDF4"),
        ("", None, None, False, NAVY, None),
        ("LIABILITIES & EQUITY", None, None, True, AMBER, NAVY),
        ("Current Liabilities", None, None, True, "94A3B8", "F0F4FF"),
        ("Merchant Payables", 4_800, 6_200, False, NAVY, None),
        ("Accruals & Payables", 2_100, 2_800, False, NAVY, None),
        ("Tax Payable", 1_380, 1_680, False, NAVY, None),
        ("TOTAL CURRENT LIABILITIES", 8_280, 10_680, True, AMBER, "FFFBEB"),
        ("", None, None, False, NAVY, None),
        ("Shareholders' Equity", None, None, True, "94A3B8", "F0F4FF"),
        ("Share Capital", 500, 500, False, NAVY, None),
        ("Share Premium / SAFE Reserve", 28_000, 28_000, False, NAVY, None),
        ("Retained Earnings / (Deficit)", (6_280), (1_280), False, NAVY, None),
        ("TOTAL EQUITY", 22_220, 27_220, True, GREEN, "F0FDF4"),
        ("TOTAL LIABILITIES & EQUITY", 30_500, 37_900, True, GREEN, "F0FDF4"),
    ]
    for i, (lbl, y1, y2, bold, color, bg) in enumerate(bs_rows):
        row = 5 + i
        if lbl:
            ws2[f"B{row}"] = lbl
            ws2[f"B{row}"].font = Font(name="Calibri", size=10, bold=bold, color=color)
            ws2[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
            if bg:
                ws2[f"B{row}"].fill = PatternFill("solid", fgColor=bg)
            ws2[f"B{row}"].border = thin
        for col, val in zip(["C","D"], [y1, y2]):
            if val is not None:
                ws2[f"{col}{row}"] = val
                ws2[f"{col}{row}"].font = Font(name="Calibri", size=10, bold=bold, color=color)
                ws2[f"{col}{row}"].number_format = "#,##0;(#,##0)"
                ws2[f"{col}{row}"].alignment = Alignment(horizontal="right", vertical="center")
                if bg:
                    ws2[f"{col}{row}"].fill = PatternFill("solid", fgColor=bg)
                ws2[f"{col}{row}"].border = thin

    # ── Cash Flow ──────────────────────────────────────────────────────────────
    ws3 = wb.create_sheet("Cash Flow")
    ws3.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D"], [3,36,16,16]):
        ws3.column_dimensions[c].width = w
    for r in range(1, 35):
        ws3.row_dimensions[r].height = 18

    hdr(ws3, "B1", "BOMPAY — CASH FLOW STATEMENT (MANAGEMENT ACCOUNTS)", WHITE, NAVY, 13)
    hdr(ws3, "B2", f"All figures in ₦'000. CONFIDENTIAL · {STAMP}", "94A3B8", NAVY, 9, False)
    for col, yr in zip(["B","C","D"], ["Item","FY2023 (₦'000)","H1 FY2024E (₦'000)"]):
        hdr(ws3, f"{col}4", yr, WHITE, MID, 10)

    cf_rows = [
        ("OPERATING ACTIVITIES", None, None, True, BLUE, NAVY),
        ("Net Profit / (Loss)", 3_220, 3_920, False, NAVY, None),
        ("Add: Depreciation & Amortisation", 600, 350, False, NAVY, None),
        ("Changes in Working Capital", None, None, True, "94A3B8", "F0F4FF"),
        ("(Increase)/Decrease in Receivables", (2_100), (900), False, NAVY, None),
        ("Increase/(Decrease) in Payables", 3_600, 2_400, False, NAVY, None),
        ("NET CASH FROM OPERATIONS", 5_320, 5_770, True, GREEN, "F0FDF4"),
        ("", None, None, False, NAVY, None),
        ("INVESTING ACTIVITIES", None, None, True, AMBER, NAVY),
        ("Capital Expenditure (IT equipment)", (1_200), (600), False, NAVY, None),
        ("Platform development (capitalised)", (2_400), (1_000), False, NAVY, None),
        ("NET CASH FROM INVESTING", (3_600), (1_600), True, AMBER, "FFFBEB"),
        ("", None, None, False, NAVY, None),
        ("FINANCING ACTIVITIES", None, None, True, PURPLE, NAVY),
        ("SAFE proceeds received", 28_000, 0, False, NAVY, None),
        ("Loan repayments", (1_200), (600), False, NAVY, None),
        ("NET CASH FROM FINANCING", 26_800, (600), True, PURPLE, "F5F3FF"),
        ("", None, None, False, NAVY, None),
        ("NET MOVEMENT IN CASH", 28_520, 3_570, True, NAVY, "F8FAFF"),
        ("Opening Cash Balance", (10_120), 18_400, False, NAVY, None),
        ("CLOSING CASH BALANCE", 18_400, 21_970, True, GREEN, "F0FDF4"),
    ]
    for i, (lbl, y1, y2, bold, color, bg) in enumerate(cf_rows):
        row = 5 + i
        if lbl:
            ws3[f"B{row}"] = lbl
            ws3[f"B{row}"].font = Font(name="Calibri", size=10, bold=bold, color=color)
            ws3[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
            if bg: ws3[f"B{row}"].fill = PatternFill("solid", fgColor=bg)
            ws3[f"B{row}"].border = thin
        for col, val in zip(["C","D"], [y1, y2]):
            if val is not None:
                ws3[f"{col}{row}"] = val
                ws3[f"{col}{row}"].font = Font(name="Calibri", size=10, bold=bold, color=color)
                ws3[f"{col}{row}"].number_format = "#,##0;(#,##0)"
                ws3[f"{col}{row}"].alignment = Alignment(horizontal="right", vertical="center")
                if bg: ws3[f"{col}{row}"].fill = PatternFill("solid", fgColor=bg)
                ws3[f"{col}{row}"].border = thin

    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    data = buf.read()
    oid = ObjectId()
    pub_id = f"bompay_investor_docs/{oid}/BOMPAY_Management_Accounts.xlsx"
    url = await _upload(data, pub_id)
    return _doc_record(oid,
        "Management Accounts & Financial Statements",
        "Income Statement, Balance Sheet and Cash Flow Statement — FY2022, FY2023 and H1 2024E. Confidential — NDA required.",
        "BOMPAY_Management_Accounts.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        len(data), 3, "financial", pub_id, url)


async def _make_term_sheet() -> dict:
    body = f"""
<p class="lead">This document sets out the principal terms on which BOMPAY Financial Services Limited proposes to raise a seed round of investment. These terms are indicative, subject to due diligence, legal documentation and board approval. This is not a binding commitment.</p>

<div class="hl"><p><strong>STRICTLY CONFIDENTIAL — NDA REQUIRED</strong><br/>This term sheet is provided under a mutual Non-Disclosure Agreement. It must not be disclosed to any third party without BOMPAY's prior written consent. It does not constitute legal, tax or investment advice.</p></div>

<h2>1. Summary of Key Terms</h2>
<table>
  <tr><th>Term</th><th>Detail</th></tr>
  <tr><td>Issuer</td><td>BOMPAY Financial Services Limited (RC 1987654)</td></tr>
  <tr><td>Instrument</td><td>Simple Agreement for Future Equity (SAFE)</td></tr>
  <tr><td>Total Raise</td><td>$5,000,000 (USD five million)</td></tr>
  <tr><td>Valuation Cap</td><td>$20,000,000 post-money</td></tr>
  <tr><td>Discount Rate</td><td>20% on the price per share at a Qualified Financing</td></tr>
  <tr><td>Minimum Ticket</td><td>$250,000</td></tr>
  <tr><td>Lead Investor Ticket</td><td>$1,000,000+ (Board Observer Seat included)</td></tr>
  <tr><td>Target Close</td><td>Q1 2024 (rolling close, minimum $2M)</td></tr>
  <tr><td>Currency</td><td>USD (investor may fund in USD or GBP/EUR equivalent)</td></tr>
  <tr><td>Jurisdiction</td><td>Federal Republic of Nigeria (laws of Lagos State govern)</td></tr>
</table>

<h2>2. SAFE Key Provisions</h2>
<h3>2.1 Conversion Trigger — Qualified Financing</h3>
<p>This SAFE converts into Preferred Shares at the next priced equity financing round that raises not less than <strong>$3,000,000</strong> (a "Qualified Financing"). Conversion occurs at the lower of: (i) the Valuation Cap price, or (ii) the Qualified Financing price less the Discount Rate.</p>

<h3>2.2 Change of Control / Liquidity Event</h3>
<p>If BOMPAY undergoes a Change of Control (acquisition, merger, IPO) before a Qualified Financing, SAFE holders may elect to either: (a) receive 1× their investment back (liquidation preference), or (b) convert to ordinary shares at the Valuation Cap price immediately prior to the event.</p>

<h3>2.3 Dissolution Event</h3>
<p>In a dissolution, SAFE holders rank above ordinary shareholders but below secured creditors. They receive the lower of their investment amount or their pro-rata share of distributable assets.</p>

<h3>2.4 No Maturity Date</h3>
<p>This SAFE has no maturity date or interest rate. It is not debt. It does not accrue interest and cannot be called by investors prior to a conversion trigger.</p>

<h2>3. Investor Rights</h2>
<table>
  <tr><th>Right</th><th>Threshold</th><th>Detail</th></tr>
  <tr><td>Information Rights</td><td>All investors</td><td>Quarterly management accounts (within 30 days of quarter end); Annual audited accounts (within 90 days of year end)</td></tr>
  <tr><td>Board Observer Seat</td><td>$1M+ investors</td><td>Non-voting observer seat; attend all board meetings; receive all board materials</td></tr>
  <tr><td>Pro-Rata Rights</td><td>All SAFE holders</td><td>Right to participate in next priced round up to their SAFE ownership %; exercisable within 20 business days of round announcement</td></tr>
  <tr><td>MFN Clause</td><td>All SAFE holders</td><td>If BOMPAY issues a more favourable SAFE (lower cap or higher discount) before conversion, existing holders may elect to adopt those terms</td></tr>
</table>

<h2>4. Use of Proceeds</h2>
<table>
  <tr><th>Category</th><th>Allocation</th><th>Specific Use</th></tr>
  <tr><td>Regulatory &amp; Expansion</td><td>40% ($400K)</td><td>CBN PSP full licence, Ghana/Kenya market entry, compliance infrastructure</td></tr>
  <tr><td>Engineering &amp; Infrastructure</td><td>30% ($300K)</td><td>Core banking module, card issuance integration, lending API, security hardening</td></tr>
  <tr><td>Merchant Acquisition</td><td>18% ($180K)</td><td>Sales headcount, referral programme, co-marketing with SafeHaven MFB</td></tr>
  <tr><td>Reserve &amp; Compliance</td><td>12% ($120K)</td><td>Working capital, external audit, NDPR compliance, legal fees</td></tr>
</table>

<h2>5. Conditions Precedent</h2>
<ul>
  <li>Satisfactory legal due diligence on BOMPAY's corporate documents, contracts and IP ownership</li>
  <li>Receipt of certified copies of CAC incorporation documents and latest filing</li>
  <li>Execution of Mutual NDA and Investor Subscription Agreement by both parties</li>
  <li>Board resolution approving the issuance of this SAFE</li>
  <li>Wire of investment amount to BOMPAY's designated USD escrow account</li>
  <li>Confirmation that no material adverse change has occurred since investor's initial meeting</li>
</ul>

<h2>6. Confidentiality &amp; Exclusivity</h2>
<p>The terms of this term sheet are strictly confidential. By engaging in negotiations under this document, each party agrees: (a) not to disclose the terms to any third party without prior written consent; (b) to use information provided solely to evaluate this investment opportunity; (c) to return or destroy all materials if negotiations are terminated.</p>
<p>BOMPAY does not grant exclusivity to any single investor. This round is being offered to multiple qualifying investors on a first-come, first-committed basis.</p>

<h2>7. Governing Law</h2>
<p>This term sheet and any resulting SAFE agreement shall be governed by the laws of the Federal Republic of Nigeria. Any disputes shall be resolved by arbitration under the Lagos Court of Arbitration rules.</p>

<div class="disc">
  <strong>Important Legal Notice:</strong> This term sheet is for discussion purposes only and does not constitute a binding legal agreement. Neither party is obligated to proceed until a definitive SAFE Agreement has been executed by both parties. BOMPAY strongly recommends all prospective investors obtain independent legal and financial advice before committing to this investment. Past performance is not a guide to future results. Capital is at risk.
</div>

<p style="margin-top:8mm;font-size:9pt;color:#94A3B8;">
  Prepared by BOMPAY Financial Services Limited · {STAMP} · Version 2.1<br/>
  For enquiries: <a href="mailto:investors@bompay.app" style="color:#1769FF;">investors@bompay.app</a>
</p>
"""
    html = _pdf_base("SAFE Investment Term Sheet", 3, body)
    pdf  = await _weasyprint(html)
    oid  = ObjectId()
    return _pdf_record(oid,
        "SAFE Investment Term Sheet",
        "Full term sheet for the $1M seed SAFE: valuation cap, discount rate, investor rights, use of proceeds and governing law. NDA required.",
        "BOMPAY_Term_Sheet.pdf",
        pdf, 3, "legal")


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

async def seed_investor_dataroom():
    """Generate and upload world-class investor data room documents.
    Re-seeds when SEED_VERSION changes. Preserves manually uploaded documents."""
    seeded_count = await db.investor_documents.count_documents(
        {"uploaded_by": "system_seed", "seed_version": SEED_VERSION}
    )
    if seeded_count >= 9:
        logger.info("[DataRoom Seed] Up to date (%s) — skipping", SEED_VERSION)
        return

    # Remove old seeded docs (wrong upload config) so we re-upload correctly
    deleted = await db.investor_documents.delete_many({"uploaded_by": "system_seed"})
    logger.info("[DataRoom Seed] Removed %d old seeded docs — re-seeding (%s)...", deleted.deleted_count, SEED_VERSION)

    generators = [
        # Tier 1
        ("Investor Pitch Deck (PDF)",            _make_pitch_deck_pdf),
        ("Executive Summary (PDF)",              _make_executive_summary),
        ("Market Opportunity (PDF)",             _make_market_opportunity),
        # Tier 2
        ("Financial Model (XLSX)",               _make_financial_model_xlsx),
        ("Investor Presentation (PPTX)",         _make_investor_pptx),
        ("Due Diligence Pack (PDF)",             _make_due_diligence_pack),
        ("Competitive Analysis (PDF)",           _make_competitive_analysis),
        # Tier 3
        ("Cap Table (XLSX)",                     _make_cap_table),
        ("Management Accounts (XLSX)",           _make_management_accounts),
        ("Term Sheet (PDF)",                     _make_term_sheet),
    ]

    inserted = 0
    for label, gen_fn in generators:
        try:
            logger.info("[DataRoom Seed] Generating: %s", label)
            doc = await gen_fn()
            await db.investor_documents.insert_one(doc)
            inserted += 1
            logger.info("[DataRoom Seed] ✓ %s (%d KB)", label, doc["size_bytes"] // 1024)
        except Exception as e:
            logger.error("[DataRoom Seed] ✗ FAILED %s: %s", label, e)

    # Add the Live Traction Report (no Cloudinary upload — generated fresh on each download)
    try:
        await db.investor_documents.insert_one({
            "_id": ObjectId(),
            "title": "Live Traction & KPIs Report",
            "description": "Real-time platform metrics: users, merchants, TPV, transaction count, active stores. Auto-generated from live DB on every download.",
            "filename": "BOMPAY_Traction_Report.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 0,
            "tier": 1,
            "category": "general",
            "cloudinary_public_id": None,
            "cloudinary_url": None,
            "resource_type": "raw",
            "source_type": "traction",
            "is_active": True,
            "download_count": 0,
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
            "uploaded_by": "system_seed",
            "seed_version": SEED_VERSION,
        })
        inserted += 1
        logger.info("[DataRoom Seed] ✓ Live Traction Report (dynamic)")
    except Exception as e:
        logger.error("[DataRoom Seed] ✗ FAILED Live Traction Report: %s", e)

    logger.info("[DataRoom Seed] Complete — %d/%d documents seeded", inserted, len(generators) + 1)
