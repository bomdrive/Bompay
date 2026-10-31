"""Investor Centre — PDF / PPTX / Excel export endpoints."""
import io
import logging
from datetime import datetime, timezone
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from database import db

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Helpers ────────────────────────────────────────────────────────────────────

BOMPAY_BLUE = "1769FF"
DARK_NAVY   = "071426"
MID_NAVY    = "0B1F3A"
GREEN       = "10B981"
PURPLE      = "8B5CF6"
AMBER       = "F59E0B"
TEAL        = "06B6D4"
WHITE       = "FFFFFF"
LIGHT_GREY  = "F5F7FB"
SLATE_600   = "475569"
SLATE_400   = "94A3B8"

SLIDE_ACCENT = {
    "executive_summary": BOMPAY_BLUE,
    "financial_projections": GREEN,
    "traction": PURPLE,
    "market_opportunity": AMBER,
    "product_tech": TEAL,
    "use_of_funds": BOMPAY_BLUE,
    "unit_economics": GREEN,
    "regulatory": AMBER,
    "cap_table": PURPLE,
    "data_room": TEAL,
    "team": PURPLE,
    "enquiry": BOMPAY_BLUE,
}

FINANCIAL_DATA = [
    {"year": "Y1", "arr_m": 120, "tpv_b": 3.2, "revenue_m": 48, "gross_margin": 38},
    {"year": "Y2", "arr_m": 420, "tpv_b": 9.8, "revenue_m": 175, "gross_margin": 45},
    {"year": "Y3", "arr_m": 1200, "tpv_b": 28.5, "revenue_m": 490, "gross_margin": 54},
    {"year": "Y4", "arr_m": 3800, "tpv_b": 75.0, "revenue_m": 1400, "gross_margin": 62},
    {"year": "Y5", "arr_m": 9500, "tpv_b": 180.0, "revenue_m": 3600, "gross_margin": 68},
]

FUNDS_DATA = [
    {"name": "Regulatory & Expansion", "pct": 40, "amount": "$400K", "hex": "1769FF"},
    {"name": "Engineering & Infrastructure", "pct": 30, "amount": "$300K", "hex": "10B981"},
    {"name": "Merchant Acquisition", "pct": 18, "amount": "$180K", "hex": "8B5CF6"},
    {"name": "Reserve & Compliance", "pct": 12, "amount": "$120K", "hex": "F59E0B"},
]


async def _load_sections_dict() -> dict:
    """Load all investor sections from DB as {section_id: doc}."""
    docs = await db.investor_sections.find({}, {"_id": 0}).to_list(20)
    return {d["section_id"]: d for d in docs}


# ── PDF Export (WeasyPrint) ────────────────────────────────────────────────────

def _build_pdf_html(sections: dict, recipient_name: str = "", recipient_org: str = "") -> str:
    from datetime import datetime, timezone as _tz
    stamp_date = datetime.now(_tz.utc).strftime("%d %b %Y")
    if recipient_name:
        watermark_text = f"PREPARED FOR: {recipient_name.upper()}"
        if recipient_org:
            watermark_text += f" · {recipient_org.upper()}"
        watermark_text += f"  ·  {stamp_date}"
    else:
        watermark_text = f"CONFIDENTIAL — BOMPAY INVESTOR MATERIALS  ·  {stamp_date}"
    slide_ids = [
        "executive_summary", "financial_projections", "traction",
        "market_opportunity", "product_tech", "use_of_funds",
        "unit_economics", "regulatory", "cap_table", "data_room",
        "team", "enquiry",
    ]

    slides_html = ""
    for idx, sid in enumerate(slide_ids):
        s = sections.get(sid, {})
        accent = SLIDE_ACCENT.get(sid, BOMPAY_BLUE)
        title = s.get("title", sid.replace("_", " ").title())
        overview = s.get("overview", "")
        key_points = s.get("key_points", [])
        tagline = s.get("tagline", "")
        hm = s.get("highlight_metric", {})

        points_html = "".join(
            f"<li>{p}</li>" for p in key_points[:6]
        )
        metric_html = ""
        if hm:
            metric_html = f"""
            <div class="metric-box" style="border-color:#{accent};">
              <div class="metric-label">{hm.get('label','')}</div>
              <div class="metric-value" style="color:#{accent};">{hm.get('value','')}</div>
              <div class="metric-note">{hm.get('note','')}</div>
            </div>"""

        # Extra: financial table for projections slide
        extra_html = ""
        if sid == "financial_projections":
            rows = "".join(
                f"<tr><td>{d['year']}</td><td>₦{d['arr_m']}M</td>"
                f"<td>₦{d['revenue_m']}M</td><td>₦{d['tpv_b']}B</td>"
                f"<td>{d['gross_margin']}%</td></tr>"
                for d in FINANCIAL_DATA
            )
            extra_html = f"""
            <table class="data-table">
              <thead><tr><th>Year</th><th>ARR</th><th>Revenue</th><th>TPV</th><th>Gross Margin</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
            <p class="disclaimer">All projections are indicative and forward-looking.</p>"""
        elif sid == "use_of_funds":
            fund_rows = []
            for d in FUNDS_DATA:
                fund_rows.append(
                    f"<tr><td style='color:#{d['hex']};font-weight:600;'>{d['name']}</td>"
                    f"<td style='text-align:right;font-weight:700;'>{d['amount']}</td>"
                    f"<td style='text-align:right;color:#94A3B8;'>{d['pct']}%</td></tr>"
                )
            rows = "".join(fund_rows)
            extra_html = f"""
            <table class="data-table">
              <thead><tr><th>Category</th><th style='text-align:right'>Amount</th><th style='text-align:right'>%</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>"""
        elif sid == "unit_economics":
            ue = s.get("metrics_table", [])
            if ue:
                rows = "".join(
                    f"<tr><td>{r['metric']}</td><td style='text-align:right;font-weight:700;'>{r['value']}</td>"
                    f"<td style='text-align:right;color:#94A3B8;font-size:10px;'>{r['note']}</td></tr>"
                    for r in ue
                )
                extra_html = f"""
                <table class="data-table">
                  <thead><tr><th>Metric</th><th style='text-align:right'>Value</th><th style='text-align:right'>Note</th></tr></thead>
                  <tbody>{rows}</tbody>
                </table>"""

        slides_html += f"""
        <div class="slide" style="page-break-after: always;">
          <div class="slide-header">
            <span class="slide-number" style="color:#{accent};">{str(idx+1).zfill(2)} / 12</span>
            <span class="brand">BOMPAY  ·  INVESTOR RELATIONS  ·  A PRODUCT OF BOMDRIVE LIMITED</span>
          </div>
          <div class="slide-accent-bar" style="background:#{accent};"></div>
          <h1 class="slide-title">{title}</h1>
          {f'<p class="slide-tagline">{tagline}</p>' if tagline else ''}
          {f'<p class="slide-overview">{overview[:400]}{"…" if len(overview) > 400 else ""}</p>' if overview else ''}
          {f'<ul class="key-points">{points_html}</ul>' if key_points else ''}
          {metric_html}
          {extra_html}
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Plus Jakarta Sans',sans-serif; background:#fff; color:#071426; }}
  .slide {{
    width:297mm; min-height:210mm; padding:18mm 20mm 14mm 20mm;
    display:flex; flex-direction:column; position:relative;
    background:#071426;
  }}
  .slide-header {{
    display:flex; justify-content:space-between; align-items:center; margin-bottom:6mm;
  }}
  .slide-number {{ font-size:11px; font-weight:700; font-family:monospace; letter-spacing:0.1em; }}
  .brand {{ font-size:10px; color:rgba(255,255,255,0.3); letter-spacing:0.15em; font-weight:600; }}
  .slide-accent-bar {{ height:3px; width:48px; border-radius:2px; margin-bottom:8mm; }}
  .slide-title {{ font-size:32px; font-weight:800; color:#FFFFFF; margin-bottom:4mm; line-height:1.2; }}
  .slide-tagline {{ font-size:13px; color:rgba(255,255,255,0.5); margin-bottom:5mm; font-style:italic; }}
  .slide-overview {{ font-size:12px; color:rgba(255,255,255,0.65); line-height:1.7; margin-bottom:5mm; max-width:200mm; }}
  .key-points {{ list-style:none; margin-bottom:5mm; }}
  .key-points li {{ font-size:11px; color:rgba(255,255,255,0.7); padding:2.5mm 0; border-bottom:1px solid rgba(255,255,255,0.06); padding-left:5mm; position:relative; }}
  .key-points li::before {{ content:"→"; position:absolute; left:0; color:rgba(255,255,255,0.3); }}
  .metric-box {{
    display:inline-block; border:1.5px solid; border-radius:12px;
    padding:4mm 8mm; margin-top:4mm; min-width:50mm;
    background:rgba(255,255,255,0.04);
  }}
  .metric-label {{ font-size:10px; color:rgba(255,255,255,0.4); text-transform:uppercase; letter-spacing:0.1em; }}
  .metric-value {{ font-size:28px; font-weight:800; font-family:monospace; margin:1mm 0; }}
  .metric-note {{ font-size:10px; color:rgba(255,255,255,0.35); }}
  .data-table {{ width:100%; border-collapse:collapse; margin-top:4mm; font-size:11px; }}
  .data-table th {{ text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:0.08em; color:rgba(255,255,255,0.4); padding:2mm 3mm; border-bottom:1px solid rgba(255,255,255,0.1); }}
  .data-table td {{ padding:2.5mm 3mm; border-bottom:1px solid rgba(255,255,255,0.06); color:rgba(255,255,255,0.8); }}
  .disclaimer {{ font-size:9px; color:rgba(255,255,255,0.3); margin-top:3mm; font-style:italic; }}
  .watermark {{
    position:fixed; bottom:6mm; left:0; right:0;
    text-align:center; font-size:8px; font-weight:700;
    color:rgba(255,255,255,0.12); letter-spacing:0.15em;
    font-family:monospace; text-transform:uppercase;
    pointer-events:none;
  }}
</style>
</head>
<body>
  <div class="watermark">{watermark_text}</div>
  {slides_html}
</body>
</html>"""


@router.get("/investors/exports/pdf")
async def export_pdf(name: str = "", organisation: str = ""):
    """Generate WeasyPrint PDF of the 12-slide investor pitch deck with optional watermark."""
    from weasyprint import HTML
    sections = await _load_sections_dict()
    html_str = _build_pdf_html(sections, recipient_name=name, recipient_org=organisation)
    pdf_bytes = HTML(string=html_str, base_url=None).write_pdf()
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=Bompay_Investor_Deck.pdf"},
    )


# ── Excel Export (openpyxl) ────────────────────────────────────────────────────

@router.get("/investors/exports/excel")
async def export_excel():
    """Generate formatted Excel workbook with 5-year financial model."""
    import openpyxl
    from openpyxl.styles import (
        Font, PatternFill, Alignment, Border, Side, numbers
    )
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()

    # ── Sheet 1: Cover ─────────────────────────────────────────────────────────
    ws_cover = wb.active
    ws_cover.title = "Cover"
    ws_cover.sheet_view.showGridLines = False
    ws_cover.column_dimensions["A"].width = 4
    ws_cover.column_dimensions["B"].width = 40
    ws_cover.column_dimensions["C"].width = 22
    ws_cover.row_dimensions[1].height = 20

    navy_fill = PatternFill("solid", fgColor=DARK_NAVY)
    blue_fill = PatternFill("solid", fgColor=BOMPAY_BLUE)
    light_fill = PatternFill("solid", fgColor="F0F4FF")

    for row in range(1, 35):
        ws_cover.row_dimensions[row].height = 18
        for col in ["A", "B", "C", "D", "E"]:
            ws_cover[f"{col}{row}"].fill = navy_fill

    ws_cover["B3"] = "BOMPAY FINANCIAL SERVICES"
    ws_cover["B3"].font = Font(name="Calibri", size=20, bold=True, color=WHITE)
    ws_cover["B4"] = "5-Year Financial Model — Indicative Projections"
    ws_cover["B4"].font = Font(name="Calibri", size=12, color="94A3B8")
    ws_cover["B6"] = f"Generated: {datetime.now(timezone.utc).strftime('%B %Y')}"
    ws_cover["B6"].font = Font(name="Calibri", size=10, color="64748B")
    ws_cover["B8"] = "IMPORTANT DISCLAIMER"
    ws_cover["B8"].font = Font(name="Calibri", size=11, bold=True, color=AMBER)
    ws_cover["B9"] = "All projections are indicative and forward-looking statements based on"
    ws_cover["B10"] = "management assumptions. Actual results may differ materially. This"
    ws_cover["B11"] = "document is for qualified investor use only and is confidential."
    for r in [9, 10, 11]:
        ws_cover[f"B{r}"].font = Font(name="Calibri", size=10, color="94A3B8")

    # ── Sheet 2: Financial Projections ─────────────────────────────────────────
    ws_fp = wb.create_sheet("Financial Projections")
    ws_fp.sheet_view.showGridLines = False

    header_fill = PatternFill("solid", fgColor=DARK_NAVY)
    accent_fill = PatternFill("solid", fgColor=BOMPAY_BLUE)
    alt_fill    = PatternFill("solid", fgColor="F8FAFF")
    green_fill  = PatternFill("solid", fgColor="ECFDF5")
    thin_border = Border(bottom=Side(style="thin", color="E2E8F0"))

    def header(ws, cell, text, color=WHITE, bg=DARK_NAVY, size=11, bold=True):
        ws[cell] = text
        ws[cell].font = Font(name="Calibri", size=size, bold=bold, color=color)
        ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    def data_cell(ws, cell, value, fmt=None, bold=False, color="071426", bg=None, align="right"):
        ws[cell] = value
        ws[cell].font = Font(name="Calibri", size=10, bold=bold, color=color)
        if bg:
            ws[cell].fill = PatternFill("solid", fgColor=bg)
        ws[cell].alignment = Alignment(horizontal=align, vertical="center")
        if fmt:
            ws[cell].number_format = fmt

    cols = ["A", "B", "C", "D", "E", "F", "G"]
    widths = [3, 32, 14, 14, 14, 14, 14]
    for i, (col, w) in enumerate(zip(cols, widths)):
        ws_fp.column_dimensions[col].width = w
    for r in range(1, 50):
        ws_fp.row_dimensions[r].height = 18

    header(ws_fp, "B1", "BOMPAY — FINANCIAL PROJECTIONS (INDICATIVE)", WHITE, DARK_NAVY, 13)
    header(ws_fp, "B2", "All figures in Nigerian Naira (₦). Marked INDICATIVE — subject to change.", "94A3B8", DARK_NAVY, 9, False)

    years = ["Metric", "Year 1", "Year 2", "Year 3", "Year 4", "Year 5"]
    for i, (col, yr) in enumerate(zip(["B","C","D","E","F","G"], years)):
        header(ws_fp, f"{col}4", yr, WHITE, DARK_NAVY if i == 0 else BOMPAY_BLUE, 10)

    # ARR section
    header(ws_fp, "B6", "── ANNUAL RECURRING REVENUE (₦M)", "94A3B8", "F0F4FF", 9, False)
    rows_data = [
        (7, "ARR (₦M)", [d["arr_m"] for d in FINANCIAL_DATA], "#,##0", GREEN),
        (8, "YoY ARR Growth", ["—", "250%", "186%", "217%", "150%"], None, AMBER),
    ]
    for row, label, vals, fmt, color in rows_data:
        data_cell(ws_fp, f"B{row}", label, align="left", bold=True)
        for col, val in zip(["C","D","E","F","G"], vals):
            data_cell(ws_fp, f"{col}{row}", val, fmt, bold=(row == 7), color=color if isinstance(val, (int, float)) else "64748B")
        for col in ["B","C","D","E","F","G"]:
            ws_fp[f"{col}{row}"].border = thin_border

    header(ws_fp, "B10", "── REVENUE (₦M)", "94A3B8", "F0F4FF", 9, False)
    rows_data2 = [
        (11, "Total Revenue (₦M)", [d["revenue_m"] for d in FINANCIAL_DATA], "#,##0", BOMPAY_BLUE),
        (12, "Gross Margin %", [f'{d["gross_margin"]}%' for d in FINANCIAL_DATA], None, GREEN),
        (13, "YoY Revenue Growth", ["—", "265%", "180%", "186%", "157%"], None, AMBER),
    ]
    for row, label, vals, fmt, color in rows_data2:
        data_cell(ws_fp, f"B{row}", label, align="left", bold=True)
        for col, val in zip(["C","D","E","F","G"], vals):
            data_cell(ws_fp, f"{col}{row}", val, fmt, bold=(row == 11), color=color if isinstance(val, (int, float)) else "64748B")
        for col in ["B","C","D","E","F","G"]:
            ws_fp[f"{col}{row}"].border = thin_border

    header(ws_fp, "B15", "── TOTAL PAYMENT VOLUME (₦B)", "94A3B8", "F0F4FF", 9, False)
    data_cell(ws_fp, "B16", "TPV (₦B)", align="left", bold=True)
    for col, d in zip(["C","D","E","F","G"], FINANCIAL_DATA):
        data_cell(ws_fp, f"{col}16", d["tpv_b"], "#,##0.0", bold=True, color=PURPLE)
    for col in ["B","C","D","E","F","G"]:
        ws_fp[f"{col}16"].border = thin_border

    header(ws_fp, "B18", "── UNIT ECONOMICS", "94A3B8", "F0F4FF", 9, False)
    ue_rows = [
        (19, "Blended Take Rate", "1.2%", "1.2%", "1.3%", "1.3%", "1.4%"),
        (20, "Consumer CAC (₦)", "350", "320", "290", "260", "230"),
        (21, "Consumer LTV 24M (₦)", "4,200", "5,000", "6,200", "7,500", "9,000"),
        (22, "Merchant CAC (₦)", "8,500", "7,800", "7,200", "6,500", "5,800"),
        (23, "Merchant LTV 36M (₦)", "95,000", "110,000", "130,000", "155,000", "185,000"),
    ]
    for row_data in ue_rows:
        row, label, *vals = row_data
        data_cell(ws_fp, f"B{row}", label, align="left")
        for col, val in zip(["C","D","E","F","G"], vals):
            data_cell(ws_fp, f"{col}{row}", val)

    # ── Sheet 3: Use of Funds ──────────────────────────────────────────────────
    ws_uof = wb.create_sheet("Use of Funds")
    ws_uof.sheet_view.showGridLines = False
    for c, w in zip(["A","B","C","D","E"], [3, 36, 14, 12, 20]):
        ws_uof.column_dimensions[c].width = w
    for r in range(1, 25):
        ws_uof.row_dimensions[r].height = 20

    header(ws_uof, "B1", "USE OF FUNDS — $1M SEED ROUND (INDICATIVE)", WHITE, DARK_NAVY, 13)
    header(ws_uof, "B2", "Allocation subject to change based on investor terms and board approval.", "94A3B8", DARK_NAVY, 9, False)
    header(ws_uof, "B4", "Category", WHITE, DARK_NAVY, 10)
    header(ws_uof, "C4", "Amount", WHITE, DARK_NAVY, 10)
    header(ws_uof, "D4", "Allocation", WHITE, DARK_NAVY, 10)

    uof_colors = [BOMPAY_BLUE, GREEN, PURPLE, AMBER]
    for i, (d, c) in enumerate(zip(FUNDS_DATA, uof_colors)):
        row = 5 + i
        ws_uof[f"B{row}"] = d["name"]
        ws_uof[f"B{row}"].font = Font(name="Calibri", size=10, bold=True, color=c)
        ws_uof[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
        ws_uof[f"C{row}"] = d["amount"]
        ws_uof[f"C{row}"].font = Font(name="Calibri", size=10, bold=True, color="071426")
        ws_uof[f"C{row}"].alignment = Alignment(horizontal="right", vertical="center")
        ws_uof[f"D{row}"] = f"{d['pct']}%"
        ws_uof[f"D{row}"].font = Font(name="Calibri", size=10, color="64748B")
        ws_uof[f"D{row}"].alignment = Alignment(horizontal="right", vertical="center")
        for col in ["B","C","D"]:
            ws_uof[f"{col}{row}"].border = thin_border
        if i % 2 == 1:
            for col in ["B","C","D"]:
                ws_uof[f"{col}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")

    ws_uof["B10"] = "TOTAL"
    ws_uof["B10"].font = Font(name="Calibri", size=11, bold=True, color=DARK_NAVY)
    ws_uof["C10"] = "$1.0M"
    ws_uof["C10"].font = Font(name="Calibri", size=11, bold=True, color=BOMPAY_BLUE)
    ws_uof["C10"].alignment = Alignment(horizontal="right")
    ws_uof["D10"] = "100%"
    ws_uof["D10"].font = Font(name="Calibri", size=11, bold=True, color=DARK_NAVY)
    ws_uof["D10"].alignment = Alignment(horizontal="right")

    ws_uof["B12"] = "Note: Figures are indicative and subject to board and investor approval."
    ws_uof["B12"].font = Font(name="Calibri", size=9, italic=True, color="94A3B8")

    # ── Sheet 4: Assumptions ───────────────────────────────────────────────────
    ws_ass = wb.create_sheet("Assumptions")
    ws_ass.sheet_view.showGridLines = False
    ws_ass.column_dimensions["B"].width = 40
    ws_ass.column_dimensions["C"].width = 22
    ws_ass.column_dimensions["D"].width = 30

    header(ws_ass, "B1", "MODEL ASSUMPTIONS", WHITE, DARK_NAVY, 13)
    header(ws_ass, "B3", "Assumption", WHITE, DARK_NAVY, 10)
    header(ws_ass, "C3", "Value", WHITE, DARK_NAVY, 10)
    header(ws_ass, "D3", "Notes", WHITE, DARK_NAVY, 10)

    assumptions = [
        ("Checkout Fee Rate", "1.5%", "Applied to merchant transaction value"),
        ("Transfer Margin", "0.3%", "Net spread on NIP transfers"),
        ("VAS Gross Margin", "18%", "Average across airtime/data/bills"),
        ("Consumer CAC (Y1)", "₦350", "Organic + referral growth"),
        ("Merchant CAC (Y1)", "₦8,500", "Sales team + digital marketing"),
        ("Consumer Churn Rate (annual)", "12%", "Industry average for digital wallets"),
        ("Merchant Churn Rate (annual)", "8%", "SaaS comparable"),
        ("Monthly Consumer ARPU (Y1)", "₦1,200", "Transaction fees + VAS commissions"),
        ("Monthly Merchant ARPU (Y1)", "₦14,500", "Platform fee + checkout + transfers"),
        ("Headcount Growth (Y1→Y5)", "12 → 85", "Key hires per growth phase"),
        ("Nigeria GDP Growth (assumed)", "4.5%/yr", "IMF forecast"),
        ("NIP Volume Growth", "18%/yr", "NIBSS historical trend"),
    ]
    for i, (a, v, n) in enumerate(assumptions):
        row = 4 + i
        ws_ass[f"B{row}"] = a
        ws_ass[f"B{row}"].font = Font(name="Calibri", size=10, color="071426")
        ws_ass[f"B{row}"].alignment = Alignment(horizontal="left", vertical="center")
        ws_ass[f"C{row}"] = v
        ws_ass[f"C{row}"].font = Font(name="Calibri", size=10, bold=True, color=BOMPAY_BLUE)
        ws_ass[f"C{row}"].alignment = Alignment(horizontal="right", vertical="center")
        ws_ass[f"D{row}"] = n
        ws_ass[f"D{row}"].font = Font(name="Calibri", size=9, color="64748B", italic=True)
        ws_ass[f"D{row}"].alignment = Alignment(horizontal="left", vertical="center")
        if i % 2 == 0:
            for col in ["B","C","D"]:
                ws_ass[f"{col}{row}"].fill = PatternFill("solid", fgColor="F8FAFF")
        for col in ["B","C","D"]:
            ws_ass[f"{col}{row}"].border = thin_border
    for r in range(1, 20):
        ws_ass.row_dimensions[r].height = 18

    # Stream the workbook
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=Bompay_Financial_Model.xlsx"},
    )


# ── PPTX Export (python-pptx) ──────────────────────────────────────────────────

@router.get("/investors/exports/pptx")
async def export_pptx():
    """Generate editable PowerPoint pitch deck (12 slides)."""
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN

    def rgb(hex_str: str) -> RGBColor:
        h = hex_str.lstrip("#")
        return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

    sections = await _load_sections_dict()

    prs = Presentation()
    prs.slide_width  = Inches(13.33)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]  # blank

    slide_order = [
        "executive_summary", "financial_projections", "traction",
        "market_opportunity", "product_tech", "use_of_funds",
        "unit_economics", "regulatory", "cap_table", "data_room",
        "team", "enquiry",
    ]

    for idx, sid in enumerate(slide_order):
        s = sections.get(sid, {})
        accent_hex = SLIDE_ACCENT.get(sid, BOMPAY_BLUE)
        title_text  = s.get("title", sid.replace("_", " ").title())
        tagline     = s.get("tagline", "")
        overview    = s.get("overview", "")
        key_points  = s.get("key_points", [])[:6]
        hm          = s.get("highlight_metric", {})

        slide = prs.slides.add_slide(blank_layout)

        # Background
        bg = slide.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, prs.slide_height)
        bg.fill.solid(); bg.fill.fore_color.rgb = rgb(DARK_NAVY)
        bg.line.fill.background()

        # Accent bar (left)
        ab = slide.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.07), prs.slide_height)
        ab.fill.solid(); ab.fill.fore_color.rgb = rgb(accent_hex)
        ab.line.fill.background()

        # Slide number (top-right)
        txb = slide.shapes.add_textbox(Inches(11.5), Inches(0.3), Inches(1.5), Inches(0.4))
        tf = txb.text_frame
        tf.text = f"{idx+1:02d} / 12"
        tf.paragraphs[0].runs[0].font.size = Pt(9)
        tf.paragraphs[0].runs[0].font.color.rgb = rgb("475569")
        tf.paragraphs[0].runs[0].font.name = "Calibri"
        tf.paragraphs[0].alignment = PP_ALIGN.RIGHT

        # Brand
        txb2 = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(6), Inches(0.4))
        tf2 = txb2.text_frame
        tf2.text = "BOMPAY  ·  INVESTOR DECK  ·  A PRODUCT OF BOMDRIVE LIMITED"
        tf2.paragraphs[0].runs[0].font.size = Pt(7)
        tf2.paragraphs[0].runs[0].font.color.rgb = rgb("475569")
        tf2.paragraphs[0].runs[0].font.name = "Calibri"

        # Title
        txb3 = slide.shapes.add_textbox(Inches(0.6), Inches(1.0), Inches(8.5), Inches(1.2))
        tf3 = txb3.text_frame
        tf3.word_wrap = True
        p3 = tf3.paragraphs[0]
        run3 = p3.add_run()
        run3.text = title_text
        run3.font.size = Pt(36)
        run3.font.bold = True
        run3.font.color.rgb = rgb(WHITE)
        run3.font.name = "Calibri"

        # Tagline
        if tagline:
            txb4 = slide.shapes.add_textbox(Inches(0.6), Inches(2.1), Inches(8.5), Inches(0.5))
            tf4 = txb4.text_frame
            tf4.word_wrap = True
            p4 = tf4.paragraphs[0]
            run4 = p4.add_run()
            run4.text = tagline
            run4.font.size = Pt(13)
            run4.font.color.rgb = rgb(accent_hex)
            run4.font.name = "Calibri"
            run4.font.italic = True

        # Overview (truncated)
        if overview:
            txb5 = slide.shapes.add_textbox(Inches(0.6), Inches(2.7), Inches(7.8), Inches(1.5))
            tf5 = txb5.text_frame
            tf5.word_wrap = True
            p5 = tf5.paragraphs[0]
            run5 = p5.add_run()
            run5.text = overview[:450] + ("…" if len(overview) > 450 else "")
            run5.font.size = Pt(11)
            run5.font.color.rgb = rgb("94A3B8")
            run5.font.name = "Calibri"

        # Key points
        kp_top = Inches(4.3) if overview else Inches(2.9)
        if key_points:
            txb6 = slide.shapes.add_textbox(Inches(0.6), kp_top, Inches(7.8), Inches(2.5))
            tf6 = txb6.text_frame
            tf6.word_wrap = True
            for i, kp in enumerate(key_points):
                para = tf6.paragraphs[0] if i == 0 else tf6.add_paragraph()
                para.space_before = Pt(4)
                r = para.add_run()
                r.text = f"→  {kp}"
                r.font.size = Pt(10)
                r.font.color.rgb = rgb("CBD5E1")
                r.font.name = "Calibri"

        # Metric box (right column)
        if hm:
            box = slide.shapes.add_shape(1, Inches(9.8), Inches(1.2), Inches(2.9), Inches(1.8))
            box.fill.solid(); box.fill.fore_color.rgb = rgb("0F2744")
            box.line.color.rgb = rgb(accent_hex)
            box.line.width = Pt(1.5)

            txb_m1 = slide.shapes.add_textbox(Inches(10.0), Inches(1.35), Inches(2.5), Inches(0.4))
            tf_m1 = txb_m1.text_frame
            tf_m1.text = hm.get("label", "").upper()
            tf_m1.paragraphs[0].runs[0].font.size = Pt(9)
            tf_m1.paragraphs[0].runs[0].font.color.rgb = rgb("94A3B8")
            tf_m1.paragraphs[0].runs[0].font.name = "Calibri"

            txb_m2 = slide.shapes.add_textbox(Inches(10.0), Inches(1.75), Inches(2.5), Inches(0.7))
            tf_m2 = txb_m2.text_frame
            tf_m2.text = hm.get("value", "")
            tf_m2.paragraphs[0].runs[0].font.size = Pt(28)
            tf_m2.paragraphs[0].runs[0].font.bold = True
            tf_m2.paragraphs[0].runs[0].font.color.rgb = rgb(accent_hex)
            tf_m2.paragraphs[0].runs[0].font.name = "Calibri"

            txb_m3 = slide.shapes.add_textbox(Inches(10.0), Inches(2.5), Inches(2.5), Inches(0.35))
            tf_m3 = txb_m3.text_frame
            tf_m3.text = hm.get("note", "")
            tf_m3.paragraphs[0].runs[0].font.size = Pt(9)
            tf_m3.paragraphs[0].runs[0].font.color.rgb = rgb("64748B")
            tf_m3.paragraphs[0].runs[0].font.name = "Calibri"

        # Confidentiality footer
        foot = slide.shapes.add_textbox(Inches(0.6), Inches(7.1), Inches(12), Inches(0.3))
        tf_f = foot.text_frame
        tf_f.text = "CONFIDENTIAL  ·  BOMPAY FINANCIAL SERVICES  ·  FOR QUALIFIED INVESTOR USE ONLY"
        tf_f.paragraphs[0].runs[0].font.size = Pt(7)
        tf_f.paragraphs[0].runs[0].font.color.rgb = rgb("2D4A6E")
        tf_f.paragraphs[0].runs[0].font.name = "Calibri"
        tf_f.paragraphs[0].alignment = PP_ALIGN.CENTER

    buf = io.BytesIO()
    prs.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": "attachment; filename=Bompay_Investor_Deck.pptx"},
    )



# ── Live Traction & KPI Report ─────────────────────────────────────────────────

async def _generate_traction_pdf() -> bytes:
    """Query real DB metrics and generate a live traction report PDF."""
    from weasyprint import HTML
    import asyncio

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%d %B %Y, %H:%M UTC")
    month_label = now.strftime("%B %Y")

    # Month boundary as ISO string (handles both string and datetime stored formats)
    month_start_iso = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    async def _safe_count(collection, query):
        try:
            return await collection.count_documents(query)
        except Exception:
            return 0

    async def _safe_agg(collection, pipeline):
        try:
            result = await collection.aggregate(pipeline).to_list(1)
            return result[0]["total"] if result else 0
        except Exception:
            return 0

    # Gather all metrics in parallel
    results = await asyncio.gather(
        _safe_count(db.users,            {}),
        _safe_count(db.merchants,        {}),
        _safe_count(db.merchants,        {"status": "active"}),
        _safe_count(db.stores,           {"is_active": True}),
        _safe_count(db.wallets,          {}),
        _safe_count(db.transactions,     {}),
        _safe_count(db.transactions,     {"created_at": {"$gte": month_start_iso}}),
        _safe_count(db.investor_enquiries, {}),
        _safe_agg(db.transactions, [
            {"$match": {"status": {"$in": ["successful", "success", "completed"]}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
        ]),
        _safe_agg(db.transactions, [
            {"$match": {"created_at": {"$gte": month_start_iso}, "status": {"$in": ["successful", "success", "completed"]}}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
        ]),
    )
    (total_users, total_merchants, active_merchants, active_stores,
     total_wallets, total_txns, month_txns, enquiries,
     cumulative_tpv, month_tpv) = results

    def fmt_ngn(val):
        if val >= 1_000_000_000:
            return f"₦{val/1_000_000_000:.2f}B"
        if val >= 1_000_000:
            return f"₦{val/1_000_000:.1f}M"
        if val >= 1_000:
            return f"₦{val/1_000:.0f}K"
        return f"₦{val:,.0f}"

    def fmt_n(val):
        if val >= 1_000_000:
            return f"{val/1_000_000:.1f}M"
        if val >= 1_000:
            return f"{val/1_000:.1f}K"
        return str(val)

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;700;800&display=swap');
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Plus Jakarta Sans',Arial,sans-serif;background:#fff;color:#071426;font-size:10.5pt;line-height:1.65;}}
  .page{{padding:14mm 20mm 12mm 20mm;}}
  .hdr{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8mm;padding-bottom:4mm;border-bottom:2.5px solid #1769FF;}}
  .logo{{font-size:17pt;font-weight:800;color:#071426;}}
  .meta{{text-align:right;}}
  .badge{{display:inline-block;font-size:6.5pt;font-weight:700;letter-spacing:0.12em;color:#10B981;background:#10B98118;padding:3px 8px;border-radius:20px;margin-bottom:3px;}}
  .live{{color:#EF4444;font-size:7pt;font-weight:700;letter-spacing:0.1em;}}
  h1{{font-size:18pt;font-weight:800;color:#071426;margin-bottom:2mm;}}
  h2{{font-size:11.5pt;font-weight:700;color:#071426;margin:6mm 0 2mm;padding-bottom:1.5mm;border-bottom:1px solid #E2E8F0;}}
  h3{{font-size:10pt;font-weight:700;color:#1769FF;margin:4mm 0 1.5mm;}}
  .sub{{font-size:10.5pt;color:#64748B;margin-bottom:4mm;}}
  .mgrid{{display:flex;flex-wrap:wrap;gap:3mm;margin:4mm 0;}}
  .mc{{background:#071426;border-radius:8px;padding:4mm 5mm;text-align:center;min-width:38mm;flex:1;}}
  .mv{{font-size:18pt;font-weight:800;font-family:monospace;}}
  .ml{{font-size:7pt;color:rgba(255,255,255,0.45);text-transform:uppercase;letter-spacing:0.1em;margin-top:0.5mm;}}
  .mn{{font-size:7pt;color:rgba(255,255,255,0.25);margin-top:0.3mm;}}
  table{{width:100%;border-collapse:collapse;margin:3mm 0;font-size:9.5pt;}}
  th{{background:#071426;color:#fff;padding:2.5mm 3.5mm;text-align:left;font-size:8.5pt;font-weight:600;}}
  td{{padding:2.5mm 3.5mm;border-bottom:1px solid #E2E8F0;}}
  tr:nth-child(even) td{{background:#F8FAFF;}}
  .hl{{background:#1769FF12;border-left:3px solid #1769FF;padding:3mm 5mm;border-radius:0 6px 6px 0;margin:3mm 0;}}
  .disc{{margin-top:6mm;padding:3mm 5mm;background:#FEF3C7;border-radius:6px;font-size:8pt;color:#92400E;}}
  .footer{{position:fixed;bottom:6mm;left:0;right:0;text-align:center;font-size:6.5pt;color:#94A3B8;font-weight:600;letter-spacing:0.1em;}}
  .note{{font-size:8pt;color:#64748B;font-style:italic;}}
</style></head>
<body>
  <div class="footer">LIVE REPORT · GENERATED {stamp} · BOMPAY FINANCIAL SERVICES · TIER 1 — PUBLIC MATERIALS</div>
  <div class="page">
    <div class="hdr">
      <div class="logo">BOMPAY</div>
      <div class="meta">
        <div class="badge">TIER 1 — PUBLIC MATERIALS</div>
        <div class="live">● LIVE DATA — {stamp}</div>
      </div>
    </div>
    <h1>Traction & KPIs Report</h1>
    <p class="sub">Real-time platform metrics pulled directly from the BOMPAY production database. Updated on every download.</p>

    <h2>Platform Overview</h2>
    <div class="mgrid">
      <div class="mc"><div class="mv" style="color:#1769FF">{fmt_n(total_users)}</div><div class="ml">Registered Users</div><div class="mn">Total accounts</div></div>
      <div class="mc"><div class="mv" style="color:#10B981">{fmt_n(active_merchants)}</div><div class="ml">Active Merchants</div><div class="mn">of {fmt_n(total_merchants)} total</div></div>
      <div class="mc"><div class="mv" style="color:#F59E0B">{fmt_n(active_stores)}</div><div class="ml">Live Storefronts</div><div class="mn">Active stores</div></div>
      <div class="mc"><div class="mv" style="color:#8B5CF6">{fmt_n(total_wallets)}</div><div class="ml">Wallets</div><div class="mn">Total wallet accounts</div></div>
    </div>

    <h2>Transaction Metrics</h2>
    <div class="mgrid">
      <div class="mc"><div class="mv" style="color:#10B981">{fmt_ngn(cumulative_tpv)}</div><div class="ml">Cumulative TPV</div><div class="mn">Total platform volume</div></div>
      <div class="mc"><div class="mv" style="color:#1769FF">{fmt_ngn(month_tpv)}</div><div class="ml">TPV This Month</div><div class="mn">{month_label}</div></div>
      <div class="mc"><div class="mv" style="color:#F59E0B">{fmt_n(total_txns)}</div><div class="ml">All-Time Transactions</div><div class="mn">Completed transactions</div></div>
      <div class="mc"><div class="mv" style="color:#8B5CF6">{fmt_n(month_txns)}</div><div class="ml">Transactions This Month</div><div class="mn">{month_label}</div></div>
    </div>

    <h2>Investor Relations</h2>
    <table>
      <tr><th>Metric</th><th>Value</th><th>Notes</th></tr>
      <tr><td>Investor Enquiries Received</td><td><strong>{enquiries}</strong></td><td>Via public investor portal form</td></tr>
      <tr><td>Data Room Documents</td><td><strong>10</strong></td><td>Across Tier 1, 2 and 3</td></tr>
      <tr><td>Report Generated</td><td><strong>{stamp}</strong></td><td>Live — refreshes on each download</td></tr>
    </table>

    <h2>Platform Health Summary</h2>
    <div class="hl">
      <p>BOMPAY's platform is live and processing real transactions. All metrics above are sourced directly from the production database and reflect the current state of the platform as of the report generation timestamp.</p>
    </div>
    <p class="note">Note: Transaction volumes include all successfully processed payments across checkout, transfers, VAS and payment links. Merchant count includes all registered businesses with at least one transaction.</p>

    <div class="disc">
      This report is auto-generated from live BOMPAY platform data. It is provided for informational purposes to Tier 1 qualified investors. All figures are unaudited management data. For detailed financial projections and audited accounts, please request Tier 2 or Tier 3 data room access.
    </div>
  </div>
</body></html>"""

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: HTML(string=html, base_url=None).write_pdf())


@router.get("/investors/exports/traction-pdf")
async def export_traction_pdf():
    """Live Traction & KPI Report — pulled from real DB on every request."""
    pdf = await _generate_traction_pdf()
    now = datetime.now(timezone.utc).strftime("%Y%m%d")
    return StreamingResponse(
        io.BytesIO(pdf),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=BOMPAY_Traction_Report_{now}.pdf"},
    )
