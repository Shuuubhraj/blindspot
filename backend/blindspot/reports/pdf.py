"""PDF report generation via ReportLab (pure Python, no system libraries).

Replaces the old WeasyPrint engine: WeasyPrint needs Pango/Cairo system
libraries that are painful to install on Windows, which produced the
"PDF export needs WeasyPrint's system libraries" error. ReportLab ships
as a plain wheel and works everywhere with zero setup.

Layout: mirrors the HTML console report section for section,
because the HTML print-to-PDF is the look the user asked for:
  - Title block: "Blindspot Security Assessment", tagline, "Developed by
    @shuuubhraj", then the APK metadata as a 3-column BOX GRID (like the
    HTML .meta-grid).
  - Executive summary (prose with severity counts).
  - Contents list.
  - Scope and methodology.
  - APK metadata (key/value).
  - Scan coverage (stage table + rule execution outcomes).
  - Severity distribution as tinted count boxes (color).
  - OWASP Mobile Top 10 (2024) mapping table.
  - AI review: dedicated section with model stats and the AI findings table.
  - Detailed findings: EACH finding starts on its own page, severity badge
    plus an AI badge for AI-engine findings.
  - Limitations and exclusions.
  - Footer on every page: hairline, branding + page number, CONFIDENTIAL.
"""

from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape as _xesc

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, HRFlowable, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table,
                                TableStyle)

from .common import build_report_data

# --- palette (matches the HTML console) --------------------------------------
_INK = colors.HexColor("#1d1d1f")
_GRAY = colors.HexColor("#6e6e73")
_BLUE = colors.HexColor("#0071e3")
_HAIRLINE = colors.HexColor("#e5e5ea")
_NAVY = colors.HexColor("#1a2332")
_CODE_BG = colors.HexColor("#f5f5f7")
_AI_PURPLE = colors.HexColor("#7c3aed")

_SEV_COLORS = {
    "critical": colors.HexColor("#c0362c"),
    "high": colors.HexColor("#d35400"),
    "medium": colors.HexColor("#b7791f"),
    "low": colors.HexColor("#2471a3"),
    "informational": colors.HexColor("#5d6d7e"),
}
_SEV_TINTS = {
    "critical": colors.HexColor("#fdecea"),
    "high": colors.HexColor("#fef4e8"),
    "medium": colors.HexColor("#fdf6e3"),
    "low": colors.HexColor("#eaf4fb"),
    "informational": colors.HexColor("#f2f4f7"),
}
_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
_OWASP_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

_STYLES = getSampleStyleSheet()
S_TITLE = ParagraphStyle("bs_title", parent=_STYLES["Title"],
                         fontName="Helvetica-Bold", fontSize=26, leading=30,
                         textColor=_INK, spaceAfter=4)
S_KICKER = ParagraphStyle("bs_kicker", parent=_STYLES["Normal"],
                          fontName="Helvetica-Bold", fontSize=9, leading=12,
                          textColor=_GRAY, spaceAfter=2)
S_TAGLINE = ParagraphStyle("bs_tagline", parent=_STYLES["Normal"],
                           fontSize=11, leading=14, textColor=_GRAY,
                           spaceAfter=2)
S_CREDIT = ParagraphStyle("bs_credit", parent=_STYLES["Normal"],
                          fontSize=11, leading=14, textColor=_GRAY,
                          spaceAfter=0)
S_H1 = ParagraphStyle("bs_h1", parent=_STYLES["Heading1"],
                      fontName="Helvetica-Bold", fontSize=15, leading=19,
                      textColor=_INK, spaceBefore=16, spaceAfter=4)
S_H2 = ParagraphStyle("bs_h2", parent=_STYLES["Heading2"],
                      fontName="Helvetica-Bold", fontSize=11.5, leading=15,
                      textColor=_INK, spaceBefore=10, spaceAfter=4)
S_FINDING_TITLE = ParagraphStyle("bs_ftitle", parent=_STYLES["Title"],
                                 fontName="Helvetica-Bold", fontSize=17,
                                 leading=21, textColor=_INK, spaceAfter=6)
S_BODY = ParagraphStyle("bs_body", parent=_STYLES["Normal"],
                        fontSize=10, leading=14.5, textColor=_INK,
                        spaceAfter=6)
S_SMALL = ParagraphStyle("bs_small", parent=_STYLES["Normal"],
                         fontSize=8.5, leading=11.5, textColor=_GRAY,
                         spaceAfter=4)
S_CODE = ParagraphStyle("bs_code", parent=_STYLES["Code"],
                        fontName="Courier", fontSize=8, leading=11,
                        textColor=_INK, backColor=_CODE_BG,
                        borderPadding=(8, 8, 8), spaceAfter=8)
S_CELL = ParagraphStyle("bs_cell", parent=_STYLES["Normal"],
                        fontSize=9, leading=12.5, textColor=_INK)
S_CELL_H = ParagraphStyle("bs_cell_h", parent=S_CELL,
                          fontName="Helvetica-Bold", textColor=colors.white)
S_BADGE = ParagraphStyle("bs_badge", parent=_STYLES["Normal"],
                         fontName="Helvetica-Bold", fontSize=10, leading=13,
                         textColor=colors.white, alignment=1)
S_BIGNUM = ParagraphStyle("bs_bignum", parent=_STYLES["Normal"],
                          fontName="Helvetica-Bold", fontSize=22, leading=24,
                          alignment=1, spaceAfter=2)
S_BIGLBL = ParagraphStyle("bs_biglbl", parent=_STYLES["Normal"],
                          fontSize=8.5, leading=10, textColor=_GRAY,
                          alignment=1)
S_META_LBL = ParagraphStyle("bs_meta_lbl", parent=_STYLES["Normal"],
                            fontName="Helvetica-Bold", fontSize=8,
                            leading=10, textColor=_GRAY, spaceAfter=3)
S_META_VAL = ParagraphStyle("bs_meta_val", parent=_STYLES["Normal"],
                            fontSize=9.5, leading=13, textColor=_INK)
S_META_MONO = ParagraphStyle("bs_meta_mono", parent=S_META_VAL,
                             fontName="Courier", fontSize=7.5, leading=10)
S_BULLET = ParagraphStyle("bs_bullet", parent=S_BODY,
                          leftIndent=14, firstLineIndent=0, spaceAfter=3,
                          bulletIndent=6)


def _p(text: object, style: ParagraphStyle = S_BODY) -> Paragraph:
    return Paragraph(_xesc("" if text is None else str(text)), style)


def _pm(markup: str, style: ParagraphStyle = S_BODY) -> Paragraph:
    """Paragraph with trusted inline markup (<b>, <i/>). Only for hardcoded
    strings - never for scan/finding data, which must go through _p."""
    return Paragraph(markup, style)


def _hr(color=_BLUE, thickness: float = 1.2) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness, color=color,
                      spaceBefore=2, spaceAfter=8)


def _section(title: str) -> list:
    return [_p(title, S_H1), _hr()]


def _styled_table(rows: list, col_widths: list) -> Table:
    """Navy header, zebra rows, generous padding - the console table look."""
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f7f9fb")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, _HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def _badge(text: str, bg) -> Table:
    t = Table([[Paragraph(_xesc(text), S_BADGE)]], colWidths=[30 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _badges_row(items: list[tuple[str, object]]) -> Table:
    """Side-by-side badges (severity + AI marker)."""
    cells = [[_badge(text, bg) for text, bg in items]]
    t = Table(cells, colWidths=[30 * mm] * len(items))
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _meta_grid(d: dict) -> Table:
    """3-column box grid mirroring the HTML report's .meta-grid."""
    def cell(label: str, value: object, mono: bool = False):
        return [[_p(label, S_META_LBL)],
                [_p(value, S_META_MONO if mono else S_META_VAL)]]

    rows = [
        [cell("APP NAME", d["app_name"] or d["file_name"]),
         cell("PACKAGE", d["package_name"] or "-"),
         cell("VERSION",
              f"{d['version_name'] or '-'} ({d['version_code'] or '-'})")],
        [cell("SDK (MIN / TARGET)",
              f"{d['min_sdk'] or '-'} / {d['target_sdk'] or '-'}"),
         cell("FILE", d["file_name"]),
         cell("SIZE", d["file_size_human"])],
        [cell("SHA-256", d["sha256"], mono=True),
         cell("ASSESSED", d["finished_at"] or d["created_at"]),
         cell("STATUS", d["status"])],
    ]
    t = Table(rows, colWidths=[170 / 3 * mm] * 3)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, _HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _exec_summary(d: dict) -> list:
    flow: list = _section("Executive summary")
    c = d["counts"]
    if c["critical"] or c["high"]:
        tail = ("Critical and high findings should be triaged first; each "
                "includes evidence, impact, and remediation guidance below.")
    else:
        tail = ("No critical or high severity findings were identified by the "
                "automated checks; review medium findings for defense-in-depth "
                "improvements.")
    flow.append(_pm(
        f"Blindspot performed an automated <b>static</b> security assessment "
        f"of <b>{_xesc(d['file_name'])}</b>"
        + (f" (<b>{_xesc(d['package_name'])}</b>)" if d["package_name"] else "")
        + f". The scan produced <b>{d['total_findings']}</b> finding(s): "
        f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
        f"{c['low']} low, {c['informational']} informational. {tail}"))
    if d["limitations"]:
        flow.append(_pm(
            f"<b>Coverage notice:</b> {len(d['limitations'])} limitation(s) "
            "apply to this assessment - see Limitations and exclusions."))
    return flow


def _contents() -> list:
    flow: list = _section("Contents")
    items = ["Scope and methodology", "APK metadata", "Scan coverage",
             "Severity distribution", "OWASP Mobile Top 10 (2024) mapping",
             "AI review", "Detailed findings", "Limitations and exclusions"]
    for it in items:
        flow.append(_p("\u2022  " + it, S_BULLET))
    return flow


def _scope(d: dict) -> list:
    flow: list = _section("Scope and methodology")
    flow.append(_p(
        "This assessment is static analysis only: the APK was unpacked and "
        "inspected without executing it. No dynamic testing, network "
        "interaction, or backend testing was performed."))
    bullets = [
        "APK structure validation, SHA-256 hashing, safe extraction",
        "AndroidManifest.xml decoding and configuration analysis",
        "Permission, component-export and intent-filter analysis",
        "Decompiled-source review (where a decompiler was available)",
        "MobSFScan static analysis (when available)",
        (f"{d.get('rules_total', '?')} custom Blindspot detection-rule "
         "executions across 7 categories"),
        "Optional local-AI review (Ollama, on-device only - never a cloud service)",
    ]
    for b in bullets:
        flow.append(_p("\u2022  " + b, S_BULLET))
    flow.append(_p(
        "Severity reflects potential impact if the issue is real and "
        "exploitable. Confidence reflects how strongly the evidence supports "
        "the finding. The two are independent.", S_SMALL))
    return flow


def _apk_metadata(d: dict) -> list:
    flow: list = _section("APK metadata")
    rows = [
        ("File name", d["file_name"], False),
        ("SHA-256", d["sha256"], True),
        ("File size", d["file_size_human"], False),
        ("Package", d["package_name"] or "-", False),
        ("App name", d["app_name"] or "-", False),
        ("Version",
         f"{d['version_name'] or '-'} ({d['version_code'] or '-'})", False),
        ("SDK (min / target)",
         f"{d['min_sdk'] or '-'} / {d['target_sdk'] or '-'}", False),
    ]
    trows = []
    for label, value, mono in rows:
        trows.append([_pm(f"<b>{label}</b>", S_META_LBL),
                      _p(value, S_META_MONO if mono else S_META_VAL)])
    t = Table(trows, colWidths=[42 * mm, 128 * mm])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, _HAIRLINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    flow.append(t)
    return flow


def _coverage(d: dict) -> list:
    flow: list = _section("Scan coverage")
    stages = d.get("stages") or []
    if stages:
        rows = [[_pm("<b>Stage</b>", S_CELL_H),
                 _pm("<b>Status</b>", S_CELL_H),
                 _pm("<b>Duration</b>", S_CELL_H),
                 _pm("<b>Note</b>", S_CELL_H)]]
        for st in stages:
            ms = st.get("duration_ms")
            dur = f"{ms} ms" if ms is not None else "-"
            rows.append([_p(st.get("name", "-"), S_CELL),
                         _p(st.get("status", "-"), S_CELL),
                         _p(dur, S_CELL),
                         _p(st.get("note") or "-", S_CELL)])
        flow.append(_styled_table(
            rows, [32 * mm, 28 * mm, 28 * mm, 82 * mm]))
    executions = d.get("executions") or {}
    if executions:
        flow.append(_p("Rule executions by outcome: "
                       + "  ".join(f"{k}: {v}"
                                   for k, v in executions.items()),
                       S_SMALL))
    return flow


def _sev_boxes(d: dict) -> Table:
    cells = []
    for sev in _SEV_ORDER:
        n = d["counts"].get(sev, 0)
        num_style = ParagraphStyle(f"bn_{sev}", parent=S_BIGNUM,
                                   textColor=_SEV_COLORS[sev])
        cells.append([Paragraph(_xesc(str(n)), num_style),
                      Paragraph(_xesc(sev.capitalize()), S_BIGLBL)])
    t = Table([cells], colWidths=[34 * mm] * 5, spaceBefore=4, spaceAfter=4)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]
    for i, sev in enumerate(_SEV_ORDER):
        style.append(("BACKGROUND", (i, 0), (i, 0), _SEV_TINTS[sev]))
        if i > 0:
            style.append(("LEFTPADDING", (i, 0), (i, 0), 8))
    t.setStyle(TableStyle(style))
    return t


def _finding_flow(f: dict, idx: int, total: int) -> list:
    """Flowables for one finding. Caller puts a PageBreak before each."""
    flow: list = []
    flow.append(_p(f"FINDING {idx} OF {total}", S_KICKER))
    flow.append(_p(f["title"], S_FINDING_TITLE))
    badges = [(f["severity"].upper(),
               _SEV_COLORS.get(f["severity"], _GRAY))]
    if f.get("engine") == "ai":
        badges.append(("AI", _AI_PURPLE))
    flow.append(_badges_row(badges))
    flow.append(Spacer(1, 3 * mm))
    meta = (f"{f['finding_id']} · rule {f['rule_id']} v{f['rule_version']} · "
            f"engine: {f['engine']} · confidence: {f['confidence']} · "
            f"validation: {f['validation_status']}")
    flow.append(_p(meta, S_SMALL))
    if f.get("file_path"):
        loc = f["file_path"]
        if f.get("line_start"):
            loc += f" : lines {f['line_start']}"
            if f.get("line_end") and f["line_end"] != f["line_start"]:
                loc += f"–{f['line_end']}"
        flow.append(Paragraph(_xesc(f"Location: {loc}"),
                              ParagraphStyle("loc", parent=S_CODE,
                                             fontSize=8, spaceAfter=4)))
    if f.get("owasp") or f.get("cwe"):
        tags = []
        if f.get("owasp"):
            tags.append("OWASP " + ", ".join(
                f"{c} ({_OWASP_2024.get(c, '')})" for c in f["owasp"]))
        if f.get("cwe"):
            tags.append("CWE " + ", ".join(f["cwe"]))
        flow.append(_p(" · ".join(tags), S_SMALL))
    flow.append(_hr(color=_HAIRLINE, thickness=0.6))

    flow.append(_p("Description", S_H2))
    flow.append(_p(f["description"]))
    if f.get("snippet"):
        flow.append(_p("Evidence", S_H2))
        flow.append(Paragraph(_xesc(f["snippet"]), S_CODE))
    if f.get("impact"):
        flow.append(_p("Impact", S_H2))
        flow.append(_p(f["impact"]))
    if f.get("remediation"):
        flow.append(_p("Remediation", S_H2))
        flow.append(_p(f["remediation"]))
    if f.get("severity_rationale"):
        flow.append(_p(f"Severity rationale: {f['severity_rationale']}",
                       S_SMALL))
    if f.get("confidence_rationale"):
        flow.append(_p(f"Confidence rationale: {f['confidence_rationale']}",
                       S_SMALL))
    prov = [p for p in (f.get("provenance") or [])[1:]]
    if prov:
        flow.append(_p("Also detected by: "
                       + ", ".join(str(p.get("engine", "?")) for p in prov),
                       S_SMALL))
    if f.get("review_note"):
        flow.append(_p(f"Reviewer note: {f['review_note']}", S_SMALL))
    return flow


def _ai_section(d: dict) -> list:
    flow: list = _section("AI review")
    if not d["ai_rows"]:
        flow.append(_p("AI review was not run for this scan. Enable it in the "
                       "scan configuration for a local on-device LLM second "
                       "opinion (Ollama - never a cloud service)."))
        return flow
    for a in d["ai_rows"]:
        flow.append(_p(
            f"Model {a['model']}: {a['status']} - {a['files_reviewed']} files "
            f"reviewed, {a['findings_proposed']} proposed, "
            f"{a['findings_accepted']} accepted."))
        if a.get("error"):
            flow.append(_p(a["error"], S_SMALL))
    flow.append(_p(
        "AI findings are hypotheses with hallucination controls: each one is "
        "validated against real code locations before it is kept, and findings "
        "the static engines independently confirm are marked ai-corroborated. "
        "AI output never overrides a static-engine result.", S_SMALL))
    if d["ai_findings"]:
        rows = [[_pm("<b>#</b>", S_CELL_H), _pm("<b>Finding</b>", S_CELL_H),
                 _pm("<b>Severity</b>", S_CELL_H),
                 _pm("<b>Location</b>", S_CELL_H),
                 _pm("<b>Status</b>", S_CELL_H)]]
        for i, f in enumerate(d["ai_findings"], 1):
            loc = f["file_path"] or "-"
            if f.get("line_start"):
                loc += f":{f['line_start']}"
            sev_style = ParagraphStyle(f"ac_{i}", parent=S_CELL,
                                       fontName="Helvetica-Bold",
                                       textColor=_SEV_COLORS.get(
                                           f["severity"], _GRAY))
            rows.append([_p(str(i)), _p(f["title"]),
                         Paragraph(_xesc(f["severity"].capitalize()),
                                   sev_style),
                         _p(loc, ParagraphStyle("ail", parent=S_CELL,
                                                fontName="Courier",
                                                fontSize=7.5)),
                         _p(f["validation_status"])])
        flow.append(_styled_table(
            rows, [10 * mm, 62 * mm, 28 * mm, 42 * mm, 28 * mm]))
    else:
        flow.append(_p("The AI review proposed no findings that survived "
                       "validation for this scan.", S_SMALL))
    return flow


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(_HAIRLINE)
    canvas.setLineWidth(0.6)
    canvas.line(14 * mm, 14.5 * mm, A4[0] - 14 * mm, 14.5 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(_GRAY)
    canvas.drawString(14 * mm, 11 * mm, "Blindspot - developed by @shuuubhraj")
    canvas.drawRightString(A4[0] - 14 * mm, 11 * mm, f"Page {doc.page}")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(A4[0] - 14 * mm, A4[1] - 12 * mm,
                           "CONFIDENTIAL - authorized assessment use only")
    canvas.restoreState()


def render_pdf(scan_id: str) -> bytes | None:
    d = build_report_data(scan_id)
    if d is None:
        return None

    buf = BytesIO()
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Blindspot assessment - {d['file_name']}",
        author="Blindspot (@shuuubhraj)")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height,
                  id="main")
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                       onPage=_footer)])

    story: list = []
    # ---- title block + meta grid (mirrors the HTML report header) ----
    story.append(_p("Blindspot Security Assessment", S_TITLE))
    story.append(_p("Find what others miss. Static APK security assessment "
                    "report", S_TAGLINE))
    story.append(_p("Developed by @shuuubhraj", S_CREDIT))
    story.append(Spacer(1, 4 * mm))
    story.append(_meta_grid(d))
    story.append(Spacer(1, 2 * mm))

    # ---- executive summary / contents / scope ----
    story.extend(_exec_summary(d))
    story.extend(_contents())
    story.extend(_scope(d))
    story.extend(_apk_metadata(d))
    story.extend(_coverage(d))

    # ---- severity ----
    story.extend(_section("Severity distribution"))
    story.append(_sev_boxes(d))
    story.append(Spacer(1, 2 * mm))

    # ---- OWASP ----
    story.extend(_section("OWASP Mobile Top 10 (2024) mapping"))
    rows = [[_pm("<b>Category</b>", S_CELL_H), _pm("<b>Name</b>", S_CELL_H),
             _pm("<b>Findings</b>", S_CELL_H)]]
    for code in _OWASP_2024:
        n = d["owasp_counts"].get(code, 0)
        n_style = ParagraphStyle(f"ow_{code}", parent=S_CELL,
                                 fontName="Helvetica-Bold" if n
                                 else "Helvetica",
                                 textColor=_BLUE if n else _INK)
        rows.append([_p(code, ParagraphStyle(f"oc_{code}", parent=S_CELL,
                                             fontName="Helvetica-Bold")),
                     _p(_OWASP_2024[code]),
                     Paragraph(_xesc(str(n)), n_style)])
    story.append(_styled_table(rows, [25 * mm, 110 * mm, 35 * mm]))
    story.append(_p("OWASP categories are classification metadata, not "
                    "severity scores.", S_SMALL))

    # ---- AI review ----
    story.extend(_ai_section(d))

    # ---- findings: one per page ----
    for i, f in enumerate(d["findings"], 1):
        story.append(PageBreak())
        if i == 1:
            story.extend(_section("Detailed findings"))
            story.append(_p(f"{d['total_findings']} finding(s), ordered by "
                            "severity. Each finding starts on its own page.",
                            S_SMALL))
            story.append(Spacer(1, 4 * mm))
        story.extend(_finding_flow(f, i, d["total_findings"]))

    # ---- limitations ----
    story.append(PageBreak())
    story.extend(_section("Limitations and exclusions"))
    lims = [
        "Static analysis only - no runtime, network, or backend testing was performed.",
        "Findings marked heuristic or ai-unverified require manual confirmation.",
        "Absence of a finding is not proof of absence of the vulnerability.",
        *(d["limitations"] or []),
        *[f"Tool error: {e}" for e in (d["errors"] or [])],
    ]
    for lim in lims:
        story.append(_p("\u2022  " + lim, S_BULLET))
    story.append(Spacer(1, 8 * mm))
    story.append(_p(
        "Generated by Blindspot Security Console - local-first Android APK "
        "assessment. Developed by @shuuubhraj. Findings are point-in-time "
        "static observations for authorized assessment use.", S_SMALL))

    doc.build(story)
    return buf.getvalue()
