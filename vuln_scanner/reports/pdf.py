"""Professional PDF reporter using ReportLab."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from vuln_scanner.model import Assessment
from vuln_scanner.reports.base import AbstractReporter
from vuln_scanner.tools.enums import Confidence, ScanStatus, Severity, severity_passes
from vuln_scanner.tools.models import Finding, ScanResult

# ── Palette ───────────────────────────────────────────────────────────────────

_C = {
    "critical": colors.HexColor("#d32f2f"),
    "high": colors.HexColor("#e64a19"),
    "medium": colors.HexColor("#f9a825"),
    "low": colors.HexColor("#1565c0"),
    "info": colors.HexColor("#546e7a"),
    "accent": colors.HexColor("#1976d2"),
    "bg_dark": colors.HexColor("#1a237e"),
    "bg_light": colors.HexColor("#e3f2fd"),
    "row_alt": colors.HexColor("#f5f5f5"),
    "border": colors.HexColor("#bdbdbd"),
    "text": colors.HexColor("#212121"),
    "muted": colors.HexColor("#757575"),
    "white": colors.white,
    "black": colors.black,
}

_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEV_COLOR: dict[Severity, colors.Color] = {
    Severity.CRITICAL: _C["critical"],
    Severity.HIGH: _C["high"],
    Severity.MEDIUM: _C["medium"],
    Severity.LOW: _C["low"],
    Severity.INFO: _C["info"],
}

_SEV_BG: dict[Severity, colors.Color] = {
    Severity.CRITICAL: colors.HexColor("#ffebee"),
    Severity.HIGH: colors.HexColor("#fbe9e7"),
    Severity.MEDIUM: colors.HexColor("#fffde7"),
    Severity.LOW: colors.HexColor("#e3f2fd"),
    Severity.INFO: colors.HexColor("#eceff1"),
}

_CONF_LABEL = {
    Confidence.HIGH: "High",
    Confidence.MEDIUM: "Medium",
    Confidence.LOW: "Low",
    Confidence.UNKNOWN: "—",
}


def _hex(color: colors.Color) -> str:
    return f"#{int(color.hexval(), 16):06x}"


# ── Styles ────────────────────────────────────────────────────────────────────


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    normal = base["Normal"]

    def s(name: str, **kw: object) -> ParagraphStyle:
        return ParagraphStyle(name, parent=normal, **kw)

    return {
        "cover_title": s(
            "cover_title",
            fontSize=28,
            leading=34,
            textColor=_C["white"],
            fontName="Helvetica-Bold",
            alignment=TA_LEFT,
        ),
        "cover_sub": s(
            "cover_sub",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#bbdefb"),
            fontName="Helvetica",
            alignment=TA_LEFT,
        ),
        "cover_meta": s(
            "cover_meta",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#90caf9"),
            fontName="Helvetica",
            alignment=TA_LEFT,
        ),
        "section_title": s(
            "section_title",
            fontSize=14,
            leading=18,
            textColor=_C["accent"],
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6,
        ),
        "sub_title": s(
            "sub_title",
            fontSize=11,
            leading=14,
            textColor=_C["text"],
            fontName="Helvetica-Bold",
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": s(
            "body",
            fontSize=9,
            leading=13,
            textColor=_C["text"],
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "body_small": s(
            "body_small",
            fontSize=8,
            leading=11,
            textColor=_C["text"],
            fontName="Helvetica",
        ),
        "muted": s(
            "muted",
            fontSize=8,
            leading=11,
            textColor=_C["muted"],
            fontName="Helvetica",
        ),
        "code": s(
            "code",
            fontSize=8,
            leading=11,
            textColor=_C["text"],
            fontName="Courier",
            backColor=colors.HexColor("#f5f5f5"),
        ),
        "th": s(
            "th",
            fontSize=8,
            leading=10,
            textColor=_C["white"],
            fontName="Helvetica-Bold",
            alignment=TA_LEFT,
        ),
        "td": s(
            "td",
            fontSize=8,
            leading=11,
            textColor=_C["text"],
            fontName="Helvetica",
        ),
        "td_code": s(
            "td_code",
            fontSize=7.5,
            leading=10,
            textColor=_C["text"],
            fontName="Courier",
        ),
        "footer": s(
            "footer",
            fontSize=7.5,
            leading=10,
            textColor=_C["muted"],
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "page_num": s(
            "page_num",
            fontSize=7.5,
            leading=10,
            textColor=_C["muted"],
            fontName="Helvetica",
            alignment=TA_RIGHT,
        ),
    }


# ── Page canvas decorators ────────────────────────────────────────────────────


class _ReportCanvas:
    """Mixin that draws the header/footer on every page after the cover."""

    def __init__(self, generated_at: str) -> None:
        self._generated_at = generated_at

    def _draw_page_decoration(self, canvas: object, doc: object) -> None:
        from reportlab.lib.units import cm

        c = canvas
        page_w, page_h = A4
        page_no = c.getPageNumber()

        if page_no == 1:
            return  # cover page — no decoration

        # Top bar
        c.saveState()
        c.setFillColor(_C["accent"])
        c.rect(0, page_h - 1.2 * cm, page_w, 1.2 * cm, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 8)
        c.setFillColor(_C["white"])
        c.drawString(1.5 * cm, page_h - 0.85 * cm, "Vulnerability Assessment Report")
        c.setFont("Helvetica", 8)
        c.drawRightString(page_w - 1.5 * cm, page_h - 0.85 * cm, f"Page {page_no}")
        c.restoreState()

        # Bottom bar
        c.saveState()
        c.setFillColor(colors.HexColor("#eeeeee"))
        c.rect(0, 0, page_w, 0.9 * cm, fill=1, stroke=0)
        c.setFont("Helvetica", 7)
        c.setFillColor(_C["muted"])
        c.drawString(1.5 * cm, 0.3 * cm, f"Generated: {self._generated_at}")
        c.drawRightString(page_w - 1.5 * cm, 0.3 * cm, "CONFIDENTIAL")
        c.restoreState()


def _make_doc_template(output_path: Path, generated_at: str) -> SimpleDocTemplate:
    decorator = _ReportCanvas(generated_at)
    return SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.5 * cm,
        onFirstPage=lambda c, d: None,
        onLaterPages=decorator._draw_page_decoration,
    )


# ── Helper builders ───────────────────────────────────────────────────────────


def _sev_badge_para(sev: Severity, st: dict) -> Paragraph:
    color = _SEV_COLOR.get(sev, _C["info"])
    label = sev.value.upper()
    return Paragraph(
        f'<font color="white"><b>{label}</b></font>',
        ParagraphStyle(
            f"badge_{label}",
            parent=st["td"],
            backColor=color,
            textColor=_C["white"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            alignment=TA_CENTER,
            borderPadding=(2, 4, 2, 4),
        ),
    )


def _hr(color: colors.Color = None, thickness: float = 0.5) -> HRFlowable:
    return HRFlowable(
        width="100%",
        thickness=thickness,
        color=color or _C["border"],
        spaceAfter=6,
        spaceBefore=6,
    )


def _table_style(header_color: colors.Color | None = None) -> TableStyle:
    hc = header_color or _C["accent"]
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), hc),
            ("TEXTCOLOR", (0, 0), (-1, 0), _C["white"]),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
            ("TOPPADDING", (0, 0), (-1, 0), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C["white"], _C["row_alt"]]),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("TOPPADDING", (0, 1), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.3, _C["border"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
    )


# ── Reporter ──────────────────────────────────────────────────────────────────


class PDFReporter(AbstractReporter):
    def generate(self, assessment: Assessment, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        st = _build_styles()
        story = self._build_story(assessment, st)
        doc = _make_doc_template(output_path, assessment.stats.generated_at)
        doc.build(story)
        return output_path

    def _build_story(self, assessment: Assessment, st: dict) -> list:
        story: list = []
        story += self._cover(assessment, st)
        story.append(PageBreak())
        story += self._exec_summary(assessment, st)
        story += self._stats_section(assessment, st)
        if assessment.clusters:
            story += self._clusters_section(assessment, st)
        story += self._findings_section(assessment, st)
        if assessment.poc_asset_paths:
            story += self._poc_section(assessment, st)
        return story

    # ── Cover page ────────────────────────────────────────────────────────────

    def _cover(self, assessment: Assessment, st: dict) -> list:
        page_w, page_h = A4
        stats = assessment.stats
        parts: list = []

        # Dark hero band (simulated via a colored table spanning the "page")
        cover_data = [[""]]
        cover_table = Table(cover_data, colWidths=[page_w - 3 * cm], rowHeights=[9 * cm])
        cover_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _C["bg_dark"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 20),
                    ("TOPPADDING", (0, 0), (-1, -1), 30),
                ]
            )
        )
        parts.append(cover_table)
        # Overlay text via separate paragraphs with top spacing hack:
        # We'll build a proper cover using a big colored table with nested content.
        parts.clear()

        inner = [
            [Paragraph("Vulnerability Assessment Report", st["cover_title"])],
            [Spacer(1, 0.4 * cm)],
            [
                Paragraph(
                    f"Targets: {stats.targets_scanned} &nbsp;|&nbsp; "
                    f"Findings: <b>{stats.total_findings}</b> &nbsp;|&nbsp; "
                    f"Duration: {stats.total_duration:.0f}s",
                    st["cover_sub"],
                )
            ],
            [Spacer(1, 0.3 * cm)],
            [Paragraph(f"Generated: {stats.generated_at}", st["cover_meta"])],
        ]
        inner_table = Table(
            inner,
            colWidths=[page_w - 3 * cm - 2 * cm],
        )
        inner_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _C["bg_dark"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )

        hero = Table([[inner_table]], colWidths=[page_w - 3 * cm], rowHeights=[7 * cm])
        hero.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _C["bg_dark"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 1 * cm),
                    ("TOPPADDING", (0, 0), (-1, -1), 1.5 * cm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * cm),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        parts.append(hero)
        parts.append(Spacer(1, 1 * cm))

        # Severity summary cards row
        sev_data = [
            [
                Paragraph(
                    f'<font color="{_hex(_SEV_COLOR[sev])}">'
                    f"<b>{stats.by_severity.get(sev.value, 0)}</b></font><br/>"
                    f'<font size="8" color="#757575">{sev.value.capitalize()}</font>',
                    ParagraphStyle(
                        f"stat_{sev.value}",
                        alignment=TA_CENTER,
                        fontSize=22,
                        leading=28,
                    ),
                )
                for sev in _SEV_ORDER
            ]
        ]
        sev_col_w = (page_w - 3 * cm) / len(_SEV_ORDER)
        sev_table = Table(sev_data, colWidths=[sev_col_w] * len(_SEV_ORDER), rowHeights=[2.2 * cm])
        sev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _C["white"]),
                    ("BOX", (0, 0), (-1, -1), 0.5, _C["border"]),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, _C["border"]),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        parts.append(sev_table)
        parts.append(Spacer(1, 1.5 * cm))

        # Meta stats table
        meta_rows = [
            ["Targets scanned", str(stats.targets_scanned), "Tools run", str(stats.tools_run)],
            ["Tools skipped", str(stats.tools_skipped), "Tools failed", str(stats.tools_failed)],
            ["Total duration", f"{stats.total_duration:.1f}s", "Total findings", str(stats.total_findings)],
        ]
        col_w = (page_w - 3 * cm) / 4
        meta_table = Table(meta_rows, colWidths=[col_w] * 4)
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTNAME", (3, 0), (3, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (0, 0), (0, -1), _C["muted"]),
                    ("TEXTCOLOR", (2, 0), (2, -1), _C["muted"]),
                    ("TEXTCOLOR", (1, 0), (1, -1), _C["text"]),
                    ("TEXTCOLOR", (3, 0), (3, -1), _C["text"]),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_C["white"], _C["row_alt"]]),
                    ("BOX", (0, 0), (-1, -1), 0.5, _C["border"]),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, _C["border"]),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        parts.append(meta_table)
        parts.append(Spacer(1, 2 * cm))
        parts.append(
            Paragraph(
                "CONFIDENTIAL",
                ParagraphStyle(
                    "confidential",
                    fontSize=9,
                    textColor=_C["muted"],
                    alignment=TA_CENTER,
                    fontName="Helvetica-Oblique",
                ),
            )
        )
        return parts

    # ── Executive summary ─────────────────────────────────────────────────────

    def _exec_summary(self, assessment: Assessment, st: dict) -> list:
        summary = assessment.executive_summary or self._computed_summary(assessment)
        parts: list = []
        parts.append(Paragraph("Executive Summary", st["section_title"]))
        parts.append(_hr(color=_C["accent"], thickness=1.5))
        parts.append(Spacer(1, 0.3 * cm))
        # Highlighted box
        box_data = [[Paragraph(summary, st["body"])]]
        box = Table(box_data, colWidths=[A4[0] - 3 * cm])
        box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _C["bg_light"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("BOX", (0, 0), (-1, -1), 2, _C["accent"]),
                ]
            )
        )
        parts.append(box)
        parts.append(Spacer(1, 0.5 * cm))
        return parts

    # ── Stats section ─────────────────────────────────────────────────────────

    def _stats_section(self, assessment: Assessment, st: dict) -> list:
        stats = assessment.stats
        parts: list = []
        parts.append(Paragraph("Scan Statistics", st["section_title"]))
        parts.append(_hr(color=_C["accent"], thickness=1.5))

        header = [
            Paragraph("Severity", st["th"]),
            Paragraph("Count", st["th"]),
            Paragraph("% of Total", st["th"]),
        ]
        rows = [header]
        total = stats.total_findings or 1
        for sev in _SEV_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            pct = f"{count / total * 100:.1f}%"
            c = _SEV_COLOR.get(sev, _C["info"])
            rows.append(
                [
                    Paragraph(
                        f'<font color="{_hex(c)}"><b>{sev.value.upper()}</b></font>',
                        st["td"],
                    ),
                    Paragraph(str(count), st["td"]),
                    Paragraph(pct, st["td"]),
                ]
            )

        col_w = (A4[0] - 3 * cm) / 3
        tbl = Table(rows, colWidths=[col_w * 1.5, col_w * 0.75, col_w * 0.75])
        tbl.setStyle(_table_style())
        parts.append(tbl)
        parts.append(Spacer(1, 0.5 * cm))

        # Per-tool stats
        if stats.by_tool:
            parts.append(Paragraph("Findings by Tool", st["sub_title"]))
            tool_header = [Paragraph("Tool", st["th"]), Paragraph("Findings", st["th"])]
            tool_rows = [tool_header] + [
                [Paragraph(tool, st["td_code"]), Paragraph(str(cnt), st["td"])]
                for tool, cnt in sorted(stats.by_tool.items(), key=lambda x: -x[1])
            ]
            col_w2 = A4[0] - 3 * cm
            tbl2 = Table(tool_rows, colWidths=[col_w2 * 0.75, col_w2 * 0.25])
            tbl2.setStyle(_table_style())
            parts.append(tbl2)
            parts.append(Spacer(1, 0.5 * cm))

        return parts

    # ── Clusters ──────────────────────────────────────────────────────────────

    def _clusters_section(self, assessment: Assessment, st: dict) -> list:
        parts: list = []
        parts.append(Paragraph("Vulnerability Clusters", st["section_title"]))
        parts.append(_hr(color=_C["accent"], thickness=1.5))

        for cluster in sorted(assessment.clusters, key=lambda c: _SEV_ORDER.index(c.severity)):
            sev_c = _SEV_COLOR.get(cluster.severity, _C["info"])
            sev_hex = _hex(sev_c)
            sev_bg = _SEV_BG.get(cluster.severity, colors.white)

            title_para = Paragraph(
                f'<font color="{sev_hex}"><b>[{cluster.severity.value.upper()}]</b></font>  {cluster.title}',
                st["sub_title"],
            )
            summary_para = Paragraph(cluster.summary, st["body"])

            inner_content = [title_para, summary_para]
            if cluster.shared_remediation:
                inner_content.append(
                    Paragraph(
                        f"<b>Remediation:</b> {cluster.shared_remediation}",
                        st["body_small"],
                    )
                )
            if cluster.tags:
                inner_content.append(
                    Paragraph(
                        f"<i>Tags: {', '.join(cluster.tags)}</i>",
                        st["muted"],
                    )
                )

            card_data = [[inner_content]]
            card = Table(card_data, colWidths=[A4[0] - 3 * cm])
            card.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("BOX", (0, 0), (-1, -1), 0.5, sev_c),
                        ("LINEBEFORE", (0, 0), (0, -1), 4, sev_c),
                    ]
                )
            )
            parts.append(KeepTogether(card))
            parts.append(Spacer(1, 0.3 * cm))

        parts.append(Spacer(1, 0.3 * cm))
        return parts

    # ── Findings ──────────────────────────────────────────────────────────────

    def _findings_section(self, assessment: Assessment, st: dict) -> list:
        parts: list = []
        parts.append(Paragraph("Findings", st["section_title"]))
        parts.append(_hr(color=_C["accent"], thickness=1.5))

        by_target: dict[str, list[ScanResult]] = defaultdict(list)
        for r in assessment.results:
            by_target[r.target].append(r)

        for target in sorted(by_target):
            target_results = by_target[target]
            all_findings: list[tuple[str, Finding]] = []
            errors: list[tuple[str, str]] = []

            for r in sorted(target_results, key=lambda x: x.tool):
                if r.status == ScanStatus.SKIPPED and not r.findings:
                    continue
                if r.error and r.status != ScanStatus.SKIPPED:
                    errors.append((r.tool, r.error))
                for f in r.findings:
                    if f.false_positive:
                        continue
                    if not severity_passes(f.severity, self._min_severity):
                        continue
                    all_findings.append((r.tool, f))

            if not all_findings and not errors:
                continue

            all_findings.sort(key=lambda x: _SEV_ORDER.index(x[1].severity))

            parts.append(
                Paragraph(
                    f'Target: <font name="Courier">{target}</font> — {len(all_findings)} finding(s)',
                    st["sub_title"],
                )
            )

            for tool_name, err in errors:
                parts.append(
                    Paragraph(
                        f'<font color="#e64a19"><b>{tool_name}:</b></font> {err}',
                        st["body_small"],
                    )
                )

            if all_findings:
                col_widths = self._findings_col_widths()
                header = [
                    Paragraph("Severity", st["th"]),
                    Paragraph("Tool", st["th"]),
                    Paragraph("Title", st["th"]),
                    Paragraph("CWE", st["th"]),
                    Paragraph("Conf.", st["th"]),
                    Paragraph("CVEs", st["th"]),
                ]
                rows = [header]

                for tool_name, f in all_findings:
                    sev_c = _SEV_COLOR.get(f.severity, _C["info"])
                    sev_hex = _hex(sev_c)
                    cwes = ", ".join(f.cwe) if f.cwe else "—"
                    cves = ", ".join(f.cve) if f.cve else "—"
                    conf = _CONF_LABEL.get(f.confidence, "—")

                    title_content = [Paragraph(f.title, st["td"])]
                    if f.description:
                        desc = f.description[:300]
                        if len(f.description) > 300:
                            desc += "…"
                        title_content.append(Paragraph(desc, st["muted"]))
                    if f.mitigation:
                        title_content.append(
                            Paragraph(
                                f"<b>Mitigation:</b> {f.mitigation[:200]}",
                                st["body_small"],
                            )
                        )
                    if f.poc_ids:
                        title_content.append(
                            Paragraph(
                                f"<i>PoC: {', '.join(f.poc_ids)}</i>",
                                st["muted"],
                            )
                        )

                    rows.append(
                        [
                            Paragraph(
                                f'<font color="{sev_hex}"><b>{f.severity.value.upper()}</b></font>',
                                st["td"],
                            ),
                            Paragraph(tool_name, st["td_code"]),
                            title_content,
                            Paragraph(cwes, st["td_code"]),
                            Paragraph(conf, st["td"]),
                            Paragraph(cves, st["td_code"]),
                        ]
                    )

                tbl = Table(rows, colWidths=col_widths, repeatRows=1)
                sev_style = _table_style()
                # Color severity column cells per row
                for i, (_, f) in enumerate(all_findings, start=1):
                    sev_c = _SEV_COLOR.get(f.severity, _C["info"])
                    sev_bg = _SEV_BG.get(f.severity, colors.white)
                    sev_style.add("BACKGROUND", (0, i), (0, i), sev_bg)
                    sev_style.add("TEXTCOLOR", (0, i), (0, i), sev_c)
                tbl.setStyle(sev_style)
                parts.append(tbl)
            parts.append(Spacer(1, 0.5 * cm))

        return parts

    @staticmethod
    def _findings_col_widths() -> list[float]:
        w = A4[0] - 3 * cm
        return [w * 0.08, w * 0.12, w * 0.42, w * 0.12, w * 0.10, w * 0.16]

    # ── PoC assets ────────────────────────────────────────────────────────────

    def _poc_section(self, assessment: Assessment, st: dict) -> list:
        parts: list = []
        parts.append(Paragraph("PoC Assets", st["section_title"]))
        parts.append(_hr(color=_C["accent"], thickness=1.5))
        for path in assessment.poc_asset_paths:
            parts.append(Paragraph(path, st["code"]))
        parts.append(Spacer(1, 0.5 * cm))
        return parts

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _computed_summary(assessment: Assessment) -> str:
        stats = assessment.stats
        if not stats.total_findings:
            return "No significant findings were identified during this assessment."
        sev_parts = []
        for sev in _SEV_ORDER:
            count = stats.by_severity.get(sev.value, 0)
            if count:
                sev_parts.append(f"{count} {sev.value}")
        return (
            f"The assessment identified {stats.total_findings} finding(s) "
            f"across {stats.targets_scanned} target(s): {', '.join(sev_parts)}."
        )
