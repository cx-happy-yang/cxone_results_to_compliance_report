"""Assemble the PCI compliance PDF with reportlab."""

import json
import logging
from dataclasses import asdict
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from .. import __version__, TOOL_NAME
from ..aggregate import ReportData
from ..config import ReportConfig
from ..models import Scanner, Severity, SEVERITY_ORDER
from ..pci_requirements import PCI_REQUIREMENTS, REQUIREMENT_BY_ID
from .charts import SCANNER_LABELS, severity_bar_chart
from .components import (
    detailed_finding_table,
    plain_table,
    requirement_subsection,
    sample_finding_table,
    severity_chip,
)
from .styles import FRAME_H, FRAME_W, MARGIN, PAGE_H, PAGE_W, Styles
from .theme import build_theme

log = logging.getLogger(__name__)


class NumberedCanvas(canvas.Canvas):
    """Canvas that draws 'Page X of Y' footers on every saved page."""

    def __init__(self, *args, footer_left: str = "", footer_right: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._footer_left = footer_left
        self._footer_right = footer_right
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_footer(self, num_pages: int) -> None:
        self.saveState()
        self.setStrokeColor(colors.HexColor("#B9C4D1"))
        self.setLineWidth(0.5)
        self.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#666666"))
        self.drawString(MARGIN, 10 * mm, self._footer_left)
        self.drawRightString(
            PAGE_W - MARGIN, 10 * mm,
            f"{self._footer_right} — Page {self._pageNumber + 1} of {num_pages}",
        )
        self.restoreState()


def _make_canvas_class(footer_left: str, footer_right: str):
    class _NumberedCanvas(NumberedCanvas):
        def __init__(self, *args, **kwargs):
            super().__init__(
                *args,
                footer_left=footer_left,
                footer_right=footer_right,
                **kwargs,
            )

    return _NumberedCanvas


class _PciDocTemplate(BaseDocTemplate):
    """BaseDocTemplate that feeds H1/H2 headings into the table of contents.

    In reportlab 5.x ``afterFlowable`` is an overridable method (it is no
    longer accepted as a build kwarg).
    """

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style_name = flowable.style.name
            if style_name == "H1":
                self.notify(
                    "TOCEntry", (0, flowable.getPlainText(), self.page)
                )
            elif style_name == "H2":
                self.notify(
                    "TOCEntry", (1, flowable.getPlainText(), self.page)
                )


def _draw_cover_background(canv: canvas.Canvas, doc, primary, accent):
    canv.saveState()
    canv.setFillColor(primary)
    canv.rect(0, PAGE_H - 28 * mm, PAGE_W, 28 * mm, stroke=0, fill=1)
    canv.setFillColor(accent)
    canv.rect(0, 0, PAGE_W, 12 * mm, stroke=0, fill=1)
    canv.restoreState()


def _draw_body_background(canv: canvas.Canvas, doc, primary, title):
    canv.saveState()
    canv.setFillColor(primary)
    canv.rect(0, PAGE_H - 10 * mm, PAGE_W, 10 * mm, stroke=0, fill=1)
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 8)
    canv.drawString(MARGIN, PAGE_H - 7 * mm, title[:90])
    canv.restoreState()


def build_pdf(
    data: ReportData,
    cfg: ReportConfig,
    out_path: str | Path,
) -> Path:
    """Render the full report; returns the output path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    theme = build_theme(cfg.appearance, logo_path=cfg.report.logo_path)
    styles = Styles(theme)
    for style in (styles.h1, styles.h2, styles.h3):
        style.keepWithNext = True

    footer_left = f"{TOOL_NAME} v{__version__}"
    footer_right = cfg.report.confidentiality

    doc = _PciDocTemplate(
        str(out_path),
        pagesize=(PAGE_W, PAGE_H),
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=cfg.report.title,
        author=cfg.report.auditor,
        subject="PCI DSS v4.0.1 compliance report",
        canvasmaker=_make_canvas_class(footer_left, footer_right),
    )

    frame_cover = Frame(0, 0, PAGE_W, PAGE_H, id="cover")
    frame_body = Frame(MARGIN, MARGIN, FRAME_W, FRAME_H, id="body")

    doc.addPageTemplates(
        [
            PageTemplate(
                id="cover",
                frames=[frame_cover],
                onPage=lambda c, d: _draw_cover_background(
                    c, d, theme.primary, theme.accent
                ),
            ),
            PageTemplate(
                id="body",
                frames=[frame_body],
                onPage=lambda c, d: _draw_body_background(
                    c, d, theme.primary, cfg.report.title
                ),
            ),
        ]
    )

    toc = TableOfContents()
    toc.levelStyles = styles.toc_entry
    toc.dotsMinLevel = 0

    story = _build_story(data, cfg, styles, theme, toc)
    doc.multiBuild(story)
    return out_path


def _cover(data, cfg, styles, theme) -> list:
    flowables = [Spacer(1, 18 * mm)]
    if theme.logo_path:
        try:
            img = Image(theme.logo_path, width=45 * mm, height=45 * mm)
            img.hAlign = "CENTER"
            flowables.append(img)
            flowables.append(Spacer(1, 10 * mm))
        except OSError as exc:
            log.warning("Could not load logo %s: %s", theme.logo_path, exc)

    flowables.extend(
        [
            Paragraph(escape(cfg.report.title), styles.cover_title),
            Paragraph(
                f"{escape(cfg.report.company_name)}<br/>"
                "PCI DSS v4.0.1 Compliance Report",
                styles.cover_subtitle,
            ),
            Spacer(1, 16 * mm),
        ]
    )
    meta_rows = [
        ["Prepared by", cfg.report.auditor],
        ["Prepared date", cfg.report.prepared_date],
        ["Assessment period", cfg.report.assessment_period],
        ["Standard", "PCI DSS v4.0.1"],
        ["Tool", f"{TOOL_NAME} v{__version__}"],
    ]
    meta_table = plain_table(
        ["", ""],
        meta_rows,
        styles,
        col_widths=[45 * mm, 95 * mm],
        zebra=False,
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), theme.table_alt),
                ("FONTNAME", (0, 0), (0, -1), theme.font_bold),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B9C4D1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    flowables.append(meta_table)
    flowables.append(Spacer(1, 10 * mm))

    project_rows = [
        [
            p.display_name,
            p.scan_id,
            p.branch or "-",
            ", ".join(p.engines) if p.engines else "-",
        ]
        for p in data.projects
    ]
    flowables.append(
        Paragraph("Projects in scope", styles.cover_projects)
    )
    flowables.append(
        plain_table(
            ["Project", "Scan ID", "Branch", "Engines"],
            project_rows,
            styles,
            col_widths=[42 * mm, 48 * mm, 22 * mm, 58 * mm],
            small=True,
        )
    )

    flowables.append(Spacer(1, 18 * mm))
    banner = Table(
        [[Paragraph(
            f"<b>{escape(cfg.report.confidentiality.upper())}</b> — "
            "This document contains security assessment results and must be "
            "handled in accordance with the organization's data handling policy.",
            styles.chip,
        )]],
        colWidths=[FRAME_W - 20 * mm],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), theme.accent),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    banner.hAlign = "CENTER"
    flowables.append(banner)
    flowables.append(NextPageTemplate("body"))
    flowables.append(PageBreak())
    return flowables


def _document_control(cfg, styles, theme) -> list:
    disclaimer = (
        "The findings in this report are supporting evidence and gap "
        "indications for the referenced PCI DSS v4.0.1 requirements. This "
        "document is not a certification statement and does not constitute "
        "an assessment by a Qualified Security Assessor (QSA). Requirement "
        "texts are paraphrased for readability; PCI SSC is the authoritative "
        "source for normative requirement language."
    )
    box = Table(
        [[Paragraph(f"<b>Disclaimer</b><br/>{escape(disclaimer)}", styles.small)]],
        colWidths=[FRAME_W],
    )
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), theme.table_alt),
                ("BOX", (0, 0), (-1, -1), 1, theme.primary),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return [
        Paragraph("Document Control &amp; Scope", styles.h1),
        Paragraph(
            "This report was generated from Checkmarx One scan results "
            "consolidated across the SAST, SCA, IaC Security (KICS) and API "
            "Security engines for the projects listed in the scope table.",
            styles.body_justify,
        ),
        Spacer(1, 3 * mm),
        box,
        Spacer(1, 5 * mm),
        Paragraph("Distribution", styles.h2),
        plain_table(
            ["Role", "Recipient"],
            [
                ["Prepared by", cfg.report.auditor],
                ["Organization", cfg.report.company_name],
                ["Confidentiality", cfg.report.confidentiality],
            ],
            styles,
            col_widths=[45 * mm, 125 * mm],
        ),
        PageBreak(),
    ]


def _executive_summary(data, cfg, styles, theme) -> list:
    project_names = ", ".join(p.display_name for p in data.projects)
    flowables = [
        Paragraph("1. Executive Summary", styles.h1),
        Paragraph(
            f"This report consolidates the most recent completed Checkmarx One "
            f"scans for {data.totals['projects']} project(s) — {escape(project_names)} — "
            f"using the SAST, SCA, IaC Security (KICS) and API Security engines. "
            f"A total of {data.totals['kept']} findings passed the configured "
            f"filters and are mapped to PCI DSS v4.0.1 requirements in Section 3.",
            styles.body_justify,
        ),
        Paragraph("1.1 Findings by project", styles.h2),
    ]
    header = ["Project", *[s.value for s in SEVERITY_ORDER], "Total"]
    rows = [
        [row["project"], row["CRITICAL"], row["HIGH"], row["MEDIUM"],
         row["LOW"], row["INFO"], row["total"]]
        for row in data.severity_by_project
    ]
    flowables.append(
        plain_table(
            header,
            rows,
            styles,
            col_widths=[None] + [16 * mm] * len(SEVERITY_ORDER) + [15 * mm],
        )
    )

    flowables.append(Paragraph("1.2 Findings by scanner", styles.h2))
    matrix_header = ["Scanner", *[s.value for s in SEVERITY_ORDER], "Total"]
    matrix_rows = [
        [
            SCANNER_LABELS[scanner],
            *[data.scanner_matrix[scanner][sev] for sev in SEVERITY_ORDER],
            sum(data.scanner_matrix[scanner].values()),
        ]
        for scanner in Scanner
    ]
    flowables.append(
        plain_table(
            matrix_header,
            matrix_rows,
            styles,
            col_widths=[30 * mm] + [16 * mm] * len(SEVERITY_ORDER) + [15 * mm],
        )
    )
    flowables.append(Spacer(1, 3 * mm))
    flowables.append(severity_bar_chart(data.scanner_matrix, theme, width=FRAME_W))
    flowables.append(Spacer(1, 4 * mm))

    flowables.append(Paragraph("1.3 Findings excluded by filters", styles.h2))
    excluded = data.filtered_out
    filter_rows = [
        ["Excluded by state filter", excluded.get("by_state", 0)],
        ["Excluded by status filter", excluded.get("by_status", 0)],
        ["Excluded by severity floor", excluded.get("by_severity", 0)],
        ["Deduplicated findings", excluded.get("deduplicated", 0)],
        ["SCA ignored vulnerabilities", excluded.get("by_sca_ignored", 0)],
    ]
    flowables.append(
        plain_table(
            ["Exclusion", "Count"],
            filter_rows,
            styles,
            col_widths=[100 * mm, 30 * mm],
        )
    )

    if data.top_findings:
        flowables.append(Paragraph("1.4 Highest-severity findings", styles.h2))
        flowables.append(
            sample_finding_table(data.top_findings, styles, theme)
        )
    flowables.append(PageBreak())
    return flowables


def _methodology(data, cfg, styles, theme) -> list:
    flowables = [
        Paragraph("2. Methodology", styles.h1),
        Paragraph(
            f"Scan results were retrieved from Checkmarx One via the "
            f"CheckmarxPythonSDK and normalized into a common finding model. "
            f"Findings were filtered client-side (see 2.2) and mapped to PCI "
            f"DSS v4.0.1 requirements by a rule engine (see 2.3). Scan "
            f"timestamps are UTC.",
            styles.body_justify,
        ),
        Paragraph("2.1 Scan inventory", styles.h2),
        plain_table(
            ["Project", "Scan ID", "Scan date (UTC)", "Branch", "Engines", "Status"],
            [
                [
                    row["project"],
                    row["scan_id"],
                    (row["scan_created_at"] or "-"),
                    row["branch"] or "-",
                    row["engines"] or "-",
                    row["status"] or "-",
                ]
                for row in data.scan_table
            ],
            styles,
            col_widths=[30 * mm, 42 * mm, 34 * mm, 18 * mm, 42 * mm, 22 * mm],
            small=True,
        ),
        Paragraph("2.2 Filters applied", styles.h2),
        plain_table(
            ["Filter", "Value"],
            [
                ["Result states included", ", ".join(cfg.filters.states)],
                ["Result statuses included", ", ".join(cfg.filters.statuses)],
                ["Minimum severity", cfg.filters.min_severity],
                ["Deduplication scope", cfg.filters.dedupe_scope],
                [
                    "SCA ignored vulnerabilities",
                    "included" if cfg.filters.sca_include_ignored else "excluded",
                ],
            ],
            styles,
            col_widths=[70 * mm, 100 * mm],
        ),
        Paragraph("2.3 PCI mapping provenance", styles.h2),
        Paragraph(
            "Findings are mapped by a built-in rule table (keyword, CWE and "
            "CVE patterns; CVSS >= 9.0 findings are escalated to "
            "requirement 6.5.6). Unmatched findings fall back to requirement "
            f"{escape(cfg.mapping.default_requirement)}. Custom rule "
            "overlays: "
            f"{escape(cfg.mapping.rules_override_path or 'none configured')}. "
            "Each finding may map to multiple requirements; Section 3 shows "
            "the primary requirement's samples and Appendix A lists the "
            "full set per requirement.",
            styles.body_justify,
        ),
        Paragraph(
            "Note: the dedicated SCA endpoint does not expose CxOne triage "
            "state/status, so state and status filters apply to SAST, KICS "
            "and API Security findings only; SCA findings are filtered by "
            "the CxOne SCA 'ignored' flag.",
            styles.small_italic,
        ),
        PageBreak(),
    ]
    return flowables


def _requirements_section(data, cfg, styles, theme) -> list:
    flowables = [
        Paragraph("3. PCI DSS v4.0.1 Requirements Mapping", styles.h1),
        Paragraph(
            "Each requirement below lists the findings mapped to it, with "
            "severity counts and a status indicator. Indicators reflect the "
            "presence of open findings in scope — they are gap indications, "
            "not pass/fail judgments. Requirement texts are paraphrased.",
            styles.body_justify,
        ),
    ]
    for req in PCI_REQUIREMENTS:
        stat = data.requirement_stats[req.requirement]
        flowables.extend(
            requirement_subsection(stat, req.text, req.guidance, styles, theme)
        )
    flowables.append(PageBreak())
    return flowables


def _appendix_a(data, cfg, styles, theme) -> list:
    flowables = [
        Paragraph("Appendix A — Detailed Findings by PCI Requirement", styles.h1),
        Paragraph(
            "Findings are sorted by severity (descending), then first-seen "
            "date. Tables are capped at "
            f"{cfg.mapping.max_findings_per_requirement} rows per requirement; "
            "omitted findings remain available in Checkmarx One.",
            styles.body_justify,
        ),
    ]
    for req in PCI_REQUIREMENTS:
        findings = data.findings_by_requirement[req.requirement]
        if not findings:
            continue
        cap = cfg.mapping.max_findings_per_requirement
        shown = findings[:cap]
        omitted = len(findings) - len(shown)
        flowables.append(
            Paragraph(
                f"{escape(req.requirement)} {escape(req.title)} "
                f"({len(findings)} finding(s))",
                styles.h2,
            )
        )
        flowables.append(detailed_finding_table(shown, styles, theme))
        if omitted > 0:
            flowables.append(
                Paragraph(
                    f"{omitted} additional finding(s) omitted (see Checkmarx "
                    "One).",
                    styles.small_italic,
                )
            )
    flowables.append(PageBreak())
    return flowables


def _appendix_b(cfg, styles, theme) -> list:
    config_echo = json.dumps(asdict(cfg), indent=2, default=str)
    return [
        Paragraph("Appendix B — Tool Information", styles.h1),
        plain_table(
            ["", ""],
            [
                ["Tool", TOOL_NAME],
                ["Tool version", __version__],
                ["Report standard", "PCI DSS v4.0.1"],
                ["Generated", cfg.report.prepared_date],
            ],
            styles,
            col_widths=[45 * mm, 125 * mm],
            zebra=False,
        ),
        Paragraph("Configuration used", styles.h2),
        Table(
            [[Paragraph(f"<font face='Courier' size='7.5'>{escape(config_echo)}</font>", styles.mono)]],
            colWidths=[FRAME_W],
        ),
        Spacer(1, 6 * mm),
        Paragraph("— End of report —", styles.small_italic),
    ]


def _build_story(data, cfg, styles, theme, toc) -> list:
    story: list = []
    story.extend(_cover(data, cfg, styles, theme))
    story.extend(_document_control(cfg, styles, theme))
    story.append(Paragraph("Table of Contents", styles.h1))
    story.append(toc)
    story.append(PageBreak())
    story.extend(_executive_summary(data, cfg, styles, theme))
    story.extend(_methodology(data, cfg, styles, theme))
    story.extend(_requirements_section(data, cfg, styles, theme))
    story.extend(_appendix_a(data, cfg, styles, theme))
    story.extend(_appendix_b(cfg, styles, theme))
    return story
