"""Reusable flowable factories for the PDF report."""

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from ..aggregate import (
    GAP_INDICATOR,
    OK_INDICATOR,
    RequirementStat,
    WATCH_INDICATOR,
)
from ..models import Finding, Scanner, Severity, SEVERITY_ORDER
from .styles import FRAME_W, Styles
from .theme import ReportTheme

SCANNER_LABELS = {
    Scanner.SAST: "SAST",
    Scanner.SCA: "SCA",
    Scanner.KICS: "IaC/KICS",
    Scanner.APISEC: "API Sec",
}


def _esc(text: str | None) -> str:
    return escape(str(text) if text is not None else "")


def _truncate(text: str, limit: int = 90) -> str:
    text = (text or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def severity_chip(severity: Severity, styles: Styles, theme: ReportTheme) -> Table:
    color = theme.severity_color(severity)
    para = Paragraph(f"<b>{_esc(severity.value)}</b>", styles.chip)
    table = Table([[para]], colWidths=[22 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 1.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ]
        )
    )
    return table


def status_chip(text: str, styles: Styles, theme: ReportTheme) -> Table:
    color = {
        GAP_INDICATOR: theme.gap,
        WATCH_INDICATOR: theme.watch,
        OK_INDICATOR: theme.ok,
    }.get(text, theme.primary)
    para = Paragraph(f"<b>{_esc(text)}</b>", styles.chip)
    table = Table([[para]], colWidths=[46 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


def plain_table(
    header: list[str],
    rows: list[list],
    styles: Styles,
    *,
    col_widths: list[float] | None = None,
    zebra: bool = True,
    small: bool = False,
) -> Table:
    """Header Paragraph row + body rows (strings escaped; zebra striping)."""
    cell_style = styles.table_cell_small if small else styles.table_cell
    header_row = [
        Paragraph(f"<b>{_esc(h)}</b>", styles.table_header) for h in header
    ]
    body_rows = []
    for row in rows:
        body_rows.append(
            [
                (
                    cell
                    if isinstance(cell, Flowable)
                    else Paragraph(_esc(cell), cell_style)
                )
                for cell in row
            ]
        )
    table = Table([header_row, *body_rows], colWidths=col_widths)
    table.setStyle(styles.table_base)
    if zebra:
        table.setStyle(styles.table_zebra)
    return table


def sample_finding_table(
    findings: list[Finding],
    styles: Styles,
    theme: ReportTheme,
) -> Table:
    rows = []
    for f in findings:
        cwe_cve = f.cwe or f.cve or "-"
        rows.append(
            [
                severity_chip(f.severity, styles, theme),
                Paragraph(
                    f"<b>{_esc(f.title)}</b><br/>"
                    f"<font color='#555555'>{_esc(_truncate(f.description, 110))}</font>",
                    styles.table_cell,
                ),
                Paragraph(
                    f"{_esc(SCANNER_LABELS[f.scanner])}<br/>"
                    f"<font color='#555555'>{_esc(f.component or '-')}</font>",
                    styles.table_cell,
                ),
                Paragraph(_esc(cwe_cve), styles.table_cell),
            ]
        )
    return plain_table(
        ["Severity", "Finding", "Scanner / Component", "CWE/CVE"],
        rows,
        styles,
        col_widths=[24 * mm, None, 62 * mm, 22 * mm],
        zebra=True,
    )


def detailed_finding_table(
    findings: list[Finding],
    styles: Styles,
    theme: ReportTheme,
) -> Table:
    """Appendix A full-detail table."""
    rows = []
    for f in findings:
        cwe_cve = f.cwe or f.cve or "-"
        state = f.state or "n/a"
        pci_tag = "PCI" if f.pci_tagged else ""
        rows.append(
            [
                Paragraph(_esc(f.finding_id), styles.table_cell_small),
                Paragraph(_esc(SCANNER_LABELS[f.scanner]), styles.table_cell_small),
                severity_chip(f.severity, styles, theme),
                Paragraph(_esc(state), styles.table_cell_small),
                Paragraph(_esc(cwe_cve), styles.table_cell_small),
                Paragraph(_esc(f.component or "-"), styles.table_cell_small),
                Paragraph(_esc(f.description or "-"), styles.table_cell_small),
                Paragraph(
                    _esc(_truncate(f.remediation or "-", 160)),
                    styles.table_cell_small,
                ),
                Paragraph(_esc(pci_tag), styles.table_cell_small),
            ]
        )
    return plain_table(
        [
            "Finding ID", "Scanner", "Severity", "State", "CWE/CVE",
            "Component / Location", "Description", "Remediation", "PCI",
        ],
        rows,
        styles,
        col_widths=[
            21 * mm, 15 * mm, 22 * mm, 17 * mm, 20 * mm,
            45 * mm, 68 * mm, 48 * mm, 12 * mm,
        ],
        zebra=True,
        small=True,
    )


def requirement_subsection(
    stat: RequirementStat,
    req_text: str,
    req_guidance: str,
    styles: Styles,
    theme: ReportTheme,
) -> list:
    """Section 3 flowables for one PCI requirement."""
    counts_row = [
        severity_chip(sev, styles, theme)
        for sev in SEVERITY_ORDER
    ]
    # A compact counts line: severity chips with numbers underneath.
    counts_cells = []
    for sev in SEVERITY_ORDER:
        counts_cells.append(
            Paragraph(
                f"<b>{_esc(sev.value)}</b><br/>{stat.counts[sev]}",
                styles.table_cell_small,
            )
        )
    counts_table = Table(
        [[status_chip(stat.indicator, styles, theme), *counts_cells]],
        colWidths=[46 * mm] + [22 * mm] * len(SEVERITY_ORDER),
    )
    counts_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B9C4D1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND", (1, 0), (-1, -1), theme.table_alt),
                ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ]
        )
    )

    flowables = [
        Paragraph(
            f"<font color='{theme.accent.hexval()}'>{_esc(stat.requirement)}</font> "
            f"{_esc(stat.title)}",
            styles.h2,
        ),
        Paragraph(_esc(req_text), styles.body_justify),
        Paragraph(f"<i>Guidance: {_esc(req_guidance)}</i>", styles.small_italic),
        Spacer(1, 2 * mm),
        counts_table,
    ]
    if stat.sample_findings:
        flowables.append(Spacer(1, 2 * mm))
        flowables.append(
            sample_finding_table(stat.sample_findings, styles, theme)
        )
    else:
        flowables.append(Spacer(1, 2 * mm))
        flowables.append(
            Paragraph(
                "No findings mapped to this requirement in the report scope.",
                styles.small,
            )
        )
    return flowables
