"""Reportlab chart drawings."""

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing

from ..models import Scanner, Severity, SEVERITY_ORDER
from .theme import ReportTheme

SCANNER_LABELS: dict[Scanner, str] = {
    Scanner.SAST: "SAST",
    Scanner.SCA: "SCA",
    Scanner.KICS: "IaC/KICS",
    Scanner.APISEC: "API Sec",
}


def severity_bar_chart(
    scanner_matrix: dict[Scanner, dict[Severity, int]],
    theme: ReportTheme,
    *,
    width: float = 480,
    height: float = 170,
) -> Drawing:
    """Grouped vertical bar chart: one group per scanner, one bar per severity."""
    categories = [SCANNER_LABELS[s] for s in Scanner]
    # One series per severity, values across the scanner categories.
    data = [
        [scanner_matrix[scanner][severity] for scanner in Scanner]
        for severity in SEVERITY_ORDER
    ]

    chart = VerticalBarChart()
    chart.x = 40
    chart.y = 45
    chart.width = width - 60
    chart.height = height - 60
    chart.data = data
    chart.categoryAxis.categoryNames = categories
    chart.categoryAxis.labels.fontName = theme.font
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontName = theme.font
    chart.valueAxis.labels.fontSize = 7
    chart.groupSpacing = 6
    chart.barSpacing = 1.2
    chart.bars[0].fillColor = theme.severity_color(Severity.CRITICAL)
    chart.bars[1].fillColor = theme.severity_color(Severity.HIGH)
    chart.bars[2].fillColor = theme.severity_color(Severity.MEDIUM)
    chart.bars[3].fillColor = theme.severity_color(Severity.LOW)
    chart.bars[4].fillColor = theme.severity_color(Severity.INFO)
    for bar, severity in zip(chart.bars, SEVERITY_ORDER):
        bar.strokeColor = None

    legend = Legend()
    legend.x = width - 170
    legend.y = 6
    legend.fontName = theme.font
    legend.fontSize = 7
    legend.colorNamePairs = [
        (theme.severity_color(s), s.value) for s in SEVERITY_ORDER
    ]
    legend.dx = 6
    legend.dy = 6
    legend.columnMaximum = 5
    legend.deltax = 28
    legend.alignment = "right"

    drawing = Drawing(width, height)
    drawing.add(chart)
    drawing.add(legend)
    return drawing
