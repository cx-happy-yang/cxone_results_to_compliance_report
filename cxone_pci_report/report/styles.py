"""ParagraphStyle / TableStyle palette — the single restyle point.

Every style is derived from the ReportTheme so changing the appearance
config (colors, logo) updates the whole document.
"""

from dataclasses import dataclass, field

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import TableStyle

from .theme import FONT_NAME_OBLIQUE, ReportTheme

PAGE_W, PAGE_H = (210 * mm, 297 * mm)  # A4
MARGIN = 20 * mm
FRAME_W = PAGE_W - 2 * MARGIN
FRAME_H = PAGE_H - 2 * MARGIN


@dataclass
class Styles:
    theme: ReportTheme

    cover_title: ParagraphStyle = field(init=False)
    cover_subtitle: ParagraphStyle = field(init=False)
    cover_meta: ParagraphStyle = field(init=False)
    cover_projects: ParagraphStyle = field(init=False)
    h1: ParagraphStyle = field(init=False)
    h2: ParagraphStyle = field(init=False)
    h3: ParagraphStyle = field(init=False)
    body: ParagraphStyle = field(init=False)
    body_justify: ParagraphStyle = field(init=False)
    small: ParagraphStyle = field(init=False)
    small_italic: ParagraphStyle = field(init=False)
    table_cell: ParagraphStyle = field(init=False)
    table_cell_small: ParagraphStyle = field(init=False)
    table_header: ParagraphStyle = field(init=False)
    chip: ParagraphStyle = field(init=False)
    toc_entry: list = field(init=False)
    mono: ParagraphStyle = field(init=False)

    table_base: TableStyle = field(init=False)
    table_zebra: TableStyle = field(init=False)

    def __post_init__(self) -> None:
        t = self.theme
        base = getSampleStyleSheet()
        font = t.font
        bold = t.font_bold

        self.cover_title = ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName=bold,
            fontSize=24, leading=30, textColor=t.primary,
            spaceAfter=6 * mm,
        )
        self.cover_subtitle = ParagraphStyle(
            "CoverSubtitle", parent=base["Title"], fontName=font,
            fontSize=14, leading=18, textColor=t.accent,
        )
        self.cover_meta = ParagraphStyle(
            "CoverMeta", parent=base["Normal"], fontName=font,
            fontSize=11, leading=16, textColor=colors.black,
        )
        self.cover_projects = ParagraphStyle(
            "CoverProjects", parent=base["Normal"], fontName=font,
            fontSize=10, leading=14, textColor=colors.HexColor("#333333"),
        )
        self.h1 = ParagraphStyle(
            "H1", parent=base["Heading1"], fontName=bold, fontSize=16,
            leading=20, textColor=t.primary, spaceBefore=8 * mm,
            spaceAfter=4 * mm,
        )
        self.h2 = ParagraphStyle(
            "H2", parent=base["Heading2"], fontName=bold, fontSize=12.5,
            leading=16, textColor=t.primary, spaceBefore=5 * mm,
            spaceAfter=2.5 * mm,
        )
        self.h3 = ParagraphStyle(
            "H3", parent=base["Heading3"], fontName=bold, fontSize=10.5,
            leading=14, textColor=t.accent, spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        )
        self.body = ParagraphStyle(
            "Body", parent=base["BodyText"], fontName=font, fontSize=9.5,
            leading=13, textColor=colors.black, alignment=TA_LEFT,
            spaceAfter=2 * mm,
        )
        self.body_justify = ParagraphStyle(
            "BodyJustify", parent=self.body, alignment=TA_JUSTIFY,
        )
        self.small = ParagraphStyle(
            "Small", parent=self.body, fontSize=8, leading=10.5,
            textColor=colors.HexColor("#444444"), spaceAfter=1 * mm,
        )
        self.small_italic = ParagraphStyle(
            "SmallItalic", parent=self.small, fontName=FONT_NAME_OBLIQUE,
            textColor=colors.HexColor("#666666"),
        )
        self.table_cell = ParagraphStyle(
            "TableCell", parent=self.body, fontSize=8.5, leading=11,
            spaceAfter=0,
        )
        self.table_cell_small = ParagraphStyle(
            "TableCellSmall", parent=self.table_cell, fontSize=7.5,
            leading=9.5,
        )
        self.table_header = ParagraphStyle(
            "TableHeader", parent=self.table_cell, fontName=bold,
            textColor=colors.white,
        )
        self.chip = ParagraphStyle(
            "Chip", parent=self.table_cell, fontName=bold, fontSize=8.5,
            leading=11, alignment=TA_CENTER, textColor=colors.white,
        )
        self.toc_entry = [
            ParagraphStyle(
                "TOC1", parent=base["Normal"], fontName=bold, fontSize=11,
                leading=16, textColor=t.primary, leftIndent=0,
                spaceBefore=2 * mm,
            ),
            ParagraphStyle(
                "TOC2", parent=base["Normal"], fontName=font, fontSize=9,
                leading=13, textColor=colors.black, leftIndent=5 * mm,
            ),
        ]
        self.mono = ParagraphStyle(
            "Mono", parent=self.small, fontName="Courier", fontSize=7.5,
            leading=9.5,
        )

        self.table_base = TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B9C4D1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), t.primary),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
        self.table_zebra = TableStyle(
            [
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, t.table_alt]),
            ]
        )
