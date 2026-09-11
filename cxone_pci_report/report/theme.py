"""Report theme: colors and fonts derived from the appearance config.

Font resolution: reportlab 5.x no longer bundles the DejaVu TTFs, so we
cascade through system fonts. Preference order:

1. Microsoft YaHei (``C:\\Windows\\Fonts\\msyh*.ttc``) — Latin + CJK
   coverage; primary choice on Windows because CxOne finding text can
   contain Chinese.
2. Arial (``arial*.ttf``) — Latin only.
3. reportlab-bundled Vera — pure fallback (any OS).

The oblique face maps to the light variant for YaHei (no true italic).
"""

import logging
import platform
from dataclasses import dataclass, field
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from ..config import AppearanceConfigSection
from ..models import Severity

log = logging.getLogger(__name__)

FONT_NAME = "ReportSans"
FONT_NAME_BOLD = "ReportSans-Bold"
FONT_NAME_OBLIQUE = "ReportSans-Oblique"
FONT_NAME_BOLD_OBLIQUE = "ReportSans-BoldOblique"

SEVERITY_COLORS: dict[Severity, HexColor] = {
    Severity.CRITICAL: HexColor("#7B1FA2"),
    Severity.HIGH: HexColor("#C0392B"),
    Severity.MEDIUM: HexColor("#E67E22"),
    Severity.LOW: HexColor("#F1C40F"),
    Severity.INFO: HexColor("#95A5A6"),
}


@dataclass(frozen=True)
class FontBundle:
    """(name, path, subfont_index) per face."""

    normal: tuple[str, str, int]
    bold: tuple[str, str, int]
    oblique: tuple[str, str, int]
    bold_oblique: tuple[str, str, int]


def _windows_fonts_dir() -> Path | None:
    if platform.system() != "Windows":
        return None
    fonts_dir = Path("C:/Windows/Fonts")
    return fonts_dir if fonts_dir.is_dir() else None


def _reportlab_fonts_dir() -> Path:
    import reportlab

    return Path(reportlab.__file__).parent / "fonts"


def _resolve_font_bundle() -> FontBundle:
    """Locate usable TTF/TTC files; falls back to reportlab's Vera."""
    reportlab_dir = _reportlab_fonts_dir()
    win = _windows_fonts_dir()

    candidates: list[FontBundle] = []
    if win:
        # Microsoft YaHei: excellent CJK + Latin coverage (TTC files).
        candidates.append(
            FontBundle(
                normal=(f"{FONT_NAME}-src", str(win / "msyh.ttc"), 0),
                bold=(f"{FONT_NAME_BOLD}-src", str(win / "msyhbd.ttc"), 0),
                oblique=(f"{FONT_NAME_OBLIQUE}-src", str(win / "msyhl.ttc"), 0),
                bold_oblique=(f"{FONT_NAME_BOLD_OBLIQUE}-src", str(win / "msyhbd.ttc"), 0),
            )
        )
        # Arial: Latin-only.
        candidates.append(
            FontBundle(
                normal=("ArialMT", str(win / "arial.ttf"), 0),
                bold=("ArialMT-Bold", str(win / "arialbd.ttf"), 0),
                oblique=("ArialMT-Oblique", str(win / "ariali.ttf"), 0),
                bold_oblique=("ArialMT-BoldOblique", str(win / "arialbi.ttf"), 0),
            )
        )
    # DejaVu was bundled with reportlab < 5; keep support if present.
    candidates.append(
        FontBundle(
            normal=("DejaVuSans", str(reportlab_dir / "DejaVuSans.ttf"), 0),
            bold=("DejaVuSans-Bold", str(reportlab_dir / "DejaVuSans-Bold.ttf"), 0),
            oblique=("DejaVuSans-Oblique", str(reportlab_dir / "DejaVuSans-Oblique.ttf"), 0),
            bold_oblique=("DejaVuSans-BoldOblique", str(reportlab_dir / "DejaVuSans-BoldOblique.ttf"), 0),
        )
    )
    # Vera is still bundled with reportlab 5.
    candidates.append(
        FontBundle(
            normal=("Vera", str(reportlab_dir / "Vera.ttf"), 0),
            bold=("Vera-Bold", str(reportlab_dir / "VeraBd.ttf"), 0),
            oblique=("Vera-Italic", str(reportlab_dir / "VeraIt.ttf"), 0),
            bold_oblique=("Vera-BoldItalic", str(reportlab_dir / "VeraBI.ttf"), 0),
        )
    )

    for bundle in candidates:
        faces = (
            bundle.normal, bundle.bold, bundle.oblique, bundle.bold_oblique
        )
        if all(Path(path).is_file() for _, path, _ in faces):
            return bundle
    raise RuntimeError("No usable TTF fonts found for the PDF report.")


def register_fonts() -> None:
    """Register a real TTF family under the ReportSans names."""
    if FONT_NAME in pdfmetrics.getRegisteredFontNames():
        return
    bundle = _resolve_font_bundle()
    for logical_name, (_, path, subfont) in (
        (FONT_NAME, bundle.normal),
        (FONT_NAME_BOLD, bundle.bold),
        (FONT_NAME_OBLIQUE, bundle.oblique),
        (FONT_NAME_BOLD_OBLIQUE, bundle.bold_oblique),
    ):
        pdfmetrics.registerFont(TTFont(logical_name, path, subfontIndex=subfont))
    pdfmetrics.registerFontFamily(
        FONT_NAME,
        normal=FONT_NAME,
        bold=FONT_NAME_BOLD,
        italic=FONT_NAME_OBLIQUE,
        boldItalic=FONT_NAME_BOLD_OBLIQUE,
    )
    log.info("Report fonts registered from: %s", bundle.normal[1])


@dataclass(frozen=True)
class ReportTheme:
    primary: HexColor
    accent: HexColor
    table_alt: HexColor
    gap: HexColor
    watch: HexColor
    ok: HexColor
    logo_path: str | None
    font: str = FONT_NAME
    font_bold: str = FONT_NAME_BOLD
    severity_colors: dict = field(default_factory=dict)

    def severity_color(self, severity: Severity) -> HexColor:
        return SEVERITY_COLORS[severity]


def build_theme(
    config: AppearanceConfigSection,
    *,
    logo_path: str | None = None,
) -> ReportTheme:
    register_fonts()
    return ReportTheme(
        primary=HexColor(config.primary_color),
        accent=HexColor(config.accent_color),
        table_alt=HexColor(config.table_alt_row),
        gap=HexColor(config.gap_color),
        watch=HexColor(config.watch_color),
        ok=HexColor(config.ok_color),
        logo_path=logo_path,
    )
