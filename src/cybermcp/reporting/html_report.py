"""HTML report generator — async Jinja2-based renderer producing self-contained HTML."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import jinja2

from cybermcp.reporting.models import Report, Severity, VulnCard

__all__ = ["HTMLReportGenerator"]

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_ASSET_DIR = Path(__file__).parent / "assets"


class HTMLReportGenerator:
    """Generates self-contained HTML reports from Report objects."""

    def __init__(self) -> None:
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=jinja2.select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["severity_color"] = _severity_color
        self._env.filters["severity_icon"] = _severity_icon
        self._env.filters["format_dt"] = _format_dt
        self._env.filters["nl2br"] = _nl2br

    async def generate(self, report: Report, output_path: str) -> str:
        """Render a Report to an HTML file. Returns the output path."""
        logo_svg = _load_logo()
        css = _load_css()
        sorted_cards = report.sorted_cards()

        severity_data = {
            "critical": report.summary.critical_count,
            "high": report.summary.high_count,
            "medium": report.summary.medium_count,
            "low": report.summary.low_count,
            "info": report.summary.info_count,
        }

        template = self._env.get_template("report.html")
        html = await asyncio.to_thread(
            template.render,
            report=report,
            cards=sorted_cards,
            severity_data=severity_data,
            logo_svg=logo_svg,
            css=css,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(out.write_text, html, "utf-8")
        return str(out.resolve())

    async def render_card(self, card: VulnCard) -> str:
        """Render a single vulnerability card to HTML."""
        template = self._env.get_template("vuln_card.html")
        return await asyncio.to_thread(template.render, card=card)


def _severity_color(severity: Severity | str) -> str:
    if isinstance(severity, str):
        try:
            severity = Severity(severity.lower())
        except ValueError:
            return "#1e90ff"
    return severity.color


def _severity_icon(severity: Severity | str) -> str:
    icons = {
        "critical": "&#9888;",   # ⚠
        "high": "&#9650;",       # ▲
        "medium": "&#9670;",     # ◆
        "low": "&#9679;",        # ●
        "info": "&#8505;",       # ℹ
    }
    val = severity.value if isinstance(severity, Severity) else severity.lower()
    return icons.get(val, "&#8505;")


def _format_dt(dt: Any) -> str:
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(dt)


def _nl2br(text: str) -> str:
    return text.replace("\n", "<br>")


def _load_logo() -> str:
    logo_path = _ASSET_DIR / "logo.svg"
    if logo_path.exists():
        return logo_path.read_text("utf-8")
    return ""


def _load_css() -> str:
    css_path = _TEMPLATE_DIR / "styles.css"
    if css_path.exists():
        return css_path.read_text("utf-8")
    return ""
