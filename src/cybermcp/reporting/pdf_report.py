"""PDF report generator — renders HTML then converts to PDF."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from cybermcp.reporting.html_report import HTMLReportGenerator
from cybermcp.reporting.models import Report

__all__ = ["PDFReportGenerator"]


class PDFReportGenerator:
    """Generates PDF reports using WeasyPrint if available."""

    def __init__(self) -> None:
        self._html = HTMLReportGenerator()

    async def generate(self, report: Report, output_path: str) -> str:
        """Render a Report to PDF. Returns the output path."""
        try:
            from weasyprint import HTML  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("WeasyPrint is required for PDF export") from exc

        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
            tmp_path = tmp.name

        await self._html.generate(report, tmp_path)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        await asyncio.to_thread(HTML(filename=tmp_path).write_pdf, str(out))
        return str(out.resolve())
