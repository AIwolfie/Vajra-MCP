"""Katana — crawling and URL discovery tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["KatanaTool"]


class KatanaInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    depth: int = Field(2, ge=1, le=5, description="Crawl depth")
    js_crawl: bool = Field(False, description="Enable JavaScript crawling")


class KatanaTool(BaseTool):
    name = "katana"
    description = "Fast crawler and URL discovery tool"
    category = ToolCategory.RECON
    binary_name = "katana"
    tags = ["crawler", "urls", "recon", "web"]
    input_model = KatanaInput

    def build_command(self, input_model: KatanaInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.target, "-silent", "-json", "-d", str(input_model.depth)]
        if input_model.js_crawl:
            cmd.append("-js-crawl")
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        results: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                if line.startswith("http"):
                    results.append({"url": line})

        success = return_code == 0 or bool(results)
        error = stderr.strip() if return_code != 0 and not results else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={"results": results, "count": len(results)},
            error=error,
        )


TOOLS = [KatanaTool()]
