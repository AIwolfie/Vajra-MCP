"""Feroxbuster — directory discovery tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["FeroxbusterTool"]


class FeroxbusterInput(BaseModel):
    url: str = Field(..., description="Target URL")
    wordlist: str | None = Field(None, description="Optional wordlist path")
    threads: int = Field(50, ge=1, le=200, description="Concurrent threads")


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"
    description = "Fast content discovery for web applications"
    category = ToolCategory.WEB
    binary_name = "feroxbuster"
    tags = ["content-discovery", "web", "directories"]
    input_model = FeroxbusterInput

    def build_command(self, input_model: FeroxbusterInput) -> list[str]:
        cmd = [
            self.get_binary_path(),
            "-u", input_model.url,
            "--json",
            "--threads", str(input_model.threads),
        ]
        if input_model.wordlist:
            cmd.extend(["-w", input_model.wordlist])
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append(obj)
            url = obj.get("url", "")
            status = obj.get("status", 0)
            findings.append(
                Finding(
                    title=f"Discovered path {url}",
                    severity=Severity.INFO,
                    description=f"feroxbuster discovered {url} with status {status}",
                    evidence=str(obj),
                    affected_asset=url,
                    tool_name=self.name,
                )
            )

        target_extracted = ""
        if results:
            target_extracted = results[0].get("url", "")

        success = return_code == 0 or bool(results)
        error = stderr.strip() if return_code != 0 and not results else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={
                "tool": self.name,
                "target": target_extracted,
                "findings": [f.model_dump() for f in findings],
                "metadata": {"results": results, "count": len(results)},
                "raw_file": "",
            },
            findings=findings,
            error=error,
        )


TOOLS = [FeroxbusterTool()]
