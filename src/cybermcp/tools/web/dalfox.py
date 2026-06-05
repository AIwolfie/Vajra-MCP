"""Dalfox — XSS scanning tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["DalfoxTool"]


class DalfoxInput(BaseModel):
    target: str = Field(..., description="Target URL")
    blind: str | None = Field(None, description="Blind XSS callback URL")


class DalfoxTool(BaseTool):
    name = "dalfox"
    description = "XSS scanning and verification"
    category = ToolCategory.WEB
    binary_name = "dalfox"
    tags = ["xss", "web", "scanner"]
    input_model = DalfoxInput

    def build_command(self, input_model: DalfoxInput) -> list[str]:
        cmd = [self.get_binary_path(), "url", input_model.target, "--json", "--no-color"]
        if input_model.blind:
            cmd.extend(["--blind", input_model.blind])
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

            issue_type = obj.get("type", "")
            payload = obj.get("payload", "")
            severity = Severity.HIGH if issue_type.lower().startswith("xss") else Severity.MEDIUM
            findings.append(
                Finding(
                    title=f"Dalfox {issue_type or 'finding'}",
                    severity=severity,
                    description=obj.get("message", "XSS finding"),
                    evidence=payload,
                    affected_asset=obj.get("url", ""),
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


TOOLS = [DalfoxTool()]
