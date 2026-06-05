"""WPScan — WordPress security scanner tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["WpscanTool"]


class WpscanInput(BaseModel):
    url: str = Field(..., description="Target WordPress site URL")
    api_token: str | None = Field(None, description="WPScan API token")
    enumerate: list[str] | None = Field(None, description="Enumeration options (e,u,vt,cb)")


class WpscanTool(BaseTool):
    name = "wpscan"
    description = "WordPress security scanner"
    category = ToolCategory.WEB
    binary_name = "wpscan"
    tags = ["wordpress", "cms", "scanner", "web"]
    input_model = WpscanInput

    def build_command(self, input_model: WpscanInput) -> list[str]:
        cmd = [self.get_binary_path(), "--url", input_model.url, "--format", "json"]
        if input_model.api_token:
            cmd.extend(["--api-token", input_model.api_token])
        if input_model.enumerate:
            cmd.extend(["--enumerate", ",".join(input_model.enumerate)])
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {}

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {}

        vulns = parsed.get("vulnerabilities", []) if isinstance(parsed, dict) else []
        for vuln in vulns:
            title = vuln.get("title", "WordPress vulnerability")
            refs = vuln.get("references", {})
            cves = refs.get("cve", []) if isinstance(refs, dict) else []
            findings.append(
                Finding(
                    title=title,
                    severity=Severity.HIGH,
                    description=vuln.get("fixed_in", ""),
                    evidence=json.dumps(vuln, default=str),
                    cve_ids=cves,
                    affected_asset=parsed.get("target_url", ""),
                )
            )

        success = return_code == 0 or bool(vulns)
        error = stderr.strip() if return_code != 0 and not vulns else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data=parsed if isinstance(parsed, dict) else {"data": parsed},
            findings=findings,
            error=error,
        )


TOOLS = [WpscanTool()]
