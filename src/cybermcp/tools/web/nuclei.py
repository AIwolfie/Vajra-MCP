"""Nuclei — fast vulnerability scanner using template-based detection."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["NucleiTool"]

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    templates: list[str] | None = Field(None, description="Template IDs or paths")
    severity: list[str] | None = Field(None, description="Filter by severity (critical/high/medium/low/info)")
    tags: list[str] | None = Field(None, description="Filter templates by tags")
    rate_limit: int | None = Field(None, description="Max requests per second")
    concurrency: int | None = Field(None, description="Number of concurrent templates")
    output_format: str = Field("json", description="Output format (json)")


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "Fast and customizable vulnerability scanner based on YAML templates"
    category = ToolCategory.WEB
    binary_name = "nuclei"
    tags = ["scanner", "templates", "vulnerability", "web"]
    input_model = NucleiInput

    def build_command(self, input_model: NucleiInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.target, "-jsonl", "-silent"]

        if input_model.templates:
            for t in input_model.templates:
                cmd.extend(["-t", t])
        if input_model.severity:
            cmd.extend(["-severity", ",".join(input_model.severity)])
        if input_model.tags:
            cmd.extend(["-tags", ",".join(input_model.tags)])
        if input_model.rate_limit is not None:
            cmd.extend(["-rl", str(input_model.rate_limit)])
        if input_model.concurrency is not None:
            cmd.extend(["-c", str(input_model.concurrency)])

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {"results": [], "matched_count": 0}

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            parsed["results"].append(obj)

            template_id = obj.get("template-id", obj.get("templateID", "unknown"))
            matched_at = obj.get("matched-at", obj.get("matched", ""))
            info = obj.get("info", {})
            sev_str = info.get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
            name = info.get("name", template_id)
            desc = info.get("description", "")
            reference = info.get("reference", [])
            references = reference if isinstance(reference, list) else [reference]
            cve_ids: list[str] = []
            for ref in references:
                cve_ids.extend(re.findall(r"CVE-\d{4}-\d{4,7}", str(ref), flags=re.IGNORECASE))
            cve_ids = sorted({cve.upper() for cve in cve_ids})

            findings.append(
                Finding(
                    title=f"{name} ({template_id})",
                    severity=severity,
                    description=desc or f"Nuclei template {template_id} matched",
                    evidence=matched_at,
                    remediation=info.get("remediation", ""),
                    cve_ids=cve_ids,
                    affected_asset=obj.get("host", matched_at),
                )
            )

        parsed["matched_count"] = len(findings)
        success = return_code == 0

        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr.strip() if return_code != 0 and not findings else "",
        )


TOOLS = [NucleiTool()]
