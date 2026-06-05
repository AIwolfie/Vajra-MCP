"""Prowler — cloud security assessment for AWS, Azure, GCP."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["ProwlerTool"]


class ProwlerInput(BaseModel):
    provider: str = Field(description="Cloud provider: aws, azure, or gcp")
    profile: str = Field(default="", description="Cloud credential profile name")
    checks: list[str] = Field(default_factory=list, description="Specific checks to run")
    severity: list[str] = Field(default_factory=list, description="Filter by severity: critical, high, medium, low")
    output_format: str = Field(default="json", description="Output format")
    region: str = Field(default="", description="Cloud region to scan")


_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


class ProwlerTool(BaseTool):
    name = "prowler"
    description = "Cloud security posture assessment for AWS, Azure, and GCP"
    category = ToolCategory.CLOUD
    binary_name = "prowler"

    def build_command(self, input_model: ProwlerInput) -> list[str]:
        cmd = [self.get_binary_path(), input_model.provider]

        if input_model.profile:
            cmd.extend(["--profile", input_model.profile])

        if input_model.region:
            cmd.extend(["--region", input_model.region])

        if input_model.checks:
            cmd.extend(["--checks", ",".join(input_model.checks)])

        if input_model.severity:
            cmd.extend(["--severity", ",".join(input_model.severity)])

        cmd.extend(["--output-formats", input_model.output_format])
        cmd.append("--no-banner")

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        if return_code != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stderr,
                error=f"Prowler exited with code {return_code}: {stderr}",
            )

        findings: list[Finding] = []
        parsed: dict[str, Any] = {"checks_passed": 0, "checks_failed": 0, "results": []}

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            parsed["results"].append(entry)
            status = entry.get("Status", entry.get("status", "")).upper()

            if status == "FAIL":
                parsed["checks_failed"] += 1
                sev_str = entry.get("Severity", entry.get("severity", "info")).lower()
                findings.append(
                    Finding(
                        title=entry.get("CheckTitle", entry.get("check_title", "Unknown check")),
                        severity=_SEVERITY_MAP.get(sev_str, Severity.INFO),
                        description=entry.get("StatusExtended", entry.get("status_extended", "")),
                        evidence=entry.get("ResourceId", entry.get("resource_id", "")),
                        remediation=entry.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                        affected_asset=entry.get("ResourceArn", entry.get("resource_arn", "")),
                    )
                )
            elif status == "PASS":
                parsed["checks_passed"] += 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
        )
