"""ScoutSuite — multi-cloud security auditing tool."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["ScoutSuiteTool"]


class ScoutSuiteInput(BaseModel):
    provider: str = Field(description="Cloud provider: aws, azure, gcp")
    profile: str = Field(default="", description="Cloud credential profile name")
    services: list[str] = Field(default_factory=list, description="Services to audit (e.g. ec2, s3, iam)")
    report_dir: str = Field(default="", description="Directory for output report")


_SEVERITY_MAP: dict[str, Severity] = {
    "danger": Severity.CRITICAL,
    "warning": Severity.HIGH,
    "caution": Severity.MEDIUM,
    "good": Severity.LOW,
}


class ScoutSuiteTool(BaseTool):
    name = "scoutsuite"
    description = "Multi-cloud security auditing for AWS, Azure, and GCP"
    category = ToolCategory.CLOUD
    binary_name = "scout"

    def build_command(self, input_model: ScoutSuiteInput) -> list[str]:
        cmd = [self.get_binary_path(), input_model.provider]

        if input_model.profile:
            cmd.extend(["--profile", input_model.profile])

        if input_model.services:
            cmd.extend(["--services"] + input_model.services)

        if input_model.report_dir:
            cmd.extend(["--report-dir", input_model.report_dir])

        cmd.append("--no-browser")

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        if return_code != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stderr,
                error=f"ScoutSuite exited with code {return_code}: {stderr}",
            )

        findings: list[Finding] = []
        parsed: dict[str, Any] = {"services_scanned": [], "total_rules": 0, "flagged_items": 0}

        # ScoutSuite writes a JSON report to disk — attempt to parse from stdout too
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "services" in data:
                for svc_name, svc_data in data.get("services", {}).items():
                    parsed["services_scanned"].append(svc_name)
                    for rule_name, rule_data in svc_data.get("findings", {}).items():
                        parsed["total_rules"] += 1
                        flagged = rule_data.get("flagged_items", 0)
                        if flagged > 0:
                            parsed["flagged_items"] += flagged
                            level = rule_data.get("level", "warning").lower()
                            findings.append(
                                Finding(
                                    title=rule_data.get("description", rule_name),
                                    severity=_SEVERITY_MAP.get(level, Severity.MEDIUM),
                                    description=f"{flagged} resource(s) flagged for {rule_name}",
                                    evidence=json.dumps(rule_data.get("items", [])[:5]),
                                    remediation=rule_data.get("remediation", ""),
                                    affected_asset=svc_name,
                                )
                            )

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
        )
