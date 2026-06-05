"""Pacu — AWS exploitation framework."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["PacuTool"]


class PacuInput(BaseModel):
    module: str = Field(description="Pacu module to run (e.g. iam__enum_permissions, ec2__enum)")
    options: dict[str, str] = Field(default_factory=dict, description="Module-specific options as key-value pairs")
    profile: str = Field(default="", description="AWS credential profile name")


class PacuTool(BaseTool):
    name = "pacu"
    description = "AWS exploitation framework for post-compromise cloud enumeration and escalation"
    category = ToolCategory.CLOUD
    binary_name = "pacu"

    def build_command(self, input_model: PacuInput) -> list[str]:
        cmd = [self.get_binary_path(), "--module", input_model.module]

        if input_model.profile:
            cmd.extend(["--set-regions", input_model.profile])

        for key, value in input_model.options.items():
            cmd.extend([f"--{key}", value])

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        if return_code != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stderr,
                error=f"Pacu exited with code {return_code}: {stderr}",
            )

        findings: list[Finding] = []
        parsed: dict[str, Any] = {"module_output": stdout, "enumerated_items": []}

        # Pacu text output parsing — look for common patterns
        priv_esc_pattern = re.compile(r"CONFIRMED\s+PRIVESC", re.IGNORECASE)
        vuln_pattern = re.compile(r"(VULNERABLE|EXPLOITABLE|MISCONFIGURED)", re.IGNORECASE)
        resource_pattern = re.compile(r"(arn:aws:\S+)")

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            arn_match = resource_pattern.search(stripped)
            if arn_match:
                parsed["enumerated_items"].append(arn_match.group(1))

            if priv_esc_pattern.search(stripped):
                findings.append(
                    Finding(
                        title="Privilege Escalation Path Confirmed",
                        severity=Severity.CRITICAL,
                        description=stripped,
                        evidence=stripped,
                        affected_asset=arn_match.group(1) if arn_match else "",
                    )
                )
            elif vuln_pattern.search(stripped):
                findings.append(
                    Finding(
                        title="AWS Misconfiguration Detected",
                        severity=Severity.HIGH,
                        description=stripped,
                        evidence=stripped,
                        affected_asset=arn_match.group(1) if arn_match else "",
                    )
                )

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
        )
