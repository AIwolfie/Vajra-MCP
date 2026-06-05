"""testssl.sh — TLS/SSL configuration scanner tool wrapper."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["TestsslTool"]


class TestsslInput(BaseModel):
    target: str = Field(..., description="Target host or URL")
    full: bool = Field(False, description="Run full test suite")


class TestsslTool(BaseTool):
    name = "testssl"
    description = "TLS/SSL configuration scanner"
    category = ToolCategory.WEB
    binary_name = "testssl.sh"
    binary_candidates = ["testssl"]
    tags = ["tls", "ssl", "web", "crypto"]
    input_model = TestsslInput

    def build_command(self, input_model: TestsslInput) -> list[str]:
        cmd = [self.get_binary_path(), "--quiet", "--color", "0"]
        if input_model.full:
            cmd.append("--full")
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        issues: list[dict[str, str]] = []
        findings: list[Finding] = []

        for line in stdout.splitlines():
            clean = line.strip()
            if not clean:
                continue
            if "VULNERABLE" in clean.upper() or "NOT OK" in clean.upper() or "NOT OK" in clean:
                severity = Severity.HIGH if "VULNERABLE" in clean.upper() else Severity.MEDIUM
                issues.append({"issue": clean, "severity": severity.value})
                findings.append(
                    Finding(
                        title="TLS issue detected",
                        severity=severity,
                        description=clean,
                        evidence=clean,
                        affected_asset="",
                    )
                )

        success = return_code == 0 or bool(issues)
        error = stderr.strip() if return_code != 0 and not issues else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={"issues": issues, "count": len(issues)},
            findings=findings,
            error=error,
        )


TOOLS = [TestsslTool()]
