"""Wafw00f — WAF detection tool wrapper."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["Wafw00fTool"]


class Wafw00fInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    find_all: bool = Field(False, description="Detect multiple WAFs (-a)")


class Wafw00fTool(BaseTool):
    name = "wafw00f"
    description = "WAF detection and fingerprinting"
    category = ToolCategory.RECON
    binary_name = "wafw00f"
    tags = ["waf", "fingerprint", "web", "recon"]
    input_model = Wafw00fInput

    def build_command(self, input_model: Wafw00fInput) -> list[str]:
        cmd = [self.get_binary_path()]
        if input_model.find_all:
            cmd.append("-a")
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        waf_name = ""
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.search(r"behind (.+?) WAF", line, re.IGNORECASE)
            if match:
                waf_name = match.group(1).strip()
                break
            match = re.search(r"Detected:?\s*(.+)$", line, re.IGNORECASE)
            if match:
                waf_name = match.group(1).strip()
                break

        findings = []
        if waf_name:
            findings.append(
                Finding(
                    title="WAF detected",
                    severity=Severity.INFO,
                    description=f"Detected WAF: {waf_name}",
                    evidence=waf_name,
                )
            )

        success = return_code == 0 or bool(waf_name)
        error = stderr.strip() if return_code != 0 and not waf_name else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={"waf": waf_name, "detected": bool(waf_name)},
            findings=findings,
            error=error,
        )


TOOLS = [Wafw00fTool()]
