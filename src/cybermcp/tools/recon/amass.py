"""Amass — subdomain enumeration and OSINT tool wrapper."""

from __future__ import annotations

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["AmassTool"]


class AmassInput(BaseModel):
    domain: str = Field(..., description="Root domain to enumerate")
    passive: bool = Field(True, description="Use passive sources only")


class AmassTool(BaseTool):
    name = "amass"
    description = "Subdomain enumeration and OSINT"
    category = ToolCategory.RECON
    binary_name = "amass"
    tags = ["subdomain", "recon", "osint"]
    input_model = AmassInput

    def build_command(self, input_model: AmassInput) -> list[str]:
        cmd = [self.get_binary_path(), "enum", "-d", input_model.domain, "-silent", "-norecursive"]
        if input_model.passive:
            cmd.append("-passive")
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        subdomains = sorted(set(lines))
        success = return_code == 0 or bool(subdomains)
        error = stderr.strip() if return_code != 0 and not subdomains else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={"subdomains": subdomains, "count": len(subdomains)},
            error=error,
        )


TOOLS = [AmassTool()]
