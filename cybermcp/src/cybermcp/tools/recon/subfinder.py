"""Subfinder — fast subdomain discovery tool wrapper."""

from __future__ import annotations

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["SubfinderTool"]


class SubfinderInput(BaseModel):
    domain: str = Field(..., description="Root domain to enumerate")
    all_sources: bool = Field(False, description="Use all sources (-all)")
    recursive: bool = Field(False, description="Enable recursive search")


class SubfinderTool(BaseTool):
    name = "subfinder"
    description = "Fast passive subdomain discovery"
    category = ToolCategory.RECON
    binary_name = "subfinder"
    tags = ["subdomain", "recon", "osint"]
    input_model = SubfinderInput

    def build_command(self, input_model: SubfinderInput) -> list[str]:
        cmd = [self.get_binary_path(), "-d", input_model.domain, "-silent"]
        if input_model.all_sources:
            cmd.append("-all")
        if input_model.recursive:
            cmd.append("-recursive")
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


TOOLS = [SubfinderTool()]
