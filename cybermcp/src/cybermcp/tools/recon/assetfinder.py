"""Assetfinder — subdomain discovery tool wrapper."""

from __future__ import annotations

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["AssetfinderTool"]


class AssetfinderInput(BaseModel):
    domain: str = Field(..., description="Root domain to enumerate")


class AssetfinderTool(BaseTool):
    name = "assetfinder"
    description = "Find related subdomains and assets"
    category = ToolCategory.RECON
    binary_name = "assetfinder"
    tags = ["subdomain", "recon", "osint"]
    input_model = AssetfinderInput

    def build_command(self, input_model: AssetfinderInput) -> list[str]:
        return [self.get_binary_path(), "--subs-only", input_model.domain]

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


TOOLS = [AssetfinderTool()]
