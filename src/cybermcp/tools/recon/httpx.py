"""httpx — fast HTTP probing and metadata collection."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["HttpxTool"]


class HttpxInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    follow_redirects: bool = Field(True, description="Follow redirects")
    status_code: bool = Field(True, description="Include status code")


class HttpxTool(BaseTool):
    name = "httpx"
    description = "Fast HTTP probe with metadata output"
    category = ToolCategory.RECON
    binary_name = "httpx"
    tags = ["http", "probe", "recon", "web"]
    input_model = HttpxInput

    def build_command(self, input_model: HttpxInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.target, "-silent", "-json"]
        if input_model.follow_redirects:
            cmd.append("-fr")
        if input_model.status_code:
            cmd.append("-status-code")
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        from cybermcp.tools.base import Finding, Severity

        results: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                if line.startswith("http"):
                    results.append({"url": line})

        findings: list[Finding] = []
        for res in results:
            url = res.get("url", "")
            if url:
                status_code = res.get("status_code")
                title = res.get("title", "")
                webserver = res.get("webserver", "")
                techs = res.get("tech", [])
                
                desc_parts = [f"HTTP Service found at {url}"]
                if status_code is not None:
                    desc_parts.append(f"responding with status {status_code}")
                if title:
                    desc_parts.append(f"titled '{title}'")
                if webserver:
                    desc_parts.append(f"running {webserver}")
                if techs:
                    desc_parts.append(f"technologies: {', '.join(techs)}")

                findings.append(Finding(
                    title=f"Discovered HTTP Service: {url}",
                    severity=Severity.INFO,
                    description=" ".join(desc_parts),
                    evidence=json.dumps(res, default=str),
                    affected_asset=url,
                    tool_name=self.name,
                ))

        target_extracted = ""
        if results:
            target_extracted = results[0].get("input", "") or results[0].get("host", "") or results[0].get("url", "")

        success = return_code == 0 or bool(results)
        error = stderr.strip() if return_code != 0 and not results else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={
                "tool": self.name,
                "target": target_extracted,
                "findings": [f.model_dump() for f in findings],
                "metadata": {"results": results, "count": len(results)},
                "raw_file": "",
            },
            findings=findings,
            error=error,
        )


TOOLS = [HttpxTool()]
