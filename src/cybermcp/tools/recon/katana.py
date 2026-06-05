"""Katana — crawling and URL discovery tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["KatanaTool"]


class KatanaInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    depth: int = Field(2, ge=1, le=5, description="Crawl depth")
    js_crawl: bool = Field(False, description="Enable JavaScript crawling")


class KatanaTool(BaseTool):
    name = "katana"
    description = "Fast crawler and URL discovery tool"
    category = ToolCategory.RECON
    binary_name = "katana"
    tags = ["crawler", "urls", "recon", "web"]
    input_model = KatanaInput

    docker_capable = True

    def build_command(self, input_model: KatanaInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.target, "-silent", "-json", "-d", str(input_model.depth)]
        if input_model.js_crawl:
            cmd.append("-js-crawl")
        return cmd

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        from cybermcp.tools.base import Finding, Severity

        results: list[dict[str, Any]] = []
        try:
            with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        if line.startswith("http"):
                            results.append({"url": line})
        except Exception:
            pass

        findings: list[Finding] = []
        for res in results:
            url = res.get("url", "")
            if url:
                findings.append(Finding(
                    title=f"Discovered Endpoint: {url}",
                    severity=Severity.INFO,
                    description=f"Katana crawler discovered endpoint: {url}",
                    evidence=json.dumps(res, default=str),
                    affected_asset=url,
                    tool_name=self.name,
                ))

        target_extracted = ""
        if results:
            target_extracted = results[0].get("url", "") or results[0].get("request", {}).get("endpoint", "")

        success = complete and return_code == 0
        if not complete or not success:
            success = bool(results)

        parsed_data = {
            "tool": self.name,
            "target": target_extracted,
            "findings": [f.model_dump() for f in findings],
            "metadata": {"results": results, "count": len(results)},
            "raw_file": "",
        }
        if not complete:
            parsed_data["partial"] = True

        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output="",
            parsed_data=parsed_data,
            findings=findings,
            error="" if success else "Truncated or crashed scan",
        )

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        import tempfile
        import os
        fd, path = tempfile.mkstemp()
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(stdout)
            os.close(fd)
            return self.parse_output_file(path, "", return_code)
        finally:
            try:
                os.unlink(path)
            except Exception:
                pass


TOOLS = [KatanaTool()]
