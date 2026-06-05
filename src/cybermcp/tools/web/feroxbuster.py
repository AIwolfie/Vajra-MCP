"""Feroxbuster — directory discovery tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["FeroxbusterTool"]


class FeroxbusterInput(BaseModel):
    url: str = Field(..., description="Target URL")
    wordlist: str | None = Field(None, description="Optional wordlist path")
    threads: int = Field(50, ge=1, le=200, description="Concurrent threads")

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, v: str | None) -> str | None:
        if v:
            from cybermcp.utils.sanitizer import validate_wordlist_path
            validate_wordlist_path(v)
        return v


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"
    description = "Fast content discovery for web applications"
    category = ToolCategory.WEB
    binary_name = "feroxbuster"
    tags = ["content-discovery", "web", "directories"]
    input_model = FeroxbusterInput

    docker_capable = True

    def build_command(self, input_model: FeroxbusterInput) -> list[str]:
        cmd = [
            self.get_binary_path(),
            "-u", input_model.url,
            "--json",
            "--threads", str(input_model.threads),
        ]
        if input_model.wordlist:
            cmd.extend(["-w", input_model.wordlist])
        return cmd

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        try:
            with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    if len(results) < 2000:
                        results.append(obj)
                        
                    url = obj.get("url", "")
                    status = obj.get("status", 0)
                    findings.append(
                        Finding(
                            title=f"Discovered path {url}",
                            severity=Severity.INFO,
                            description=f"feroxbuster discovered {url} with status {status}",
                            evidence=str(obj),
                            affected_asset=url,
                            tool_name=self.name,
                        )
                    )
        except Exception:
            pass

        target_extracted = ""
        if results:
            target_extracted = results[0].get("url", "")

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


TOOLS = [FeroxbusterTool()]
