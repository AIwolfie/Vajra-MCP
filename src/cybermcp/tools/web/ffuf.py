"""ffuf — web content discovery and fuzzing tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["FfufTool"]


class FfufInput(BaseModel):
    url: str = Field(..., description="Target URL with FUZZ keyword")
    wordlist: str = Field(..., description="Wordlist file path")
    method: str = Field("GET", description="HTTP method")
    threads: int = Field(40, ge=1, le=200, description="Concurrent threads")

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, v: str) -> str:
        from cybermcp.utils.sanitizer import validate_wordlist_path
        validate_wordlist_path(v)
        return v


class FfufTool(BaseTool):
    name = "ffuf"
    description = "Fast web fuzzer for directories and parameters"
    category = ToolCategory.WEB
    binary_name = "ffuf"
    tags = ["fuzzing", "content-discovery", "web"]
    input_model = FfufInput

    docker_capable = True

    def build_command(self, input_model: FfufInput) -> list[str]:
        cmd = [
            self.get_binary_path(),
            "-u", input_model.url,
            "-w", input_model.wordlist,
            "-X", input_model.method.upper(),
            "-t", str(input_model.threads),
            "-of", "json",
            "-o", "-",
        ]
        return cmd

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        import re
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []
        parsed = None

        try:
            with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            
            try:
                parsed = json.loads(content.strip())
                results = parsed.get("results", []) if isinstance(parsed, dict) else []
            except json.JSONDecodeError:
                # Regex recovery for truncated JSON results array
                matches = re.findall(r'\{[^{}]*"url"\s*:\s*"[^"]*"[^{}]*\}', content)
                for match in matches:
                    try:
                        obj = json.loads(match)
                        results.append(obj)
                    except Exception:
                        pass
        except Exception:
            pass

        for res in results:
            url = res.get("url", "")
            status = res.get("status", 0)
            findings.append(
                Finding(
                    title=f"Discovered path {url}",
                    severity=Severity.INFO,
                    description=f"ffuf discovered {url} with status {status}",
                    evidence=str(res),
                    affected_asset=url,
                    tool_name=self.name,
                )
            )

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
            "metadata": parsed if isinstance(parsed, dict) else {"results": results, "count": len(results)},
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


TOOLS = [FfufTool()]
