"""ffuf — web content discovery and fuzzing tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["FfufTool"]


class FfufInput(BaseModel):
    url: str = Field(..., description="Target URL with FUZZ keyword")
    wordlist: str = Field(..., description="Wordlist file path")
    method: str = Field("GET", description="HTTP method")
    threads: int = Field(40, ge=1, le=200, description="Concurrent threads")


class FfufTool(BaseTool):
    name = "ffuf"
    description = "Fast web fuzzer for directories and parameters"
    category = ToolCategory.WEB
    binary_name = "ffuf"
    tags = ["fuzzing", "content-discovery", "web"]
    input_model = FfufInput

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

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []

        try:
            parsed = json.loads(stdout.strip())
            results = parsed.get("results", []) if isinstance(parsed, dict) else []
        except json.JSONDecodeError:
            parsed = None

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
        if isinstance(parsed, dict):
            if results:
                target_extracted = results[0].get("url", "")

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
                "metadata": parsed if isinstance(parsed, dict) else {"results": results, "count": len(results)},
                "raw_file": "",
            },
            findings=findings,
            error=error,
        )


TOOLS = [FfufTool()]
