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
        import tempfile
        import os

        if not hasattr(self, "_json_files"):
            self._json_files = {}

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self._json_files[input_model.target] = path

        cmd = [self.get_binary_path(), "--quiet", "--color", "0", "--jsonfile", path]
        if input_model.full:
            cmd.append("--full")
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        import json
        import os
        from pathlib import Path

        # Find the temp file
        json_path = None
        target_extracted = ""
        target_match = re.search(r"Start\s+.*?\s+for\s+(\S+)", stdout, re.IGNORECASE)
        if target_match:
            target_extracted = target_match.group(1).strip()

        if hasattr(self, "_json_files"):
            target_clean = target_extracted.replace("https://", "").replace("http://", "").split("/")[0]
            for k, v in list(self._json_files.items()):
                k_clean = k.replace("https://", "").replace("http://", "").split("/")[0]
                if target_clean in k_clean or k_clean in target_clean or not target_clean:
                    json_path = v
                    target_extracted = k
                    self._json_files.pop(k, None)
                    break

        results = []
        findings: list[Finding] = []

        if json_path and Path(json_path).exists():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    results = json.load(f)
                os.unlink(json_path)
            except Exception:
                pass

        if results:
            for item in results:
                severity_str = item.get("severity", "INFO").upper()
                finding_id = item.get("id", "")
                finding_desc = item.get("finding", "")
                
                if severity_str in ("HIGH", "CRITICAL", "VULNERABLE"):
                    severity = Severity.HIGH
                elif severity_str in ("MEDIUM", "WARN"):
                    severity = Severity.MEDIUM
                elif severity_str == "LOW":
                    severity = Severity.LOW
                else:
                    continue
                
                findings.append(Finding(
                    title=f"TLS Configuration: {finding_id}",
                    severity=severity,
                    description=f"{finding_id}: {finding_desc}",
                    evidence=json.dumps(item),
                    affected_asset=item.get("ip", ""),
                    tool_name=self.name,
                ))
        else:
            # Fallback to stdout parsing
            issues: list[dict[str, str]] = []
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
                            tool_name=self.name,
                        )
                    )

        success = return_code == 0 or bool(findings)
        error = stderr.strip() if return_code != 0 and not findings else ""
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


TOOLS = [TestsslTool()]
