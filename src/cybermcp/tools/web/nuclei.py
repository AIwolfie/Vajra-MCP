"""Nuclei — fast vulnerability scanner using template-based detection."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["NucleiTool"]

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    templates: list[str] | None = Field(None, description="Template IDs or paths")
    severity: list[str] | None = Field(None, description="Filter by severity (critical/high/medium/low/info)")
    tags: list[str] | None = Field(None, description="Filter templates by tags")
    rate_limit: int | None = Field(None, description="Max requests per second")
    concurrency: int | None = Field(None, description="Number of concurrent templates")
    output_format: str = Field("json", description="Output format (json)")


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "Fast and customizable vulnerability scanner based on YAML templates"
    category = ToolCategory.WEB
    binary_name = "nuclei"
    tags = ["scanner", "templates", "vulnerability", "web"]
    input_model = NucleiInput

    docker_capable = True

    def build_command(self, input_model: NucleiInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.target, "-jsonl", "-silent"]

        if input_model.templates:
            for t in input_model.templates:
                cmd.extend(["-t", t])
        if input_model.severity:
            cmd.extend(["-severity", ",".join(input_model.severity)])
        if input_model.tags:
            cmd.extend(["-tags", ",".join(input_model.tags)])
        if input_model.rate_limit is not None:
            cmd.extend(["-rl", str(input_model.rate_limit)])
        if input_model.concurrency is not None:
            cmd.extend(["-c", str(input_model.concurrency)])

        return cmd

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {"results": [], "matched_count": 0}
        
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

                    if len(parsed["results"]) < 1000:
                        parsed["results"].append(obj)

                    template_id = obj.get("template-id", obj.get("templateID", "unknown"))
                    matched_at = obj.get("matched-at", obj.get("matched", ""))
                    info = obj.get("info", {})
                    sev_str = info.get("severity", "info").lower()
                    severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
                    name = info.get("name", template_id)
                    desc = info.get("description", "")
                    reference = info.get("reference", [])
                    references = reference if isinstance(reference, list) else [reference]
                    cve_ids: list[str] = []
                    for ref in references:
                        cve_ids.extend(re.findall(r"CVE-\d{4}-\d{4,7}", str(ref), flags=re.IGNORECASE))
                    cve_ids = sorted({cve.upper() for cve in cve_ids})

                    findings.append(
                        Finding(
                            title=f"{name} ({template_id})",
                            severity=severity,
                            description=desc or f"Nuclei template {template_id} matched",
                            evidence=matched_at,
                            remediation=info.get("remediation", ""),
                            cve_ids=cve_ids,
                            affected_asset=obj.get("host", matched_at),
                        )
                    )
        except Exception:
            pass

        parsed["matched_count"] = len(findings)
        success = complete and return_code == 0
        if not complete or not success:
            success = bool(findings)

        target_extracted = ""
        if parsed.get("results"):
            target_extracted = parsed["results"][0].get("host", "") or parsed["results"][0].get("matched-at", "")

        parsed_data = {
            "tool": self.name,
            "target": target_extracted,
            "findings": [f.model_dump() for f in findings],
            "metadata": parsed,
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


TOOLS = [NucleiTool()]
