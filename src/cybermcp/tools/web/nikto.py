"""Nikto — web server vulnerability scanner."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["NiktoTool"]


class NiktoInput(BaseModel):
    host: str = Field(..., description="Target host or URL")
    port: int | None = Field(None, description="Target port")
    ssl: bool = Field(False, description="Force SSL/TLS connection")
    tuning: str | None = Field(None, description="Scan tuning options (1-9,a-c)")
    plugins: str | None = Field(None, description="Plugins to run, comma-separated")
    output_format: str = Field("csv", description="Output format (csv/txt/html/xml)")


class NiktoTool(BaseTool):
    name = "nikto"
    description = "Web server scanner for dangerous files, outdated software, and vulnerabilities"
    category = ToolCategory.WEB
    binary_name = "nikto"
    tags = ["webserver", "scanner", "vulnerability", "web"]
    input_model = NiktoInput

    def build_command(self, input_model: NiktoInput) -> list[str]:
        cmd = [self.get_binary_path(), "-h", input_model.host, "-ask", "no"]

        if input_model.port is not None:
            cmd.extend(["-p", str(input_model.port)])
        if input_model.ssl:
            cmd.append("-ssl")
        if input_model.tuning:
            cmd.extend(["-Tuning", input_model.tuning])
        if input_model.plugins:
            cmd.extend(["-Plugins", input_model.plugins])
        if input_model.output_format:
            cmd.extend(["-Format", input_model.output_format])

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "vulnerabilities": [],
            "server_info": {},
            "statistics": {},
        }

        # Extract server info
        server_match = re.search(r"\+\s+Server:\s+(.+)", stdout)
        if server_match:
            parsed["server_info"]["server"] = server_match.group(1).strip()

        target_match = re.search(r"\+\s+Target\s+IP:\s+(\S+)", stdout)
        if target_match:
            parsed["server_info"]["target_ip"] = target_match.group(1)

        hostname_match = re.search(r"\+\s+Target\s+Hostname:\s+(\S+)", stdout)
        if hostname_match:
            parsed["server_info"]["hostname"] = hostname_match.group(1)

        target_port_match = re.search(r"\+\s+Target\s+Port:\s+(\d+)", stdout)
        if target_port_match:
            parsed["server_info"]["port"] = int(target_port_match.group(1))

        # Parse vulnerability lines: + OSVDB-XXXX: /path: description
        vuln_pattern = re.compile(
            r"\+\s+(OSVDB-\d+|[A-Z]+-\d+)?:?\s*(/\S*)?\s*:\s*(.+)"
        )
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            # Skip info lines
            if any(kw in line for kw in ["Target IP:", "Target Hostname:", "Target Port:", "Server:", "Start Time:", "End Time:", "host(s) tested", "items checked"]):
                continue

            m = vuln_pattern.match(line)
            if m:
                osvdb = m.group(1) or ""
                path = m.group(2) or ""
                desc = m.group(3).strip()

                severity = Severity.INFO
                desc_lower = desc.lower()
                if any(w in desc_lower for w in ["remote code", "rce", "command execution", "backdoor"]):
                    severity = Severity.CRITICAL
                elif any(w in desc_lower for w in ["sql injection", "xss", "cross-site", "file inclusion", "traversal", "upload"]):
                    severity = Severity.HIGH
                elif any(w in desc_lower for w in ["information disclosure", "directory listing", "default", "version"]):
                    severity = Severity.MEDIUM
                elif any(w in desc_lower for w in ["cookie", "header", "missing"]):
                    severity = Severity.LOW

                vuln = {"id": osvdb, "path": path, "description": desc}
                parsed["vulnerabilities"].append(vuln)

                findings.append(
                    Finding(
                        title=f"Nikto: {desc[:80]}",
                        severity=severity,
                        description=desc,
                        evidence=f"{osvdb} {path}".strip(),
                        affected_asset=path or parsed["server_info"].get("hostname", ""),
                    )
                )

        # Statistics
        items_match = re.search(r"(\d+)\s+items?\s+checked", stdout)
        if items_match:
            parsed["statistics"]["items_checked"] = int(items_match.group(1))

        errors_match = re.search(r"(\d+)\s+error", stdout)
        if errors_match:
            parsed["statistics"]["errors"] = int(errors_match.group(1))

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr.strip() if return_code != 0 and not findings else "",
        )


TOOLS = [NiktoTool()]
