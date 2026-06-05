"""Metasploit Framework wrapper — module execution via resource-file approach."""

from __future__ import annotations

import re
import tempfile
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["MetasploitTool"]


class InputModel(BaseModel):
    module: str = Field(..., description="Metasploit module path, e.g. exploit/multi/handler")
    rhosts: str = Field("", description="Target host(s)")
    rport: int | None = Field(None, description="Target port")
    payload: str = Field("", description="Payload to use, e.g. windows/meterpreter/reverse_tcp")
    options: dict[str, str] = Field(default_factory=dict, description="Additional module options as key=value")
    lhost: str = Field("", description="Local host for reverse connections")
    lport: int | None = Field(None, description="Local port for reverse connections")
    timeout: int = Field(300, description="Execution timeout in seconds")


class MetasploitTool(BaseTool):
    name = "metasploit"
    description = "Metasploit Framework — exploit execution, payload delivery, and post-exploitation"
    category = ToolCategory.NETWORK
    binary_name = "msfconsole"

    def _build_resource_script(self, inp: InputModel) -> str:
        lines: list[str] = []
        lines.append(f"use {inp.module}")
        if inp.rhosts:
            lines.append(f"set RHOSTS {inp.rhosts}")
        if inp.rport is not None:
            lines.append(f"set RPORT {inp.rport}")
        if inp.payload:
            lines.append(f"set PAYLOAD {inp.payload}")
        if inp.lhost:
            lines.append(f"set LHOST {inp.lhost}")
        if inp.lport is not None:
            lines.append(f"set LPORT {inp.lport}")
        for key, val in inp.options.items():
            lines.append(f"set {key} {val}")
        lines.append("run")
        lines.append("exit")
        return "\n".join(lines)

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        script_content = self._build_resource_script(input_model)
        rc_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", prefix="msf_", delete=False
        )
        rc_file.write(script_content)
        rc_file.close()
        return [
            self.get_binary_path(),
            "-q",
            "-r", rc_file.name,
        ]

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "sessions": [],
            "vulnerabilities": [],
            "raw_lines": [],
        }

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parsed["raw_lines"].append(stripped)

            # Detect opened sessions
            session_match = re.search(
                r"(?:Meterpreter|Command shell) session (\d+) opened.*?(\S+:\d+ -> \S+:\d+)",
                stripped,
            )
            if session_match:
                parsed["sessions"].append({
                    "id": int(session_match.group(1)),
                    "connection": session_match.group(2),
                })
                findings.append(Finding(
                    title=f"Session {session_match.group(1)} opened",
                    severity=Severity.CRITICAL,
                    description=f"Exploit succeeded — session via {session_match.group(2)}",
                    evidence=stripped,
                ))

            # Detect vulnerable hosts
            vuln_match = re.search(r"\[\+\].*(?:vulnerable|exploited|success)", stripped, re.IGNORECASE)
            if vuln_match:
                parsed["vulnerabilities"].append(stripped)
                findings.append(Finding(
                    title="Vulnerability confirmed",
                    severity=Severity.HIGH,
                    description=stripped,
                    evidence=stripped,
                ))

        success = return_code == 0 or len(parsed["sessions"]) > 0
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 and not parsed["sessions"] else "",
        )
