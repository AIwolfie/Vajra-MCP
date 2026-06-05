"""CrackMapExec wrapper — network protocol attack and enumeration swiss-army knife."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["CrackMapExecTool"]


class InputModel(BaseModel):
    protocol: str = Field("smb", description="Protocol: smb, ssh, winrm, ldap, mssql")
    target: str = Field(..., description="Target host, range, or CIDR")
    username: str = Field("", description="Username for authentication")
    password: str = Field("", description="Password for authentication")
    hash: str = Field("", description="NTLM hash for pass-the-hash")
    domain: str = Field("", description="Domain name")
    module: str = Field("", description="CME module to execute")
    module_options: dict[str, str] = Field(default_factory=dict, description="Module options")
    command: str = Field("", description="Command to execute on target")
    shares: bool = Field(False, description="Enumerate shares")
    sessions: bool = Field(False, description="Enumerate active sessions")
    users: bool = Field(False, description="Enumerate users")
    groups: bool = Field(False, description="Enumerate groups")
    local_auth: bool = Field(False, description="Use local authentication")


class CrackMapExecTool(BaseTool):
    name = "crackmapexec"
    description = "CrackMapExec — SMB/SSH/WinRM/LDAP/MSSQL attack and enumeration"
    category = ToolCategory.NETWORK
    binary_name = "crackmapexec"

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path(), input_model.protocol, input_model.target]
        if input_model.username:
            cmd.extend(["-u", input_model.username])
        if input_model.password:
            cmd.extend(["-p", input_model.password])
        if input_model.hash:
            cmd.extend(["-H", input_model.hash])
        if input_model.domain:
            cmd.extend(["-d", input_model.domain])
        if input_model.local_auth:
            cmd.append("--local-auth")
        if input_model.module:
            cmd.extend(["-M", input_model.module])
            for k, v in input_model.module_options.items():
                cmd.extend(["-o", f"{k}={v}"])
        if input_model.command:
            cmd.extend(["-x", input_model.command])
        if input_model.shares:
            cmd.append("--shares")
        if input_model.sessions:
            cmd.append("--sessions")
        if input_model.users:
            cmd.append("--users")
        if input_model.groups:
            cmd.append("--groups")
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "hosts": [],
            "credentials": [],
            "shares": [],
            "command_output": [],
        }

        pwned_pattern = re.compile(r"(\S+)\s+.*\(Pwn3d!\)")
        cred_pattern = re.compile(
            r"(\S+)\s+\d+\s+\S+\s+\[.\]\s+(?:.*\\)?(\S+):(\S+)"
        )
        share_pattern = re.compile(
            r"\s+(\S+)\s+(READ|WRITE|READ,WRITE|NO ACCESS)\s+(.*)"
        )

        for line in stdout.splitlines():
            stripped = line.strip()

            pm = pwned_pattern.search(stripped)
            if pm:
                host = pm.group(1)
                parsed["hosts"].append({"host": host, "pwned": True})
                findings.append(Finding(
                    title=f"Admin access confirmed on {host}",
                    severity=Severity.CRITICAL,
                    description=f"Pwn3d! — full admin access on {host}",
                    evidence=stripped,
                    affected_asset=host,
                ))

            if "[+]" in stripped and ":" in stripped:
                cm = cred_pattern.search(stripped)
                if cm:
                    parsed["credentials"].append({
                        "host": cm.group(1),
                        "username": cm.group(2),
                        "credential": cm.group(3),
                    })
                    findings.append(Finding(
                        title=f"Valid credentials for {cm.group(2)}",
                        severity=Severity.HIGH,
                        description=f"Authenticated as {cm.group(2)} on {cm.group(1)}",
                        evidence=stripped,
                        affected_asset=cm.group(1),
                    ))

            sm = share_pattern.search(stripped)
            if sm:
                parsed["shares"].append({
                    "name": sm.group(1),
                    "access": sm.group(2),
                    "remark": sm.group(3).strip(),
                })

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 else "",
        )
