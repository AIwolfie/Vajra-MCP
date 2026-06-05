"""Enum4linux wrapper — SMB enumeration for Windows/Samba hosts."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["Enum4LinuxTool"]


class InputModel(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    all: bool = Field(False, description="Run all enumeration (-a)")
    users: bool = Field(False, description="Enumerate users (-U)")
    shares: bool = Field(False, description="Enumerate shares (-S)")
    groups: bool = Field(False, description="Enumerate groups (-G)")
    policies: bool = Field(False, description="Enumerate password policies (-P)")
    os_info: bool = Field(False, description="Enumerate OS info (-o)")
    username: str = Field("", description="Username for authentication")
    password: str = Field("", description="Password for authentication")
    workgroup: str = Field("", description="Workgroup/domain")


class Enum4LinuxTool(BaseTool):
    name = "enum4linux"
    description = "Enum4linux — SMB/NetBIOS enumeration on Windows and Samba"
    category = ToolCategory.NETWORK
    binary_name = "enum4linux"

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path()]
        if input_model.all:
            cmd.append("-a")
        if input_model.users:
            cmd.append("-U")
        if input_model.shares:
            cmd.append("-S")
        if input_model.groups:
            cmd.append("-G")
        if input_model.policies:
            cmd.append("-P")
        if input_model.os_info:
            cmd.append("-o")
        if input_model.username:
            cmd.extend(["-u", input_model.username])
        if input_model.password:
            cmd.extend(["-p", input_model.password])
        if input_model.workgroup:
            cmd.extend(["-w", input_model.workgroup])
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "users": [],
            "shares": [],
            "groups": [],
            "os_info": {},
            "password_policy": {},
        }

        # Users
        user_pattern = re.compile(r"user:\[(\S+?)\]\s+rid:\[0x([0-9a-fA-F]+)\]")
        for m in user_pattern.finditer(stdout):
            parsed["users"].append({
                "username": m.group(1),
                "rid": int(m.group(2), 16),
            })

        # Shares
        share_pattern = re.compile(r"\\\\\S+\\(\S+)\s+(?:Mapping:\s+(\S+))?\s*(?:Listing:\s+(\S+))?")
        for m in share_pattern.finditer(stdout):
            parsed["shares"].append({
                "name": m.group(1),
                "mapping": m.group(2) or "",
                "listing": m.group(3) or "",
            })

        # Groups
        group_pattern = re.compile(r"group:\[(.+?)\]\s+rid:\[0x([0-9a-fA-F]+)\]")
        for m in group_pattern.finditer(stdout):
            parsed["groups"].append({
                "name": m.group(1),
                "rid": int(m.group(2), 16),
            })

        # OS info
        os_match = re.search(r"os info for (\S+):.*?OS=\[(.+?)\].*?Server=\[(.+?)\]", stdout, re.DOTALL)
        if os_match:
            parsed["os_info"] = {
                "host": os_match.group(1),
                "os": os_match.group(2),
                "server": os_match.group(3),
            }

        # Null session check
        if "Attempting to map shares" in stdout or len(parsed["users"]) > 0:
            null_session = "Anonymous" in stdout or "null session" in stdout.lower()
            if null_session:
                findings.append(Finding(
                    title="Null session permitted",
                    severity=Severity.MEDIUM,
                    description="SMB null session access allows unauthenticated enumeration",
                    evidence="Null session established",
                    remediation="Restrict anonymous access via RestrictAnonymous registry key",
                    affected_asset=input_model.target if hasattr(input_model, "target") else "",
                ))

        if parsed["users"]:
            findings.append(Finding(
                title=f"Enumerated {len(parsed['users'])} user(s)",
                severity=Severity.INFO,
                description=f"Users found: {', '.join(u['username'] for u in parsed['users'][:10])}",
                evidence=f"{len(parsed['users'])} users enumerated via SMB",
            ))

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 else "",
        )
