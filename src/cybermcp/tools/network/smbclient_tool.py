"""SMBClient wrapper — interactive/scripted SMB share access."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["SmbClientTool"]


class InputModel(BaseModel):
    target: str = Field(..., description="Target host IP or hostname")
    share: str = Field("", description="Share name to connect to")
    username: str = Field("", description="Username")
    password: str = Field("", description="Password")
    domain: str = Field("", description="Domain/workgroup")
    command: str = Field("", description="SMB command to execute (ls, get, put, etc.)")
    no_pass: bool = Field(False, description="Null session / no password")
    port: int = Field(445, description="SMB port")
    list_shares: bool = Field(False, description="List available shares (-L)")


class SmbClientTool(BaseTool):
    name = "smbclient"
    description = "smbclient — SMB/CIFS share browsing and file transfer"
    category = ToolCategory.NETWORK
    binary_name = "smbclient"

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path()]
        if input_model.list_shares:
            cmd.extend(["-L", input_model.target])
        elif input_model.share:
            cmd.append(f"//{input_model.target}/{input_model.share}")
        else:
            cmd.extend(["-L", input_model.target])

        if input_model.username:
            cmd.extend(["-U", input_model.username])
        if input_model.password and not input_model.no_pass:
            cmd.extend(["-p", input_model.password])
        if input_model.domain:
            cmd.extend(["-W", input_model.domain])
        if input_model.no_pass:
            cmd.append("-N")
        if input_model.port != 445:
            cmd.extend(["-p", str(input_model.port)])
        if input_model.command:
            cmd.extend(["-c", input_model.command])
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "shares": [],
            "files": [],
            "directories": [],
        }

        # Parse share listing
        share_pattern = re.compile(r"^\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)", re.MULTILINE)
        for m in share_pattern.finditer(stdout):
            parsed["shares"].append({
                "name": m.group(1),
                "type": m.group(2),
                "comment": m.group(3).strip(),
            })

        # Parse directory listing
        file_pattern = re.compile(
            r"^\s+(\S.*?)\s+([ADHNRS]+)\s+(\d+)\s+\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4}",
            re.MULTILINE,
        )
        for m in file_pattern.finditer(stdout):
            name = m.group(1).strip()
            attrs = m.group(2)
            size = int(m.group(3))
            entry = {"name": name, "attributes": attrs, "size": size}
            if "D" in attrs:
                parsed["directories"].append(entry)
            else:
                parsed["files"].append(entry)

        if parsed["shares"]:
            findings.append(Finding(
                title=f"Found {len(parsed['shares'])} SMB share(s)",
                severity=Severity.INFO,
                description=f"Shares: {', '.join(s['name'] for s in parsed['shares'])}",
                evidence=f"{len(parsed['shares'])} shares enumerated",
            ))

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 else "",
        )
