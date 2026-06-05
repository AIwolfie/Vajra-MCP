"""Impacket tools wrapper — smbclient.py, psexec.py, wmiexec.py, secretsdump.py, etc."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["ImpacketTool"]


class InputModel(BaseModel):
    tool: str = Field(
        ...,
        description="Impacket script name: smbclient.py, psexec.py, wmiexec.py, secretsdump.py, "
        "smbexec.py, atexec.py, dcomexec.py, getTGT.py, getST.py, GetNPUsers.py, GetUserSPNs.py",
    )
    target: str = Field(..., description="Target host or IP")
    username: str = Field("", description="Username")
    password: str = Field("", description="Password")
    domain: str = Field("", description="Domain name")
    hash: str = Field("", description="NTLM hash (LM:NT format)")
    command: str = Field("", description="Command to execute (psexec/wmiexec/smbexec)")
    share: str = Field("", description="SMB share to connect to")
    output_file: str = Field("", description="Output file path")
    kerberos: bool = Field(False, description="Use Kerberos authentication")
    dc_ip: str = Field("", description="Domain controller IP")
    extra_args: list[str] = Field(default_factory=list, description="Additional arguments")


class ImpacketTool(BaseTool):
    name = "impacket"
    description = "Impacket suite — SMB, WMI, DCOM, Kerberos, secretsdump, and remote execution"
    category = ToolCategory.NETWORK
    binary_name = "python"

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path(), "-m"]

        # Map script name to module path
        tool_map: dict[str, str] = {
            "smbclient.py": "impacket.examples.smbclient",
            "psexec.py": "impacket.examples.psexec",
            "wmiexec.py": "impacket.examples.wmiexec",
            "smbexec.py": "impacket.examples.smbexec",
            "atexec.py": "impacket.examples.atexec",
            "dcomexec.py": "impacket.examples.dcomexec",
            "secretsdump.py": "impacket.examples.secretsdump",
            "getTGT.py": "impacket.examples.getTGT",
            "getST.py": "impacket.examples.getST",
            "GetNPUsers.py": "impacket.examples.GetNPUsers",
            "GetUserSPNs.py": "impacket.examples.GetUserSPNs",
        }
        module = tool_map.get(input_model.tool, f"impacket.examples.{input_model.tool.replace('.py', '')}")
        cmd.append(module)

        # Build authentication string: domain/user:pass@target
        auth_parts: list[str] = []
        if input_model.domain:
            auth_parts.append(f"{input_model.domain}/")
        if input_model.username:
            auth_parts.append(input_model.username)
        if input_model.password:
            auth_parts.append(f":{input_model.password}")
        auth_parts.append(f"@{input_model.target}")
        cmd.append("".join(auth_parts))

        if input_model.hash:
            cmd.extend(["-hashes", input_model.hash])
        if input_model.kerberos:
            cmd.append("-k")
        if input_model.dc_ip:
            cmd.extend(["-dc-ip", input_model.dc_ip])
        if input_model.command:
            cmd.append(input_model.command)
        if input_model.share:
            cmd.extend(["-share", input_model.share])
        if input_model.output_file:
            cmd.extend(["-outputfile", input_model.output_file])
        cmd.extend(input_model.extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "credentials": [],
            "command_output": [],
            "shares": [],
            "tickets": [],
        }
        combined = stdout + "\n" + stderr

        # secretsdump output: user:rid:lmhash:nthash:::
        hash_pattern = re.compile(r"^(\S+?):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::", re.MULTILINE)
        for m in hash_pattern.finditer(combined):
            cred = {
                "username": m.group(1),
                "lm_hash": m.group(2),
                "nt_hash": m.group(3),
            }
            parsed["credentials"].append(cred)
            findings.append(Finding(
                title=f"Credential hash dumped for {cred['username']}",
                severity=Severity.CRITICAL,
                description=f"NTLM hash extracted: {cred['nt_hash']}",
                evidence=m.group(0),
                remediation="Rotate compromised credentials immediately",
            ))

        # Kerberos tickets
        tgt_pattern = re.compile(r"Saving ticket in (.+\.ccache)")
        for m in tgt_pattern.finditer(combined):
            parsed["tickets"].append(m.group(1))

        # Command output from exec tools
        if "C:\\" in combined or "$ " in combined:
            for line in combined.splitlines():
                if line.strip() and not line.startswith("["):
                    parsed["command_output"].append(line.strip())

        # Kerberoast / AS-REP roast results
        spn_pattern = re.compile(r"\$krb5tgs\$\d+\$\*.*?\$[a-fA-F0-9]+")
        for m in spn_pattern.finditer(combined):
            findings.append(Finding(
                title="Kerberoastable hash captured",
                severity=Severity.HIGH,
                description="TGS hash captured — offline crackable",
                evidence=m.group(0)[:100] + "...",
            ))

        asrep_pattern = re.compile(r"\$krb5asrep\$\d+\$.*?\$[a-fA-F0-9]+")
        for m in asrep_pattern.finditer(combined):
            findings.append(Finding(
                title="AS-REP roastable hash captured",
                severity=Severity.HIGH,
                description="AS-REP hash — user has no pre-auth",
                evidence=m.group(0)[:100] + "...",
            ))

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0 or len(findings) > 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 and not findings else "",
        )
