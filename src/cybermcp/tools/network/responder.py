"""Responder wrapper — LLMNR/NBT-NS/MDNS poisoner and credential capture."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["ResponderTool"]


class InputModel(BaseModel):
    interface: str = Field(..., description="Network interface to listen on")
    analyze: bool = Field(False, description="Analyze mode — passive, no poisoning")
    wpad: bool = Field(False, description="Enable WPAD rogue proxy")
    fingerprint: bool = Field(False, description="Fingerprint hosts")
    verbose: bool = Field(False, description="Verbose output")


class ResponderTool(BaseTool):
    name = "responder"
    description = "Responder — LLMNR/NBT-NS/MDNS poisoner for credential harvesting"
    category = ToolCategory.NETWORK
    binary_name = "responder"

    def build_command(self, input_model: InputModel) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path(), "-I", input_model.interface]
        if input_model.analyze:
            cmd.append("-A")
        if input_model.wpad:
            cmd.append("-w")
        if input_model.fingerprint:
            cmd.append("-f")
        if input_model.verbose:
            cmd.append("-v")
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "captured_hashes": [],
            "poisoned_requests": [],
        }

        hash_pattern = re.compile(
            r"\[(?P<proto>\S+)\]\s+NTLMv[12]-(?:SSP\s+)?Hash\s*:\s*(?P<hash>.+)"
        )
        poison_pattern = re.compile(
            r"\[\*\]\s+\[(?P<proto>\S+)\]\s+Poisoned answer sent to\s+(?P<target>\S+)"
        )

        for line in stdout.splitlines():
            stripped = line.strip()

            hm = hash_pattern.search(stripped)
            if hm:
                entry = {
                    "protocol": hm.group("proto"),
                    "hash": hm.group("hash").strip(),
                }
                parsed["captured_hashes"].append(entry)
                findings.append(Finding(
                    title=f"NTLMv2 hash captured via {entry['protocol']}",
                    severity=Severity.HIGH,
                    description=f"Credential hash captured: {entry['hash'][:60]}...",
                    evidence=stripped,
                    remediation="Disable LLMNR and NBT-NS via GPO",
                ))

            pm = poison_pattern.search(stripped)
            if pm:
                parsed["poisoned_requests"].append({
                    "protocol": pm.group("proto"),
                    "target": pm.group("target"),
                })

        return ToolResult(
            tool_name=self.name,
            success=return_code == 0 or len(parsed["captured_hashes"]) > 0,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=stderr if return_code != 0 else "",
        )
