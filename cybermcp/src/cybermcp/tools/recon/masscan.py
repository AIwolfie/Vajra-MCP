"""Masscan high-speed port scanner tool wrapper."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["MasscanTool"]


class MasscanInput(BaseModel):
    target: str = Field(..., description="Target IP/CIDR range")
    ports: str = Field("1-65535", description="Port range (e.g. '0-65535', '80,443')")
    rate: int = Field(1000, description="Packets per second")
    interface: str | None = Field(None, description="Network interface to use")
    banners: bool = Field(False, description="Grab banners from discovered services")
    extra_args: list[str] = Field(default_factory=list, description="Additional masscan args")


class MasscanTool(BaseTool):
    name = "masscan"
    description = "High-speed TCP port scanner (masscan)"
    category = ToolCategory.RECON
    binary_name = "masscan"
    tags = ["port-scan", "fast-scan", "network", "recon"]
    input_model = MasscanInput

    def build_command(self, input_model: MasscanInput) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path()]
        cmd.append(input_model.target)
        cmd.extend(["-p", input_model.ports])
        cmd.extend(["--rate", str(input_model.rate)])
        if input_model.interface:
            cmd.extend(["-e", input_model.interface])
        if input_model.banners:
            cmd.append("--banners")
        cmd.extend(["-oJ", "-"])  # JSON to stdout
        cmd.extend(input_model.extra_args)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        if return_code != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stderr or stdout,
                error=f"Masscan exited with code {return_code}: {stderr.strip()}",
            )

        findings: list[Finding] = []
        hosts: dict[str, list[dict[str, Any]]] = {}

        clean = stdout.strip()
        if clean.startswith("{") or clean.startswith("["):
            try:
                records = json.loads(clean)
            except json.JSONDecodeError:
                lines = [l.strip().rstrip(",") for l in clean.splitlines() if l.strip().startswith("{")]
                records = []
                for line in lines:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            records = []
            for line in clean.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for rec in records:
            ip = rec.get("ip", "")
            ports_data = rec.get("ports", [])
            if ip not in hosts:
                hosts[ip] = []
            for p in ports_data:
                port_info = {
                    "port": p.get("port"),
                    "protocol": p.get("proto", "tcp"),
                    "status": p.get("status", "open"),
                    "service": p.get("service", {}).get("name", "") if isinstance(p.get("service"), dict) else "",
                    "banner": p.get("service", {}).get("banner", "") if isinstance(p.get("service"), dict) else "",
                }
                hosts[ip].append(port_info)

                findings.append(Finding(
                    title=f"Open port {port_info['port']}/{port_info['protocol']} on {ip}",
                    severity=Severity.INFO,
                    description=f"Port {port_info['port']}/{port_info['protocol']} detected open",
                    evidence=f"Banner: {port_info['banner']}" if port_info["banner"] else "",
                    affected_asset=ip,
                ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=stdout,
            parsed_data={"hosts": hosts, "total_open_ports": len(findings)},
            findings=findings,
        )


TOOLS = [MasscanTool()]
