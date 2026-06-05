"""Nmap network scanner tool wrapper."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["NmapTool"]


class ScanType(str, Enum):
    SYN = "syn"
    CONNECT = "connect"
    UDP = "udp"
    COMPREHENSIVE = "comprehensive"


class NmapInput(BaseModel):
    target: str = Field(..., description="Target IP, CIDR, or hostname")
    ports: str | None = Field(None, description="Port spec (e.g. '80,443' or '1-1024')")
    scan_type: ScanType = Field(ScanType.CONNECT, description="Scan type")
    scripts: list[str] = Field(default_factory=list, description="NSE scripts to run")
    timing: str = Field("T3", description="Timing template T0-T5")
    os_detection: bool = Field(False, description="Enable OS detection (-O)")
    service_detection: bool = Field(True, description="Enable service/version detection (-sV)")
    output_format: str = Field("xml", description="Output format (xml recommended)")
    extra_args: list[str] = Field(default_factory=list, description="Additional nmap args")


class NmapTool(BaseTool):
    name = "nmap"
    description = "Network exploration and security auditing via Nmap"
    category = ToolCategory.RECON
    binary_name = "nmap"
    tags = ["port-scan", "service-detection", "network", "recon"]
    input_model = NmapInput

    _scan_type_flags: dict[ScanType, list[str]] = {
        ScanType.SYN: ["-sS"],
        ScanType.CONNECT: ["-sT"],
        ScanType.UDP: ["-sU"],
        ScanType.COMPREHENSIVE: ["-sS", "-sU", "-sV", "-O", "--script=default,vuln"],
    }

    def build_command(self, input_model: NmapInput) -> list[str]:  # type: ignore[override]
        cmd = [self.get_binary_path()]
        cmd.extend(self._scan_type_flags.get(input_model.scan_type, ["-sS"]))

        if input_model.service_detection and input_model.scan_type != ScanType.COMPREHENSIVE:
            cmd.append("-sV")
        if input_model.os_detection and input_model.scan_type != ScanType.COMPREHENSIVE:
            cmd.append("-O")
        if input_model.timing:
            cmd.append(f"-{input_model.timing}")
        if input_model.ports:
            cmd.extend(["-p", input_model.ports])
        for script in input_model.scripts:
            cmd.append(f"--script={script}")
        cmd.extend(["-oX", "-"])  # XML to stdout
        cmd.extend(input_model.extra_args)
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        if return_code != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stderr or stdout,
                error=f"Nmap exited with code {return_code}: {stderr.strip()}",
            )

        hosts: list[dict[str, Any]] = []
        findings: list[Finding] = []

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return ToolResult(
                tool_name=self.name,
                success=False,
                raw_output=stdout,
                error="Failed to parse nmap XML output",
            )

        for host_el in root.findall(".//host"):
            host_data: dict[str, Any] = {}
            addr_el = host_el.find("address")
            if addr_el is not None:
                host_data["ip"] = addr_el.get("addr", "")
                host_data["addr_type"] = addr_el.get("addrtype", "")

            status_el = host_el.find("status")
            if status_el is not None:
                host_data["state"] = status_el.get("state", "")

            hostnames: list[str] = []
            for hn in host_el.findall(".//hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)
            host_data["hostnames"] = hostnames

            os_matches: list[dict[str, str]] = []
            for osmatch in host_el.findall(".//osmatch"):
                os_matches.append({
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })
            host_data["os_matches"] = os_matches

            ports: list[dict[str, Any]] = []
            for port_el in host_el.findall(".//port"):
                port_info: dict[str, Any] = {
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                }
                state_el = port_el.find("state")
                if state_el is not None:
                    port_info["state"] = state_el.get("state", "")
                    port_info["reason"] = state_el.get("reason", "")

                svc_el = port_el.find("service")
                if svc_el is not None:
                    port_info["service"] = svc_el.get("name", "")
                    port_info["product"] = svc_el.get("product", "")
                    port_info["version"] = svc_el.get("version", "")
                    port_info["extra_info"] = svc_el.get("extrainfo", "")

                script_results: list[dict[str, str]] = []
                for script_el in port_el.findall("script"):
                    script_results.append({
                        "id": script_el.get("id", ""),
                        "output": script_el.get("output", ""),
                    })
                port_info["scripts"] = script_results
                ports.append(port_info)

                if port_info.get("state") == "open":
                    svc_name = port_info.get("service", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    desc_parts = [f"Port {port_info['port']}/{port_info['protocol']} is open"]
                    if svc_name:
                        desc_parts.append(f"running {svc_name}")
                    if product:
                        desc_parts.append(f"({product} {version})".strip())
                    findings.append(Finding(
                        title=f"Open port {port_info['port']}/{port_info['protocol']}",
                        severity=Severity.INFO,
                        description=" ".join(desc_parts),
                        evidence=f"Service: {svc_name}, Product: {product} {version}".strip(),
                        affected_asset=host_data.get("ip", ""),
                    ))

                for sr in script_results:
                    if any(kw in sr["id"].lower() for kw in ("vuln", "exploit", "cve")):
                        cve_ids = re.findall(r"CVE-\d{4}-\d+", sr["output"])
                        findings.append(Finding(
                            title=f"NSE {sr['id']} finding on port {port_info['port']}",
                            severity=Severity.MEDIUM,
                            description=sr["output"][:500],
                            evidence=sr["output"],
                            cve_ids=cve_ids,
                            affected_asset=host_data.get("ip", ""),
                        ))

            host_data["ports"] = ports
            hosts.append(host_data)

        run_stats = {}
        stats_el = root.find(".//runstats/finished")
        if stats_el is not None:
            run_stats["elapsed"] = stats_el.get("elapsed", "")
            run_stats["exit"] = stats_el.get("exit", "")
        hosts_stat = root.find(".//runstats/hosts")
        if hosts_stat is not None:
            run_stats["hosts_up"] = hosts_stat.get("up", "0")
            run_stats["hosts_down"] = hosts_stat.get("down", "0")
            run_stats["hosts_total"] = hosts_stat.get("total", "0")

        target_extracted = ""
        if hosts:
            target_extracted = hosts[0].get("ip", "") or (hosts[0].get("hostnames")[0] if hosts[0].get("hostnames") else "")

        return ToolResult(
            tool_name=self.name,
            success=True,
            raw_output=stdout,
            parsed_data={
                "tool": self.name,
                "target": target_extracted,
                "findings": [f.model_dump() for f in findings],
                "metadata": {"hosts": hosts, "run_stats": run_stats},
                "raw_file": "",
            },
            findings=findings,
        )


TOOLS = [NmapTool()]
