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

    docker_capable = True

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

    def _parse_xml_incremental(self, file_path: str) -> tuple[list[dict[str, Any]], list[Finding]]:
        hosts: list[dict[str, Any]] = []
        findings: list[Finding] = []
        
        try:
            context = ET.iterparse(file_path, events=("start", "end"))
        except Exception:
            return hosts, findings
            
        current_host: dict[str, Any] = {}
        current_port: dict[str, Any] = {}
        
        try:
            for event, elem in context:
                if event == "start":
                    if elem.tag == "host":
                        current_host = {
                            "ip": "",
                            "addr_type": "",
                            "state": "",
                            "hostnames": [],
                            "os_matches": [],
                            "ports": []
                        }
                    elif elem.tag == "port":
                        current_port = {
                            "port": int(elem.get("portid", 0)),
                            "protocol": elem.get("protocol", "tcp"),
                            "state": "",
                            "reason": "",
                            "service": "",
                            "product": "",
                            "version": "",
                            "extra_info": "",
                            "scripts": []
                        }
                elif event == "end":
                    if elem.tag == "address" and current_host:
                        current_host["ip"] = elem.get("addr", "")
                        current_host["addr_type"] = elem.get("addrtype", "")
                    elif elem.tag == "status" and current_host:
                        current_host["state"] = elem.get("state", "")
                    elif elem.tag == "hostname" and current_host:
                        name = elem.get("name")
                        if name:
                            current_host["hostnames"].append(name)
                    elif elem.tag == "osmatch" and current_host:
                        current_host["os_matches"].append({
                            "name": osmatch.get("name", "") if (osmatch := elem) is not None else "",
                            "accuracy": osmatch.get("accuracy", "") if (osmatch := elem) is not None else "",
                        })
                    elif elem.tag == "state" and current_port:
                        current_port["state"] = elem.get("state", "")
                        current_port["reason"] = elem.get("reason", "")
                    elif elem.tag == "service" and current_port:
                        current_port["service"] = elem.get("name", "")
                        current_port["product"] = elem.get("product", "")
                        current_port["version"] = elem.get("version", "")
                        current_port["extra_info"] = elem.get("extrainfo", "")
                    elif elem.tag == "script" and current_port:
                        current_port["scripts"].append({
                            "id": elem.get("id", ""),
                            "output": elem.get("output", "")
                        })
                    elif elem.tag == "port" and current_host and current_port:
                        current_host["ports"].append(current_port)
                        if current_port.get("state") == "open":
                            svc_name = current_port.get("service", "unknown")
                            product = current_port.get("product", "")
                            version = current_port.get("version", "")
                            desc_parts = [f"Port {current_port['port']}/{current_port['protocol']} is open"]
                            if svc_name:
                                desc_parts.append(f"running {svc_name}")
                            if product:
                                desc_parts.append(f"({product} {version})".strip())
                            findings.append(Finding(
                                title=f"Open port {current_port['port']}/{current_port['protocol']}",
                                severity=Severity.INFO,
                                description=" ".join(desc_parts),
                                evidence=f"Service: {svc_name}, Product: {product} {version}".strip(),
                                affected_asset=current_host.get("ip", ""),
                            ))
                        for sr in current_port.get("scripts", []):
                            if any(kw in sr["id"].lower() for kw in ("vuln", "exploit", "cve")):
                                cve_ids = re.findall(r"CVE-\d{4}-\d+", sr["output"])
                                findings.append(Finding(
                                    title=f"NSE {sr['id']} finding on port {current_port['port']}",
                                    severity=Severity.MEDIUM,
                                    description=sr["output"][:500],
                                    evidence=sr["output"],
                                    cve_ids=cve_ids,
                                    affected_asset=current_host.get("ip", ""),
                                ))
                        current_port = {}
                    elif elem.tag == "host":
                        hosts.append(current_host)
                        current_host = {}
                    elem.clear()
        except ET.ParseError:
            # Incremental recovery of truncated XML
            if current_host and current_host.get("ip") and current_host not in hosts:
                hosts.append(current_host)
        except Exception:
            pass
            
        return hosts, findings

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        hosts, findings = self._parse_xml_incremental(stdout_path)
        
        target_extracted = ""
        if hosts:
            target_extracted = hosts[0].get("ip", "") or (hosts[0].get("hostnames")[0] if hosts[0].get("hostnames") else "")

        success = complete and return_code == 0
        if not complete or not success:
            success = bool(findings)

        parsed_data = {
            "tool": self.name,
            "target": target_extracted,
            "findings": [f.model_dump() for f in findings],
            "metadata": {"hosts": hosts, "run_stats": {}},
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


TOOLS = [NmapTool()]
