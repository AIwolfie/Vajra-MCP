"""Burp Suite REST API integration — scan management via Burp's HTTP API."""

from __future__ import annotations

import json
import time
from typing import Any

import aiohttp
from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["BurpApiTool"]

_SEVERITY_MAP: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "information": Severity.INFO,
}


class BurpApiInput(BaseModel):
    target_url: str = Field(..., description="URL to scan")
    api_url: str = Field("http://127.0.0.1:1337", description="Burp REST API base URL")
    api_key: str = Field(..., description="Burp REST API key")
    scan_type: str = Field("active", description="Scan type: active, passive, or crawl")


class BurpApiTool(BaseTool):
    name = "burp_api"
    description = "Burp Suite Professional REST API integration for web vulnerability scanning"
    category = ToolCategory.WEB
    binary_name = ""
    tags = ["burp", "proxy", "scanner", "web", "api"]

    def build_command(self, input_model: BurpApiInput) -> list[str]:
        # Not a CLI tool — API-based interaction
        return []

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        # Parsing handled in run() override
        return ToolResult(tool_name=self.name, success=False, error="Use run() for API interaction")

    async def run(self, input_model: BurpApiInput, timeout: float = 600.0) -> ToolResult:
        """Interact with Burp REST API to launch and retrieve scan results."""
        start = time.monotonic()
        base = input_model.api_url.rstrip("/")
        api_key = input_model.api_key
        findings: list[Finding] = []
        parsed: dict[str, Any] = {"scan_id": None, "status": "", "issues": []}

        try:
            async with aiohttp.ClientSession() as session:
                # Launch scan
                scan_config: dict[str, Any] = {
                    "urls": [input_model.target_url],
                }
                if input_model.scan_type == "crawl":
                    scan_config["scan_configurations"] = [{"name": "Crawl only", "type": "NamedConfiguration"}]
                elif input_model.scan_type == "passive":
                    scan_config["scan_configurations"] = [{"name": "Crawl and audit - passive", "type": "NamedConfiguration"}]
                else:
                    scan_config["scan_configurations"] = [{"name": "Crawl and audit - balanced", "type": "NamedConfiguration"}]

                headers = {"Content-Type": "application/json"}
                launch_url = f"{base}/{api_key}/v0.1/scan"

                async with session.post(launch_url, json=scan_config, headers=headers) as resp:
                    if resp.status not in (200, 201):
                        body = await resp.text()
                        return ToolResult(
                            tool_name=self.name,
                            success=False,
                            error=f"Failed to launch scan: HTTP {resp.status} — {body}",
                            execution_time=time.monotonic() - start,
                        )
                    location = resp.headers.get("Location", "")
                    scan_id = location.rsplit("/", 1)[-1] if location else ""
                    if not scan_id:
                        body = await resp.text()
                        try:
                            scan_id = str(json.loads(body).get("task_id", ""))
                        except (json.JSONDecodeError, AttributeError):
                            scan_id = body.strip()
                    parsed["scan_id"] = scan_id

                # Poll scan status
                status_url = f"{base}/{api_key}/v0.1/scan/{scan_id}"
                deadline = start + timeout
                while time.monotonic() < deadline:
                    async with session.get(status_url) as resp:
                        if resp.status != 200:
                            break
                        data = await resp.json()
                        status = data.get("scan_status", "")
                        parsed["status"] = status
                        if status in ("succeeded", "failed", "finished"):
                            break
                    await __import__("asyncio").sleep(5)

                # Retrieve issues
                async with session.get(status_url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        issues = data.get("issue_events", [])
                        for ie in issues:
                            issue = ie.get("issue", ie)
                            sev = _SEVERITY_MAP.get(issue.get("severity", "info").lower(), Severity.INFO)
                            name = issue.get("name", "Unknown Issue")
                            parsed["issues"].append(issue)
                            findings.append(
                                Finding(
                                    title=name,
                                    severity=sev,
                                    description=issue.get("description", ""),
                                    evidence=issue.get("evidence", ""),
                                    remediation=issue.get("remediation", ""),
                                    affected_asset=issue.get("origin", input_model.target_url),
                                )
                            )

            return ToolResult(
                tool_name=self.name,
                success=True,
                raw_output=json.dumps(parsed, indent=2),
                parsed_data=parsed,
                findings=findings,
                execution_time=time.monotonic() - start,
            )

        except aiohttp.ClientError as exc:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=f"HTTP error communicating with Burp API: {exc}",
                execution_time=time.monotonic() - start,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error=str(exc),
                execution_time=time.monotonic() - start,
            )
