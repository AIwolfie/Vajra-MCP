"""WhatWeb — web technology fingerprinting tool wrapper."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult

__all__ = ["WhatWebTool"]


class WhatWebInput(BaseModel):
    target: str = Field(..., description="Target URL or host")
    aggressive: bool = Field(False, description="Use aggressive mode (-a 3)")


class WhatWebTool(BaseTool):
    name = "whatweb"
    description = "Web technology fingerprinting"
    category = ToolCategory.RECON
    binary_name = "whatweb"
    tags = ["fingerprint", "web", "recon"]
    input_model = WhatWebInput

    def build_command(self, input_model: WhatWebInput) -> list[str]:
        cmd = [self.get_binary_path(), "--no-errors", "--color=never", "--log-json", "-"]
        if input_model.aggressive:
            cmd.extend(["-a", "3"])
        cmd.append(input_model.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        from cybermcp.tools.base import Finding, Severity

        results: list[dict[str, Any]] = []
        technologies: list[str] = []
        plugins: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, list):
                    for item in obj:
                        if isinstance(item, dict):
                            results.append(item)
                            plugins_val = item.get("plugins", {})
                            if isinstance(plugins_val, dict):
                                for key in plugins_val.keys():
                                    if key not in plugins:
                                        plugins.append(key)
                                        technologies.append(key)
                elif isinstance(obj, dict):
                    results.append(obj)
                    plugins_val = obj.get("plugins", {})
                    if isinstance(plugins_val, dict):
                        for key in plugins_val.keys():
                            if key not in plugins:
                                plugins.append(key)
                                technologies.append(key)
            except json.JSONDecodeError:
                matches = re.findall(r"\[([^\]]+)\]", line)
                for m in matches:
                    if m and m not in technologies:
                        technologies.append(m)

        findings: list[Finding] = []
        target_extracted = ""
        if results:
            target_extracted = results[0].get("target", "")
            for res in results:
                target = res.get("target", "")
                plugins_found = res.get("plugins", {})
                for p_name, p_data in plugins_found.items():
                    version = p_data.get("version", "") or ""
                    if isinstance(version, list):
                        version = ", ".join(map(str, version))
                    os_str = p_data.get("os", "") or ""
                    if isinstance(os_str, list):
                        os_str = ", ".join(map(str, os_str))
                    desc_parts = [f"WhatWeb fingerprint discovered technology '{p_name}'"]
                    if version:
                        desc_parts.append(f"version {version}")
                    if os_str:
                        desc_parts.append(f"on OS: {os_str}")
                    
                    findings.append(Finding(
                        title=f"Discovered Tech: {p_name}",
                        severity=Severity.INFO,
                        description=" ".join(desc_parts),
                        evidence=json.dumps(p_data, default=str),
                        affected_asset=target,
                        tool_name=self.name,
                    ))

        success = return_code == 0 or bool(results) or bool(technologies)
        error = stderr.strip() if return_code != 0 and not technologies else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={
                "tool": self.name,
                "target": target_extracted,
                "findings": [f.model_dump() for f in findings],
                "metadata": {
                    "results": results,
                    "technologies": technologies,
                    "plugins": plugins,
                },
                "raw_file": "",
            },
            findings=findings,
            error=error,
        )


TOOLS = [WhatWebTool()]
