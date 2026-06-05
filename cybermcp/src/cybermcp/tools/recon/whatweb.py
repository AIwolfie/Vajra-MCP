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
        results: list[dict[str, Any]] = []
        technologies: list[str] = []
        plugins: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
                for key in obj.get("plugins", {}).keys():
                    if key not in plugins:
                        plugins.append(key)
                        technologies.append(key)
            except json.JSONDecodeError:
                matches = re.findall(r"\[([^\]]+)\]", line)
                for m in matches:
                    if m and m not in technologies:
                        technologies.append(m)

        success = return_code == 0 or bool(results) or bool(technologies)
        error = stderr.strip() if return_code != 0 and not technologies else ""
        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data={
                "results": results,
                "technologies": technologies,
                "plugins": plugins,
            },
            error=error,
        )


TOOLS = [WhatWebTool()]
