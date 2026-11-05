"""Tool health diagnostics system for Vajra MCP priority tools."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from cybermcp.config import get_config
from cybermcp.tools.registry import ToolRegistry

__all__ = ["health_check", "diagnostics"]

_INSTALL_COMMANDS = {
    "nmap": "sudo apt install nmap | brew install nmap",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@latest",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "wafw00f": "pip install wafw00f",
    "whatweb": "sudo apt install whatweb | brew install whatweb",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
    "feroxbuster": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "pip install sqlmap",
    "wpscan": "gem install wpscan",
    "testssl": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git",
}

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

_VERSION_SPECS = {
    "nmap": (["--version"], r"Nmap\s+version\s+([0-9.]+)"),
    "subfinder": (["-version"], r"(?:version\s*[:v]?\s*|\bv?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    "amass": (["-version"], r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b"),
    "assetfinder": (["--version"], r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b"),
    "httpx": (["-version"], r"(?:version\s*[:v]?\s*|\bv?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    "katana": (["-version"], r"(?:version\s*[:v]?\s*|\bv?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    "wafw00f": (["--version"], r"WAFW00F\s*(?:version)?\s*v?([0-9.]+)"),
    "whatweb": (["--version"], r"WhatWeb\s*(?:version)?\s*v?([0-9.]+)"),
    "nuclei": (["-version"], r"(?:version\s*[:v]?\s*|\bv?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    "ffuf": (["-V"], r"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-\S+)?)"),
    "feroxbuster": (["-V"], r"feroxbuster\s+v?([0-9.]+)"),
    "dalfox": (["version"], r"dalfox\s+v?([0-9.]+)"),
    "sqlmap": (["--version"], r"([0-9.]+#\S+|[0-9.]+)"),
    "wpscan": (["--version"], r"Version\s+([0-9.]+)"),
    "testssl": (["--version"], r"testssl\.sh\s+v?(\S+)"),
}


async def _detect_version(binary_path: str, tool_name: str) -> str:
    """Execute version flag command and extract version via regex."""
    spec = _VERSION_SPECS.get(tool_name)
    if not spec:
        return "unknown"

    args, pattern = spec
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=3.0)
        output = (stdout_bytes + stderr_bytes).decode("utf-8", errors="replace")
        clean_output = _ANSI_ESCAPE_RE.sub("", output)

        match = re.search(pattern, clean_output, re.IGNORECASE)
        if match:
            v = match.group(1).strip()
            if re.search(r"\d", v) and v != ".":
                return v
    except Exception:
        pass
    return "unknown"


async def health_check(tool_name: str) -> dict[str, Any]:
    """Check availability, version, path, and API keys for a specific tool."""
    tool_name = tool_name.strip().lower()
    registry = ToolRegistry()
    # Discover if not loaded
    if registry.tool_count == 0:
        registry.auto_discover()

    tool = registry.get(tool_name)
    if not tool:
        return {
            "tool": tool_name,
            "installed": False,
            "version": "unknown",
            "path": "",
            "api_keys": {},
            "install_command": _INSTALL_COMMANDS.get(tool_name, ""),
        }

    path = tool.get_binary_path()
    installed = tool.is_available()
    version = "unknown"

    if installed and path:
        version = await _detect_version(path, tool_name)

    # API Keys status
    cfg = get_config()
    api_keys = {}
    if tool_name in ("subfinder", "amass"):
        api_keys = {
            "shodan_api_key": bool(cfg.shodan_api_key),
            "virustotal_api_key": bool(cfg.virustotal_api_key),
            "censys_api_id": bool(cfg.censys_api_id),
        }
    elif tool_name == "wpscan":
        wpscan_token = bool(
            getattr(cfg, "wpscan_api_token", None)
            or Path("~/.wpscan/config.yml").expanduser().exists()
        )
        api_keys = {
            "wpscan_api_token": wpscan_token,
        }

    return {
        "tool": tool_name,
        "installed": installed,
        "version": version,
        "path": path or "",
        "api_keys": api_keys,
        "install_command": _INSTALL_COMMANDS.get(tool_name, ""),
    }


async def diagnostics() -> list[dict[str, Any]]:
    """Run diagnostics checks for all priority tools."""
    priority_tools = [
        "subfinder",
        "amass",
        "assetfinder",
        "httpx",
        "katana",
        "nmap",
        "whatweb",
        "wafw00f",
        "nuclei",
        "ffuf",
        "feroxbuster",
        "dalfox",
        "sqlmap",
        "wpscan",
        "testssl",
    ]
    tasks = [health_check(name) for name in priority_tools]
    return await asyncio.gather(*tasks)
