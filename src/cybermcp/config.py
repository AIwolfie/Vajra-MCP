"""Vajra MCP configuration with Pydantic Settings and .env support."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class VajraMCPConfig(BaseSettings):
    """Central configuration for Vajra MCP server."""

    model_config = SettingsConfigDict(
        env_prefix="CYBERMCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    server_name: str = "Vajra MCP"
    server_version: str = "1.0.0rc1"

    transport: Literal["stdio", "sse", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = 8394

    # HTTP/SSE authentication
    http_api_key: str = ""
    allow_localhost_no_auth: bool = False

    # Storage
    db_path: str = Field(default_factory=lambda: str(_PROJECT_ROOT / "data" / "vajra-mcp.db"))
    reports_dir: str = Field(default_factory=lambda: str(_PROJECT_ROOT / "reports"))
    sessions_dir: str = Field(default_factory=lambda: str(_PROJECT_ROOT / "sessions"))

    # Hardening & Execution limits
    execution_mode: Literal["native", "docker"] = "native"
    max_memory_mb: int = 1024
    max_output_mb: int = 500
    docker_images: dict[str, str] = Field(default_factory=lambda: {
        "nmap": "instrumentisto/nmap:latest",
        "nuclei": "projectdiscovery/nuclei:latest",
        "httpx": "projectdiscovery/httpx:latest",
        "katana": "projectdiscovery/katana:latest",
        "subfinder": "projectdiscovery/subfinder:latest",
        "amass": "caffix/amass:latest",
        "assetfinder": "sle118/assetfinder:latest",
        "wafw00f": "securesocket/wafw00f:latest",
        "whatweb": "securesocket/whatweb:latest",
        "ffuf": "ffuf/ffuf:latest",
        "feroxbuster": "epi052/feroxbuster:latest",
        "dalfox": "hahwul/dalfox:latest",
        "sqlmap": "paolonaldi/sqlmap:latest",
        "wpscan": "wpscan/wpscan:latest",
        "testssl": "drwetter/testssl.sh:latest",
    })

    # Logging
    log_level: str = "INFO"

    # API keys
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    virustotal_api_key: str = ""
    hunter_api_key: str = ""

    # Tool path overrides — tool_name -> absolute path to binary
    tool_paths: dict[str, str] = Field(default_factory=dict)

    # Tool execution helpers
    default_wordlist: str = ""
    installer_enabled: bool = False
    installer_require_confirm: bool = True

    # Execution limits
    max_concurrent_tools: int = 5
    default_timeout: int = 300  # seconds

    def get_tool_path(self, tool_name: str, default_binary: str) -> str:
        """Resolve binary path: override → default."""
        return self.tool_paths.get(tool_name, default_binary)

    def ensure_dirs(self) -> None:
        """Create data, reports, and sessions directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        Path(self.sessions_dir).mkdir(parents=True, exist_ok=True)


CyberMCPConfig = VajraMCPConfig


_CONFIG_INSTANCE = None


def get_config() -> VajraMCPConfig:
    """Singleton-style config loader."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = VajraMCPConfig()
    return _CONFIG_INSTANCE


__all__ = ["VajraMCPConfig", "CyberMCPConfig", "get_config"]
