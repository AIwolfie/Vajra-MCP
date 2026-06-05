"""CyberMCP configuration — Pydantic Settings with .env support."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class CyberMCPConfig(BaseSettings):
    """Central configuration for CyberMCP server."""

    model_config = SettingsConfigDict(
        env_prefix="CYBERMCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server
    server_name: str = "CyberMCP"
    server_version: str = "1.0.0"
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = 8394

    # HTTP/SSE authentication
    http_api_key: str = ""
    allow_localhost_no_auth: bool = False

    # Storage
    db_path: str = Field(default_factory=lambda: str(_PROJECT_ROOT / "data" / "cybermcp.db"))
    reports_dir: str = Field(default_factory=lambda: str(_PROJECT_ROOT / "reports"))

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
        """Create data and reports directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)


def get_config() -> CyberMCPConfig:
    """Singleton-style config loader."""
    return CyberMCPConfig()


__all__ = ["CyberMCPConfig", "get_config"]
