"""Base classes and models for the Vajra MCP tool framework."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Type

from pydantic import BaseModel, Field

__all__ = [
    "BaseTool",
    "Finding",
    "Severity",
    "ToolCategory",
    "ToolResult",
]


class ToolCategory(str, Enum):
    """Categories for pentesting tools."""
    RECON = "recon"
    WEB = "web"
    NETWORK = "network"
    EXPLOIT = "exploit"
    CLOUD = "cloud"
    CREDENTIAL = "credential"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    OSINT = "osint"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single security finding produced by a tool."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    affected_asset: str = ""
    tool_name: str = ""
    timestamp: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class ToolResult(BaseModel):
    """Structured result returned by every tool execution."""
    tool_name: str
    success: bool
    raw_output: str = ""
    parsed_data: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    error: str = ""
    execution_time: float = 0.0
    command: str = ""
    return_code: int = -1
    started_at: str = ""
    completed_at: str = ""

    def model_post_init(self, __context: Any) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.completed_at:
            self.completed_at = now


class BaseTool(ABC):
    """Abstract base class every tool wrapper must subclass.

    Subclasses set class-level attrs and implement build_command + parse_output.
    """
    name: str = ""
    description: str = ""
    category: ToolCategory = ToolCategory.RECON
    binary_name: str = ""
    binary_candidates: list[str] = []
    tags: list[str] = []
    timeout: int = 300
    needs_root: bool = False
    input_model: Type[BaseModel] = BaseModel
    docker_capable: bool = False

    def parse_output_file(
        self,
        stdout_path: str,
        stderr_path: str,
        return_code: int,
        complete: bool = True
    ) -> ToolResult:
        """Parse process output from files. Default implementation reads files into memory and delegates to parse_output."""
        stdout = ""
        stderr = ""
        try:
            with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
                stdout = f.read()
        except Exception:
            pass
        try:
            with open(stderr_path, "r", encoding="utf-8", errors="replace") as f:
                stderr = f.read()
        except Exception:
            pass
        result = self.parse_output(stdout, stderr, return_code)
        if not complete:
            result.parsed_data["partial"] = True
        return result

    def is_available(self) -> bool:
        """Check whether the backing binary is on PATH."""
        configured = self.get_binary_path()
        if configured is None:
            return False
        if shutil.which(configured) is not None:
            return True
        return Path(configured).exists()

    def get_binary_path(self) -> str | None:
        """Return the resolved path of the binary, or the binary name."""
        try:
            from cybermcp.config import get_config

            configured = get_config().get_tool_path(self.name, self.binary_name)
        except Exception:
            configured = self.binary_name
        candidates = [configured]
        candidates.extend(candidate for candidate in self.binary_candidates if candidate not in candidates)
        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
            if Path(candidate).exists():
                return candidate
        return configured

    @abstractmethod
    def build_command(self, input_data: BaseModel) -> list[str]:
        """Build the CLI argument list from validated input.

        Returns:
            List of strings suitable for subprocess invocation.
            First element should be the binary name/path.
        """
        ...

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        """Parse raw process output into a structured ToolResult."""
        ...

    def get_default_args(self) -> dict[str, Any]:
        """Return default safe arguments for this tool."""
        return {}

    def get_tool_info(self) -> dict[str, Any]:
        """Return a metadata dict describing this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "binary": self.binary_name,
            "available": self.is_available(),
            "tags": list(self.tags),
            "needs_root": self.needs_root,
            "timeout": self.timeout,
        }
