"""Database models — SQL schemas and Pydantic models for sessions, scans, findings, tool runs."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# SQL schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    scope_json      TEXT NOT NULL DEFAULT '[]',
    scope_excludes_json TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    target          TEXT NOT NULL DEFAULT '',
    args_json       TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending',
    started_at      TEXT,
    completed_at    TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    scan_id         TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    description     TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    remediation     TEXT NOT NULL DEFAULT '',
    cvss_score      REAL,
    cve_ids_json    TEXT NOT NULL DEFAULT '[]',
    affected_asset  TEXT NOT NULL DEFAULT '',
    hash            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    command         TEXT NOT NULL DEFAULT '',
    stdout          TEXT NOT NULL DEFAULT '',
    stderr          TEXT NOT NULL DEFAULT '',
    return_code     INTEGER NOT NULL DEFAULT -1,
    execution_time  REAL NOT NULL DEFAULT 0.0,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id);
"""

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SessionModel(BaseModel):
    id: str
    name: str = ""
    target: str = ""
    scope: list[str] = Field(default_factory=list)
    scope_excludes: list[str] = Field(default_factory=list)
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: datetime
    updated_at: datetime

    @field_validator("scope", mode="before")
    @classmethod
    def _parse_scope(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return json.loads(v)
        return v

    @field_validator("scope_excludes", mode="before")
    @classmethod
    def _parse_scope_excludes(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return json.loads(v)
        return v

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "scope_json": json.dumps(self.scope),
            "scope_excludes_json": json.dumps(self.scope_excludes),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class ScanModel(BaseModel):
    id: str
    session_id: str
    tool_name: str
    target: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @field_validator("args", mode="before")
    @classmethod
    def _parse_args(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, str):
            return json.loads(v)
        return v

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "args_json": json.dumps(self.args),
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class FindingModel(BaseModel):
    id: str
    session_id: str
    scan_id: str = ""
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    affected_asset: str = ""
    hash: str = ""
    created_at: datetime

    @field_validator("cve_ids", mode="before")
    @classmethod
    def _parse_cve_ids(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return json.loads(v)
        return v

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve_ids_json": json.dumps(self.cve_ids),
            "affected_asset": self.affected_asset,
            "hash": self.hash,
            "created_at": self.created_at.isoformat(),
        }


class ToolRunModel(BaseModel):
    id: str
    scan_id: str = ""
    tool_name: str
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    execution_time: float = 0.0
    created_at: datetime

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "tool_name": self.tool_name,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "execution_time": self.execution_time,
            "created_at": self.created_at.isoformat(),
        }


__all__ = [
    "SCHEMA_SQL",
    "SessionStatus",
    "ScanStatus",
    "Severity",
    "SessionModel",
    "ScanModel",
    "FindingModel",
    "ToolRunModel",
]
