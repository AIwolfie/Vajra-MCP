"""Async database layer using aiosqlite."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from cybermcp.db.models import (
    SCHEMA_SQL,
    FindingModel,
    ScanModel,
    ScanStatus,
    SessionModel,
    SessionStatus,
    Severity,
    ToolRunModel,
)
from cybermcp.utils.logging import get_logger

logger = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid.uuid4().hex


class Database:
    """Async SQLite database for CyberMCP persistence."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def init(self) -> None:
        """Open connection and create tables."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        await self._migrate()
        await self._conn.commit()
        logger.info("Database initialized at %s", self._db_path)

    async def _migrate(self) -> None:
        """Apply lightweight schema migrations for existing SQLite files."""
        cursor = await self.conn.execute("PRAGMA table_info(sessions)")
        columns = {row["name"] for row in await cursor.fetchall()}
        if "scope_excludes_json" not in columns:
            await self.conn.execute(
                "ALTER TABLE sessions ADD COLUMN scope_excludes_json TEXT NOT NULL DEFAULT '[]'"
            )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not initialized — call init() first")
        return self._conn

    # -----------------------------------------------------------------------
    # Sessions
    # -----------------------------------------------------------------------

    async def create_session(
        self,
        name: str = "",
        target: str = "",
        scope: list[str] | None = None,
        scope_excludes: list[str] | None = None,
    ) -> SessionModel:
        now = _now()
        session = SessionModel(
            id=_uuid(),
            name=name,
            target=target,
            scope=scope or [],
            scope_excludes=scope_excludes or [],
            status=SessionStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        row = session.to_row()
        await self.conn.execute(
            "INSERT INTO sessions (id, name, target, scope_json, scope_excludes_json, status, created_at, updated_at) "
            "VALUES (:id, :name, :target, :scope_json, :scope_excludes_json, :status, :created_at, :updated_at)",
            row,
        )
        await self.conn.commit()
        return session

    async def get_session(self, session_id: str) -> SessionModel | None:
        cursor = await self.conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    async def update_session(
        self,
        session_id: str,
        *,
        status: SessionStatus | None = None,
        name: str | None = None,
        target: str | None = None,
        scope: list[str] | None = None,
        scope_excludes: list[str] | None = None,
    ) -> SessionModel | None:
        existing = await self.get_session(session_id)
        if existing is None:
            return None

        if status is not None:
            existing.status = status
        if name is not None:
            existing.name = name
        if target is not None:
            existing.target = target
        if scope is not None:
            existing.scope = scope
        if scope_excludes is not None:
            existing.scope_excludes = scope_excludes
        existing.updated_at = _now()

        row = existing.to_row()
        await self.conn.execute(
            "UPDATE sessions SET name=:name, target=:target, scope_json=:scope_json, scope_excludes_json=:scope_excludes_json, "
            "status=:status, updated_at=:updated_at WHERE id=:id",
            row,
        )
        await self.conn.commit()
        return existing

    async def list_sessions(
        self,
        *,
        status: SessionStatus | None = None,
        limit: int = 50,
    ) -> list[SessionModel]:
        sql = "SELECT * FROM sessions"
        params: list[Any] = []
        if status is not None:
            sql += " WHERE status = ?"
            params.append(status.value)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        cursor = await self.conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [self._row_to_session(row) for row in rows]

    # -----------------------------------------------------------------------
    # Scans
    # -----------------------------------------------------------------------

    async def create_scan(
        self,
        session_id: str,
        tool_name: str,
        target: str = "",
        args: dict[str, Any] | None = None,
    ) -> ScanModel:
        scan = ScanModel(
            id=_uuid(),
            session_id=session_id,
            tool_name=tool_name,
            target=target,
            args=args or {},
            status=ScanStatus.PENDING,
            started_at=None,
            completed_at=None,
        )
        row = scan.to_row()
        await self.conn.execute(
            "INSERT INTO scans (id, session_id, tool_name, target, args_json, status, started_at, completed_at) "
            "VALUES (:id, :session_id, :tool_name, :target, :args_json, :status, :started_at, :completed_at)",
            row,
        )
        await self.conn.commit()
        return scan

    async def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
    ) -> None:
        now_str = _now().isoformat()
        updates: dict[str, Any] = {"status": status.value, "id": scan_id}
        if status == ScanStatus.RUNNING:
            updates["started_at"] = now_str
            sql = "UPDATE scans SET status=:status, started_at=:started_at WHERE id=:id"
        elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            updates["completed_at"] = now_str
            sql = "UPDATE scans SET status=:status, completed_at=:completed_at WHERE id=:id"
        else:
            sql = "UPDATE scans SET status=:status WHERE id=:id"
        await self.conn.execute(sql, updates)
        await self.conn.commit()

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------

    async def create_finding(
        self,
        session_id: str,
        title: str,
        severity: Severity = Severity.INFO,
        scan_id: str = "",
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cvss_score: float | None = None,
        cve_ids: list[str] | None = None,
        affected_asset: str = "",
        finding_hash: str = "",
    ) -> FindingModel:
        finding = FindingModel(
            id=_uuid(),
            session_id=session_id,
            scan_id=scan_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cve_ids=cve_ids or [],
            affected_asset=affected_asset,
            hash=finding_hash,
            created_at=_now(),
        )
        row = finding.to_row()
        await self.conn.execute(
            "INSERT INTO findings (id, session_id, scan_id, title, severity, description, "
            "evidence, remediation, cvss_score, cve_ids_json, affected_asset, hash, created_at) "
            "VALUES (:id, :session_id, :scan_id, :title, :severity, :description, "
            ":evidence, :remediation, :cvss_score, :cve_ids_json, :affected_asset, :hash, :created_at)",
            row,
        )
        await self.conn.commit()
        return finding

    async def get_findings(
        self,
        session_id: str,
        severity: Severity | None = None,
    ) -> list[FindingModel]:
        if severity:
            cursor = await self.conn.execute(
                "SELECT * FROM findings WHERE session_id = ? AND severity = ? ORDER BY created_at DESC",
                (session_id, severity.value),
            )
        else:
            cursor = await self.conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,),
            )
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def get_scans(self, session_id: str) -> list[ScanModel]:
        cursor = await self.conn.execute(
            "SELECT * FROM scans WHERE session_id = ? ORDER BY COALESCE(started_at, completed_at, '') DESC",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [self._row_to_scan(r) for r in rows]

    async def get_tool_runs(self, scan_id: str = "") -> list[ToolRunModel]:
        if scan_id:
            cursor = await self.conn.execute(
                "SELECT * FROM tool_runs WHERE scan_id = ? ORDER BY created_at DESC",
                (scan_id,),
            )
        else:
            cursor = await self.conn.execute(
                "SELECT * FROM tool_runs ORDER BY created_at DESC"
            )
        rows = await cursor.fetchall()
        return [self._row_to_tool_run(r) for r in rows]

    # -----------------------------------------------------------------------
    # Tool runs
    # -----------------------------------------------------------------------

    async def create_tool_run(
        self,
        tool_name: str,
        scan_id: str = "",
        command: str = "",
        stdout: str = "",
        stderr: str = "",
        return_code: int = -1,
        execution_time: float = 0.0,
    ) -> ToolRunModel:
        run = ToolRunModel(
            id=_uuid(),
            scan_id=scan_id,
            tool_name=tool_name,
            command=command,
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            execution_time=execution_time,
            created_at=_now(),
        )
        row = run.to_row()
        await self.conn.execute(
            "INSERT INTO tool_runs (id, scan_id, tool_name, command, stdout, stderr, "
            "return_code, execution_time, created_at) "
            "VALUES (:id, :scan_id, :tool_name, :command, :stdout, :stderr, "
            ":return_code, :execution_time, :created_at)",
            row,
        )
        await self.conn.commit()
        return run

    # -----------------------------------------------------------------------
    # Stats
    # -----------------------------------------------------------------------

    async def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Aggregate counts for a session."""
        stats: dict[str, Any] = {"session_id": session_id}

        cursor = await self.conn.execute(
            "SELECT COUNT(*) FROM scans WHERE session_id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        stats["total_scans"] = row[0] if row else 0

        cursor = await self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE session_id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        stats["total_findings"] = row[0] if row else 0

        cursor = await self.conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE session_id = ? GROUP BY severity",
            (session_id,),
        )
        severity_counts: dict[str, int] = {}
        for r in await cursor.fetchall():
            severity_counts[r[0]] = r[1]
        stats["findings_by_severity"] = severity_counts

        cursor = await self.conn.execute(
            "SELECT status, COUNT(*) FROM scans WHERE session_id = ? GROUP BY status",
            (session_id,),
        )
        scan_status: dict[str, int] = {}
        for r in await cursor.fetchall():
            scan_status[r[0]] = r[1]
        stats["scans_by_status"] = scan_status

        return stats

    # -----------------------------------------------------------------------
    # Row mappers
    # -----------------------------------------------------------------------

    @staticmethod
    def _row_to_session(row: aiosqlite.Row) -> SessionModel:
        return SessionModel(
            id=row["id"],
            name=row["name"],
            target=row["target"],
            scope=row["scope_json"],
            scope_excludes=row["scope_excludes_json"] if "scope_excludes_json" in row.keys() else [],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_scan(row: aiosqlite.Row) -> ScanModel:
        started_at = row["started_at"]
        completed_at = row["completed_at"]
        return ScanModel(
            id=row["id"],
            session_id=row["session_id"],
            tool_name=row["tool_name"],
            target=row["target"],
            args=row["args_json"],
            status=row["status"],
            started_at=datetime.fromisoformat(started_at) if started_at else None,
            completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
        )

    @staticmethod
    def _row_to_finding(row: aiosqlite.Row) -> FindingModel:
        return FindingModel(
            id=row["id"],
            session_id=row["session_id"],
            scan_id=row["scan_id"],
            title=row["title"],
            severity=row["severity"],
            description=row["description"],
            evidence=row["evidence"],
            remediation=row["remediation"],
            cvss_score=row["cvss_score"],
            cve_ids=row["cve_ids_json"],
            affected_asset=row["affected_asset"],
            hash=row["hash"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _row_to_tool_run(row: aiosqlite.Row) -> ToolRunModel:
        return ToolRunModel(
            id=row["id"],
            scan_id=row["scan_id"],
            tool_name=row["tool_name"],
            command=row["command"],
            stdout=row["stdout"],
            stderr=row["stderr"],
            return_code=row["return_code"],
            execution_time=row["execution_time"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )


__all__ = ["Database"]
