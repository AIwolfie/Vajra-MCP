"""Session manager backed by the primary CyberMCP SQLite database."""

from __future__ import annotations

from cybermcp.db.database import Database
from cybermcp.db.models import SessionModel, SessionStatus

__all__ = ["SessionManager", "SessionStatus"]


class SessionManager:
    """Small coordination layer for the active MCP engagement session."""

    def __init__(self, database: Database) -> None:
        self._database = database
        self._current_session_id: str | None = None

    async def create_session(
        self,
        name: str = "",
        target: str = "",
        scope: list[str] | None = None,
        scope_excludes: list[str] | None = None,
    ) -> SessionModel:
        session = await self._database.create_session(
            name=name or "default",
            target=target,
            scope=scope,
            scope_excludes=scope_excludes,
        )
        self._current_session_id = session.id
        return session

    async def ensure_session(self) -> SessionModel:
        if self._current_session_id:
            existing = await self._database.get_session(self._current_session_id)
            if existing is not None:
                return existing
        return await self.create_session(name="default")

    async def get_session(self, session_id: str) -> SessionModel | None:
        return await self._database.get_session(session_id)

    async def set_current_session(self, session_id: str) -> SessionModel | None:
        session = await self._database.get_session(session_id)
        if session is not None:
            self._current_session_id = session.id
        return session

    async def get_current_session(self) -> SessionModel:
        return await self.ensure_session()

    async def list_sessions(
        self,
        status: SessionStatus | None = None,
        limit: int = 50,
    ) -> list[SessionModel]:
        return await self._database.list_sessions(status=status, limit=limit)

    async def update_scope(
        self,
        session_id: str,
        targets: list[str],
        excludes: list[str],
    ) -> SessionModel | None:
        return await self._database.update_session(
            session_id,
            scope=targets,
            scope_excludes=excludes,
        )

    async def update_target(self, session_id: str, target: str) -> SessionModel | None:
        return await self._database.update_session(session_id, target=target)
