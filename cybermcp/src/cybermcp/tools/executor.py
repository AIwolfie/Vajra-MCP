"""Async tool executor — runs CLI tools as subprocesses with timeout, scope validation, and resource limits."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from cybermcp.core.scope import ScopeManager
from cybermcp.tools.base import BaseTool, ToolResult

__all__ = ["ToolExecutor"]

logger = logging.getLogger("cybermcp.tools.executor")

_DEFAULT_MAX_BUFFER = 10 * 1024 * 1024  # 10 MB


class ToolExecutor:
    """Execute BaseTool instances as async subprocesses."""

    def __init__(
        self,
        max_buffer: int = _DEFAULT_MAX_BUFFER,
        allowed_scope: list[str] | None = None,
        scope_manager: ScopeManager | None = None,
    ) -> None:
        self._max_buffer = int(os.environ.get("CYBERMCP_MAX_BUFFER", max_buffer))
        self._allowed_scope = allowed_scope or []
        self._scope_manager = scope_manager

    # ------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_scope(target: str, scope: list[str]) -> bool:
        """Return True if *target* falls within the declared *scope*.

        Scope entries can be:
          - CIDR ranges   ("10.0.0.0/24")
          - Single IPs    ("192.168.1.1")
          - Domain globs  ("*.example.com", "example.com")
          - Wildcard       ("*")

        A target matches if it is:
          - An IP contained in any CIDR/IP entry, or
          - A hostname that matches a domain glob (suffix match), or
          - scope contains "*".
        """
        if not scope:
            return True
        if "*" in scope:
            return True

        target_clean = target.strip().lower()

        for entry in scope:
            entry_clean = entry.strip().lower()

            # CIDR / IP match
            try:
                net = ipaddress.ip_network(entry_clean, strict=False)
                try:
                    addr = ipaddress.ip_address(target_clean)
                    if addr in net:
                        return True
                except ValueError:
                    pass
                continue
            except ValueError:
                pass

            # Domain / glob match
            if entry_clean.startswith("*."):
                suffix = entry_clean[1:]  # ".example.com"
                if target_clean == entry_clean[2:] or target_clean.endswith(suffix):
                    return True
            else:
                if target_clean == entry_clean:
                    return True

        return False

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        tool: BaseTool,
        input_data: BaseModel,
        timeout: int | None = None,
        target: str | None = None,
    ) -> ToolResult:
        """Run *tool* with *input_data* and return a structured result.

        Args:
            tool: The tool wrapper instance.
            input_data: Validated Pydantic input model.
            timeout: Per-run timeout in seconds; falls back to tool.timeout.
            target: Optional target string for scope check.

        Returns:
            ToolResult with parsed output, findings, timing.
        """
        effective_timeout = timeout if timeout is not None else tool.timeout
        started_at = datetime.now(timezone.utc).isoformat()

        # Scope gate
        if target and self._scope_manager is not None:
            if not self._scope_manager.is_in_scope(target):
                return ToolResult(
                    tool_name=tool.name,
                    success=False,
                    error=f"Target '{target}' is outside allowed scope",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
        if target and self._allowed_scope:
            if not self.validate_scope(target, self._allowed_scope):
                return ToolResult(
                    tool_name=tool.name,
                    success=False,
                    error=f"Target '{target}' is outside allowed scope",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )

        # Binary availability
        if not tool.is_available():
            return ToolResult(
                tool_name=tool.name,
                success=False,
                error=f"Binary '{tool.binary_name}' not found in PATH",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

        cmd = tool.build_command(input_data)
        cmd_str = " ".join(cmd)
        logger.info("Executing: %s (timeout=%ds)", cmd_str, effective_timeout)

        env = self._build_env()
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    self._read_streams(proc), timeout=effective_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.monotonic() - start
                logger.warning("Tool %s timed out after %.1fs", tool.name, elapsed)
                return ToolResult(
                    tool_name=tool.name,
                    success=False,
                    error=f"Timed out after {elapsed:.1f}s",
                    execution_time=elapsed,
                    command=cmd_str,
                    return_code=-1,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )

            elapsed = time.monotonic() - start
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            logger.debug(
                "Tool %s finished in %.2fs (rc=%s, stdout=%d bytes, stderr=%d bytes)",
                tool.name, elapsed, proc.returncode, len(stdout_bytes), len(stderr_bytes),
            )

            result = tool.parse_output(stdout, stderr, proc.returncode or 0)
            result.execution_time = elapsed
            result.command = cmd_str
            result.return_code = proc.returncode if proc.returncode is not None else -1
            result.started_at = started_at
            result.completed_at = datetime.now(timezone.utc).isoformat()
            return result

        except FileNotFoundError:
            elapsed = time.monotonic() - start
            return ToolResult(
                tool_name=tool.name,
                success=False,
                error=f"Binary '{tool.binary_name}' not found",
                execution_time=elapsed,
                command=cmd_str,
                return_code=-1,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.exception("Unexpected error running %s", tool.name)
            return ToolResult(
                tool_name=tool.name,
                success=False,
                error=f"Execution error: {exc}",
                execution_time=elapsed,
                command=cmd_str,
                return_code=-1,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _read_streams(
        self, proc: asyncio.subprocess.Process
    ) -> tuple[bytes, bytes]:
        """Read stdout/stderr from *proc*, capping each at max_buffer."""
        assert proc.stdout is not None
        assert proc.stderr is not None

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_len = 0
        stderr_len = 0

        async def _drain(
            stream: asyncio.StreamReader,
            chunks: list[bytes],
            counter: list[int],
        ) -> None:
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                if counter[0] < self._max_buffer:
                    take = min(len(chunk), self._max_buffer - counter[0])
                    chunks.append(chunk[:take])
                counter[0] += len(chunk)

        stdout_counter: list[int] = [0]
        stderr_counter: list[int] = [0]

        await asyncio.gather(
            _drain(proc.stdout, stdout_chunks, stdout_counter),
            _drain(proc.stderr, stderr_chunks, stderr_counter),
        )
        await proc.wait()

        return b"".join(stdout_chunks), b"".join(stderr_chunks)

    @staticmethod
    def _build_env() -> dict[str, str]:
        """Build subprocess environment with resource-limit overrides."""
        env = dict(os.environ)
        # Propagate any CYBERMCP_ prefixed env vars as resource hints
        for key in ("CYBERMCP_ULIMIT_CPU", "CYBERMCP_ULIMIT_MEM", "CYBERMCP_NICE"):
            val = os.environ.get(key)
            if val:
                env[key] = val
        return env
