"""Async tool executor — runs CLI tools as subprocesses with timeout, scope validation, and resource limits."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from datetime import datetime, timezone

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
        stdout_path: str | None = None,
        stderr_path: str | None = None,
    ) -> ToolResult:
        """Run *tool* with *input_data* and return a structured result.

        Args:
            tool: The tool wrapper instance.
            input_data: Validated Pydantic input model.
            timeout: Per-run timeout in seconds; falls back to tool.timeout.
            target: Optional target string for scope check.
            stdout_path: Path to write stdout stream.
            stderr_path: Path to write stderr stream.

        Returns:
            ToolResult with parsed output, findings, timing.
        """
        import tempfile
        from cybermcp.config import get_config
        import psutil

        cfg = get_config()
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

        # Setup temp paths for streaming files if none provided
        tmp_stdout = None
        tmp_stderr = None
        if not stdout_path:
            fd, stdout_path = tempfile.mkstemp(suffix="_stdout.log")
            os.close(fd)
            tmp_stdout = stdout_path
        if not stderr_path:
            fd, stderr_path = tempfile.mkstemp(suffix="_stderr.log")
            os.close(fd)
            tmp_stderr = stderr_path

        # Determine execution parameters
        run_mode = cfg.execution_mode
        warning_msg = ""
        is_docker = False

        if run_mode == "docker":
            if tool.docker_capable:
                is_docker = True
            else:
                run_mode = "native"
                warning_msg = "Tool does not support Docker execution; falling back to native mode."
                logger.warning("Tool %s is not Docker-capable; falling back to native mode", tool.name)

        cmd = tool.build_command(input_data)

        if is_docker:
            # Map native paths to docker /workspace volume mount points
            # Assumes project root is mounted into docker
            project_root = str(cfg.db_path).replace("\\", "/").rsplit("/data/", 1)[0]
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{project_root}:/workspace",
                "-w", "/workspace",
                "--memory", f"{cfg.max_memory_mb}m",
            ]
            
            # Translate binary path / command arguments matching project root
            translated_cmd = []
            for arg in cmd:
                arg_clean = arg.replace("\\", "/")
                if project_root in arg_clean:
                    translated_cmd.append(arg_clean.replace(project_root, "/workspace"))
                else:
                    translated_cmd.append(arg)

            image = cfg.docker_images.get(tool.name, f"projectdiscovery/{tool.name}:latest")
            docker_cmd.append(image)
            docker_cmd.extend(translated_cmd)
            cmd = docker_cmd
        else:
            if not tool.is_available():
                return ToolResult(
                    tool_name=tool.name,
                    success=False,
                    error=f"Binary '{tool.binary_name}' not found in PATH",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )

        cmd_str = " ".join(cmd)
        logger.info("Executing (%s): %s (timeout=%ds)", run_mode, cmd_str, effective_timeout)

        env = self._build_env()
        start = time.monotonic()
        resource_limited = False
        completed_status = True

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # Monitor task
            async def _monitor_resources() -> None:
                nonlocal resource_limited
                try:
                    p = psutil.Process(proc.pid)
                    while proc.returncode is None:
                        # Check RSS memory limit
                        mem_info = p.memory_info()
                        if mem_info.rss > (cfg.max_memory_mb * 1024 * 1024):
                            logger.error("Process %d exceeded memory limit (%d MB)", proc.pid, cfg.max_memory_mb)
                            resource_limited = True
                            proc.kill()
                            break
                        # Check CPU utilization - best effort
                        await asyncio.sleep(0.5)
                except psutil.NoSuchProcess:
                    pass
                except Exception:
                    pass

            monitor_task = asyncio.create_task(_monitor_resources())

            try:
                await asyncio.wait_for(
                    self._read_streams_to_files(proc, stdout_path, stderr_path, cfg.max_output_mb),
                    timeout=effective_timeout
                )
            except asyncio.TimeoutError:
                completed_status = False
                proc.kill()
                await proc.wait()
                elapsed = time.monotonic() - start
                logger.warning("Tool %s timed out after %.1fs", tool.name, elapsed)
            except Exception as e:
                if "output limit" in str(e).lower():
                    resource_limited = True
                completed_status = False
                proc.kill()
                await proc.wait()

            monitor_task.cancel()
            elapsed = time.monotonic() - start
            return_code = proc.returncode if proc.returncode is not None else -1

            # Run recovery parser
            result = tool.parse_output_file(stdout_path, stderr_path, return_code, complete=completed_status)
            result.execution_time = elapsed
            result.command = cmd_str
            result.return_code = return_code
            result.started_at = started_at
            result.completed_at = datetime.now(timezone.utc).isoformat()

            if "metadata" not in result.parsed_data or not isinstance(result.parsed_data["metadata"], dict):
                result.parsed_data["metadata"] = {}
            if warning_msg:
                result.parsed_data["metadata"]["warning"] = warning_msg
            if resource_limited:
                result.parsed_data["metadata"]["resource_limited"] = True
                result.success = False

            return result

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
        finally:
            # Clean up temp files if generated dynamically
            if tmp_stdout:
                try:
                    os.unlink(tmp_stdout)
                except Exception:
                    pass
            if tmp_stderr:
                try:
                    os.unlink(tmp_stderr)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _read_streams_to_files(
        self, proc: asyncio.subprocess.Process, stdout_path: str, stderr_path: str, max_output_mb: int
    ) -> None:
        """Stream stdout/stderr from process straight to output files on disk."""
        import aiofiles
        assert proc.stdout is not None
        assert proc.stderr is not None
        
        max_bytes = max_output_mb * 1024 * 1024

        async def _drain(stream: asyncio.StreamReader, path: str) -> None:
            written = 0
            async with aiofiles.open(path, "wb") as f:
                while True:
                    chunk = await stream.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError(f"Process output limit of {max_output_mb}MB exceeded")
                    await f.write(chunk)

        await asyncio.gather(
            _drain(proc.stdout, stdout_path),
            _drain(proc.stderr, stderr_path),
        )
        await proc.wait()

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

