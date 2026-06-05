"""CyberMCP FastMCP server for direct Phase 1 tool execution."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from cybermcp.config import CyberMCPConfig, get_config
from cybermcp.core.scope import ScopeManager
from cybermcp.core.session import SessionManager
from cybermcp.db.database import Database
from cybermcp.db.models import ScanStatus, SessionStatus, Severity as DbSeverity
from cybermcp.reporting import CardGenerator, HTMLReportGenerator, Report, ReportSummary
from cybermcp.reporting.models import Finding as ReportFinding, Severity as ReportSeverity
from cybermcp.tools.base import ToolResult
from cybermcp.tools.executor import ToolExecutor
from cybermcp.tools.registry import ToolRegistry
from cybermcp.utils.crypto import hash_finding
from cybermcp.utils.logging import get_logger, setup_logging
from cybermcp.utils.sanitizer import sanitize_target

logger = get_logger(__name__)

_PHASE1_TOOLS = {
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
}

_db: Database | None = None
_config: CyberMCPConfig | None = None
_registry: ToolRegistry | None = None
_executor: ToolExecutor | None = None
_scope_manager: ScopeManager | None = None
_session_manager: SessionManager | None = None


def _get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


def _get_config() -> CyberMCPConfig:
    if _config is None:
        raise RuntimeError("Config not loaded")
    return _config


def _get_registry() -> ToolRegistry:
    if _registry is None:
        raise RuntimeError("Tool registry not initialized")
    return _registry


def _get_executor() -> ToolExecutor:
    if _executor is None:
        raise RuntimeError("Tool executor not initialized")
    return _executor


def _get_scope_manager() -> ScopeManager:
    if _scope_manager is None:
        raise RuntimeError("Scope manager not initialized")
    return _scope_manager


def _get_session_manager() -> SessionManager:
    if _session_manager is None:
        raise RuntimeError("Session manager not initialized")
    return _session_manager


def _target_from_args(args: dict[str, Any]) -> str:
    for key in ("target", "url", "host", "domain"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _session_to_json(session: Any) -> dict[str, Any]:
    return {
        "id": session.id,
        "name": session.name,
        "target": session.target,
        "scope": session.scope,
        "scope_excludes": session.scope_excludes,
        "status": session.status.value if hasattr(session.status, "value") else session.status,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
    }


def _scan_to_json(scan: Any) -> dict[str, Any]:
    return {
        "id": scan.id,
        "session_id": scan.session_id,
        "tool_name": scan.tool_name,
        "target": scan.target,
        "args": scan.args,
        "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


def _finding_to_json(finding: Any) -> dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "description": finding.description,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "cvss_score": finding.cvss_score,
        "cve_ids": finding.cve_ids,
        "affected_asset": finding.affected_asset,
        "created_at": finding.created_at.isoformat(),
    }


def _error_response(
    message: str,
    *,
    status: str = "error",
    details: Any | None = None,
    session_id: str = "",
    tool_name: str = "",
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "status": status,
        "message": message,
        "session_id": session_id,
        "tool_name": tool_name,
        "scope": scope or _get_scope_manager().describe(),
    }
    if details is not None:
        response["details"] = details
    return response


async def _ensure_session() -> Any:
    return await _get_session_manager().ensure_session()


async def _record_tool_result(
    session_id: str,
    scan_id: str,
    tool_name: str,
    result: ToolResult,
) -> None:
    db = _get_db()
    await db.create_tool_run(
        tool_name=tool_name,
        scan_id=scan_id,
        command=result.command,
        stdout=result.raw_output,
        stderr=result.error,
        return_code=result.return_code,
        execution_time=result.execution_time,
    )

    for finding in result.findings:
        finding_dict = finding.model_dump()
        finding_hash = hash_finding(finding_dict)
        await db.create_finding(
            session_id=session_id,
            scan_id=scan_id,
            title=finding.title,
            severity=DbSeverity(finding.severity.value),
            description=finding.description,
            evidence=finding.evidence,
            remediation=finding.remediation,
            cvss_score=finding.cvss_score,
            cve_ids=finding.cve_ids,
            affected_asset=finding.affected_asset,
            finding_hash=finding_hash,
        )


def _tool_result_payload(result: ToolResult) -> dict[str, Any]:
    return {
        "success": result.success,
        "parsed_data": result.parsed_data,
        "findings": [finding.model_dump() for finding in result.findings],
        "raw_output": result.raw_output,
        "error": result.error,
    }


async def _execute_tool(
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    timeout: int | None = None,
) -> dict[str, Any]:
    normalized_tool_name = tool_name.strip().lower()
    registry = _get_registry()
    tool = registry.get(normalized_tool_name)
    if tool is None or normalized_tool_name not in _PHASE1_TOOLS:
        return _error_response(
            f"Tool '{normalized_tool_name}' is not registered for Phase 1",
            tool_name=normalized_tool_name,
        )

    raw_args = args or {}
    target = _target_from_args(raw_args)
    cleaned_target = ""
    scope_decision = _get_scope_manager().describe()
    if target:
        try:
            cleaned_target = sanitize_target(target)
        except ValueError as exc:
            return _error_response(
                "Invalid target",
                details=str(exc),
                tool_name=normalized_tool_name,
            )
        scope_decision = _get_scope_manager().evaluate_target(cleaned_target)
        if not scope_decision["allowed"]:
            session = await _ensure_session()
            return _error_response(
                f"Target '{cleaned_target}' is outside allowed scope",
                session_id=session.id,
                tool_name=normalized_tool_name,
                scope=scope_decision,
            )

    try:
        input_data = tool.input_model.model_validate(raw_args)
    except ValidationError as exc:
        return _error_response(
            "Invalid tool arguments",
            details=exc.errors(),
            tool_name=normalized_tool_name,
            scope=scope_decision,
        )

    session = await _ensure_session()
    if cleaned_target:
        await _get_session_manager().update_target(session.id, cleaned_target)

    scan = await _get_db().create_scan(session.id, normalized_tool_name, cleaned_target, raw_args)
    await _get_db().update_scan_status(scan.id, ScanStatus.RUNNING)

    result = await _get_executor().execute(
        tool,
        input_data,
        timeout=timeout,
        target=cleaned_target or None,
    )
    await _record_tool_result(session.id, scan.id, normalized_tool_name, result)
    await _get_db().update_scan_status(
        scan.id,
        ScanStatus.COMPLETED if result.success else ScanStatus.FAILED,
    )

    return {
        "status": "success" if result.success else "error",
        "session_id": session.id,
        "scan_id": scan.id,
        "tool_name": normalized_tool_name,
        "scope": scope_decision,
        "execution": {
            "command": result.command,
            "return_code": result.return_code,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "execution_time": result.execution_time,
        },
        "result": _tool_result_payload(result),
    }


async def _build_report(session_id: str) -> tuple[Report, ReportSummary]:
    db = _get_db()
    session = await db.get_session(session_id)
    if session is None:
        raise ValueError(f"Session {session_id} not found")

    findings = await db.get_findings(session_id)
    report_findings = [
        ReportFinding(
            title=f.title,
            severity=ReportSeverity(f.severity.value),
            description=f.description,
            evidence=f.evidence,
            remediation=f.remediation,
            cvss_score=f.cvss_score,
            cve_ids=f.cve_ids,
            affected_asset=f.affected_asset,
        )
        for f in findings
    ]
    cards = CardGenerator.findings_to_cards(report_findings)
    summary = ReportSummary.from_cards(cards)
    report = Report(
        target=session.target,
        scope=", ".join(session.scope),
        summary=summary,
        vuln_cards=cards,
        methodology="Direct MCP tool execution controlled by Claude Code.",
    )
    return report, summary


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    global _db, _config, _registry, _executor, _scope_manager, _session_manager

    _config = get_config()
    setup_logging(_config.log_level)
    _config.ensure_dirs()

    _db = Database(_config.db_path)
    await _db.init()

    _scope_manager = ScopeManager()
    _registry = ToolRegistry()
    _registry.clear()
    _registry.auto_discover()
    _executor = ToolExecutor(scope_manager=_scope_manager)
    _session_manager = SessionManager(_db)

    logger.info("CyberMCP Phase 1 server started: %s v%s", _config.server_name, _config.server_version)
    yield {}
    await _db.close()
    logger.info("CyberMCP server shut down")


def create_server() -> FastMCP:
    cfg = get_config()
    server = FastMCP(
        cfg.server_name,
        log_level=cfg.log_level,
        host=cfg.host,
        port=cfg.port,
        lifespan=_lifespan,
    )
    _register_tools(server)
    return server


def _register_tools(server: FastMCP) -> None:
    @server.tool()
    async def list_tools(category: str = "", available_only: bool = False) -> dict[str, Any]:
        tools = _get_registry().list_available() if available_only else _get_registry().list_tools()
        phase1_tools = [tool for tool in tools if tool["name"] in _PHASE1_TOOLS]
        if category:
            phase1_tools = [tool for tool in phase1_tools if tool["category"] == category.lower()]
        return {
            "status": "success",
            "phase": "phase_1",
            "category_filter": category or "all",
            "available_only": available_only,
            "total_tools": len(phase1_tools),
            "tools": phase1_tools,
        }

    @server.tool()
    async def get_scope() -> dict[str, Any]:
        return {"status": "success", "scope": _get_scope_manager().describe()}

    @server.tool()
    async def set_scope(
        targets: list[str],
        excludes: list[str] | None = None,
        notes: str = "",
    ) -> dict[str, Any]:
        session = await _ensure_session()
        try:
            cleaned = [sanitize_target(target) for target in targets]
            cleaned_excludes = [sanitize_target(exclude) for exclude in (excludes or [])]
        except ValueError as exc:
            return _error_response("Invalid scope target", details=str(exc), session_id=session.id)

        scope = _get_scope_manager().set_scope(cleaned, excludes=cleaned_excludes, notes=notes)
        await _get_session_manager().update_scope(session.id, cleaned, cleaned_excludes)
        return {
            "status": "success",
            "session_id": session.id,
            "scope": {
                "configured": True,
                "in_scope": scope.targets,
                "excluded": scope.excludes,
                "notes": scope.notes,
            },
        }

    @server.tool()
    async def create_session(
        name: str = "default",
        target: str = "",
        scope: list[str] | None = None,
        excludes: list[str] | None = None,
    ) -> dict[str, Any]:
        try:
            clean_target = sanitize_target(target) if target else ""
            clean_scope = [sanitize_target(item) for item in (scope or [])]
            clean_excludes = [sanitize_target(item) for item in (excludes or [])]
        except ValueError as exc:
            return _error_response("Invalid session target or scope", details=str(exc))

        session = await _get_session_manager().create_session(
            name=name,
            target=clean_target,
            scope=clean_scope,
            scope_excludes=clean_excludes,
        )
        if clean_scope or clean_excludes:
            _get_scope_manager().set_scope(clean_scope, excludes=clean_excludes)
        return {"status": "success", "session": _session_to_json(session)}

    @server.tool()
    async def set_current_session(session_id: str) -> dict[str, Any]:
        session = await _get_session_manager().set_current_session(session_id)
        if session is None:
            return _error_response(f"Session {session_id} not found")
        if session.scope or session.scope_excludes:
            _get_scope_manager().set_scope(session.scope, excludes=session.scope_excludes)
        return {"status": "success", "session": _session_to_json(session)}

    @server.tool()
    async def list_sessions(status: str = "", limit: int = 50) -> dict[str, Any]:
        session_status = None
        if status:
            try:
                session_status = SessionStatus(status.lower())
            except ValueError:
                return _error_response("Invalid session status", details=status)
        sessions = await _get_session_manager().list_sessions(status=session_status, limit=limit)
        return {
            "status": "success",
            "total_sessions": len(sessions),
            "sessions": [_session_to_json(session) for session in sessions],
        }

    @server.tool()
    async def get_session(session_id: str = "") -> dict[str, Any]:
        session = await _ensure_session() if not session_id else await _get_db().get_session(session_id)
        if session is None:
            return _error_response(f"Session {session_id} not found")
        scans = await _get_db().get_scans(session.id)
        findings = await _get_db().get_findings(session.id)
        stats = await _get_db().get_session_stats(session.id)
        return {
            "status": "success",
            "session": _session_to_json(session),
            "stats": stats,
            "scans": [_scan_to_json(scan) for scan in scans],
            "findings": [_finding_to_json(finding) for finding in findings],
        }

    @server.tool()
    async def run_tool(
        tool_name: str,
        args: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        return await _execute_tool(tool_name, args, timeout=timeout)

    @server.tool()
    async def generate_html_report(session_id: str = "") -> dict[str, Any]:
        session = await _ensure_session() if not session_id else await _get_db().get_session(session_id)
        if session is None:
            return _error_response(f"Session {session_id} not found")

        try:
            report, summary = await _build_report(session.id)
        except ValueError as exc:
            return _error_response(str(exc), session_id=session.id)

        output_path = f"{_get_config().reports_dir}/report-{session.id[:8]}.html"
        path = await HTMLReportGenerator().generate(report, output_path)
        return {
            "status": "success",
            "session_id": session.id,
            "format": "html",
            "report_path": path,
            "summary": summary.model_dump(),
        }

    @server.tool()
    async def subfinder(domain: str, all_sources: bool = False, recursive: bool = False, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("subfinder", {"domain": domain, "all_sources": all_sources, "recursive": recursive}, timeout=timeout)

    @server.tool()
    async def amass(domain: str, passive: bool = True, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("amass", {"domain": domain, "passive": passive}, timeout=timeout)

    @server.tool()
    async def assetfinder(domain: str, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("assetfinder", {"domain": domain}, timeout=timeout)

    @server.tool()
    async def httpx(target: str, follow_redirects: bool = True, status_code: bool = True, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("httpx", {"target": target, "follow_redirects": follow_redirects, "status_code": status_code}, timeout=timeout)

    @server.tool()
    async def katana(target: str, depth: int = 2, js_crawl: bool = False, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("katana", {"target": target, "depth": depth, "js_crawl": js_crawl}, timeout=timeout)

    @server.tool()
    async def nmap(
        target: str,
        ports: str | None = None,
        scan_type: str = "connect",
        scripts: list[str] | None = None,
        timing: str = "T3",
        os_detection: bool = False,
        service_detection: bool = True,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        return await _execute_tool(
            "nmap",
            {
                "target": target,
                "ports": ports,
                "scan_type": scan_type,
                "scripts": scripts or [],
                "timing": timing,
                "os_detection": os_detection,
                "service_detection": service_detection,
            },
            timeout=timeout,
        )

    @server.tool()
    async def whatweb(target: str, aggressive: bool = False, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("whatweb", {"target": target, "aggressive": aggressive}, timeout=timeout)

    @server.tool()
    async def wafw00f(target: str, find_all: bool = False, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("wafw00f", {"target": target, "find_all": find_all}, timeout=timeout)

    @server.tool()
    async def nuclei(
        target: str,
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        rate_limit: int | None = None,
        concurrency: int | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        return await _execute_tool(
            "nuclei",
            {
                "target": target,
                "templates": templates,
                "severity": severity,
                "tags": tags,
                "rate_limit": rate_limit,
                "concurrency": concurrency,
            },
            timeout=timeout,
        )

    @server.tool()
    async def ffuf(url: str, wordlist: str, method: str = "GET", threads: int = 40, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("ffuf", {"url": url, "wordlist": wordlist, "method": method, "threads": threads}, timeout=timeout)

    @server.tool()
    async def feroxbuster(url: str, wordlist: str | None = None, threads: int = 50, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("feroxbuster", {"url": url, "wordlist": wordlist, "threads": threads}, timeout=timeout)

    @server.tool()
    async def dalfox(target: str, blind: str | None = None, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("dalfox", {"target": target, "blind": blind}, timeout=timeout)

    @server.tool()
    async def sqlmap(
        url: str,
        data: str | None = None,
        cookie: str | None = None,
        method: str | None = None,
        dbms: str | None = None,
        level: int = 1,
        risk: int = 1,
        tamper: str | None = None,
        batch: bool = True,
        forms: bool = False,
        crawl: int | None = None,
        threads: int | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        return await _execute_tool(
            "sqlmap",
            {
                "url": url,
                "data": data,
                "cookie": cookie,
                "method": method,
                "dbms": dbms,
                "level": level,
                "risk": risk,
                "tamper": tamper,
                "batch": batch,
                "forms": forms,
                "crawl": crawl,
                "threads": threads,
            },
            timeout=timeout,
        )

    @server.tool()
    async def wpscan(url: str, api_token: str | None = None, enumerate: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("wpscan", {"url": url, "api_token": api_token, "enumerate": enumerate}, timeout=timeout)

    @server.tool()
    async def testssl(target: str, full: bool = False, timeout: int | None = None) -> dict[str, Any]:
        return await _execute_tool("testssl", {"target": target, "full": full}, timeout=timeout)


__all__ = ["create_server"]
