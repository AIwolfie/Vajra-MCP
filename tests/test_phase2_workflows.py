from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import cybermcp.server as server_module
from cybermcp.config import get_config
from cybermcp.core.scope import ScopeManager
from cybermcp.core.session import SessionManager
from cybermcp.db.database import Database
from cybermcp.reporting import HTMLReportGenerator, Report, ReportSummary
from cybermcp.tools.registry import ToolRegistry


class BrandingTest(unittest.TestCase):
    def test_default_server_name_uses_vajra_mcp(self) -> None:
        self.assertEqual(get_config().server_name, "Vajra MCP")


class WorkflowTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._db = Database(str(Path(self._tmp.name) / "vajra-mcp.db"))
        await self._db.init()

        self._old_db = server_module._db
        self._old_config = server_module._config
        self._old_registry = server_module._registry
        self._old_executor = server_module._executor
        self._old_scope_manager = server_module._scope_manager
        self._old_session_manager = server_module._session_manager

        server_module._db = self._db
        server_module._config = get_config()
        server_module._registry = ToolRegistry()
        server_module._registry.clear()
        server_module._registry.auto_discover()
        server_module._executor = None
        server_module._scope_manager = ScopeManager()
        server_module._scope_manager.set_scope(["example.com"], excludes=["blocked.example.com"])
        server_module._session_manager = SessionManager(self._db)

    async def asyncTearDown(self) -> None:
        await self._db.close()
        self._tmp.cleanup()

        server_module._db = self._old_db
        server_module._config = self._old_config
        server_module._registry = self._old_registry
        server_module._executor = self._old_executor
        server_module._scope_manager = self._old_scope_manager
        server_module._session_manager = self._old_session_manager

    async def test_auto_recon_orchestrates_priority_recon_tools(self) -> None:
        calls: list[tuple[str, dict[str, Any]]] = []
        original_execute_tool = server_module._execute_tool

        async def fake_execute_tool(tool_name: str, args: dict[str, Any] | None, *, timeout: int | None = None) -> dict[str, Any]:
            calls.append((tool_name, args or {}))
            parsed_data: dict[str, Any] = {}
            if tool_name == "subfinder":
                parsed_data = {"subdomains": ["api.example.com"], "count": 1}
            return {
                "status": "success",
                "scan_id": f"scan-{tool_name}",
                "result": {"parsed_data": parsed_data, "error": ""},
            }

        server_module._execute_tool = fake_execute_tool
        try:
            response = await server_module._auto_recon_workflow("example.com", depth="quick", max_hosts=3)
        finally:
            server_module._execute_tool = original_execute_tool

        tool_names = [name for name, _args in calls]
        self.assertEqual(response["status"], "success")
        self.assertIn("api.example.com", response["subdomains"])
        self.assertIn("subfinder", tool_names)
        self.assertIn("amass", tool_names)
        self.assertIn("assetfinder", tool_names)
        self.assertIn("httpx", tool_names)
        self.assertIn("nmap", tool_names)

    async def test_web_audit_skips_content_tools_without_wordlist(self) -> None:
        calls: list[str] = []
        original_execute_tool = server_module._execute_tool

        async def fake_execute_tool(tool_name: str, args: dict[str, Any] | None, *, timeout: int | None = None) -> dict[str, Any]:
            calls.append(tool_name)
            return {
                "status": "success",
                "scan_id": f"scan-{tool_name}",
                "result": {"parsed_data": {}, "error": ""},
            }

        server_module._execute_tool = fake_execute_tool
        try:
            response = await server_module._web_audit_workflow(
                "https://example.com",
                checks=["content", "tls"],
                wordlist="",
            )
        finally:
            server_module._execute_tool = original_execute_tool

        skipped = [run for run in response["tool_runs"] if run["status"] == "skipped"]
        self.assertEqual(response["status"], "success")
        self.assertEqual(calls, ["testssl"])
        self.assertEqual({run["tool_name"] for run in skipped}, {"ffuf", "feroxbuster"})

    async def test_workflow_respects_scope_before_session_target_update(self) -> None:
        response = await server_module._auto_recon_workflow("blocked.example.com", depth="quick")

        session = await server_module._session_manager.get_current_session()
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["scope"]["reason"], "excluded")
        self.assertEqual(session.target, "")


class ReportingTest(unittest.IsolatedAsyncioTestCase):
    async def test_html_report_generation_uses_vajra_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "report.html"
            report = Report(target="example.com", scope="example.com", summary=ReportSummary())

            rendered_path = await HTMLReportGenerator().generate(report, str(output_path))
            html = Path(rendered_path).read_text(encoding="utf-8")

            self.assertIn("Vajra MCP Security Assessment Report", html)
            self.assertIn("Vajra MCP", html)


if __name__ == "__main__":
    unittest.main()
