from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pydantic import BaseModel

from cybermcp.core.scope import ScopeManager
from cybermcp.core.session import SessionManager
from cybermcp.db.database import Database
from cybermcp.tools.base import BaseTool, ToolCategory, ToolResult
from cybermcp.tools.executor import ToolExecutor
from cybermcp.tools.registry import ToolRegistry
from cybermcp.tools.web.nuclei import NucleiTool


class _DummyInput(BaseModel):
    target: str


class _MissingBinaryTool(BaseTool):
    name = "missing-binary"
    description = "Missing binary test tool"
    category = ToolCategory.RECON
    binary_name = "cybermcp-definitely-missing-binary"
    input_model = _DummyInput

    def build_command(self, input_data: _DummyInput) -> list[str]:
        return [self.binary_name, input_data.target]

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        return ToolResult(tool_name=self.name, success=return_code == 0, raw_output=stdout)


class ScopeManagerTest(unittest.TestCase):
    def test_scope_decision_reports_allowed_and_excluded_targets(self) -> None:
        scope = ScopeManager()
        scope.set_scope(["example.com", "10.0.0.0/24"], excludes=["admin.example.com"])

        allowed = scope.evaluate_target("api.example.com")
        excluded = scope.evaluate_target("admin.example.com")
        cidr_allowed = scope.evaluate_target("10.0.0.7")

        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["reason"], "allowed")
        self.assertFalse(excluded["allowed"])
        self.assertEqual(excluded["reason"], "excluded")
        self.assertTrue(cidr_allowed["allowed"])

    def test_unconfigured_scope_is_explicit(self) -> None:
        scope = ScopeManager()
        decision = scope.evaluate_target("example.com")

        self.assertFalse(decision["configured"])
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["reason"], "no_scope_configured")


class RegistryTest(unittest.TestCase):
    def test_phase1_priority_tools_are_discovered(self) -> None:
        registry = ToolRegistry()
        registry.clear()
        registry.auto_discover()

        names = {tool["name"] for tool in registry.list_tools()}
        expected = {
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

        self.assertTrue(expected.issubset(names))


class ParserTest(unittest.TestCase):
    def test_nuclei_extracts_cves_from_reference_urls(self) -> None:
        output = (
            '{"template-id":"cve-test","host":"https://example.com",'
            '"matched-at":"https://example.com",'
            '"info":{"name":"Test finding","severity":"high",'
            '"reference":["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]}}'
        )

        result = NucleiTool().parse_output(output, "", 0)

        self.assertTrue(result.success)
        self.assertEqual(result.findings[0].cve_ids, ["CVE-2024-12345"])


class ExecutorTest(unittest.IsolatedAsyncioTestCase):
    async def test_missing_binary_returns_structured_result(self) -> None:
        executor = ToolExecutor(scope_manager=ScopeManager())
        result = await executor.execute(
            _MissingBinaryTool(),
            _DummyInput(target="example.com"),
            target="example.com",
        )

        self.assertFalse(result.success)
        self.assertIn("not found", result.error)
        self.assertEqual(result.return_code, -1)
        self.assertTrue(result.completed_at)


class SessionDatabaseTest(unittest.IsolatedAsyncioTestCase):
    async def test_session_manager_uses_primary_database_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(str(Path(tmp) / "cybermcp.db"))
            await db.init()
            try:
                manager = SessionManager(db)
                session = await manager.create_session(
                    name="phase1",
                    target="example.com",
                    scope=["example.com"],
                    scope_excludes=["admin.example.com"],
                )
                fetched = await manager.get_session(session.id)

                self.assertIsNotNone(fetched)
                assert fetched is not None
                self.assertEqual(fetched.scope, ["example.com"])
                self.assertEqual(fetched.scope_excludes, ["admin.example.com"])
            finally:
                await db.close()


if __name__ == "__main__":
    unittest.main()
