from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybermcp.config import get_config
from cybermcp.core.session import SessionManager
from cybermcp.db.database import Database
from cybermcp.db.models import ScanStatus
from cybermcp.reporting import HTMLReportGenerator, Report, ReportSummary
from cybermcp.tools.health import diagnostics, health_check
from cybermcp.tools.recon.httpx import HttpxTool
from cybermcp.tools.recon.katana import KatanaTool
from cybermcp.tools.recon.nmap import NmapTool
from cybermcp.tools.recon.wafw00f import Wafw00fTool
from cybermcp.tools.recon.whatweb import WhatWebTool
from cybermcp.tools.web.dalfox import DalfoxTool
from cybermcp.tools.web.feroxbuster import FeroxbusterTool
from cybermcp.tools.web.ffuf import FfufTool
from cybermcp.tools.web.nuclei import NucleiTool
from cybermcp.tools.web.testssl import TestsslTool
from cybermcp.tools.web.wpscan import WpscanTool


class ParserVerificationTest(unittest.TestCase):
    def test_nmap_parser_returns_normalized_schema(self) -> None:
        mock_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" start="1670000000" version="7.92">'
            '<host><status state="up" reason="localhost-response"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/>'
            '<hostnames><hostname name="localhost" type="user"/></hostnames>'
            '<ports>'
            '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4.41"/></port>'
            '</ports></host></nmaprun>'
        )
        res = NmapTool().parse_output(mock_xml, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "nmap")
        self.assertEqual(res.parsed_data["target"], "127.0.0.1")
        self.assertIn("metadata", res.parsed_data)
        self.assertIn("raw_file", res.parsed_data)
        self.assertTrue(len(res.parsed_data["findings"]) > 0)
        self.assertEqual(res.parsed_data["findings"][0]["title"], "Open port 80/tcp")

    def test_nuclei_parser_returns_normalized_schema(self) -> None:
        mock_jsonl = (
            '{"template-id":"git-config","host":"https://example.com","matched-at":"https://example.com/.git/config",'
            '"info":{"name":"Git Config Exposure","severity":"medium","description":"Git config exposed"}}'
        )
        res = NucleiTool().parse_output(mock_jsonl, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "nuclei")
        self.assertEqual(res.parsed_data["target"], "https://example.com")
        self.assertEqual(len(res.parsed_data["findings"]), 1)
        self.assertEqual(res.parsed_data["findings"][0]["severity"], "medium")

    def test_httpx_parser_returns_normalized_schema(self) -> None:
        mock_jsonl = (
            '{"url":"https://example.com","status_code":200,"title":"Example Domain","webserver":"Apache","tech":["PHP","jQuery"]}\n'
            '{"url":"https://api.example.com","status_code":401,"title":"API Access Denied","webserver":"nginx"}'
        )
        res = HttpxTool().parse_output(mock_jsonl, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "httpx")
        self.assertEqual(res.parsed_data["target"], "https://example.com")
        self.assertEqual(len(res.parsed_data["findings"]), 2)
        self.assertEqual(res.parsed_data["findings"][0]["affected_asset"], "https://example.com")

    def test_katana_parser_returns_normalized_schema(self) -> None:
        mock_jsonl = (
            '{"request":{"endpoint":"/admin","method":"GET"},"url":"https://example.com/admin"}\n'
            '{"request":{"endpoint":"/login","method":"POST"},"url":"https://example.com/login"}'
        )
        res = KatanaTool().parse_output(mock_jsonl, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "katana")
        self.assertEqual(res.parsed_data["target"], "https://example.com/admin")
        self.assertEqual(len(res.parsed_data["findings"]), 2)

    def test_ffuf_parser_returns_normalized_schema(self) -> None:
        mock_json = '{"commandline":"ffuf -u https://example.com/FUZZ","results":[{"url":"https://example.com/admin","status":200}]}'
        res = FfufTool().parse_output(mock_json, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "ffuf")
        self.assertEqual(res.parsed_data["target"], "https://example.com/admin")
        self.assertEqual(len(res.parsed_data["findings"]), 1)

    def test_feroxbuster_parser_returns_normalized_schema(self) -> None:
        mock_jsonl = '{"url":"https://example.com/images","status":200}\n{"url":"https://example.com/uploads","status":301}'
        res = FeroxbusterTool().parse_output(mock_jsonl, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "feroxbuster")
        self.assertEqual(res.parsed_data["target"], "https://example.com/images")
        self.assertEqual(len(res.parsed_data["findings"]), 2)

    def test_dalfox_parser_returns_normalized_schema(self) -> None:
        mock_jsonl = '{"type":"XSS","payload":"<script>alert(1)</script>","url":"https://example.com/search?q=xss","message":"Reflected XSS"}'
        res = DalfoxTool().parse_output(mock_jsonl, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "dalfox")
        self.assertEqual(res.parsed_data["target"], "https://example.com/search?q=xss")
        self.assertEqual(len(res.parsed_data["findings"]), 1)

    def test_wpscan_parser_returns_normalized_schema(self) -> None:
        mock_json = '{"target_url":"https://example.com/wp","vulnerabilities":[{"title":"WP Core RCE","fixed_in":"5.8.1","references":{"cve":["CVE-2021-1234"]}}]}'
        res = WpscanTool().parse_output(mock_json, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "wpscan")
        self.assertEqual(res.parsed_data["target"], "https://example.com/wp")
        self.assertEqual(len(res.parsed_data["findings"]), 1)

    def test_testssl_parser_fallback_returns_normalized_schema(self) -> None:
        mock_text = "Start 2026-06-05 for https://example.com\nTesting example.com\n  cipher_RC4: VULNERABLE"
        res = TestsslTool().parse_output(mock_text, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "testssl")
        self.assertEqual(res.parsed_data["target"], "https://example.com")
        self.assertEqual(len(res.parsed_data["findings"]), 1)

    def test_wafw00f_parser_returns_normalized_schema(self) -> None:
        mock_text = "Checking http://example.com\n[*] The site http://example.com is behind Cloudflare WAF"
        res = Wafw00fTool().parse_output(mock_text, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "wafw00f")
        self.assertEqual(res.parsed_data["target"], "http://example.com")
        self.assertEqual(len(res.parsed_data["findings"]), 1)

    def test_whatweb_parser_returns_normalized_schema(self) -> None:
        mock_json = '[{"target":"http://example.com","plugins":{"Apache":{"version":"2.4.41"},"PHP":{"version":"7.4.3"}}}]'
        res = WhatWebTool().parse_output(mock_json, "", 0)
        self.assertTrue(res.success)
        self.assertEqual(res.parsed_data["tool"], "whatweb")
        self.assertEqual(res.parsed_data["target"], "http://example.com")
        self.assertEqual(len(res.parsed_data["findings"]), 2)


class HealthDiagnosticsTest(unittest.IsolatedAsyncioTestCase):
    async def test_health_check_returns_valid_health_report_for_non_existent(self) -> None:
        res = await health_check("missing-pentest-tool-name-non-exist")
        self.assertEqual(res["tool"], "missing-pentest-tool-name-non-exist")
        self.assertFalse(res["installed"])
        self.assertEqual(res["version"], "unknown")
        self.assertEqual(res["path"], "")

    async def test_diagnostics_aggregates_health_for_all_priority_tools(self) -> None:
        res = await diagnostics()
        self.assertEqual(len(res), 15)
        tools = {r["tool"] for r in res}
        expected = {"subfinder", "nmap", "nuclei", "httpx", "testssl"}
        self.assertTrue(expected.issubset(tools))


class ArtifactStorageTest(unittest.IsolatedAsyncioTestCase):
    async def test_session_manager_creates_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = get_config()
            cfg.sessions_dir = str(Path(tmp) / "sessions")
            cfg.db_path = str(Path(tmp) / "data" / "vajra-mcp.db")
            cfg.ensure_dirs()

            db = Database(cfg.db_path)
            await db.init()
            try:
                manager = SessionManager(db)
                session = await manager.create_session(name="test-artifact-session")
                session_path = Path(cfg.sessions_dir) / session.id
                
                self.assertTrue(session_path.exists())
                self.assertTrue((session_path / "scans").exists())
                self.assertTrue((session_path / "screenshots").exists())
                self.assertTrue((session_path / "reports").exists())
                self.assertTrue((session_path / "artifacts").exists())
            finally:
                await db.close()


class ReportInventoriesTest(unittest.IsolatedAsyncioTestCase):
    async def test_html_report_incorporates_timeline_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = get_config()
            cfg.sessions_dir = str(Path(tmp) / "sessions")
            cfg.reports_dir = str(Path(tmp) / "reports")
            cfg.db_path = str(Path(tmp) / "data" / "vajra-mcp.db")
            cfg.ensure_dirs()

            db = Database(cfg.db_path)
            await db.init()

            import cybermcp.server as server_module
            server_module._db = db
            server_module._config = cfg
            server_module._session_manager = SessionManager(db)

            try:
                session = await server_module._session_manager.create_session(
                    name="test-report",
                    target="example.com",
                    scope=["example.com"]
                )
                
                # Mock scanning activity
                scan = await db.create_scan(session.id, "nmap", "example.com", {})
                await db.update_scan_status(scan.id, ScanStatus.RUNNING)
                await db.create_tool_run(
                    tool_name="nmap",
                    scan_id=scan.id,
                    command="nmap -sV example.com",
                    stdout="Open port 80/tcp",
                    stderr="",
                    return_code=0,
                    execution_time=2.4
                )
                await db.update_scan_status(scan.id, ScanStatus.COMPLETED)

                await db.create_finding(
                    session_id=session.id,
                    scan_id=scan.id,
                    title="Open port 80/tcp",
                    severity=server_module.DbSeverity.INFO,
                    description="Port 80 is open running Apache",
                    evidence="Apache 2.4",
                    affected_asset="example.com",
                )

                report, summary = await server_module._build_report(session.id)
                
                self.assertEqual(len(report.scan_history), 1)
                self.assertEqual(report.scan_history[0]["tool_name"], "nmap")
                self.assertTrue(len(report.scan_timeline) > 0)
                self.assertEqual(report.subdomain_inventory, ["example.com"])
                self.assertEqual(len(report.open_port_inventory), 1)
                self.assertEqual(report.open_port_inventory[0]["port"], 80)
                self.assertEqual(len(report.asset_inventory), 1)
                self.assertEqual(report.asset_inventory[0]["host"], "example.com")

                # Verify HTML Report compiling
                rendered_path = await HTMLReportGenerator().generate(report, str(Path(tmp) / "reports" / "report.html"))
                html = Path(rendered_path).read_text(encoding="utf-8")
                self.assertIn("Activity Timeline", html)
                self.assertIn("Asset Inventory", html)
                self.assertIn("Open Port Inventory", html)
                self.assertIn("Scan History & Tool Execution Summary", html)

            finally:
                await db.close()


class DoctorCLITest(unittest.TestCase):
    @patch("cybermcp.tools.health.diagnostics", new_callable=AsyncMock)
    @patch("rich.console.Console")
    def test_doctor_command_runs_successfully_and_prints_tables(self, mock_console: MagicMock, mock_diag: AsyncMock) -> None:
        mock_diag.return_value = [
            {
                "tool": "nmap",
                "installed": True,
                "version": "7.92",
                "path": "/usr/bin/nmap",
                "api_keys": {},
                "install_command": "sudo apt install nmap"
            }
        ]
        
        from cybermcp.__main__ import main
        with patch("sys.argv", ["vajra-mcp", "doctor"]):
            main()
            mock_diag.assert_called_once()
            # Ensure console print was called
            mock_console.return_value.print.assert_called()


if __name__ == "__main__":
    unittest.main()
