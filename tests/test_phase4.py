import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cybermcp.config import get_config
from cybermcp.tools.base import BaseTool, ToolResult, Finding, Severity
from cybermcp.tools.executor import ToolExecutor
from cybermcp.tools.recon.nmap import NmapTool
from cybermcp.tools.web.nuclei import NucleiTool


class MockTool(BaseTool):
    name = "mocktool"
    description = "Mock Tool for Testing"
    binary_name = "mock"
    docker_capable = False

    def build_command(self, input_data) -> list[str]:
        return ["mock", "run"]

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            success=return_code == 0,
            parsed_data={"data": stdout},
        )


class Phase4HardeningTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.cfg = get_config()
        self.cfg.max_output_mb = 1
        self.cfg.max_memory_mb = 128
        self.cfg.execution_mode = "native"

    async def test_path_translation_for_docker(self) -> None:
        executor = ToolExecutor()
        tool = NucleiTool()
        tool.docker_capable = True
        
        self.cfg.execution_mode = "docker"
        
        with patch("cybermcp.tools.executor.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = MagicMock()
            mock_proc.stdout = asyncio.StreamReader()
            mock_proc.stderr = asyncio.StreamReader()
            mock_proc.returncode = 0
            
            async def mock_wait():
                return 0
            mock_proc.wait = mock_wait
            
            mock_exec.return_value = mock_proc
            
            # Put some dummy data in stream
            mock_proc.stdout.feed_data(b'{"template-id":"git-config","host":"https://example.com"}\n')
            mock_proc.stdout.feed_eof()
            mock_proc.stderr.feed_eof()
            
            # Run
            from cybermcp.tools.web.nuclei import NucleiInput
            res = await executor.execute(
                tool,
                NucleiInput(target="https://example.com"),
            )
            
            self.assertTrue(mock_exec.called)
            args = mock_exec.call_args[0]
            self.assertEqual(args[0], "docker")
            self.assertIn("run", args)
            self.assertIn("--memory", args)
            self.assertIn("projectdiscovery/nuclei:latest", args)

    async def test_docker_fallback_warning(self) -> None:
        executor = ToolExecutor()
        tool = MockTool()  # docker_capable is False
        
        self.cfg.execution_mode = "docker"
        
        with patch("cybermcp.tools.executor.asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = MagicMock()
            mock_proc.stdout = asyncio.StreamReader()
            mock_proc.stderr = asyncio.StreamReader()
            mock_proc.returncode = 0
            
            async def mock_wait():
                return 0
            mock_proc.wait = mock_wait
            mock_exec.return_value = mock_proc
            
            mock_proc.stdout.feed_eof()
            mock_proc.stderr.feed_eof()
            
            with patch.object(MockTool, "is_available", return_value=True):
                from pydantic import BaseModel
                class Args(BaseModel):
                    pass
                    
                res = await executor.execute(tool, Args())
                
                # Check warning in metadata
                self.assertIn("warning", res.parsed_data["metadata"])
                self.assertEqual(
                    res.parsed_data["metadata"]["warning"],
                    "Tool does not support Docker execution; falling back to native mode."
                )

    def test_nmap_incremental_parser_handles_truncated_xml(self) -> None:
        # Create truncated XML nmap output
        truncated_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sT example.com">\n'
            '<host>\n'
            '<status state="up" reason="localhost-response"/>\n'
            '<address addr="127.0.0.1" addrtype="ipv4"/>\n'
            '<ports>\n'
            '<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache" version="2.4.41"/></port>\n'
            '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
            # Truncated here!
        )
        
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "nmap_trunc.xml"
            out_file.write_text(truncated_xml, encoding="utf-8")
            
            tool = NmapTool()
            res = tool.parse_output_file(str(out_file), "", 0, complete=False)
            
            # The XML parsing raised ParseError, but the first host and port 80 are recovered!
            self.assertTrue(res.success)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].title, "Open port 80/tcp")
            self.assertEqual(res.parsed_data["target"], "127.0.0.1")
            self.assertTrue(res.parsed_data.get("partial"))

    def test_nuclei_incremental_parser_handles_truncated_jsonl(self) -> None:
        truncated_jsonl = (
            '{"template-id":"git-config","host":"https://example.com","matched-at":"https://example.com/.git/config","info":{"name":"Git Config","severity":"medium"}}\n'
            '{"template-id":"db-exposure","host":"https://example.com"'  # Truncated here!
        )
        
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "nuclei_trunc.jsonl"
            out_file.write_text(truncated_jsonl, encoding="utf-8")
            
            tool = NucleiTool()
            res = tool.parse_output_file(str(out_file), "", 0, complete=False)
            
            self.assertTrue(res.success)
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].title, "Git Config (git-config)")
            self.assertTrue(res.parsed_data.get("partial"))


if __name__ == "__main__":
    unittest.main()
