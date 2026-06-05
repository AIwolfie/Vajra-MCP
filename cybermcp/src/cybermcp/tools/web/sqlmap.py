"""SQLMap — automatic SQL injection detection and exploitation."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from cybermcp.tools.base import BaseTool, Finding, Severity, ToolCategory, ToolResult

__all__ = ["SqlmapTool"]


class SqlmapInput(BaseModel):
    url: str = Field(..., description="Target URL with injectable parameter")
    data: str | None = Field(None, description="POST body data string")
    cookie: str | None = Field(None, description="HTTP cookie header value")
    method: str | None = Field(None, description="Force HTTP method (GET/POST/PUT)")
    dbms: str | None = Field(None, description="Force back-end DBMS (mysql/mssql/oracle/pgsql/sqlite)")
    level: int = Field(1, ge=1, le=5, description="Level of tests (1-5)")
    risk: int = Field(1, ge=1, le=3, description="Risk of tests (1-3)")
    tamper: str | None = Field(None, description="Tamper script(s), comma-separated")
    batch: bool = Field(True, description="Non-interactive mode, use defaults")
    forms: bool = Field(False, description="Parse and test forms on target URL")
    crawl: int | None = Field(None, description="Crawl depth from target URL")
    threads: int | None = Field(None, ge=1, le=10, description="Number of concurrent threads")


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = "Automatic SQL injection detection and exploitation tool"
    category = ToolCategory.WEB
    binary_name = "sqlmap"
    tags = ["sqli", "injection", "database", "web"]
    input_model = SqlmapInput

    def build_command(self, input_model: SqlmapInput) -> list[str]:
        cmd = [self.get_binary_path(), "-u", input_model.url]

        if input_model.data:
            cmd.extend(["--data", input_model.data])
        if input_model.cookie:
            cmd.extend(["--cookie", input_model.cookie])
        if input_model.method:
            cmd.extend(["--method", input_model.method.upper()])
        if input_model.dbms:
            cmd.extend(["--dbms", input_model.dbms])
        if input_model.level != 1:
            cmd.extend(["--level", str(input_model.level)])
        if input_model.risk != 1:
            cmd.extend(["--risk", str(input_model.risk)])
        if input_model.tamper:
            cmd.extend(["--tamper", input_model.tamper])
        if input_model.batch:
            cmd.append("--batch")
        if input_model.forms:
            cmd.append("--forms")
        if input_model.crawl is not None:
            cmd.extend(["--crawl", str(input_model.crawl)])
        if input_model.threads is not None:
            cmd.extend(["--threads", str(input_model.threads)])

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ToolResult:
        findings: list[Finding] = []
        parsed: dict[str, Any] = {
            "injectable_params": [],
            "databases": [],
            "tables": [],
            "payloads": [],
        }

        # Extract injectable parameters
        param_pattern = re.compile(
            r"Parameter:\s+([^\s]+)\s+\(([^)]+)\)", re.IGNORECASE
        )
        for m in param_pattern.finditer(stdout):
            param_name = m.group(1)
            injection_type = m.group(2)
            parsed["injectable_params"].append(
                {"parameter": param_name, "type": injection_type}
            )
            findings.append(
                Finding(
                    title=f"SQL Injection in parameter '{param_name}'",
                    severity=Severity.CRITICAL,
                    description=f"SQL injection vulnerability found via {injection_type}",
                    evidence=m.group(0),
                    remediation="Use parameterized queries / prepared statements",
                    affected_asset=param_name,
                )
            )

        # Extract payload lines
        payload_pattern = re.compile(r"Payload:\s+(.+)")
        for m in payload_pattern.finditer(stdout):
            parsed["payloads"].append(m.group(1).strip())

        # Extract database names
        db_pattern = re.compile(r"available databases\s*\[\d+\]:\s*\n((?:\[\*\]\s+.+\n?)+)", re.IGNORECASE)
        db_match = db_pattern.search(stdout)
        if db_match:
            for line in db_match.group(1).splitlines():
                db_name = line.strip().lstrip("[*]").strip()
                if db_name:
                    parsed["databases"].append(db_name)

        # Fallback: individual db lines
        if not parsed["databases"]:
            for line in stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("[*]") and "database" not in stripped.lower():
                    val = stripped.lstrip("[*]").strip()
                    if val and not val.startswith("--"):
                        parsed["databases"].append(val)

        # Extract tables
        table_pattern = re.compile(
            r"Database:\s+(\S+)\s*\n.*?(\d+)\s+tables?\s*\n((?:\|.+\n?)+)",
            re.IGNORECASE,
        )
        for m in table_pattern.finditer(stdout):
            db = m.group(1)
            for line in m.group(3).splitlines():
                table = line.strip().strip("|").strip()
                if table and table != "-" * len(table):
                    parsed["tables"].append({"database": db, "table": table})

        # Detect back-end DBMS
        dbms_match = re.search(r"back-end DBMS:\s+(.+)", stdout, re.IGNORECASE)
        if dbms_match:
            parsed["dbms"] = dbms_match.group(1).strip()

        success = bool(findings) or return_code == 0
        error = stderr.strip() if return_code != 0 and not findings else ""

        return ToolResult(
            tool_name=self.name,
            success=success,
            raw_output=stdout,
            parsed_data=parsed,
            findings=findings,
            error=error,
        )


TOOLS = [SqlmapTool()]
