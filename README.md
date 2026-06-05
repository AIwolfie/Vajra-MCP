# Vajra MCP

Vajra MCP is a FastMCP execution backend for Claude Code security workflows.
Claude Code remains the reasoning and orchestration layer. Vajra MCP validates
scope, runs approved CLI tools, persists session evidence in SQLite, and returns
structured JSON.

The internal Python package is still `cybermcp` to avoid breaking imports during
the branding migration.

## Phase 2 Tooling

Recon tools:

- `subfinder`
- `amass`
- `assetfinder`
- `httpx`
- `katana`
- `nmap`
- `whatweb`
- `wafw00f`

Web tools:

- `nuclei`
- `ffuf`
- `feroxbuster`
- `dalfox`
- `sqlmap`
- `wpscan`
- `testssl`

Each tool inherits from `BaseTool`, executes through `ToolExecutor`, supports
timeouts, uses scope validation, reports binary availability, handles missing
binaries gracefully, and returns structured JSON.

## Install

```powershell
python -m pip install -e .
```

## Run As An MCP Server

For Claude Code, use stdio transport:

```powershell
vajra-mcp --transport stdio
```

The legacy entrypoint also remains available:

```powershell
cybermcp --transport stdio
```

## Claude Code Usage Examples

Set scope first:

```json
{
  "tool": "set_scope",
  "arguments": {
    "targets": ["example.com"],
    "excludes": ["admin.example.com"],
    "notes": "Authorized external assessment scope"
  }
}
```

List available priority tools:

```json
{
  "tool": "list_tools",
  "arguments": {
    "available_only": true
  }
}
```

Run a single tool:

```json
{
  "tool": "run_tool",
  "arguments": {
    "tool_name": "subfinder",
    "args": {
      "domain": "example.com"
    },
    "timeout": 120
  }
}
```

Run the direct `subfinder` MCP endpoint:

```json
{
  "tool": "subfinder",
  "arguments": {
    "domain": "example.com",
    "all_sources": false,
    "recursive": false,
    "timeout": 120
  }
}
```

## Ready-to-Use Claude Code Prompts

You can use the following prompts directly inside **Claude Code** to drive your security testing workflows:

1. **Reconnaissance & Active Target Profiling:**
   > "Vajra, run reconnaissance against example.com. Set the scope to example.com first, then run the auto_recon workflow with standard depth. Generate the HTML report when finished."

2. **Subdomain Enumeration & Scanning:**
   > "Enumerate subdomains for example.com. Use subfinder and assetfinder, check the scope, and probe all found subdomains with httpx to locate live services."

3. **Vulnerability Assessment:**
   > "Run nuclei against discovered hosts in the current session. Run with the default templates on target https://example.com, parse the findings, and check the timeline."

4. **Reporting and Artifact Extraction:**
   > "Generate report for current session. Retrieve the active session, check the timeline, list all open ports and technologies, and build the premium HTML report."

## Diagnostics (Vajra MCP Doctor)

Vajra MCP includes a `doctor` command-line diagnostic tool to verify your local configuration and priority binary installations.

To run diagnostics:
```powershell
vajra-mcp doctor
```

This will run self-checks on all 15 priority security tools, detect their versions, identify missing environment variables/API keys, and display recommended installation commands.

## Scan Artifact Storage

Vajra MCP automatically logs and organizes all scan files, console traces, screenshots, and HTML reports inside a structured workspace:

```text
sessions/
  <session-id>/
    scans/          <-- Consolidated console stdout/stderr/time log per tool execution (.log)
    screenshots/    <-- (Optional) Screen captures of target web interfaces
    reports/        <-- Final security assessment HTML reports
    artifacts/      <-- Raw XML/JSON output files saved directly from binaries (.xml, .json, .jsonl)
```

Parsed outputs returned to Claude Code contain direct file URI references in `raw_file`. Report files reference raw artifact paths and console logs.

Run recon workflow helper:

```json
{
  "tool": "auto_recon",
  "arguments": {
    "target": "example.com",
    "depth": "standard",
    "timeout": 180,
    "max_hosts": 25
  }
}
```

Run web audit workflow helper:

```json
{
  "tool": "web_audit",
  "arguments": {
    "target": "https://example.com",
    "checks": ["vuln", "content", "xss", "sqli", "tls"],
    "wordlist": "C:/wordlists/common.txt",
    "timeout": 300
  }
}
```

Generate an HTML report:

```json
{
  "tool": "generate_html_report",
  "arguments": {
    "session_id": ""
  }
}
```

## Structured Output Shape

Tool responses use a stable JSON envelope:

```json
{
  "status": "success",
  "session_id": "session-id",
  "scan_id": "scan-id",
  "tool_name": "subfinder",
  "scope": {
    "configured": true,
    "allowed": true,
    "target": "example.com",
    "reason": "allowed"
  },
  "execution": {
    "command": "subfinder -d example.com -silent",
    "return_code": 0,
    "started_at": "2026-06-05T00:00:00+00:00",
    "completed_at": "2026-06-05T00:00:01+00:00",
    "execution_time": 1.0
  },
  "result": {
    "success": true,
    "parsed_data": {
      "subdomains": ["api.example.com", "dev.example.com"],
      "count": 2
    },
    "findings": [],
    "raw_output": "api.example.com\ndev.example.com\n",
    "error": ""
  }
}
```

## Workflow Helpers

`auto_recon` and `web_audit` are deterministic workflow helpers. They do not
make decisions, create agents, or perform autonomous red-team activity. Claude
Code invokes them when it wants a fixed execution pipeline.

`auto_recon` runs:

1. `subfinder`
2. `amass`
3. `assetfinder`
4. `httpx`
5. `katana`
6. `whatweb`
7. `wafw00f`
8. `nmap`

`web_audit` runs selected checks from:

1. `nuclei`
2. `ffuf`
3. `feroxbuster`
4. `dalfox`
5. `sqlmap`
6. `wpscan`
7. `testssl`

Content discovery tools require a wordlist through the `wordlist` argument or
`CYBERMCP_DEFAULT_WORDLIST`.

## Configuration

Environment variables still use the `CYBERMCP_` prefix for compatibility:

- `CYBERMCP_TRANSPORT`
- `CYBERMCP_HOST`
- `CYBERMCP_PORT`
- `CYBERMCP_HTTP_API_KEY`
- `CYBERMCP_DEFAULT_WORDLIST`
- `CYBERMCP_TOOL_PATHS`

Default SQLite path:

```text
data/vajra-mcp.db
```

Default report directory:

```text
reports/
```
