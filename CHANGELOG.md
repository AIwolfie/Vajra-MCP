# Changelog - Vajra MCP

All notable changes to this project are documented in this file.

---

## [1.0.0] - 2026-06-05

This is the initial production-ready release of Vajra MCP, featuring structured parser interfaces, robust scan lifecycle logging, multi-format HTML reporting, execution sandboxing, and resource constraints.

### Added

#### Core Engine & Session Storage
* **SQLite Backend**: Integrated multi-table schema (`sessions`, `scans`, `tool_runs`, `findings`) with automatic migration capabilities.
* **Session Directory Management**: Automatically initializes structured subdirectories under `/sessions/<session-id>/` for `scans` (console logs), `screenshots`, `reports`, and `artifacts` (raw outputs).
* **CLI Doctor**: Added a standalone `doctor` utility (`python -m cybermcp doctor`) printing tool status, paths, versions, and API keys.

#### Structured Parsing
* **1.1 Native Parsers**: Replaced raw terminal text logging with native structured parser logic for:
  - Nmap (XML)
  - Nuclei (JSONL)
  - HTTPx (JSON)
  - Katana (JSONL)
  - FFUF (JSON)
  - Feroxbuster (JSON)
  - Dalfox (JSON)
  - WPScan (JSON)
  - TestSSL (JSON / Text fallback)
  - Wafw00f (Text pattern regex)
  - WhatWeb (JSON array/object)

#### Hardening & Resource Controls
* **Streaming execution**: Subprocesses write directly to file outputs, limiting RAM overhead to constant $O(1)$ sizes.
* **Size & Memory Limits**: Restricts execution sizes via `max_output_mb` and runs best-effort `psutil` parent/children RSS checks.
* **Docker execution backend**: Support running tools inside transient Docker containers with path-to-volume mappings.
* **Partial parsing**: Recovers data parsed before process timeouts, crashes, or limit terminations.
* **Truncated Nmap XML recovery**: Rebuilds elements using `iterparse` to capture open ports before file truncation.
