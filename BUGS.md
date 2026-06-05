# Vajra MCP - Bugs & Edge Case Vulnerabilities

This document details identified software bugs, parser vulnerabilities, and edge cases discovered during real-world validation of Vajra MCP.

---

## 1. Parser Resilience Issues

### 1.1. WPScan Non-JSON Failure Modes
* **Description**: If a target URL is not a WordPress site, or if WPScan encounters an authorization issue, it may return raw text containing ASCII tables or error logs instead of a valid JSON object.
* **Impact**: `json.loads(stdout)` raises `JSONDecodeError`, catching it safely but resulting in a completely empty `parsed_data["target"]` and setting `success` to `False` even if the tool ran completely without crashes.
* **Fix**: Fallback regex parsing to extract the target URL from the text body, similar to the TestSSL implementation.

### 1.2. WhatWeb Top-Level Array vs Object Schema
* **Description**: Depending on plugins activated, WhatWeb can return a nested JSON array of objects or, occasionally, a single object.
* **Impact**: If it returns a single dictionary object where a list is expected, it can cause `AttributeError` during iterations.
* **Fix**: Added validation helpers (`isinstance(..., list)`) to sanitize input, but schema shifts in plugins might still skip tech details.

### 1.3. Nmap XML Parsing of Empty Hosts
* **Description**: If Nmap runs against an offline host or a target protected by firewall filtering, the XML output contains no `<host>` blocks.
* **Impact**: `NmapTool.parse_output()` will return success, but `parsed_data["target"]` resolves to an empty string because the hostname parsing depends entirely on `<host>` elements.
* **Fix**: Pre-parse the target from the command args if XML host information is absent.

---

## 2. Shell Execution and Interoperability

### 2.1. Process Deadlock with High Output Volumes
* **Description**: Large-scale Nuclei or Katana scans that yield millions of lines of output can saturate the standard OS pipe buffer if stdout/stderr are not drained continuously.
* **Impact**: Standard library subprocess execution could block indefinitely waiting for the pipe to clear.
* **Fix**: Ensure that all priority wrappers leverage `asyncio.subprocess.PIPE` coupled with asynchronous `communicate()` or structured tempfile redirects.

### 2.2. ANSI Color Escapes Polluting Raw Outputs
* **Description**: If standard tools do not receive explicit disable-color flags (like `--color 0` in TestSSL or `-no-color` in Nuclei), they may write ASCII color escapes directly to stdout.
* **Impact**: Causes regex matches to fail and corrupts JSON/XML parsers.
* **Fix**: Standardize color suppression parameters across all tool wrappers.
