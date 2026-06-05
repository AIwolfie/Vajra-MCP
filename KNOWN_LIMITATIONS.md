# Vajra MCP - Known Limitations & Design Boundaries

This document outlines structural, security, and runtime constraints inherent to the current architecture of Vajra MCP.

---

## 1. Security & Scope Boundaries

### 1.1. Dynamic Runtime Out-of-Scope Traversals
* **Limitation**: Vajra MCP checks and enforces target scopes *statically* before invoking a tool. If a web crawler like **Katana** or directory brute-forcer like **Feroxbuster** is launched against `https://example.com`, but follows redirects or links to `https://thirdparty.com`, the network requests will hit the off-scope target.
* **Workaround**: Users must configure strict crawler boundaries directly inside tool arguments (e.g. configuring Katana to stay within the target host).

### 1.2. Lack of Sandboxed Execution
* **Limitation**: Subprocesses run natively under the operating system user context running the Vajra MCP server. If an adversary compromises a third-party target and returns a payload that exploits a buffer overflow in one of the tools (e.g., Nmap or Nuclei), the host system could be compromised.
* **Workaround**: Deploy Vajra MCP inside an isolated VM, a lightweight Docker container, or an AWS Sandbox.

---

## 2. Resource & Storage Management

### 2.1. In-Memory Data Load for Large Scans
* **Limitation**: Scans yielding tens of megabytes of raw JSON/XML outputs (such as Nuclei scanning massive target lists) are loaded into RAM in their entirety as Python strings for parser processing. This can lead to system-wide out-of-memory crashes.
* **Workaround**: Limit concurrent execution tasks or target sub-list sizes.

### 2.2. No Automatic Storage Cleanup
* **Limitation**: Every session creates a persistent SQLite history and subdirectories (`scans/`, `artifacts/`, `reports/`) that are never automatically purged or rotated.
* **Workaround**: Implement manual cron-jobs to clean out `/sessions` periodically.

---

## 3. Tool Runtime Dependencies
* **Limitation**: Vajra MCP is an orchestrator, not a package manager. It does not install security binaries. Standard tools require multiple runtimes:
  - **Go**: subfinder, amass, assetfinder, httpx, katana, nuclei, ffuf, dalfox
  - **Python**: wafw00f, sqlmap
  - **Ruby**: whatweb, wpscan
  - **Bash/OpenSSL**: testssl.sh
* **Workaround**: Users must run `vajra-mcp doctor` and manually install missing dependencies using their respective runtime managers.
