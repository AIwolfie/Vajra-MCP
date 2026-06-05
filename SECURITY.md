# Security Policy - Vajra MCP

This document details security boundaries, command injection mitigations, and procedures for reporting vulnerabilities.

---

## 1. Security Boundaries

Vajra MCP executes command-line security scanners on behalf of the user. Because these scanners make outbound network requests and parse untrusted inputs, they present distinct threat vectors.

### 1.1. Native Execution Mode
* **Risk**: Subprocesses inherit the security context, user ID, and network permissions of the Vajra MCP server. A malicious target returning structured overflow payloads could exploit binary parsing vulnerabilities.
* **Mitigation**: Run Vajra MCP under a dedicated, low-privilege user account.

### 1.2. Docker Execution Mode (Recommended)
* **Design**: Restricts execution within containers. Host workspace mounts are mapped directly to `/workspace` inside the container.
* **Mitigation**: Constrain memory limits (`max_memory_mb`) and restrict networking namespaces of container engines where possible.

---

## 2. Command Injection & Sanitization

* Target inputs passed to tools are sanitized via `sanitize_target` to strip shell metacharacters and format domains, URLs, or IPs cleanly.
* We invoke subprocesses using `asyncio.create_subprocess_exec` passing commands as a list of argument tokens. We do NOT run commands inside shells (`shell=True`), which mitigates traditional shell command injection.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability, do not open a public issue. Please report it privately to the maintainers or security contacts specified in the repository configuration.
