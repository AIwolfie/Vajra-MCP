# Vajra MCP - Product Roadmap

This document outlines the milestones and roadmap targets leading toward a stable v1.0 and future feature updates.

---

## Milestone 1: v1.0 Release Candidate (RC)
* **Objective**: Standardize parser robustness, exception handling, and dependency tracking.
* **Key Tasks**:
  - Implement fallback regex matches for all JSON parsers (WPScan, WhatWeb, Feroxbuster) to handle malformed string outputs.
  - Standardize error return schemas on process crashes to ensure Claude Code receives clean context.
  - Implement memory safety checks for massive file ingestion.

---

## Milestone 2: Sandboxing & Containerization (Phase 4)
* **Objective**: Secure execution environments and automate tool dependency resolution.
* **Key Tasks**:
  - Support Docker-based tool execution: pull lightweight Alpine images on demand and run tools inside restricted containers.
  - Restrict network interfaces of container runtimes to prevent local network scanning unless explicitly authorized in the session scope.
  - Mount dynamic sessions directory into container instances to output artifacts seamlessly.

---

## Milestone 3: Real-Time Stream Parsing
* **Objective**: Enhance speed, memory efficiency, and workflow visibility.
* **Key Tasks**:
  - Refactor Nuclei and Katana parsers to use async generator chunk streams instead of loading entire logs into RAM.
  - Expose a SSE progress channel to stream findings live to Claude Code during long-running scans instead of blocking until process completion.

---

## Milestone 4: Advanced Scope Interception & Storage Lifecycle
* **Objective**: Strict operational control and automated storage cleanup.
* **Key Tasks**:
  - Automatically inject exclusion configurations (e.g. nuclei `-exclude-hosts`, katana `-field`) using scope targets.
  - Build database and disk pruning capabilities: expose `purge_session` and `rotate_logs` commands.
  - Support exporting structured JSON/Markdown reports to external platforms (DefectDojo, Jira).
