# Contributing to Vajra MCP

We welcome contributions! This document outlines guidelines for setting up your environment and submitting updates.

---

## 1. Development Environment Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/project/Vajra-MCP.git
   cd Vajra-MCP
   ```
2. Install in editable mode along with testing requirements:
   ```bash
   pip install -e .
   pip install psutil aiofiles pytest ruff build
   ```

---

## 2. Adding a New Tool Wrapper

Every tool wrapper must subclass `BaseTool` in `src/cybermcp/tools/base.py`:
1. Implement `build_command(self, input_data: BaseModel) -> list[str]`.
2. Implement `parse_output_file(self, stdout_path: str, stderr_path: str, return_code: int, complete: bool = True) -> ToolResult`.
3. Provide a fallback `parse_output(self, stdout: str, stderr: str, return_code: int)` mapping.
4. Set `docker_capable: bool = True` if verified to run inside Docker.

---

## 3. Coding Standards & Testing

* **Code Style**: We use `ruff` to lint and format python code. Run `ruff check src/` before submitting.
* **Testing**: All changes must be covered by unit or integration tests. Run the test suite:
  ```bash
  python -m unittest discover tests
  ```
