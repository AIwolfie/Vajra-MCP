"""Tool registry — singleton that tracks, discovers, and indexes all tool wrappers."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from threading import Lock
from typing import Any

from cybermcp.tools.base import BaseTool, ToolCategory

__all__ = ["ToolRegistry"]

logger = logging.getLogger("cybermcp.tools.registry")


class ToolRegistry:
    """Singleton registry for BaseTool instances."""

    _instance: ToolRegistry | None = None
    _lock: Lock = Lock()

    def __new__(cls) -> ToolRegistry:
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._tools: dict[str, BaseTool] = {}
                cls._instance = inst
            return cls._instance

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, tool: BaseTool) -> None:
        """Add *tool* to the registry, keyed by tool.name."""
        if not tool.name:
            raise ValueError("Tool must have a non-empty 'name' attribute")
        if tool.name in self._tools:
            logger.warning("Overwriting existing tool registration: %s", tool.name)
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s [%s]", tool.name, tool.category.value)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> BaseTool | None:
        """Return the tool registered under *name*, or None."""
        return self._tools.get(name)

    def list_tools(self, category: ToolCategory | None = None) -> list[dict[str, Any]]:
        """List tool metadata dicts, optionally filtered by category."""
        tools = self._tools.values()
        if category is not None:
            tools = [t for t in tools if t.category == category]
        return [t.get_tool_info() for t in sorted(tools, key=lambda t: t.name)]

    def list_available(self) -> list[dict[str, Any]]:
        """List metadata only for tools whose binary is installed."""
        return [
            t.get_tool_info()
            for t in sorted(self._tools.values(), key=lambda t: t.name)
            if t.is_available()
        ]

    def search(self, query: str) -> list[dict[str, Any]]:
        """Search tools by name, description, and tags (case-insensitive substring)."""
        q = query.lower()
        results: list[dict[str, Any]] = []
        for tool in self._tools.values():
            haystack = " ".join(
                [tool.name, tool.description, " ".join(tool.tags)]
            ).lower()
            if q in haystack:
                results.append(tool.get_tool_info())
        return sorted(results, key=lambda d: d["name"])

    def get_by_category(self, category: ToolCategory) -> list[BaseTool]:
        """Return all tool instances in *category*."""
        return [
            t for t in sorted(self._tools.values(), key=lambda t: t.name)
            if t.category == category
        ]

    @property
    def tool_count(self) -> int:
        return len(self._tools)

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def auto_discover(self) -> int:
        """Import all tool modules from category subdirectories under tools/.

        Each subdirectory (recon/, web/, etc.) is scanned for Python modules.
        Any module-level ``TOOLS`` list containing BaseTool instances is
        automatically registered.

        Returns:
            Number of newly registered tools.
        """
        tools_dir = Path(__file__).resolve().parent
        before = self.tool_count
        category_dirs = [
            d for d in tools_dir.iterdir()
            if d.is_dir() and not d.name.startswith("_")
        ]

        for cat_dir in category_dirs:
            package_name = f"cybermcp.tools.{cat_dir.name}"
            try:
                package = importlib.import_module(package_name)
            except ImportError as exc:
                logger.debug("Skipping package %s: %s", package_name, exc)
                continue

            for importer, mod_name, is_pkg in pkgutil.iter_modules(
                package.__path__, prefix=f"{package_name}."
            ):
                try:
                    mod = importlib.import_module(mod_name)
                except Exception as exc:
                    logger.warning("Failed to import %s: %s", mod_name, exc)
                    continue

                # Convention: a module exports TOOLS = [ToolClass(), ...]
                tools_list = getattr(mod, "TOOLS", None)
                if tools_list and isinstance(tools_list, (list, tuple)):
                    for tool in tools_list:
                        if isinstance(tool, BaseTool):
                            self.register(tool)

                # Also pick up any BaseTool subclass instantiated at module level
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name)
                    if (
                        isinstance(obj, BaseTool)
                        and obj.name
                        and obj.name not in self._tools
                    ):
                        self.register(obj)

        discovered = self.tool_count - before
        logger.info("Auto-discovery registered %d new tools", discovered)
        return discovered

    # ------------------------------------------------------------------
    # Reset (testing)
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all registered tools. Intended for test isolation."""
        self._tools.clear()

    @classmethod
    def reset_singleton(cls) -> None:
        """Destroy the singleton instance. Test-only."""
        with cls._lock:
            cls._instance = None
