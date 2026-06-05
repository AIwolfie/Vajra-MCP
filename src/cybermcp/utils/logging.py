"""Structured logging with rich console handler."""

import logging
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_initialized = False


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging with rich output."""
    global _initialized
    if _initialized:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handler = RichHandler(
        console=_console,
        show_time=True,
        show_level=True,
        show_path=True,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        markup=True,
        log_time_format="[%Y-%m-%d %H:%M:%S]",
    )
    handler.setLevel(numeric_level)

    fmt = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%Y-%m-%d %H:%M:%S]",
    )
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(numeric_level)
    root.handlers.clear()
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    for name in ("asyncio", "aiosqlite", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)

    _initialized = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a named logger. Initializes logging on first call if needed."""
    if not _initialized:
        setup_logging()
    return logging.getLogger(name or "cybermcp")


__all__ = ["setup_logging", "get_logger"]
