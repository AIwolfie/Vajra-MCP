"""Crypto helpers — session IDs, finding dedup hashes, API tokens."""

import hashlib
import json
import secrets
import uuid
from typing import Any


def generate_session_id() -> str:
    """Generate a hex session ID from uuid4."""
    return uuid.uuid4().hex


def hash_finding(finding: dict[str, Any]) -> str:
    """SHA-256 hash of a finding dict for deduplication.

    Uses a stable JSON serialization (sorted keys, no whitespace).
    """
    canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def generate_api_token() -> str:
    """Generate a URL-safe API token (32 bytes of randomness)."""
    return secrets.token_urlsafe(32)


__all__ = ["generate_session_id", "hash_finding", "generate_api_token"]
