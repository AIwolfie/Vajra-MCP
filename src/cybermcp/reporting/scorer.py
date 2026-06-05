"""CVSS v3.1 scoring engine — vector parsing, score calculation, severity rating."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any

from cybermcp.reporting.models import Severity

__all__ = ["CVSSScorer", "CVSSVector"]

# ---------------------------------------------------------------------------
# CVSS v3.1 metric value tables (ISS weights from spec)
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_S = {"U": False, "C": True}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass
class CVSSVector:
    """Parsed CVSS v3.1 base vector."""

    av: str = "N"   # Attack Vector
    ac: str = "L"   # Attack Complexity
    pr: str = "N"   # Privileges Required
    ui: str = "N"   # User Interaction
    s: str = "U"    # Scope
    c: str = "H"    # Confidentiality
    i: str = "H"    # Integrity
    a: str = "H"    # Availability

    def to_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
            f"/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    @classmethod
    def from_string(cls, vector: str) -> CVSSVector:
        parts: dict[str, str] = {}
        for segment in vector.split("/"):
            if ":" in segment:
                key, val = segment.split(":", 1)
                parts[key.upper()] = val.upper()

        return cls(
            av=parts.get("AV", "N"),
            ac=parts.get("AC", "L"),
            pr=parts.get("PR", "N"),
            ui=parts.get("UI", "N"),
            s=parts.get("S", "U"),
            c=parts.get("C", "H"),
            i=parts.get("I", "H"),
            a=parts.get("A", "H"),
        )


# ---------------------------------------------------------------------------
# Default vectors for common vuln types
# ---------------------------------------------------------------------------

_DEFAULT_VECTORS: dict[str, CVSSVector] = {
    "sqli": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "sql_injection": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "xss": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "reflected_xss": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "stored_xss": CVSSVector(av="N", ac="L", pr="L", ui="R", s="C", c="L", i="L", a="N"),
    "dom_xss": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "ssrf": CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="N", a="N"),
    "rce": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "remote_code_execution": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "lfi": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "rfi": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "path_traversal": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "idor": CVSSVector(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N"),
    "csrf": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="N", i="H", a="N"),
    "xxe": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "open_redirect": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "deserialization": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "command_injection": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "ssti": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "auth_bypass": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "broken_auth": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "info_disclosure": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "information_disclosure": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "directory_listing": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "cors_misconfiguration": CVSSVector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="N", a="N"),
    "crlf_injection": CVSSVector(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"),
    "buffer_overflow": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "heap_overflow": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "use_after_free": CVSSVector(av="L", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "type_confusion": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "race_condition": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "privilege_escalation": CVSSVector(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="H"),
    "weak_crypto": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "hardcoded_credentials": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "default_credentials": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "missing_headers": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"),
    "tls_misconfiguration": CVSSVector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "dns_zone_transfer": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "subdomain_takeover": CVSSVector(av="N", ac="L", pr="N", ui="N", s="C", c="L", i="L", a="N"),
    "jwt_misconfiguration": CVSSVector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
}


class CVSSScorer:
    """CVSS v3.1 base-score calculator and vulnerability auto-scorer."""

    @staticmethod
    def calculate(vector: CVSSVector) -> float:
        scope_changed = _S[vector.s]
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

        iss = 1.0 - (
            (1.0 - _CIA[vector.c])
            * (1.0 - _CIA[vector.i])
            * (1.0 - _CIA[vector.a])
        )

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22 * _AV[vector.av] * _AC[vector.ac] * pr_table[vector.pr] * _UI[vector.ui]
        )

        if impact <= 0:
            return 0.0

        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        return math.ceil(score * 10) / 10

    @staticmethod
    def calculate_from_string(vector_string: str) -> float:
        vec = CVSSVector.from_string(vector_string)
        return CVSSScorer.calculate(vec)

    @staticmethod
    def severity_from_score(score: float) -> Severity:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score >= 0.1:
            return Severity.LOW
        return Severity.INFO

    @staticmethod
    def vector_from_metrics(
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "H",
    ) -> str:
        vec = CVSSVector(av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a)
        return vec.to_string()

    @staticmethod
    def auto_score(vuln_type: str) -> tuple[float, str, Severity]:
        """Return (score, vector_string, severity) for a known vuln type."""
        key = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
        vec = _DEFAULT_VECTORS.get(key)
        if vec is None:
            return 0.0, "", Severity.INFO
        score = CVSSScorer.calculate(vec)
        return score, vec.to_string(), CVSSScorer.severity_from_score(score)

    @staticmethod
    def known_types() -> list[str]:
        return sorted(_DEFAULT_VECTORS.keys())
