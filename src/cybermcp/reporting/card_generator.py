"""Vulnerability card generator — converts Findings to VulnCards with enrichment."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cybermcp.reporting.models import Finding, Severity, VulnCard
from cybermcp.reporting.scorer import CVSSScorer

__all__ = ["CardGenerator"]


class CardGenerator:
    """Converts raw Finding objects into enriched VulnCard objects."""

    @staticmethod
    def finding_to_card(
        finding: Finding,
        tool_name: str = "",
        endpoint: str = "",
        parameter: str = "",
        proof_of_concept: str = "",
        references: list[str] | None = None,
    ) -> VulnCard:
        cvss_score = finding.cvss_score
        cvss_vector = ""

        if cvss_score is None:
            score, vector, severity = CVSSScorer.auto_score(finding.title)
            if score > 0:
                cvss_score = score
                cvss_vector = vector
            else:
                cvss_score = _severity_to_default_score(finding.severity)
                cvss_vector = ""
        else:
            cvss_vector = ""

        return VulnCard(
            title=finding.title,
            severity=finding.severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=finding.description,
            affected_asset=finding.affected_asset,
            endpoint=endpoint,
            parameter=parameter,
            evidence=finding.evidence,
            proof_of_concept=proof_of_concept,
            remediation=finding.remediation,
            references=references or [],
            cve_ids=finding.cve_ids,
            tool_name=tool_name,
            found_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def findings_to_cards(
        findings: list[Finding],
        tool_name: str = "",
    ) -> list[VulnCard]:
        cards = [CardGenerator.finding_to_card(f, tool_name=tool_name) for f in findings]
        return CardGenerator.deduplicate(cards)

    @staticmethod
    def deduplicate(cards: list[VulnCard]) -> list[VulnCard]:
        seen: set[str] = set()
        unique: list[VulnCard] = []
        for card in cards:
            key = f"{card.title}|{card.affected_asset}|{card.endpoint}|{card.severity.value}"
            if key not in seen:
                seen.add(key)
                unique.append(card)
        return unique

    @staticmethod
    def group_by_severity(cards: list[VulnCard]) -> dict[Severity, list[VulnCard]]:
        groups: dict[Severity, list[VulnCard]] = {s: [] for s in Severity}
        for card in cards:
            groups[card.severity].append(card)
        return groups

    @staticmethod
    def group_by_host(cards: list[VulnCard]) -> dict[str, list[VulnCard]]:
        groups: dict[str, list[VulnCard]] = {}
        for card in cards:
            host = card.affected_asset or "unknown"
            groups.setdefault(host, []).append(card)
        return groups

    @staticmethod
    def group_by_category(cards: list[VulnCard]) -> dict[str, list[VulnCard]]:
        groups: dict[str, list[VulnCard]] = {}
        for card in cards:
            cat = _infer_category(card.title)
            groups.setdefault(cat, []).append(card)
        return groups

    @staticmethod
    def sort_by_severity(cards: list[VulnCard]) -> list[VulnCard]:
        return sorted(cards, key=lambda c: (c.severity.rank, -(c.cvss_score or 0)))


def _severity_to_default_score(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.0,
    }[severity]


_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "Injection": ["sqli", "sql injection", "command injection", "ldap injection", "xpath injection", "nosql injection"],
    "Cross-Site Scripting": ["xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"],
    "Authentication": ["auth bypass", "broken auth", "brute force", "credential", "session", "jwt"],
    "Access Control": ["idor", "privilege escalation", "access control", "unauthorized"],
    "Cryptography": ["weak crypto", "tls", "ssl", "certificate", "cipher"],
    "Server-Side Request Forgery": ["ssrf", "server-side request"],
    "XML External Entity": ["xxe", "xml external"],
    "Deserialization": ["deserialization", "deserialize"],
    "Remote Code Execution": ["rce", "remote code execution", "code execution"],
    "File Inclusion": ["lfi", "rfi", "file inclusion", "path traversal", "directory traversal"],
    "Information Disclosure": ["info disclosure", "information disclosure", "directory listing", "source code"],
    "Cross-Site Request Forgery": ["csrf", "cross-site request forgery"],
    "Denial of Service": ["dos", "denial of service", "resource exhaustion"],
    "Configuration": ["misconfiguration", "default credential", "hardcoded", "missing header", "cors"],
    "Network": ["open port", "dns", "subdomain", "zone transfer", "network"],
}


def _infer_category(title: str) -> str:
    lower = title.lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return category
    return "Other"
