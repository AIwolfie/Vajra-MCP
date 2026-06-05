"""Reporting data models — VulnCard, ReportSummary, Report."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "Severity",
    "Finding",
    "VulnCard",
    "ReportSummary",
    "Report",
    "TimelineEntry",
]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#ff4757",
            Severity.HIGH: "#ff6b35",
            Severity.MEDIUM: "#ffa502",
            Severity.LOW: "#2ed573",
            Severity.INFO: "#1e90ff",
        }[self]


class Finding(BaseModel):
    """Raw finding from a tool."""

    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    affected_asset: str = ""


class VulnCard(BaseModel):
    """Enriched vulnerability card for reporting."""

    title: str
    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str = ""
    description: str
    affected_asset: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    tool_name: str = ""
    found_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def severity_color(self) -> str:
        return self.severity.color

    @property
    def severity_label(self) -> str:
        return self.severity.value.upper()


class TimelineEntry(BaseModel):
    """Single event in a scan timeline."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool: str = ""
    event: str = ""
    details: str = ""


class ReportSummary(BaseModel):
    """Aggregate statistics for a report."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    unique_hosts: int = 0
    tools_used: list[str] = Field(default_factory=list)
    scan_duration: float = 0.0
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)

    @classmethod
    def from_cards(cls, cards: list[VulnCard]) -> ReportSummary:
        hosts: set[str] = set()
        tools: set[str] = set()
        counts = {s: 0 for s in Severity}

        for c in cards:
            counts[c.severity] += 1
            if c.affected_asset:
                hosts.add(c.affected_asset)
            if c.tool_name:
                tools.add(c.tool_name)

        total = len(cards)
        risk = min(
            10.0,
            (counts[Severity.CRITICAL] * 3.0
             + counts[Severity.HIGH] * 2.0
             + counts[Severity.MEDIUM] * 1.0
             + counts[Severity.LOW] * 0.3
             + counts[Severity.INFO] * 0.05),
        )

        return cls(
            total_findings=total,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            unique_hosts=len(hosts),
            tools_used=sorted(tools),
            risk_score=round(risk, 1),
        )


class Report(BaseModel):
    """Top-level report container."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = "CyberMCP Security Assessment Report"
    target: str = ""
    scope: str = ""
    summary: ReportSummary = Field(default_factory=ReportSummary)
    vuln_cards: list[VulnCard] = Field(default_factory=list)
    scan_timeline: list[TimelineEntry] = Field(default_factory=list)
    methodology: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def sorted_cards(self) -> list[VulnCard]:
        return sorted(self.vuln_cards, key=lambda c: c.severity.rank)
