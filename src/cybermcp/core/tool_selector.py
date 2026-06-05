"""Intelligent tool selector — recommends tools based on target profile and objective."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from cybermcp.core.target_analyzer import TargetProfile, TargetType

__all__ = ["ToolRecommendation", "ToolSelector"]


class ToolRecommendation(BaseModel):
    """A recommended tool with priority and rationale."""

    tool_name: str
    priority: int = Field(ge=1, le=10, description="1=highest priority, 10=lowest")
    rationale: str
    estimated_time: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    category: str = ""


# Decision matrices mapping conditions to tool recommendations.
# Each entry: (tool_name, priority, rationale, estimated_time, category)

_SERVICE_TOOLS: dict[str, list[tuple[str, int, str, str, str]]] = {
    "ssh": [
        ("ssh-audit", 2, "SSH config and algorithm audit", "30s", "network"),
    ],
    "ftp": [
        ("nmap", 3, "FTP anonymous login and bounce check via NSE", "30s", "network"),
    ],
    "smb": [
        ("enum4linux", 2, "SMB/NetBIOS enumeration — shares, users, groups", "60s", "network"),
        ("smbclient", 4, "Manual SMB share listing", "30s", "network"),
        ("crackmapexec", 3, "SMB credential testing and enumeration", "60s", "network"),
    ],
    "snmp": [
        ("snmpwalk", 3, "SNMP community string walk", "60s", "network"),
        ("onesixtyone", 2, "SNMP community string brute-force", "30s", "network"),
    ],
    "rdp": [
        ("nmap", 4, "RDP NSE scripts — encryption, NLA check", "30s", "network"),
    ],
    "mysql": [
        ("nmap", 3, "MySQL NSE enum scripts", "30s", "network"),
    ],
    "mssql": [
        ("nmap", 3, "MSSQL NSE enum scripts", "30s", "network"),
        ("crackmapexec", 4, "MSSQL credential testing", "60s", "network"),
    ],
    "postgresql": [
        ("nmap", 4, "PostgreSQL NSE scripts", "30s", "network"),
    ],
    "redis": [
        ("nmap", 2, "Redis info and config dump via NSE", "20s", "network"),
    ],
    "dns": [
        ("dnsrecon", 2, "DNS enumeration — zone transfer, records", "60s", "recon"),
        ("dig", 4, "Manual DNS queries", "10s", "recon"),
    ],
    "smtp": [
        ("nmap", 3, "SMTP user enum via VRFY/EXPN NSE", "30s", "network"),
        ("smtp-user-enum", 2, "SMTP user enumeration", "60s", "network"),
    ],
    "ldap": [
        ("ldapsearch", 3, "LDAP anonymous bind and enumeration", "60s", "network"),
    ],
    "vnc": [
        ("nmap", 3, "VNC auth-bypass NSE scripts", "30s", "network"),
    ],
}

_TECH_TOOLS: dict[str, list[tuple[str, int, str, str, str]]] = {
    "wordpress": [
        ("wpscan", 1, "WordPress vulnerability scanner — plugins, themes, users", "120s", "web"),
    ],
    "drupal": [
        ("droopescan", 2, "Drupal vulnerability and version scanner", "60s", "web"),
    ],
    "joomla": [
        ("joomscan", 2, "Joomla vulnerability scanner", "60s", "web"),
    ],
    "nginx": [
        ("nuclei", 3, "Nginx-specific misconfig templates", "60s", "web"),
    ],
    "apache": [
        ("nuclei", 3, "Apache-specific misconfig templates", "60s", "web"),
        ("nikto", 4, "Apache misconfig and default-file check", "90s", "web"),
    ],
    "iis": [
        ("nuclei", 3, "IIS-specific templates", "60s", "web"),
        ("nikto", 4, "IIS misconfig check", "90s", "web"),
    ],
    "tomcat": [
        ("nuclei", 2, "Tomcat manager and default-cred templates", "60s", "web"),
    ],
    "php": [
        ("nuclei", 4, "PHP-specific vuln templates", "60s", "web"),
    ],
    "asp.net": [
        ("nuclei", 4, "ASP.NET misconfig templates", "60s", "web"),
    ],
}

_OBJECTIVE_CHAINS: dict[str, list[tuple[str, int, str, str, str]]] = {
    "recon": [
        ("subfinder", 1, "Passive subdomain enumeration", "60s", "recon"),
        ("amass", 2, "Active/passive subdomain enumeration", "180s", "recon"),
        ("nmap", 1, "Port scanning and service detection", "120s", "recon"),
        ("whatweb", 3, "Web technology fingerprinting", "30s", "recon"),
        ("wafw00f", 4, "WAF detection", "15s", "recon"),
        ("dnsx", 5, "DNS resolution and probing", "30s", "recon"),
        ("httpx", 3, "HTTP probing and tech detection", "30s", "recon"),
    ],
    "vuln-scan": [
        ("nuclei", 1, "Template-based vulnerability scanner", "300s", "vuln"),
        ("nikto", 3, "Web server scanner", "120s", "vuln"),
        ("nmap", 2, "NSE vulnerability scripts", "120s", "vuln"),
        ("searchsploit", 4, "Exploit-DB offline search", "10s", "vuln"),
    ],
    "web-audit": [
        ("nuclei", 1, "Template-based web vuln scan", "300s", "web"),
        ("nikto", 3, "Web misconfig scanner", "120s", "web"),
        ("ffuf", 2, "Directory and file brute-force", "120s", "web"),
        ("katana", 2, "Web crawling and endpoint discovery", "90s", "web"),
        ("sqlmap", 4, "SQL injection testing", "180s", "web"),
        ("dalfox", 4, "XSS scanner", "120s", "web"),
        ("testssl", 5, "SSL/TLS configuration audit", "60s", "web"),
        ("arjun", 5, "Hidden parameter discovery", "60s", "web"),
    ],
    "exploit": [
        ("searchsploit", 1, "Exploit-DB search for known CVEs", "10s", "exploit"),
        ("msfconsole", 2, "Metasploit exploit module search", "30s", "exploit"),
        ("msfvenom", 3, "Payload generation", "15s", "exploit"),
    ],
    "full-audit": [
        ("nmap", 1, "Full port scan with service/OS detection", "300s", "recon"),
        ("nuclei", 1, "Full template vulnerability scan", "300s", "vuln"),
        ("nikto", 3, "Web server audit", "120s", "web"),
        ("ffuf", 3, "Directory brute-force", "120s", "web"),
        ("searchsploit", 4, "Exploit search for discovered services", "10s", "exploit"),
        ("testssl", 5, "TLS audit", "60s", "web"),
    ],
}


class ToolSelector:
    """Recommends tools based on target profile, objective, and availability."""

    def __init__(self, tool_registry: Any | None = None) -> None:
        self._registry = tool_registry

    def select_tools(
        self,
        profile: TargetProfile,
        objective: str = "full-audit",
        max_tools: int = 10,
    ) -> list[ToolRecommendation]:
        """Build a prioritized tool list for the given profile and objective."""
        recommendations: dict[str, ToolRecommendation] = {}

        # 1. Objective-based chain
        chain = _OBJECTIVE_CHAINS.get(objective, _OBJECTIVE_CHAINS["full-audit"])
        for tool_name, priority, rationale, est, category in chain:
            self._add(recommendations, tool_name, priority, rationale, est, category)

        # 2. Service-specific tools
        for port_info in profile.open_ports:
            svc = port_info.service.lower()
            for svc_key, tools in _SERVICE_TOOLS.items():
                if svc_key in svc:
                    for tool_name, priority, rationale, est, category in tools:
                        self._add(recommendations, tool_name, priority, rationale, est, category)

        # 3. Technology-specific tools
        all_tech = " ".join(profile.technologies).lower()
        if profile.cms_detected:
            all_tech += " " + profile.cms_detected.lower()
        for tech_key, tools in _TECH_TOOLS.items():
            if tech_key in all_tech:
                for tool_name, priority, rationale, est, category in tools:
                    self._add(recommendations, tool_name, priority, rationale, est, category)

        # 4. Target-type adjustments
        if profile.target_type in (TargetType.URL, TargetType.DOMAIN):
            has_web = any(p.port in (80, 443, 8080, 8443) for p in profile.open_ports)
            if has_web:
                self._add(recommendations, "katana", 3, "Web crawling for the target", "90s", "web")
                self._add(recommendations, "httpx", 4, "HTTP probing", "30s", "recon")

        if profile.target_type == TargetType.CIDR:
            self._add(recommendations, "masscan", 1, "Fast port scan across CIDR", "120s", "recon")
            self._add(recommendations, "nmap", 2, "Service detection on live hosts", "180s", "recon")

        # 5. WAF-aware adjustments
        if profile.waf_detected:
            self._add(recommendations, "wafw00f", 5, f"Confirm WAF: {profile.waf_detected}", "15s", "recon")

        # 6. Filter by availability
        if self._registry:
            available = {name for name in recommendations if self._is_available(name)}
            recommendations = {k: v for k, v in recommendations.items() if k in available}

        # Sort by priority (ascending = highest first), truncate
        sorted_recs = sorted(recommendations.values(), key=lambda r: r.priority)
        return sorted_recs[:max_tools]

    def _add(
        self,
        recs: dict[str, ToolRecommendation],
        tool_name: str,
        priority: int,
        rationale: str,
        estimated_time: str,
        category: str,
    ) -> None:
        """Add or upgrade a recommendation — keep the higher-priority entry."""
        existing = recs.get(tool_name)
        if existing is None or priority < existing.priority:
            recs[tool_name] = ToolRecommendation(
                tool_name=tool_name,
                priority=priority,
                rationale=rationale,
                estimated_time=estimated_time,
                category=category,
            )

    def _is_available(self, tool_name: str) -> bool:
        """Check if a tool is registered and executable."""
        if not self._registry:
            return True
        try:
            return self._registry.get(tool_name) is not None
        except Exception:
            return False
