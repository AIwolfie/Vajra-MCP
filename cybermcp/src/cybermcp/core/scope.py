"""Scope enforcement — CIDR, domain, subdomain, URL, and IP matching."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field

__all__ = ["ScopeDefinition", "ScopeManager"]


class ScopeDefinition(BaseModel):
    """Defines the authorized engagement scope."""

    targets: list[str] = Field(default_factory=list, description="IPs, CIDRs, domains, URLs")
    excludes: list[str] = Field(default_factory=list, description="Excluded targets")
    notes: str = ""


class ScopeManager:
    """Validates targets against defined scope before tool execution."""

    def __init__(self) -> None:
        self._scope: ScopeDefinition | None = None
        self._target_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._target_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        self._target_domains: list[str] = []
        self._target_urls: list[str] = []
        self._exclude_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._exclude_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        self._exclude_domains: list[str] = []

    def set_scope(
        self, targets: list[str], excludes: list[str] | None = None, notes: str = ""
    ) -> ScopeDefinition:
        """Parse and store scope definition."""
        excludes = excludes or []
        self._scope = ScopeDefinition(targets=targets, excludes=excludes, notes=notes)
        self._target_networks.clear()
        self._target_ips.clear()
        self._target_domains.clear()
        self._target_urls.clear()
        self._exclude_networks.clear()
        self._exclude_ips.clear()
        self._exclude_domains.clear()

        for t in targets:
            self._classify_and_store(t, exclude=False)
        for e in excludes:
            self._classify_and_store(e, exclude=True)

        return self._scope

    def _classify_and_store(self, entry: str, *, exclude: bool) -> None:
        """Classify an entry as IP, CIDR, domain, or URL and store it."""
        entry = entry.strip()
        if not entry:
            return

        # Try CIDR first
        if "/" in entry and not entry.startswith("http"):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if exclude:
                    self._exclude_networks.append(net)
                else:
                    self._target_networks.append(net)
                return
            except ValueError:
                pass

        # Try bare IP
        try:
            addr = ipaddress.ip_address(entry)
            if exclude:
                self._exclude_ips.append(addr)
            else:
                self._target_ips.append(addr)
            return
        except ValueError:
            pass

        # URL
        if entry.startswith(("http://", "https://")):
            if exclude:
                pass  # URL excludes handled at match time
            else:
                self._target_urls.append(entry)
            # Also extract domain from URL
            parsed = urlparse(entry)
            host = parsed.hostname or ""
            if host:
                if exclude:
                    self._exclude_domains.append(host.lower())
                else:
                    self._target_domains.append(host.lower())
            return

        # Treat as domain
        if exclude:
            self._exclude_domains.append(entry.lower())
        else:
            self._target_domains.append(entry.lower())

    def is_in_scope(self, target: str) -> bool:
        """Check if a target falls within scope and is not excluded."""
        if self._scope is None:
            return True  # No scope defined — everything permitted

        target = target.strip()
        if not target:
            return False

        # Check exclusions first
        if self._is_excluded(target):
            return False

        return self._matches_scope(target)

    @property
    def has_scope(self) -> bool:
        """Return True when an explicit scope has been configured."""
        return self._scope is not None

    def evaluate_target(self, target: str) -> dict[str, object]:
        """Return structured scope decision metadata for an MCP response."""
        if self._scope is None:
            return {
                "configured": False,
                "allowed": True,
                "target": target,
                "reason": "no_scope_configured",
                "in_scope": [],
                "excluded": [],
            }

        allowed = self.is_in_scope(target)
        reason = "allowed" if allowed else "out_of_scope"
        if target.strip() and self._is_excluded(target):
            reason = "excluded"

        return {
            "configured": True,
            "allowed": allowed,
            "target": target,
            "reason": reason,
            "in_scope": list(self._scope.targets),
            "excluded": list(self._scope.excludes),
        }

    def _matches_scope(self, target: str) -> bool:
        """Check if target matches any scope entry."""
        # Try as IP
        ip_addr = self._try_parse_ip(target)
        if ip_addr is not None:
            if ip_addr in self._target_ips:
                return True
            for net in self._target_networks:
                if ip_addr in net:
                    return True
            return False

        # Try as URL — extract host and match
        if target.startswith(("http://", "https://")):
            # Exact URL match
            for url in self._target_urls:
                if self._url_matches(target, url):
                    return True
            # Fall through to domain match on the hostname
            parsed = urlparse(target)
            host = parsed.hostname or ""
            if host:
                return self._domain_in_scope(host.lower())
            return False

        # Treat as domain
        return self._domain_in_scope(target.lower())

    def _is_excluded(self, target: str) -> bool:
        """Check if target is explicitly excluded."""
        ip_addr = self._try_parse_ip(target)
        if ip_addr is not None:
            if ip_addr in self._exclude_ips:
                return True
            for net in self._exclude_networks:
                if ip_addr in net:
                    return True
            return False

        # Extract hostname from URL if needed
        host = target
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host = parsed.hostname or target

        host = host.lower()
        for exc in self._exclude_domains:
            if host == exc or host.endswith("." + exc):
                return True
        return False

    def _domain_in_scope(self, domain: str) -> bool:
        """Check domain/subdomain match. foo.example.com matches example.com in scope."""
        for d in self._target_domains:
            if domain == d or domain.endswith("." + d):
                return True
        return False

    @staticmethod
    def _url_matches(candidate: str, scope_url: str) -> bool:
        """URL matching — candidate must be under the scope URL path."""
        c = urlparse(candidate)
        s = urlparse(scope_url)
        if (c.scheme or "https") != (s.scheme or "https"):
            return False
        if (c.hostname or "").lower() != (s.hostname or "").lower():
            return False
        if c.port != s.port:
            # Handle default ports
            c_port = c.port or (443 if c.scheme == "https" else 80)
            s_port = s.port or (443 if s.scheme == "https" else 80)
            if c_port != s_port:
                return False
        # Path prefix matching
        c_path = (c.path or "/").rstrip("/")
        s_path = (s.path or "/").rstrip("/")
        return c_path == s_path or c_path.startswith(s_path + "/") or s_path == ""

    @staticmethod
    def _try_parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Attempt to parse a string as an IP address."""
        # Strip URL wrapper
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            value = parsed.hostname or value
        # Strip port
        if ":" in value and not value.startswith("["):
            # Could be host:port for IPv4
            maybe_host = value.rsplit(":", 1)[0]
            try:
                return ipaddress.ip_address(maybe_host)
            except ValueError:
                pass
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def get_scope(self) -> ScopeDefinition | None:
        """Return the current scope definition."""
        return self._scope

    def describe(self) -> dict[str, object]:
        """Return current scope as JSON-serializable data."""
        if self._scope is None:
            return {
                "configured": False,
                "in_scope": [],
                "excluded": [],
                "notes": "",
            }
        return {
            "configured": True,
            "in_scope": list(self._scope.targets),
            "excluded": list(self._scope.excludes),
            "notes": self._scope.notes,
        }

    def clear_scope(self) -> None:
        """Remove all scope constraints."""
        self._scope = None
        self._target_networks.clear()
        self._target_ips.clear()
        self._target_domains.clear()
        self._target_urls.clear()
        self._exclude_networks.clear()
        self._exclude_ips.clear()
        self._exclude_domains.clear()
