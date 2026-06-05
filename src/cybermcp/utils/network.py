"""Network helper utilities — resolution, CIDR expansion, target parsing."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from cybermcp.utils.sanitizer import validate_cidr, validate_domain, validate_ip, validate_url

# RFC 1918 + loopback + link-local
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class TargetSpec:
    """Parsed representation of a user-supplied target string."""

    type: Literal["ip", "domain", "cidr", "url"]
    value: str
    port: int | None = None
    protocol: str | None = None


def resolve_domain(domain: str) -> list[str]:
    """Resolve a domain to its A/AAAA records. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen: set[str] = set()
        ips: list[str] = []
        for family, _, _, _, sockaddr in results:
            addr = sockaddr[0]
            if addr not in seen:
                seen.add(addr)
                ips.append(addr)
        return ips
    except socket.gaierror:
        return []


def is_private_ip(ip: str) -> bool:
    """Return True if *ip* falls within a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def cidr_to_ip_list(cidr: str, max_ips: int = 256) -> list[str]:
    """Expand a CIDR block into individual host IPs, capped at *max_ips*."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return []

    hosts: list[str] = []
    for host in network.hosts():
        if len(hosts) >= max_ips:
            break
        hosts.append(str(host))
    return hosts


def get_ip_info(ip: str) -> dict[str, str | bool]:
    """Basic local info about an IP — version, private/public, reverse DNS."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"error": f"invalid IP: {ip}"}

    info: dict[str, str | bool] = {
        "ip": str(addr),
        "version": addr.version,
        "is_private": any(addr in net for net in _PRIVATE_NETWORKS),
        "is_loopback": addr.is_loopback,
        "is_multicast": addr.is_multicast,
    }

    try:
        hostname, _, _ = socket.gethostbyaddr(str(addr))
        info["reverse_dns"] = hostname
    except (socket.herror, socket.gaierror):
        info["reverse_dns"] = ""

    return info


def parse_target(target: str) -> TargetSpec:
    """Parse a raw target string into a typed TargetSpec.

    Supports: bare IP, domain, CIDR, or full URL.
    """
    target = target.strip()

    # URL first — has scheme
    if "://" in target:
        if validate_url(target):
            parsed = urlparse(target)
            return TargetSpec(
                type="url",
                value=target,
                port=parsed.port,
                protocol=parsed.scheme,
            )
        raise ValueError(f"invalid URL: {target}")

    # CIDR — contains /
    if "/" in target:
        if validate_cidr(target):
            return TargetSpec(type="cidr", value=target)
        raise ValueError(f"invalid CIDR: {target}")

    # Strip optional port (host:port)
    host = target
    port: int | None = None
    if ":" in target and not target.startswith("["):
        # IPv4:port or domain:port
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    # IP
    if validate_ip(host):
        return TargetSpec(type="ip", value=host, port=port)

    # Domain
    if validate_domain(host):
        return TargetSpec(type="domain", value=host, port=port)

    raise ValueError(f"cannot parse target: {target}")


__all__ = [
    "TargetSpec",
    "resolve_domain",
    "is_private_ip",
    "cidr_to_ip_list",
    "get_ip_info",
    "parse_target",
]
