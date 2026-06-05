"""Input sanitization and validation for targets and command arguments."""

import ipaddress
import re
import shlex
from urllib.parse import urlparse

# Characters that must never appear in shell arguments
_SHELL_DANGEROUS = set(";|&$`\\!{}()[]<>\n\r\x00")

# Domain label regex per RFC 1123
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Loose URL scheme whitelist
_ALLOWED_SCHEMES = {"http", "https", "ftp", "ftps", "ssh"}


def sanitize_target(target: str) -> str:
    """Validate and normalize a target string (IP, domain, CIDR, or URL).

    Strips whitespace, rejects embedded shell metacharacters.
    Returns cleaned string or raises ValueError.
    """
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if any(c in _SHELL_DANGEROUS for c in target):
        raise ValueError(f"target contains disallowed characters: {target!r}")
    # Basic length sanity
    if len(target) > 2048:
        raise ValueError("target exceeds 2048 characters")
    return target


def sanitize_command_arg(arg: str) -> str:
    """Sanitize a single CLI argument to prevent injection.

    Rejects args containing shell metacharacters.
    Returns the arg unchanged if safe.
    """
    arg = arg.strip()
    if not arg:
        raise ValueError("empty argument")
    if any(c in _SHELL_DANGEROUS for c in arg):
        raise ValueError(f"argument contains disallowed characters: {arg!r}")
    if len(arg) > 4096:
        raise ValueError("argument exceeds 4096 characters")
    return arg


def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Return True if *domain* looks like a valid FQDN."""
    domain = domain.strip().rstrip(".")
    if len(domain) > 253:
        return False
    return _DOMAIN_RE.match(domain) is not None


def validate_cidr(cidr: str) -> bool:
    """Return True if *cidr* is a valid IPv4 or IPv6 network in CIDR notation."""
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False


def validate_url(url: str) -> bool:
    """Return True if *url* has an allowed scheme and a hostname."""
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in _ALLOWED_SCHEMES and bool(parsed.hostname)
    except Exception:
        return False


__all__ = [
    "sanitize_target",
    "sanitize_command_arg",
    "validate_ip",
    "validate_domain",
    "validate_cidr",
    "validate_url",
]
