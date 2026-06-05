"""Input sanitization and validation for targets and command arguments."""

import ipaddress
import os
from pathlib import Path
import re
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


def validate_wordlist_path(path_str: str) -> str:
    """Validate that the wordlist path is safe and restricted to allowed directories.

    Allowed locations:
      - The project workspace (root) directory
      - The configured default wordlist directory
      - Explicitly allowed paths from environment (CYBERMCP_ALLOWED_WORDLIST_PATHS)

    Rejects absolute system paths outside allowed locations, path traversal, and symlink escapes.
    """
    if not path_str:
        raise ValueError("Wordlist path cannot be empty")

    path = Path(path_str)

    # Reject path traversal attempts
    if any(part == ".." for part in path.parts):
        raise ValueError(f"Path traversal detected in wordlist path: {path_str}")

    from cybermcp.config import get_config
    cfg = get_config()

    # Resolve project root
    project_root = Path(cfg.db_path).parent.parent.resolve()

    # Get absolute resolved path
    resolved_path = path.resolve()

    # Verify symlink escapes
    try:
        if path.exists() and path.is_symlink():
            link_target = Path(os.readlink(path)).resolve()
        else:
            link_target = resolved_path
    except Exception:
        link_target = resolved_path

    # Define allowed directories
    allowed_dirs = [project_root, Path.cwd().resolve()]

    if cfg.default_wordlist:
        dw_path = Path(cfg.default_wordlist).resolve()
        if dw_path.is_file():
            allowed_dirs.append(dw_path.parent)
        elif dw_path.is_dir():
            allowed_dirs.append(dw_path)

    allowed_paths_env = os.environ.get("CYBERMCP_ALLOWED_WORDLIST_PATHS", "")
    if allowed_paths_env:
        for p in allowed_paths_env.split(os.pathsep):
            p = p.strip()
            if p:
                allowed_dirs.append(Path(p).resolve())

    # Helper function to check containment
    def is_inside(target: Path, parent: Path) -> bool:
        try:
            target.relative_to(parent)
            return True
        except ValueError:
            return False

    is_safe = False
    for allowed in allowed_dirs:
        if is_inside(resolved_path, allowed) and is_inside(link_target, allowed):
            is_safe = True
            break

    if not is_safe:
        raise ValueError(f"Wordlist path '{path_str}' is outside allowed locations.")

    return path_str


__all__ = [
    "sanitize_target",
    "sanitize_command_arg",
    "validate_ip",
    "validate_domain",
    "validate_cidr",
    "validate_url",
    "validate_wordlist_path",
]
