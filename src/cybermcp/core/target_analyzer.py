"""Target analysis engine — profile targets via DNS, ports, services, and tech fingerprinting."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

__all__ = ["TargetAnalyzer", "TargetProfile", "TargetType"]


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"
    UNKNOWN = "unknown"


class PortInfo(BaseModel):
    """Single port with service metadata."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class TargetProfile(BaseModel):
    """Comprehensive target profile built by the analyzer."""

    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    open_ports: list[PortInfo] = Field(default_factory=list)
    services: dict[str, str] = Field(default_factory=dict)  # port -> service
    technologies: list[str] = Field(default_factory=list)
    os_guess: str = ""
    waf_detected: str = ""
    cdn_detected: str = ""
    cms_detected: str = ""
    http_headers: dict[str, str] = Field(default_factory=dict)
    ssl_info: dict[str, Any] = Field(default_factory=dict)
    subdomains: list[str] = Field(default_factory=list)
    whois_info: dict[str, Any] = Field(default_factory=dict)
    attack_surface_score: float = 0.0
    analysis_depth: str = "quick"
    analysis_time: float = 0.0
    raw_results: dict[str, Any] = Field(default_factory=dict)


def _classify_target(target: str) -> TargetType:
    """Determine the type of target string."""
    target = target.strip()
    if not target:
        return TargetType.UNKNOWN

    # CIDR
    if "/" in target and not target.startswith("http"):
        try:
            ipaddress.ip_network(target, strict=False)
            return TargetType.CIDR
        except ValueError:
            pass

    # IP
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass

    # URL
    if target.startswith(("http://", "https://")):
        return TargetType.URL

    # Domain — basic check
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", target):
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


def _extract_hostname(target: str) -> str:
    """Pull hostname out of a URL or return the target as-is."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


class TargetAnalyzer:
    """Builds target profiles using tool registry for actual tool execution.

    Accepts tool_registry and executor objects. If they're None, analysis falls
    back to stdlib-only passive checks.
    """

    def __init__(
        self,
        tool_registry: Any | None = None,
        executor: Any | None = None,
    ) -> None:
        self._registry = tool_registry
        self._executor = executor

    async def analyze(self, target: str, depth: str = "quick") -> TargetProfile:
        """Run analysis pipeline at the requested depth.

        Depths:
            quick    — DNS lookup + top-100 port scan + HTTP header grab
            standard — quick + service detection + tech fingerprint + WAF check
            deep     — standard + full port scan + OS detection + subdomain enum
        """
        t0 = time.time()
        profile = TargetProfile(target=target, analysis_depth=depth)
        profile.target_type = _classify_target(target)

        hostname = _extract_hostname(target)

        # Quick checks always run.
        await self._dns_resolve(hostname, profile)
        await self._port_scan(profile, quick=True)
        await self._grab_http_headers(hostname, profile)

        if depth in ("standard", "deep"):
            # Phase 2 — standard
            await self._service_detect(profile)
            await self._tech_fingerprint(hostname, profile)
            await self._waf_check(hostname, profile)

        if depth == "deep":
            # Phase 3 — deep
            await self._port_scan(profile, quick=False)
            await self._os_detect(profile)
            await self._subdomain_enum(hostname, profile)

        self._compute_attack_surface(profile)
        profile.analysis_time = time.time() - t0
        return profile

    # ------------------------------------------------------------------
    # Quick checks
    # ------------------------------------------------------------------

    async def _dns_resolve(self, hostname: str, profile: TargetProfile) -> None:
        """Resolve hostname to IPs via stdlib."""
        try:
            ip = ipaddress.ip_address(hostname)
            profile.ip_addresses = [str(ip)]
            return
        except ValueError:
            pass

        loop = asyncio.get_running_loop()
        try:
            results = await loop.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            seen: set[str] = set()
            for family, _type, _proto, _canon, sockaddr in results:
                addr = sockaddr[0]
                if addr not in seen:
                    seen.add(addr)
                    profile.ip_addresses.append(addr)
            if hostname not in profile.domains:
                profile.domains.append(hostname)
        except socket.gaierror:
            pass

    async def _port_scan(self, profile: TargetProfile, *, quick: bool) -> None:
        """Run nmap via tool registry, fall back to socket connect scan."""
        scan_target = profile.ip_addresses[0] if profile.ip_addresses else _extract_hostname(profile.target)

        # Try nmap through tool registry
        if self._registry and self._executor:
            nmap_args: dict[str, Any] = {"target": scan_target}
            if quick:
                nmap_args["ports"] = "21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
                nmap_args["scan_type"] = "connect"
                nmap_args["timing"] = 4
            else:
                nmap_args["ports"] = "1-65535"
                nmap_args["scan_type"] = "syn"
                nmap_args["timing"] = 4

            result = await self._run_tool("nmap", nmap_args)
            if result and result.get("success"):
                self._parse_nmap_result(result, profile)
                return

        # Fallback: socket connect scan on common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]
        if not quick:
            ports = list(range(1, 1025))

        loop = asyncio.get_running_loop()

        async def _check_port(port: int) -> PortInfo | None:
            try:
                fut = loop.create_connection(asyncio.Protocol, scan_target, port)
                transport, _ = await asyncio.wait_for(fut, timeout=1.5)
                transport.close()
                return PortInfo(port=port, state="open", service=_guess_service(port))
            except (OSError, asyncio.TimeoutError):
                return None

        sem = asyncio.Semaphore(100)

        async def _bounded(port: int) -> PortInfo | None:
            async with sem:
                return await _check_port(port)

        tasks = [_bounded(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, PortInfo):
                # Avoid duplicate ports from quick + deep
                existing = {p.port for p in profile.open_ports}
                if r.port not in existing:
                    profile.open_ports.append(r)
                    profile.services[str(r.port)] = r.service

    async def _grab_http_headers(self, hostname: str, profile: TargetProfile) -> None:
        """Grab HTTP response headers via stdlib."""
        has_http = any(p.port in (80, 8080, 8000) for p in profile.open_ports)
        has_https = any(p.port in (443, 8443) for p in profile.open_ports)

        if not has_http and not has_https:
            # If we have a URL target, try anyway
            if profile.target_type == TargetType.URL:
                has_https = profile.target.startswith("https://")
                has_http = profile.target.startswith("http://")
            else:
                return

        import ssl
        from http.client import HTTPConnection, HTTPSConnection

        loop = asyncio.get_running_loop()

        async def _fetch(scheme: str, port: int) -> None:
            def _do() -> dict[str, str]:
                headers: dict[str, str] = {}
                try:
                    if scheme == "https":
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = HTTPSConnection(hostname, port, timeout=5, context=ctx)
                    else:
                        conn = HTTPConnection(hostname, port, timeout=5)
                    conn.request("HEAD", "/", headers={"User-Agent": "Vajra-MCP/1.0"})
                    resp = conn.getresponse()
                    for k, v in resp.getheaders():
                        headers[k.lower()] = v
                    conn.close()
                except Exception:
                    pass
                return headers

            hdrs = await loop.run_in_executor(None, _do)
            profile.http_headers.update(hdrs)
            self._extract_tech_from_headers(hdrs, profile)

        if has_https:
            await _fetch("https", 443)
        elif has_http:
            await _fetch("http", 80)

    def _extract_tech_from_headers(self, headers: dict[str, str], profile: TargetProfile) -> None:
        """Pull technology clues from HTTP headers."""
        server = headers.get("server", "")
        if server and server not in profile.technologies:
            profile.technologies.append(server)

        powered = headers.get("x-powered-by", "")
        if powered and powered not in profile.technologies:
            profile.technologies.append(powered)

        # CDN detection
        via = headers.get("via", "") + " " + headers.get("server", "")
        cdn_sigs = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "cloudfront": "CloudFront",
            "incapsula": "Incapsula",
            "sucuri": "Sucuri",
        }
        for sig, name in cdn_sigs.items():
            if sig in via.lower() or sig in headers.get("x-cdn", "").lower():
                profile.cdn_detected = name
                break

        # WAF hints from headers
        waf_headers = {
            "x-sucuri-id": "Sucuri",
            "x-sucuri-cache": "Sucuri",
            "cf-ray": "Cloudflare WAF",
            "x-distil-cs": "Distil Networks",
        }
        for hdr, waf_name in waf_headers.items():
            if hdr in headers:
                profile.waf_detected = waf_name
                break

    # ------------------------------------------------------------------
    # Phase 2: Standard
    # ------------------------------------------------------------------

    async def _service_detect(self, profile: TargetProfile) -> None:
        """Run nmap -sV for version detection via registry."""
        if not (self._registry and self._executor):
            return

        scan_target = profile.ip_addresses[0] if profile.ip_addresses else _extract_hostname(profile.target)
        ports_csv = ",".join(str(p.port) for p in profile.open_ports)
        if not ports_csv:
            return

        result = await self._run_tool("nmap", {
            "target": scan_target,
            "ports": ports_csv,
            "service_detection": True,
            "timing": 4,
        })
        if result and result.get("success"):
            self._parse_nmap_result(result, profile)

    async def _tech_fingerprint(self, hostname: str, profile: TargetProfile) -> None:
        """Run whatweb via registry for tech fingerprinting."""
        has_web = any(p.port in (80, 443, 8080, 8443) for p in profile.open_ports)
        if not has_web:
            return

        if self._registry and self._executor:
            result = await self._run_tool("whatweb", {"target": hostname})
            if result and result.get("success"):
                parsed = result.get("parsed_data", {})
                techs = parsed.get("technologies", [])
                for t in techs:
                    if t not in profile.technologies:
                        profile.technologies.append(t)
                cms = parsed.get("cms", "")
                if cms:
                    profile.cms_detected = cms

    async def _waf_check(self, hostname: str, profile: TargetProfile) -> None:
        """Run wafw00f via registry for WAF detection."""
        if profile.waf_detected:
            return
        has_web = any(p.port in (80, 443, 8080, 8443) for p in profile.open_ports)
        if not has_web:
            return

        if self._registry and self._executor:
            result = await self._run_tool("wafw00f", {"target": hostname})
            if result and result.get("success"):
                waf = result.get("parsed_data", {}).get("waf", "")
                if waf:
                    profile.waf_detected = waf

    # ------------------------------------------------------------------
    # Phase 3: Deep
    # ------------------------------------------------------------------

    async def _os_detect(self, profile: TargetProfile) -> None:
        """Run nmap -O via registry for OS fingerprinting."""
        if not (self._registry and self._executor):
            return

        scan_target = profile.ip_addresses[0] if profile.ip_addresses else _extract_hostname(profile.target)
        result = await self._run_tool("nmap", {
            "target": scan_target,
            "os_detection": True,
            "timing": 4,
        })
        if result and result.get("success"):
            os_guess = result.get("parsed_data", {}).get("os_guess", "")
            if os_guess:
                profile.os_guess = os_guess

    async def _subdomain_enum(self, hostname: str, profile: TargetProfile) -> None:
        """Run subfinder and amass via registry for subdomain enumeration."""
        if not (self._registry and self._executor):
            return

        for tool_name in ("subfinder", "amass"):
            result = await self._run_tool(tool_name, {"domain": hostname})
            if result and result.get("success"):
                subs = result.get("parsed_data", {}).get("subdomains", [])
                for s in subs:
                    if s not in profile.subdomains:
                        profile.subdomains.append(s)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _run_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any] | None:
        """Execute a tool via the registry/executor if available."""
        if not (self._registry and self._executor):
            return None
        try:
            tool = self._registry.get(tool_name)
            if tool is None:
                return None
            input_data = tool.input_model.model_validate(args)
            result = await self._executor.execute(tool, input_data, target=args.get("target") or args.get("domain") or args.get("url"))
            return result.model_dump() if hasattr(result, "model_dump") else result
        except Exception:
            return None

    def _parse_nmap_result(self, result: dict[str, Any], profile: TargetProfile) -> None:
        """Merge nmap output into the profile."""
        parsed = result.get("parsed_data", {})
        hosts = parsed.get("hosts", [])
        for host in hosts:
            for port_data in host.get("ports", []):
                pnum = port_data.get("port", 0)
                existing = {p.port for p in profile.open_ports}
                info = PortInfo(
                    port=pnum,
                    protocol=port_data.get("protocol", "tcp"),
                    state=port_data.get("state", "open"),
                    service=port_data.get("service", ""),
                    version=port_data.get("version", ""),
                    banner=port_data.get("banner", ""),
                )
                if pnum not in existing:
                    profile.open_ports.append(info)
                else:
                    # Update existing with richer data
                    for p in profile.open_ports:
                        if p.port == pnum:
                            if info.service:
                                p.service = info.service
                            if info.version:
                                p.version = info.version
                            if info.banner:
                                p.banner = info.banner
                            break
                profile.services[str(pnum)] = info.service or _guess_service(pnum)

            os_info = host.get("os_guess", "")
            if os_info and not profile.os_guess:
                profile.os_guess = os_info

    def _compute_attack_surface(self, profile: TargetProfile) -> None:
        """Heuristic attack surface score 0-100."""
        score = 0.0

        # More open ports → larger surface
        port_count = len(profile.open_ports)
        score += min(port_count * 3, 30)

        # High-risk services
        risky_services = {"ftp", "telnet", "smb", "snmp", "rdp", "vnc", "mysql", "mssql", "postgresql", "redis", "mongodb", "memcached"}
        for p in profile.open_ports:
            svc = p.service.lower()
            if any(r in svc for r in risky_services):
                score += 5

        # Web services increase surface
        web_ports = {p.port for p in profile.open_ports if p.port in (80, 443, 8080, 8443, 8000, 3000, 9090)}
        score += len(web_ports) * 4

        # No WAF = higher surface
        if not profile.waf_detected:
            score += 10

        # CMS detected adds surface
        if profile.cms_detected:
            score += 8

        # Subdomains increase surface
        score += min(len(profile.subdomains) * 0.5, 15)

        profile.attack_surface_score = min(score, 100.0)


def _guess_service(port: int) -> str:
    """Best-guess service name from port number."""
    _COMMON: dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 1723: "pptp", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
        8443: "https-alt", 27017: "mongodb", 11211: "memcached",
    }
    return _COMMON.get(port, "")
