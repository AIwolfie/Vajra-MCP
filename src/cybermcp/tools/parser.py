"""Output parser utilities — extract structured data from raw CLI output."""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

__all__ = [
    "extract_domains",
    "extract_emails",
    "extract_ips",
    "extract_urls",
    "parse_csv_output",
    "parse_json_output",
    "parse_key_value",
    "parse_nmap_xml",
    "parse_table_output",
    "parse_xml_output",
]

# --------------------------------------------------------------------------
# Regex patterns
# --------------------------------------------------------------------------

_URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\)]+",
    re.IGNORECASE,
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def parse_json_output(output: str) -> dict[str, Any]:
    """Extract the first JSON object or array from *output*.

    Handles mixed output where JSON is embedded in surrounding text
    by scanning for the first ``{`` or ``[`` and matching its close.
    """
    output = output.strip()

    # Fast path — entire output is JSON
    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            return parsed
        return {"data": parsed}
    except json.JSONDecodeError:
        pass

    # Scan for first JSON structure
    for start_char, end_char in (("{", "}"), ("[", "]")):
        idx = output.find(start_char)
        if idx == -1:
            continue
        depth = 0
        in_str = False
        escape = False
        for i in range(idx, len(output)):
            c = output[i]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == start_char:
                depth += 1
            elif c == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(output[idx : i + 1])
                        if isinstance(parsed, dict):
                            return parsed
                        return {"data": parsed}
                    except json.JSONDecodeError:
                        break

    # NDJSON — one JSON object per line
    lines = output.splitlines()
    objects: list[Any] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if objects:
        return {"data": objects}

    return {}


# --------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------


def parse_xml_output(output: str) -> dict[str, Any]:
    """Convert an XML string into a nested dict."""
    output = output.strip()
    # Strip leading non-XML content
    xml_start = output.find("<?xml")
    if xml_start == -1:
        xml_start = output.find("<")
    if xml_start > 0:
        output = output[xml_start:]

    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return {}

    return _element_to_dict(root)


def _element_to_dict(elem: ET.Element) -> dict[str, Any]:
    """Recursively convert an ElementTree element to a dict."""
    result: dict[str, Any] = {}
    if elem.attrib:
        result["@attributes"] = dict(elem.attrib)
    if elem.text and elem.text.strip():
        result["@text"] = elem.text.strip()

    children: dict[str, list[Any]] = {}
    for child in elem:
        tag = child.tag
        child_dict = _element_to_dict(child)
        children.setdefault(tag, []).append(child_dict)

    for tag, items in children.items():
        result[tag] = items if len(items) > 1 else items[0]

    return result


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------


def parse_csv_output(output: str, delimiter: str = ",") -> list[dict[str, str]]:
    """Parse CSV text (with header row) into a list of dicts."""
    output = output.strip()
    if not output:
        return []

    reader = csv.DictReader(io.StringIO(output), delimiter=delimiter)
    return [dict(row) for row in reader]


# --------------------------------------------------------------------------
# Nmap XML
# --------------------------------------------------------------------------


def parse_nmap_xml(xml_str: str) -> dict[str, Any]:
    """Parse nmap XML output into a structured dict of hosts and ports."""
    xml_str = xml_str.strip()
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {}

    scan_info: dict[str, Any] = {}
    if root.attrib:
        scan_info["scanner"] = root.attrib.get("scanner", "")
        scan_info["args"] = root.attrib.get("args", "")
        scan_info["start"] = root.attrib.get("start", "")
        scan_info["version"] = root.attrib.get("version", "")

    hosts: list[dict[str, Any]] = []
    for host_elem in root.findall("host"):
        host: dict[str, Any] = {}

        # Status
        status_elem = host_elem.find("status")
        if status_elem is not None:
            host["status"] = status_elem.attrib.get("state", "unknown")

        # Addresses
        addresses: list[dict[str, str]] = []
        for addr in host_elem.findall("address"):
            addresses.append({
                "addr": addr.attrib.get("addr", ""),
                "addrtype": addr.attrib.get("addrtype", ""),
                "vendor": addr.attrib.get("vendor", ""),
            })
        host["addresses"] = addresses

        # Hostnames
        hostnames: list[str] = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                name = hn.attrib.get("name", "")
                if name:
                    hostnames.append(name)
        host["hostnames"] = hostnames

        # Ports
        ports: list[dict[str, Any]] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info: dict[str, Any] = {
                    "portid": port_elem.attrib.get("portid", ""),
                    "protocol": port_elem.attrib.get("protocol", ""),
                }
                state = port_elem.find("state")
                if state is not None:
                    port_info["state"] = state.attrib.get("state", "")
                    port_info["reason"] = state.attrib.get("reason", "")

                service = port_elem.find("service")
                if service is not None:
                    port_info["service"] = {
                        "name": service.attrib.get("name", ""),
                        "product": service.attrib.get("product", ""),
                        "version": service.attrib.get("version", ""),
                        "extrainfo": service.attrib.get("extrainfo", ""),
                        "tunnel": service.attrib.get("tunnel", ""),
                    }

                # Scripts
                scripts: list[dict[str, str]] = []
                for script_elem in port_elem.findall("script"):
                    scripts.append({
                        "id": script_elem.attrib.get("id", ""),
                        "output": script_elem.attrib.get("output", ""),
                    })
                if scripts:
                    port_info["scripts"] = scripts

                ports.append(port_info)
        host["ports"] = ports

        # OS detection
        os_matches: list[dict[str, str]] = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.attrib.get("name", ""),
                    "accuracy": osmatch.attrib.get("accuracy", ""),
                })
        host["os_matches"] = os_matches

        hosts.append(host)

    return {"scan_info": scan_info, "hosts": hosts}


# --------------------------------------------------------------------------
# Table output
# --------------------------------------------------------------------------


def parse_table_output(output: str) -> list[dict[str, str]]:
    """Parse ASCII table output (column-aligned or separator-based) into dicts.

    Handles both separator-delimited tables and whitespace-aligned tables.
    The first non-empty line is treated as the header row.
    Lines consisting only of dashes/pipes/plus signs are skipped.
    """
    lines = output.strip().splitlines()
    if not lines:
        return []

    # Filter out separator lines (e.g., "+---+---+" or "----  ----")
    separator_re = re.compile(r"^[\s\-+|=]+$")
    content_lines = [ln for ln in lines if not separator_re.match(ln)]
    if not content_lines:
        return []

    header_line = content_lines[0]

    # Detect pipe-delimited tables
    if "|" in header_line:
        headers = [h.strip() for h in header_line.split("|") if h.strip()]
        results: list[dict[str, str]] = []
        for line in content_lines[1:]:
            values = [v.strip() for v in line.split("|") if v.strip()]
            if len(values) == len(headers):
                results.append(dict(zip(headers, values)))
        return results

    # Tab-delimited
    if "\t" in header_line:
        headers = [h.strip() for h in header_line.split("\t")]
        results = []
        for line in content_lines[1:]:
            values = [v.strip() for v in line.split("\t")]
            if len(values) == len(headers):
                results.append(dict(zip(headers, values)))
        return results

    # Whitespace-aligned — use header column positions
    headers_raw = re.split(r"\s{2,}", header_line.strip())
    headers = [h.strip() for h in headers_raw]

    # Find column start positions
    col_starts: list[int] = []
    for h in headers:
        idx = header_line.find(h, col_starts[-1] + 1 if col_starts else 0)
        col_starts.append(idx)

    results = []
    for line in content_lines[1:]:
        if not line.strip():
            continue
        values: list[str] = []
        for i, start in enumerate(col_starts):
            end = col_starts[i + 1] if i + 1 < len(col_starts) else len(line)
            values.append(line[start:end].strip())
        if any(values):
            results.append(dict(zip(headers, values)))
    return results


# --------------------------------------------------------------------------
# Regex extractors
# --------------------------------------------------------------------------


def extract_urls(text: str) -> list[str]:
    """Extract unique URLs from *text*."""
    return list(dict.fromkeys(_URL_RE.findall(text)))


def extract_ips(text: str) -> list[str]:
    """Extract unique IPv4 addresses from *text*."""
    return list(dict.fromkeys(_IPV4_RE.findall(text)))


def extract_emails(text: str) -> list[str]:
    """Extract unique email addresses from *text*."""
    return list(dict.fromkeys(_EMAIL_RE.findall(text)))


def extract_domains(text: str) -> list[str]:
    """Extract unique domain names from *text*."""
    return list(dict.fromkeys(_DOMAIN_RE.findall(text)))


# --------------------------------------------------------------------------
# Key-value
# --------------------------------------------------------------------------


def parse_key_value(output: str, separator: str = ":") -> dict[str, str]:
    """Parse ``key: value`` lines into a dict.

    Lines without the separator are skipped.
    """
    result: dict[str, str] = {}
    for line in output.splitlines():
        if separator not in line:
            continue
        key, _, value = line.partition(separator)
        key = key.strip()
        value = value.strip()
        if key:
            result[key] = value
    return result
