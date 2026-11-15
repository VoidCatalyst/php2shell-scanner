"""
validators.py — Target validation and URL normalization for PHP2Shell Scanner.
"""

import re
import sys
from typing import List, Optional
from urllib.parse import urlparse, urlunparse


# Regex for a bare IP address or hostname
_HOSTNAME_RE = re.compile(
    r'^(?:'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}'  # FQDN
    r'|'
    r'(?:\d{1,3}\.){3}\d{1,3}'  # IPv4
    r'|'
    r'\[?[0-9a-fA-F:]+\]?'  # IPv6
    r')$'
)


def normalize_url(raw: str, default_port: int = None) -> Optional[str]:
    """
    Normalize a user-supplied URL or hostname to a canonical form.

    Rules:
    - Bare hostnames/IPs → https://hostname/
    - http:// or https:// kept as-is
    - Custom port applied if default_port is set and no port in URL
    - Trailing / stripped from path for uniformity

    Returns the normalized URL string, or None if the input is invalid.
    """
    raw = raw.strip()
    if not raw:
        return None

    # Strip comment chars
    if raw.startswith("#"):
        return None

    # Add scheme if missing
    if not raw.startswith(("http://", "https://")):
        # Bare IP/hostname with or without port
        if "://" in raw:
            return None  # Unknown scheme
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    netloc = parsed.netloc
    if not netloc:
        return None

    # Apply custom port if no port already in URL
    if default_port and ":" not in parsed.netloc.split("]")[-1]:
        host = parsed.hostname or parsed.netloc
        netloc = f"{host}:{default_port}"

    # Reconstruct
    path = parsed.path or "/"
    normalized = urlunparse((
        scheme, netloc, path,
        parsed.params, parsed.query, ""  # drop fragment
    ))
    return normalized


def validate_target(raw: str, port: int = None) -> Optional[str]:
    """
    Validate and normalize a single target.

    Args:
        raw:  Raw URL, hostname, or IP address.
        port: Optional custom port override.

    Returns:
        Normalized URL string, or None if invalid.
    """
    return normalize_url(raw, default_port=port)


def validate_targets_file(filepath: str, port: int = None) -> List[str]:
    """
    Read a targets file (one target per line) and return a list of
    validated, normalized URLs.

    Lines starting with # are treated as comments.
    Empty lines are skipped.

    Args:
        filepath: Path to the targets file.
        port:     Optional custom port applied to all targets.

    Returns:
        List of validated normalized URL strings.
    """
    targets = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                normalized = validate_target(line, port)
                if normalized:
                    targets.append(normalized)
                else:
                    print(
                        f"[!] Line {lineno}: skipping invalid target '{line}'",
                        file=sys.stderr
                    )
    except FileNotFoundError:
        print(f"[-] Targets file not found: {filepath}", file=sys.stderr)
    except PermissionError:
        print(f"[-] Cannot read targets file: {filepath}", file=sys.stderr)
    except OSError as exc:
        print(f"[-] Error reading targets file: {exc}", file=sys.stderr)

    return targets


def parse_custom_headers(header_list: List[str]) -> dict:
    """
    Parse a list of 'Key:Value' strings into a dict.
    Silently drops malformed entries.
    """
    headers = {}
    if not header_list:
        return headers
    for item in header_list:
        if ":" not in item:
            continue
        key, _, value = item.partition(":")
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers
