"""
helpers.py — General-purpose helper functions for PHP2Shell Scanner.
"""

import socket
import time
from datetime import datetime, timezone
from typing import Optional


def resolve_dns(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """
    Resolve a hostname to its first IPv4/IPv6 address.

    Returns the IP string, or None if resolution fails.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def elapsed_since(start: float) -> float:
    """Return elapsed seconds since a time.monotonic() value."""
    return round(time.monotonic() - start, 3)


def safe_get(d: dict, *keys, default=None):
    """
    Safely traverse nested dicts/lists.

    Example:
        safe_get(result, "cve_assessments", "CVE-2026-109618", "status")
    """
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        elif isinstance(current, list) and isinstance(key, int):
            try:
                current = current[key]
            except IndexError:
                return default
        else:
            return default
        if current is None:
            return default
    return current


def truncate(text: str, max_len: int = 120) -> str:
    """Truncate a string to max_len characters, appending '...' if needed."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def sanitize_header_value(value: str) -> str:
    """Remove non-printable characters from an HTTP header value."""
    return "".join(c for c in value if c.isprintable()).strip()


def build_recommendation(overall_status: str, php_version: Optional[str],
                          fixed_version: Optional[str], branch: Optional[str]) -> str:
    """Generate a human-readable remediation recommendation."""
    if overall_status == "NOT_VULNERABLE":
        return "No action required for PHP2Shell. Keep PHP updated for future vulnerabilities."
    if overall_status in ("CRITICAL", "HIGH"):
        if fixed_version:
            return (
                f"Upgrade PHP to {fixed_version} or a later release as soon as possible. "
                f"PHP2Shell (CVE-2026-109618, CVE-2026-109619) enables unauthenticated remote "
                f"code execution. This is a CISA KEV vulnerability."
            )
        return (
            "Upgrade PHP to a supported branch with PHP2Shell patches applied "
            "(PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12 or later). "
            "Contact your vendor or distribution for EOL branch backport packages."
        )
    if overall_status == "MEDIUM":
        return (
            "PHP version could not be fully verified. Confirm the actual PHP version "
            "and check that it is 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later, "
            "or that your vendor has applied PHP2Shell backport patches."
        )
    if overall_status == "LOW":
        return (
            "PHP was detected but no version information was disclosed. "
            "Determine the PHP version and verify PHP2Shell patch status."
        )
    return (
        "Insufficient information to assess PHP2Shell exposure. "
        "Identify the PHP version and confirm patch status."
    )
