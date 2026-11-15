"""
header_detector.py — PHP version detection from HTTP response headers.

Detection Method 1: HTTP Header Fingerprinting.
Inspects X-Powered-By, Server, Via, X-Generator, and related headers
for PHP version and architecture information.

This is a purely passive method — it reads headers from the HTTP response
to a standard GET request and never modifies server state.
"""

import re
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("php2shell")

# ─────────────────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────────────────

# Matches "PHP/8.3.20", "PHP/8.3.20-fpm", etc.
PHP_HEADER_VERSION_RE = re.compile(
    r'PHP/(\d+\.\d+\.\d+(?:[.\-][a-z0-9]+)?)',
    re.IGNORECASE
)

# Matches "PHP 8.3.20" (space instead of slash)
PHP_HEADER_VERSION_SPACE_RE = re.compile(
    r'\bPHP\s+(\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Architecture hints in Server header
FPM_RE       = re.compile(r'\bFPM\b',       re.IGNORECASE)
MOD_PHP_RE   = re.compile(r'\bmod_php\b',   re.IGNORECASE)
CGI_RE       = re.compile(r'\bCGI\b',       re.IGNORECASE)
LITESPEED_RE = re.compile(r'\blitespeed\b', re.IGNORECASE)
FRANKEN_RE   = re.compile(r'\bfrankenphp\b',re.IGNORECASE)
APACHE_RE    = re.compile(r'\bApache\b',    re.IGNORECASE)
NGINX_RE     = re.compile(r'\bNginx\b',     re.IGNORECASE)

# Headers to inspect (in priority order)
PHP_REVEALING_HEADERS = [
    "X-Powered-By",
    "Server",
    "X-Generator",
    "Via",
    "X-PHP-Version",
    "X-AspNet-Version",   # Sometimes co-present; note if found
]


def detect(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Inspect HTTP response headers for PHP version and architecture signals.

    Parameters
    ----------
    headers : dict of response header names → values (case-insensitive assumed
              — normalize before calling if needed)

    Returns
    -------
    {
        "php_detected":  bool,
        "version":       str | None,          # e.g. "8.3.20"
        "version_raw":   str | None,          # Raw string the version was found in
        "header_source": str | None,          # Header name version came from
        "architecture":  str | None,          # "fpm", "mod_php", "cgi", etc.
        "signals":       list[str],           # Confidence signal names
        "evidence":      list[str],           # Human-readable evidence lines
        "raw_headers":   dict[str, str],      # Subset of revealing headers
    }
    """
    result: Dict[str, Any] = {
        "php_detected":  False,
        "version":       None,
        "version_raw":   None,
        "header_source": None,
        "architecture":  None,
        "signals":       [],
        "evidence":      [],
        "raw_headers":   {},
    }

    # Normalize header names to title case for consistent lookup
    normalized: Dict[str, str] = {k.title(): v for k, v in headers.items()}

    # Collect revealing headers for evidence
    for header_name in PHP_REVEALING_HEADERS:
        if header_name.title() in normalized:
            result["raw_headers"][header_name] = normalized[header_name.title()]

    # ── 1. X-Powered-By (most reliable PHP indicator) ──────────────────────
    powered_by = normalized.get("X-Powered-By", "")
    if powered_by:
        version = _extract_version(powered_by)
        if version:
            result["php_detected"]  = True
            result["version"]       = version
            result["version_raw"]   = powered_by
            result["header_source"] = "X-Powered-By"
            result["signals"].append("header_x_powered_by")
            result["evidence"].append(
                f"X-Powered-By: {powered_by!r} → PHP version {version}"
            )
        elif re.search(r'\bPHP\b', powered_by, re.IGNORECASE):
            result["php_detected"] = True
            result["signals"].append("header_x_powered_by")
            result["evidence"].append(
                f"X-Powered-By: {powered_by!r} → PHP detected (version not disclosed)"
            )

    # ── 2. Server header ──────────────────────────────────────────────────
    server = normalized.get("Server", "")
    if server:
        # Architecture from Server header
        arch = _detect_architecture(server)
        if arch and not result["architecture"]:
            result["architecture"] = arch
            result["signals"].append(f"arch_{arch}")
            result["evidence"].append(
                f"Server: {server!r} → PHP execution model: {arch.upper()}"
            )

        # Version from Server header (lower confidence)
        if not result["version"]:
            version = _extract_version(server)
            if version:
                result["php_detected"]  = True
                result["version"]       = version
                result["version_raw"]   = server
                result["header_source"] = "Server"
                result["signals"].append("header_server")
                result["evidence"].append(
                    f"Server: {server!r} → PHP version {version}"
                )
            elif re.search(r'\bPHP\b', server, re.IGNORECASE):
                result["php_detected"] = True
                result["signals"].append("header_server")
                result["evidence"].append(
                    f"Server: {server!r} → PHP detected in Server header"
                )

    # ── 3. X-Generator ───────────────────────────────────────────────────
    x_gen = normalized.get("X-Generator", "")
    if x_gen:
        if not result["version"]:
            version = _extract_version(x_gen)
            if version:
                result["php_detected"]  = True
                result["version"]       = version
                result["version_raw"]   = x_gen
                result["header_source"] = "X-Generator"
                result["signals"].append("header_x_generator")
                result["evidence"].append(
                    f"X-Generator: {x_gen!r} → PHP version {version}"
                )

    # ── 4. Via header ────────────────────────────────────────────────────
    via = normalized.get("Via", "")
    if via and not result["version"]:
        version = _extract_version(via)
        if version:
            result["php_detected"]  = True
            result["version"]       = version
            result["version_raw"]   = via
            result["header_source"] = "Via"
            result["signals"].append("header_via")
            result["evidence"].append(
                f"Via: {via!r} → PHP version {version}"
            )

    # ── 5. X-PHP-Version (non-standard but seen in some frameworks) ──────
    x_php_ver = normalized.get("X-Php-Version", "")
    if x_php_ver and not result["version"]:
        version = _extract_version(x_php_ver) or x_php_ver.strip()
        if re.match(r'^\d+\.\d+', version):
            result["php_detected"]  = True
            result["version"]       = version
            result["version_raw"]   = x_php_ver
            result["header_source"] = "X-PHP-Version"
            result["signals"].append("header_x_powered_by")  # treat same weight
            result["evidence"].append(
                f"X-PHP-Version: {x_php_ver!r} → PHP version {version}"
            )

    # ── 6. Infer architecture from web server type if not set ─────────────
    if not result["architecture"] and server:
        if APACHE_RE.search(server):
            # Apache + PHP header usually means mod_php unless Server says FPM
            result["architecture"] = "mod_php"
            result["signals"].append("arch_mod_php")
            result["evidence"].append(
                f"Server: Apache detected — inferring mod_php architecture"
            )

    return result


def _extract_version(text: str) -> Optional[str]:
    """Extract the first PHP version string from text."""
    m = PHP_HEADER_VERSION_RE.search(text)
    if m:
        raw = m.group(1)
        # Normalize to X.Y.Z
        base = re.match(r'^(\d+\.\d+\.\d+)', raw)
        return base.group(1) if base else raw

    m = PHP_HEADER_VERSION_SPACE_RE.search(text)
    if m:
        return m.group(1)

    return None


def _detect_architecture(text: str) -> Optional[str]:
    """
    Infer PHP execution model from Server header or similar strings.
    Returns a short key: "fpm", "mod_php", "cgi", "litespeed", "frankenphp"
    or None.
    """
    if FRANKEN_RE.search(text):
        return "frankenphp"
    if FPM_RE.search(text):
        return "fpm"
    if LITESPEED_RE.search(text):
        return "litespeed"
    if MOD_PHP_RE.search(text):
        return "mod_php"
    if CGI_RE.search(text):
        return "cgi"
    return None
