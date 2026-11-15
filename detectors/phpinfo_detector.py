"""
phpinfo_detector.py — Exposed phpinfo() page detection and parsing.

Detection Method 3: phpinfo() Endpoint Detection.
Checks well-known phpinfo file paths for accidentally exposed phpinfo()
pages. When found, parses version, Server API (architecture), PHP
configuration variables, and compilation flags.

This is a passive read-only method. The scanner only sends a GET request
to common paths and reads the response — no payloads, no injections,
no server state modifications.
"""

import re
import logging
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("php2shell")

# ─────────────────────────────────────────────────────────────────────────────
# Well-known phpinfo() paths — in priority order
# ─────────────────────────────────────────────────────────────────────────────
PHPINFO_PATHS: List[str] = [
    "/phpinfo.php",
    "/info.php",
    "/php.php",
    "/test.php",
    "/test/phpinfo.php",
    "/phptest.php",
    "/check.php",
    "/status.php",
    "/server-status.php",
    "/php_info.php",
    "/phpinfo/",
    "/admin/phpinfo.php",
    "/debug/phpinfo.php",
]

# ─────────────────────────────────────────────────────────────────────────────
# Patterns for phpinfo() page content
# ─────────────────────────────────────────────────────────────────────────────

# Distinguish a real phpinfo page from a 404/redirect page with PHP in it
PHPINFO_SIGNATURE_RE = re.compile(
    r'PHP\s+Version\s*</(?:td|th)>|'
    r'<title>phpinfo\(\)</title>|'
    r'PHP\s+Version\s*<br\s*/?>|'
    r'PHP\s+Core',
    re.IGNORECASE
)

# Extract PHP version from phpinfo output
PHPINFO_VERSION_RE = re.compile(
    r'(?:<td[^>]*>PHP\s+Version\s*</td>\s*<td[^>]*>|'
    r'PHP\s+Version\s*<br\s*/?>\s*|'
    r'<h1[^>]*>PHP\s+Version\s+)(\d+\.\d+\.\d+)',
    re.IGNORECASE | re.DOTALL
)

# Fallback version extraction
PHPINFO_VERSION_FALLBACK_RE = re.compile(
    r'PHP\s+Version\s+(\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# Server API (execution architecture)
SERVER_API_RE = re.compile(
    r'Server\s+API\s*</td>\s*<td[^>]*>\s*([^<]+)',
    re.IGNORECASE | re.DOTALL
)

# memory_limit configuration
MEMORY_LIMIT_RE = re.compile(
    r'memory_limit\s*</td>\s*<td[^>]*>\s*([^<]+)\s*</td>',
    re.IGNORECASE | re.DOTALL
)

# fatal_error_backtraces (CVE-2026-109619 mitigation, PHP 8.5 only)
FATAL_BT_RE = re.compile(
    r'fatal_error_backtraces\s*</td>\s*<td[^>]*>\s*([^<]+)\s*</td>',
    re.IGNORECASE | re.DOTALL
)

# Compilation flags
ZEND_THREAD_SAFE_RE = re.compile(
    r'Thread\s+Safety\s*</td>\s*<td[^>]*>\s*(enabled|disabled)',
    re.IGNORECASE | re.DOTALL
)

# Server software (web server)
SERVER_SOFTWARE_RE = re.compile(
    r'(?:_SERVER\["SERVER_SOFTWARE"\]|SERVER_SOFTWARE)\s*</td>\s*<td[^>]*>\s*([^<]+)',
    re.IGNORECASE | re.DOTALL
)


def detect(
    base_url: str,
    http_client,
    check_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Probe well-known phpinfo() paths and parse any page found.

    Parameters
    ----------
    base_url     : Target base URL (e.g. "https://example.com")
    http_client  : PhpHttpClient instance
    check_paths  : Override default path list (optional)

    Returns
    -------
    {
        "found":          bool,
        "url":            str | None,          # URL where phpinfo was found
        "version":        str | None,
        "server_api":     str | None,          # Raw Server API string
        "architecture":   str | None,          # Normalized arch key
        "memory_limit":   str | None,
        "fatal_bt":       str | None,          # fatal_error_backtraces value
        "thread_safe":    bool | None,
        "server_software":str | None,
        "signals":        list[str],
        "evidence":       list[str],
        "paths_checked":  list[str],
    }
    """
    result: Dict[str, Any] = {
        "found":           False,
        "url":             None,
        "version":         None,
        "server_api":      None,
        "architecture":    None,
        "memory_limit":    None,
        "fatal_bt":        None,
        "thread_safe":     None,
        "server_software": None,
        "signals":         [],
        "evidence":        [],
        "paths_checked":   [],
    }

    paths = check_paths if check_paths is not None else PHPINFO_PATHS

    # Normalize base URL
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in paths:
        url = urljoin(base + "/", path.lstrip("/"))
        result["paths_checked"].append(url)

        response = http_client.get(url, allow_redirects=False)
        if response is None:
            continue

        # Only inspect 200 OK responses
        if response.status_code != 200:
            continue

        try:
            body = response.text
        except Exception:
            continue

        if not PHPINFO_SIGNATURE_RE.search(body):
            continue

        # ── We found a phpinfo() page ──────────────────────────────────
        result["found"] = True
        result["url"]   = url
        result["signals"].append("phpinfo_page")
        result["evidence"].append(
            f"phpinfo() page found at: {url}"
        )

        # Extract version
        version = _extract_version(body)
        if version:
            result["version"] = version
            result["signals"].append("phpinfo_version")
            result["evidence"].append(f"PHP version from phpinfo(): {version}")

        # Extract Server API
        sa_match = SERVER_API_RE.search(body)
        if sa_match:
            server_api = sa_match.group(1).strip()
            result["server_api"] = server_api
            arch = _normalize_architecture(server_api)
            result["architecture"] = arch
            result["signals"].append("phpinfo_server_api")
            result["evidence"].append(
                f"Server API (phpinfo): {server_api!r} → architecture: {arch}"
            )

        # Extract memory_limit
        ml_match = MEMORY_LIMIT_RE.search(body)
        if ml_match:
            result["memory_limit"] = ml_match.group(1).strip()
            result["evidence"].append(
                f"memory_limit (phpinfo): {result['memory_limit']}"
            )
            if result["memory_limit"] == "-1":
                result["evidence"].append(
                    "⚠  memory_limit=-1 detected — CVE-2026-109618 mitigation "
                    "is active but masks OOM conditions; upgrade still required"
                )

        # Extract fatal_error_backtraces
        fbt_match = FATAL_BT_RE.search(body)
        if fbt_match:
            result["fatal_bt"] = fbt_match.group(1).strip()
            result["evidence"].append(
                f"fatal_error_backtraces (phpinfo): {result['fatal_bt']}"
            )
            if result["fatal_bt"] in ("0", "Off", "off"):
                result["evidence"].append(
                    "fatal_error_backtraces=0 detected — CVE-2026-109619 "
                    "workaround active (PHP 8.5 only; upgrade still required)"
                )

        # Thread safety
        ts_match = ZEND_THREAD_SAFE_RE.search(body)
        if ts_match:
            result["thread_safe"] = ts_match.group(1).lower() == "enabled"

        # Server software
        sw_match = SERVER_SOFTWARE_RE.search(body)
        if sw_match:
            result["server_software"] = sw_match.group(1).strip()[:120]

        # Stop after first valid phpinfo page found
        break

    return result


def _extract_version(body: str) -> Optional[str]:
    """Extract PHP version from phpinfo() page HTML."""
    m = PHPINFO_VERSION_RE.search(body)
    if m:
        raw = m.group(1)
        base = re.match(r'^(\d+\.\d+\.\d+)', raw)
        return base.group(1) if base else raw

    m = PHPINFO_VERSION_FALLBACK_RE.search(body)
    if m:
        return m.group(1)

    return None


def _normalize_architecture(server_api: str) -> str:
    """
    Normalize a PHP Server API string to a short architecture key.

    Common Server API values from phpinfo():
    - "FPM/FastCGI"
    - "Apache 2.0 Handler"
    - "CGI/FastCGI"
    - "CGI"
    - "LiteSpeed"
    - "FrankenPHP"
    - "Command Line Interface" (should not be web-serving, but noted)
    """
    sa = server_api.lower()
    if "fpm" in sa or "fastcgi" in sa:
        return "fpm"
    if "litespeed" in sa:
        return "litespeed"
    if "frankenphp" in sa:
        return "frankenphp"
    if "apache" in sa:
        return "mod_php"
    if "cgi" in sa:
        return "cgi"
    if "command line" in sa or "cli" in sa:
        return "cli"
    return "unknown"
