"""
html_detector.py — PHP detection from HTML body / application fingerprinting.

Detection Method 2: HTML & Application Fingerprinting.
Inspects page body, cookies, error messages, and CMS/framework patterns
to infer PHP presence, version, and execution context.

This is a purely passive method — no code execution, no file writes,
no server state changes.
"""

import re
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("php2shell")

# ─────────────────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────────────────

# PHP error page patterns
PHP_ERROR_RE = re.compile(
    r'<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:',
    re.IGNORECASE
)
PHP_ERROR_VERSION_RE = re.compile(
    r'PHP\s+(\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# PHP version in HTML comments or meta tags
PHP_HTML_VERSION_RE = re.compile(
    r'(?:<!--.*?PHP[/\s](\d+\.\d+\.\d+).*?-->|'
    r'content="PHP[/\s](\d+\.\d+\.\d+)")',
    re.IGNORECASE | re.DOTALL
)

# CMS and framework PHP indicators
CMS_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "WordPress",
        "pattern": re.compile(
            r'(?:wp-content|wp-includes|WordPress)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "Drupal",
        "pattern": re.compile(
            r'(?:Drupal\.settings|drupal\.js|sites/default)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "Joomla",
        "pattern": re.compile(
            r'(?:/media/jui/|Joomla!|/components/com_)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "Laravel",
        "pattern": re.compile(
            r'(?:laravel_session|/vendor/laravel)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "Symfony",
        "pattern": re.compile(
            r'(?:symfony|_sf2_|sf-toolbar)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "Magento",
        "pattern": re.compile(
            r'(?:mage/|Mage\.Cookies|magento)',
            re.IGNORECASE
        ),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "phpBB",
        "pattern": re.compile(r'phpBB', re.IGNORECASE),
        "confidence_signal": "html_cms_php",
    },
    {
        "name": "OpenCart",
        "pattern": re.compile(r'(?:OpenCart|route=common/home)', re.IGNORECASE),
        "confidence_signal": "html_cms_php",
    },
]

# PHPSESSID in Set-Cookie header or cookie value
PHPSESSID_RE = re.compile(r'\bPHPSESSID\b', re.IGNORECASE)

# PHP CLI error format seen in misconfigured web exposure
PHP_CLI_ERROR_RE = re.compile(
    r'PHP\s+\d+\.\d+\.\d+.*?(?:Copyright|cli|cgi)',
    re.IGNORECASE
)


def detect(
    body: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Inspect HTTP response body, cookies, and headers for PHP fingerprinting.

    Parameters
    ----------
    body    : HTTP response body text
    cookies : dict of cookie name → value (optional)
    headers : dict of response header names → values (optional)

    Returns
    -------
    {
        "php_detected":  bool,
        "version":       str | None,
        "cms":           str | None,       # Detected CMS/framework name
        "has_phpsessid": bool,
        "has_php_error": bool,
        "signals":       list[str],
        "evidence":      list[str],
    }
    """
    result: Dict[str, Any] = {
        "php_detected":  False,
        "version":       None,
        "cms":           None,
        "has_phpsessid": False,
        "has_php_error": False,
        "signals":       [],
        "evidence":      [],
    }

    if not body:
        body = ""

    cookies = cookies or {}
    headers = headers or {}
    norm_headers = {k.lower(): v for k, v in headers.items()}

    # ── 1. PHPSESSID cookie ───────────────────────────────────────────────
    # Check in Set-Cookie header and in cookies dict
    set_cookie = norm_headers.get("set-cookie", "")
    if PHPSESSID_RE.search(set_cookie) or any(
        PHPSESSID_RE.search(k) for k in cookies
    ):
        result["php_detected"]  = True
        result["has_phpsessid"] = True
        result["signals"].append("html_phpsessid")
        result["evidence"].append("PHPSESSID cookie detected → PHP session handling active")

    # ── 2. PHP error page ─────────────────────────────────────────────────
    if PHP_ERROR_RE.search(body):
        result["php_detected"] = True
        result["has_php_error"] = True
        result["signals"].append("html_php_error")
        result["evidence"].append("PHP error page pattern detected in response body")

        # Try to extract version from error page (some configurations expose it)
        vm = PHP_ERROR_VERSION_RE.search(body)
        if vm and not result["version"]:
            version = vm.group(1)
            result["version"] = version
            result["evidence"].append(
                f"PHP version {version} extracted from error page output"
            )

    # ── 3. CMS / Framework fingerprinting ────────────────────────────────
    for cms_def in CMS_PATTERNS:
        if cms_def["pattern"].search(body):
            result["php_detected"] = True
            if not result["cms"]:
                result["cms"] = cms_def["name"]
            result["signals"].append(cms_def["confidence_signal"])
            result["evidence"].append(
                f"CMS/framework pattern detected: {cms_def['name']} (uses PHP)"
            )
            break  # Only record first CMS match

    # ── 4. PHP version in HTML comments ──────────────────────────────────
    if not result["version"]:
        vm = PHP_HTML_VERSION_RE.search(body)
        if vm:
            version = vm.group(1) or vm.group(2)
            if version:
                result["php_detected"] = True
                result["version"]      = version
                result["signals"].append("html_php_comment")
                result["evidence"].append(
                    f"PHP version {version} found in HTML comment or meta tag"
                )

    # ── 5. PHP CLI error output accidentally served ───────────────────────
    if not result["version"]:
        cm = PHP_CLI_ERROR_RE.search(body)
        if cm:
            result["php_detected"] = True
            vm2 = PHP_ERROR_VERSION_RE.search(cm.group(0))
            if vm2:
                result["version"] = vm2.group(1)
                result["signals"].append("html_php_error")
                result["evidence"].append(
                    f"PHP CLI error output found in body → version {result['version']}"
                )

    # ── 6. Generic PHP presence from body ─────────────────────────────────
    if not result["php_detected"]:
        # Look for .php links in page (indicates PHP app even if version hidden)
        if re.search(r'href="[^"]*\.php', body, re.IGNORECASE):
            result["php_detected"] = True
            result["evidence"].append("PHP file links (.php) found in page body")

    return result
