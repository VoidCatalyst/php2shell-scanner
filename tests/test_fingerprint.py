"""
test_fingerprint.py — Tests for PhpFingerprinter detector merging logic.

These tests exercise version-source priority resolution, conflict detection,
confidence calculation, and the interaction between the four detection methods
(header, HTML, phpinfo, local).  The HTTP client is mocked so no live
network calls are made.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from core.fingerprint import PhpFingerprinter, PhpFingerprint
from core.confidence import ConfidenceLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client():
    """Return a minimal mock of PhpHttpClient."""
    c = MagicMock()
    # get_response_dict returns None by default → no network activity
    c.get_response_dict.return_value = None
    return c


def _make_fp_with_header_version(version: str = "8.3.35") -> PhpFingerprint:
    """Run fingerprinter with only a header-detected PHP version."""
    client = _make_client()

    # Simulate header detector returning a version
    header_result = {
        "php_detected": True,
        "version": version,
        "version_raw": f"PHP/{version}",
        "header_source": "X-Powered-By",
        "architecture": None,
        "signals": ["header_x_powered_by"],
        "evidence": [f"X-Powered-By: PHP/{version}"],
        "raw_headers": {"x-powered-by": f"PHP/{version}"},
    }
    # Simulate no phpinfo, no local, no HTML
    html_result = {"php_detected": False, "version": None, "cms": None,
                   "has_phpsessid": False, "has_php_error": False,
                   "signals": [], "evidence": []}

    fp = PhpFingerprint()
    fp._apply_header_result(header_result)
    fp._apply_html_result(html_result)
    fp._apply_phpinfo_result({"php_detected": False, "version": None,
                               "architecture": None, "signals": [],
                               "evidence": [], "mitigation_applied": False,
                               "checked_paths": []})
    fp._apply_local_result({"php_detected": False, "version": None,
                              "architecture": None, "signals": [],
                              "evidence": [], "package_manager_version": None})
    fp._calculate_final_confidence()
    return fp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVersionPriority:

    def test_header_only_version_used(self):
        fp = _make_fp_with_header_version("8.3.20")
        assert fp.version == "8.3.20"
        assert fp.version_source == "header"

    def test_phpinfo_overrides_header(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": True, "version": "8.3.20", "version_raw": "PHP/8.3.20",
            "header_source": "X-Powered-By", "architecture": None,
            "signals": ["header_x_powered_by"], "evidence": [],
            "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": True, "version": "8.3.21", "version_raw": "8.3.21",
            "architecture": "fpm", "signals": ["phpinfo_page", "phpinfo_version"],
            "evidence": ["phpinfo found at /phpinfo.php"],
            "mitigation_applied": False, "checked_paths": ["/phpinfo.php"]
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        # phpinfo priority > header
        assert fp.version == "8.3.21"
        assert fp.version_source in ("phpinfo", "phpinfo_version")

    def test_local_overrides_phpinfo(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": False, "version": None, "version_raw": None,
            "header_source": None, "architecture": None,
            "signals": [], "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": True, "version": "8.4.10", "version_raw": "8.4.10",
            "architecture": "fpm", "signals": ["phpinfo_version"],
            "evidence": [], "mitigation_applied": False, "checked_paths": []
        })
        fp._apply_local_result({
            "php_detected": True, "version": "8.4.11", "version_raw": "PHP 8.4.11",
            "architecture": "fpm", "signals": ["local_php_binary"],
            "evidence": ["php --version → PHP 8.4.11"],
            "package_manager_version": None
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._calculate_final_confidence()
        # local binary has highest priority
        assert fp.version == "8.4.11"
        assert fp.version_source in ("local", "local_php_binary")


class TestArchitectureDetection:

    def test_architecture_from_phpinfo(self):
        fp = PhpFingerprint()
        fp._apply_phpinfo_result({
            "php_detected": True, "version": "8.5.11", "version_raw": "8.5.11",
            "architecture": "fpm",
            "signals": ["phpinfo_page", "phpinfo_version"],
            "evidence": [], "mitigation_applied": False, "checked_paths": []
        })
        fp._apply_header_result({
            "php_detected": True, "version": "8.5.11", "version_raw": "PHP/8.5.11",
            "header_source": "X-Powered-By", "architecture": None,
            "signals": ["header_x_powered_by"], "evidence": [], "raw_headers": {}
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        assert fp.architecture == "fpm"

    def test_architecture_from_header(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": True, "version": "8.2.34", "version_raw": "PHP/8.2.34",
            "header_source": "X-Powered-By", "architecture": "litespeed",
            "signals": ["header_x_powered_by", "architecture_litespeed"],
            "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "mitigation_applied": False,
            "checked_paths": []
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        assert fp.architecture == "litespeed"


class TestConfidenceCalc:

    def test_local_binary_gives_high_confidence(self):
        fp = PhpFingerprint()
        fp._apply_local_result({
            "php_detected": True, "version": "8.4.26", "version_raw": "PHP 8.4.26",
            "architecture": "fpm", "signals": ["local_php_binary"],
            "evidence": ["php --version → PHP 8.4.26"],
            "package_manager_version": None
        })
        fp._apply_header_result({
            "php_detected": False, "version": None, "version_raw": None,
            "header_source": None, "architecture": None,
            "signals": [], "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "mitigation_applied": False,
            "checked_paths": []
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._calculate_final_confidence()
        assert fp.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED)

    def test_header_only_gives_at_most_medium_confidence(self):
        fp = _make_fp_with_header_version("8.3.35")
        # Header-only evidence should not reach CONFIRMED
        assert fp.confidence <= ConfidenceLevel.MEDIUM

    def test_no_php_gives_none_confidence(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": False, "version": None, "version_raw": None,
            "header_source": None, "architecture": None,
            "signals": [], "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "mitigation_applied": False,
            "checked_paths": []
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        assert not fp.php_detected
        assert fp.confidence == ConfidenceLevel.NONE


class TestVersionConflict:

    def test_conflict_flagged_when_versions_differ(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": True, "version": "8.3.10", "version_raw": "PHP/8.3.10",
            "header_source": "X-Powered-By", "architecture": None,
            "signals": ["header_x_powered_by"], "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": True, "version": "8.3.20", "version_raw": "8.3.20",
            "architecture": "fpm", "signals": ["phpinfo_version"],
            "evidence": [], "mitigation_applied": False, "checked_paths": []
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        # Fingerprint should note the disagreement
        assert fp.version_conflict is True

    def test_no_conflict_when_versions_agree(self):
        fp = PhpFingerprint()
        fp._apply_header_result({
            "php_detected": True, "version": "8.5.11", "version_raw": "PHP/8.5.11",
            "header_source": "X-Powered-By", "architecture": None,
            "signals": ["header_x_powered_by"], "evidence": [], "raw_headers": {}
        })
        fp._apply_phpinfo_result({
            "php_detected": True, "version": "8.5.11", "version_raw": "8.5.11",
            "architecture": "fpm", "signals": ["phpinfo_version"],
            "evidence": [], "mitigation_applied": False, "checked_paths": []
        })
        fp._apply_html_result({
            "php_detected": False, "version": None, "cms": None,
            "has_phpsessid": False, "has_php_error": False,
            "signals": [], "evidence": []
        })
        fp._apply_local_result({
            "php_detected": False, "version": None, "architecture": None,
            "signals": [], "evidence": [], "package_manager_version": None
        })
        fp._calculate_final_confidence()
        assert fp.version_conflict is False
