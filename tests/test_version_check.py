"""
test_version_check.py — All 16 version-check scenarios for PHP2Shell Scanner.

Tests verify correct behavior of check_version_status() for all PHP branches,
including upstream-fixed, vendor-only backport, EOL, and edge cases.

Run with: python -m pytest tests/test_version_check.py -v
"""

import sys
import os
import pytest

# Allow import from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.version_check import (
    check_version_status,
    parse_php_version,
    extract_version_from_string,
    normalize_version,
    VersionStatus,
)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1: PHP 8.5.11 — AFFECTED (below 8.5.12)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_5_11_affected():
    result = check_version_status("8.5.11")
    assert result["status"] == VersionStatus.AFFECTED
    assert result["is_affected"] is True
    assert result["fixed_version"] == "8.5.12"
    assert result["branch"] == "8.5"
    assert result["eol"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2: PHP 8.5.12 — FIXED (at the first fixed release)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_5_12_fixed():
    result = check_version_status("8.5.12")
    assert result["status"] == VersionStatus.FIXED
    assert result["is_affected"] is False
    assert result["fixed_version"] == "8.5.12"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3: PHP 8.4.26 — AFFECTED (below 8.4.27)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_4_26_affected():
    result = check_version_status("8.4.26")
    assert result["status"] == VersionStatus.AFFECTED
    assert result["is_affected"] is True
    assert result["fixed_version"] == "8.4.27"
    assert result["branch"] == "8.4"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4: PHP 8.4.27 — FIXED
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_4_27_fixed():
    result = check_version_status("8.4.27")
    assert result["status"] == VersionStatus.FIXED
    assert result["is_affected"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5: PHP 8.3.35 — AFFECTED (below 8.3.36)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_3_35_affected():
    result = check_version_status("8.3.35")
    assert result["status"] == VersionStatus.AFFECTED
    assert result["is_affected"] is True
    assert result["fixed_version"] == "8.3.36"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 6: PHP 8.3.36 — FIXED
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_3_36_fixed():
    result = check_version_status("8.3.36")
    assert result["status"] == VersionStatus.FIXED
    assert result["is_affected"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 7: PHP 8.2.34 — AFFECTED (below 8.2.35)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_2_34_affected():
    result = check_version_status("8.2.34")
    assert result["status"] == VersionStatus.AFFECTED
    assert result["is_affected"] is True
    assert result["fixed_version"] == "8.2.35"
    assert result["branch"] == "8.2"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 8: PHP 8.2.35 — FIXED
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_2_35_fixed():
    result = check_version_status("8.2.35")
    assert result["status"] == VersionStatus.FIXED
    assert result["is_affected"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 9: PHP 7.4.x — VENDOR_CHECK (source backport, no numbered release)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_7_4_vendor_check():
    result = check_version_status("7.4.33")
    assert result["status"] == VersionStatus.VENDOR_CHECK
    assert result["is_affected"] is None      # Indeterminate without distro pkg query
    assert result["fixed_version"] is None
    assert result["support_type"] == "vendor_only"
    assert result["eol"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 10: PHP 8.1.x — VENDOR_CHECK (source backport, no numbered release)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_8_1_vendor_check():
    result = check_version_status("8.1.28")
    assert result["status"] == VersionStatus.VENDOR_CHECK
    assert result["is_affected"] is None
    assert result["support_type"] == "vendor_only"
    assert result["branch"] == "8.1"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 11: PHP 7.3 — LEGACY_EOL (EOL, no patch)
# ─────────────────────────────────────────────────────────────────────────────
def test_php_7_3_legacy_eol():
    result = check_version_status("7.3.33")
    assert result["status"] == VersionStatus.LEGACY_EOL
    assert result["support_type"] == "none"
    assert result["eol"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 12: No version string — PARSE_ERROR
# ─────────────────────────────────────────────────────────────────────────────
def test_no_version_string():
    result = check_version_status("")
    assert result["status"] == VersionStatus.PARSE_ERROR
    assert result["normalized_version"] is None


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 13: PHP not detected (nonsense string) — PARSE_ERROR
# ─────────────────────────────────────────────────────────────────────────────
def test_non_php_string():
    result = check_version_status("nginx/1.24.0")
    assert result["status"] == VersionStatus.PARSE_ERROR


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 14: Malformed version string (letters only) — PARSE_ERROR
# ─────────────────────────────────────────────────────────────────────────────
def test_malformed_version():
    result = check_version_status("PHPVERSION")
    assert result["status"] == VersionStatus.PARSE_ERROR

    result2 = check_version_status("8.3")
    # Only X.Y provided — should fail normalize (no patch)
    assert result2["status"] == VersionStatus.PARSE_ERROR


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 15: Reverse proxy header (X-Powered-By with extra text)
# Tests extract_version_from_string() against a typical header value
# ─────────────────────────────────────────────────────────────────────────────
def test_extract_version_from_header():
    header_value = "PHP/8.3.20"
    version = extract_version_from_string(header_value)
    assert version == "8.3.20"

    result = check_version_status(version)
    assert result["status"] == VersionStatus.AFFECTED
    assert result["branch"] == "8.3"


def test_extract_version_from_server_header():
    # Reverse proxy may expose PHP version inside Server header
    header_value = "Apache/2.4.57 (Ubuntu) OpenSSL/3.0.9 PHP/8.2.14"
    version = extract_version_from_string(header_value)
    assert version == "8.2.14"

    result = check_version_status(version)
    assert result["status"] == VersionStatus.AFFECTED


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 16: CLI vs FPM version mismatch (normalize both)
# Tests that packaging.version is used (not string comparison)
# ─────────────────────────────────────────────────────────────────────────────
def test_packaging_version_no_string_comparison():
    """
    Critical: verify that version comparison uses packaging.version,
    not naive string ordering (which would rank "8.9" > "8.10").
    """
    from packaging.version import Version

    v_a = Version("8.3.9")
    v_b = Version("8.3.10")
    # Naive string comparison would claim "8.3.9" > "8.3.10" (wrong!)
    # packaging.version must correctly order these
    assert v_a < v_b, "packaging.version must handle X.Y.Z correctly"
    assert Version("8.3.10") > Version("8.3.9"), "10 > 9 in patch"
    assert Version("8.5.12") >= Version("8.5.12"), "exact match is not less"

    # check_version_status must use this comparison internally
    r9  = check_version_status("8.3.9")
    r10 = check_version_status("8.3.10")
    # Both below 8.3.36, both should be AFFECTED
    assert r9["status"] == VersionStatus.AFFECTED
    assert r10["status"] == VersionStatus.AFFECTED


def test_version_at_fix_boundary():
    """Fixed version is exactly at boundary — must classify as FIXED, not AFFECTED."""
    for ver, expected_fixed in [
        ("8.5.12", "8.5.12"),
        ("8.4.27", "8.4.27"),
        ("8.3.36", "8.3.36"),
        ("8.2.35", "8.2.35"),
    ]:
        r = check_version_status(ver)
        assert r["status"] == VersionStatus.FIXED, (
            f"{ver} should be FIXED (>= {expected_fixed})"
        )
        assert r["is_affected"] is False


def test_version_just_below_fix_boundary():
    """One patch below fixed version must classify as AFFECTED."""
    for ver, fixed in [
        ("8.5.11", "8.5.12"),
        ("8.4.26", "8.4.27"),
        ("8.3.35", "8.3.36"),
        ("8.2.34", "8.2.35"),
    ]:
        r = check_version_status(ver)
        assert r["status"] == VersionStatus.AFFECTED, (
            f"{ver} should be AFFECTED (below {fixed})"
        )
        assert r["is_affected"] is True


def test_normalize_version_strips_suffix():
    """normalize_version should strip pre-release suffixes."""
    assert normalize_version("8.3.20-fpm") == "8.3.20"
    assert normalize_version("8.3.20") == "8.3.20"
    assert normalize_version("8.3.20-ubuntu22.04") == "8.3.20"


def test_extract_version_from_phpinfo_output():
    """Test extraction from phpinfo() style strings."""
    phpinfo_text = "PHP Version 8.4.26"
    version = extract_version_from_string(phpinfo_text)
    assert version == "8.4.26"

    result = check_version_status(version)
    assert result["status"] == VersionStatus.AFFECTED
