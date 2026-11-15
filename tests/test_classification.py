"""
test_classification.py — End-to-end classification pipeline tests.

Exercises the full chain:
  version_check.check_version_status()
  → confidence.calculate_confidence()
  → vulnerability_engine.VulnerabilityEngine.classify_target()

Verifies that the documented CVSS-v4.0 severity tiers are produced for
real-world PHP version / architecture / signal combinations.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.version_check   import check_version_status, VersionStatus
from core.confidence      import calculate_confidence, ConfidenceLevel, SIGNAL_WEIGHTS
from core.fingerprint     import PhpFingerprint
from core.vulnerability_engine import VulnerabilityEngine, VulnStatus


engine = VulnerabilityEngine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fp(version, arch=None, signals=None, version_sources=None, version_consistent=True):
    """Build a PhpFingerprint directly from primitives for classification tests."""
    fp = PhpFingerprint()
    fp.php_detected    = True
    fp.version         = version
    fp.architecture    = arch
    fp.evidence        = []
    fp.version_conflict= not version_consistent
    _sigs = signals or []
    _vsrcs = version_sources or (["phpinfo_version"] if version else [])
    fp.confidence      = calculate_confidence(_sigs, _vsrcs, version_consistent)
    fp.confidence_note = ""
    return fp


# ---------------------------------------------------------------------------
# Full-pipeline version status tests
# ---------------------------------------------------------------------------

class TestVersionStatusMapping:

    def test_8_5_11_affected(self):
        s = check_version_status("8.5.11")
        assert s["status"] == VersionStatus.AFFECTED
        assert s["is_affected"] is True

    def test_8_5_12_fixed(self):
        s = check_version_status("8.5.12")
        assert s["status"] == VersionStatus.FIXED
        assert s["is_affected"] is False

    def test_8_4_26_affected(self):
        s = check_version_status("8.4.26")
        assert s["status"] == VersionStatus.AFFECTED

    def test_8_4_27_fixed(self):
        s = check_version_status("8.4.27")
        assert s["status"] == VersionStatus.FIXED

    def test_8_3_35_affected(self):
        s = check_version_status("8.3.35")
        assert s["status"] == VersionStatus.AFFECTED

    def test_8_3_36_fixed(self):
        s = check_version_status("8.3.36")
        assert s["status"] == VersionStatus.FIXED

    def test_8_2_34_affected(self):
        s = check_version_status("8.2.34")
        assert s["status"] == VersionStatus.AFFECTED

    def test_8_2_35_fixed(self):
        s = check_version_status("8.2.35")
        assert s["status"] == VersionStatus.FIXED

    def test_8_1_vendor_check(self):
        s = check_version_status("8.1.28")
        assert s["status"] == VersionStatus.VENDOR_CHECK
        assert s["is_affected"] is None

    def test_7_4_vendor_check(self):
        s = check_version_status("7.4.33")
        assert s["status"] == VersionStatus.VENDOR_CHECK

    def test_7_3_legacy_eol(self):
        s = check_version_status("7.3.33")
        assert s["status"] == VersionStatus.LEGACY_EOL

    def test_5_6_legacy_eol(self):
        s = check_version_status("5.6.40")
        assert s["status"] == VersionStatus.LEGACY_EOL


# ---------------------------------------------------------------------------
# Confidence tier tests
# ---------------------------------------------------------------------------

class TestConfidenceTiers:

    def test_local_binary_signal_alone_is_high(self):
        c = calculate_confidence(["local_php_binary"], ["local_php_binary"], True)
        assert c >= ConfidenceLevel.HIGH

    def test_phpinfo_signals_are_high(self):
        c = calculate_confidence(
            ["phpinfo_page", "phpinfo_version"],
            ["phpinfo_version"],
            True,
        )
        assert c >= ConfidenceLevel.HIGH

    def test_x_powered_by_alone_is_low_or_medium(self):
        c = calculate_confidence(["header_x_powered_by"], ["header_x_powered_by"], True)
        assert c <= ConfidenceLevel.MEDIUM

    def test_no_signals_is_none(self):
        c = calculate_confidence([], [], True)
        assert c == ConfidenceLevel.NONE

    def test_phpsessid_alone_is_low(self):
        c = calculate_confidence(["html_phpsessid"], ["html_phpsessid"], True)
        assert c <= ConfidenceLevel.LOW

    def test_inconsistent_sources_reduces_confidence(self):
        c_consistent   = calculate_confidence(
            ["header_x_powered_by", "phpinfo_version"],
            ["header_x_powered_by", "phpinfo_version"],
            True,
        )
        c_inconsistent = calculate_confidence(
            ["header_x_powered_by", "phpinfo_version"],
            ["header_x_powered_by", "phpinfo_version"],
            False,
        )
        assert c_inconsistent <= c_consistent


# ---------------------------------------------------------------------------
# End-to-end classification tests (vuln status)
# ---------------------------------------------------------------------------

class TestClassificationPipeline:

    # ---- CRITICAL ---------------------------------------------------------

    def test_critical_fpm_8_3_35_high_confidence(self):
        fp = _fp(
            version="8.3.35",
            arch="fpm",
            signals=["phpinfo_page", "phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.CRITICAL

    def test_critical_modphp_8_4_26_high_confidence(self):
        fp = _fp(
            version="8.4.26",
            arch="mod_php",
            signals=["phpinfo_page", "phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.CRITICAL

    def test_critical_litespeed_8_2_34(self):
        fp = _fp(
            version="8.2.34",
            arch="litespeed",
            signals=["phpinfo_page", "phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.CRITICAL

    def test_critical_frankenphp_8_5_11(self):
        fp = _fp(
            version="8.5.11",
            arch="frankenphp",
            signals=["local_php_binary"],
            version_sources=["local_php_binary"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.CRITICAL

    # ---- HIGH -------------------------------------------------------------

    def test_high_no_arch_8_3_20_medium_confidence(self):
        fp = _fp(
            version="8.3.20",
            arch=None,
            signals=["phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.HIGH

    def test_high_cgi_arch_does_not_upgrade_to_critical(self):
        """CGI is not a persistent-worker architecture → no CRITICAL upgrade."""
        fp = _fp(
            version="8.4.10",
            arch="cgi",
            signals=["phpinfo_page", "phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        # CGI is not in HIGH_RISK_ARCHITECTURES, so must NOT be CRITICAL
        assert a.overall_status != VulnStatus.CRITICAL

    # ---- MEDIUM -----------------------------------------------------------

    def test_medium_low_confidence_header_only(self):
        fp = _fp(
            version="8.5.10",
            arch="fpm",
            signals=["header_x_powered_by"],
            version_sources=["header_x_powered_by"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.MEDIUM

    # ---- NOT_VULNERABLE ---------------------------------------------------

    def test_not_vulnerable_8_3_36_fixed(self):
        fp = _fp(
            version="8.3.36",
            arch="fpm",
            signals=["phpinfo_page", "phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.NOT_VULNERABLE

    def test_not_vulnerable_8_4_27_fixed(self):
        fp = _fp(
            version="8.4.27",
            arch="mod_php",
            signals=["phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.NOT_VULNERABLE

    def test_not_vulnerable_8_5_12_fixed(self):
        fp = _fp(
            version="8.5.12",
            arch="fpm",
            signals=["local_php_binary"],
            version_sources=["local_php_binary"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.NOT_VULNERABLE

    # ---- LOW (vendor_check / legacy_eol) ----------------------------------

    def test_low_vendor_check_8_1_28(self):
        fp = _fp(
            version="8.1.28",
            arch="fpm",
            signals=["phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.LOW

    def test_low_legacy_eol_7_4_33(self):
        fp = _fp(
            version="7.4.33",
            arch=None,
            signals=["header_x_powered_by"],
            version_sources=["header_x_powered_by"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.LOW

    def test_low_legacy_eol_5_6(self):
        fp = _fp(
            version="5.6.40",
            arch=None,
            signals=["header_x_powered_by"],
            version_sources=["header_x_powered_by"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.LOW

    # ---- UNKNOWN ----------------------------------------------------------

    def test_unknown_no_version(self):
        fp = _fp(version=None, arch=None, signals=[], version_sources=[])
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.UNKNOWN

    def test_unknown_php_not_detected(self):
        fp = PhpFingerprint()
        fp.php_detected = False
        fp.confidence   = ConfidenceLevel.NONE
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.UNKNOWN

    # ---- Boundary / regression -------------------------------------------

    def test_exactly_at_fix_boundary(self):
        """8.3.36 is exactly the fix → NOT_VULNERABLE, not AFFECTED."""
        from packaging.version import Version
        from core.version_check import VERSION_BRANCHES
        fix = Version(VERSION_BRANCHES["8.3"]["fixed_version"])
        assert fix == Version("8.3.36")
        fp = _fp(
            version="8.3.36",
            arch="fpm",
            signals=["phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status == VulnStatus.NOT_VULNERABLE

    def test_one_patch_below_fix_boundary(self):
        """8.3.35 is one patch before the fix → AFFECTED."""
        fp = _fp(
            version="8.3.35",
            arch="fpm",
            signals=["phpinfo_version"],
            version_sources=["phpinfo_version"],
        )
        a = engine.classify_target(fp)
        assert a.overall_status in (VulnStatus.CRITICAL, VulnStatus.HIGH)
