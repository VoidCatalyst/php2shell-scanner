"""
version_check.py — PHP version parsing and PHP2Shell vulnerability status determination.

Uses packaging.version for proper semantic version comparison — never string-based
comparison. All CVE-2026-109618 / CVE-2026-109619 version boundaries are encoded here.
"""

import re
from enum import Enum
from typing import Optional, Dict, Any

try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    raise ImportError(
        "The 'packaging' library is required. Install with: pip install packaging"
    )


class VersionStatus(Enum):
    """Outcome codes for a PHP version vulnerability assessment."""
    AFFECTED       = "affected"        # Version is in the confirmed affected range
    FIXED          = "fixed"           # Version meets or exceeds the upstream fix
    VENDOR_CHECK   = "vendor_check"    # Branch requires vendor/distro patch verification
    LEGACY_EOL     = "legacy_eol"      # EOL branch; no standard upstream patch available
    PARSE_ERROR    = "parse_error"     # Version string could not be parsed
    UNKNOWN_BRANCH = "unknown_branch"  # Branch is not in the advisory database


# ─────────────────────────────────────────────────────────────────────────────
# PHP branch vulnerability data for CVE-2026-109618 and CVE-2026-109619.
#
# Fixed versions:  8.5.12 | 8.4.27 | 8.3.36 | 8.2.35  (released 2026-10-21)
# PHP 8.1, 8.0, 7.4: source backports published, no numbered upstream release.
#   → Requires vendor/distro package verification.
# PHP ≤ 7.3: end-of-life with no security support. No upstream patch path.
# Earliest affected code path per research: PHP 5.4.0.
# ─────────────────────────────────────────────────────────────────────────────
VERSION_BRANCHES: Dict[str, Dict[str, Any]] = {
    "8.5": {
        "fixed": "8.5.12",
        "eol": False,
        "support_type": "upstream",
        "eol_date": "2029-12-31",
        "notes": (
            "Active support branch. Update to PHP 8.5.12 or later. "
            "PHP2Shell workaround for CVE-2026-109619: set fatal_error_backtraces=0 "
            "and restart all PHP-FPM workers (temporary mitigation only)."
        ),
    },
    "8.4": {
        "fixed": "8.4.27",
        "eol": False,
        "support_type": "upstream",
        "eol_date": "2028-12-31",
        "notes": "Active support branch. Update to PHP 8.4.27 or later.",
    },
    "8.3": {
        "fixed": "8.3.36",
        "eol": False,
        "support_type": "upstream",
        "eol_date": "2027-12-31",
        "notes": "Security fixes branch. Update to PHP 8.3.36 or later.",
    },
    "8.2": {
        "fixed": "8.2.35",
        "eol": False,
        "support_type": "upstream",
        "eol_date": "2026-12-31",
        "notes": (
            "Security-fixes-only branch (EOL December 2026). "
            "Update to PHP 8.2.35 or later; plan migration to PHP 8.3+."
        ),
    },
    "8.1": {
        "fixed": None,
        "eol": True,
        "support_type": "vendor_only",
        "eol_date": "2024-11-25",
        "notes": (
            "PHP 8.1 is end-of-life (EOL 2024-11-25). "
            "The PHP project published source backports for 8.1 but no numbered release. "
            "Check your Linux distribution or platform vendor for a backported package "
            "containing the PHP2Shell fix."
        ),
    },
    "8.0": {
        "fixed": None,
        "eol": True,
        "support_type": "vendor_only",
        "eol_date": "2023-11-26",
        "notes": (
            "PHP 8.0 is end-of-life (EOL 2023-11-26). "
            "The PHP project published source backports for 8.0. "
            "Check your vendor for backported packages."
        ),
    },
    "7.4": {
        "fixed": None,
        "eol": True,
        "support_type": "vendor_only",
        "eol_date": "2022-11-28",
        "notes": (
            "PHP 7.4 is end-of-life (EOL 2022-11-28). "
            "The PHP project published source backports for 7.4. "
            "Check your vendor (e.g. Ubuntu, Debian, RHEL/AlmaLinux) for patched packages."
        ),
    },
    "7.3": {
        "fixed": None,
        "eol": True,
        "support_type": "none",
        "eol_date": "2021-12-06",
        "notes": (
            "PHP 7.3 is end-of-life (EOL 2021-12-06) with no upstream security support. "
            "No standard upstream security patch is available. "
            "Upgrade to PHP 8.2 or later immediately."
        ),
    },
    "7.2": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2020-11-30",
        "notes": "PHP 7.2 is end-of-life with no upstream security support. Upgrade immediately.",
    },
    "7.1": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2019-12-01",
        "notes": "PHP 7.1 is end-of-life with no upstream security support. Upgrade immediately.",
    },
    "7.0": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2019-01-10",
        "notes": "PHP 7.0 is end-of-life with no upstream security support. Upgrade immediately.",
    },
    "5.6": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2018-12-31",
        "notes": "PHP 5.6 is end-of-life with no upstream security support. Upgrade immediately.",
    },
    "5.5": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2016-07-21",
        "notes": "PHP 5.5 is end-of-life with no upstream security support. Upgrade immediately.",
    },
    "5.4": {
        "fixed": None, "eol": True, "support_type": "none", "eol_date": "2015-09-14",
        "notes": (
            "PHP 5.4 is end-of-life (EOL 2015-09-14) with no upstream security support. "
            "Earliest affected PHP branch per PHP2Shell research. Upgrade immediately."
        ),
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for version extraction
# ─────────────────────────────────────────────────────────────────────────────

# Matches "PHP/8.3.20", "PHP 8.3.20", "php/8.3.20RC1", etc.
PHP_VERSION_RE = re.compile(
    r'PHP[/\s](\d+\.\d+\.\d+(?:[.-](?:alpha|beta|rc|RC|dev|nts)\d*)?)',
    re.IGNORECASE
)

# Matches bare version strings like "8.3.20" or "8.3.20-fpm"
BARE_VERSION_RE = re.compile(
    r'^(\d+\.\d+\.\d+)(?:[.\-].*)?$'
)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def extract_version_from_string(text: str) -> Optional[str]:
    """
    Extract the first PHP version string from arbitrary text.
    Returns the version string (e.g. "8.3.20"), or None if not found.
    """
    if not text:
        return None
    match = PHP_VERSION_RE.search(text)
    if match:
        return _strip_prerelease(match.group(1))
    # Try bare version
    stripped = text.strip()
    match = BARE_VERSION_RE.match(stripped)
    if match:
        return match.group(1)
    return None


def normalize_version(version_str: str) -> Optional[str]:
    """
    Normalize a PHP version to canonical major.minor.patch, dropping pre-release tags.
    Returns None if the input cannot be recognized as a version.
    """
    if not version_str:
        return None
    version_str = version_str.strip()
    match = re.match(r'^(\d+\.\d+\.\d+)', version_str)
    return match.group(1) if match else None


def parse_php_version(version_str: str) -> Optional[Version]:
    """
    Parse a PHP version string into a packaging.version.Version object.
    Returns None on any parse failure — never raises.
    """
    normalized = normalize_version(version_str)
    if not normalized:
        return None
    try:
        return Version(normalized)
    except (InvalidVersion, TypeError, ValueError):
        return None


def get_php_branch(version: Version) -> str:
    """Return the PHP branch string (major.minor) for a Version object."""
    return f"{version.major}.{version.minor}"


def check_version_status(version_str: str) -> Dict[str, Any]:
    """
    Determine the PHP2Shell vulnerability status for a given PHP version string.

    This is the primary API for the vulnerability engine.

    Returns a dict:
    {
        "input_version":       str,            # Original input as supplied
        "normalized_version":  str | None,     # Normalized "X.Y.Z" form
        "branch":              str | None,     # "X.Y" branch (e.g. "8.3")
        "status":              VersionStatus,  # Classification enum
        "is_affected":         bool | None,    # True/False/None (None = indeterminate)
        "fixed_version":       str | None,     # First fixed version for branch
        "eol":                 bool,
        "support_type":        str,            # "upstream" / "vendor_only" / "none"
        "eol_date":            str | None,
        "notes":               list[str],
        "remediation":         str,
    }
    """
    result: Dict[str, Any] = {
        "input_version":      version_str,
        "normalized_version": None,
        "branch":             None,
        "status":             VersionStatus.PARSE_ERROR,
        "is_affected":        None,
        "fixed_version":      None,
        "eol":                False,
        "support_type":       "unknown",
        "eol_date":           None,
        "notes":              [],
        "remediation":        "Verify the PHP version and consult your vendor's security advisories.",
    }

    # ── 1. Normalize ──────────────────────────────────────────────────────────
    normalized = normalize_version(version_str)
    if not normalized:
        result["notes"].append(
            f"Cannot parse PHP version string: '{version_str}'"
        )
        return result

    result["normalized_version"] = normalized

    # ── 2. Parse ──────────────────────────────────────────────────────────────
    parsed = parse_php_version(normalized)
    if parsed is None:
        result["notes"].append(
            f"Cannot parse normalized version '{normalized}' as a semantic version."
        )
        return result

    # ── 3. Determine branch ───────────────────────────────────────────────────
    branch = get_php_branch(parsed)
    result["branch"] = branch

    if branch not in VERSION_BRANCHES:
        result["status"] = VersionStatus.UNKNOWN_BRANCH
        result["notes"].append(
            f"PHP branch {branch} is not in the PHP2Shell advisory database. "
            f"Cannot determine vulnerability status automatically."
        )
        result["remediation"] = (
            f"PHP {branch} is not covered by this advisory database. "
            f"Check https://www.php.net/security.php for applicable advisories."
        )
        return result

    # ── 4. Apply branch data ──────────────────────────────────────────────────
    bdata = VERSION_BRANCHES[branch]
    result["eol"]          = bdata["eol"]
    result["support_type"] = bdata["support_type"]
    result["fixed_version"] = bdata["fixed"]
    result["eol_date"]     = bdata.get("eol_date")
    result["notes"].append(bdata["notes"])

    # ── 5. Classify ───────────────────────────────────────────────────────────
    if bdata["support_type"] == "upstream":
        fixed_version = Version(bdata["fixed"])
        if parsed < fixed_version:
            result["status"]      = VersionStatus.AFFECTED
            result["is_affected"] = True
            result["notes"].append(
                f"PHP {normalized} is below the first fixed release {bdata['fixed']} "
                f"for the {branch} branch."
            )
            result["remediation"] = (
                f"Upgrade to PHP {bdata['fixed']} or any later {branch}.x release. "
                f"See https://www.php.net/downloads for the latest packages."
            )
        else:
            result["status"]      = VersionStatus.FIXED
            result["is_affected"] = False
            result["notes"].append(
                f"PHP {normalized} meets or exceeds the first fixed release "
                f"{bdata['fixed']} for the {branch} branch."
            )
            result["remediation"] = (
                "No action required for PHP2Shell on this version. "
                "Continue to keep PHP updated."
            )

    elif bdata["support_type"] == "vendor_only":
        result["status"]      = VersionStatus.VENDOR_CHECK
        result["is_affected"] = None
        eol_note = " (this branch is end-of-life upstream)" if bdata["eol"] else ""
        result["notes"].append(
            f"PHP {branch}{eol_note} has no numbered upstream release fixing PHP2Shell. "
            f"The PHP project published source backports. "
            f"Consult your Linux distribution or vendor for a backported package."
        )
        result["remediation"] = (
            f"Check your Linux distribution or platform vendor (e.g. Ubuntu, Debian, "
            f"RHEL/AlmaLinux/Rocky) for a PHP {branch} backport package containing the "
            f"PHP2Shell fix (CVE-2026-109618, CVE-2026-109619). "
            f"Consider upgrading to PHP 8.2 or later (supported branch with upstream fix)."
        )

    elif bdata["support_type"] == "none":
        result["status"]      = VersionStatus.LEGACY_EOL
        result["is_affected"] = None
        result["notes"].append(
            f"PHP {branch} is end-of-life and has no upstream security support or patch. "
            f"This branch is flagged as a legacy potentially-affected branch."
        )
        result["remediation"] = (
            f"PHP {branch} is end-of-life and receives no upstream security fixes. "
            f"Upgrade to PHP 8.3 or later immediately to receive PHP2Shell patches."
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _strip_prerelease(version_str: str) -> str:
    """Strip pre-release suffix from a version string, returning X.Y.Z."""
    match = re.match(r'^(\d+\.\d+\.\d+)', version_str)
    return match.group(1) if match else version_str
