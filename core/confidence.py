"""
confidence.py — Confidence scoring for PHP2Shell vulnerability assessments.

Confidence represents how certain we are that the detected PHP version and
execution architecture are accurate. High confidence requires direct evidence
(e.g. phpinfo page parsed, local `php --version` output). Low confidence
means we're inferring from indirect signals only (e.g. a single header).

This deliberately separates confidence (how sure we are of the detection)
from severity (how bad the vulnerability is if our detection is correct).
"""

from enum import Enum
from typing import List, Dict, Any


class ConfidenceLevel(Enum):
    """
    Confidence tiers for PHP version and architecture detection.

    CONFIRMED:   Version verified from two or more independent sources,
                 or from a direct phpinfo / local binary read.
    HIGH:        Version verified from one reliable source (e.g. phpinfo,
                 local php binary) with architectural context available.
    MEDIUM:      Version inferred from HTTP headers with consistent signals
                 across multiple headers, or single phpinfo-style page.
    LOW:         Version inferred from a single unreliable header, or
                 partial pattern match in HTML/app footprint.
    NONE:        No PHP version detected. Architecture may still be inferred.
    """
    CONFIRMED = "CONFIRMED"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    LOW       = "LOW"
    NONE      = "NONE"

    @property
    def numeric(self) -> int:
        """Return a sortable numeric weight (higher = more confident)."""
        return {
            "CONFIRMED": 100,
            "HIGH":       75,
            "MEDIUM":     50,
            "LOW":        25,
            "NONE":        0,
        }[self.value]

    def __ge__(self, other: "ConfidenceLevel") -> bool:
        return self.numeric >= other.numeric

    def __gt__(self, other: "ConfidenceLevel") -> bool:
        return self.numeric > other.numeric

    def __le__(self, other: "ConfidenceLevel") -> bool:
        return self.numeric <= other.numeric

    def __lt__(self, other: "ConfidenceLevel") -> bool:
        return self.numeric < other.numeric


# ─────────────────────────────────────────────────────────────────────────────
# Signal definitions — each detector contributes named signals
# ─────────────────────────────────────────────────────────────────────────────

# Signal weights: how much each evidence type contributes
SIGNAL_WEIGHTS: Dict[str, int] = {
    # Local (most reliable — direct binary or package query)
    "local_php_binary":     100,  # php --version output
    "local_package_query":   80,  # apt/rpm package metadata

    # phpinfo (highly reliable — from server itself)
    "phpinfo_page":          90,  # parsed phpinfo() page
    "phpinfo_version":       90,  # version extracted from phpinfo()
    "phpinfo_server_api":    85,  # Server API from phpinfo (architecture)

    # HTTP headers (moderately reliable)
    "header_x_powered_by":  60,  # X-Powered-By: PHP/X.Y.Z
    "header_server":         40,  # Server: ... PHP/X.Y.Z
    "header_x_generator":   30,  # X-Generator: ...
    "header_via":            20,  # Via: ...

    # HTML / application fingerprinting (less reliable)
    "html_phpsessid":        30,  # PHPSESSID cookie
    "html_php_error":        50,  # PHP error page (may contain version)
    "html_cms_php":          20,  # CMS using PHP (confirms PHP presence)
    "html_php_comment":      25,  # HTML comment mentioning PHP version

    # Architecture signals
    "arch_fpm":              40,  # PHP-FPM server API detected
    "arch_mod_php":          40,  # Apache mod_php detected
    "arch_cgi":              30,  # CGI mode detected
    "arch_litespeed":        35,  # LiteSpeed PHP detected
    "arch_frankenphp":       35,  # FrankenPHP detected
}


def calculate_confidence(
    detected_signals: List[str],
    version_sources: int = 0,
    version_consistent: bool = True,
) -> ConfidenceLevel:
    """
    Calculate overall confidence level from a list of detected signal names.

    Parameters
    ----------
    detected_signals : list of signal name strings (from SIGNAL_WEIGHTS keys)
    version_sources  : number of independent sources that agree on the version
    version_consistent : whether all sources report the same version
                         (False → downgrade by one tier)

    Returns
    -------
    ConfidenceLevel
    """
    if not detected_signals:
        return ConfidenceLevel.NONE

    # Compute total weight from active signals
    total_weight = sum(
        SIGNAL_WEIGHTS.get(sig, 0)
        for sig in detected_signals
        if sig in SIGNAL_WEIGHTS
    )

    # Apply source-agreement boost
    if version_sources >= 2 and version_consistent:
        total_weight += 20

    # Map weight to tier
    if total_weight >= 100:
        level = ConfidenceLevel.CONFIRMED
    elif total_weight >= 70:
        level = ConfidenceLevel.HIGH
    elif total_weight >= 40:
        level = ConfidenceLevel.MEDIUM
    elif total_weight > 0:
        level = ConfidenceLevel.LOW
    else:
        level = ConfidenceLevel.NONE

    # Downgrade one tier if version reports are inconsistent
    if not version_consistent and version_sources > 1:
        level = _downgrade(level)

    return level


def _downgrade(level: ConfidenceLevel) -> ConfidenceLevel:
    """Return the next lower confidence tier."""
    order = [
        ConfidenceLevel.CONFIRMED,
        ConfidenceLevel.HIGH,
        ConfidenceLevel.MEDIUM,
        ConfidenceLevel.LOW,
        ConfidenceLevel.NONE,
    ]
    idx = order.index(level)
    return order[min(idx + 1, len(order) - 1)]


def build_confidence_note(
    level: ConfidenceLevel,
    detected_signals: List[str],
) -> str:
    """
    Return a human-readable explanation of the confidence assessment.
    Used in VAPT reports to provide assessor transparency.
    """
    signal_names = [s.replace("_", " ") for s in detected_signals if s in SIGNAL_WEIGHTS]
    source_summary = ", ".join(signal_names) if signal_names else "no signals"

    explanations = {
        ConfidenceLevel.CONFIRMED: (
            f"Version confirmed from multiple independent sources ({source_summary}). "
            "Vulnerability status is highly reliable."
        ),
        ConfidenceLevel.HIGH: (
            f"Version detected from reliable direct source ({source_summary}). "
            "Assessment accuracy is high."
        ),
        ConfidenceLevel.MEDIUM: (
            f"Version inferred from indirect HTTP signals ({source_summary}). "
            "Accuracy is moderate; manual verification recommended for critical decisions."
        ),
        ConfidenceLevel.LOW: (
            f"Version inferred from limited indirect evidence ({source_summary}). "
            "Manual verification strongly recommended before any remediation decisions."
        ),
        ConfidenceLevel.NONE: (
            "No PHP version could be detected. PHP presence may be inferred from "
            "other signals, but vulnerability status cannot be determined."
        ),
    }

    return explanations.get(level, "Confidence level undetermined.")
