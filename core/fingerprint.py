"""
fingerprint.py — PHP fingerprinting engine.

Runs all independent detection methods and aggregates results into a
single PhpFingerprint object with version, architecture, confidence, and
all evidence collected.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from core.confidence import ConfidenceLevel, calculate_confidence, build_confidence_note
from core.version_check import extract_version_from_string
from detectors import header_detector, html_detector, phpinfo_detector, local_detector

logger = logging.getLogger("php2shell")


@dataclass
class PhpFingerprint:
    """
    Aggregated PHP fingerprint for a single target.

    Populated by PhpFingerprinter.fingerprint() and consumed by
    VulnerabilityEngine for CVE assessment.
    """
    # Core detection
    php_detected:   bool = False
    version:        Optional[str] = None          # Normalized X.Y.Z or None
    version_sources: List[str] = field(default_factory=list)  # Sources agreeing
    architecture:   Optional[str] = None          # fpm/mod_php/cgi/etc.

    # Confidence
    confidence:        ConfidenceLevel = ConfidenceLevel.NONE
    confidence_note:   str = ""
    signals:           List[str] = field(default_factory=list)

    # Per-detector results (raw)
    header_result:   Optional[Dict[str, Any]] = None
    html_result:     Optional[Dict[str, Any]] = None
    phpinfo_result:  Optional[Dict[str, Any]] = None
    local_result:    Optional[Dict[str, Any]] = None

    # Aggregated evidence lines
    evidence:        List[str] = field(default_factory=list)

    # CMS / framework hint
    cms: Optional[str] = None

    # Configuration hints (from phpinfo)
    memory_limit:   Optional[str] = None
    fatal_bt:       Optional[str] = None
    thread_safe:    Optional[bool] = None

    # Metadata
    target:         str = ""


class PhpFingerprinter:
    """
    Multi-method PHP fingerprinting engine.

    Runs up to four independent detection methods per target and merges
    all evidence into a PhpFingerprint. Version resolution prioritizes
    higher-confidence sources; conflicting versions are noted.
    """

    def __init__(
        self,
        http_client,
        check_phpinfo:  bool = True,
        check_local:    bool = False,
        phpinfo_paths:  Optional[List[str]] = None,
    ):
        self.http_client    = http_client
        self.check_phpinfo  = check_phpinfo
        self.check_local    = check_local
        self.phpinfo_paths  = phpinfo_paths

    def fingerprint(self, url: str) -> PhpFingerprint:
        """
        Run all configured detection methods against a URL and return
        a consolidated PhpFingerprint.
        """
        fp = PhpFingerprint(target=url)

        # ── Method 1: HTTP header fingerprinting ──────────────────────────
        header_result = self._run_header_detection(url)
        fp.header_result = header_result
        if header_result:
            self._merge_result(fp, header_result)

        # ── Method 2: HTML / application fingerprinting ──────────────────
        html_result = self._run_html_detection(url, header_result)
        fp.html_result = html_result
        if html_result:
            self._merge_result(fp, html_result)
            if html_result.get("cms"):
                fp.cms = html_result["cms"]

        # ── Method 3: phpinfo() endpoint detection ────────────────────────
        if self.check_phpinfo:
            phpinfo_result = self._run_phpinfo_detection(url)
            fp.phpinfo_result = phpinfo_result
            if phpinfo_result and phpinfo_result.get("found"):
                self._merge_phpinfo_result(fp, phpinfo_result)

        # ── Method 4: Local PHP runtime detection ─────────────────────────
        if self.check_local:
            local_result = local_detector.detect()
            fp.local_result = local_result
            if local_result.get("php_found"):
                self._merge_result(fp, local_result, version_key="version",
                                   found_key="php_found")

        # ── Resolve version and calculate confidence ──────────────────────
        self._resolve_version(fp)
        self._calculate_final_confidence(fp)

        return fp

    # ─────────────────────────────────────────────────────────────────────
    # Detection runners
    # ─────────────────────────────────────────────────────────────────────

    def _run_header_detection(self, url: str) -> Optional[Dict[str, Any]]:
        """Run Method 1: header detection from HTTP response."""
        try:
            resp_dict = self.http_client.get_response_dict(url)
            if not resp_dict.get("success"):
                return None
            headers = resp_dict.get("headers", {})
            result = header_detector.detect(headers)
            return result
        except Exception as exc:
            logger.debug(f"Header detection failed for {url}: {exc}")
            return None

    def _run_html_detection(
        self,
        url: str,
        header_result: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Run Method 2: HTML / application fingerprinting."""
        try:
            resp_dict = self.http_client.get_response_dict(url)
            if not resp_dict.get("success"):
                return None
            body    = resp_dict.get("body", "")
            headers = resp_dict.get("headers", {})
            result  = html_detector.detect(body=body, headers=headers)
            return result
        except Exception as exc:
            logger.debug(f"HTML detection failed for {url}: {exc}")
            return None

    def _run_phpinfo_detection(self, url: str) -> Optional[Dict[str, Any]]:
        """Run Method 3: phpinfo() endpoint detection."""
        try:
            result = phpinfo_detector.detect(
                base_url=url,
                http_client=self.http_client,
                check_paths=self.phpinfo_paths,
            )
            return result
        except Exception as exc:
            logger.debug(f"phpinfo detection failed for {url}: {exc}")
            return None

    # ─────────────────────────────────────────────────────────────────────
    # Merging helpers
    # ─────────────────────────────────────────────────────────────────────

    def _merge_result(
        self,
        fp: PhpFingerprint,
        result: Dict[str, Any],
        version_key: str = "version",
        found_key:   str = "php_detected",
    ) -> None:
        """Merge a generic detector result into the fingerprint."""
        if result.get(found_key) or result.get("php_found"):
            fp.php_detected = True

        version = result.get(version_key)
        if version:
            normalized = extract_version_from_string(version) or version
            if normalized not in fp.version_sources:
                fp.version_sources.append(normalized)
            if not fp.version:
                fp.version = normalized

        for sig in result.get("signals", []):
            if sig not in fp.signals:
                fp.signals.append(sig)

        for ev in result.get("evidence", []):
            if ev not in fp.evidence:
                fp.evidence.append(ev)

        # Architecture
        arch = result.get("architecture")
        if arch and not fp.architecture:
            fp.architecture = arch

    def _merge_phpinfo_result(
        self,
        fp: PhpFingerprint,
        result: Dict[str, Any],
    ) -> None:
        """Merge a phpinfo detector result (has additional config fields)."""
        self._merge_result(fp, result, found_key="found")

        # phpinfo-specific config
        if result.get("memory_limit"):
            fp.memory_limit = result["memory_limit"]
        if result.get("fatal_bt") is not None:
            fp.fatal_bt = result["fatal_bt"]
        if result.get("thread_safe") is not None:
            fp.thread_safe = result["thread_safe"]

    # ─────────────────────────────────────────────────────────────────────
    # Version resolution
    # ─────────────────────────────────────────────────────────────────────

    def _resolve_version(self, fp: PhpFingerprint) -> None:
        """
        Determine the final version to use and note any conflicts.

        Priority: local > phpinfo > header > html
        """
        # Collect all versions from sources in priority order
        versions_by_priority: List[str] = []

        # Highest priority: local binary
        if fp.local_result and fp.local_result.get("php_found"):
            v = fp.local_result.get("version")
            if v:
                normalized = extract_version_from_string(v) or v
                if normalized not in versions_by_priority:
                    versions_by_priority.append(normalized)

        # Second: phpinfo
        if fp.phpinfo_result and fp.phpinfo_result.get("found"):
            v = fp.phpinfo_result.get("version")
            if v:
                normalized = extract_version_from_string(v) or v
                if normalized not in versions_by_priority:
                    versions_by_priority.append(normalized)

        # Third: header
        if fp.header_result:
            v = fp.header_result.get("version")
            if v:
                normalized = extract_version_from_string(v) or v
                if normalized not in versions_by_priority:
                    versions_by_priority.append(normalized)

        # Fourth: HTML
        if fp.html_result:
            v = fp.html_result.get("version")
            if v:
                normalized = extract_version_from_string(v) or v
                if normalized not in versions_by_priority:
                    versions_by_priority.append(normalized)

        if versions_by_priority:
            fp.version = versions_by_priority[0]  # Highest priority wins

        if len(set(versions_by_priority)) > 1:
            fp.evidence.append(
                f"⚠  Multiple PHP versions detected: {', '.join(versions_by_priority)} "
                f"— using highest-confidence source ({fp.version}). "
                f"This may indicate a reverse proxy or multiple PHP deployments."
            )

    # ─────────────────────────────────────────────────────────────────────
    # Confidence calculation
    # ─────────────────────────────────────────────────────────────────────

    def _calculate_final_confidence(self, fp: PhpFingerprint) -> None:
        """Calculate and store the final confidence level."""
        all_versions = []
        for src in [fp.local_result, fp.phpinfo_result, fp.header_result, fp.html_result]:
            if src:
                v = src.get("version") or src.get("version")
                if v:
                    all_versions.append(v)

        version_consistent = len(set(all_versions)) <= 1
        version_sources_count = len(all_versions)

        fp.confidence = calculate_confidence(
            detected_signals=fp.signals,
            version_sources=version_sources_count,
            version_consistent=version_consistent,
        )
        fp.confidence_note = build_confidence_note(fp.confidence, fp.signals)
