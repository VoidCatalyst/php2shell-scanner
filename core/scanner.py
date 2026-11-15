"""
scanner.py — Main scan orchestration with concurrent threading.

Manages per-target scanning, ThreadPoolExecutor concurrency, graceful
Ctrl+C handling, rate-limiting delay, and result aggregation.
"""

import logging
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from core.fingerprint import PhpFingerprint, PhpFingerprinter
from core.http_client import PhpHttpClient
from core.vulnerability_engine import VulnerabilityEngine, TargetAssessment, VulnStatus
from utils.helpers import utc_now_iso, elapsed_since

logger = logging.getLogger("php2shell")

# Sentinel for graceful shutdown
_shutdown_requested = False


def _handle_sigint(signum, frame):
    """
    SIGINT handler: set the shutdown flag AND raise KeyboardInterrupt so that
    any blocking call (future.result(), as_completed(), time.sleep()) is
    immediately interrupted instead of waiting for the current HTTP timeout.
    """
    global _shutdown_requested
    _shutdown_requested = True
    raise KeyboardInterrupt


@dataclass
class ScanConfig:
    """All scanner configuration parameters."""
    targets:          List[str]
    threads:          int   = 5
    timeout:          float = 10.0
    retries:          int   = 2
    delay:            float = 0.0        # seconds between requests per thread
    proxy:            Optional[str] = None
    verify_ssl:       bool  = True
    user_agent:       Optional[str] = None
    custom_headers:   Optional[Dict[str, str]] = None
    check_phpinfo:    bool  = True
    check_local:      bool  = False
    phpinfo_paths:    Optional[List[str]] = None


@dataclass
class ScanResult:
    """The complete result for one scanned target."""
    target:          str
    success:         bool                   = False
    error:           Optional[str]          = None
    fingerprint:     Optional[PhpFingerprint] = None
    assessment:      Optional[TargetAssessment] = None
    scan_time_secs:  float                  = 0.0
    timestamp:       str                    = field(default_factory=utc_now_iso)


class Scanner:
    """
    PHP2Shell Scanner orchestrator.

    Creates one HTTP client per thread, runs PhpFingerprinter and
    VulnerabilityEngine for each target, collects results, and
    supports graceful Ctrl+C interruption.
    """

    def __init__(self, config: ScanConfig, terminal=None):
        self.config   = config
        self.terminal = terminal
        self._vuln_engine = VulnerabilityEngine()

    # ─────────────────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────────────────

    def scan(self) -> List[ScanResult]:
        """
        Scan all targets in config.targets concurrently.

        Returns a list of ScanResult, one per target.
        """
        global _shutdown_requested
        _shutdown_requested = False

        # Register SIGINT handler for graceful Ctrl+C
        original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _handle_sigint)

        results: List[ScanResult] = []

        try:
            if self.config.threads <= 1:
                # Single-threaded path (simpler for debugging)
                for target in self.config.targets:
                    if _shutdown_requested:
                        logger.info("Scan interrupted by user.")
                        break
                    result = self._scan_single_target(target)
                    results.append(result)
                    if self.terminal:
                        self.terminal.print_scan_result(_result_to_dict(result))
            else:
                results = self._scan_concurrent()
        except KeyboardInterrupt:
            # _handle_sigint raises KeyboardInterrupt to unblock future.result();
            # catch it here so the caller gets a clean return instead of a traceback.
            print("\n\n[!] Scan interrupted by user (Ctrl+C).\n")
        finally:
            signal.signal(signal.SIGINT, original_sigint)

        return results

    def scan_target(self, target: str) -> ScanResult:
        """Scan a single target and return its ScanResult. Thread-safe."""
        return self._scan_single_target(target)

    # ─────────────────────────────────────────────────────────────────────
    # Internal
    # ─────────────────────────────────────────────────────────────────────

    def _scan_concurrent(self) -> List[ScanResult]:
        """
        Scan all targets using a ThreadPoolExecutor.

        Uses an explicit executor (not a context manager) so that on Ctrl+C we
        can call shutdown(wait=False, cancel_futures=True) immediately instead
        of blocking until every in-flight HTTP request times out.
        """
        global _shutdown_requested
        results: List[ScanResult] = []
        future_to_target: Dict[Future, str] = {}

        executor = ThreadPoolExecutor(max_workers=self.config.threads)
        try:
            for target in self.config.targets:
                if _shutdown_requested:
                    break
                future = executor.submit(self._scan_single_target, target)
                future_to_target[future] = target

            for future in as_completed(future_to_target):
                if _shutdown_requested:
                    logger.info("Scan interrupted — stopping remaining targets.")
                    for f in future_to_target:
                        if not f.done():
                            f.cancel()
                    break
                try:
                    result = future.result(timeout=self.config.timeout + 30)
                except Exception as exc:
                    target_url = future_to_target[future]
                    logger.warning(f"Future for {target_url} raised: {exc}")
                    result = ScanResult(
                        target=target_url,
                        success=False,
                        error=str(exc),
                    )

                results.append(result)
                if self.terminal:
                    self.terminal.print_scan_result(_result_to_dict(result))

        except KeyboardInterrupt:
            # Raised by _handle_sigint to unblock future.result() / as_completed().
            # Cancel queued-but-not-started futures, then shut down without waiting
            # for in-flight threads (they'll be abandoned; the HTTP timeout is the
            # worst-case delay, but we don't block the user here).
            _shutdown_requested = True
            print("\n\n[!] Scan interrupted by user (Ctrl+C). Stopping...\n")
            for f in future_to_target:
                f.cancel()
            raise  # Re-raise so scan() prints the summary cleanly

        finally:
            # cancel_futures=True (Python 3.9+) drops queued work; wait=False
            # means we don't block on the threads that are already running.
            executor.shutdown(wait=False, cancel_futures=True)

        return results

    def _scan_single_target(self, target: str) -> ScanResult:
        """
        Perform the full scan pipeline for a single target URL.

        1. Create HTTP client
        2. Fingerprint PHP
        3. Classify vulnerability
        4. Return ScanResult
        """
        start_time = time.monotonic()
        result = ScanResult(target=target)

        try:
            if self.terminal:
                self.terminal.print_target_header(target)
                self.terminal.info(f"Scanning {target}")

            # Apply inter-request delay
            if self.config.delay > 0:
                time.sleep(self.config.delay)

            # Create a per-thread HTTP client
            http_client = PhpHttpClient(
                timeout       = self.config.timeout,
                max_retries   = self.config.retries,
                verify_ssl    = self.config.verify_ssl,
                proxy         = self.config.proxy,
                user_agent    = self.config.user_agent,
                custom_headers= self.config.custom_headers,
            )

            with http_client:
                # Fingerprint
                fingerprinter = PhpFingerprinter(
                    http_client   = http_client,
                    check_phpinfo = self.config.check_phpinfo,
                    check_local   = self.config.check_local,
                    phpinfo_paths = self.config.phpinfo_paths,
                )
                fingerprint = fingerprinter.fingerprint(target)
                result.fingerprint = fingerprint

                # Vulnerability classification
                assessment = self._vuln_engine.classify_target(fingerprint)
                result.assessment = assessment

            result.success        = True
            result.scan_time_secs = elapsed_since(start_time)

            logger.info(
                f"Completed {target}: {assessment.overall_status.value} "
                f"(PHP {fingerprint.version or 'unknown'}, "
                f"confidence={fingerprint.confidence.value}, "
                f"arch={fingerprint.architecture or 'unknown'}) "
                f"in {result.scan_time_secs:.1f}s"
            )

        except Exception as exc:
            result.success        = False
            result.error          = str(exc)
            result.scan_time_secs = elapsed_since(start_time)
            logger.error(f"Scan error for {target}: {exc}", exc_info=True)

        return result

    # ─────────────────────────────────────────────────────────────────────
    # Reporting helpers
    # ─────────────────────────────────────────────────────────────────────

    def print_summary(self, results: List[ScanResult]) -> None:
        """Print a scan summary to the terminal."""
        if self.terminal:
            dicts = [_result_to_dict(r) for r in results]
            self.terminal.print_summary(dicts)


def _result_to_dict(result: ScanResult) -> Dict[str, Any]:
    """
    Convert a ScanResult to a plain dict for terminal printing.

    Key names match what utils/terminal.py expects exactly:
      php_version, php_architecture, version_confidence, version_source,
      errors (list), recommendation (string), cve_assessments (dict keyed by CVE ID).
    """
    d: Dict[str, Any] = {
        # Identity
        "target":             result.target,
        "success":            result.success,
        "errors":             [result.error] if result.error else [],
        "scan_time_secs":     result.scan_time_secs,
        "timestamp":          result.timestamp,
        # PHP detection (key names terminal.py uses)
        "php_detected":       False,
        "php_version":        None,
        "php_architecture":   None,
        "version_confidence": "NONE",
        "version_source":     None,
        # HTTP metadata (populated from header_result below)
        "http_status":        None,
        "ip_address":         None,
        "web_server":         None,
        # Classification
        "overall_status":     "UNKNOWN",
        "risk_summary":       "",
        "recommendation":     "",        # single string; terminal reads .get("recommendation")
        "warnings":           [],
        "evidence":           [],
        # CVE assessments: dict keyed by CVE ID so terminal can call .items()/.values()
        "cve_assessments":    {},
        # phpinfo exposure sub-dict for terminal footer
        "fingerprint":        {"php_info_exposure": False, "php_info_urls": []},
    }

    if result.fingerprint:
        fp = result.fingerprint
        d["php_detected"]       = fp.php_detected
        d["php_version"]        = fp.version
        d["php_architecture"]   = fp.architecture
        d["version_confidence"] = fp.confidence.value
        # version_sources is a list; take the first (highest-priority) source
        d["version_source"]     = fp.version_sources[0] if fp.version_sources else None
        d["evidence"]           = fp.evidence

        # Version conflict warning
        if getattr(fp, "version_conflict", False):
            d["warnings"].append(
                "Multiple detection sources disagree on PHP version — confidence reduced"
            )

        # HTTP metadata from the raw header detector result
        # header_result stores the Server header value in raw_headers["Server"]
        hr = fp.header_result or {}
        d["web_server"] = (hr.get("raw_headers") or {}).get("Server") or None

        # phpinfo exposure — phpinfo_detector uses "found" (bool) and "url" (str)
        pi = fp.phpinfo_result or {}
        if pi.get("found"):
            url = pi.get("url")
            d["fingerprint"]["php_info_exposure"] = True
            d["fingerprint"]["php_info_urls"]     = [url] if url else []

    if result.assessment:
        a = result.assessment
        d["overall_status"]  = a.overall_status.value
        d["risk_summary"]    = a.risk_summary
        # recommendation: first entry from the list (or empty)
        d["recommendation"]  = a.recommendations[0] if a.recommendations else ""
        # Build a dict keyed by CVE ID so terminal.py can call .items() and .values()
        d["cve_assessments"] = {
            cve.cve_id: {
                "cve_id":        cve.cve_id,
                "affected":      cve.affected,
                "status":        cve.status,
                "cvss_score":    cve.cvss_score,
                # Map CveAssessment.notes list → "evidence" string terminal expects
                "evidence":      "; ".join(str(n) for n in cve.notes) if cve.notes else "",
                # fixed_version lives inside the raw version_status result dict
                "fixed_version": (
                    cve.version_status.get("fixed_version")
                    if isinstance(cve.version_status, dict) else None
                ),
            }
            for cve in a.cve_assessments
        }

    return d
