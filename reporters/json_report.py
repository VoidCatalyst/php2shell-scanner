"""
json_report.py — JSON VAPT report generator.

Produces a machine-readable JSON report containing full scan metadata,
per-target fingerprint evidence, and per-CVE assessments.
"""

import json
import logging
from typing import List, Dict, Any, Optional

from utils.helpers import utc_now_iso

logger = logging.getLogger("php2shell")

REPORT_VERSION = "1.0"
SCANNER_NAME   = "PHP2Shell Scanner"
SCANNER_VER    = "1.0.0"


def generate(
    results: List[Any],
    output_path: str,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a JSON report from scan results.

    Parameters
    ----------
    results     : list of ScanResult objects
    output_path : file path to write the JSON report
    scan_meta   : optional dict with scan-level metadata

    Returns
    -------
    output_path (string) on success
    """
    report = _build_report(results, scan_meta)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str, ensure_ascii=False)

    logger.info(f"JSON report written to: {output_path}")
    return output_path


def _build_report(
    results: List[Any],
    scan_meta: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the report dict from scan results."""
    meta = scan_meta or {}

    # Summary counts
    status_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        "NOT_VULNERABLE": 0, "UNKNOWN": 0,
    }
    total = len(results)
    successful = 0

    target_reports = []
    for result in results:
        target_report = _serialize_result(result)
        target_reports.append(target_report)

        if result.success:
            successful += 1

        if result.assessment:
            status = result.assessment.overall_status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        else:
            status_counts["UNKNOWN"] = status_counts.get("UNKNOWN", 0) + 1

    return {
        "report_format":  f"PHP2Shell Scanner JSON v{REPORT_VERSION}",
        "scanner":        SCANNER_NAME,
        "scanner_version": SCANNER_VER,
        "generated_at":   utc_now_iso(),
        "scan_meta": {
            "total_targets":      total,
            "successful_scans":   successful,
            "failed_scans":       total - successful,
            "threads":            meta.get("threads", 1),
            "timeout":            meta.get("timeout", 10),
            "ssl_verify":         meta.get("ssl_verify", True),
            "phpinfo_checked":    meta.get("check_phpinfo", True),
            "local_checked":      meta.get("check_local", False),
            "scan_start":         meta.get("scan_start", utc_now_iso()),
            "scan_end":           meta.get("scan_end",   utc_now_iso()),
        },
        "summary": {
            "CRITICAL":        status_counts.get("CRITICAL",       0),
            "HIGH":            status_counts.get("HIGH",           0),
            "MEDIUM":          status_counts.get("MEDIUM",         0),
            "LOW":             status_counts.get("LOW",            0),
            "NOT_VULNERABLE":  status_counts.get("NOT_VULNERABLE", 0),
            "UNKNOWN":         status_counts.get("UNKNOWN",        0),
        },
        "cves_assessed": [
            "CVE-2026-109618",
            "CVE-2026-109619",
        ],
        "targets": target_reports,
    }


def _serialize_result(result: Any) -> Dict[str, Any]:
    """Serialize one ScanResult to a dict."""
    d: Dict[str, Any] = {
        "target":          result.target,
        "scan_success":    result.success,
        "scan_error":      result.error,
        "scan_time_secs":  round(result.scan_time_secs, 2),
        "timestamp":       result.timestamp,
        "php": {
            "detected":    False,
            "version":     None,
            "architecture": None,
            "confidence":  "NONE",
            "confidence_note": "",
            "cms":         None,
            "memory_limit": None,
            "fatal_error_backtraces": None,
            "thread_safe": None,
        },
        "vulnerability": {
            "overall_status": "UNKNOWN",
            "risk_summary":   "",
            "recommendations": [],
            "cve_assessments": [],
        },
        "evidence": [],
        "detection_methods": {
            "header_detection":  None,
            "html_detection":    None,
            "phpinfo_detection": None,
            "local_detection":   None,
        },
    }

    if result.fingerprint:
        fp = result.fingerprint
        d["php"] = {
            "detected":          fp.php_detected,
            "version":           fp.version,
            "architecture":      fp.architecture,
            "confidence":        fp.confidence.value,
            "confidence_note":   fp.confidence_note,
            "cms":               fp.cms,
            "memory_limit":      fp.memory_limit,
            "fatal_error_backtraces": fp.fatal_bt,
            "thread_safe":       fp.thread_safe,
        }
        d["evidence"] = fp.evidence

        # Detection method summaries
        if fp.header_result:
            d["detection_methods"]["header_detection"] = {
                "php_detected":  fp.header_result.get("php_detected", False),
                "version":       fp.header_result.get("version"),
                "header_source": fp.header_result.get("header_source"),
                "architecture":  fp.header_result.get("architecture"),
                "raw_headers":   fp.header_result.get("raw_headers", {}),
                "signals":       fp.header_result.get("signals", []),
            }
        if fp.html_result:
            d["detection_methods"]["html_detection"] = {
                "php_detected":  fp.html_result.get("php_detected", False),
                "version":       fp.html_result.get("version"),
                "cms":           fp.html_result.get("cms"),
                "has_phpsessid": fp.html_result.get("has_phpsessid", False),
                "has_php_error": fp.html_result.get("has_php_error", False),
                "signals":       fp.html_result.get("signals", []),
            }
        if fp.phpinfo_result:
            d["detection_methods"]["phpinfo_detection"] = {
                "found":           fp.phpinfo_result.get("found", False),
                "url":             fp.phpinfo_result.get("url"),
                "version":         fp.phpinfo_result.get("version"),
                "server_api":      fp.phpinfo_result.get("server_api"),
                "architecture":    fp.phpinfo_result.get("architecture"),
                "memory_limit":    fp.phpinfo_result.get("memory_limit"),
                "fatal_bt":        fp.phpinfo_result.get("fatal_bt"),
                "paths_checked":   fp.phpinfo_result.get("paths_checked", []),
            }
        if fp.local_result:
            d["detection_methods"]["local_detection"] = {
                "php_found":       fp.local_result.get("php_found", False),
                "version":         fp.local_result.get("version"),
                "binary_path":     fp.local_result.get("binary_path"),
                "package_version": fp.local_result.get("package_version"),
                "architecture":    fp.local_result.get("architecture"),
                "distro_package":  fp.local_result.get("distro_package"),
            }

    if result.assessment:
        a = result.assessment
        d["vulnerability"] = {
            "overall_status":  a.overall_status.value,
            "risk_summary":    a.risk_summary,
            "recommendations": a.recommendations,
            "cve_assessments": [
                {
                    "cve_id":        cve.cve_id,
                    "description":   cve.description,
                    "cvss_v4_score": cve.cvss_score,
                    "affected":      cve.affected,
                    "status":        cve.status,
                    "root_cause":    cve.root_cause,
                    "remediation":   cve.remediation,
                    "mitigation":    cve.mitigation,
                    "version_details": {
                        "branch":        cve.version_status.get("branch"),
                        "eol":           cve.version_status.get("eol"),
                        "support_type":  cve.version_status.get("support_type"),
                        "fixed_version": cve.version_status.get("fixed_version"),
                        "eol_date":      cve.version_status.get("eol_date"),
                    },
                    "notes": cve.notes,
                }
                for cve in a.cve_assessments
            ],
        }

    return d
