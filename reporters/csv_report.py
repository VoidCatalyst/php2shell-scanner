"""
csv_report.py — CSV VAPT report generator.

Produces a flat CSV report with one row per target/CVE combination,
suitable for importing into spreadsheets and tracking systems.
"""

import csv
import logging
from typing import List, Any, Optional, Dict

from utils.helpers import utc_now_iso

logger = logging.getLogger("php2shell")

CSV_HEADERS = [
    "timestamp",
    "target",
    "scan_success",
    "scan_error",
    "php_detected",
    "php_version",
    "php_branch",
    "architecture",
    "confidence",
    "cms",
    "overall_status",
    "cve_id",
    "cve_affected",
    "cve_status",
    "cve_cvss_score",
    "eol",
    "support_type",
    "fixed_version",
    "eol_date",
    "phpinfo_found",
    "phpinfo_url",
    "header_source",
    "risk_summary",
    "primary_recommendation",
    "scan_time_secs",
]


def generate(
    results: List[Any],
    output_path: str,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a CSV report from scan results.

    Parameters
    ----------
    results     : list of ScanResult objects
    output_path : file path to write the CSV report
    scan_meta   : optional dict with scan-level metadata

    Returns
    -------
    output_path (string) on success
    """
    rows = _build_rows(results)

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"CSV report written to: {output_path} ({len(rows)} rows)")
    return output_path


def _build_rows(results: List[Any]) -> List[Dict[str, Any]]:
    """Build one row per target/CVE combination."""
    rows = []

    for result in results:
        base: Dict[str, Any] = {
            "timestamp":          result.timestamp,
            "target":             result.target,
            "scan_success":       result.success,
            "scan_error":         result.error or "",
            "php_detected":       False,
            "php_version":        "",
            "php_branch":         "",
            "architecture":       "",
            "confidence":         "NONE",
            "cms":                "",
            "overall_status":     "UNKNOWN",
            "cve_id":             "",
            "cve_affected":       "",
            "cve_status":         "",
            "cve_cvss_score":     "",
            "eol":                "",
            "support_type":       "",
            "fixed_version":      "",
            "eol_date":           "",
            "phpinfo_found":      False,
            "phpinfo_url":        "",
            "header_source":      "",
            "risk_summary":       "",
            "primary_recommendation": "",
            "scan_time_secs":     round(result.scan_time_secs, 2),
        }

        if result.fingerprint:
            fp = result.fingerprint
            base["php_detected"]  = fp.php_detected
            base["php_version"]   = fp.version or ""
            base["architecture"]  = fp.architecture or ""
            base["confidence"]    = fp.confidence.value
            base["cms"]           = fp.cms or ""

            # Branch from version
            if fp.version and "." in fp.version:
                parts = fp.version.split(".")
                base["php_branch"] = f"{parts[0]}.{parts[1]}"

            # phpinfo source
            if fp.phpinfo_result:
                base["phpinfo_found"] = fp.phpinfo_result.get("found", False)
                base["phpinfo_url"]   = fp.phpinfo_result.get("url") or ""

            # Header source
            if fp.header_result:
                base["header_source"] = fp.header_result.get("header_source") or ""

        if result.assessment:
            a = result.assessment
            base["overall_status"] = a.overall_status.value
            base["risk_summary"]   = a.risk_summary
            if a.recommendations:
                base["primary_recommendation"] = a.recommendations[0]

            if a.cve_assessments:
                for cve in a.cve_assessments:
                    row = dict(base)
                    row["cve_id"]        = cve.cve_id
                    row["cve_affected"]  = str(cve.affected) if cve.affected is not None else "unknown"
                    row["cve_status"]    = cve.status
                    row["cve_cvss_score"] = cve.cvss_score
                    row["eol"]           = str(cve.version_status.get("eol", ""))
                    row["support_type"]  = cve.version_status.get("support_type", "")
                    row["fixed_version"] = cve.version_status.get("fixed_version") or ""
                    row["eol_date"]      = cve.version_status.get("eol_date") or ""
                    rows.append(row)
            else:
                rows.append(base)
        else:
            rows.append(base)

    return rows
