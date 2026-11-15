"""
html_report.py — Self-contained HTML VAPT report generator.

Produces a professional, fully self-contained HTML report with:
1. Executive Summary
2. Scan Information
3. Target Information
4. PHP Fingerprinting Details
5. CVE Assessment (CVE-2026-109618 / CVE-2026-109619)
6. Technical Evidence
7. Risk Classification
8. Remediation Guidance
9. Assessment Limitations
"""

import logging
import html
from typing import List, Any, Optional, Dict

from utils.helpers import utc_now_iso

logger = logging.getLogger("php2shell")

SCANNER_NAME = "PHP2Shell Scanner"
SCANNER_VER  = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# Status → color mapping
# ─────────────────────────────────────────────────────────────────────────────
STATUS_COLORS = {
    "CRITICAL":       ("#dc2626", "#fef2f2"),   # red
    "HIGH":           ("#ea580c", "#fff7ed"),   # orange
    "MEDIUM":         ("#d97706", "#fffbeb"),   # amber
    "LOW":            ("#2563eb", "#eff6ff"),   # blue
    "NOT_VULNERABLE": ("#16a34a", "#f0fdf4"),   # green
    "UNKNOWN":        ("#6b7280", "#f9fafb"),   # gray
}

CONF_COLORS = {
    "CONFIRMED": "#16a34a",
    "HIGH":      "#2563eb",
    "MEDIUM":    "#d97706",
    "LOW":       "#ea580c",
    "NONE":      "#6b7280",
}


def generate(
    results: List[Any],
    output_path: str,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a self-contained HTML VAPT report.

    Parameters
    ----------
    results     : list of ScanResult objects
    output_path : file path to write the HTML report
    scan_meta   : optional dict with scan-level metadata

    Returns
    -------
    output_path (string) on success
    """
    meta = scan_meta or {}
    html_content = _render_report(results, meta)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    logger.info(f"HTML report written to: {output_path}")
    return output_path


def _render_report(results: List[Any], meta: Dict[str, Any]) -> str:
    """Render the full HTML report."""
    # Pre-compute summary stats
    status_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        "NOT_VULNERABLE": 0, "UNKNOWN": 0,
    }
    total = len(results)
    successful = sum(1 for r in results if r.success)

    for result in results:
        if result.assessment:
            s = result.assessment.overall_status.value
        else:
            s = "UNKNOWN"
        status_counts[s] = status_counts.get(s, 0) + 1

    generated_at = utc_now_iso()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP2Shell Scanner — VAPT Report</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     font-size:14px;color:#1f2937;background:#f9fafb;line-height:1.5}}
.page{{max-width:1200px;margin:0 auto;padding:24px 20px}}
h1{{font-size:28px;font-weight:700;color:#111827;margin-bottom:4px}}
h2{{font-size:20px;font-weight:600;color:#111827;margin:28px 0 12px;
    padding-bottom:8px;border-bottom:2px solid #e5e7eb}}
h3{{font-size:16px;font-weight:600;color:#374151;margin:16px 0 8px}}
h4{{font-size:14px;font-weight:600;color:#4b5563;margin:12px 0 6px}}
p{{margin-bottom:8px}}
ul{{padding-left:20px;margin-bottom:8px}}
li{{margin-bottom:4px}}
table{{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px}}
th{{background:#f3f4f6;border:1px solid #d1d5db;padding:8px 10px;
    text-align:left;font-weight:600;color:#374151}}
td{{border:1px solid #e5e7eb;padding:8px 10px;vertical-align:top}}
tr:nth-child(even) td{{background:#fafafa}}
code{{background:#f3f4f6;padding:2px 6px;border-radius:4px;
      font-family:'Courier New',monospace;font-size:12px}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;
        font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;
       padding:16px;margin-bottom:16px}}
.header-bar{{background:linear-gradient(135deg,#1e293b,#334155);
             color:#fff;padding:24px 28px;border-radius:10px;margin-bottom:28px}}
.header-bar p{{color:#94a3b8;font-size:13px}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
               gap:12px;margin-bottom:24px}}
.stat-card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;
            padding:14px;text-align:center}}
.stat-card .num{{font-size:28px;font-weight:700}}
.stat-card .lbl{{font-size:12px;color:#6b7280;text-transform:uppercase;
                 letter-spacing:0.5px;margin-top:2px}}
.target-card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;
              margin-bottom:20px;overflow:hidden}}
.target-header{{display:flex;align-items:center;gap:12px;padding:14px 16px;
                border-bottom:1px solid #e5e7eb;background:#f8fafc}}
.target-header .url{{font-family:monospace;font-size:13px;color:#1d4ed8;word-break:break-all}}
.target-body{{padding:16px}}
.evidence-box{{background:#0f172a;color:#94a3b8;padding:12px 14px;border-radius:6px;
               font-family:monospace;font-size:12px;line-height:1.6;
               max-height:220px;overflow-y:auto;margin:8px 0}}
.evidence-box div{{padding:1px 0}}
.limitation-box{{background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;
                 padding:12px 14px;margin-top:8px;font-size:13px}}
.section-label{{font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;
                letter-spacing:0.8px;margin-bottom:4px}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;
        font-size:12px;color:#9ca3af;text-align:center}}
</style>
</head>
<body>
<div class="page">

<!-- ── Header ─────────────────────────────────────────────────── -->
<div class="header-bar">
  <h1>PHP2Shell Scanner</h1>
  <p>Vulnerability Assessment Report — CVE-2026-109618 / CVE-2026-109619</p>
  <p style="margin-top:8px;color:#cbd5e1">
    Generated: {html.escape(generated_at)} &nbsp;|&nbsp;
    Scanner: {html.escape(SCANNER_NAME)} v{html.escape(SCANNER_VER)} &nbsp;|&nbsp;
    Targets: {total}
  </p>
</div>

<!-- ── Section 1: Executive Summary ──────────────────────────── -->
<h2>1. Executive Summary</h2>
<div class="card">
  <p>This report presents the results of a PHP2Shell vulnerability assessment
  targeting <strong>CVE-2026-109618</strong> (PHP OOM Memory Corruption / Use-After-Free,
  CVSS v4.0 9.2) and <strong>CVE-2026-109619</strong> (PHP Stale Global State /
  Use-After-Free + OPcache Type Confusion, CVSS v4.0 9.2).
  Both CVEs were added to the CISA Known Exploited Vulnerabilities (KEV) catalog on
  October 26, 2026. Fixed versions were released by the PHP project on October 21, 2026
  (PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35).</p>
  <p>The scanner uses five independent detection methods: HTTP header fingerprinting,
  HTML/application fingerprinting, phpinfo() endpoint detection, local PHP runtime
  detection, and runtime architecture identification.</p>
</div>
<div class="summary-grid">
{_summary_stat("CRITICAL",       status_counts.get("CRITICAL",0))}
{_summary_stat("HIGH",           status_counts.get("HIGH",0))}
{_summary_stat("MEDIUM",         status_counts.get("MEDIUM",0))}
{_summary_stat("LOW",            status_counts.get("LOW",0))}
{_summary_stat("NOT_VULNERABLE", status_counts.get("NOT_VULNERABLE",0))}
{_summary_stat("UNKNOWN",        status_counts.get("UNKNOWN",0))}
</div>

<!-- ── Section 2: Scan Information ───────────────────────────── -->
<h2>2. Scan Information</h2>
<table>
<tr><th style="width:30%">Parameter</th><th>Value</th></tr>
<tr><td>Scanner</td><td>{html.escape(SCANNER_NAME)} v{html.escape(SCANNER_VER)}</td></tr>
<tr><td>Report Generated</td><td>{html.escape(generated_at)}</td></tr>
<tr><td>Total Targets Scanned</td><td>{total}</td></tr>
<tr><td>Successful Scans</td><td>{successful}</td></tr>
<tr><td>Failed Scans</td><td>{total - successful}</td></tr>
<tr><td>Threads</td><td>{html.escape(str(meta.get("threads","N/A")))}</td></tr>
<tr><td>Timeout (seconds)</td><td>{html.escape(str(meta.get("timeout","N/A")))}</td></tr>
<tr><td>SSL Verification</td><td>{"Enabled" if meta.get("ssl_verify", True) else "Disabled"}</td></tr>
<tr><td>phpinfo() Check</td><td>{"Enabled" if meta.get("check_phpinfo", True) else "Disabled"}</td></tr>
<tr><td>Local PHP Check</td><td>{"Enabled" if meta.get("check_local", False) else "Disabled"}</td></tr>
<tr><td>CVEs Assessed</td><td>CVE-2026-109618, CVE-2026-109619</td></tr>
</table>

<!-- ── Section 3: Target Information ─────────────────────────── -->
<h2>3. Target Information</h2>
<table>
<tr>
  <th>Target</th><th>PHP Version</th><th>Architecture</th>
  <th>Confidence</th><th>Overall Status</th><th>Scan Time</th>
</tr>
{_target_summary_rows(results)}
</table>

<!-- ── Section 4–8: Per-Target Details ───────────────────────── -->
<h2>4–8. PHP Fingerprinting, CVE Assessment, Evidence, Risk &amp; Remediation</h2>
{''.join(_render_target(r) for r in results)}

<!-- ── Section 9: Assessment Limitations ─────────────────────── -->
<h2>9. Assessment Limitations</h2>
<div class="limitation-box">
  <ul style="margin:0;padding-left:18px">
    <li>This scanner performs <strong>passive, non-destructive detection</strong> only.
        It never sends exploit payloads, triggers memory corruption, or modifies server state.</li>
    <li>Version detection relies on HTTP headers, HTML patterns, phpinfo() pages, and local
        binary queries. Servers that suppress version disclosure (e.g. expose_php=Off) may
        produce UNKNOWN results even if vulnerable.</li>
    <li>Vendor backport awareness: PHP 8.1, 8.0, and 7.4 have source backports from the PHP
        project but no numbered upstream release. These branches are classified as LOW (vendor_check)
        and require manual verification of the installed package version.</li>
    <li>Confidence levels indicate detection reliability, not exploit complexity. A MEDIUM
        confidence CRITICAL finding should still be remediated urgently.</li>
    <li>Reverse proxies, CDNs, and load balancers may alter or strip PHP headers, causing
        version misdetection or UNKNOWN results for backend PHP installations.</li>
    <li>The scanner operates from a network perspective and cannot assess file-system
        configurations, PHP-FPM pool isolation, or OS-level mitigations.</li>
    <li>All findings should be verified by qualified personnel before remediation actions
        are taken in production environments.</li>
  </ul>
</div>

<footer>
  PHP2Shell Scanner v{html.escape(SCANNER_VER)} &mdash;
  For authorized security assessments only &mdash;
  CVE-2026-109618 / CVE-2026-109619 &mdash;
  CISA KEV: 2026-10-26 &mdash;
  Report: {html.escape(generated_at)}
</footer>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

def _summary_stat(status: str, count: int) -> str:
    color, bg = STATUS_COLORS.get(status, ("#6b7280", "#f9fafb"))
    return (
        f'<div class="stat-card" style="border-top:4px solid {color}">'
        f'<div class="num" style="color:{color}">{count}</div>'
        f'<div class="lbl">{html.escape(status.replace("_"," "))}</div>'
        f'</div>'
    )


def _badge(status: str) -> str:
    color, bg = STATUS_COLORS.get(status, ("#6b7280", "#f9fafb"))
    return (
        f'<span class="badge" style="background:{bg};color:{color};'
        f'border:1px solid {color}">{html.escape(status)}</span>'
    )


def _conf_badge(conf: str) -> str:
    color = CONF_COLORS.get(conf, "#6b7280")
    return (
        f'<span class="badge" style="background:#f1f5f9;color:{color};'
        f'border:1px solid {color}">{html.escape(conf)}</span>'
    )


def _target_summary_rows(results: List[Any]) -> str:
    rows = []
    for r in results:
        fp  = r.fingerprint
        a   = r.assessment
        status  = a.overall_status.value if a else "UNKNOWN"
        version = (fp.version or "unknown") if fp else "unknown"
        arch    = (fp.architecture or "unknown") if fp else "unknown"
        conf    = fp.confidence.value if fp else "NONE"
        rows.append(
            f"<tr>"
            f"<td><code>{html.escape(r.target)}</code></td>"
            f"<td>{html.escape(version)}</td>"
            f"<td>{html.escape(arch)}</td>"
            f"<td>{_conf_badge(conf)}</td>"
            f"<td>{_badge(status)}</td>"
            f"<td>{round(r.scan_time_secs, 1)}s</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _render_target(result: Any) -> str:
    fp = result.fingerprint
    a  = result.assessment
    status = (a.overall_status.value if a else "UNKNOWN")
    color, bg = STATUS_COLORS.get(status, ("#6b7280", "#f9fafb"))

    # Evidence box
    evidence_items = ""
    if fp and fp.evidence:
        for ev in fp.evidence:
            evidence_items += f"<div>• {html.escape(ev)}</div>"
    else:
        evidence_items = "<div><em>No evidence collected</em></div>"

    # CVE table rows
    cve_rows = ""
    if a and a.cve_assessments:
        for cve in a.cve_assessments:
            affected_txt = "Yes" if cve.affected else ("No" if cve.affected is False else "Unknown")
            cve_rows += (
                f"<tr>"
                f"<td><strong>{html.escape(cve.cve_id)}</strong></td>"
                f"<td>{html.escape(str(cve.cvss_score))}</td>"
                f"<td>{html.escape(affected_txt)}</td>"
                f"<td>{html.escape(cve.status)}</td>"
                f"<td style='font-size:12px'>{html.escape(cve.version_status.get('fixed_version') or 'N/A')}</td>"
                f"<td style='font-size:12px'>{html.escape(cve.version_status.get('support_type',''))}</td>"
                f"</tr>"
            )
    else:
        cve_rows = "<tr><td colspan='6'>No CVE assessment available</td></tr>"

    # Recommendations
    recs_html = ""
    if a and a.recommendations:
        recs_html = "<ul>" + "".join(
            f"<li>{html.escape(r)}</li>" for r in a.recommendations
        ) + "</ul>"
    else:
        recs_html = "<p>No specific recommendations.</p>"

    return f"""
<div class="target-card">
  <div class="target-header">
    <div style="flex:1">
      <div class="section-label">Target</div>
      <div class="url">{html.escape(result.target)}</div>
    </div>
    {_badge(status)}
  </div>
  <div class="target-body">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      <div>
        <h4>PHP Fingerprint</h4>
        <table>
          <tr><td>PHP Detected</td><td>{("Yes" if fp and fp.php_detected else "No")}</td></tr>
          <tr><td>Version</td><td><strong>{html.escape((fp.version or "Unknown") if fp else "Unknown")}</strong></td></tr>
          <tr><td>Architecture</td><td>{html.escape((fp.architecture or "Unknown") if fp else "Unknown")}</td></tr>
          <tr><td>Confidence</td><td>{_conf_badge((fp.confidence.value) if fp else "NONE")}</td></tr>
          <tr><td>CMS/Framework</td><td>{html.escape((fp.cms or "—") if fp else "—")}</td></tr>
          <tr><td>memory_limit</td><td>{html.escape((fp.memory_limit or "—") if fp else "—")}</td></tr>
          <tr><td>fatal_error_backtraces</td><td>{html.escape((fp.fatal_bt or "—") if fp else "—")}</td></tr>
        </table>
      </div>
      <div>
        <h4>Vulnerability Status</h4>
        <div style="margin-bottom:8px">{_badge(status)}</div>
        <p style="font-size:13px">{html.escape((a.risk_summary) if a else "")}</p>
        <h4 style="margin-top:12px">Scan Info</h4>
        <table>
          <tr><td>Scan Time</td><td>{round(result.scan_time_secs,1)}s</td></tr>
          <tr><td>Success</td><td>{"Yes" if result.success else f"No — {html.escape(result.error or '')}"}</td></tr>
        </table>
      </div>
    </div>

    <h4>CVE Assessment</h4>
    <table>
      <tr><th>CVE ID</th><th>CVSS v4.0</th><th>Affected</th>
          <th>Status</th><th>Fixed Version</th><th>Support Type</th></tr>
      {cve_rows}
    </table>

    <h4>Technical Evidence</h4>
    <div class="evidence-box">{evidence_items}</div>

    <h4>Remediation</h4>
    {recs_html}
  </div>
</div>"""
