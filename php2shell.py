#!/usr/bin/env python3
"""
php2shell.py — PHP2Shell Scanner CLI entry point.

Detects PHP environments potentially affected by:
  CVE-2026-109618: PHP OOM Memory Corruption / Use-After-Free (CVSS v4.0 9.2)
  CVE-2026-109619: PHP Stale Global State / Use-After-Free + OPcache RCE (CVSS v4.0 9.2)

For authorized VAPT and security assessments only.
This tool is strictly non-destructive — it never sends exploit payloads.
"""

import argparse
import logging
import os
import sys
import time

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import Scanner, ScanConfig
from utils.terminal import Terminal
from utils.logger import setup_logger
from utils.validators import validate_target, validate_targets_file, parse_custom_headers
from utils.helpers import utc_now_iso

BANNER = r"""
  ___ _  _ ___ ___ ___ _  _ ___ _    _
 | _ \ || | _ \ __|_  / || | __| |  | |
 |  _/ __ |  _/\__ \/ / __ | _|| |__| |__
 |_| |_||_|_|  |___/___\__|_|___|____|____|
            SCANNER v1.0.0
   CVE-2026-109618 / CVE-2026-109619
   PHP Memory Corruption / UAF RCE Detector
   For authorized VAPT use only.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell",
        description=(
            "PHP2Shell Scanner — Detects PHP environments potentially affected by "
            "CVE-2026-109618 and CVE-2026-109619 (CVSS v4.0 9.2). "
            "Defensive, non-destructive scanning only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  php2shell.py -u https://example.com\n"
            "  php2shell.py -l targets.txt --threads 10\n"
            "  php2shell.py -u https://example.com -o report.html --format html\n"
            "  php2shell.py -u https://example.com --local --no-phpinfo\n"
            "  php2shell.py -l targets.txt --proxy http://127.0.0.1:8080\n\n"
            "For authorized security assessments only."
        ),
    )

    # ── Target specification ─────────────────────────────────────────────
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-u", "--url",
        metavar="URL",
        help="Single target URL to scan (e.g. https://example.com)",
    )
    target_group.add_argument(
        "-l", "--list",
        metavar="FILE",
        help="File containing target URLs, one per line (# = comment)",
    )

    # ── Scan performance ─────────────────────────────────────────────────
    scan_group = parser.add_argument_group("Scan Performance")
    scan_group.add_argument(
        "--threads",
        type=int, default=5, metavar="N",
        help="Number of concurrent scanning threads (default: 5)",
    )
    scan_group.add_argument(
        "--timeout",
        type=float, default=10.0, metavar="SECS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    scan_group.add_argument(
        "--retries",
        type=int, default=2, metavar="N",
        help="Number of HTTP retry attempts on failure (default: 2)",
    )
    scan_group.add_argument(
        "--delay",
        type=float, default=0.0, metavar="SECS",
        help="Delay in seconds between requests per thread (default: 0)",
    )

    # ── HTTP options ─────────────────────────────────────────────────────
    http_group = parser.add_argument_group("HTTP Options")
    http_group.add_argument(
        "--proxy",
        metavar="URL",
        help="Proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050)",
    )
    http_group.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (use only on authorized targets)",
    )
    http_group.add_argument(
        "--user-agent",
        metavar="STRING",
        help="Custom User-Agent header value",
    )
    http_group.add_argument(
        "--headers",
        nargs="+", metavar="Key:Value",
        help="Custom HTTP headers (e.g. --headers 'X-Auth: token' 'Host: internal')",
    )
    http_group.add_argument(
        "--port",
        type=int, metavar="PORT",
        help="Override port for all targets",
    )

    # ── Detection methods ─────────────────────────────────────────────────
    detect_group = parser.add_argument_group("Detection Methods")
    phpinfo_excl = detect_group.add_mutually_exclusive_group()
    phpinfo_excl.add_argument(
        "--check-phpinfo",
        action="store_true", default=True,
        help="Check for exposed phpinfo() pages (default: enabled)",
    )
    phpinfo_excl.add_argument(
        "--no-phpinfo",
        action="store_true",
        help="Disable phpinfo() endpoint detection",
    )
    detect_group.add_argument(
        "--local",
        action="store_true",
        help="Include local PHP binary and package manager detection",
    )

    # ── Output ───────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file path for the report",
    )
    output_group.add_argument(
        "--format",
        choices=["json", "csv", "html"],
        default="json",
        help="Report format: json, csv, or html (default: json)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output — show all evidence lines",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode — suppress banner and informational output",
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode — show full HTTP request/response details",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # ── Logging setup ─────────────────────────────────────────────────────
    logger = setup_logger(debug=args.debug, verbose=args.verbose)
    term   = Terminal(quiet=args.quiet, verbose=args.verbose)

    if not args.quiet:
        term.banner(BANNER)

    # ── Target resolution ─────────────────────────────────────────────────
    targets = []
    if args.url:
        normalized = validate_target(args.url, port=args.port)
        if not normalized:
            term.error(f"Invalid target URL: {args.url!r}")
            return 1
        targets = [normalized]
    elif args.list:
        if not os.path.isfile(args.list):
            term.error(f"Target list file not found: {args.list!r}")
            return 1
        targets = validate_targets_file(args.list, port=args.port)
        if not targets:
            term.error(f"No valid targets found in: {args.list!r}")
            return 1

    term.info(f"Loaded {len(targets)} target(s)")

    # ── Custom headers ────────────────────────────────────────────────────
    custom_headers = {}
    if args.headers:
        custom_headers = parse_custom_headers(args.headers)

    # ── Build scan config ─────────────────────────────────────────────────
    check_phpinfo = not args.no_phpinfo

    config = ScanConfig(
        targets       = targets,
        threads       = max(1, args.threads),
        timeout       = max(1.0, args.timeout),
        retries       = max(0, args.retries),
        delay         = max(0.0, args.delay),
        proxy         = args.proxy,
        verify_ssl    = not args.no_ssl_verify,
        user_agent    = args.user_agent,
        custom_headers= custom_headers or None,
        check_phpinfo = check_phpinfo,
        check_local   = args.local,
    )

    # ── Run scan ──────────────────────────────────────────────────────────
    scan_start = utc_now_iso()
    start_monotonic = time.monotonic()

    term.info(
        f"Starting PHP2Shell scan: {len(targets)} target(s), "
        f"{config.threads} thread(s), "
        f"timeout={config.timeout}s"
    )

    scanner = Scanner(config=config, terminal=term)
    results = scanner.scan()
    scanner.print_summary(results)

    scan_end = utc_now_iso()
    total_time = time.monotonic() - start_monotonic

    # ── Write report ──────────────────────────────────────────────────────
    if args.output:
        scan_meta = {
            "threads":       config.threads,
            "timeout":       config.timeout,
            "ssl_verify":    config.verify_ssl,
            "check_phpinfo": config.check_phpinfo,
            "check_local":   config.check_local,
            "scan_start":    scan_start,
            "scan_end":      scan_end,
        }

        output_path = args.output
        # Auto-add extension if not present
        fmt = args.format
        if not output_path.endswith(f".{fmt}"):
            if "." not in os.path.basename(output_path):
                output_path = f"{output_path}.{fmt}"

        try:
            if fmt == "json":
                from reporters.json_report import generate
            elif fmt == "csv":
                from reporters.csv_report import generate
            elif fmt == "html":
                from reporters.html_report import generate
            else:
                term.error(f"Unknown format: {fmt!r}")
                return 1

            written_path = generate(results, output_path, scan_meta)
            term.success(f"Report written to: {written_path}")

        except Exception as exc:
            term.error(f"Failed to write report: {exc}")
            logger.exception("Report generation error")
            return 1

    term.info(f"Scan complete in {total_time:.1f}s")

    # ── Exit code ─────────────────────────────────────────────────────────
    # Return non-zero if any CRITICAL or HIGH findings
    has_critical = any(
        r.assessment and r.assessment.overall_status.value in ("CRITICAL", "HIGH")
        for r in results
    )
    return 2 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
