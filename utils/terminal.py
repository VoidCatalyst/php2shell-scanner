"""
terminal.py — Colorized terminal output for PHP2Shell Scanner.
Uses colorama for cross-platform ANSI color support.
"""

import sys
from datetime import datetime

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


class Colors:
    """ANSI color codes with graceful fallback when colorama is unavailable."""
    if HAS_COLOR:
        RED    = Fore.RED + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        GREEN  = Fore.GREEN + Style.BRIGHT
        BLUE   = Fore.CYAN + Style.BRIGHT
        WHITE  = Fore.WHITE + Style.BRIGHT
        GRAY   = Fore.WHITE + Style.DIM
        RESET  = Style.RESET_ALL
        BOLD   = Style.BRIGHT
        DIM    = Style.DIM
    else:
        RED = YELLOW = GREEN = BLUE = WHITE = GRAY = RESET = BOLD = DIM = ""


SEVERITY_COLORS = {
    "CRITICAL":       Colors.RED,
    "HIGH":           Colors.RED,
    "MEDIUM":         Colors.YELLOW,
    "LOW":            Colors.YELLOW,
    "NOT_VULNERABLE": Colors.GREEN,
    "FIXED":          Colors.GREEN,
    "UNKNOWN":        Colors.GRAY,
    "INFO":           Colors.BLUE,
}


class Terminal:
    """
    Handles all formatted terminal output for the scanner.
    Respects quiet and verbose flags.
    """

    def __init__(self, quiet: bool = False, verbose: bool = False):
        self.quiet = quiet
        self.verbose = verbose

    def _write(self, message: str, end: str = "\n"):
        sys.stdout.write(message + end)
        sys.stdout.flush()

    def banner(self, text: str):
        """Print the application banner."""
        if not self.quiet:
            self._write(Colors.BLUE + text + Colors.RESET)

    def section(self, title: str):
        """Print a section separator."""
        if not self.quiet:
            width = 68
            self._write(Colors.BLUE + "─" * width + Colors.RESET)
            self._write(Colors.BOLD + f"  {title}" + Colors.RESET)
            self._write(Colors.BLUE + "─" * width + Colors.RESET)

    def info(self, message: str):
        """Print an informational message [*]."""
        if not self.quiet:
            self._write(f"{Colors.BLUE}[*]{Colors.RESET} {message}")

    def success(self, message: str):
        """Print a success message [+]."""
        if not self.quiet:
            self._write(f"{Colors.GREEN}[+]{Colors.RESET} {message}")

    def warning(self, message: str):
        """Print a warning message [!]."""
        self._write(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")

    def error(self, message: str):
        """Print an error message [-]."""
        self._write(f"{Colors.RED}[-]{Colors.RESET} {Colors.RED}{message}{Colors.RESET}")

    def debug(self, message: str):
        """Print a debug message (verbose only)."""
        if self.verbose:
            self._write(f"{Colors.GRAY}[~]{Colors.RESET} {Colors.GRAY}{message}{Colors.RESET}")

    def finding(self, label: str, value: str, indent: int = 0):
        """Print a key-value finding line."""
        if not self.quiet:
            pad = "  " * indent
            self._write(f"{pad}{Colors.BOLD}[+]{Colors.RESET} {Colors.WHITE}{label}:{Colors.RESET} {value}")

    def print_target_header(self, target: str):
        """Print the scan header for a target."""
        if not self.quiet:
            ts = datetime.now().strftime("%H:%M:%S")
            self._write("")
            self._write(
                f"{Colors.BLUE}{'─' * 68}{Colors.RESET}"
            )
            self._write(
                f"{Colors.BOLD}[{ts}] Scanning: {Colors.BLUE}{target}{Colors.RESET}"
            )
            self._write(
                f"{Colors.BLUE}{'─' * 68}{Colors.RESET}"
            )

    def print_scan_result(self, result: dict):
        """Print a formatted scan result for one target."""
        if self.quiet:
            self._print_quiet_result(result)
            return

        target = result.get("target", "unknown")
        err = result.get("errors", [])
        if err and not result.get("php_detected"):
            self.error(f"Target: {target}")
            for e in err:
                self.error(f"  {e}")
            return

        # Basic info
        http_status = result.get("http_status", "N/A")
        status_color = Colors.GREEN if isinstance(http_status, int) and http_status == 200 else Colors.YELLOW
        self.finding("Target", target)
        self.finding("IP Address", result.get("ip_address") or "N/A")
        self.finding("HTTP Status", f"{status_color}{http_status}{Colors.RESET}")
        self.finding("Web Server", result.get("web_server") or "Unknown")

        # PHP info
        php_detected = result.get("php_detected", False)
        self.finding(
            "PHP Detected",
            f"{Colors.GREEN}Yes{Colors.RESET}" if php_detected else f"{Colors.GRAY}No{Colors.RESET}"
        )

        if php_detected:
            version = result.get("php_version") or "Not disclosed"
            confidence = result.get("version_confidence", "none")
            source = result.get("version_source") or "Unknown"
            arch = result.get("php_architecture") or "Unknown"

            version_color = Colors.WHITE if result.get("php_version") else Colors.GRAY
            self.finding("PHP Version", f"{version_color}{version}{Colors.RESET}")
            self.finding("Version Confidence", confidence.capitalize())
            self.finding("Detection Method", source)
            self.finding("PHP Runtime", arch)

            # Warnings
            for w in result.get("warnings", []):
                self.warning(f"  {w}")

            # CVE assessments
            self._write("")
            cve_assessments = result.get("cve_assessments", {})
            for cve_id, assessment in cve_assessments.items():
                status = assessment.get("status", "UNKNOWN")
                color = SEVERITY_COLORS.get(status, Colors.GRAY)
                symbol = "[!]" if status in ("CRITICAL", "HIGH", "MEDIUM") else "[+]"
                self._write(
                    f"  {color}{symbol} {cve_id}: {status}{Colors.RESET}"
                )
                if self.verbose:
                    evidence = assessment.get("evidence", "")
                    if evidence:
                        self._write(f"      Evidence: {Colors.GRAY}{evidence}{Colors.RESET}")
                    fixed = assessment.get("fixed_version")
                    if fixed:
                        self._write(f"      First Fixed: {Colors.GREEN}{fixed}{Colors.RESET}")

            # Summary line
            overall = result.get("overall_status", "UNKNOWN")
            overall_color = SEVERITY_COLORS.get(overall, Colors.GRAY)
            self._write("")
            if result.get("php_version"):
                fixed_v = None
                for assessment in cve_assessments.values():
                    fixed_v = assessment.get("fixed_version")
                    break
                if fixed_v:
                    self.finding("First Fixed Version", f"{Colors.GREEN}{fixed_v}{Colors.RESET}")
            self.finding("Overall Risk",
                         f"{overall_color}{Colors.BOLD}{overall}{Colors.RESET}")
            self.finding("Confidence", result.get("version_confidence", "none").capitalize())

            # phpinfo exposure
            fp = result.get("fingerprint", {})
            if fp.get("php_info_exposure"):
                self._write("")
                self.warning(f"  phpinfo() endpoint exposed:")
                for url in fp.get("php_info_urls", []):
                    self.warning(f"    {url}")

        # Recommendation
        self._write("")
        rec = result.get("recommendation", "")
        if rec:
            self._write(f"  {Colors.BOLD}Recommendation:{Colors.RESET} {rec}")

        self._write("")

    def _print_quiet_result(self, result: dict):
        """Print a minimal one-line result for quiet mode."""
        target = result.get("target", "unknown")
        overall = result.get("overall_status", "UNKNOWN")
        version = result.get("php_version") or "no-version"
        color = SEVERITY_COLORS.get(overall, Colors.GRAY)
        self._write(f"{color}{overall:16s}{Colors.RESET}  {target}  [{version}]")

    def print_summary(self, results: list):
        """Print a scan summary table."""
        if not results:
            return

        self._write("")
        self.section("SCAN SUMMARY")

        counts = {}
        for r in results:
            status = r.get("overall_status", "UNKNOWN")
            counts[status] = counts.get(status, 0) + 1

        total = len(results)
        self._write(f"\n  Total targets scanned: {Colors.BOLD}{total}{Colors.RESET}\n")

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_VULNERABLE", "UNKNOWN"]
        for status in order:
            if status in counts:
                color = SEVERITY_COLORS.get(status, Colors.GRAY)
                self._write(
                    f"  {color}{status:20s}{Colors.RESET}  {counts[status]}"
                )

        self._write("")
        self._write(
            f"  {Colors.GRAY}NOTE: Remote passive scanning cannot conclusively prove "
            f"exploitability of PHP2Shell.{Colors.RESET}"
        )
        self._write(
            f"  {Colors.GRAY}      HIGH status indicates an affected version range; "
            f"verify vendor patch status.{Colors.RESET}"
        )
        self._write("")
