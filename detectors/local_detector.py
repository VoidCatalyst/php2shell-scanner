"""
local_detector.py — Local PHP installation detection.

Detection Method 4: Local PHP Runtime Detection.
Queries the system's installed PHP binary and package manager to determine
the actual installed PHP version. This provides the highest confidence
detection since it reads directly from the runtime, not from HTTP headers.

This module runs only when --local is specified. It is safe and read-only:
it only calls `php --version`, package manager queries, and reads registry
keys — never executes PHP code or modifies any files.
"""

import re
import logging
import platform
import subprocess
import shutil
from typing import Dict, Any, Optional, List

logger = logging.getLogger("php2shell")

# Timeout for local subprocess calls
SUBPROCESS_TIMEOUT = 15  # seconds

# PHP version extraction from CLI output
PHP_CLI_VERSION_RE = re.compile(
    r'PHP\s+(\d+\.\d+\.\d+)',
    re.IGNORECASE
)

# NTS / ZTS thread safety flag
NTS_RE = re.compile(r'\(NTS\)', re.IGNORECASE)
ZTS_RE = re.compile(r'\(ZTS\)', re.IGNORECASE)

# Architecture from CLI output
FPM_CLI_RE = re.compile(r'fpm', re.IGNORECASE)


def detect() -> Dict[str, Any]:
    """
    Detect locally installed PHP version and configuration.

    Returns
    -------
    {
        "php_found":        bool,
        "version":          str | None,
        "binary_path":      str | None,
        "package_version":  str | None,       # From apt/rpm/brew
        "thread_safe":      bool | None,       # True=ZTS, False=NTS
        "architecture":     str | None,
        "distro_package":   str | None,        # Package name and version
        "signals":          list[str],
        "evidence":         list[str],
        "platform":         str,
    }
    """
    result: Dict[str, Any] = {
        "php_found":       False,
        "version":         None,
        "binary_path":     None,
        "package_version": None,
        "thread_safe":     None,
        "architecture":    None,
        "distro_package":  None,
        "signals":         [],
        "evidence":        [],
        "platform":        platform.system(),
    }

    system = platform.system().lower()

    # ── 1. PHP binary detection ───────────────────────────────────────────
    binary_result = _detect_php_binary()
    if binary_result["found"]:
        result["php_found"]   = True
        result["version"]     = binary_result["version"]
        result["binary_path"] = binary_result["path"]
        result["thread_safe"] = binary_result.get("thread_safe")
        result["signals"].append("local_php_binary")
        result["evidence"].extend(binary_result.get("evidence", []))

    # ── 2. Package manager query ──────────────────────────────────────────
    if system in ("linux", "darwin"):
        pkg_result = _detect_via_package_manager(system)
        if pkg_result["found"]:
            if not result["php_found"]:
                result["php_found"] = True
                result["version"]   = pkg_result["version"]
            result["package_version"] = pkg_result["version"]
            result["distro_package"]  = pkg_result.get("package_name")
            result["signals"].append("local_package_query")
            result["evidence"].extend(pkg_result.get("evidence", []))

    elif system == "windows":
        win_result = _detect_windows()
        if win_result["found"]:
            if not result["php_found"]:
                result["php_found"] = True
                result["version"]   = win_result["version"]
            result["evidence"].extend(win_result.get("evidence", []))

    # ── 3. Architecture inference ─────────────────────────────────────────
    if result["php_found"] and not result["architecture"]:
        # On Linux, check if PHP-FPM service exists
        if system == "linux":
            arch = _detect_linux_architecture()
            if arch:
                result["architecture"] = arch
                result["evidence"].append(
                    f"PHP execution model detected: {arch.upper()}"
                )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_command(cmd: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Optional[str]:
    """Run a subprocess command and return its stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return output.strip() if output.strip() else None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        logger.debug(f"Command timed out: {' '.join(cmd)}")
        return None
    except Exception as exc:
        logger.debug(f"Command failed {' '.join(cmd)}: {exc}")
        return None


def _detect_php_binary() -> Dict[str, Any]:
    """Find and query the PHP CLI binary."""
    result = {"found": False, "version": None, "path": None, "evidence": []}

    # Locations to check
    candidate_paths = ["php", "php8", "php7", "php5"]
    if platform.system().lower() == "windows":
        candidate_paths = ["php", "php.exe"]

    for candidate in candidate_paths:
        binary_path = shutil.which(candidate)
        if not binary_path:
            continue

        output = _run_command([binary_path, "--version"])
        if not output:
            continue

        m = PHP_CLI_VERSION_RE.search(output)
        if m:
            version = m.group(1)
            result["found"]   = True
            result["version"] = version
            result["path"]    = binary_path
            result["evidence"].append(
                f"PHP binary: {binary_path!r} → version {version}"
            )
            result["evidence"].append(f"php --version output: {output.splitlines()[0]}")

            # Thread safety
            if NTS_RE.search(output):
                result["thread_safe"] = False
                result["evidence"].append("Thread safety: NTS (non-thread-safe)")
            elif ZTS_RE.search(output):
                result["thread_safe"] = True
                result["evidence"].append("Thread safety: ZTS (thread-safe)")

            break

    return result


def _detect_via_package_manager(system: str) -> Dict[str, Any]:
    """Query apt, rpm, or brew for the installed PHP package."""
    result = {"found": False, "version": None, "package_name": None, "evidence": []}

    if system == "linux":
        # Try apt/dpkg (Debian/Ubuntu)
        apt_output = _run_command(["apt", "show", "php"])
        if not apt_output:
            # Try specific versioned package
            for ver_suffix in ["8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"]:
                apt_output = _run_command(["apt", "show", f"php{ver_suffix}"])
                if apt_output and "Version:" in apt_output:
                    break

        if apt_output and "Version:" in apt_output:
            m = re.search(r'Version:\s*(\d+:\d+\.\d+\.\d+|\d+\.\d+\.\d+)', apt_output)
            if m:
                raw_ver = m.group(1)
                # Strip epoch if present (e.g. "2:8.3.20-1")
                ver_match = re.search(r'(\d+\.\d+\.\d+)', raw_ver)
                if ver_match:
                    result["found"]        = True
                    result["version"]      = ver_match.group(1)
                    result["package_name"] = "php (apt)"
                    result["evidence"].append(
                        f"apt package query → PHP {result['version']}"
                    )
                    return result

        # Try dpkg -l
        dpkg_output = _run_command(["dpkg", "-l", "php*"])
        if dpkg_output:
            m = re.search(r'ii\s+php(\d+\.\d+)\s+(\d+\.\d+\.\d+)', dpkg_output)
            if m:
                result["found"]        = True
                result["version"]      = m.group(2)
                result["package_name"] = f"php{m.group(1)} (dpkg)"
                result["evidence"].append(
                    f"dpkg query → PHP {result['version']}"
                )
                return result

        # Try rpm (RHEL/CentOS/AlmaLinux/Rocky)
        rpm_output = _run_command(["rpm", "-q", "php"])
        if not rpm_output or "not installed" in rpm_output.lower():
            rpm_output = _run_command(["rpm", "-qa", "--queryformat",
                                       "%{NAME}-%{VERSION}\\n", "php*"])

        if rpm_output and re.search(r'php', rpm_output, re.IGNORECASE):
            m = re.search(r'php(?:-\w+)?-(\d+\.\d+\.\d+)', rpm_output)
            if m:
                result["found"]        = True
                result["version"]      = m.group(1)
                result["package_name"] = "php (rpm)"
                result["evidence"].append(
                    f"rpm query → PHP {result['version']}"
                )
                return result

    elif system == "darwin":
        # Try Homebrew
        brew_output = _run_command(["brew", "list", "--versions", "php"])
        if brew_output:
            m = re.search(r'php\s+(\d+\.\d+\.\d+)', brew_output, re.IGNORECASE)
            if m:
                result["found"]        = True
                result["version"]      = m.group(1)
                result["package_name"] = "php (Homebrew)"
                result["evidence"].append(
                    f"brew query → PHP {result['version']}"
                )
                return result

    return result


def _detect_windows() -> Dict[str, Any]:
    """Check common Windows PHP installation paths."""
    result = {"found": False, "version": None, "evidence": []}

    common_paths = [
        r"C:\php\php.exe",
        r"C:\PHP\php.exe",
        r"C:\xampp\php\php.exe",
        r"C:\wamp64\bin\php\php8.3.0\php.exe",
        r"C:\laragon\bin\php\php-8.3.0-Win32-vs16-x64\php.exe",
    ]

    for php_path in common_paths:
        import os
        if not os.path.isfile(php_path):
            continue
        output = _run_command([php_path, "--version"])
        if output:
            m = PHP_CLI_VERSION_RE.search(output)
            if m:
                result["found"]   = True
                result["version"] = m.group(1)
                result["evidence"].append(
                    f"Windows PHP binary found: {php_path!r} → version {result['version']}"
                )
                return result

    return result


def _detect_linux_architecture() -> Optional[str]:
    """Check if PHP-FPM service is running on Linux."""
    # Check systemd service
    fpm_service = _run_command(["systemctl", "is-active", "php-fpm"])
    if fpm_service and fpm_service.strip() == "active":
        return "fpm"

    # Check process list
    ps_output = _run_command(["pgrep", "-a", "php-fpm"])
    if ps_output and "php-fpm" in ps_output.lower():
        return "fpm"

    # Check if apache2/httpd is running (likely mod_php)
    apache = _run_command(["pgrep", "-a", "apache2"])
    if not apache:
        apache = _run_command(["pgrep", "-a", "httpd"])
    if apache:
        return "mod_php"

    return None
