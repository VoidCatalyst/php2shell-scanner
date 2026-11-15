"""
http_client.py — Hardened HTTP client for PHP2Shell Scanner.

Wraps requests.Session with retry logic, proxy support, timeout enforcement,
SSL control, and sane defaults. Never sends malformed or destructive requests.
"""

import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("php2shell")

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT       = 10.0          # seconds for connect + read
DEFAULT_USER_AGENT    = (
    "Mozilla/5.0 (compatible; PHP2ShellScanner/1.0; "
    "+https://github.com/security/php2shell-scanner)"
)
DEFAULT_MAX_RETRIES   = 2
DEFAULT_RETRY_BACKOFF = 0.5          # backoff factor for urllib3 Retry
RETRY_STATUS_CODES    = [500, 502, 503, 504]


class PhpHttpClient:
    """
    Reusable HTTP client for one scan session.

    All requests are GET only (no POST, PUT, DELETE, etc.) — the scanner
    is a passive detection tool and never modifies server state.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.timeout     = timeout
        self.verify_ssl  = verify_ssl
        self.proxy       = proxy
        self.user_agent  = user_agent or DEFAULT_USER_AGENT

        self._session = requests.Session()
        self._configure_retries(max_retries)
        self._configure_headers(custom_headers)
        self._configure_proxy(proxy)

        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning(
                "SSL verification disabled — connections will not be verified. "
                "Use only on trusted networks and authorized targets."
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Configuration helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _configure_retries(self, max_retries: int) -> None:
        retry = Retry(
            total=max_retries,
            read=max_retries,
            connect=max_retries,
            backoff_factor=DEFAULT_RETRY_BACKOFF,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)

    def _configure_headers(self, custom_headers: Optional[Dict[str, str]]) -> None:
        self._session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Cache-Control": "no-cache",
        })
        if custom_headers:
            self._session.headers.update(custom_headers)

    def _configure_proxy(self, proxy: Optional[str]) -> None:
        if proxy:
            parsed = urlparse(proxy)
            if parsed.scheme not in ("http", "https", "socks5", "socks5h"):
                raise ValueError(
                    f"Unsupported proxy scheme '{parsed.scheme}'. "
                    "Use http://, https://, socks5://, or socks5h://"
                )
            self._session.proxies = {"http": proxy, "https": proxy}
            logger.debug(f"Proxy configured: {proxy}")

    # ─────────────────────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────────────────────

    def get(
        self,
        url: str,
        allow_redirects: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[requests.Response]:
        """
        Perform a single HTTP GET request.

        Returns the Response on success, or None if any exception occurs.
        Never raises — callers check for None to handle failures.
        """
        effective_timeout = timeout if timeout is not None else self.timeout
        headers = dict(extra_headers) if extra_headers else {}

        try:
            response = self._session.get(
                url,
                headers=headers,
                timeout=effective_timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            logger.debug(
                f"GET {url} → HTTP {response.status_code} "
                f"({len(response.content)} bytes)"
            )
            return response

        except requests.exceptions.SSLError as exc:
            logger.debug(f"SSL error for {url}: {exc}")
            return None
        except requests.exceptions.ProxyError as exc:
            logger.debug(f"Proxy error for {url}: {exc}")
            return None
        except requests.exceptions.ConnectionError as exc:
            logger.debug(f"Connection error for {url}: {exc}")
            return None
        except requests.exceptions.Timeout as exc:
            logger.debug(f"Timeout for {url}: {exc}")
            return None
        except requests.exceptions.TooManyRedirects as exc:
            logger.debug(f"Too many redirects for {url}: {exc}")
            return None
        except requests.exceptions.RequestException as exc:
            logger.debug(f"Request exception for {url}: {exc}")
            return None
        except Exception as exc:
            logger.debug(f"Unexpected error for {url}: {exc}")
            return None

    def head(
        self,
        url: str,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[requests.Response]:
        """
        Perform an HTTP HEAD request to retrieve headers with minimal data transfer.

        Returns the Response on success, or None if any exception occurs.
        """
        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            response = self._session.head(
                url,
                timeout=effective_timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            logger.debug(
                f"HEAD {url} → HTTP {response.status_code}"
            )
            return response

        except Exception as exc:
            logger.debug(f"HEAD exception for {url}: {exc}")
            return None

    def get_response_dict(
        self,
        url: str,
        allow_redirects: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Perform GET and return a structured dict with status, headers, and body.

        Always returns a dict (never None); 'success' key indicates fetch outcome.
        """
        response = self.get(url, allow_redirects=allow_redirects, extra_headers=extra_headers)
        if response is None:
            return {
                "success": False,
                "url": url,
                "status_code": None,
                "headers": {},
                "body": "",
                "final_url": url,
                "error": "Request failed",
            }

        try:
            body = response.text
        except Exception:
            body = ""

        return {
            "success": True,
            "url": url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "final_url": response.url,
            "error": None,
        }

    def close(self) -> None:
        """Release the underlying session resources."""
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "PhpHttpClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()
