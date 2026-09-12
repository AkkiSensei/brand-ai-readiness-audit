"""
http_client.py
==============
Shared HTTP & Crawler Client for brand-ai-readiness-audit.

Provides:
  - RateLimiter      : per-host token-bucket rate limiter (1 req/sec/host default)
  - RobotsTxtCache   : cached robots.txt parser with AI-crawler awareness
  - HttpClient       : sync HTTP session (GET/HEAD only) with retry, timeout, and
                       response-size caps
  - PlaywrightRenderer: on-demand Playwright headless DOM renderer (optional dep)
  - PageResult       : typed dataclass returned by all fetch operations

Design constraints enforced here:
  - Pure read-only: only GET and HEAD methods are issued.
  - Robots-respecting: every GET is checked against robots.txt before fetching.
  - Rate-limited: 1 request per second per host by default (configurable via thresholds).
  - Resilient: network and parse errors are captured into PageResult.error, never raised.
  - Portable: requires only requests, beautifulsoup4, lxml. playwright is optional.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import warnings
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3.connection
import urllib3.connectionpool
import urllib3.exceptions
import urllib3.util.connection as conn_util

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load centralised thresholds
# ---------------------------------------------------------------------------
_THRESHOLDS_PATH = (
    Path(__file__).resolve().parents[2]
    / "audit-orchestrator"
    / "references"
    / "thresholds.json"
)

def _load_thresholds() -> dict:
    try:
        with open(_THRESHOLDS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # pragma: no cover
        logger.warning("Could not load thresholds.json (%s); using built-in defaults.", exc)
        return {}

_T = _load_thresholds()
_HTTP_CFG = _T.get("http", {})
_CRAWL_CFG = _T.get("crawl", {})
_RENDER_CFG = _T.get("render", {})
_ROBOTS_CFG = _T.get("robots", {})

REQUEST_TIMEOUT: float = float(_HTTP_CFG.get("request_timeout_seconds", 8.0))
CONNECT_TIMEOUT: float = float(_HTTP_CFG.get("connect_timeout_seconds", 5.0))
RATE_LIMIT_SECS: float = float(_HTTP_CFG.get("rate_limit_seconds_per_host", 1.0))
MAX_RETRIES: int = int(_HTTP_CFG.get("max_retries", 2))
RETRY_BACKOFF: float = float(_HTTP_CFG.get("retry_backoff_factor", 0.5))
USER_AGENT: str = _HTTP_CFG.get(
    "user_agent",
    "BrandAIReadinessAuditBot/1.0 (+https://github.com/brand-ai-readiness-audit)",
)
MAX_RESPONSE_BYTES: int = int(_HTTP_CFG.get("max_response_size_bytes", 5_242_880))
DEFAULT_HEADERS: dict = _HTTP_CFG.get(
    "default_headers",
    {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    },
)
KNOWN_AI_CRAWLERS: list[str] = _ROBOTS_CFG.get(
    "known_ai_crawlers",
    [
        "GPTBot",
        "ChatGPT-User",
        "Google-Extended",
        "CCBot",
        "anthropic-ai",
        "Claude-Web",
        "PerplexityBot",
        "Amazonbot",
        "FacebookBot",
        "Applebot-Extended",
        "YouBot",
        "Omgilibot",
        "Diffbot",
        "Bytespider",
    ],
)
PLAYWRIGHT_WAIT_MS: int = int(_RENDER_CFG.get("playwright_wait_ms", 3000))
PLAYWRIGHT_TIMEOUT_MS: int = int(_RENDER_CFG.get("playwright_timeout_ms", 15000))
RENDER_TIMEOUT_MS: int = int(_RENDER_CFG.get("playwright_timeout_ms", 10000))
PLAYWRIGHT_VIEWPORT: dict = {
    "width": int(_RENDER_CFG.get("playwright_viewport_width", 1280)),
    "height": int(_RENDER_CFG.get("playwright_viewport_height", 800)),
}

# ---------------------------------------------------------------------------
# SSRF Disallowed Address Ranges & Destination Pinning
# ---------------------------------------------------------------------------
_DISALLOWED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback IPv4
    ipaddress.ip_network("10.0.0.0/8"),        # Private RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private RFC1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),         # Current / unspecified network
    # IPv6
    ipaddress.ip_network("::1/128"),           # Loopback IPv6
    ipaddress.ip_network("::/128"),            # Unspecified IPv6
    ipaddress.ip_network("fc00::/7"),          # Unique local IPv6 (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
]


def normalize_ip(ip_or_str: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize an IP address or string, extracting the IPv4 address from IPv4-mapped IPv6."""
    if isinstance(ip_or_str, str):
        ip = ipaddress.ip_address(ip_or_str.strip("[]"))
    else:
        ip = ip_or_str
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return mapped
    return ip


def is_ip_disallowed(ip_or_str: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Check whether a single IP address (with IPv4-mapped IPv6 normalization) falls in any disallowed network."""
    try:
        norm_ip = normalize_ip(ip_or_str)
        for net in _DISALLOWED_NETWORKS:
            if norm_ip in net:
                return True, f"IP {norm_ip} is in disallowed network {net}"
        return False, ""
    except Exception as exc:
        return True, f"Malformed or invalid IP '{ip_or_str}': {exc}"


def resolve_and_validate_destination(
    hostname_or_ip: str,
    allow_private_ips: bool = False,
) -> tuple[bool, str, list[str]]:
    """Resolve a destination and validate all resulting IP addresses against SSRF policies.

    Returns:
        (is_disallowed, reason, list_of_validated_ips)
    """
    if not hostname_or_ip:
        return False, "", []

    cleaned = hostname_or_ip.strip("[]")

    # 1. Direct IP string
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if allow_private_ips:
            return False, "", [str(ip_obj)]
        disallowed, reason = is_ip_disallowed(ip_obj)
        if disallowed:
            return True, reason, []
        return False, "", [str(normalize_ip(ip_obj))]
    except ValueError:
        pass

    # 2. Check restricted local domain names
    if not allow_private_ips and cleaned.lower() in ("localhost", "metadata.google.internal"):
        return True, f"Hostname '{hostname_or_ip}' is a restricted local domain", []

    # 3. Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(cleaned, None)
        if not addr_info:
            return True, f"DNS resolution for '{hostname_or_ip}' returned no addresses", []

        valid_ips: list[str] = []
        for res in addr_info:
            ip_str = res[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not allow_private_ips:
                    disallowed, reason = is_ip_disallowed(ip_obj)
                    if disallowed:
                        return True, f"Hostname '{hostname_or_ip}' resolved to disallowed IP {ip_str} ({reason})", []
                valid_ips.append(str(normalize_ip(ip_obj)))
            except ValueError:
                return True, f"Hostname '{hostname_or_ip}' resolved to malformed IP '{ip_str}'", []

        # Deduplicate while preserving order
        unique_ips = list(dict.fromkeys(valid_ips))
        return False, "", unique_ips
    except Exception as exc:
        # Phase 2.5: DNS resolution failures must fail closed
        return True, f"DNS resolution failed for hostname '{hostname_or_ip}': {exc}", []


def is_ssrf_disallowed(hostname_or_ip: str) -> tuple[bool, str]:
    """Check if a hostname or IP resolves to a private, loopback, link-local, or cloud-metadata address."""
    disallowed, reason, _ = resolve_and_validate_destination(hostname_or_ip, allow_private_ips=False)
    return disallowed, reason


class DestinationPinningManager:
    """Thread-safe destination pinning cache mapping hostnames to validated IP addresses."""

    def __init__(self) -> None:
        self._pinned: dict[str, str] = {}
        self._lock = threading.Lock()

    def pin(self, host: str, ip: str) -> None:
        if not host or not ip:
            return
        with self._lock:
            self._pinned[host.lower()] = ip

    def get(self, host: str) -> Optional[str]:
        if not host:
            return None
        with self._lock:
            return self._pinned.get(host.lower())

    def clear(self) -> None:
        with self._lock:
            self._pinned.clear()


class SSRFSafeHTTPConnection(urllib3.connection.HTTPConnection):
    """HTTPConnection that pins the socket connection to a pre-validated IP address."""

    def __init__(
        self,
        *args,
        pin_manager: Optional[DestinationPinningManager] = None,
        allow_private_ips: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._pin_manager = pin_manager
        self._allow_private_ips = allow_private_ips

    def _new_conn(self) -> socket.socket:
        target_ip = None
        if not self._allow_private_ips:
            try:
                ip_obj = ipaddress.ip_address(self.host.strip("[]"))
                disallowed, reason = is_ip_disallowed(ip_obj)
                if disallowed:
                    raise urllib3.exceptions.NewConnectionError(
                        self, f"Blocked by SSRF protection: {reason}"
                    )
                target_ip = str(normalize_ip(ip_obj))
            except ValueError:
                if self._pin_manager:
                    target_ip = self._pin_manager.get(self.host)
                if not target_ip:
                    disallowed, reason, ips = resolve_and_validate_destination(
                        self.host, allow_private_ips=self._allow_private_ips
                    )
                    if disallowed or not ips:
                        raise urllib3.exceptions.NewConnectionError(
                            self, f"Blocked by SSRF protection: {reason or 'no valid IP addresses resolved'}"
                        )
                    target_ip = ips[0]
                    if self._pin_manager:
                        self._pin_manager.pin(self.host, target_ip)

        connect_host = target_ip if target_ip else self._dns_host
        try:
            sock = conn_util.create_connection(
                (connect_host, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as e:
            raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
        except TimeoutError as e:
            raise urllib3.exceptions.ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
            ) from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError(
                self, f"Failed to establish a new connection: {e}"
            ) from e

        sys.audit("http.client.connect", self, self.host, self.port)
        return sock


class SSRFSafeHTTPSConnection(urllib3.connection.HTTPSConnection):
    """HTTPSConnection that connects strictly to the pre-validated/pinned IP while preserving TLS SNI and cert validation."""

    def __init__(
        self,
        *args,
        pin_manager: Optional[DestinationPinningManager] = None,
        allow_private_ips: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._pin_manager = pin_manager
        self._allow_private_ips = allow_private_ips

    def _new_conn(self) -> socket.socket:
        target_ip = None
        if not self._allow_private_ips:
            try:
                ip_obj = ipaddress.ip_address(self.host.strip("[]"))
                disallowed, reason = is_ip_disallowed(ip_obj)
                if disallowed:
                    raise urllib3.exceptions.NewConnectionError(
                        self, f"Blocked by SSRF protection: {reason}"
                    )
                target_ip = str(normalize_ip(ip_obj))
            except ValueError:
                if self._pin_manager:
                    target_ip = self._pin_manager.get(self.host)
                if not target_ip:
                    disallowed, reason, ips = resolve_and_validate_destination(
                        self.host, allow_private_ips=self._allow_private_ips
                    )
                    if disallowed or not ips:
                        raise urllib3.exceptions.NewConnectionError(
                            self, f"Blocked by SSRF protection: {reason or 'no valid IP addresses resolved'}"
                        )
                    target_ip = ips[0]
                    if self._pin_manager:
                        self._pin_manager.pin(self.host, target_ip)

        connect_host = target_ip if target_ip else self._dns_host
        try:
            sock = conn_util.create_connection(
                (connect_host, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as e:
            raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
        except TimeoutError as e:
            raise urllib3.exceptions.ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
            ) from e
        except OSError as e:
            raise urllib3.exceptions.NewConnectionError(
                self, f"Failed to establish a new connection: {e}"
            ) from e

        sys.audit("http.client.connect", self, self.host, self.port)
        return sock


class SSRFSafeHTTPAdapter(HTTPAdapter):
    """Requests HTTPAdapter enforcing SSRF destination validation and pinning socket connections."""

    def __init__(
        self,
        pin_manager: Optional[DestinationPinningManager] = None,
        allow_private_ips: bool = False,
        **kwargs,
    ) -> None:
        self.pin_manager = pin_manager or DestinationPinningManager()
        self.allow_private_ips = allow_private_ips
        super().__init__(**kwargs)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        conn = super().get_connection_with_tls_context(request, verify, proxies, cert)
        if getattr(conn, "scheme", "") == "https":
            conn.ConnectionCls = SSRFSafeHTTPSConnection
        else:
            conn.ConnectionCls = SSRFSafeHTTPConnection
        conn.conn_kw["pin_manager"] = self.pin_manager
        conn.conn_kw["allow_private_ips"] = self.allow_private_ips
        return conn

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        if not self.allow_private_ips:
            url_parsed = urllib.parse.urlparse(request.url)
            host = url_parsed.hostname or ""
            pinned = self.pin_manager.get(host)
            if pinned:
                disallowed, reason = is_ip_disallowed(pinned)
                if disallowed:
                    raise requests.exceptions.ConnectionError(
                        f"Blocked by SSRF protection: pinned IP {pinned} is disallowed ({reason})"
                    )
            else:
                disallowed, reason, ips = resolve_and_validate_destination(host, allow_private_ips=False)
                if disallowed or not ips:
                    raise requests.exceptions.ConnectionError(
                        f"Blocked by SSRF protection: {reason or 'no valid IP addresses resolved'}"
                    )
                self.pin_manager.pin(host, ips[0])

        return super().send(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class PageResult:
    """Unified result object returned by all fetch operations."""

    url: str
    """Final URL after redirects."""

    status_code: Optional[int] = None
    """HTTP status code, or None if the request failed before receiving a response."""

    content_type: Optional[str] = None
    """Value of the Content-Type response header (lower-cased, without parameters)."""

    html: Optional[str] = None
    """Raw HTML text of the response body (may be truncated to MAX_RESPONSE_BYTES)."""

    soup: Optional[BeautifulSoup] = None
    """Parsed BeautifulSoup object (lxml parser). None on parse errors."""

    rendered_html: Optional[str] = None
    """DOM HTML captured by Playwright after JavaScript execution (if used)."""

    rendered_soup: Optional[BeautifulSoup] = None
    """Parsed BeautifulSoup from rendered_html."""

    network_requests: list[dict] = field(default_factory=list)
    """Captured network requests during Playwright JavaScript execution."""

    performance_metrics: Optional[dict] = None
    """Browser Performance Timing metrics (FCP, LCP, DOMContentLoaded, etc.)."""

    render_error: Optional[str] = None
    """Error message encountered during Playwright rendering, if any."""

    rendered_word_count: Optional[int] = None
    """Word count of visible text from rendered DOM."""

    static_word_count: Optional[int] = None
    """Word count of visible text from static HTML."""

    csr_blanking_ratio: Optional[float] = None
    """Ratio of static visible text length to rendered visible text length."""

    response_headers: dict = field(default_factory=dict)
    """Full response headers as a lowercase-keyed dict."""

    redirect_chain: list[str] = field(default_factory=list)
    """Ordered list of intermediate URLs in the redirect chain."""

    fetch_duration_seconds: float = 0.0
    """Wall-clock seconds taken for the HTTP request."""

    robots_allowed: bool = True
    """Whether the URL was permitted by robots.txt for our user-agent."""

    error: Optional[str] = None
    """Human-readable error message if any stage failed; None on success."""

    is_rendered: bool = False
    """True if Playwright was used to capture rendered_html."""

    render_confidence: str = "high"
    """Render confidence for this page: 'high' or 'low'."""

    @property
    def is_html(self) -> bool:
        """True if the response represents an HTML document."""
        if self.content_type:
            ct = self.content_type.lower()
            return "text/html" in ct or "application/xhtml+xml" in ct
        # Fallback based on URL extension when Content-Type header is absent
        parsed = urllib.parse.urlparse(self.url or "")
        path = parsed.path.lower()
        non_html_exts = (
            ".md", ".markdown", ".txt", ".xml", ".json", ".pdf",
            ".csv", ".tsv", ".yaml", ".yml", ".rss", ".atom",
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
            ".mp4", ".mp3", ".zip", ".gz"
        )
        return not any(path.endswith(ext) for ext in non_html_exts)


class FrontierEntry(str):
    """An entry in the crawl frontier carrying URL and render confidence.

    Inherits from str for seamless backwards compatibility with string-based
    consumers, while exposing .render_confidence and dict-like access.
    """
    render_confidence: str

    def __new__(cls, url: str, render_confidence: str = "high"):
        obj = super().__new__(cls, url)
        obj.render_confidence = render_confidence
        return obj

    @property
    def url(self) -> str:
        return str(self)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "url":
            return str(self)
        if key == "render_confidence":
            return self.render_confidence
        return default

    def __getitem__(self, item: Any) -> Any:
        if item == "url":
            return str(self)
        if item == "render_confidence":
            return self.render_confidence
        return super().__getitem__(item)

    def to_dict(self) -> dict[str, str]:
        return {"url": str(self), "render_confidence": self.render_confidence}


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Per-host token-bucket rate limiter (thread-safe).

    Ensures at most 1 request per ``interval`` seconds per host.
    """

    def __init__(self, interval: float = RATE_LIMIT_SECS) -> None:
        self._interval = interval
        self._last_request: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        """Block the calling thread until the rate limit window has elapsed."""
        sleep_time = 0.0
        with self._lock:
            now = time.monotonic()
            last = self._last_request.get(host, 0.0)
            gap = self._interval - (now - last)
            if gap > 0:
                sleep_time = gap
                self._last_request[host] = now + gap
            else:
                self._last_request[host] = now
        if sleep_time > 0:
            time.sleep(sleep_time)


# ---------------------------------------------------------------------------
# Robots.txt Cache
# ---------------------------------------------------------------------------

class RobotsTxtCache:
    """Fetches and caches robots.txt parsers per origin (scheme + host + port).

    Provides:
      - can_fetch(url, agent)       — standard robots.txt agent check
      - get_disallowed_ai_agents(url) — list of AI crawlers that are blocked
      - get_sitemaps(url)           — sitemap URLs declared in robots.txt
    """

    def __init__(
        self,
        session: requests.Session,
        rate_limiter: RateLimiter,
        allow_private_ips: bool = False,
    ) -> None:
        self._session = session
        self._limiter = rate_limiter
        self._allow_private_ips = allow_private_ips
        self._cache: dict[str, urllib.robotparser.RobotFileParser] = {}
        self._raw_cache: dict[str, str] = {}
        self._lock = threading.Lock()

    def _origin(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"

    def _fetch_robots(self, origin: str) -> tuple[urllib.robotparser.RobotFileParser, str]:
        robots_url = f"{origin}/robots.txt"
        parser = urllib.robotparser.RobotFileParser()
        parser.set_url(robots_url)
        raw = ""
        try:
            host = urllib.parse.urlparse(origin).hostname or origin
            if not self._allow_private_ips:
                blocked, _ = is_ssrf_disallowed(host)
                if blocked:
                    parser.allow_all = False
                    return parser, ""
            self._limiter.wait(host)
            resp = self._session.get(
                robots_url,
                timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
                allow_redirects=True,
            )
            if resp.status_code == 200:
                raw = resp.text
                parser.parse(raw.splitlines())
            else:
                # Non-200 means assume all allowed (per RFC)
                parser.allow_all = True
        except Exception as exc:
            logger.debug("robots.txt fetch failed for %s: %s", origin, exc)
            parser.allow_all = True
        return parser, raw

    def _get_parser(self, url: str) -> tuple[urllib.robotparser.RobotFileParser, str]:
        origin = self._origin(url)
        with self._lock:
            if origin not in self._cache:
                parser, raw = self._fetch_robots(origin)
                self._cache[origin] = parser
                self._raw_cache[origin] = raw
            return self._cache[origin], self._raw_cache[origin]

    def can_fetch(self, url: str, agent: str = USER_AGENT) -> bool:
        """Return True if the given agent is allowed to fetch this URL."""
        try:
            parser, _ = self._get_parser(url)
            if getattr(parser, "allow_all", False):
                return True
            return parser.can_fetch(agent, url)
        except Exception as exc:
            logger.debug("can_fetch check failed for %s: %s", url, exc)
            return True  # fail open

    def get_disallowed_ai_agents(self, url: str) -> list[str]:
        """Return list of known AI crawlers that are explicitly Disallowed."""
        try:
            _, raw = self._get_parser(url)
            blocked: list[str] = []
            for crawler in KNOWN_AI_CRAWLERS:
                if not self._agent_allowed_in_raw(raw, crawler, url):
                    blocked.append(crawler)
            return blocked
        except Exception as exc:
            logger.debug("get_disallowed_ai_agents failed: %s", exc)
            return []

    def _agent_allowed_in_raw(self, raw: str, agent: str, url: str) -> bool:
        """Parse raw robots.txt text to check a specific agent against a URL path."""
        try:
            tmp_parser = urllib.robotparser.RobotFileParser()
            tmp_parser.parse(raw.splitlines())
            return tmp_parser.can_fetch(agent, url)
        except Exception:
            return True

    def get_sitemaps(self, url: str) -> list[str]:
        """Return all Sitemap: URLs declared in robots.txt for this origin."""
        try:
            _, raw = self._get_parser(url)
            sitemaps: list[str] = []
            for line in raw.splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("sitemap:"):
                    sitemap_url = stripped.split(":", 1)[1].strip()
                    if sitemap_url:
                        sitemaps.append(sitemap_url)
            return sitemaps
        except Exception as exc:
            logger.debug("get_sitemaps failed: %s", exc)
            return []


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------

class HttpClient:
    """Synchronous, rate-limited HTTP client (GET/HEAD only).

    Features:
      - Robots.txt compliance check before every GET.
      - Per-host rate limiting.
      - Automatic retry with exponential backoff.
      - Response-size cap (truncates to MAX_RESPONSE_BYTES).
      - BeautifulSoup parsing with lxml fallback to html.parser.
      - All errors captured in PageResult.error — never propagated.
    """

    def __init__(
        self,
        rate_limit_secs: float = RATE_LIMIT_SECS,
        allow_private_ips: bool = False,
        block_private_redirects: bool = True,
    ) -> None:
        self._allow_private_ips = bool(allow_private_ips)
        self._block_private_redirects = block_private_redirects
        self._limiter = RateLimiter(interval=rate_limit_secs)
        self._pin_manager = DestinationPinningManager()
        self._session = self._build_session()
        self.robots = RobotsTxtCache(self._session, self._limiter, allow_private_ips=self._allow_private_ips)

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, **DEFAULT_HEADERS})
        retry_strategy = Retry(
            total=0,
            connect=False,
            read=False,
            status=0,
            raise_on_status=False,
        )
        adapter = SSRFSafeHTTPAdapter(
            pin_manager=self._pin_manager,
            allow_private_ips=self._allow_private_ips,
            max_retries=retry_strategy,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _parse_html(self, html: str) -> Optional[BeautifulSoup]:
        """Parse HTML with lxml, falling back to html.parser."""
        for parser in ("lxml", "html.parser"):
            try:
                return BeautifulSoup(html, parser)
            except Exception:
                continue
        return None

    def _host(self, url: str) -> str:
        return urllib.parse.urlparse(url).hostname or url

    def get(
        self,
        url: str,
        skip_robots_check: bool = False,
        stream: bool = False,
        headers: Optional[dict] = None,
    ) -> PageResult:
        """Perform a rate-limited, robots-compliant HTTP GET with SSRF and redirect validation."""
        result = PageResult(url=url)

        # --- SSRF check on target URL and destination pinning ---
        if not self._allow_private_ips:
            target_host = urllib.parse.urlparse(url).hostname or ""
            disallowed, reason, ips = resolve_and_validate_destination(target_host, allow_private_ips=False)
            if disallowed:
                result.error = f"Blocked by SSRF protection: {reason}"
                logger.warning("SSRF blocked: %s (%s)", url, reason)
                return result
            if ips:
                self._pin_manager.pin(target_host, ips[0])

        # --- robots.txt check ---
        if not skip_robots_check:
            allowed = self.robots.can_fetch(url)
            result.robots_allowed = allowed
            if not allowed:
                result.error = f"robots.txt disallows fetching: {url}"
                logger.info("Blocked by robots.txt: %s", url)
                return result

        # --- rate limit ---
        try:
            self._limiter.wait(self._host(url))
        except Exception as exc:
            logger.debug("Rate limiter error for %s: %s", url, exc)

        # --- HTTP GET with SSRF and redirect protection ---
        t0 = time.monotonic()
        current_url = url
        redirect_chain: list[str] = []
        max_redirects = 5
        resp = None

        try:
            for _ in range(max_redirects + 1):
                parsed = urllib.parse.urlparse(current_url)
                hostname = parsed.hostname or ""

                # Check SSRF on current_url and pin
                if not self._allow_private_ips:
                    disallowed, reason, cur_ips = resolve_and_validate_destination(hostname, allow_private_ips=False)
                    if disallowed:
                        result.fetch_duration_seconds = time.monotonic() - t0
                        result.error = f"Blocked by SSRF protection: {reason}"
                        logger.warning("SSRF blocked: %s (%s)", current_url, reason)
                        return result
                    if cur_ips:
                        self._pin_manager.pin(hostname, cur_ips[0])

                req_headers = {}
                if headers:
                    req_headers.update(headers)

                resp = self._session.get(
                    current_url,
                    headers=req_headers if req_headers else None,
                    timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
                    allow_redirects=False,
                    stream=True,
                )

                if resp.is_redirect and "Location" in resp.headers:
                    redirect_chain.append(current_url)
                    next_url = urllib.parse.urljoin(current_url, resp.headers["Location"])
                    next_hostname = urllib.parse.urlparse(next_url).hostname or ""

                    # Check SSRF on redirect target
                    check_allow_private = self._allow_private_ips and not self._block_private_redirects
                    disallowed, reason, next_ips = resolve_and_validate_destination(
                        next_hostname,
                        allow_private_ips=check_allow_private,
                    )
                    if disallowed:
                        result.fetch_duration_seconds = time.monotonic() - t0
                        result.error = f"Blocked by SSRF protection on redirect to {next_url}: {reason}"
                        result.redirect_chain = redirect_chain
                        logger.warning("SSRF blocked redirect: %s -> %s (%s)", current_url, next_url, reason)
                        return result

                    if next_ips:
                        self._pin_manager.pin(next_hostname, next_ips[0])

                    current_url = next_url
                    continue
                else:
                    break

            if resp is None:
                result.error = f"No response received for {url}"
                return result

            result.fetch_duration_seconds = time.monotonic() - t0
            result.status_code = resp.status_code
            result.url = current_url
            result.redirect_chain = redirect_chain
            if resp.is_redirect:
                result.error = f"Too many redirects ({len(redirect_chain)} hops) fetching {url}"
            result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
            content_type_full = resp.headers.get("Content-Type", "")
            result.content_type = content_type_full.split(";")[0].strip().lower()

            # Read body with size cap (streaming strictly up to MAX_RESPONSE_BYTES)
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65536):
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    excess = total - MAX_RESPONSE_BYTES
                    if excess < len(chunk):
                        chunks.append(chunk[:-excess])
                    break
                chunks.append(chunk)
            raw_bytes = b"".join(chunks)

            # Robust encoding resolution (Content-Type charset, BOM, meta charset, fallbacks)
            encoding = None
            if "charset=" in content_type_full.lower():
                try:
                    encoding = content_type_full.lower().split("charset=")[-1].split(";")[0].strip().strip("\"'")
                except Exception:
                    pass

            if not encoding:
                if raw_bytes.startswith(b"\xef\xbb\xbf"):
                    encoding = "utf-8-sig"
                elif raw_bytes.startswith(b"\xff\xfe"):
                    encoding = "utf-16-le"
                elif raw_bytes.startswith(b"\xfe\xff"):
                    encoding = "utf-16-be"

            if not encoding:
                meta_head = raw_bytes[:2048].lower()
                m = re.search(rb'<meta[^>]+charset=["\']?([a-zA-Z0-9_-]+)', meta_head)
                if m:
                    try:
                        encoding = m.group(1).decode("ascii")
                    except Exception:
                        pass

            if not encoding:
                encoding = resp.encoding or "utf-8"

            try:
                result.html = raw_bytes.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                try:
                    result.html = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    result.html = raw_bytes.decode("latin-1", errors="replace")

            # Parse HTML with BeautifulSoup only for HTML content
            if result.is_html and result.html:
                result.soup = self._parse_html(result.html)

        except requests.exceptions.Timeout as exc:
            result.fetch_duration_seconds = time.monotonic() - t0
            result.error = f"Timeout fetching {url}: {exc}"
            logger.warning(result.error)
        except requests.exceptions.TooManyRedirects as exc:
            result.fetch_duration_seconds = time.monotonic() - t0
            result.error = f"Too many redirects for {url}: {exc}"
            logger.warning(result.error)
        except requests.exceptions.ConnectionError as exc:
            result.fetch_duration_seconds = time.monotonic() - t0
            exc_str = str(exc)
            if "Blocked by SSRF protection:" in exc_str:
                clean_msg = exc_str.split("Blocked by SSRF protection:")[-1].strip(" :'\")")
                result.error = f"Blocked by SSRF protection: {clean_msg}"
            else:
                result.error = f"Connection error for {url}: {exc}"
            logger.warning(result.error)
        except Exception as exc:
            result.fetch_duration_seconds = time.monotonic() - t0
            result.error = f"Unexpected error fetching {url}: {exc}"
            logger.exception(result.error)
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass

        return result

    def head(self, url: str) -> PageResult:
        """Perform a lightweight HTTP HEAD request with SSRF and redirect protection."""
        result = PageResult(url=url)
        t0 = time.monotonic()
        current_url = url
        redirect_chain: list[str] = []
        max_redirects = 5
        resp = None

        try:
            # Check initial URL SSRF and pin
            if not self._allow_private_ips:
                target_host = urllib.parse.urlparse(url).hostname or ""
                disallowed, reason, ips = resolve_and_validate_destination(target_host, allow_private_ips=False)
                if disallowed:
                    result.error = f"HEAD blocked by SSRF protection: {reason}"
                    return result
                if ips:
                    self._pin_manager.pin(target_host, ips[0])

            for _ in range(max_redirects + 1):
                parsed = urllib.parse.urlparse(current_url)
                hostname = parsed.hostname or ""

                if not self._allow_private_ips:
                    disallowed, reason, cur_ips = resolve_and_validate_destination(hostname, allow_private_ips=False)
                    if disallowed:
                        result.fetch_duration_seconds = time.monotonic() - t0
                        result.error = f"HEAD blocked by SSRF protection: {reason}"
                        return result
                    if cur_ips:
                        self._pin_manager.pin(hostname, cur_ips[0])

                self._limiter.wait(self._host(current_url))
                resp = self._session.head(
                    current_url,
                    timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
                    allow_redirects=False,
                )

                if resp.is_redirect and "Location" in resp.headers:
                    redirect_chain.append(current_url)
                    next_url = urllib.parse.urljoin(current_url, resp.headers["Location"])
                    next_hostname = urllib.parse.urlparse(next_url).hostname or ""

                    # Check SSRF on redirect target
                    check_allow_private = self._allow_private_ips and not self._block_private_redirects
                    disallowed, reason, next_ips = resolve_and_validate_destination(
                        next_hostname,
                        allow_private_ips=check_allow_private,
                    )
                    if disallowed:
                        result.fetch_duration_seconds = time.monotonic() - t0
                        result.error = f"HEAD blocked by SSRF protection on redirect to {next_url}: {reason}"
                        result.redirect_chain = redirect_chain
                        return result

                    if next_ips:
                        self._pin_manager.pin(next_hostname, next_ips[0])

                    current_url = next_url
                    continue
                else:
                    break

            if resp is not None:
                result.fetch_duration_seconds = time.monotonic() - t0
                result.status_code = resp.status_code
                result.url = current_url
                result.redirect_chain = redirect_chain
                if resp.is_redirect:
                    result.error = f"Too many redirects ({len(redirect_chain)} hops) for {url}"
                result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
                content_type_full = resp.headers.get("Content-Type", "")
                result.content_type = content_type_full.split(";")[0].strip().lower()
        except requests.exceptions.Timeout as exc:
            result.error = f"HEAD timeout for {url}: {exc}"
        except requests.exceptions.ConnectionError as exc:
            exc_str = str(exc)
            if "Blocked by SSRF protection:" in exc_str:
                clean_msg = exc_str.split("Blocked by SSRF protection:")[-1].strip(" :'\")")
                result.error = f"HEAD blocked by SSRF protection: {clean_msg}"
            else:
                result.error = f"HEAD connection error for {url}: {exc}"
        except Exception as exc:
            result.error = f"HEAD unexpected error for {url}: {exc}"
        return result

    def close(self) -> None:
        """Release the underlying requests.Session."""
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Playwright Renderer (optional dependency)
# ---------------------------------------------------------------------------

class PlaywrightRenderer:
    """On-demand headless Chromium renderer using Playwright.

    Playwright is an optional dependency. If it is not installed, all
    render() calls return a PageResult with error set and is_rendered=False.

    Features:
      - Shared RateLimiter coordination with HttpClient.
      - Shared RobotsTxtCache compliance verification.
      - SSRF protection on initial navigation, mid-navigation redirects, and subrequests.
      - Network request capture with fully resolved timings (requestfinished listener).
      - W3C Navigation & Performance API metrics (FCP, LCP, DOMContentLoaded).
      - Single browser process lifecycle with isolated per-render contexts.
    """

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        robots_cache: Optional[RobotsTxtCache] = None,
        allow_private_ips: bool = False,
    ) -> None:
        self._allow_private_ips = bool(allow_private_ips)
        self._limiter = rate_limiter
        self._robots = robots_cache
        self._playwright = None
        self._browser = None
        self._available = self._check_availability()
        self._launch_count = 0

    def _check_availability(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            logger.info(
                "Playwright not installed. DOM rendering will be skipped. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return False

    def _ensure_browser(self) -> None:
        """Lazily launch the Playwright browser once across the crawler lifecycle."""
        if self._browser is not None:
            return
        from playwright.sync_api import sync_playwright  # type: ignore[import]
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )
        self._launch_count += 1
        browser_pid = "unknown"
        try:
            if hasattr(self._browser, "_process") and self._browser._process:
                browser_pid = str(self._browser._process.pid)
            elif hasattr(self._browser, "process") and self._browser.process:
                browser_pid = str(self._browser.process.pid)
        except Exception:
            pass
        logger.info(
            "Playwright browser launched (pid=%s, launch_count=%d)",
            browser_pid,
            self._launch_count,
        )

    def render(
        self,
        url: str,
        wait_ms: int = PLAYWRIGHT_WAIT_MS,
        page_result: Optional[PageResult] = None,
    ) -> PageResult:
        """Render a page with Playwright and return the post-JS DOM.

        Args:
            url: The absolute URL to render.
            wait_ms: Milliseconds to wait after page load for JS execution.
            page_result: Optional existing PageResult to populate in-place.

        Returns:
            PageResult with rendered_html, rendered_soup, network_requests,
            performance_metrics, render_error populated.
        """
        result = page_result if page_result is not None else PageResult(url=url)
        if not self._available:
            result.render_error = "Playwright not installed; render skipped."
            result.error = result.error or result.render_error
            result.render_confidence = "low"
            return result

        parsed = urllib.parse.urlparse(url)
        target_host = parsed.hostname or ""

        # --- SSRF Check before navigation ---
        if not self._allow_private_ips:
            disallowed, reason = is_ssrf_disallowed(target_host)
            if disallowed:
                result.render_error = f"Blocked by SSRF protection: {reason}"
                result.render_confidence = "low"
                logger.warning("SSRF blocked in PlaywrightRenderer: %s (%s)", url, reason)
                return result

        # --- Robots.txt Check ---
        if self._robots is not None:
            if not self._robots.can_fetch(url):
                result.render_error = f"robots.txt disallows rendering: {url}"
                result.render_confidence = "low"
                logger.info("Blocked by robots.txt in renderer: %s", url)
                return result

        # --- Shared Rate Limiter Check ---
        if self._limiter is not None:
            t0_pace = time.monotonic()
            self._limiter.wait(target_host or url)
            paced_time = time.monotonic() - t0_pace
            if paced_time > 0.05:
                logger.info("Renderer rate limiter paced host %s (slept %.3fs)", target_host, paced_time)

        context = None
        network_requests: list[dict] = []
        req_entry_map: dict[Any, dict] = {}
        ssrf_abort_events: list[tuple[str, str]] = []

        try:
            self._ensure_browser()
            if self._browser is None:
                result.render_error = "Playwright browser failed to launch."
                result.render_confidence = "low"
                return result

            context = self._browser.new_context(
                viewport=PLAYWRIGHT_VIEWPORT,
                user_agent=USER_AGENT,
            )

            # SSRF Route Interception: protects all subrequests and mid-navigation redirects
            if not self._allow_private_ips:
                def intercept_route(route):
                    req_url = route.request.url
                    req_host = urllib.parse.urlparse(req_url).hostname or ""
                    is_blocked, block_reason = is_ssrf_disallowed(req_host)
                    if is_blocked:
                        logger.warning("SSRF blocked route in Playwright: %s (%s)", req_url, block_reason)
                        ssrf_abort_events.append((req_url, block_reason))
                        route.abort("accessdenied")
                        return
                    route.continue_()

                context.route("**/*", intercept_route)

            page = context.new_page()

            def on_request(req):
                entry = {
                    "method": req.method,
                    "url": req.url,
                    "status": None,
                    "resource_type": req.resource_type,
                    "timing": None,
                }
                req_entry_map[req] = entry
                network_requests.append(entry)

            def on_response(resp):
                entry = req_entry_map.get(resp.request)
                if entry is not None:
                    entry["status"] = resp.status
                    try:
                        entry["timing"] = resp.request.timing
                    except Exception:
                        pass

            def on_request_finished(req):
                entry = req_entry_map.get(req)
                if entry is not None:
                    try:
                        entry["timing"] = req.timing
                    except Exception:
                        pass

            def on_request_failed(req):
                entry = req_entry_map.get(req)
                if entry is not None:
                    if entry.get("status") is None:
                        entry["status"] = 0
                    try:
                        entry["timing"] = req.timing
                    except Exception:
                        pass

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfinished", on_request_finished)
            page.on("requestfailed", on_request_failed)

            # Observe LCP if supported by browser
            try:
                page.add_init_script("""
                    window.__lcp = null;
                    try {
                        const observer = new PerformanceObserver((entryList) => {
                            const entries = entryList.getEntries();
                            if (entries.length > 0) {
                                window.__lcp = entries[entries.length - 1].startTime;
                            }
                        });
                        observer.observe({ type: 'largest-contentful-paint', buffered: true });
                    } catch (e) {}
                """)
            except Exception:
                pass

            # Navigate: wait for networkidle or bounded timeout RENDER_TIMEOUT_MS
            try:
                page.goto(url, timeout=RENDER_TIMEOUT_MS, wait_until="networkidle")
            except Exception as nav_exc:
                if ssrf_abort_events:
                    viol_url, viol_reason = ssrf_abort_events[0]
                    result.render_error = f"Blocked by SSRF protection on redirect/subrequest to {viol_url}: {viol_reason}"
                    result.render_confidence = "low"
                    result.network_requests = network_requests
                    return result
                logger.debug("networkidle timeout/error for %s: %s; falling back to domcontentloaded", url, nav_exc)
                try:
                    _ = page.content()
                except Exception:
                    try:
                        page.goto(url, timeout=RENDER_TIMEOUT_MS, wait_until="domcontentloaded")
                    except Exception as fallback_exc:
                        if ssrf_abort_events:
                            viol_url, viol_reason = ssrf_abort_events[0]
                            result.render_error = f"Blocked by SSRF protection on redirect/subrequest to {viol_url}: {viol_reason}"
                        else:
                            result.render_error = f"Playwright navigation failed for {url}: {fallback_exc}"
                        result.render_confidence = "low"
                        result.network_requests = network_requests
                        return result

            if wait_ms > 0:
                try:
                    page.wait_for_timeout(wait_ms)
                except Exception:
                    pass

            # Final pass to capture any completed response timings
            for req, entry in req_entry_map.items():
                try:
                    t = req.timing
                    if t:
                        entry["timing"] = t
                except Exception:
                    pass

            result.rendered_html = page.content()
            result.is_rendered = True
            result.rendered_soup = _safe_parse_html(result.rendered_html)
            result.network_requests = network_requests

            # Capture Navigation Timing API & Performance API
            try:
                metrics = page.evaluate("""() => {
                    const nav = (performance.getEntriesByType('navigation')[0]) || {};
                    const paint = performance.getEntriesByType('paint') || [];
                    let fcp = null;
                    for (const p of paint) {
                        if (p.name === 'first-contentful-paint') {
                            fcp = p.startTime;
                        }
                    }
                    let lcp = window.__lcp || null;
                    if (lcp === null) {
                        try {
                            const lcpEntries = performance.getEntriesByType('largest-contentful-paint') || [];
                            if (lcpEntries.length > 0) {
                                lcp = lcpEntries[lcpEntries.length - 1].startTime;
                            }
                        } catch (e) {}
                    }
                    const pt = performance.timing || {};
                    const navStart = pt.navigationStart || 0;
                    const dcl = nav.domContentLoadedEventEnd != null
                        ? nav.domContentLoadedEventEnd
                        : (pt.domContentLoadedEventEnd && navStart ? pt.domContentLoadedEventEnd - navStart : null);
                    const load = nav.loadEventEnd != null
                        ? nav.loadEventEnd
                        : (pt.loadEventEnd && navStart ? pt.loadEventEnd - navStart : null);

                    return {
                        "fcp": fcp,
                        "lcp": lcp,
                        "dom_content_loaded": dcl,
                        "load_event": load,
                        "duration": nav.duration || (load != null ? load : null),
                        "transfer_size": nav.transferSize || null,
                        "decoded_body_size": nav.decodedBodySize || null
                    };
                }""")
                result.performance_metrics = metrics
            except Exception as perf_exc:
                logger.debug("Performance metrics evaluation failed for %s: %s", url, perf_exc)
                result.performance_metrics = None

        except Exception as exc:
            result.render_error = f"Playwright render error for {url}: {exc}"
            result.render_confidence = "low"
            result.network_requests = network_requests
            logger.warning(result.render_error)
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

        return result

    def close(self) -> None:
        """Shut down the Playwright browser."""
        try:
            if self._browser:
                self._browser.close()
                self._browser = None
        except Exception:
            pass
        try:
            if self._playwright:
                self._playwright.stop()
                self._playwright = None
        except Exception:
            pass

    def __enter__(self) -> "PlaywrightRenderer":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_parse_html(html: str) -> Optional[BeautifulSoup]:
    """Parse HTML string safely, returning None on any failure."""
    for parser in ("lxml", "html.parser"):
        try:
            return BeautifulSoup(html, parser)
        except Exception:
            continue
    return None


def normalise_url(url: str, base: str) -> Optional[str]:
    """Resolve a possibly-relative URL against a base URL.

    Returns an absolute URL string, or None if the result is unusable.
    """
    try:
        resolved = urllib.parse.urljoin(base, url.strip())
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in ("http", "https"):
            return None
        # Strip fragments
        clean = urllib.parse.urlunparse(parsed._replace(fragment=""))
        return clean
    except Exception:
        return None


def extract_text_ratio(soup: BeautifulSoup) -> float:
    """Compute ratio of visible text length to cleaned HTML markup length.

    Returns a float in [0.0, 1.0]. Lower values suggest heavy JS rendering
    or content trapped in non-text elements. Non-text elements like script,
    style, noscript, meta, link, and svg are stripped before comparison.
    """
    try:
        # Strip script/style/noscript/svg/meta/link
        working = BeautifulSoup(str(soup), "html.parser")
        for tag in working.find_all(["script", "style", "noscript", "meta", "link", "svg"]):
            tag.decompose()
        clean_html = str(working)
        clean_len = len(clean_html)
        if clean_len == 0:
            return 0.0
        text = working.get_text(separator=" ", strip=True)
        return min(len(text) / clean_len, 1.0)
    except Exception:
        return 0.0


def is_same_origin(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share the same scheme, host, and port."""
    try:
        a = urllib.parse.urlparse(url_a)
        b = urllib.parse.urlparse(url_b)
        return (
            a.scheme == b.scheme
            and (a.hostname or "").lower() == (b.hostname or "").lower()
            and a.port == b.port
        )
    except Exception:
        return False
