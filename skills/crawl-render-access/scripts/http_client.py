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

from enum import Enum
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
MAX_BROWSER_REQUESTS_PER_PAGE: int = int(_RENDER_CFG.get("max_browser_requests_per_page", 150))
MAX_BROWSER_REDIRECTS: int = int(_RENDER_CFG.get("max_browser_redirects", 5))
ALLOWED_BROWSER_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# ---------------------------------------------------------------------------
# SSRF Disallowed Address Ranges & Destination Pinning
# ---------------------------------------------------------------------------
_DISALLOWED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback IPv4
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC1918
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC1918
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),          # Current / unspecified network
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-Grade NAT / Cloud Shared RFC 6598
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments RFC 6890
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 RFC 5737
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 RFC 5737
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 RFC 5737
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmark RFC 2544
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast RFC 5771
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved RFC 1112
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast RFC 919
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback IPv6
    ipaddress.ip_network("::/128"),             # Unspecified IPv6
    ipaddress.ip_network("fc00::/7"),           # Unique local IPv6 (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local IPv6
    ipaddress.ip_network("ff00::/8"),           # Multicast IPv6
    ipaddress.ip_network("2001:db8::/32"),      # Documentation IPv6 RFC 3849
]

_6TO4_NET = ipaddress.ip_network("2002::/16")
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPAT_NET = ipaddress.ip_network("::/96")
_RESTRICTED_LOCAL_DOMAINS = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
})


def normalize_ip(ip_or_str: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalize an IP address or string, extracting the IPv4 address from IPv4-mapped, 6to4, or NAT64 IPv6."""
    if isinstance(ip_or_str, str):
        ip = ipaddress.ip_address(ip_or_str.strip("[]"))
    else:
        ip = ip_or_str

    if isinstance(ip, ipaddress.IPv6Address):
        # 1. Standard IPv4-mapped IPv6 (::ffff:0:0/96)
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            return mapped

        # 2. 6to4 prefix (2002::/16): bytes 2..6 encode embedded IPv4
        if ip in _6TO4_NET:
            try:
                return ipaddress.IPv4Address(ip.packed[2:6])
            except Exception:
                pass

        # 3. Well-known NAT64 prefix (64:ff9b::/96): bytes 12..16 encode embedded IPv4
        if ip in _NAT64_NET:
            try:
                return ipaddress.IPv4Address(ip.packed[12:16])
            except Exception:
                pass

        # 4. Deprecated IPv4-compatible IPv6 (::/96): bytes 12..16 encode embedded IPv4
        if ip != ipaddress.IPv6Address("::") and ip != ipaddress.IPv6Address("::1") and ip in _IPV4_COMPAT_NET:
            try:
                return ipaddress.IPv4Address(ip.packed[12:16])
            except Exception:
                pass

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
    if not hostname_or_ip or not hostname_or_ip.strip():
        return True, "Destination hostname is empty", []

    cleaned = hostname_or_ip.strip().strip("[]")
    if not cleaned:
        return True, "Destination hostname is empty", []

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
    if not allow_private_ips and cleaned.lower() in _RESTRICTED_LOCAL_DOMAINS:
        return True, f"Hostname '{hostname_or_ip}' is a restricted local or cloud metadata domain", []

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
# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

class EvidenceState(str, Enum):
    """Minimal observation state of evidence for audited claims, facts, and assets.

    Distinguishes positive observation, definitive contradiction, absence of
    asserted corroboration, and unobservable/unreachable targets without
    manufacturing certainty.
    """

    CONFIRMED = "CONFIRMED"                      # Direct observation verified (e.g. resolving accreditation link, confirmed entity/markup)
    CONTRADICTED = "CONTRADICTED"                # Definitively disproven or broken (e.g. 404/410 broken link, contradictory facts)
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Claim or fact asserted but uncorroborated (e.g. claim without verification link, unstated date)
    NOT_OBSERVABLE = "NOT_OBSERVABLE"            # Target source unreachable, timeout, transport failure, renderer unavailable


class CoverageState(str, Enum):
    """Compact, deterministic audit coverage state.

    Indicates how much of the target and domain checks were genuinely observable:
    - COMPLETE: Full observation; all planned pages and checks executed with high confidence.
    - PARTIAL: Substantial audit ran, but bounded by budget, sampled probes, or partial responses.
    - LIMITED: Key evidence sources unobservable (e.g. static-only without JS, unverified external links).
    - UNAVAILABLE: Target or domain blocked, unreachable, or failed before inspection.
    """

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    LIMITED = "LIMITED"
    UNAVAILABLE = "UNAVAILABLE"


class RenderState(str, Enum):
    """Explicit observation state of browser rendering for a page."""

    CONFIRMED = "CONFIRMED"                      # Rendering succeeded; post-JS DOM captured and inspected
    PARTIAL = "PARTIAL"                          # Partial rendering / blanking observed
    STATIC_ONLY = "STATIC_ONLY"                  # Browser rendering not requested or static-only crawl
    RENDER_UNAVAILABLE = "RENDER_UNAVAILABLE"    # Playwright or Chromium not available / installed
    RENDER_FAILED = "RENDER_FAILED"              # Browser navigation timed out, crashed, or errored
    BLOCKED = "BLOCKED"                          # Blocked by SSRF or security boundary


class FetchState(str, Enum):
    """Explicit fetch state for a page resource."""

    FETCHED_OK = "fetched_ok"                  # HTTP 200-399 with inspectable response body
    BLOCKED_BY_ROBOTS = "blocked_by_robots"    # Disallowed by robots.txt
    RATE_LIMITED = "rate_limited"              # HTTP 429 or rate-limited response
    WAF_BLOCKED = "waf_blocked"                # Active WAF / bot challenge (403/429/503 with challenge headers/signatures)
    UNUSABLE_CHALLENGE = "unusable_challenge"  # HTTP 200 but behaviorally a JS/WAF/CAPTCHA challenge shell
    FETCH_FAILED = "fetch_failed"              # Network drop, timeout, DNS failure, SSL failure, SSRF blocked
    HTTP_ERROR = "http_error"                  # HTTP 4xx / 5xx error responses (not WAF/rate-limit)
    REDIRECT_FAILED = "redirect_failed"        # Redirect cycle, too many redirects, or redirect to blocked destination


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
    """Render confidence for this page: 'high', 'medium', or 'low'."""

    render_state: RenderState = RenderState.STATIC_ONLY
    """Explicit observation state for dynamic rendering."""

    evidence_state: Optional[EvidenceState] = None
    """Observation state of evidence for this page resource."""

    fetch_state: Optional[FetchState] = None
    """Explicit fetch state for this page resource."""

    @property
    def effective_fetch_state(self) -> FetchState:
        """Derive or return the explicit FetchState for this page."""
        if self.fetch_state is not None:
            return self.fetch_state
        if not self.robots_allowed:
            return FetchState.BLOCKED_BY_ROBOTS
        if self.error:
            err_lower = self.error.lower()
            if "redirect" in err_lower:
                return FetchState.REDIRECT_FAILED
            if "robots.txt" in err_lower:
                return FetchState.BLOCKED_BY_ROBOTS
        if self.status_code is None:
            return FetchState.FETCH_FAILED
        if self.status_code == 429:
            return FetchState.RATE_LIMITED
        headers_lower = {k.lower(): str(v).lower() for k, v in self.response_headers.items()}
        html_lower = (self.html or "").lower()
        if self.status_code in (403, 429, 503, 202):
            if any(h in headers_lower for h in ("cf-ray", "cf-mitigated", "cf-chl-bypass", "x-datadome")) or \
               any(k.startswith("akamai-") or k.startswith("x-px-") for k in headers_lower) or \
               "signalnonbrowseruseragent" in headers_lower.get("x-rate-limit", "") or \
               any(c in headers_lower.get("set-cookie", "") for c in ("bm_s=", "_abck=", "bm_sz=")) or \
               "px-captcha" in html_lower or ("access denied" in html_lower and "reference #" in html_lower):
                return FetchState.WAF_BLOCKED
            if self.status_code == 403:
                return FetchState.WAF_BLOCKED
            if self.status_code == 503 and ("retry-after" in headers_lower or "rate" in html_lower):
                return FetchState.RATE_LIMITED
        if 200 <= self.status_code < 400:
            return FetchState.FETCHED_OK
        if self.status_code >= 400:
            return FetchState.HTTP_ERROR
        return FetchState.FETCH_FAILED

    @property
    def is_usable_content(self) -> bool:
        """True if the page was successfully fetched, is not a challenge/interstitial shell,
        and contains inspectable DOM content."""
        fs = self.effective_fetch_state
        return (
            fs == FetchState.FETCHED_OK
            and self.fetch_state != FetchState.UNUSABLE_CHALLENGE
            and self.soup is not None
        )

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


# ---------------------------------------------------------------------------
# Generic HTTP-200 Challenge / Interstitial Detection
# ---------------------------------------------------------------------------
# Uses multiple corroborating behavioral signals — NO vendor-name lists.
# Requires ≥ CHALLENGE_MIN_SIGNALS to classify a page as UNUSABLE_CHALLENGE,
# which prevents any downstream DOM-quality findings from being generated.

import hashlib as _hashlib

# Title patterns that are strongly associated with challenge/interstitial pages.
# These are generic behavioral terms, not vendor names.
_CHALLENGE_TITLE_RE = re.compile(
    r"^\s*(?:checking|(?:client\s+)?challenge|security\s+check|please\s+wait|attention\s+required|"
    r"ddos\s+protection|verif(?:y|ying|ication)|access\s+denied|one\s+more\s+step|"
    r"just\s+a\s+moment|human\s+verification|bot\s+check|browser\s+check|"
    r"are\s+you\s+a\s+(?:human|robot)|captcha|loading|enable\s+javascript|"
    r"site\s+is\s+protected|service\s+unavailable|ray\s+id|under\s+attack)"
    r"(?:[.\s!?:…|–-].*)?$",
    re.IGNORECASE,
)

# Structural patterns in the body text that are classic challenge content
_CHALLENGE_BODY_RE = re.compile(
    r"(?:complete\s+(?:the\s+)?(?:security\s+)?check|"
    r"you\s+(?:have\s+been\s+)?blocked|"
    r"press\s+&\s+hold|slide\s+to\s+verify|"
    r"checking\s+your\s+browser|"
    r"please\s+enable\s+(?:javascript|cookies)|"
    r"proving\s+you\s+are\s+human|"
    r"your\s+ip\s+(?:has\s+been|is)\s+(?:blocked|flagged)|"
    r"automated\s+access|bot\s+protection)\b",
    re.IGNORECASE,
)

# Minimum number of corroborating signals required to classify as UNUSABLE_CHALLENGE.
# Set to 3 to prevent false-positives on legitimate sparse or SPA pages.
CHALLENGE_MIN_SIGNALS: int = 3


def detect_challenge_page(
    html: Optional[str],
    soup: Optional["BeautifulSoup"],
    url: str = "",
) -> tuple[bool, float, list[str]]:
    """Detect whether a page is a JS/WAF/CAPTCHA challenge shell using behavioral signals.

    Uses multiple corroborating signals — not vendor-specific string matching.
    Requires at least CHALLENGE_MIN_SIGNALS (default=3) to classify as a challenge,
    preventing false-positives on legitimate sparse pages or normal SPA shells.

    Returns:
        (is_challenge, confidence, signals_list)
        - is_challenge: True if ≥ CHALLENGE_MIN_SIGNALS triggered AND a mandatory
          content-intent anchor (challenge title or body text) is also present
        - confidence: float 0.0–1.0 proportional to signal count
        - signals_list: human-readable list of which signals fired

    IMPORTANT: This function NEVER mutates the passed soup object.
    All text extraction is performed on the raw html string to preserve
    the caller's soup for downstream word-count and DOM checks.
    """
    signals: list[str] = []

    if not html and not soup:
        return False, 0.0, signals

    html_text = html or ""
    html_lower = html_text.lower()

    # ── Signal 1: Generic/challenge page title ───────────────────────────────
    # Read-only: uses soup.find() which never mutates.
    title_text = ""
    if soup is not None:
        title_tag = soup.find("title")
        if title_tag:
            title_text = (title_tag.get_text() or "").strip()
    else:
        m = re.search(r"<title[^>]*>([^<]{0,200})</title>", html_text, re.IGNORECASE)
        if m:
            title_text = m.group(1).strip()

    if title_text and _CHALLENGE_TITLE_RE.match(title_text):
        signals.append(f"challenge_title:{title_text[:80]!r}")

    # ── Signals 2 & 3: Script-dominant structure + low content density ────────
    # CRITICAL: compute entirely from raw HTML strings — NEVER call decompose()
    # on the passed soup, which would permanently mutate the caller's PageResult.
    #
    # Extract script content bytes via regex on raw html.
    script_bytes = sum(
        len(m.group(1) or "")
        for m in re.finditer(
            r"<script(?:\s[^>]*)?>([^<]*(?:<(?!/script>)[^<]*)*)</script>",
            html_text,
            re.IGNORECASE | re.DOTALL,
        )
    )

    # Build visible text by stripping all HTML tags from the raw string.
    # This is semantically equivalent to soup.get_text() after decomposing
    # script/style/noscript — but without touching the soup object.
    _tag_strip_re = re.compile(
        r"<(?:script|style|noscript)(?:\s[^>]*)?>.*?</(?:script|style|noscript)>",
        re.IGNORECASE | re.DOTALL,
    )
    bare_html = _tag_strip_re.sub(" ", html_text)
    bare_html = re.sub(r"<[^>]+>", " ", bare_html)
    visible_text = re.sub(r"\s+", " ", bare_html).strip()

    visible_word_count = len(visible_text.split())

    # Script-dominant: total script content is much larger than visible text.
    if script_bytes > 0 and script_bytes > max(300, visible_word_count * 8):
        signals.append(f"script_dominant:script={script_bytes}B visible_words={visible_word_count}")

    # Very low meaningful content density — challenge shells have near-zero.
    if visible_word_count < 30:
        signals.append(f"low_content_density:words={visible_word_count}")

    # ── Signal 4: Absence of semantic content elements ───────────────────────
    # Read-only: soup.find() never mutates.
    if soup is not None:
        has_h1 = bool(soup.find("h1"))
        has_p = bool(soup.find("p"))
        has_article = bool(soup.find(["article", "main", "section"]))
        has_nav = bool(soup.find("nav"))
        if not has_h1 and not has_p and not has_article:
            signals.append("no_semantic_elements:missing_h1_p_article")
        if not has_nav and not has_h1:
            if "no_semantic_elements:missing_h1_p_article" not in signals:
                signals.append("no_nav_no_h1")
    else:
        if not re.search(r"<(?:h1|article|main|section|nav)[>\s]", html_lower):
            signals.append("no_semantic_elements_raw")

    # ── Signal 5: Challenge body content match ────────────────────────────────
    if _CHALLENGE_BODY_RE.search(visible_text) or _CHALLENGE_BODY_RE.search(html_lower):
        signals.append("challenge_body_text_pattern")

    # ── Signal 6: Noscript-only meaningful content (JS-gate pattern) ─────────
    # Read-only: soup.find_all("noscript") never mutates.
    if soup is not None:
        noscript_tags = soup.find_all("noscript")
        noscript_text = " ".join((t.get_text() or "") for t in noscript_tags)
        noscript_words = len(noscript_text.split())
        if noscript_words > 5 and noscript_words >= visible_word_count:
            signals.append(f"noscript_dominant:noscript_words={noscript_words}")

    # ── Signal 7: Hidden-only form (typical challenge token submission) ────────
    # Read-only: soup.find_all("form") never mutates.
    if soup is not None:
        all_forms = soup.find_all("form")
        for form in all_forms:
            visible_inputs = [
                i for i in form.find_all("input")
                if (i.get("type") or "text").lower() not in ("hidden", "submit", "button")
            ]
            hidden_inputs = [
                i for i in form.find_all("input")
                if (i.get("type") or "").lower() == "hidden"
            ]
            if hidden_inputs and not visible_inputs:
                signals.append("hidden_form_only:likely_challenge_token_form")
                break

    # ── Signal 8: Zero or near-zero visible links ─────────────────────────────
    # Read-only: soup.find_all("a") never mutates.
    if soup is not None:
        link_count = len(soup.find_all("a", href=True))
        if link_count == 0:
            signals.append("zero_visible_links")
    elif not re.search(r"<a\s[^>]*href", html_lower):
        signals.append("zero_visible_links_raw")

    signal_count = len(signals)
    confidence = min(1.0, signal_count / max(1, CHALLENGE_MIN_SIGNALS + 2))

    # Safety gate — two requirements must BOTH be met:
    #
    # 1. Quantity gate: ≥ CHALLENGE_MIN_SIGNALS total signals fired.
    # 2. Mandatory content-intent anchor: Signal 1 (challenge_title) OR
    #    Signal 5 (challenge_body_text_pattern) must be present.
    #
    # This two-lock design prevents legitimate SPA shells and thin pages from
    # being misclassified. A real SPA bundle has lots of script bytes and may
    # have no semantic elements — but it does NOT have a challenge-titled page
    # or challenge body text. Only actual bot-protection pages carry those.
    has_mandatory_anchor = any(
        sig.startswith("challenge_title") or sig == "challenge_body_text_pattern"
        for sig in signals
    )
    is_challenge = signal_count >= CHALLENGE_MIN_SIGNALS and has_mandatory_anchor

    if is_challenge:
        logger.debug(
            "detect_challenge_page: %s classified as UNUSABLE_CHALLENGE "
            "(signals=%d/%d): %s",
            url, signal_count, CHALLENGE_MIN_SIGNALS, signals,
        )
    return is_challenge, confidence, signals



def detect_challenge_cluster(
    page_results: "dict[str, PageResult]",
    min_cluster_size: int = 3,
) -> dict[str, list[str]]:
    """Identify challenge-shell clustering: multiple URLs returning the same content fingerprint.

    When ≥ min_cluster_size different requested URLs share the same visible-text fingerprint
    (SHA-256 of the first 300 chars of normalized visible text), all are reclassified as
    FetchState.UNUSABLE_CHALLENGE. This detects unknown-vendor challenge pages that present
    identical content regardless of which URL was requested.

    Returns:
        dict mapping fingerprint -> list[url] for all detected clusters.
        As a side-effect, sets fetch_state=UNUSABLE_CHALLENGE on clustered PageResults.
    """
    import hashlib

    fingerprint_map: dict[str, list[str]] = {}

    for url, pr in page_results.items():
        if pr is None:
            continue
        # Only fingerprint HTTP-200 pages with a soup
        if pr.status_code is None or pr.status_code < 200 or pr.status_code >= 400:
            continue
        if pr.soup is None and not pr.html:
            continue

        # Build a normalized fingerprint from visible text
        if pr.soup is not None:
            try:
                # Work on a copy to avoid mutating the cached soup
                import copy
                soup_copy = copy.copy(pr.soup)
                for tag in soup_copy.find_all(["script", "style"]):
                    tag.decompose()
                text = soup_copy.get_text(separator=" ", strip=True)
            except Exception:
                text = pr.html or ""
        else:
            text = re.sub(r"<[^>]+>", " ", pr.html or "")

        normalized = re.sub(r"\s+", " ", text).strip().lower()[:300]
        if len(normalized) < 10:
            # Skip nearly-empty pages (already caught by other signals)
            continue

        fp = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]
        fingerprint_map.setdefault(fp, []).append(url)

    # Identify clusters and reclassify
    clusters: dict[str, list[str]] = {}
    for fp, urls in fingerprint_map.items():
        if len(urls) >= min_cluster_size:
            clusters[fp] = urls
            for u in urls:
                pr = page_results.get(u)
                if pr is not None and pr.fetch_state != FetchState.UNUSABLE_CHALLENGE:
                    pr.fetch_state = FetchState.UNUSABLE_CHALLENGE
                    logger.debug(
                        "detect_challenge_cluster: reclassified %s as UNUSABLE_CHALLENGE "
                        "(fingerprint=%s, cluster_size=%d)",
                        u, fp, len(urls),
                    )
    return clusters


class FrontierEntry(str):
    """An entry in the crawl frontier carrying URL, render confidence, and render state.

    Inherits from str for seamless backwards compatibility with string-based
    consumers, while exposing .render_confidence, .render_state and dict-like access.
    """
    render_confidence: str
    render_state: str

    def __new__(
        cls,
        url: str,
        render_confidence: str = "high",
        render_state: str = "STATIC_ONLY",
    ):
        obj = super().__new__(cls, url)
        obj.render_confidence = render_confidence
        obj.render_state = render_state
        return obj

    @property
    def url(self) -> str:
        return str(self)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "url":
            return str(self)
        if key == "render_confidence":
            return self.render_confidence
        if key == "render_state":
            return self.render_state
        return default

    def __getitem__(self, item: Any) -> Any:
        if item == "url":
            return str(self)
        if item == "render_confidence":
            return self.render_confidence
        if item == "render_state":
            return self.render_state
        return super().__getitem__(item)

    def to_dict(self) -> dict[str, str]:
        return {
            "url": str(self),
            "render_confidence": self.render_confidence,
            "render_state": self.render_state,
        }


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

    def wait(self, host: str, deadline: Optional["AuditDeadline"] = None) -> None:
        """Block the calling thread until the rate limit window has elapsed, bounded by deadline."""
        if deadline and deadline.expired():
            return
        clean_host = (host or "").split(":")[0].lower()
        if not clean_host or clean_host in ("127.0.0.1", "localhost", "::1"):
            return
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
            if deadline:
                sleep_time = min(sleep_time, deadline.remaining())
            if sleep_time > 0:
                time.sleep(sleep_time)


# ---------------------------------------------------------------------------
# Global Audit Deadline Abstraction
# ---------------------------------------------------------------------------

class AuditDeadline:
    """Shared authoritative deadline tracking remaining runtime budget across all operations."""

    def __init__(
        self,
        timeout_s: float | None = None,
        started_at: float | None = None,
    ) -> None:
        now = time.monotonic()
        # If started_at is synthetic or in the future, clamp to now to prevent clock skew / negative durations
        if started_at is not None:
            self.started_at: float = min(float(started_at), now)
        else:
            self.started_at = now

        self.timeout_s: float = float(timeout_s) if timeout_s is not None else float("inf")
        self.deadline: float = self.started_at + self.timeout_s

    def elapsed(self) -> float:
        """Wall-clock elapsed time since start (strictly non-negative)."""
        return max(0.0, time.monotonic() - self.started_at)

    def remaining(self) -> float:
        """Seconds remaining before deadline expiration (never negative, bounded by timeout_s if positive)."""
        rem = self.deadline - time.monotonic()
        if self.timeout_s > 0:
            return max(0.0, min(self.timeout_s, rem))
        return 0.0 if rem <= 0 else max(0.0, rem)

    def expired(self) -> bool:
        """True if the deadline has elapsed."""
        return self.remaining() <= 0.0

    def child_timeout(self, maximum: float) -> float:
        """Return min(maximum, remaining()), or 0.0 if expired."""
        rem = self.remaining()
        return max(0.0, min(float(maximum), rem))

    def child_timeout_tuple(
        self,
        connect_max: float = CONNECT_TIMEOUT,
        request_max: float = REQUEST_TIMEOUT,
    ) -> tuple[float, float]:
        """Return (connect_timeout, request_timeout) tuple clamped to remaining budget."""
        rem = self.remaining()
        eff_conn = max(0.001, min(float(connect_max), rem))
        eff_req = max(0.001, min(float(request_max), rem))
        return (eff_conn, eff_req)

    @classmethod
    def from_budget(
        cls,
        timeout_s: float | None,
        started_at: float | None = None,
    ) -> "AuditDeadline":
        return cls(timeout_s=timeout_s, started_at=started_at)


# ---------------------------------------------------------------------------
# Robots State Model & Unified Safe Fetch Primitive
# ---------------------------------------------------------------------------

class RobotsState(str, Enum):
    """Explicit state of robots.txt retrieval and evaluation."""

    ALLOWED = "ALLOWED"          # robots.txt retrieved and explicitly allows URL, OR 4xx status (unrestricted per RFC 9309)
    DISALLOWED = "DISALLOWED"    # robots.txt retrieved and explicitly disallows URL, OR 5xx status (server error per RFC 9309)
    UNAVAILABLE = "UNAVAILABLE"  # network/transport/timeout error retrieving robots.txt (fails closed)
    BLOCKED = "BLOCKED"          # blocked by SSRF protection on initial URL or redirect hop (fails closed)
    INVALID = "INVALID"          # redirect loop / too many redirects / parser exception (fails closed)


@dataclass
class RobotsEntry:
    """Cached robots metadata and parsed rules for an origin."""

    state: RobotsState
    parser: Optional[urllib.robotparser.RobotFileParser] = None
    raw: str = ""
    error: Optional[str] = None


@dataclass
class SafeFetchResult:
    """Outcome of bounded, SSRF-validated HTTP fetch."""

    response: Optional[requests.Response] = None
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    error: Optional[str] = None
    is_ssrf_blocked: bool = False
    is_too_many_redirects: bool = False
    is_timeout: bool = False
    is_connection_error: bool = False
    duration_seconds: float = 0.0


def _safe_fetch_with_redirects(
    session: requests.Session,
    method: str,
    url: str,
    pin_manager: Optional[DestinationPinningManager] = None,
    allow_private_ips: bool = False,
    block_private_redirects: bool = True,
    max_redirects: int = 5,
    headers: Optional[dict] = None,
    stream: bool = False,
    timeout: tuple[float, float] = (CONNECT_TIMEOUT, REQUEST_TIMEOUT),
    limiter: Optional[RateLimiter] = None,
    deadline: Optional[AuditDeadline] = None,
) -> SafeFetchResult:
    """Execute an HTTP request with bounded, SSRF-validated redirects and destination pinning.

    Ensures that every outbound hop (initial request and every redirect transition)
    is checked against SSRF policy, pinned in DestinationPinningManager, and bounded
    by the global AuditDeadline.
    """
    t0 = time.monotonic()
    current_url = url
    redirect_chain: list[str] = []
    resp: Optional[requests.Response] = None

    ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD"})
    method_upper = method.upper()
    if method_upper not in ALLOWED_HTTP_METHODS:
        return SafeFetchResult(
            final_url=url,
            redirect_chain=redirect_chain,
            error=f"Blocked non-read-only method '{method_upper}' (only GET and HEAD permitted)",
            is_connection_error=True,
            duration_seconds=max(0.0, time.monotonic() - t0),
        )

    if deadline and deadline.expired():
        return SafeFetchResult(
            final_url=url,
            redirect_chain=redirect_chain,
            error=f"Audit deadline expired before request could start for {url}",
            is_timeout=True,
            duration_seconds=max(0.0, time.monotonic() - t0),
        )

    for hop in range(max_redirects + 1):
        if deadline and deadline.expired():
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Audit deadline expired fetching {current_url}",
                is_timeout=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )

        parsed = urllib.parse.urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Blocked unsupported URL scheme '{parsed.scheme}' (only HTTP and HTTPS permitted)",
                is_ssrf_blocked=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )
        hostname = parsed.hostname or ""

        # Validate SSRF on current_url destination and pin IP
        if not allow_private_ips:
            disallowed, reason, cur_ips = resolve_and_validate_destination(hostname, allow_private_ips=False)
            if disallowed:
                return SafeFetchResult(
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=f"Blocked by SSRF protection: {reason}",
                    is_ssrf_blocked=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )
            if pin_manager and cur_ips:
                pin_manager.pin(hostname, cur_ips[0])

        if limiter:
            try:
                limiter.wait(hostname or current_url, deadline=deadline)
            except Exception as exc:
                logger.debug("Rate limiter error for %s: %s", current_url, exc)

        # Compute effective hop timeout clamped to remaining deadline
        if deadline:
            hop_conn, hop_req = deadline.child_timeout_tuple(timeout[0], timeout[1])
            if deadline.remaining() <= 0.001:
                return SafeFetchResult(
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=f"Audit deadline exhausted fetching {current_url}",
                    is_timeout=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )
            hop_timeout = (hop_conn, hop_req)
        else:
            hop_timeout = timeout

        try:
            req_headers = dict(headers) if headers else None
            resp = session.request(
                method=method,
                url=current_url,
                headers=req_headers,
                timeout=hop_timeout,
                allow_redirects=False,
                stream=stream,
            )
        except requests.exceptions.Timeout as exc:
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Request timed out for {current_url}: {exc}",
                is_timeout=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )
        except requests.exceptions.ConnectionError as exc:
            exc_str = str(exc)
            if "Blocked by SSRF protection:" in exc_str:
                clean_msg = exc_str.split("Blocked by SSRF protection:")[-1].strip(" :'\")")
                return SafeFetchResult(
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=f"Blocked by SSRF protection: {clean_msg}",
                    is_ssrf_blocked=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Connection error for {current_url}: {exc}",
                is_connection_error=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )
        except requests.exceptions.RequestException as exc:
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Request error for {current_url}: {exc}",
                is_connection_error=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )
        except Exception as exc:
            return SafeFetchResult(
                final_url=current_url,
                redirect_chain=redirect_chain,
                error=f"Unexpected error for {current_url}: {exc}",
                is_connection_error=True,
                duration_seconds=max(0.0, time.monotonic() - t0),
            )

        location_header = resp.headers.get("Location") or resp.headers.get("location")
        if (resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308)) and location_header:
            redirect_chain.append(current_url)
            if hop >= max_redirects:
                return SafeFetchResult(
                    response=resp,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=f"Too many redirects ({len(redirect_chain)} hops) fetching {url}",
                    is_too_many_redirects=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )

            next_url = urllib.parse.urljoin(current_url, location_header)
            next_parsed = urllib.parse.urlparse(next_url)
            if next_parsed.scheme not in ("http", "https"):
                return SafeFetchResult(
                    response=resp,
                    final_url=next_url,
                    redirect_chain=redirect_chain,
                    error=f"Blocked redirect to unsupported scheme '{next_parsed.scheme}'",
                    is_ssrf_blocked=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )
            next_hostname = next_parsed.hostname or ""

            # Validate redirect target against SSRF
            check_allow_private = allow_private_ips and not block_private_redirects
            disallowed, reason, next_ips = resolve_and_validate_destination(
                next_hostname,
                allow_private_ips=check_allow_private,
            )
            if disallowed:
                return SafeFetchResult(
                    response=resp,
                    final_url=next_url,
                    redirect_chain=redirect_chain,
                    error=f"Blocked by SSRF protection on redirect to {next_url}: {reason}",
                    is_ssrf_blocked=True,
                    duration_seconds=max(0.0, time.monotonic() - t0),
                )
            if pin_manager and next_ips:
                pin_manager.pin(next_hostname, next_ips[0])

            current_url = next_url
            continue
        else:
            break

    if resp is None:
        return SafeFetchResult(
            final_url=current_url,
            redirect_chain=redirect_chain,
            error=f"No response received for {url}",
            is_connection_error=True,
            duration_seconds=max(0.0, time.monotonic() - t0),
        )

    if resp.is_redirect:
        return SafeFetchResult(
            response=resp,
            final_url=current_url,
            redirect_chain=redirect_chain,
            error=f"Too many redirects ({len(redirect_chain)} hops) fetching {url}",
            is_too_many_redirects=True,
            duration_seconds=max(0.0, time.monotonic() - t0),
        )

    return SafeFetchResult(
        response=resp,
        final_url=current_url,
        redirect_chain=redirect_chain,
        duration_seconds=max(0.0, time.monotonic() - t0),
    )


# ---------------------------------------------------------------------------
# Robots.txt Cache
# ---------------------------------------------------------------------------

class RobotsTxtCache:
    """Fetches and caches robots.txt parsers per origin (scheme + host + port).

    Provides:
      - can_fetch(url, agent)         — standard robots.txt agent check (fails closed)
      - get_robots_state(url)         — explicit RobotsState enum
      - get_disallowed_ai_agents(url) — list of AI crawlers that are blocked
      - get_sitemaps(url)             — sitemap URLs declared in robots.txt
    """

    def __init__(
        self,
        session: requests.Session,
        rate_limiter: RateLimiter,
        allow_private_ips: bool = False,
        block_private_redirects: bool = True,
        pin_manager: Optional[DestinationPinningManager] = None,
        deadline: Optional[AuditDeadline] = None,
    ) -> None:
        self._session = session
        self._limiter = rate_limiter
        self._allow_private_ips = allow_private_ips
        self._block_private_redirects = block_private_redirects
        self.deadline = deadline
        self._pin_manager = (
            pin_manager
            or getattr(session.adapters.get("https://"), "pin_manager", None)
            or getattr(session.adapters.get("http://"), "pin_manager", None)
            or DestinationPinningManager()
        )
        self._cache: dict[str, RobotsEntry] = {}
        self._lock = threading.Lock()

    def set_deadline(self, deadline: Optional[AuditDeadline]) -> None:
        """Update or establish the shared authoritative deadline."""
        self.deadline = deadline

    def _origin(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _fetch_robots(self, origin: str, deadline: Optional[AuditDeadline] = None) -> RobotsEntry:
        eff_deadline = deadline or self.deadline
        if eff_deadline and eff_deadline.expired():
            logger.warning("Audit deadline expired before fetching robots.txt for %s", origin)
            return RobotsEntry(state=RobotsState.UNAVAILABLE, error="Audit deadline expired")

        robots_url = f"{origin}/robots.txt"
        fetch_res = _safe_fetch_with_redirects(
            session=self._session,
            method="GET",
            url=robots_url,
            pin_manager=self._pin_manager,
            allow_private_ips=self._allow_private_ips,
            block_private_redirects=self._block_private_redirects,
            max_redirects=5,
            limiter=self._limiter,
            timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
            stream=False,
            deadline=eff_deadline,
        )

        if fetch_res.is_ssrf_blocked:
            logger.warning("SSRF blocked robots.txt fetch for %s: %s", origin, fetch_res.error)
            return RobotsEntry(state=RobotsState.BLOCKED, error=fetch_res.error)

        if fetch_res.is_too_many_redirects:
            logger.warning("Redirect loop/exceeded fetching robots.txt for %s: %s", origin, fetch_res.error)
            return RobotsEntry(state=RobotsState.INVALID, error=fetch_res.error)

        if fetch_res.is_timeout or fetch_res.is_connection_error:
            logger.warning("Network/transport error fetching robots.txt for %s: %s", origin, fetch_res.error)
            return RobotsEntry(state=RobotsState.UNAVAILABLE, error=fetch_res.error)

        resp = fetch_res.response
        if resp is None:
            logger.warning("No response for robots.txt at %s: %s", origin, fetch_res.error)
            return RobotsEntry(state=RobotsState.UNAVAILABLE, error=fetch_res.error or "No response")

        # RFC 9309 Status code semantics
        if 200 <= resp.status_code < 300:
            raw = resp.text
            try:
                parser = urllib.robotparser.RobotFileParser()
                parser.set_url(robots_url)
                parser.parse(raw.splitlines())
                return RobotsEntry(state=RobotsState.ALLOWED, parser=parser, raw=raw)
            except Exception as exc:
                logger.warning("Failed to parse robots.txt for %s: %s", origin, exc)
                return RobotsEntry(state=RobotsState.INVALID, raw=raw, error=str(exc))

        elif 400 <= resp.status_code < 500:
            # Per RFC 9309 section 2.3.1.2: 4xx means robots.txt does not exist; access is unrestricted
            logger.info("robots.txt for %s returned HTTP %s; crawling unrestricted per RFC 9309", origin, resp.status_code)
            return RobotsEntry(state=RobotsState.ALLOWED, parser=None, raw="")

        elif 500 <= resp.status_code < 600:
            # Per RFC 9309 section 2.3.1.3: 5xx server error is a temporary failure -> disallow all
            logger.warning("robots.txt for %s returned HTTP %s; disallowing crawl per RFC 9309", origin, resp.status_code)
            return RobotsEntry(state=RobotsState.DISALLOWED, error=f"HTTP {resp.status_code}")

        else:
            logger.warning("robots.txt for %s returned unexpected HTTP %s; disallowing", origin, resp.status_code)
            return RobotsEntry(state=RobotsState.DISALLOWED, error=f"Unexpected HTTP {resp.status_code}")

    def _get_entry(self, url: str, deadline: Optional[AuditDeadline] = None) -> RobotsEntry:
        origin = self._origin(url)
        with self._lock:
            if origin not in self._cache:
                self._cache[origin] = self._fetch_robots(origin, deadline=deadline)
            return self._cache[origin]

    def _get_parser(self, url: str) -> tuple[Optional[urllib.robotparser.RobotFileParser], str]:
        """Backward-compatible helper returning (parser, raw)."""
        entry = self._get_entry(url)
        return entry.parser, entry.raw

    def get_robots_state(self, url: str, deadline: Optional[AuditDeadline] = None) -> RobotsState:
        """Return the explicit RobotsState enum for the origin of url."""
        return self._get_entry(url, deadline=deadline).state

    def can_fetch(
        self,
        url: str,
        agent: str = USER_AGENT,
        deadline: Optional[AuditDeadline] = None,
    ) -> bool:
        """Return True if the given agent is allowed to fetch this URL under robots.txt policy."""
        try:
            eff_deadline = deadline or self.deadline
            if eff_deadline and eff_deadline.expired():
                logger.warning("Audit deadline expired checking robots policy for %s", url)
                return False  # fail closed

            entry = self._get_entry(url, deadline=eff_deadline)
            if entry.state == RobotsState.BLOCKED:
                logger.warning("robots.txt blocked by SSRF for %s: %s", url, entry.error)
                return False
            if entry.state == RobotsState.UNAVAILABLE:
                logger.warning("robots.txt unavailable (transport error) for %s: %s", url, entry.error)
                return False
            if entry.state == RobotsState.INVALID:
                logger.warning("robots.txt invalid (redirect/parser error) for %s: %s", url, entry.error)
                return False
            if entry.state == RobotsState.DISALLOWED:
                logger.info("robots.txt disallows crawling for %s: %s", url, entry.error)
                return False
            if entry.state == RobotsState.ALLOWED:
                if entry.parser is None:
                    # 4xx or unrestricted robots.txt per RFC 9309
                    return True
                try:
                    return bool(entry.parser.can_fetch(agent, url))
                except Exception as exc:
                    logger.warning("Parser error evaluating can_fetch(%s, %s): %s", agent, url, exc)
                    return False  # fail closed
            return False
        except Exception as exc:
            logger.warning("Unexpected error evaluating robots policy for %s: %s", url, exc)
            return False  # fail closed

    def get_disallowed_ai_agents(self, url: str) -> list[str]:
        """Return list of known AI crawlers that are explicitly Disallowed."""
        try:
            entry = self._get_entry(url)
            # Epistemic honesty: only evaluate explicit disallows when robots.txt was successfully
            # retrieved and parsed. Network failure, malformed syntax, or SSRF blocks must not be
            # reported as explicit AI-crawler disallows.
            if entry.state != RobotsState.ALLOWED or not entry.raw:
                return []
            blocked: list[str] = []
            for crawler in KNOWN_AI_CRAWLERS:
                if not self._agent_allowed_in_raw(entry.raw, crawler, url):
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
            # Epistemic honesty: on parser error / malformed line, do not falsely conclude
            # that this agent is explicitly disallowed by policy.
            return True

    def get_sitemaps(self, url: str) -> list[str]:
        """Return all Sitemap: URLs declared in robots.txt for this origin."""
        try:
            entry = self._get_entry(url)
            if not entry.raw:
                return []
            sitemaps: list[str] = []
            for line in entry.raw.splitlines():
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
        deadline: Optional[AuditDeadline] = None,
    ) -> None:
        self._allow_private_ips = bool(allow_private_ips)
        self._block_private_redirects = block_private_redirects
        self.deadline = deadline
        self._limiter = RateLimiter(interval=rate_limit_secs)
        self._pin_manager = DestinationPinningManager()
        self._session = self._build_session()
        self.verify_transport_security()
        self.robots = RobotsTxtCache(
            session=self._session,
            rate_limiter=self._limiter,
            allow_private_ips=self._allow_private_ips,
            block_private_redirects=self._block_private_redirects,
            pin_manager=self._pin_manager,
            deadline=self.deadline,
        )

    def verify_transport_security(self) -> bool:
        """Verify that the underlying requests.Session has SSRFSafeHTTPAdapter mounted on HTTP and HTTPS."""
        http_adapter = self._session.adapters.get("http://")
        https_adapter = self._session.adapters.get("https://")
        is_safe = isinstance(http_adapter, SSRFSafeHTTPAdapter) and isinstance(https_adapter, SSRFSafeHTTPAdapter)
        if not is_safe:
            logger.error("Security invariant violation: HttpClient session lacks SSRFSafeHTTPAdapter wiring!")
        return is_safe

    def set_deadline(self, deadline: Optional[AuditDeadline]) -> None:
        """Update or establish the shared authoritative deadline across client and robots cache."""
        self.deadline = deadline
        self.robots.set_deadline(deadline)

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
        deadline: Optional[AuditDeadline] = None,
    ) -> PageResult:
        """Perform a rate-limited, robots-compliant HTTP GET with SSRF, redirect, and deadline validation."""
        result = PageResult(url=url)
        eff_deadline = deadline or self.deadline

        if eff_deadline and eff_deadline.expired():
            result.error = f"Audit deadline expired before fetching {url}"
            result.robots_allowed = False
            result.fetch_state = result.effective_fetch_state
            return result

        # --- robots.txt check ---
        if not skip_robots_check:
            allowed = self.robots.can_fetch(url, deadline=eff_deadline)
            result.robots_allowed = allowed
            if not allowed:
                entry = self.robots._get_entry(url, deadline=eff_deadline)
                if entry.state == RobotsState.BLOCKED:
                    result.error = f"Blocked by SSRF protection (robots.txt): {entry.error or 'disallowed destination'}"
                else:
                    result.error = f"robots.txt disallows fetching ({entry.state.value}): {url}"
                logger.info("Blocked by robots.txt (%s): %s", entry.state.value, url)
                result.fetch_state = result.effective_fetch_state
                return result

        fetch_res = _safe_fetch_with_redirects(
            session=self._session,
            method="GET",
            url=url,
            pin_manager=self._pin_manager,
            allow_private_ips=self._allow_private_ips,
            block_private_redirects=self._block_private_redirects,
            max_redirects=5,
            headers=headers,
            stream=True,
            timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
            limiter=self._limiter,
            deadline=eff_deadline,
        )

        result.fetch_duration_seconds = max(0.0, fetch_res.duration_seconds)
        result.url = fetch_res.final_url or url
        result.redirect_chain = fetch_res.redirect_chain

        if fetch_res.error:
            result.error = fetch_res.error
            if not fetch_res.response:
                result.fetch_state = result.effective_fetch_state
                return result

        resp = fetch_res.response
        if resp is None:
            if not result.error:
                result.error = f"No response received for {url}"
            result.fetch_state = result.effective_fetch_state
            return result

        result.status_code = resp.status_code
        result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type_full = resp.headers.get("Content-Type", "")
        result.content_type = content_type_full.split(";")[0].strip().lower()

        # Read body with size cap (streaming strictly up to MAX_RESPONSE_BYTES)
        try:
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65536):
                if eff_deadline and eff_deadline.expired():
                    result.error = f"Audit deadline expired while reading response body from {url}"
                    break
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
                elif raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
                    encoding = "utf-16"
                else:
                    meta_match = re.search(
                        rb'<meta[^>]+charset=["\']?([a-zA-Z0-9_-]+)',
                        raw_bytes[:2048],
                        re.IGNORECASE,
                    )
                    if meta_match:
                        try:
                            encoding = meta_match.group(1).decode("ascii", errors="ignore").strip()
                        except Exception:
                            pass

            if not encoding:
                encoding = resp.encoding or "utf-8"

            try:
                result.html = raw_bytes.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                result.html = raw_bytes.decode("utf-8", errors="replace")

            result.soup = self._parse_html(result.html)
        except Exception as exc:
            result.error = f"Error reading response body from {url}: {exc}"
            logger.warning(result.error)
        finally:
            try:
                resp.close()
            except Exception:
                pass

        # Run behavioral challenge detection on HTTP 200 responses before finalizing state.
        # Must run AFTER soup is parsed so DOM signals are available.
        if result.status_code is not None and 200 <= result.status_code < 400:
            try:
                is_chal, _conf, _sigs = detect_challenge_page(result.html, result.soup, url)
                if is_chal:
                    result.fetch_state = FetchState.UNUSABLE_CHALLENGE
                    logger.info(
                        "HttpClient.get: %s is an HTTP-200 challenge/interstitial "
                        "(signals: %s)", url, _sigs
                    )
                else:
                    result.fetch_state = result.effective_fetch_state
            except Exception as _exc:
                logger.debug("detect_challenge_page error for %s: %s", url, _exc)
                result.fetch_state = result.effective_fetch_state
        else:
            result.fetch_state = result.effective_fetch_state
        return result

    def head(
        self,
        url: str,
        deadline: Optional[AuditDeadline] = None,
    ) -> PageResult:
        """Perform a lightweight HTTP HEAD request with SSRF, redirect, and deadline protection."""
        result = PageResult(url=url)
        eff_deadline = deadline or self.deadline

        if eff_deadline and eff_deadline.expired():
            result.error = f"Audit deadline expired before HEAD {url}"
            result.fetch_state = result.effective_fetch_state
            return result

        fetch_res = _safe_fetch_with_redirects(
            session=self._session,
            method="HEAD",
            url=url,
            pin_manager=self._pin_manager,
            allow_private_ips=self._allow_private_ips,
            block_private_redirects=self._block_private_redirects,
            max_redirects=5,
            limiter=self._limiter,
            timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
            stream=False,
            deadline=eff_deadline,
        )

        result.fetch_duration_seconds = max(0.0, fetch_res.duration_seconds)
        result.url = fetch_res.final_url or url
        result.redirect_chain = fetch_res.redirect_chain

        if fetch_res.error:
            result.error = fetch_res.error
            if not fetch_res.response:
                result.fetch_state = result.effective_fetch_state
                return result

        resp = fetch_res.response
        if resp is None:
            if not result.error:
                result.error = f"No response received for {url}"
            result.fetch_state = result.effective_fetch_state
            return result

        result.status_code = resp.status_code
        result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type_full = resp.headers.get("Content-Type", "")
        result.content_type = content_type_full.split(";")[0].strip().lower()
        result.fetch_state = result.effective_fetch_state
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
        block_private_subrequests: bool = False,
        deadline: Optional[AuditDeadline] = None,
        session: Optional[requests.Session] = None,
        pin_manager: Optional[DestinationPinningManager] = None,
    ) -> None:
        self._allow_private_ips = bool(allow_private_ips)
        self._block_private_subrequests = bool(block_private_subrequests)
        self._limiter = rate_limiter
        self._robots = robots_cache
        self.deadline = deadline
        self._pin_manager = pin_manager  # Fix: was dropped in __init__, causing AttributeError in intercept_route
        # Fix: session was accepted but never stored, causing AttributeError in intercept_route
        if session is not None:
            self._session = session
            self._owns_session = False
        else:
            # Build a minimal SSRF-safe session for route interception fetch calls
            self._session = requests.Session()
            self._owns_session = True
            adapter = SSRFSafeHTTPAdapter(
                pin_manager=self._pin_manager,
                allow_private_ips=self._allow_private_ips,
            )
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        self._playwright = None
        self._browser = None
        self._available = self._check_availability()
        self._launch_count = 0
        self._lock = threading.Lock()

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
        with self._lock:
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
        deadline: Optional[AuditDeadline] = None,
    ) -> PageResult:
        """Render a page with Playwright and return the post-JS DOM.

        Args:
            url: The absolute URL to render.
            wait_ms: Milliseconds to wait after page load for JS execution.
            page_result: Optional existing PageResult to populate in-place.
            deadline: Optional AuditDeadline bounding navigation and wait windows.

        Returns:
            PageResult with rendered_html, rendered_soup, network_requests,
            performance_metrics, render_error populated.
        """
        result = page_result if page_result is not None else PageResult(url=url)
        eff_deadline = deadline or self.deadline

        if eff_deadline and eff_deadline.expired():
            result.render_error = f"Audit deadline expired before rendering {url}"
            result.render_confidence = "low"
            result.render_state = RenderState.RENDER_FAILED
            return result

        if not self._available:
            result.render_error = "Playwright not installed; render skipped."
            result.error = result.error or result.render_error
            result.render_confidence = "low"
            result.render_state = RenderState.RENDER_UNAVAILABLE
            return result

        parsed = urllib.parse.urlparse(url)
        target_host = parsed.hostname or ""

        # --- SSRF Check before navigation ---
        if not self._allow_private_ips:
            disallowed, reason = is_ssrf_disallowed(target_host)
            if disallowed:
                result.render_error = f"Blocked by SSRF protection: {reason}"
                result.render_confidence = "low"
                result.render_state = RenderState.BLOCKED
                logger.warning("SSRF blocked in PlaywrightRenderer: %s (%s)", url, reason)
                return result

        # --- Robots.txt Check ---
        if self._robots is not None:
            if not self._robots.can_fetch(url, deadline=eff_deadline):
                result.render_error = f"robots.txt disallows rendering: {url}"
                result.render_confidence = "low"
                result.render_state = RenderState.BLOCKED
                logger.info("Blocked by robots.txt in renderer: %s", url)
                return result

        # --- Shared Rate Limiter Check ---
        if self._limiter is not None:
            t0_pace = time.monotonic()
            self._limiter.wait(target_host or url, deadline=eff_deadline)
            paced_time = max(0.0, time.monotonic() - t0_pace)
            if paced_time > 0.05:
                logger.info("Renderer rate limiter paced host %s (slept %.3fs)", target_host, paced_time)

        context = None
        network_requests: list[dict] = []
        req_entry_map: dict[Any, dict] = {}
        ssrf_abort_events: list[tuple[str, str]] = []
        method_abort_events: list[tuple[str, str]] = []
        budget_abort_events: list[tuple[str, int]] = []
        redirect_abort_events: list[tuple[str, int]] = []

        try:
            self._ensure_browser()
            if self._browser is None:
                result.render_error = "Playwright browser failed to launch."
                result.render_confidence = "low"
                return result

            # Service workers blocked engine-wide to prevent policy/interception bypass
            context = self._browser.new_context(
                viewport=PLAYWRIGHT_VIEWPORT,
                user_agent=USER_AGENT,
                service_workers="block",
            )

            # Security Route Interceptor:
            # 1. Global audit deadline enforcement
            # 2. Strict read-only HTTP method policy (GET, HEAD, OPTIONS only)
            # 3. Request count budget per render (MAX_BROWSER_REQUESTS_PER_PAGE)
            # 4. Redirect hop budget per chain (MAX_BROWSER_REDIRECTS)
            # 5. SSRF protection on all destinations (subrequests, scripts, frames, redirects)
            request_counter = 0

            def intercept_route(route):
                nonlocal request_counter
                req = route.request
                req_url = req.url
                method = req.method.upper()

                # 1. Global audit deadline check
                if eff_deadline and eff_deadline.expired():
                    logger.debug("Audit deadline expired; aborting browser route %s", req_url)
                    route.abort("timedout")
                    return

                # 2. HTTP method policy: Marketplace is strictly read-only
                if method not in ALLOWED_BROWSER_METHODS:
                    logger.warning("Blocked non-read-only method in Playwright: %s %s", method, req_url)
                    method_abort_events.append((req_url, method))
                    route.abort("blockedbyclient")
                    return

                # 3. Network request budget per page render
                request_counter += 1
                if request_counter > MAX_BROWSER_REQUESTS_PER_PAGE:
                    logger.warning(
                        "Browser request budget exceeded (%d > %d): aborting %s",
                        request_counter, MAX_BROWSER_REQUESTS_PER_PAGE, req_url,
                    )
                    budget_abort_events.append((req_url, request_counter))
                    route.abort("blockedbyclient")
                    return

                # 4. Redirect hop budget
                chain_len = 0
                cur_req = req.redirected_from
                while cur_req:
                    chain_len += 1
                    cur_req = cur_req.redirected_from
                if chain_len > MAX_BROWSER_REDIRECTS:
                    logger.warning(
                        "Browser redirect budget exceeded (%d > %d): aborting %s",
                        chain_len, MAX_BROWSER_REDIRECTS, req_url,
                    )
                    redirect_abort_events.append((req_url, chain_len))
                    route.abort("failed")
                    return

                # 5. Scheme Filtering: In-memory schemes continue; non-HTTP schemes abort
                parsed_req = urllib.parse.urlparse(req_url)
                if parsed_req.scheme in ("data", "blob", "about"):
                    route.continue_()
                    return

                if parsed_req.scheme not in ("http", "https"):
                    logger.warning("Blocked non-HTTP browser scheme: %s in %s", parsed_req.scheme, req_url)
                    method_abort_events.append((req_url, f"SCHEME:{parsed_req.scheme}"))
                    route.abort("blockedbyclient")
                    return

                # 6. SSRF Destination Validation & Pre-fetch Pinning (Anti-TOCTOU)
                req_host = parsed_req.hostname or ""
                disallow_dest = not self._allow_private_ips or (
                    self._block_private_subrequests and req_url != url
                )
                if disallow_dest:
                    is_blocked, block_reason, valid_ips = resolve_and_validate_destination(
                        req_host, allow_private_ips=False
                    )
                    if is_blocked:
                        logger.warning("SSRF blocked route in Playwright: %s (%s)", req_url, block_reason)
                        ssrf_abort_events.append((req_url, block_reason))
                        route.abort("accessdenied")
                        return
                    if valid_ips and self._pin_manager:
                        self._pin_manager.pin(req_host, valid_ips[0])
                else:
                    if self._pin_manager:
                        _, _, valid_ips = resolve_and_validate_destination(
                            req_host, allow_private_ips=True
                        )
                        if valid_ips:
                            self._pin_manager.pin(req_host, valid_ips[0])

                # 7. Shared Rate Limiting
                if self._limiter is not None and req_host:
                    try:
                        self._limiter.wait(req_host, deadline=eff_deadline)
                    except Exception:
                        pass

                # 8. Timeouts clamped to remaining AuditDeadline
                if eff_deadline:
                    c_conn, c_req = eff_deadline.child_timeout_tuple(CONNECT_TIMEOUT, REQUEST_TIMEOUT)
                    if eff_deadline.expired() or eff_deadline.remaining() <= 0.001:
                        route.abort("timedout")
                        return
                    hop_timeout = (c_conn, c_req)
                else:
                    hop_timeout = (CONNECT_TIMEOUT, REQUEST_TIMEOUT)

                # 9. Controlled Secure Fetch with DNS-Pinned Transport
                fwd_headers = {}
                for hk, hv in req.headers.items():
                    if hk.lower() not in ("host", "connection", "content-length", "accept-encoding"):
                        fwd_headers[hk] = hv

                try:
                    fetch_res = _safe_fetch_with_redirects(
                        session=self._session,
                        method=method,
                        url=req_url,
                        headers=fwd_headers,
                        pin_manager=self._pin_manager,
                        allow_private_ips=(self._allow_private_ips and not (self._block_private_subrequests and req_url != url)),
                        block_private_redirects=True,
                        max_redirects=max(1, MAX_BROWSER_REDIRECTS - chain_len),
                        limiter=self._limiter,
                        timeout=hop_timeout,
                        stream=False,
                        deadline=eff_deadline,
                    )
                except Exception as exc:
                    logger.debug("Browser route fetch error for %s: %s", req_url, exc)
                    route.abort("failed")
                    return

                if fetch_res.is_ssrf_blocked:
                    logger.warning("SSRF blocked browser fetch for %s: %s", req_url, fetch_res.error)
                    ssrf_abort_events.append((fetch_res.final_url or req_url, fetch_res.error or "SSRF blocked"))
                    route.abort("accessdenied")
                    return

                if fetch_res.is_too_many_redirects:
                    redirect_abort_events.append((req_url, len(fetch_res.redirect_chain)))
                    route.abort("failed")
                    return

                if fetch_res.is_timeout:
                    route.abort("timedout")
                    return

                if fetch_res.response is None:
                    route.abort("failed")
                    return

                resp = fetch_res.response

                # Clean response headers for browser fulfillment (strip hop-by-hop & compression)
                clean_headers = {}
                for k, v in resp.headers.items():
                    if k.lower() in ("content-encoding", "transfer-encoding", "connection", "keep-alive"):
                        continue
                    clean_headers[k] = v

                raw_body = resp.content or b""
                if len(raw_body) > MAX_RESPONSE_BYTES:
                    raw_body = raw_body[:MAX_RESPONSE_BYTES]
                clean_headers["content-length"] = str(len(raw_body))

                try:
                    route.fulfill(
                        status=resp.status_code,
                        headers=clean_headers,
                        body=raw_body,
                    )
                except Exception as fulfill_exc:
                    logger.debug("Failed to fulfill route for %s: %s", req_url, fulfill_exc)
                    route.abort("failed")

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
                    cl = resp.headers.get("content-length")
                    if cl:
                        try:
                            size = int(cl)
                            entry["size"] = size
                            if size > MAX_RESPONSE_BYTES:
                                entry["oversized"] = True
                        except ValueError:
                            pass

            def on_request_finished(req):
                entry = req_entry_map.get(req)
                if entry is not None:
                    try:
                        t = req.timing
                        if t:
                            entry["timing"] = t
                    except Exception:
                        pass

            def on_request_failed(req):
                entry = req_entry_map.get(req)
                if entry is not None:
                    entry["status"] = 0

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfinished", on_request_finished)
            page.on("requestfailed", on_request_failed)

            # Observe LCP if supported by browser; neutralize WebSockets and Service Workers
            try:
                page.add_init_script("""
                    // Neutralize WebSockets in audit sandbox
                    try {
                        delete window.WebSocket;
                        window.WebSocket = class {
                            constructor() {
                                throw new Error("WebSockets are disabled in the audit sandbox.");
                            }
                        };
                    } catch (e) {}

                    // Disable Service Workers in JavaScript context
                    try {
                        if ('serviceWorker' in navigator) {
                            Object.defineProperty(navigator, 'serviceWorker', {
                                get: () => undefined,
                                configurable: false,
                            });
                        }
                    } catch (e) {}

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
            eff_nav_timeout_ms = RENDER_TIMEOUT_MS
            if eff_deadline:
                eff_nav_timeout_ms = int(eff_deadline.child_timeout(RENDER_TIMEOUT_MS / 1000.0) * 1000.0)
                if eff_nav_timeout_ms < 100:
                    result.render_error = f"Audit deadline exhausted before navigation to {url}"
                    result.render_confidence = "low"
                    result.render_state = RenderState.RENDER_FAILED
                    result.network_requests = network_requests
                    return result

            try:
                page.goto(url, timeout=eff_nav_timeout_ms, wait_until="networkidle")
            except Exception as nav_exc:
                if ssrf_abort_events:
                    viol_url, viol_reason = ssrf_abort_events[0]
                    result.render_error = f"Blocked by SSRF protection on redirect/subrequest to {viol_url}: {viol_reason}"
                    result.render_confidence = "low"
                    result.render_state = RenderState.BLOCKED
                    result.network_requests = network_requests
                    return result
                if method_abort_events:
                    viol_url, viol_method = method_abort_events[0]
                    result.render_error = f"Blocked mutating HTTP method {viol_method} in browser request to {viol_url}"
                    result.render_confidence = "low"
                    result.render_state = RenderState.BLOCKED
                    result.network_requests = network_requests
                    return result
                if redirect_abort_events:
                    viol_url, viol_hops = redirect_abort_events[0]
                    result.render_error = f"Blocked browser redirect loop ({viol_hops} hops) for {viol_url}"
                    result.render_confidence = "low"
                    result.render_state = RenderState.BLOCKED
                    result.network_requests = network_requests
                    return result
                logger.debug("networkidle timeout/error for %s: %s; falling back to domcontentloaded", url, nav_exc)
                try:
                    _ = page.content()
                except Exception:
                    eff_fallback_ms = RENDER_TIMEOUT_MS
                    if eff_deadline:
                        eff_fallback_ms = int(eff_deadline.child_timeout(RENDER_TIMEOUT_MS / 1000.0) * 1000.0)
                        if eff_fallback_ms < 100:
                            result.render_error = f"Audit deadline exhausted during navigation fallback for {url}"
                            result.render_confidence = "low"
                            result.render_state = RenderState.RENDER_FAILED
                            result.network_requests = network_requests
                            return result
                    try:
                        page.goto(url, timeout=eff_fallback_ms, wait_until="domcontentloaded")
                    except Exception as fallback_exc:
                        if ssrf_abort_events:
                            viol_url, viol_reason = ssrf_abort_events[0]
                            result.render_error = f"Blocked by SSRF protection on redirect/subrequest to {viol_url}: {viol_reason}"
                            result.render_state = RenderState.BLOCKED
                        elif method_abort_events:
                            viol_url, viol_method = method_abort_events[0]
                            result.render_error = f"Blocked mutating HTTP method {viol_method} in browser request to {viol_url}"
                            result.render_state = RenderState.BLOCKED
                        elif redirect_abort_events:
                            viol_url, viol_hops = redirect_abort_events[0]
                            result.render_error = f"Blocked browser redirect loop ({viol_hops} hops) for {viol_url}"
                            result.render_state = RenderState.BLOCKED
                        else:
                            result.render_error = f"Playwright navigation failed for {url}: {fallback_exc}"
                            result.render_state = RenderState.RENDER_FAILED
                        result.render_confidence = "low"
                        result.network_requests = network_requests
                        return result

            if wait_ms > 0:
                eff_wait_ms = wait_ms
                if eff_deadline:
                    eff_wait_ms = int(eff_deadline.child_timeout(wait_ms / 1000.0) * 1000.0)
                if eff_wait_ms > 0:
                    try:
                        page.wait_for_timeout(eff_wait_ms)
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
            result.render_state = RenderState.CONFIRMED
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
            result.render_state = RenderState.RENDER_FAILED
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
        """Shut down the Playwright browser and release owned resources."""
        with self._lock:
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
            # Close the session only if we created it (not if an external session was passed)
            if getattr(self, "_owns_session", False):
                try:
                    self._session.close()
                except Exception:
                    pass

    def set_deadline(self, deadline: Optional[AuditDeadline]) -> None:
        """Update or establish the authoritative deadline for rendering operations."""
        self.deadline = deadline
        if self._robots is not None and hasattr(self._robots, "set_deadline"):
            self._robots.set_deadline(deadline)

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


def canonicalize_url(url: str, base: Optional[str] = None) -> Optional[str]:
    """Canonicalize a URL to prevent duplicate crawl slots and inconsistent evidence.

    Handles:
    - Resolving relative URLs against base
    - Scheme & host case normalization (lowercase)
    - Default port stripping (:80 for http, :443 for https)
    - URL fragment removal (#...)
    - Empty path normalization (https://example.com -> https://example.com/)
    - Redundant slash normalization (// -> /)
    - Trailing slash normalization for non-root paths (https://example.com/about/ -> https://example.com/about)
    - Preserves query parameters without over-normalizing
    """
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    try:
        if base:
            url = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return None

        # Normalize hostname and port
        host = parsed.hostname
        if not host:
            return None
        host = host.lower()
        port = parsed.port
        if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        # Normalize path
        path = parsed.path or ""
        if not path or path == "":
            path = "/"
        else:
            # Collapse multiple redundant consecutive slashes in path
            path = re.sub(r"/+", "/", path)
            # Normalize trailing slash: root remains "/", non-root paths strip trailing slash
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")

        # Construct canonical URL, omitting fragment
        canonical = urllib.parse.urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            "",  # Strip fragment
        ))
        return canonical
    except Exception:
        return None


def normalise_url(url: str, base: str) -> Optional[str]:
    """Resolve a possibly-relative URL against a base URL and return its canonical form."""
    return canonicalize_url(url, base=base)


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


_AUTH_OR_UTILITY_PATTERNS = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|signup|sign-up|register|auth|oauth|sso|openid|"
    r"account|my-account|profile|cart|checkout|basket|order-status|"
    r"forgot-password|reset-password|password/reset|verify|session|logout)(?:[/?#]|$)",
    re.IGNORECASE,
)


def is_auth_or_utility_url(url: str, soup: Optional[BeautifulSoup] = None) -> bool:
    """Return True if the URL or DOM represents an authentication, session, or utility page.

    Such pages intentionally lack general site navigation, have minimal editorial text,
    and frequently redirect unauthenticated requests or are disallowed in robots.txt.
    """
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        if _AUTH_OR_UTILITY_PATTERNS.search(path):
            return True
        if any(term in query for term in ("openid", "signin", "login", "oauth", "redirect_to")):
            return True
        if soup is not None:
            # Check for password input or auth forms
            if soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
                return True
            if soup.find("form", attrs={"action": re.compile(r"login|signin|auth", re.I)}):
                return True
    except Exception:
        pass
    return False
