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

import json
import logging
import re
import threading
import time
import urllib.parse
import urllib.robotparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
        "Accept-Encoding": "gzip, deflate, br",
    },
)
KNOWN_AI_CRAWLERS: list[str] = _ROBOTS_CFG.get(
    "known_ai_crawlers",
    ["GPTBot", "ChatGPT-User", "Google-Extended", "CCBot", "anthropic-ai"],
)
PLAYWRIGHT_WAIT_MS: int = int(_RENDER_CFG.get("playwright_wait_ms", 3000))
PLAYWRIGHT_TIMEOUT_MS: int = int(_RENDER_CFG.get("playwright_timeout_ms", 15000))
PLAYWRIGHT_VIEWPORT: dict = {
    "width": int(_RENDER_CFG.get("playwright_viewport_width", 1280)),
    "height": int(_RENDER_CFG.get("playwright_viewport_height", 800)),
}


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
        with self._lock:
            now = time.monotonic()
            last = self._last_request.get(host, 0.0)
            gap = self._interval - (now - last)
            if gap > 0:
                time.sleep(gap)
            self._last_request[host] = time.monotonic()


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

    def __init__(self, session: requests.Session, rate_limiter: RateLimiter) -> None:
        self._session = session
        self._limiter = rate_limiter
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

    def __init__(self, rate_limit_secs: float = RATE_LIMIT_SECS) -> None:
        self._limiter = RateLimiter(interval=rate_limit_secs)
        self._session = self._build_session()
        self.robots = RobotsTxtCache(self._session, self._limiter)

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT, **DEFAULT_HEADERS})
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=RETRY_BACKOFF,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
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
    ) -> PageResult:
        """Perform a rate-limited, robots-compliant HTTP GET.

        Args:
            url: The absolute URL to fetch.
            skip_robots_check: If True, bypass robots.txt verification.
            stream: If True, stream the response (for large files).

        Returns:
            PageResult populated with response data or an error string.
        """
        result = PageResult(url=url)

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

        # --- HTTP GET ---
        t0 = time.monotonic()
        try:
            resp = self._session.get(
                url,
                timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
                allow_redirects=True,
                stream=stream,
            )
            result.fetch_duration_seconds = time.monotonic() - t0
            result.status_code = resp.status_code
            result.url = resp.url  # final URL after redirects
            result.redirect_chain = [r.url for r in resp.history]
            result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
            content_type_full = resp.headers.get("Content-Type", "")
            result.content_type = content_type_full.split(";")[0].strip().lower()

            # Read body with size cap
            if stream:
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=65536):
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        break
                    chunks.append(chunk)
                raw_bytes = b"".join(chunks)
            else:
                raw_bytes = resp.content[:MAX_RESPONSE_BYTES]

            # Decode
            encoding = resp.encoding or "utf-8"
            try:
                result.html = raw_bytes.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                result.html = raw_bytes.decode("utf-8", errors="replace")

            # Parse HTML
            if result.content_type in (
                "text/html",
                "application/xhtml+xml",
                "text/xml",
                "application/xml",
            ) or result.content_type.startswith("text/"):
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
            result.error = f"Connection error for {url}: {exc}"
            logger.warning(result.error)
        except Exception as exc:
            result.fetch_duration_seconds = time.monotonic() - t0
            result.error = f"Unexpected error fetching {url}: {exc}"
            logger.exception(result.error)

        return result

    def head(self, url: str) -> PageResult:
        """Perform a lightweight HTTP HEAD request (no body, no robots check).

        Returns:
            PageResult with status_code and headers populated.
        """
        result = PageResult(url=url)
        try:
            self._limiter.wait(self._host(url))
            t0 = time.monotonic()
            resp = self._session.head(
                url,
                timeout=(CONNECT_TIMEOUT, REQUEST_TIMEOUT),
                allow_redirects=True,
            )
            result.fetch_duration_seconds = time.monotonic() - t0
            result.status_code = resp.status_code
            result.url = resp.url
            result.redirect_chain = [r.url for r in resp.history]
            result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
            content_type_full = resp.headers.get("Content-Type", "")
            result.content_type = content_type_full.split(";")[0].strip().lower()
        except requests.exceptions.Timeout as exc:
            result.error = f"HEAD timeout for {url}: {exc}"
        except requests.exceptions.ConnectionError as exc:
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

    Usage:
        with PlaywrightRenderer() as renderer:
            result = renderer.render("https://example.com")
    """

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._available = self._check_availability()

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
        """Lazily launch the Playwright browser."""
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

    def render(self, url: str, wait_ms: int = PLAYWRIGHT_WAIT_MS) -> PageResult:
        """Render a page with Playwright and return the post-JS DOM.

        Args:
            url: The absolute URL to render.
            wait_ms: Milliseconds to wait after page load for JS execution.

        Returns:
            PageResult with rendered_html and rendered_soup populated on success.
        """
        result = PageResult(url=url)
        if not self._available:
            result.error = "Playwright not installed; render skipped."
            return result

        try:
            self._ensure_browser()
            context = self._browser.new_context(
                viewport=PLAYWRIGHT_VIEWPORT,
                user_agent=USER_AGENT,
            )
            page = context.new_page()
            try:
                page.goto(url, timeout=PLAYWRIGHT_TIMEOUT_MS, wait_until="networkidle")
            except Exception:
                # Fallback: wait for domcontentloaded instead
                try:
                    page.goto(
                        url,
                        timeout=PLAYWRIGHT_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                except Exception as exc:
                    result.error = f"Playwright navigation failed for {url}: {exc}"
                    context.close()
                    return result

            if wait_ms > 0:
                try:
                    page.wait_for_timeout(wait_ms)
                except Exception:
                    pass

            result.rendered_html = page.content()
            result.is_rendered = True
            result.rendered_soup = _safe_parse_html(result.rendered_html)

            # Capture HTTP-level info via response interception if available
            try:
                result.status_code = 200  # Playwright doesn't easily expose final status
            except Exception:
                pass

            context.close()

        except Exception as exc:
            result.error = f"Playwright render error for {url}: {exc}"
            logger.warning(result.error)

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
    """Compute ratio of visible text length to total HTML length.

    Returns a float in [0.0, 1.0]. Lower values suggest heavy JS rendering
    or content trapped in non-text elements.
    """
    try:
        html_len = len(str(soup))
        if html_len == 0:
            return 0.0
        # Strip script/style/noscript
        working = BeautifulSoup(str(soup), "html.parser")
        for tag in working.find_all(["script", "style", "noscript", "meta", "link"]):
            tag.decompose()
        text = working.get_text(separator=" ", strip=True)
        return min(len(text) / html_len, 1.0)
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
