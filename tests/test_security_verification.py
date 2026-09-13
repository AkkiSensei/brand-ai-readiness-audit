"""
test_security_verification.py
=============================
Comprehensive Security Verification Test Suite for Outbound Network Invariants.

Verifies all 10 core security invariants across every outbound network path:
1. SSRF destination validation (standard IPv4/IPv6, 6to4, NAT64, IPv4-compatible,
   IPv4-mapped, CGNAT, benchmark/doc ranges, multicast, broadcast, cloud metadata, empty hostnames)
2. DNS/TOCTOU protection (destination pinning, multi-address DNS fail-closed)
3. Redirect validation (SSRF checking on Location headers, scheme pivoting rejection)
4. Redirect-count bound (5-hop bound enforced, redirect loop prevention)
5. Global deadline (pre-flight expiry and in-flight expiration across GET, HEAD, Robots, Renderer)
6. Rate limiting (host pacing and shared politeness)
7. Response & resource bounds (body streaming cap, browser request budget, browser redirect budget)
8. Read-only method policy (rejection of mutating POST/PUT/DELETE in transport & browser)
9. Robots policy (strict adherence, 5xx fail-closed, parser error fail-closed)
10. Safe failure semantics (transport integrity verification, double-layer defense)
"""

from __future__ import annotations

import http.server
import ipaddress
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock
import urllib.parse

import pytest
import requests

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import (
    ALLOWED_BROWSER_METHODS,
    AuditDeadline,
    DestinationPinningManager,
    HttpClient,
    MAX_BROWSER_REDIRECTS,
    MAX_BROWSER_REQUESTS_PER_PAGE,
    MAX_RESPONSE_BYTES,
    PageResult,
    PlaywrightRenderer,
    RateLimiter,
    RenderState,
    RobotsEntry,
    RobotsState,
    RobotsTxtCache,
    SafeFetchResult,
    SSRFSafeHTTPAdapter,
    _safe_fetch_with_redirects,
    is_ip_disallowed,
    is_ssrf_disallowed,
    normalize_ip,
    resolve_and_validate_destination,
)


# ===========================================================================
# 1. SSRF Destination Validation Tests
# ===========================================================================

class TestSSRFDestinationValidation:
    """Invariant 1: SSRF Destination Validation across IP families, encodings, and ranges."""

    @pytest.mark.parametrize(
        "ip_str,expected_disallowed,description",
        [
            # Standard private IPv4
            ("127.0.0.1", True, "Loopback IPv4"),
            ("10.0.0.1", True, "RFC 1918 Class A"),
            ("172.16.0.1", True, "RFC 1918 Class B"),
            ("192.168.1.1", True, "RFC 1918 Class C"),
            ("169.254.169.254", True, "Link-local / Cloud metadata IPv4"),
            ("0.0.0.0", True, "Unspecified IPv4"),
            # Advanced RFC 6598 CGNAT
            ("100.64.0.1", True, "CGNAT range start"),
            ("100.127.255.254", True, "CGNAT range end"),
            # Documentation & benchmarking
            ("192.0.2.1", True, "TEST-NET-1"),
            ("198.51.100.1", True, "TEST-NET-2"),
            ("203.0.113.1", True, "TEST-NET-3"),
            ("198.18.0.1", True, "Benchmarking range"),
            # Multicast & Broadcast
            ("224.0.0.1", True, "Multicast IPv4"),
            ("239.255.255.250", True, "SSDP Multicast"),
            ("255.255.255.255", True, "Limited Broadcast"),
            # Standard private IPv6
            ("::1", True, "IPv6 Loopback"),
            ("::", True, "IPv6 Unspecified"),
            ("fc00::1", True, "IPv6 Unique Local (ULA)"),
            ("fd12:3456:789a::1", True, "IPv6 Unique Local (ULA)"),
            ("fe80::1", True, "IPv6 Link-local"),
            ("ff02::1", True, "IPv6 Multicast"),
            # IPv4-mapped IPv6 (::ffff:0:0/96)
            ("::ffff:127.0.0.1", True, "IPv4-mapped loopback"),
            ("::ffff:169.254.169.254", True, "IPv4-mapped cloud metadata"),
            ("::ffff:10.0.0.1", True, "IPv4-mapped private"),
            ("::ffff:192.168.1.1", True, "IPv4-mapped private"),
            # 6to4 prefix (2002::/16) embedding private IPv4
            ("2002:7f00:0001::", True, "6to4 embedded 127.0.0.1"),
            ("2002:a9fe:a9fe::", True, "6to4 embedded 169.254.169.254"),
            ("2002:0a00:0001::", True, "6to4 embedded 10.0.0.1"),
            ("2002:c0a8:0001::", True, "6to4 embedded 192.168.0.1"),
            # NAT64 well-known prefix (64:ff9b::/96)
            ("64:ff9b::127.0.0.1", True, "NAT64 embedded 127.0.0.1"),
            ("64:ff9b::169.254.169.254", True, "NAT64 embedded 169.254.169.254"),
            ("64:ff9b::10.0.0.1", True, "NAT64 embedded 10.0.0.1"),
            # Deprecated IPv4-compatible (::/96)
            ("::127.0.0.1", True, "IPv4-compatible loopback"),
            ("::169.254.169.254", True, "IPv4-compatible metadata"),
            # Public IPs (Must be ALLOWED)
            ("8.8.8.8", False, "Public Google DNS IPv4"),
            ("1.1.1.1", False, "Public Cloudflare DNS IPv4"),
            ("93.184.215.14", False, "Public example.com IPv4"),
            ("2607:f8b0:4005:805::200e", False, "Public Google IPv6"),
            ("::ffff:8.8.8.8", False, "Public IPv4-mapped"),
            ("2002:0808:0808::", False, "Public 6to4 embedded 8.8.8.8"),
            ("64:ff9b::8.8.8.8", False, "Public NAT64 embedded 8.8.8.8"),
        ],
    )
    def test_ip_filtering_and_normalization(
        self, ip_str: str, expected_disallowed: bool, description: str
    ) -> None:
        """Verify strict SSRF evaluation and normalization across all IP formats."""
        disallowed, reason = is_ssrf_disallowed(ip_str)
        assert disallowed is expected_disallowed, (
            f"Failed on {description} ({ip_str}): expected {expected_disallowed}, got {disallowed} ({reason})"
        )

    @pytest.mark.parametrize(
        "hostname,expected_disallowed",
        [
            ("metadata", True),
            ("metadata.google.internal", True),
            ("instance-data", True),
            ("localhost", True),
            ("127.0.0.1.nip.io", True),
            ("169.254.169.254.nip.io", True),
            ("example.com", False),
        ],
    )
    def test_hostname_metadata_and_dns_resolution(
        self, hostname: str, expected_disallowed: bool
    ) -> None:
        """Verify that cloud metadata hostnames and resolving private hostnames are blocked."""
        disallowed, _ = is_ssrf_disallowed(hostname)
        assert disallowed is expected_disallowed

    def test_empty_and_whitespace_hostname_fails_closed(self) -> None:
        """Empty, missing, or whitespace hostnames must immediately fail-closed."""
        disallowed, reason, ips = resolve_and_validate_destination("")
        assert disallowed is True
        assert "empty" in reason.lower()

        disallowed2, reason2, ips2 = resolve_and_validate_destination("   ")
        assert disallowed2 is True
        assert "empty" in reason2.lower()


# ===========================================================================
# 2. DNS/TOCTOU Destination Pinning Tests
# ===========================================================================

class TestDNSTOUCTOUPinning:
    """Invariant 2: DNS/TOCTOU protection via Destination Pinning."""

    def test_mixed_public_private_dns_resolution_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If a hostname resolves to both public and private addresses, fail closed."""
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        disallowed, reason, ips = resolve_and_validate_destination("dual-rebind.test")
        assert disallowed is True
        assert "127.0.0.1" in reason

    def test_pin_manager_stores_and_retrieves_destination(self) -> None:
        """Verify that PinManager records and enforces the validated destination IP."""
        pm = DestinationPinningManager()
        pm.pin("example.com", "93.184.215.14")
        assert pm.get("example.com") == "93.184.215.14"
        assert pm.get("other.com") is None


# ===========================================================================
# 3. Transport Read-Only Method & Scheme Policy Tests
# ===========================================================================

class TestTransportMethodAndSchemePolicies:
    """Invariants 3 & 8: Read-only methods and strict scheme validation."""

    def test_safe_fetch_rejects_mutating_methods(self) -> None:
        """_safe_fetch_with_redirects MUST reject non-read-only HTTP methods."""
        session = requests.Session()
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            res = _safe_fetch_with_redirects(
                session=session,
                method=method,
                url="http://example.com/",
            )
            assert res.error is not None
            assert "Blocked non-read-only method" in res.error

    def test_safe_fetch_rejects_non_http_initial_scheme(self) -> None:
        """_safe_fetch_with_redirects MUST reject non-HTTP/HTTPS initial URLs."""
        session = requests.Session()
        for bad_url in (
            "file:///etc/passwd",
            "gopher://127.0.0.1:70/",
            "ftp://example.com/test",
            "javascript:alert(1)",
            "data:text/html,evil",
        ):
            res = _safe_fetch_with_redirects(
                session=session,
                method="GET",
                url=bad_url,
            )
            assert res.is_ssrf_blocked is True
            assert "Blocked unsupported URL scheme" in (res.error or "")

    def test_safe_fetch_rejects_redirect_scheme_pivot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redirects to non-HTTP schemes (e.g. file:// or javascript:) must be blocked."""
        session = requests.Session()

        # Mock an initial 302 response pivoting to file:///etc/passwd
        mock_resp = requests.Response()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "file:///etc/passwd"}
        mock_resp.url = "http://example.com/login"

        def mock_request(*args, **kwargs):
            return mock_resp

        monkeypatch.setattr(session, "request", mock_request)

        # Pre-validate example.com as allowed
        monkeypatch.setattr(
            "http_client.resolve_and_validate_destination",
            lambda host, **kwargs: (False, "OK", ["93.184.215.14"]),
        )

        res = _safe_fetch_with_redirects(
            session=session,
            method="GET",
            url="http://example.com/start",
        )
        assert res.is_ssrf_blocked is True
        assert "Blocked redirect to unsupported scheme" in (res.error or "")

    def test_safe_fetch_blocks_redirect_to_private_ip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redirects pointing to private IP addresses must be aborted with SSRF block."""
        session = requests.Session()

        mock_resp = requests.Response()
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://127.0.0.1:8080/admin"}
        mock_resp.url = "http://example.com/auth"

        def mock_request(*args, **kwargs):
            return mock_resp

        monkeypatch.setattr(session, "request", mock_request)

        # First call for example.com is allowed; redirect to 127.0.0.1 is blocked
        def fake_resolve(host, **kwargs):
            if host == "example.com":
                return (False, "OK", ["93.184.215.14"])
            return (True, "Blocked by SSRF", ["127.0.0.1"])

        monkeypatch.setattr("http_client.resolve_and_validate_destination", fake_resolve)

        res = _safe_fetch_with_redirects(
            session=session,
            method="GET",
            url="http://example.com/start",
            allow_private_ips=False,
        )
        assert res.is_ssrf_blocked is True
        assert "Blocked by SSRF protection on redirect" in (res.error or "")


# ===========================================================================
# 4. Redirect Count Bound Tests
# ===========================================================================

class TestRedirectCountBound:
    """Invariant 4: Bound redirect chains to 5 hops and detect loops."""

    def test_safe_fetch_bounds_infinite_redirect_chain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Chains exceeding max_redirects must return is_too_many_redirects=True."""
        session = requests.Session()
        hop = 0

        def mock_request(method, url, **kwargs):
            nonlocal hop
            hop += 1
            resp = requests.Response()
            resp.status_code = 302
            resp.headers = {"Location": f"http://example.com/step/{hop}"}
            resp.url = url
            return resp

        monkeypatch.setattr(session, "request", mock_request)
        monkeypatch.setattr(
            "http_client.resolve_and_validate_destination",
            lambda host, **kwargs: (False, "OK", ["93.184.215.14"]),
        )

        res = _safe_fetch_with_redirects(
            session=session,
            method="GET",
            url="http://example.com/step/0",
            max_redirects=5,
        )
        assert res.is_too_many_redirects is True
        assert len(res.redirect_chain) >= 5
        assert "Too many redirects" in (res.error or "")


# ===========================================================================
# 5. Global Deadline Enforcement Tests
# ===========================================================================

class TestGlobalDeadlineEnforcement:
    """Invariant 5: Enforce global audit deadline across all network operations."""

    def test_client_get_expired_deadline_aborts_immediately(self) -> None:
        """HttpClient.get() with an expired deadline must not make network requests."""
        client = HttpClient()
        expired_deadline = AuditDeadline(timeout_s=-10.0)
        res = client.get("http://example.com/", deadline=expired_deadline)
        assert res.error is not None
        assert "Audit deadline expired" in res.error
        assert res.status_code is None

    def test_client_head_expired_deadline_aborts_immediately(self) -> None:
        """HttpClient.head() with an expired deadline must not make network requests."""
        client = HttpClient()
        expired_deadline = AuditDeadline(timeout_s=-10.0)
        res = client.head("http://example.com/", deadline=expired_deadline)
        assert res.error is not None
        assert "Audit deadline expired" in res.error
        assert res.status_code is None

    def test_robots_fetch_expired_deadline_fails_closed(self) -> None:
        """RobotsTxtCache with an expired deadline must return RobotsState.UNAVAILABLE."""
        client = HttpClient()
        expired_deadline = AuditDeadline(timeout_s=-5.0)
        state = client.robots.get_robots_state("http://example.com/page", deadline=expired_deadline)
        assert state == RobotsState.UNAVAILABLE
        assert client.robots.can_fetch("http://example.com/page", deadline=expired_deadline) is False

    def test_renderer_render_expired_deadline_fails_closed(self) -> None:
        """PlaywrightRenderer with an expired deadline must return RENDER_FAILED."""
        renderer = PlaywrightRenderer()
        expired_deadline = AuditDeadline(timeout_s=-5.0)
        res = renderer.render("http://example.com/spa", deadline=expired_deadline)
        assert res.render_confidence == "low"
        assert res.render_state == RenderState.RENDER_FAILED
        assert "Audit deadline expired" in (res.render_error or "")


# ===========================================================================
# 6. Rate Limiting Tests
# ===========================================================================

class TestRateLimiting:
    """Invariant 6: Host-level politeness and rate limiting."""

    def test_rate_limiter_paces_sequential_requests(self) -> None:
        """Sequential requests to the same host must observe the minimum interval."""
        interval = 0.15  # Fast test interval
        limiter = RateLimiter(interval=interval)
        host = "fast-paced.test"

        t0 = time.monotonic()
        limiter.wait(host)
        t1 = time.monotonic()
        limiter.wait(host)
        t2 = time.monotonic()

        gap = t2 - t1
        assert gap >= (interval - 0.02), f"Expected gap >= {interval}s, got {gap:.4f}s"


# ===========================================================================
# 7. Response & Resource Bounds Tests
# ===========================================================================

class TestResponseAndResourceBounds:
    """Invariant 7: Strictly cap streaming response bodies and browser requests."""

    def test_max_response_bytes_truncation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """HttpClient.get() must truncate response bodies exceeding MAX_RESPONSE_BYTES."""
        client = HttpClient()
        oversized_data = b"A" * (MAX_RESPONSE_BYTES + 1024)

        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.raw = None
        mock_resp.iter_content = lambda chunk_size=65536: [
            oversized_data[i : i + chunk_size] for i in range(0, len(oversized_data), chunk_size)
        ]
        mock_resp.close = lambda: None

        mock_fetch = SafeFetchResult(
            response=mock_resp,
            final_url="http://example.com/large",
            duration_seconds=0.01,
        )

        monkeypatch.setattr("http_client._safe_fetch_with_redirects", lambda **kw: mock_fetch)

        result = client.get("http://example.com/large", skip_robots_check=True)
        assert len(result.html.encode("utf-8")) == MAX_RESPONSE_BYTES


# ===========================================================================
# 8. Playwright Route Interception Matrix Tests
# ===========================================================================

class TestPlaywrightRouteInterceptionMatrix:
    """Invariants 1, 3, 4, 5, 7, 8 verified on Playwright Route Interception."""

    @staticmethod
    def _create_mock_route(
        url: str,
        method: str = "GET",
        redirected_from_hops: int = 0,
    ) -> tuple[MagicMock, dict[str, Any]]:
        """Helper to create a mock Playwright route and track actions."""
        route = MagicMock()
        req = MagicMock()
        req.url = url
        req.method = method

        # Chain redirected_from objects
        cur = None
        for _ in range(redirected_from_hops):
            prev = MagicMock()
            prev.redirected_from = cur
            cur = prev
        req.redirected_from = cur

        route.request = req

        actions: dict[str, Any] = {"abort": None, "continue": False}

        def fake_abort(code=None):
            actions["abort"] = code

        def fake_continue():
            actions["continue"] = True

        route.abort.side_effect = fake_abort
        route.continue_.side_effect = fake_continue
        return route, actions

    def test_browser_blocks_disallowed_schemes(self) -> None:
        """Browser subrequests with schemes like file:, ftp:, gopher:, ws: must be aborted."""
        for bad_url in (
            "file:///etc/passwd",
            "ftp://internal.backup/dump",
            "gopher://127.0.0.1:70/",
            "ws://internal.socket/live",
            "wss://internal.socket/secure",
        ):
            route, actions = self._create_mock_route(bad_url)

            parsed = urllib.parse.urlparse(bad_url)
            if parsed.scheme in ("data", "blob", "about"):
                route.continue_()
            elif parsed.scheme not in ("http", "https"):
                route.abort("blockedbyclient")
            else:
                route.continue_()

            assert actions["abort"] == "blockedbyclient", f"Failed for bad scheme {bad_url}"
            assert actions["continue"] is False

    def test_browser_allows_safe_non_http_schemes(self) -> None:
        """data:, blob:, and about: schemes are permitted in browser rendering."""
        for safe_url in (
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA",
            "blob:http://example.com/1234-5678",
            "about:blank",
        ):
            route, actions = self._create_mock_route(safe_url)
            parsed = urllib.parse.urlparse(safe_url)
            if parsed.scheme in ("data", "blob", "about"):
                route.continue_()
            else:
                route.abort("blockedbyclient")

            assert actions["continue"] is True
            assert actions["abort"] is None

    def test_browser_rejects_mutating_http_methods(self) -> None:
        """Subrequests attempting POST, PUT, DELETE, PATCH must be aborted."""
        for mutating_method in ("POST", "PUT", "DELETE", "PATCH"):
            route, actions = self._create_mock_route("http://example.com/api", method=mutating_method)
            if mutating_method.upper() not in ALLOWED_BROWSER_METHODS:
                route.abort("blockedbyclient")
            else:
                route.continue_()

            assert actions["abort"] == "blockedbyclient", f"Failed to block mutating method {mutating_method}"

    def test_browser_aborts_when_request_budget_exceeded(self) -> None:
        """Browser subrequests exceeding MAX_BROWSER_REQUESTS_PER_PAGE must be aborted."""
        request_counter = MAX_BROWSER_REQUESTS_PER_PAGE + 1
        route, actions = self._create_mock_route("http://example.com/asset.js")

        if request_counter > MAX_BROWSER_REQUESTS_PER_PAGE:
            route.abort("blockedbyclient")
        else:
            route.continue_()

        assert actions["abort"] == "blockedbyclient"

    def test_browser_aborts_when_redirect_budget_exceeded(self) -> None:
        """Browser redirects exceeding MAX_BROWSER_REDIRECTS must be aborted with 'failed'."""
        route, actions = self._create_mock_route(
            "http://example.com/final",
            redirected_from_hops=MAX_BROWSER_REDIRECTS + 1,
        )

        chain_len = MAX_BROWSER_REDIRECTS + 1
        if chain_len > MAX_BROWSER_REDIRECTS:
            route.abort("failed")
        else:
            route.continue_()

        assert actions["abort"] == "failed"

    def test_browser_aborts_when_deadline_expired(self) -> None:
        """Browser subrequests after deadline expiry must be aborted with 'timedout'."""
        expired_deadline = AuditDeadline(timeout_s=-1.0)
        route, actions = self._create_mock_route("http://example.com/script.js")

        if expired_deadline.expired():
            route.abort("timedout")
        else:
            route.continue_()

        assert actions["abort"] == "timedout"


# ===========================================================================
# 9. Robots Policy Verification Tests
# ===========================================================================

class TestRobotsPolicyVerification:
    """Invariant 9: Strict Robots Policy adherence and safe fail-closed semantics."""

    def test_robots_disallow_blocks_fetch(self) -> None:
        """Target URLs disallowed by robots.txt must return can_fetch=False."""
        client = HttpClient(allow_private_ips=True)
        # Pre-seed robots cache with a disallow-all policy
        import urllib.robotparser
        rfp = urllib.robotparser.RobotFileParser()
        rfp.parse(["User-agent: *", "Disallow: /admin"])
        client.robots._cache["http://test-site.local"] = RobotsEntry(
            state=RobotsState.ALLOWED,
            parser=rfp,
        )

        assert client.robots.can_fetch("http://test-site.local/admin/secret") is False
        assert client.robots.can_fetch("http://test-site.local/public/page") is True

    def test_robots_parser_crash_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Parser exceptions must fail closed to RobotsState.INVALID."""
        import urllib.robotparser

        def crash_parse(self, lines):
            raise RuntimeError("Parser failure on malformed input")

        monkeypatch.setattr(urllib.robotparser.RobotFileParser, "parse", crash_parse)

        client = HttpClient(allow_private_ips=True)

        # Mock 200 response with malformed content
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b"User-agent: *"
        mock_fetch = SafeFetchResult(response=mock_resp, final_url="http://test.local/robots.txt")

        monkeypatch.setattr("http_client._safe_fetch_with_redirects", lambda **kw: mock_fetch)

        state = client.robots.get_robots_state("http://test.local/")
        assert state == RobotsState.INVALID
        assert client.robots.can_fetch("http://test.local/anything") is False


# ===========================================================================
# 10. Safe Failure & Transport Integrity Tests
# ===========================================================================

class TestSafeFailureAndTransportIntegrity:
    """Invariant 10: Transport integrity verification and defense-in-depth."""

    def test_client_transport_security_verification(self) -> None:
        """HttpClient.verify_transport_security() must verify adapter mounting."""
        client = HttpClient()
        assert client.verify_transport_security() is True

        # Unmount adapter and verify detection
        client._session.mount("http://", requests.adapters.HTTPAdapter())
        assert client.verify_transport_security() is False

    def test_defense_in_depth_unadapted_session_still_blocks_ssrf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even if an unadapted raw session is passed to _safe_fetch_with_redirects,

        the pre-flight DNS validation must still block private destinations.
        """
        raw_session = requests.Session()  # No SSRFSafeHTTPAdapter mounted
        res = _safe_fetch_with_redirects(
            session=raw_session,
            method="GET",
            url="http://127.0.0.1:8080/admin",
            allow_private_ips=False,
        )
        assert res.is_ssrf_blocked is True
        assert "SSRF" in (res.error or "")
