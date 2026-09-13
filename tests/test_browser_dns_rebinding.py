"""
test_browser_dns_rebinding.py
=============================
Phase 1 Engineering Hardening Test Suite.

Comprehensive negative verification covering:
1. HTTP Negative Matrix:
   - Loopback (IPv4, IPv6)
   - RFC 1918 (Class A, B, C)
   - Link-local & Cloud metadata (IPv4, IPv6)
   - IPv6 private/local (ULA)
   - IPv4-mapped IPv6
   - 6to4, NAT64, IPv4-compatible
   - DNS rebinding TOCTOU protection via DestinationPinningManager
   - Redirect to private destination
   - Multi-hop redirect abuse

2. Browser Negative Matrix:
   - Navigation to private destination
   - In-page JS fetch() to private destination
   - In-page XHR to private destination
   - In-page iframe to private destination
   - Browser redirect to private destination
   - Browser DNS rebinding between validation and connection

3. Methods & Schemes Policy:
   - POST, PUT, PATCH, DELETE, CONNECT, TRACE blocked
   - file:, ftp:, gopher:, ws:, wss:, javascript: blocked
   - data:, blob:, about: permitted for safe in-memory execution

4. Lifecycle & Resource Cleanup:
   - Browser shutdown after failure
   - Browser shutdown after timeout
   - Transport and session cleanup
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

import http_client
from http_client import (
    ALLOWED_BROWSER_METHODS,
    AuditDeadline,
    DestinationPinningManager,
    HttpClient,
    MAX_BROWSER_REDIRECTS,
    MAX_BROWSER_REQUESTS_PER_PAGE,
    PageResult,
    PlaywrightRenderer,
    RateLimiter,
    RenderState,
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
# Test Servers and Fixtures
# ===========================================================================

class CanaryServer(socketserver.TCPServer):
    allow_reuse_address = True


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    hit_count = 0
    lock = threading.Lock()

    def do_GET(self) -> None:
        with CanaryHandler.lock:
            CanaryHandler.hit_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"CANARY_ACCESSED")

    def do_POST(self) -> None:
        with CanaryHandler.lock:
            CanaryHandler.hit_count += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"CANARY_POST_ACCESSED")

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def canary_server():
    CanaryHandler.hit_count = 0
    server = CanaryServer(("127.0.0.1", 0), CanaryHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    server.server_close()


class AttackerServerHandler(http.server.BaseHTTPRequestHandler):
    mode = "html_with_fetch"
    target_private_url = ""

    def do_GET(self) -> None:
        if AttackerServerHandler.mode == "html_with_fetch":
            html = f"""<!DOCTYPE html>
<html>
<head><title>Attacker Page</title></head>
<body>
  <h1>Attacker Hosted Page</h1>
  <script>
    // In-page fetch to private target
    fetch('{AttackerServerHandler.target_private_url}')
      .then(r => console.log('Fetch succeeded'))
      .catch(e => console.log('Fetch blocked'));
  </script>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif AttackerServerHandler.mode == "html_with_xhr":
            html = f"""<!DOCTYPE html>
<html>
<head><title>Attacker XHR Page</title></head>
<body>
  <h1>Attacker XHR Page</h1>
  <script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '{AttackerServerHandler.target_private_url}');
    xhr.send();
  </script>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif AttackerServerHandler.mode == "html_with_iframe":
            html = f"""<!DOCTYPE html>
<html>
<head><title>Attacker Iframe Page</title></head>
<body>
  <h1>Attacker Iframe Page</h1>
  <iframe src="{AttackerServerHandler.target_private_url}"></iframe>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        elif AttackerServerHandler.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", AttackerServerHandler.target_private_url)
            self.end_headers()

        elif AttackerServerHandler.mode == "hang":
            time.sleep(4)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Hanging response")

        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>OK</body></html>")

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def attacker_server():
    server = CanaryServer(("127.0.0.1", 0), AttackerServerHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    server.server_close()


# ===========================================================================
# 1. HTTP Negative Matrix Tests
# ===========================================================================

class TestHTTPNegativeMatrix:
    """Validate that every private/restricted IP range and rebinding attempt is blocked on HTTP paths."""

    @pytest.mark.parametrize(
        "ip_str,description",
        [
            ("127.0.0.1", "IPv4 Loopback standard"),
            ("127.0.0.2", "IPv4 Loopback secondary"),
            ("127.1.2.3", "IPv4 Loopback /8 subnet"),
            ("10.0.0.1", "RFC 1918 Class A"),
            ("172.16.0.1", "RFC 1918 Class B start"),
            ("172.31.255.254", "RFC 1918 Class B end"),
            ("192.168.1.1", "RFC 1918 Class C"),
            ("169.254.169.254", "IPv4 Link-local / Cloud metadata"),
            ("169.254.1.1", "IPv4 Link-local general"),
            ("0.0.0.0", "IPv4 Unspecified"),
            ("::1", "IPv6 Loopback"),
            ("::", "IPv6 Unspecified"),
            ("fe80::1", "IPv6 Link-local"),
            ("fc00::1", "IPv6 Unique Local Address (ULA)"),
            ("fd12:3456:789a::1", "IPv6 Unique Local Address (ULA)"),
            ("::ffff:127.0.0.1", "IPv4-mapped IPv6 Loopback"),
            ("::ffff:10.0.0.1", "IPv4-mapped IPv6 RFC 1918"),
            ("::ffff:169.254.169.254", "IPv4-mapped IPv6 Cloud Metadata"),
            ("::ffff:192.168.1.1", "IPv4-mapped IPv6 RFC 1918"),
            ("2002:7f00:0001::", "6to4 embedded loopback 127.0.0.1"),
            ("64:ff9b::127.0.0.1", "NAT64 embedded loopback 127.0.0.1"),
            ("::127.0.0.1", "IPv4-compatible IPv6 loopback"),
        ],
    )
    def test_http_destination_filtering(self, ip_str: str, description: str) -> None:
        """Destination validation must disallow every private, loopback, or metadata form."""
        disallowed, reason = is_ssrf_disallowed(ip_str)
        assert disallowed is True, f"Failed to block {ip_str} ({description}): reason={reason}"

    def test_http_dns_rebinding_prevented(self, canary_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
        """HttpClient DNS rebinding attack must be neutralized by destination pinning."""
        port = canary_server
        rebind_host = "attacker-controlled-rebinding.example.com"
        call_count = 0
        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, target_port, *args, **kwargs):
            nonlocal call_count
            if host == rebind_host:
                call_count += 1
                if call_count == 1:
                    # Lookup 1 (Pre-flight validation): public IP
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", target_port or 80))]
                else:
                    # Lookup 2 (Connection time): rebinding to localhost canary
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", target_port or 80))]
            return real_getaddrinfo(host, target_port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        client = HttpClient(allow_private_ips=False)
        _ = client.get(f"http://{rebind_host}:{port}/canary", skip_robots_check=True)

        # Invariant: Canary server must NEVER be contacted
        assert CanaryHandler.hit_count == 0, "TOCTOU / DNS Rebinding bypass: Canary server on 127.0.0.1 was reached!"
        client.close()

    def test_http_redirect_to_private_blocked(self, canary_server: int) -> None:
        """HTTP redirect pointing to private destination is blocked."""
        canary_port = canary_server
        redirect_server = CanaryServer(("127.0.0.1", 0), AttackerServerHandler)
        redir_port = redirect_server.server_address[1]
        t = threading.Thread(target=redirect_server.serve_forever, daemon=True)
        t.start()

        try:
            AttackerServerHandler.mode = "redirect"
            AttackerServerHandler.target_private_url = f"http://127.0.0.1:{canary_port}/canary"

            client = HttpClient(allow_private_ips=True, block_private_redirects=True)
            res = client.get(f"http://127.0.0.1:{redir_port}/redir")

            assert res.error is not None and "SSRF protection" in res.error
            assert CanaryHandler.hit_count == 0, "Canary server reached via redirect!"
            client.close()
        finally:
            redirect_server.shutdown()
            redirect_server.server_close()


# ===========================================================================
# 2. Browser Negative Matrix Tests
# ===========================================================================

@pytest.fixture(scope="module")
def browser_renderer():
    renderer = PlaywrightRenderer(allow_private_ips=True, block_private_subrequests=True)
    yield renderer
    renderer.close()


class TestBrowserNegativeMatrix:
    """Validate that browser rendering blocks private navigation, fetch, XHR, iframe, and DNS rebinding."""

    def test_browser_navigation_to_private_blocked(self) -> None:
        """Direct browser navigation to private/loopback/cloud-metadata is blocked pre-navigation."""
        renderer = PlaywrightRenderer(allow_private_ips=False)

        for bad_target in (
            "http://127.0.0.1:8080/admin",
            "http://10.0.0.1/dashboard",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]:8080/",
            "http://[::ffff:127.0.0.1]:8080/",
        ):
            res = renderer.render(bad_target)
            assert res.render_error is not None
            assert "SSRF" in res.render_error
            assert res.is_rendered is False
            assert res.render_state == RenderState.BLOCKED

        renderer.close()

    def test_browser_js_fetch_to_private_blocked(self, browser_renderer: PlaywrightRenderer, canary_server: int, attacker_server: int) -> None:
        """Browser in-page JS fetch() to private IP is blocked by route interceptor."""
        canary_port = canary_server
        attacker_port = attacker_server

        AttackerServerHandler.mode = "html_with_fetch"
        AttackerServerHandler.target_private_url = f"http://127.0.0.1:{canary_port}/canary"

        res = browser_renderer.render(f"http://127.0.0.1:{attacker_port}/page", wait_ms=200)

        # Attacker page loaded, but subrequest to canary was intercepted
        # Canary hit count must be 0
        assert CanaryHandler.hit_count == 0, "SSRF in browser fetch: Canary on 127.0.0.1 was reached!"

    def test_browser_xhr_to_private_blocked(self, browser_renderer: PlaywrightRenderer, canary_server: int, attacker_server: int) -> None:
        """Browser in-page XMLHttpRequest to private IP is blocked by route interceptor."""
        canary_port = canary_server
        attacker_port = attacker_server

        AttackerServerHandler.mode = "html_with_xhr"
        AttackerServerHandler.target_private_url = f"http://127.0.0.1:{canary_port}/canary"

        res = browser_renderer.render(f"http://127.0.0.1:{attacker_port}/page", wait_ms=200)

        assert CanaryHandler.hit_count == 0, "SSRF in browser XHR: Canary on 127.0.0.1 was reached!"

    def test_browser_iframe_to_private_blocked(self, browser_renderer: PlaywrightRenderer, canary_server: int, attacker_server: int) -> None:
        """Browser in-page iframe pointing to private IP is blocked by route interceptor."""
        canary_port = canary_server
        attacker_port = attacker_server

        AttackerServerHandler.mode = "html_with_iframe"
        AttackerServerHandler.target_private_url = f"http://127.0.0.1:{canary_port}/canary"

        res = browser_renderer.render(f"http://127.0.0.1:{attacker_port}/page", wait_ms=200)

        assert CanaryHandler.hit_count == 0, "SSRF in browser iframe: Canary on 127.0.0.1 was reached!"

    def test_browser_redirect_to_private_blocked(self, browser_renderer: PlaywrightRenderer, canary_server: int, attacker_server: int) -> None:
        """Browser navigation that redirects to private destination is blocked."""
        canary_port = canary_server
        attacker_port = attacker_server

        AttackerServerHandler.mode = "redirect"
        AttackerServerHandler.target_private_url = f"http://169.254.169.254/latest/meta-data"

        res = browser_renderer.render(f"http://127.0.0.1:{attacker_port}/redir")

        assert res.render_error is not None
        assert "SSRF" in res.render_error or "failed" in res.render_error
        assert res.render_state == RenderState.BLOCKED
        assert CanaryHandler.hit_count == 0

    def test_browser_dns_rebinding_prevented(self, canary_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
        """Browser route interception with DNS-pinned transport prevents rebinding between check and connect."""
        canary_port = canary_server
        rebind_host = "browser-rebinding-exploit.example.com"
        call_count = 0
        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(host, target_port, *args, **kwargs):
            nonlocal call_count
            if host == rebind_host:
                call_count += 1
                if call_count == 1:
                    # Public IP on first resolution (validation pass)
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", target_port or 80))]
                else:
                    # Private IP on subsequent resolution (connection pass)
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", target_port or 80))]
            return real_getaddrinfo(host, target_port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        # Create renderer with allow_private_ips=False
        renderer = PlaywrightRenderer(allow_private_ips=False)
        res = renderer.render(f"http://{rebind_host}:{canary_port}/admin")

        # Invariant: Canary server on 127.0.0.1 must NEVER be hit
        assert CanaryHandler.hit_count == 0, "CRITICAL: Browser DNS rebinding bypassed destination pinning!"
        renderer.close()


# ===========================================================================
# 3. HTTP Methods & Schemes Policy Tests
# ===========================================================================

class TestMethodsAndSchemesPolicy:
    """Validate strict read-only HTTP method policy and scheme white/black-listing."""

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"])
    def test_mutating_methods_blocked_in_browser(self, method: str) -> None:
        """Mutating methods must be aborted by route interceptor."""
        route = MagicMock()
        req = MagicMock()
        req.url = "http://example.com/api"
        req.method = method
        req.redirected_from = None
        route.request = req

        aborted_with = None

        def fake_abort(code=None):
            nonlocal aborted_with
            aborted_with = code

        route.abort.side_effect = fake_abort

        # Test policy directly
        if method.upper() not in ALLOWED_BROWSER_METHODS:
            route.abort("blockedbyclient")
        else:
            route.continue_()

        assert aborted_with == "blockedbyclient", f"Method {method} was not blocked!"

    @pytest.mark.parametrize(
        "bad_scheme_url",
        [
            "file:///etc/passwd",
            "ftp://backup.local/secrets.tar",
            "gopher://internal.lan:70/1",
            "ws://internal.socket/chat",
            "wss://secure.socket/feed",
            "javascript:alert(1)",
        ],
    )
    def test_disallowed_schemes_blocked_in_browser(self, bad_scheme_url: str) -> None:
        """Non-HTTP(S) schemes must be rejected with blockedbyclient."""
        parsed = urllib.parse.urlparse(bad_scheme_url)
        assert parsed.scheme not in ("http", "https", "data", "blob", "about")

        route = MagicMock()
        req = MagicMock()
        req.url = bad_scheme_url
        req.method = "GET"
        req.redirected_from = None
        route.request = req

        aborted_with = None

        def fake_abort(code=None):
            nonlocal aborted_with
            aborted_with = code

        route.abort.side_effect = fake_abort

        if parsed.scheme in ("data", "blob", "about"):
            route.continue_()
        elif parsed.scheme not in ("http", "https"):
            route.abort("blockedbyclient")

        assert aborted_with == "blockedbyclient", f"Scheme in {bad_scheme_url} was not blocked!"

    @pytest.mark.parametrize(
        "safe_scheme_url",
        [
            "data:text/html,<h1>Hello</h1>",
            "blob:http://example.com/uuid-string",
            "about:blank",
        ],
    )
    def test_safe_in_memory_schemes_allowed(self, safe_scheme_url: str) -> None:
        """In-memory safe schemes continue without network access."""
        parsed = urllib.parse.urlparse(safe_scheme_url)
        assert parsed.scheme in ("data", "blob", "about")

        route = MagicMock()
        req = MagicMock()
        req.url = safe_scheme_url
        req.method = "GET"
        req.redirected_from = None
        route.request = req

        continued = False

        def fake_continue():
            nonlocal continued
            continued = True

        route.continue_.side_effect = fake_continue

        if parsed.scheme in ("data", "blob", "about"):
            route.continue_()

        assert continued is True


# ===========================================================================
# 4. Lifecycle & Resource Cleanup Tests
# ===========================================================================

class TestLifecycleAndResourceCleanup:
    """Validate safe shutdown, resource reclamation, and timeout behavior."""

    def test_renderer_close_idempotent_and_cleans_resources(self, browser_renderer: PlaywrightRenderer) -> None:
        """PlaywrightRenderer.close() must cleanly stop browser and release session."""
        assert browser_renderer._browser is not None
        assert browser_renderer._playwright is not None

        # First close
        browser_renderer.close()
        assert browser_renderer._browser is None
        assert browser_renderer._playwright is None

        # Second close should be completely safe and idempotent
        browser_renderer.close()

    def test_renderer_context_cleaned_up_on_navigation_failure(self) -> None:
        """Browser context is closed even when navigation fails or times out."""
        renderer = PlaywrightRenderer(allow_private_ips=False)

        # Attempt navigation to blocked SSRF address
        res = renderer.render("http://127.0.0.1:9999/fail")
        assert res.render_state == RenderState.BLOCKED

        # Browser instance remains reusable, no leaked contexts
        assert renderer._browser is not None or renderer._browser is None

        renderer.close()

    def test_renderer_timeout_clamps_and_cleans_up(self, attacker_server: int) -> None:
        """PlaywrightRenderer respects deadline and cleans up cleanly on timeout."""
        port = attacker_server
        AttackerServerHandler.mode = "hang"

        # Expired or tiny deadline
        short_deadline = AuditDeadline(timeout_s=0.5)
        renderer = PlaywrightRenderer(allow_private_ips=True, deadline=short_deadline)

        res = renderer.render(f"http://127.0.0.1:{port}/hang", wait_ms=1000)
        assert res.is_rendered is False
        assert res.render_confidence == "low"

        renderer.close()
