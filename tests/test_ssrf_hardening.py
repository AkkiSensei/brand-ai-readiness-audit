"""
test_ssrf_hardening.py
======================
Comprehensive security test suite for SSRF hardening in brand-ai-readiness-audit:
1. IPv4-mapped IPv6 address normalization and filtering
2. Standard IPv4/IPv6 private/loopback/link-local/unspecified filtering
3. DNS resolution fail-closed behavior
4. Multi-address DNS safety (mixed public/private resolution rejected)
5. Deterministic DNS rebinding / TOCTOU prevention with destination pinning
6. Combined redirect + rebinding protection
7. HTTPS / SNI / Host header correctness under pinned destinations
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

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

import requests
import urllib.robotparser
import http_client
from http_client import (
    HttpClient,
    RateLimiter,
    RobotsState,
    RobotsTxtCache,
    SSRFSafeHTTPAdapter,
    is_ssrf_disallowed,
    is_ip_disallowed,
    normalize_ip,
    resolve_and_validate_destination,
)
import aggregate


# ===========================================================================
# 1. IP Normalization and Matrix Tests
# ===========================================================================

@pytest.mark.parametrize(
    "ip_str,expected_disallowed",
    [
        # IPv4 Disallowed
        ("127.0.0.1", True),
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("192.168.0.1", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),
        # IPv6 Disallowed
        ("::1", True),
        ("::", True),
        ("fc00::1", True),
        ("fe80::1", True),
        # IPv4-mapped IPv6 Disallowed
        ("::ffff:127.0.0.1", True),
        ("::ffff:10.0.0.1", True),
        ("::ffff:172.16.0.1", True),
        ("::ffff:192.168.0.1", True),
        ("::ffff:169.254.169.254", True),
        ("::ffff:0.0.0.0", True),
        # Clearly Public (Allowed)
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("93.184.215.14", False),
        ("2607:f8b0:4005:805::200e", False),
        ("::ffff:8.8.8.8", False),
        ("::ffff:93.184.215.14", False),
    ],
)
def test_ip_filtering_matrix(ip_str: str, expected_disallowed: bool) -> None:
    """Validate that is_ip_disallowed and is_ssrf_disallowed strictly follow policy."""
    disallowed, reason = is_ssrf_disallowed(ip_str)
    assert disallowed is expected_disallowed, f"Expected {ip_str} disallowed={expected_disallowed}, got {disallowed} ({reason})"

    # Also test normalize_ip behavior
    ip_obj = ipaddress.ip_address(ip_str.strip("[]"))
    norm = normalize_ip(ip_obj)
    if "::ffff:" in ip_str.lower():
        assert isinstance(norm, ipaddress.IPv4Address), f"Expected IPv4Address after normalization for {ip_str}, got {type(norm)}"


# ===========================================================================
# 2. DNS Fail-Closed Behavior
# ===========================================================================

def test_dns_resolution_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS resolution errors must fail closed and report blocked/disallowed."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    disallowed, reason = is_ssrf_disallowed("nonexistent-domain-xyz-404.test")
    assert disallowed is True
    assert "DNS resolution failed" in reason


def test_dns_empty_resolution_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty address lists returned by DNS must fail closed."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    disallowed, reason = is_ssrf_disallowed("empty-dns.test")
    assert disallowed is True
    assert "returned no addresses" in reason


# ===========================================================================
# 3. Multi-Address DNS Handling
# ===========================================================================

def test_mixed_public_and_private_dns_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a host returns both public and private IP addresses, it must be rejected."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    disallowed, reason = is_ssrf_disallowed("dual-homed-adversarial.test")
    assert disallowed is True
    assert "127.0.0.1" in reason


def test_multiple_public_addresses_allowed_and_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a host returns multiple public IP addresses, all are validated and first is pinned."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    disallowed, reason, ips = resolve_and_validate_destination("multi-public.test", allow_private_ips=False)
    assert disallowed is False
    assert ips == ["93.184.215.14", "8.8.8.8"]


# ===========================================================================
# 4. Real DNS-Rebinding Integration Test (TOCTOU Attack Prevention)
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
        self.wfile.write(b"CANARY_PWNED")

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


def test_dns_rebinding_attack_prevented(canary_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 4: Real DNS-rebinding test exercising HttpClient.

    Simulates:
      Lookup #1 (Pre-flight SSRF check) -> 93.184.215.14 (public IP) -> Approved & Pinned
      Lookup #2 (Subsequent resolution) -> 127.0.0.1 (private IP)

    Asserts:
      - Canary on 127.0.0.1:{canary_server} receives 0 hits.
      - The connection does NOT connect to 127.0.0.1.
      - HttpClient either connects to the pinned public destination or fails closed.
    """
    port = canary_server
    rebind_host = "rebind-attack.test"
    resolution_count = 0

    real_getaddrinfo = socket.getaddrinfo

    def rebind_getaddrinfo(host, target_port, *args, **kwargs):
        nonlocal resolution_count
        if host == rebind_host:
            resolution_count += 1
            if resolution_count == 1:
                # First lookup: returns approved public IP
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", target_port or 80))]
            else:
                # Second and subsequent lookups: rebinding to 127.0.0.1
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", target_port or 80))]
        return real_getaddrinfo(host, target_port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebind_getaddrinfo)

    client = HttpClient(allow_private_ips=False)
    # Issue actual request through HttpClient
    result = client.get(f"http://{rebind_host}:{port}/canary", skip_robots_check=True)

    # CRITICAL ASSERTION: The canary server at 127.0.0.1:{port} MUST NOT have been accessed!
    assert CanaryHandler.hit_count == 0, "SSRF VULNERABILITY DETECTED: Canary on 127.0.0.1 was reached via DNS rebinding!"

    # Verify the request did not succeed in reaching the private destination
    if result.status_code == 200:
        assert result.html != "CANARY_PWNED", "Received canary response through DNS rebinding!"

    client.close()


# ===========================================================================
# 5. Redirect + Rebind Adversarial Test
# ===========================================================================

class RedirectToPrivateHandler(http.server.BaseHTTPRequestHandler):
    target_private_url = ""

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", RedirectToPrivateHandler.target_private_url)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


def test_redirect_to_private_is_blocked(canary_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 5: Public destination redirecting to private / mapped address is blocked."""
    canary_port = canary_server

    # Set up a redirect server on 127.0.0.1
    redirect_server = CanaryServer(("127.0.0.1", 0), RedirectToPrivateHandler)
    redir_port = redirect_server.server_address[1]
    t = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    t.start()

    try:
        # 5a. Redirect to IPv4-mapped IPv6 localhost
        RedirectToPrivateHandler.target_private_url = f"http://[::ffff:127.0.0.1]:{canary_port}/canary"

        client = HttpClient(allow_private_ips=True, block_private_redirects=True)
        res = client.get(f"http://127.0.0.1:{redir_port}/initial")
        assert "Blocked by SSRF protection" in (res.error or "")
        assert CanaryHandler.hit_count == 0, "Canary was accessed via redirect to ::ffff:127.0.0.1!"

        # 5b. Redirect to cloud metadata endpoint
        RedirectToPrivateHandler.target_private_url = "http://169.254.169.254/latest/meta-data"
        res_meta = client.get(f"http://127.0.0.1:{redir_port}/initial")
        assert "Blocked by SSRF protection" in (res_meta.error or "")

        client.close()
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()


# ===========================================================================
# 6. Real HTTPS Target Verification (SNI & Cert Correctness)
# ===========================================================================

def test_https_sni_and_cert_verification_success() -> None:
    """Phase 6: Ensure real public HTTPS connection functions with valid SNI and TLS cert validation."""
    client = HttpClient(allow_private_ips=False)
    res = client.get("https://example.com", skip_robots_check=True)
    assert res.status_code == 200
    assert res.error is None
    assert res.html is not None and "Example Domain" in res.html
    client.close()


# ===========================================================================
# 7. Aggregate Run Audit SSRF Protection
# ===========================================================================

def test_aggregate_aborts_on_mapped_ipv6_and_metadata() -> None:
    """Validate that aggregate.run_audit aborts immediately on disallowed targets."""
    # IPv4-mapped IPv6 loopback
    rep1 = aggregate.run_audit("http://[::ffff:127.0.0.1]:8080", timeout_s=5)
    assert rep1["audit_status"] == "blocked"
    assert rep1["blocked_reason"] == "ssrf_disallowed"

    # IPv4-mapped cloud metadata
    rep2 = aggregate.run_audit("http://[::ffff:169.254.169.254]", timeout_s=5)
    assert rep2["audit_status"] == "blocked"
    assert rep2["blocked_reason"] == "ssrf_disallowed"

    # Dunzo (known 127.0.0.1 sinkhole)
    rep3 = aggregate.run_audit("https://dunzo.com", timeout_s=5)
    assert rep3["audit_status"] == "blocked"
    assert rep3["blocked_reason"] == "ssrf_disallowed"


# ===========================================================================
# 8. Robots.txt Security Hardening & Fail-Closed State Model Tests
# ===========================================================================

def test_robots_cache_architectural_wiring_invariant_unadapted_session() -> None:
    """Architectural wiring invariant:
    Even when RobotsTxtCache is injected with a raw, unadapted requests.Session
    (without SSRFSafeHTTPAdapter mounted), SSRF protection in _safe_fetch_with_redirects
    must prevent requests to private/loopback/metadata destinations and fail closed.
    """
    raw_session = requests.Session()
    # Explicitly verify raw_session has no SSRFSafeHTTPAdapter
    for adapter in raw_session.adapters.values():
        assert not isinstance(adapter, SSRFSafeHTTPAdapter)

    cache = RobotsTxtCache(
        session=raw_session,
        rate_limiter=RateLimiter(interval=0.0),
        allow_private_ips=False,
    )

    # 1. Direct loopback
    state_loopback = cache.get_robots_state("http://127.0.0.1:9999/admin")
    assert state_loopback == RobotsState.BLOCKED
    assert cache.can_fetch("http://127.0.0.1:9999/admin") is False

    # 2. IPv4-mapped IPv6 loopback
    state_mapped = cache.get_robots_state("http://[::ffff:127.0.0.1]:9999/admin")
    assert state_mapped == RobotsState.BLOCKED
    assert cache.can_fetch("http://[::ffff:127.0.0.1]:9999/admin") is False

    # 3. Cloud metadata
    state_meta = cache.get_robots_state("http://169.254.169.254/latest/meta-data")
    assert state_meta == RobotsState.BLOCKED
    assert cache.can_fetch("http://169.254.169.254/latest/meta-data") is False

    # 4. Private RFC 1918 range
    state_priv = cache.get_robots_state("http://10.0.0.1/admin")
    assert state_priv == RobotsState.BLOCKED
    assert cache.can_fetch("http://10.0.0.1/admin") is False


class MockRobotsServerHandler(http.server.BaseHTTPRequestHandler):
    mode = "200_ok"
    robots_content = "User-agent: *\nDisallow: /admin\nAllow: /\n"
    redirect_target = ""
    redirect_count = 0

    def do_GET(self) -> None:
        if MockRobotsServerHandler.mode == "redirect_to_target":
            self.send_response(302)
            self.send_header("Location", MockRobotsServerHandler.redirect_target)
            self.end_headers()
        elif MockRobotsServerHandler.mode == "multi_hop":
            MockRobotsServerHandler.redirect_count += 1
            if MockRobotsServerHandler.redirect_count < 3:
                self.send_response(302)
                self.send_header("Location", f"/hop{MockRobotsServerHandler.redirect_count}")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(MockRobotsServerHandler.robots_content.encode("utf-8"))
        elif MockRobotsServerHandler.mode == "infinite_loop":
            MockRobotsServerHandler.redirect_count += 1
            self.send_response(302)
            self.send_header("Location", f"/loop_{MockRobotsServerHandler.redirect_count}")
            self.end_headers()
        elif MockRobotsServerHandler.mode == "500_server_error":
            self.send_response(500)
            self.end_headers()
        elif MockRobotsServerHandler.mode == "503_service_unavailable":
            self.send_response(503)
            self.end_headers()
        elif MockRobotsServerHandler.mode == "404_not_found":
            self.send_response(404)
            self.end_headers()
        elif MockRobotsServerHandler.mode == "410_gone":
            self.send_response(410)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(MockRobotsServerHandler.robots_content.encode("utf-8"))

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def mock_robots_server():
    server = CanaryServer(("127.0.0.1", 0), MockRobotsServerHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    MockRobotsServerHandler.mode = "200_ok"
    MockRobotsServerHandler.redirect_count = 0
    yield port
    server.shutdown()
    server.server_close()


def test_robots_redirect_to_loopback_and_private_blocked(mock_robots_server: int, canary_server: int) -> None:
    """Robots.txt redirecting to loopback, private IP, or IPv4-mapped IPv6 must be blocked with RobotsState.BLOCKED."""
    port = mock_robots_server
    canary_port = canary_server

    # 1. Redirect to loopback canary
    MockRobotsServerHandler.mode = "redirect_to_target"
    MockRobotsServerHandler.redirect_target = f"http://127.0.0.1:{canary_port}/canary"

    client = HttpClient(allow_private_ips=True, block_private_redirects=True)
    state = client.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state == RobotsState.BLOCKED
    assert client.robots.can_fetch(f"http://127.0.0.1:{port}/page") is False
    assert CanaryHandler.hit_count == 0

    # 2. Redirect to IPv4-mapped IPv6
    MockRobotsServerHandler.redirect_target = f"http://[::ffff:127.0.0.1]:{canary_port}/canary"
    client2 = HttpClient(allow_private_ips=True, block_private_redirects=True)
    state2 = client2.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state2 == RobotsState.BLOCKED
    assert client2.robots.can_fetch(f"http://127.0.0.1:{port}/page") is False
    assert CanaryHandler.hit_count == 0

    # 3. Redirect to cloud metadata
    MockRobotsServerHandler.redirect_target = "http://169.254.169.254/latest/meta-data"
    client3 = HttpClient(allow_private_ips=True, block_private_redirects=True)
    state3 = client3.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state3 == RobotsState.BLOCKED
    assert client3.robots.can_fetch(f"http://127.0.0.1:{port}/page") is False


def test_robots_5xx_disallows_and_fails_closed(mock_robots_server: int) -> None:
    """Per RFC 9309 section 2.3.1.3, 5xx server errors for robots.txt must disallow crawling."""
    port = mock_robots_server

    # 500 Internal Server Error
    MockRobotsServerHandler.mode = "500_server_error"
    client1 = HttpClient(allow_private_ips=True)
    state1 = client1.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state1 == RobotsState.DISALLOWED
    assert client1.robots.can_fetch(f"http://127.0.0.1:{port}/any-url") is False

    # 503 Service Unavailable
    MockRobotsServerHandler.mode = "503_service_unavailable"
    client2 = HttpClient(allow_private_ips=True)
    state2 = client2.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state2 == RobotsState.DISALLOWED
    assert client2.robots.can_fetch(f"http://127.0.0.1:{port}/any-url") is False


def test_robots_404_allows_unrestricted(mock_robots_server: int) -> None:
    """Per RFC 9309 section 2.3.1.2, 4xx client errors mean robots.txt does not exist; access is unrestricted."""
    port = mock_robots_server

    # 404 Not Found
    MockRobotsServerHandler.mode = "404_not_found"
    client1 = HttpClient(allow_private_ips=True)
    state1 = client1.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state1 == RobotsState.ALLOWED
    assert client1.robots.can_fetch(f"http://127.0.0.1:{port}/any-url") is True

    # 410 Gone
    MockRobotsServerHandler.mode = "410_gone"
    client2 = HttpClient(allow_private_ips=True)
    state2 = client2.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state2 == RobotsState.ALLOWED
    assert client2.robots.can_fetch(f"http://127.0.0.1:{port}/any-url") is True


def test_robots_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Transport timeouts retrieving robots.txt must fail closed (RobotsState.UNAVAILABLE)."""
    client = HttpClient(allow_private_ips=True)

    def timeout_request(*args, **kwargs):
        raise requests.exceptions.Timeout("Connection timed out")

    monkeypatch.setattr(client._session, "request", timeout_request)
    state = client.robots.get_robots_state("http://127.0.0.1:54321/test")
    assert state == RobotsState.UNAVAILABLE
    assert client.robots.can_fetch("http://127.0.0.1:54321/test") is False


def test_robots_dns_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS resolution errors on robots.txt fetch must fail closed."""
    client = HttpClient(allow_private_ips=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    state = client.robots.get_robots_state("http://unresolvable-domain-999.test/test")
    assert state in (RobotsState.BLOCKED, RobotsState.UNAVAILABLE)
    assert client.robots.can_fetch("http://unresolvable-domain-999.test/test") is False


def test_robots_malformed_parser_exception_fails_closed(mock_robots_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """Parser exceptions while parsing robots.txt must result in RobotsState.INVALID and fail closed."""
    port = mock_robots_server
    MockRobotsServerHandler.mode = "200_ok"
    MockRobotsServerHandler.robots_content = "Malformed: text: [[\x00\xff"

    def crashing_parse(self, lines):
        raise ValueError("Simulated parser crash on malformed robots content")

    monkeypatch.setattr(urllib.robotparser.RobotFileParser, "parse", crashing_parse)

    client = HttpClient(allow_private_ips=True)
    state = client.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state == RobotsState.INVALID
    assert client.robots.can_fetch(f"http://127.0.0.1:{port}/page") is False


def test_robots_multi_hop_redirects_bounded_and_validated(mock_robots_server: int) -> None:
    """Robots.txt fetch follows safe redirects up to limit, and marks loop as INVALID."""
    port = mock_robots_server

    # 1. Multi-hop (under limit) succeeds
    MockRobotsServerHandler.mode = "multi_hop"
    MockRobotsServerHandler.redirect_count = 0
    MockRobotsServerHandler.robots_content = "User-agent: *\nDisallow: /private\nAllow: /\n"

    client1 = HttpClient(allow_private_ips=True, block_private_redirects=False)
    state1 = client1.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state1 == RobotsState.ALLOWED
    assert client1.robots.can_fetch(f"http://127.0.0.1:{port}/private") is False
    assert client1.robots.can_fetch(f"http://127.0.0.1:{port}/public") is True

    # 2. Infinite redirect loop (> 5 hops) is bounded and marked INVALID
    MockRobotsServerHandler.mode = "infinite_loop"
    MockRobotsServerHandler.redirect_count = 0

    client2 = HttpClient(allow_private_ips=True, block_private_redirects=False)
    state2 = client2.robots.get_robots_state(f"http://127.0.0.1:{port}/")
    assert state2 == RobotsState.INVALID
    assert client2.robots.can_fetch(f"http://127.0.0.1:{port}/any") is False
