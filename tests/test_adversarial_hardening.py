"""
test_adversarial_hardening.py
=============================
Tests for H1-H4 adversarial site behavior hardening:
- H1: Formal audit completion status (completed, partial, blocked)
- H2: WAF / bot-challenge discrimination (critical WAF vs high generic 4xx/5xx)
- H3: Geolocation and pincode gating detection in CR-005
- H4: Bounded HTTP timeout behavior against blackhole connections
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from bs4 import BeautifulSoup

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import HttpClient, PageResult
from crawl_audit import _check_cr002, _check_cr005
import aggregate


def test_h1_ssrf_blocked_status():
    """H1: SSRF-blocked target produces audit_status='blocked' with reason='ssrf_disallowed'."""
    rep = aggregate.run_audit("https://dunzo.com", timeout_s=5)
    assert rep["audit_status"] == "blocked"
    assert rep.get("blocked_reason") == "ssrf_disallowed"
    assert rep["pages_audited"] == 0
    assert rep["summary"]["total_findings"] == 0
    assert rep["findings"] == []


def test_h1_connection_refusal_blocked_status():
    """H1: Target that fails every request produces audit_status='blocked' with reason='connection_failed'."""
    # Find an unused port that actively refuses connections
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    target = f"http://127.0.0.1:{port}"
    rep = aggregate.run_audit(target, timeout_s=5)
    assert rep["audit_status"] == "blocked"
    assert rep.get("blocked_reason") == "connection_failed"
    assert rep["pages_audited"] == 0
    assert rep["summary"]["total_findings"] == 0
    assert rep["findings"] == []


def test_h1_normal_working_completed_status():
    """H1: Reachable target produces audit_status='completed' with pages_audited >= 1."""
    import http.server
    import socketserver

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><body><h1>Reachable Page</h1><p>Sample substantive text for testing.</p></body></html>")

        def log_message(self, format, *args):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        target = f"http://127.0.0.1:{port}/"
        rep = aggregate.run_audit(target, timeout_s=10)
        httpd.shutdown()

    assert rep["audit_status"] == "completed"
    assert "blocked_reason" not in rep
    assert rep["pages_audited"] >= 1


def test_h1_partial_status_reachable():
    """H1 / R3: When timeout budget is reached before downstream checks finish, audit_status='partial'."""
    import http.server
    import socketserver

    class SlowHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.4)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><body><h1>Slow Page</h1><p>Substantive text content.</p></body></html>")

        def log_message(self, format, *args):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), SlowHandler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        target = f"http://127.0.0.1:{port}/"
        # timeout_s=1 allows crawl to complete (~0.4s) but exhausts budget before downstream checks
        rep = aggregate.run_audit(target, timeout_s=1)
        httpd.shutdown()

    assert rep["audit_status"] == "partial"
    assert rep.get("blocked_reason") == "timeout_budget_exhausted"
    assert rep["pages_audited"] >= 1
    assert "timeout budget" in rep.get("audit_status_message", "").lower()


def test_h2_waf_bot_challenge_detection():
    """H2: 403 with WAF challenge signatures emits CR-002 as critical."""
    waf_html = """<html>
    <head><title>Access Denied</title></head>
    <body>
      <h1>Access Denied</h1>
      <p>Reference #18.24f43717.1789018094.d0bf2fb</p>
      <p>https://errors.edgesuite.net/</p>
    </body>
    </html>"""

    pr = PageResult(
        url="https://example.com/catalog",
        status_code=403,
        response_headers={"server": "CloudFront", "x-rate-limit": "SignalNonBrowserUserAgent"},
        html=waf_html,
        soup=BeautifulSoup(waf_html, "html.parser"),
    )

    findings = _check_cr002({"https://example.com/catalog": pr})
    assert len(findings) == 1
    f = findings[0]
    assert f["local_id"] == "CR-002"
    assert f["severity"] == "critical"
    assert f["title"] == "WAF / anti-bot challenge blocking crawler access"
    assert "CloudFront automated bot detection" in f["evidence"] or "Akamai" in f["evidence"]


def test_h2_generic_error_not_waf():
    """H2: Generic 404 or 403 without WAF signatures emits CR-002 as high, not critical."""
    pr_404 = PageResult(
        url="https://example.com/missing-page",
        status_code=404,
        response_headers={"server": "nginx"},
        html="<html><body><h1>404 Not Found</h1></body></html>",
        soup=BeautifulSoup("<html><body><h1>404 Not Found</h1></body></html>", "html.parser"),
    )

    findings = _check_cr002({"https://example.com/missing-page": pr_404})
    assert len(findings) == 1
    f = findings[0]
    assert f["local_id"] == "CR-002"
    assert f["severity"] == "high"
    assert f["title"] == "Pages returning non-OK HTTP status codes"


def test_h3_geolocation_gate_detection():
    """H3: Page requiring location/pincode selection emits CR-005 with location gate title."""
    geo_html = """<!DOCTYPE html>
    <html>
    <head><title>Quick Commerce Store</title></head>
    <body>
      <div id="root">
        <div class="location-modal-container">
          <h2>Select Location</h2>
          <p>Please enter your delivery location or pincode to view catalog items.</p>
          <input type="text" placeholder="Enter Pincode">
        </div>
      </div>
    </body>
    </html>"""

    pr = PageResult(
        url="https://example.com",
        status_code=200,
        html=geo_html,
        soup=BeautifulSoup(geo_html, "html.parser"),
    )

    findings = _check_cr005({"https://example.com": pr})
    assert len(findings) == 1
    f = findings[0]
    assert f["local_id"] == "CR-005"
    assert f["severity"] == "high"
    assert f["title"] == "Geolocation or location-selection gate blocking catalog content"
    assert "enforce geolocation or pincode selection" in f["evidence"]


def test_h4_network_timeout_bounded():
    """H4: A TCP blackhole request terminates at the single-request timeout bound (~8s), not compounding into 26s."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)

    def blackhole():
        try:
            conn, _ = s.accept()
            time.sleep(12)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=blackhole, daemon=True)
    t.start()

    client = HttpClient(allow_private_ips=True)
    t0 = time.monotonic()
    res = client.get(f"http://127.0.0.1:{port}/", skip_robots_check=True)
    elapsed = time.monotonic() - t0

    client.close()
    s.close()

    assert res.status_code is None
    assert "timed out" in (res.error or "").lower()
    # Must terminate near request timeout (~8.0s), strictly under 10.0s, never compounding into 20s+
    assert elapsed < 10.0, f"Hang exceeded bound: took {elapsed:.2f}s"
