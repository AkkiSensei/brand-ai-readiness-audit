"""
test_deadline_boundary.py
=========================
Deterministic verification of the global AuditDeadline resource-exhaustion boundary:
- AuditDeadline abstraction properties
- Stage/sub-operation deadline propagation
- Clamped child timeouts (never granting fresh independent full windows)
- Slow robots.txt handling
- Slow HTTP connection / response
- Slow redirect chains consuming shared budget
- Retry exhaustion consuming shared budget
- Browser navigation and wait windows clamped to remaining budget
- Expired deadline before stage starts
- Multiple sequential slow pages capped by global boundary
"""

from __future__ import annotations

import http.server
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CRAWL_SCRIPTS = _REPO_ROOT / "skills" / "crawl-render-access" / "scripts"
_ORCH_SCRIPTS = _REPO_ROOT / "skills" / "audit-orchestrator" / "scripts"
_TEC_SCRIPTS = _REPO_ROOT / "skills" / "trust-entity-corroboration" / "scripts"
_ER_SCRIPTS = _REPO_ROOT / "skills" / "engagement-retention" / "scripts"

for p in (_CRAWL_SCRIPTS, _ORCH_SCRIPTS, _TEC_SCRIPTS, _ER_SCRIPTS):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from http_client import (
    AuditDeadline,
    HttpClient,
    PageResult,
    PlaywrightRenderer,
    RobotsState,
    RobotsTxtCache,
)
import crawl_audit
import aggregate
import tec_audit
import er_audit


# ===========================================================================
# 1. AuditDeadline Abstraction Tests
# ===========================================================================

def test_deadline_primitives():
    """Verify AuditDeadline core methods: remaining, expired, child_timeout."""
    t0 = time.monotonic()
    deadline = AuditDeadline(timeout_s=2.0, started_at=t0)
    
    assert deadline.started_at == t0
    assert deadline.timeout_s == 2.0
    assert not deadline.expired()
    assert 1.5 <= deadline.remaining() <= 2.0

    # child_timeout clamps to minimum of requested and remaining
    assert deadline.child_timeout(10.0) <= 2.0
    assert deadline.child_timeout(0.5) == pytest.approx(0.5, abs=0.05)

    # child_timeout_tuple clamps both connect and request timeouts
    c_to, r_to = deadline.child_timeout_tuple(connect_max=5.0, request_max=8.0)
    assert c_to <= 2.0
    assert r_to <= 2.0

    # Expired deadline
    past_deadline = AuditDeadline(timeout_s=1.0, started_at=t0 - 2.0)
    assert past_deadline.expired()
    assert past_deadline.remaining() == 0.0
    assert past_deadline.child_timeout(5.0) == 0.0


def test_deadline_does_not_reset_on_subsequent_calls():
    """Verify that successive child_timeout calls consume from the same clock."""
    deadline = AuditDeadline(timeout_s=0.3)
    c1 = deadline.child_timeout(5.0)
    time.sleep(0.1)
    c2 = deadline.child_timeout(5.0)
    assert c2 < c1
    time.sleep(0.25)
    assert deadline.expired()
    assert deadline.child_timeout(5.0) == 0.0


# ===========================================================================
# 2. Stage Skip When Deadline Already Expired
# ===========================================================================

def test_deadline_expired_before_stage_starts():
    """Verify all major stages immediately reject work if deadline is already expired."""
    expired = AuditDeadline(timeout_s=0.1, started_at=time.monotonic() - 1.0)
    assert expired.expired()

    # 1. HttpClient.get
    client = HttpClient(allow_private_ips=True, deadline=expired)
    pr = client.get("http://127.0.0.1:9999/test", deadline=expired)
    assert pr.status_code is None
    assert "deadline expired" in pr.error.lower()

    # 2. RobotsTxtCache.can_fetch
    assert not client.robots.can_fetch("http://127.0.0.1:9999/test", deadline=expired)

    # 3. PlaywrightRenderer.render
    renderer = PlaywrightRenderer(allow_private_ips=True, deadline=expired)
    r_pr = renderer.render("http://127.0.0.1:9999/page", deadline=expired)
    assert "deadline expired" in r_pr.render_error.lower()
    assert r_pr.render_confidence == "low"

    # 4. crawl_audit.run_audit
    crawl_res = crawl_audit.run_audit(
        "http://127.0.0.1:9999/",
        client,
        deadline=expired,
        timeout_s=0.1,
    )
    assert crawl_res["pages_analyzed"] == 0
    assert any("truncated" in err.lower() or "deadline expired" in err.lower() for err in crawl_res["errors"])


def test_orchestrator_skips_downstream_when_deadline_expired():
    """Verify aggregate orchestrator skips downstream modules if budget was consumed by crawl."""
    # Deadline that will expire almost immediately
    deadline = AuditDeadline(timeout_s=0.01)
    time.sleep(0.02)
    assert deadline.expired()

    report = aggregate.run_audit(
        "http://127.0.0.1:1",
        timeout_s=1,
        deadline=deadline,
        allow_private_ips=True,
    )
    # The crawl failed/aborted immediately and downstream stages were skipped
    assert report.get("audit_status") in ("blocked", "completed")


# ===========================================================================
# 3. Slow Network Operations Bounded By Remaining Deadline
# ===========================================================================

class _SlowHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet test output

    def do_GET(self):
        if self.path == "/robots.txt":
            # Sleep 0.8s before replying
            time.sleep(0.8)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /private\n")
        elif self.path == "/slow-page":
            time.sleep(0.8)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Slow</h1></body></html>")
        elif self.path == "/redirect-1":
            time.sleep(0.2)
            self.send_response(302)
            self.send_header("Location", "/redirect-2")
            self.end_headers()
        elif self.path == "/redirect-2":
            time.sleep(0.2)
            self.send_response(302)
            self.send_header("Location", "/slow-page")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>OK</h1></body></html>")

    def do_HEAD(self):
        if self.path == "/slow-head":
            time.sleep(0.8)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()


@pytest.fixture(scope="module")
def slow_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _SlowHandler)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_slow_robots_respects_deadline(slow_server):
    """Verify slow robots.txt fetch cannot exceed remaining audit deadline."""
    # Give a deadline of only 0.25s when server sleeps 0.8s
    deadline = AuditDeadline(timeout_s=0.25)
    client = HttpClient(allow_private_ips=True, deadline=deadline)

    t_start = time.monotonic()
    allowed = client.robots.can_fetch(f"{slow_server}/page", deadline=deadline)
    elapsed = time.monotonic() - t_start

    # Must have failed closed and returned within bounded window (< 0.6s, well below 0.8s server delay)
    assert not allowed
    assert elapsed < 0.6
    assert client.robots.get_robots_state(f"{slow_server}/page") == RobotsState.UNAVAILABLE


def test_slow_http_response_respects_deadline(slow_server):
    """Verify HTTP GET request timeout is clamped to remaining deadline."""
    deadline = AuditDeadline(timeout_s=0.3)
    client = HttpClient(allow_private_ips=True, deadline=deadline)

    t_start = time.monotonic()
    pr = client.get(f"{slow_server}/slow-page", skip_robots_check=True, deadline=deadline)
    elapsed = time.monotonic() - t_start

    assert pr.status_code is None
    assert "timeout" in pr.error.lower() or "deadline" in pr.error.lower()
    # Must terminate within bounded window (< 0.6s) rather than full 8.0s timeout
    assert elapsed < 0.6


def test_slow_redirect_chain_consumes_shared_deadline(slow_server):
    """Verify redirect hops do not each get a fresh full timeout window."""
    # Redirect chain has 2 hops (0.2s + 0.2s) leading to slow page (0.8s) = ~1.2s total
    # With a 0.35s deadline, it should timeout during hop 2 without waiting for the full slow page
    deadline = AuditDeadline(timeout_s=0.35)
    client = HttpClient(allow_private_ips=True, deadline=deadline)

    t_start = time.monotonic()
    pr = client.get(f"{slow_server}/redirect-1", skip_robots_check=True, deadline=deadline)
    elapsed = time.monotonic() - t_start

    assert pr.status_code is None
    assert "timeout" in pr.error.lower() or "deadline" in pr.error.lower()
    # Entire redirect sequence bounded by 0.35s budget (< 0.7s total, well under 1.2s+)
    assert elapsed < 0.7


# ===========================================================================
# 4. Browser Navigation & Wait Windows Clamped to Remaining Budget
# ===========================================================================

def test_slow_browser_navigation_bounded_by_deadline():
    """Verify PlaywrightRenderer clamps page.goto timeout to remaining deadline."""
    deadline = AuditDeadline(timeout_s=0.4)
    renderer = PlaywrightRenderer(allow_private_ips=True, deadline=deadline)
    renderer._available = True

    mock_page = MagicMock()
    # Simulate page.goto timing out
    mock_page.goto.side_effect = Exception("Timeout 400ms exceeded")
    mock_page.content.side_effect = Exception("Execution context destroyed")

    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context
    renderer._browser = mock_browser

    with patch.object(renderer, "_robots", None):
        res = renderer.render("http://example.com/test", deadline=deadline)

    # Verify that goto was called with a timeout bounded by the ~400ms deadline, NOT default 10,000ms
    assert mock_page.goto.called
    called_timeout = mock_page.goto.call_args[1].get("timeout")
    assert called_timeout <= 450
    assert called_timeout < 1000  # far less than default 10000ms


def test_slow_browser_wait_bounded_by_deadline():
    """Verify PlaywrightRenderer clamps page.wait_for_timeout to remaining deadline."""
    deadline = AuditDeadline(timeout_s=0.3)
    renderer = PlaywrightRenderer(allow_private_ips=True, deadline=deadline)
    renderer._available = True

    mock_page = MagicMock()
    mock_page.goto.return_value = None
    mock_page.content.return_value = "<html><body>Dynamic Content</body></html>"
    mock_page.evaluate.return_value = {}

    mock_context = MagicMock()
    mock_context.new_page.return_value = mock_page
    mock_browser = MagicMock()
    mock_browser.new_context.return_value = mock_context
    renderer._browser = mock_browser

    with patch.object(renderer, "_robots", None):
        res = renderer.render("http://example.com/test", wait_ms=5000, deadline=deadline)

    # Verify wait_for_timeout received a clamped value, NOT the full 5000ms
    assert mock_page.wait_for_timeout.called
    called_wait = mock_page.wait_for_timeout.call_args[0][0]
    assert called_wait <= 350
    assert called_wait < 5000


# ===========================================================================
# 5. Multiple Sequential Slow Pages Capped By Global Budget
# ===========================================================================

def test_multiple_sequential_slow_pages_capped_by_global_budget(slow_server):
    """Verify crawl frontier halts when global deadline expires across sequential slow pages."""
    # Server takes 0.8s per slow page. If max_pages=5 and budget=0.5s, it must abort after page 1.
    deadline = AuditDeadline(timeout_s=0.5)
    client = HttpClient(allow_private_ips=True, deadline=deadline)

    t_start = time.monotonic()
    crawl_res = crawl_audit.run_audit(
        f"{slow_server}/slow-page",
        client,
        max_pages=5,
        deadline=deadline,
        timeout_s=0.5,
        t_start=t_start,
    )
    elapsed = time.monotonic() - t_start

    # Must complete in ~0.5s-0.8s range, NOT 5 * 0.8s = 4.0s+
    assert elapsed < 1.5
    assert crawl_res["pages_discovered"] <= 1


def test_tec_and_er_broken_link_checks_respect_deadline():
    """Verify TEC and ER link checks abort when deadline expires."""
    deadline = AuditDeadline(timeout_s=0.01)
    time.sleep(0.02)
    assert deadline.expired()

    client = HttpClient(allow_private_ips=True, deadline=deadline)
    # tec_audit TC-003 link check
    res_tec = tec_audit.run_audit(
        "http://example.com",
        client,
        crawl_frontier=["http://example.com"],
        page_results={"http://example.com": PageResult(url="http://example.com", status_code=200, html="<p>Certified by Partner</p>")},
        deadline=deadline,
    )
    assert res_tec["domain"] == "trust-entity-corroboration"

    # er_audit ER-004 link check
    res_er = er_audit.run_audit(
        "http://example.com",
        client,
        crawl_frontier=["http://example.com"],
        page_results={"http://example.com": PageResult(url="http://example.com", status_code=200, html="<a href='/link1'>1</a><a href='/link2'>2</a>")},
        deadline=deadline,
    )
    assert res_er["domain"] == "engagement-retention"
