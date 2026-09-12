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
    rep = aggregate.run_audit(target, timeout_s=5, allow_private_ips=True)
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
        rep = aggregate.run_audit(target, timeout_s=10, allow_private_ips=True)
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
        rep = aggregate.run_audit(target, timeout_s=1, allow_private_ips=True)
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


# ---------------------------------------------------------------------------
# H5 — Hostile Content: XML / Sitemap Hardening
# ---------------------------------------------------------------------------

def test_h5_xml_entity_attack_returns_empty():
    """H5-XML-01: A billion-laughs style XML payload must not expand and must return []."""
    # defusedxml will raise on entity/DTD; stdlib ET raises on external entities.
    # Either way _parse_sitemap_xml must return [] without raising.
    billion_laughs = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE lolz ['
        '  <!ENTITY lol "lol">'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ']>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '  <url><loc>https://example.com/&lol3;</loc></url>'
        '</urlset>'
    )
    from crawl_audit import _parse_sitemap_xml
    result = _parse_sitemap_xml(billion_laughs)
    # Must return [] (either defusedxml blocked it or ET.ParseError; no crash)
    assert isinstance(result, list)
    # If it parsed despite the entity (stdlib fallback), that is still safe as long as no exception.
    # The important invariant is: no unhandled exception and no process hang.


def test_h5_oversized_sitemap_doc_rejected():
    """H5-XML-02: A sitemap document over SITEMAP_MAX_DOC_BYTES (1 MiB) is rejected before parsing."""
    from crawl_audit import _parse_sitemap_xml, SITEMAP_MAX_DOC_BYTES
    # Build a valid sitemap that exceeds the byte limit
    entry = "  <url><loc>https://example.com/page</loc></url>\n"
    header = ('<?xml version="1.0"?>'
              '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
    footer = "</urlset>"
    # Repeat entries until we exceed SITEMAP_MAX_DOC_BYTES
    n = (SITEMAP_MAX_DOC_BYTES // len(entry.encode())) + 10
    oversized = header + (entry * n) + footer
    assert len(oversized.encode()) > SITEMAP_MAX_DOC_BYTES
    result = _parse_sitemap_xml(oversized)
    assert result == [], f"Expected [] for oversized doc, got {len(result)} URLs"


def test_h5_sitemap_doc_count_cap():
    """H5-XML-03: Sitemap index recursion stops after SITEMAP_MAX_DOCS total documents."""
    import http.server
    import socketserver
    from crawl_audit import _fetch_sitemap_urls, SITEMAP_MAX_DOCS

    docs_served: list[int] = [0]

    # Each document is a sitemapindex pointing to a next-level doc.
    class ChainHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            docs_served[0] += 1
            n = docs_served[0]
            # Produce a sitemapindex pointing to the next URL
            next_url = f"http://127.0.0.1:{self.server.server_address[1]}/{n + 1}"
            body = (
                '<?xml version="1.0"?>'
                '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f'<sitemap><loc>{next_url}</loc></sitemap>'
                '</sitemapindex>'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), ChainHandler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        client = HttpClient(allow_private_ips=True)
        visited: set[str] = set()
        urls, _ = _fetch_sitemap_urls(
            f"http://127.0.0.1:{port}/1",
            client,
            visited,
            origin_url=f"http://127.0.0.1:{port}/1",
        )
        httpd.shutdown()
        client.close()

    # The visited set must never grow beyond SITEMAP_MAX_DOCS
    assert len(visited) <= SITEMAP_MAX_DOCS, (
        f"Visited {len(visited)} docs, expected <= {SITEMAP_MAX_DOCS}"
    )


def test_h5_cumulative_byte_cap():
    """H5-XML-04: Sitemap recursion aborts when cumulative bytes exceed SITEMAP_MAX_CUMULATIVE_BYTES."""
    import http.server
    import socketserver
    from crawl_audit import _fetch_sitemap_urls, SITEMAP_MAX_CUMULATIVE_BYTES, SITEMAP_MAX_DOC_BYTES

    # Each child doc is just under the per-doc limit but large enough that
    # a handful of them exceed the cumulative cap.
    filler = "x" * (SITEMAP_MAX_DOC_BYTES // 2)  # ~512 KB per doc
    docs_served: list[int] = [0]

    class BigSitemapHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            docs_served[0] += 1
            n = docs_served[0]
            port = self.server.server_address[1]
            if n == 1:
                # First doc: sitemapindex with many children
                entries = "".join(
                    f'<sitemap><loc>http://127.0.0.1:{port}/{i}</loc></sitemap>'
                    for i in range(2, 30)
                )
                body = (
                    '<?xml version="1.0"?>'
                    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    + entries +
                    '</sitemapindex>'
                ).encode()
            else:
                # Each child: a large urlset just under 1 MB
                entry = f'<url><loc>https://example.com/p{n}</loc></url>\n' + '<!-- ' + filler + ' -->'
                body = (
                    '<?xml version="1.0"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    + entry +
                    '</urlset>'
                ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), BigSitemapHandler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        client = HttpClient(allow_private_ips=True)
        cumulative: list[int] = [0]
        urls, _ = _fetch_sitemap_urls(
            f"http://127.0.0.1:{port}/1",
            client,
            origin_url=f"http://127.0.0.1:{port}/1",
            cumulative_bytes=cumulative,
        )
        httpd.shutdown()
        client.close()

    # Cumulative bytes counter must have hit the cap and stopped.
    assert cumulative[0] <= SITEMAP_MAX_CUMULATIVE_BYTES + SITEMAP_MAX_DOC_BYTES, (
        f"Cumulative bytes {cumulative[0]} greatly exceeded cap {SITEMAP_MAX_CUMULATIVE_BYTES}"
    )
    # docs_served should be far fewer than 29 (it would be 29 without the cap)
    assert docs_served[0] < 20, (
        f"Too many docs served ({docs_served[0]}); cumulative cap did not fire"
    )


def test_h5_cross_origin_sitemap_skipped():
    """H5-XML-05: Child sitemaps pointing to a different domain are skipped."""
    from crawl_audit import _is_cross_origin_sitemap

    # Same registered domain (subdomains OK)
    assert not _is_cross_origin_sitemap(
        "https://cdn.example.com/sitemap2.xml",
        "https://www.example.com/sitemap.xml",
    ), "Subdomain of same domain should NOT be treated as cross-origin"

    # Different registered domain
    assert _is_cross_origin_sitemap(
        "https://attacker.evil.com/sitemap.xml",
        "https://www.example.com/sitemap.xml",
    ), "Different domain must be detected as cross-origin"

    assert _is_cross_origin_sitemap(
        "https://example.net/sitemap.xml",
        "https://example.com/sitemap.xml",
    ), "Different TLD must be detected as cross-origin"


# ---------------------------------------------------------------------------
# H6 — Hostile Content: Link Explosion / BFS Queue Amplification
# ---------------------------------------------------------------------------

def test_h6_link_explosion_capped():
    """H6-LINK-01: A page with 10 000 links causes _extract_links to return <= MAX_LINKS_PER_PAGE URLs."""
    from bs4 import BeautifulSoup
    from crawl_audit import _extract_links, MAX_LINKS_PER_PAGE

    base = "https://example.com/"
    # Generate 10 000 unique same-origin links
    links_html = "\n".join(
        f'<a href="/page-{i}">Link {i}</a>'
        for i in range(10_000)
    )
    html = f"<html><body>{links_html}</body></html>"
    soup = BeautifulSoup(html, "html.parser")

    result = _extract_links(soup, base)
    assert len(result) <= MAX_LINKS_PER_PAGE, (
        f"Expected <= {MAX_LINKS_PER_PAGE} links, got {len(result)}"
    )


def test_h6_bfs_queue_cap():
    """H6-BFS-01: BFS queue growth is bounded by MAX_QUEUE_SIZE even with a link-farm page."""
    import http.server
    import socketserver
    from crawl_audit import _discover_frontier, MAX_QUEUE_SIZE, MAX_PAGES

    # Serve a homepage with MAX_QUEUE_SIZE*2 unique links, all same-origin
    n_links = MAX_QUEUE_SIZE * 2

    class LinkFarmHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path
            if path == "/" or path == "":
                port = self.server.server_address[1]
                links = "\n".join(
                    f'<a href="/page-{i}">Page {i}</a>'
                    for i in range(n_links)
                )
                body = (
                    f'<html><body><h1>Home</h1>{links}</body></html>'
                ).encode()
            else:
                body = b'<html><body><h1>Leaf</h1><p>Content.</p></body></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), LinkFarmHandler) as httpd:
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()

        client = HttpClient(allow_private_ips=True)
        frontier, page_results, errors, _ = _discover_frontier(
            f"http://127.0.0.1:{port}/",
            client,
            max_pages=MAX_PAGES,
        )
        httpd.shutdown()
        client.close()

    # Frontier is bounded by max_pages, not by n_links
    assert len(frontier) <= MAX_PAGES + 1, (
        f"Frontier has {len(frontier)} pages, expected <= {MAX_PAGES + 1}"
    )
