"""
test_evidence_integrity.py
===========================
Targeted tests for Phase 3 Evidence Integrity and Observation States:
1. Confirmed claim (resolving external link -> CONFIRMED, no defect).
2. Contradicted claim (404/410 broken link -> CONTRADICTED, TC-003 high).
3. No corroborating evidence (unlinked claim -> INSUFFICIENT_EVIDENCE, TC-005 medium).
4. Unreachable corroborating source (network timeout / transport error -> NOT_OBSERVABLE, TC-003 does not fire).
5. Partial render (rendered DOM observed with severe blanking -> CONFIRMED, CR-003 critical).
6. Renderer failure (renderer fails/times out -> NOT_OBSERVABLE, render_confidence="low", no false CR-003/CR-004).
7. Timeout on internal link probe (transport timeout -> NOT_OBSERVABLE, no false ER-004 broken links).
8. Insufficient source coverage (missing date -> INSUFFICIENT_EVIDENCE vs confirmed stale -> CONFIRMED).
9. Zero valid pages observed (fetch failure -> observation limitation, no fabricated SF-001).
10. EvidenceState enum integrity.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import (
    AuditDeadline,
    HttpClient,
    PageResult,
    RenderState,
    EvidenceState,
    PlaywrightRenderer,
)
from crawl_audit import _check_cr003_cr004
from sfe_audit import _check_sf001_sf002, _check_sf007_sf008
from tec_audit import _check_tc001, _check_tc003, _check_tc005
from er_audit import _check_er004


def test_evidence_state_enum_completeness():
    """Verify EvidenceState enum has the 4 required minimal evidence states."""
    assert EvidenceState.CONFIRMED.value == "CONFIRMED"
    assert EvidenceState.CONTRADICTED.value == "CONTRADICTED"
    assert EvidenceState.INSUFFICIENT_EVIDENCE.value == "INSUFFICIENT_EVIDENCE"
    assert EvidenceState.NOT_OBSERVABLE.value == "NOT_OBSERVABLE"


def test_confirmed_claim_resolves_cleanly():
    """1. Confirmed claim: External accreditation link resolves HTTP 200 OK.
    Neither TC-003 nor TC-005 must fire.
    """
    claim_link = "https://accreditation-board.org/verify/acme123"
    html = f"""<!DOCTYPE html>
    <html><body>
      <p>Certified by Example Authority. <a href="{claim_link}">Verify accreditation</a></p>
    </body></html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    mock_client.head.return_value = PageResult(url=claim_link, status_code=200)

    pr = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: pr}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    assert len(tc003_findings) == 0, f"TC-003 fired unexpectedly on confirmed link: {tc003_findings}"
    assert len(tc005_findings) == 0, f"TC-005 fired unexpectedly on confirmed link: {tc005_findings}"
    mock_client.head.assert_called_once_with(claim_link)


def test_contradicted_claim_broken_http_status():
    """2. Contradicted claim: External accreditation link returns HTTP 404.
    TC-003 must fire with severity 'high' and state CONTRADICTED.
    """
    claim_link = "https://accreditation-board.org/verify/acme123"
    html = f"""<!DOCTYPE html>
    <html><body>
      <p>Certified by Example Authority. <a href="{claim_link}">Verify accreditation</a></p>
    </body></html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    mock_client.head.return_value = PageResult(url=claim_link, status_code=404)

    pr = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: pr}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)

    assert len(tc003_findings) == 1
    f = tc003_findings[0]
    assert f["local_id"] == "TC-003"
    assert f["severity"] == "high"
    assert "[CONTRADICTED]" in f["evidence"]
    assert "404" in f["evidence"]
    assert claim_link in f["evidence"]


def test_no_corroborating_evidence_unlinked_claim():
    """3. No corroborating evidence: Claim is present without any outbound verification link.
    TC-005 fires with INSUFFICIENT_EVIDENCE (severity medium). TC-003 must NOT fire.
    """
    html = """<!DOCTYPE html>
    <html><body>
      <h1>Acme Corp</h1>
      <p>We are an authorized partner of Global Tech Systems.</p>
    </body></html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)

    pr = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: pr}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    assert len(tc003_findings) == 0, "TC-003 must not fire when claim has no link"
    assert len(tc005_findings) == 1
    f = tc005_findings[0]
    assert f["local_id"] == "TC-005"
    assert f["severity"] == "medium"
    assert "[INSUFFICIENT_EVIDENCE]" in f["evidence"]
    assert "authorized partner" in f["evidence"].lower()


def test_unreachable_corroborating_source_not_observable():
    """4. Unreachable corroborating source: External verification target experiences
    a network timeout or transport failure.
    False-positive defense: 'could not obtain corroboration' does NOT mean 'the claim is false'.
    TC-003 must NOT fire as a broken link finding.
    """
    claim_link = "https://slow-external-registry.example.org/verify/999"
    html = f"""<!DOCTYPE html>
    <html><body>
      <p>Certified by Slow External Registry. <a href="{claim_link}">Verify accreditation</a></p>
    </body></html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    # Simulate network timeout / connection error
    mock_client.head.side_effect = TimeoutError("Connection to slow-external-registry timed out after 5.0s")

    pr = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: pr}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)

    # Must NOT record as broken link / false claim
    assert len(tc003_findings) == 0, f"Unreachable host falsely reported as broken claim: {tc003_findings}"


def test_partial_render_observation():
    """5. Partial render: Post-JS rendered DOM has substantial text while raw HTML
    has almost none (CSR text blanking).
    CR-003 fires with severity 'critical' and [CONFIRMED] evidence provenance.
    """
    raw_html = '<html><body><div id="root"></div></body></html>'
    rendered_html = (
        '<html><body><div id="root"><main>'
        + ("<p>Detailed brand story and product catalog descriptions. " * 30)
        + '</main></div></body></html>'
    )

    page_url = "https://example.com"
    pr = PageResult(
        url=page_url,
        status_code=200,
        html=raw_html,
        soup=BeautifulSoup(raw_html, "html.parser"),
        rendered_html=rendered_html,
        rendered_soup=BeautifulSoup(rendered_html, "html.parser"),
    )
    mock_renderer = MagicMock(spec=PlaywrightRenderer)

    findings = _check_cr003_cr004({page_url: pr}, renderer=mock_renderer)

    assert len(findings) == 1
    f = findings[0]
    assert f["local_id"] == "CR-003"
    assert f["severity"] == "critical"
    assert "[CONFIRMED]" in f["evidence"]
    assert "static=" in f["evidence"]
    assert "rendered=" in f["evidence"]


def test_renderer_failure_not_observable():
    """6. Renderer failure: When Playwright renderer is provided but navigation fails / errors,
    render_confidence is downgraded to 'low' and CR-003 / CR-004 must NOT be falsely emitted.
    False-positive defense: 'renderer unavailable' does NOT mean 'content is missing'.
    """
    raw_html = '<html><body><div id="app"></div><script src="/bundle.js"></script></body></html>'
    page_url = "https://example.com"
    pr = PageResult(
        url=page_url,
        status_code=200,
        html=raw_html,
        soup=BeautifulSoup(raw_html, "html.parser"),
        render_error="Playwright TimeoutError: Navigation timed out after 10000ms",
    )
    mock_renderer = MagicMock(spec=PlaywrightRenderer)

    findings = _check_cr003_cr004({page_url: pr}, renderer=mock_renderer)

    assert findings == [], f"Renderer error falsely produced blanking findings: {findings}"
    assert pr.render_confidence == "low"


def test_timeout_internal_link_probe_not_observable():
    """7. Timeout on internal link probe: When probing internal links in ER-004,
    network timeouts must NOT be marked as broken internal links.
    """
    page_url = "https://example.com"
    internal_link = "https://example.com/products"
    html = f'<html><body><a href="{internal_link}">Products</a></body></html>'

    pr = PageResult(url=page_url, status_code=200, html=html, soup=BeautifulSoup(html, "html.parser"))
    page_results = {page_url: pr}
    frontier = [page_url]

    mock_client = MagicMock(spec=HttpClient)
    # Simulate timeout on internal probe
    mock_client.head.side_effect = TimeoutError("Internal link check timed out")

    findings = _check_er004(frontier, page_results, mock_client, page_url)

    assert findings == [], f"Timeout on probe was falsely marked as broken internal link: {findings}"


def test_insufficient_source_coverage_freshness():
    """8. Insufficient source coverage:
    - Pages without date metadata -> SF-007 [INSUFFICIENT_EVIDENCE] (severity low).
    - Pages with explicit date > 365 days ago -> SF-007 [CONFIRMED] (severity medium).
    """
    # 1. Test missing freshness
    html_no_date = "<html><head><title>No date page</title></head><body><p>Hello world</p></body></html>"
    frontier = ["https://example.com/p1", "https://example.com/p2"]
    prs = {
        u: PageResult(url=u, status_code=200, html=html_no_date, soup=BeautifulSoup(html_no_date, "html.parser"))
        for u in frontier
    }

    findings_no_date = _check_sf007_sf008(frontier, prs)
    f_missing = next((f for f in findings_no_date if f["title"] == "Pages missing freshness metadata"), None)
    assert f_missing is not None
    assert f_missing["severity"] == "low"
    assert "[INSUFFICIENT_EVIDENCE]" in f_missing["evidence"]

    # 2. Test confirmed stale date
    stale_date_iso = (datetime.now(timezone.utc) - timedelta(days=500)).strftime("%Y-%m-%d")
    html_stale = f"""<html><head>
      <title>Stale page</title>
      <meta name="article:modified_time" content="{stale_date_iso}">
    </head><body><p>Stale article</p></body></html>"""
    prs_stale = {
        "https://example.com/stale": PageResult(
            url="https://example.com/stale",
            status_code=200,
            html=html_stale,
            soup=BeautifulSoup(html_stale, "html.parser"),
        )
    }

    findings_stale = _check_sf007_sf008(["https://example.com/stale"], prs_stale)
    f_stale = next((f for f in findings_stale if f["title"] == "Pages with stale content metadata"), None)
    assert f_stale is not None
    assert f_stale["severity"] == "medium"
    assert "[CONFIRMED]" in f_stale["evidence"]


def test_zero_valid_pages_does_not_manufacture_missing_data():
    """9. Zero valid pages observed: When no pages could be fetched or parsed,
    SF-001/SF-002 must return an observation limitation rather than manufacturing
    missing structured data findings.
    """
    frontier = ["https://example.com"]
    page_results = {"https://example.com": PageResult(url="https://example.com", error="Connection refused")}

    findings, errors = _check_sf001_sf002(frontier, page_results)

    assert findings == [], f"Manufactured findings on uninspected pages: {findings}"
    assert len(errors) == 1
    assert "No HTML pages could be inspected" in errors[0]
