"""
test_trustworthiness.py
========================
Tests for epistemic honesty and trustworthy degradation across audit subsystems:
1. RenderState propagation & graceful degradation when renderer is unavailable or fails (no false CR-003/CR-004).
2. Robots.txt failure & malformed syntax does not masquerade as site-wide AI agent block.
3. Sitemap timeout budget does not falsely report missing sitemap (CR-006).
4. SFE and TEC do not assert absence of structured data when zero valid pages are observed.
5. TC-001 does not fire when no Organization schema exists at all.
6. TC-003 and ER-004 do not falsely record broken external/internal links when global deadline expires.
7. Orchestrator handles downstream domain crashes by setting audit_status="partial" with blocked_reason="subsystem_failure".
8. Full JSON-Schema validity is preserved under all partial and degraded execution paths.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from bs4 import BeautifulSoup
from unittest.mock import MagicMock, patch

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
    FrontierEntry,
    RenderState,
    RobotsTxtCache,
    RobotsEntry,
    RobotsState,
)
from crawl_audit import _check_cr003_cr004, _check_cr006_cr007
from sfe_audit import _check_sf001_sf002
from tec_audit import _check_tc001, _check_tc003, _check_tc004_tc006
from er_audit import _check_er001, _check_er004
from aggregate import _normalise_finding, _run_pipeline, _build_coverage
from schema_validate import validate_report


def test_render_state_enum_and_propagation():
    """Verify RenderState enum values and presence on PageResult and FrontierEntry."""
    assert RenderState.CONFIRMED.name == "CONFIRMED"
    assert RenderState.PARTIAL.name == "PARTIAL"
    assert RenderState.STATIC_ONLY.name == "STATIC_ONLY"
    assert RenderState.RENDER_UNAVAILABLE.name == "RENDER_UNAVAILABLE"
    assert RenderState.RENDER_FAILED.name == "RENDER_FAILED"
    assert RenderState.BLOCKED.name == "BLOCKED"

    pr = PageResult(url="https://example.com", render_state=RenderState.RENDER_FAILED)
    assert pr.render_state == RenderState.RENDER_FAILED

    fe = FrontierEntry("https://example.com", render_confidence="high", render_state=RenderState.STATIC_ONLY.name)
    assert fe.render_state == "STATIC_ONLY"
    assert str(fe) == "https://example.com"


def test_renderer_failure_sets_low_confidence_without_false_cr003_cr004():
    """When a renderer is provided but fails or times out (rendered_soup is None),
    CR-003 and CR-004 must NOT be reported as critical defects.
    Instead, render_confidence must be marked as low.
    """
    html = '<html><body><div id="root"></div><script src="/app.js"></script></body></html>'
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(
        url="https://example.com",
        status_code=200,
        html=html,
        soup=soup,
        render_state=RenderState.RENDER_FAILED,
        rendered_soup=None,  # Renderer failed
    )
    page_results = {"https://example.com": pr}
    mock_renderer = MagicMock()

    findings = _check_cr003_cr004(page_results, renderer=mock_renderer)

    assert findings == []
    assert pr.render_confidence == "low"


def test_robots_txt_unavailable_does_not_block_ai_agents():
    """When robots.txt fetch fails (500 or network error), robots cache must NOT
    report that all AI agents are disallowed.
    """
    cache = RobotsTxtCache(session=MagicMock(), rate_limiter=MagicMock())
    entry = RobotsEntry(state=RobotsState.UNAVAILABLE, raw="")
    cache._cache["https://example.com"] = entry

    disallowed = cache.get_disallowed_ai_agents("https://example.com")
    assert disallowed == []


def test_malformed_robots_does_not_block_all_agents():
    """When robots.txt syntax is corrupt/malformed, it must NOT falsely report
    all 14 AI crawlers as disallowed.
    """
    cache = RobotsTxtCache(session=MagicMock(), rate_limiter=MagicMock())
    raw_corrupt = "User-agent: *\nDisallow: [unclosed regex syntax (invalid]\n<<<>>>???"
    entry = RobotsEntry(state=RobotsState.ALLOWED, raw=raw_corrupt)
    cache._cache["https://example.com"] = entry

    disallowed = cache.get_disallowed_ai_agents("https://example.com")
    assert len(disallowed) < 14


def test_sitemap_timeout_does_not_falsely_report_cr006():
    """When sitemap discovery is aborted due to timeout budget exhaustion,
    CR-006 ('No XML sitemap found') must NOT be emitted.
    """
    findings = _check_cr006_cr007(
        target_url="https://example.com",
        client=MagicMock(),
        sitemap_xml="",
        sitemap_from_robots=False,
        sitemap_timeout=True,
    )
    assert not any(f["local_id"] == "CR-006" for f in findings)


def test_sfe_empty_pages_no_false_assertions():
    """When frontier has zero validly fetched pages, SFE must return empty findings
    rather than asserting that the homepage lacks Organization schema.
    """
    pr = PageResult(url="https://example.com", error="Connection reset", soup=None)
    page_results = {"https://example.com": pr}
    frontier = ["https://example.com"]

    findings, errors = _check_sf001_sf002(frontier, page_results)
    assert findings == []


def test_tec_no_org_no_false_tc001():
    """When pages are successfully fetched but contain no Organization schema,
    TC-001 ('No sameAs links in Organization schema') must NOT be emitted.
    """
    html = "<html><body><h1>Hello World</h1><p>Some plain content without schema</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url="https://example.com", status_code=200, html=html, soup=soup)
    page_results = {"https://example.com": pr}
    frontier = ["https://example.com"]
    mock_client = MagicMock(spec=HttpClient)

    findings = _check_tc001(frontier, page_results, mock_client)
    assert findings == []


def test_tec_empty_pages_no_false_tc006():
    """When no pages were successfully parsed, TC-006 ('No Organization schema found')
    must NOT be emitted.
    """
    pr = PageResult(url="https://example.com", error="Timeout", soup=None)
    page_results = {"https://example.com": pr}
    frontier = ["https://example.com"]

    findings = _check_tc004_tc006(frontier, page_results)
    assert findings == []


def test_tc003_deadline_expired_guards_false_broken_link():
    """When global deadline expires during external claim verification,
    the HEAD request failure must NOT be recorded as a broken accreditation link.
    """
    html = """<html><body>
    <p>Certified partner of <a href="https://partner.example.org/cert">Partner</a></p>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url="https://example.com", status_code=200, html=html, soup=soup)
    page_results = {"https://example.com": pr}
    frontier = ["https://example.com"]

    deadline = AuditDeadline.from_budget(1, started_at=time.monotonic() - 10)
    assert deadline.expired()

    mock_client = MagicMock(spec=HttpClient)
    mock_client._deadline = deadline
    mock_client.head.side_effect = TimeoutError("Deadline expired")

    findings = _check_tc003(frontier, page_results, mock_client, deadline=deadline)
    assert findings == []


def test_er004_deadline_expired_guards_false_broken_link():
    """When global deadline expires during internal link checking,
    incomplete checks must NOT be counted as broken internal links.
    """
    html = """<html><body>
    <a href="/page1">Page 1</a>
    <a href="/page2">Page 2</a>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url="https://example.com", status_code=200, html=html, soup=soup)
    page_results = {"https://example.com": pr}
    frontier = ["https://example.com"]

    deadline = AuditDeadline.from_budget(1, started_at=time.monotonic() - 10)
    assert deadline.expired()

    mock_client = MagicMock(spec=HttpClient)
    mock_client._deadline = deadline
    mock_client.head.side_effect = TimeoutError("Deadline expired")

    findings = _check_er004(
        frontier, page_results, mock_client, "https://example.com", deadline=deadline
    )
    assert findings == []


def test_normalise_finding_resilience():
    """Test that malformed raw findings are normalised cleanly and comply with schema."""
    # Test non-dict input
    f1 = _normalise_finding("String finding", "crawl-render-access", "https://example.com")
    assert f1["title"] == "String finding"
    assert f1["evidence"] == "String finding"
    assert f1["category"] == "crawl_render_access"

    # Test confidence calculation & clamping
    f2 = _normalise_finding(
        {
            "title": "Valid title here",
            "evidence": "Observed evidence",
            "pages_affected": 15,
            "pages_checked": 10,  # ratio > 1.0
            "source": "rendered",
        },
        "structured-fact-extraction",
        "https://example.com",
    )
    assert f2["confidence"] == 1.0
    assert f2["source"] == "rendered"

    # Invalid source is stripped
    f3 = _normalise_finding(
        {"title": "Valid title here", "evidence": "Observed evidence", "source": "bogus"},
        "trust-entity-corroboration",
        "https://example.com",
    )
    assert "source" not in f3


def test_orchestrator_subsystem_crash_graceful_degradation():
    """When a downstream domain runner throws an unhandled exception,
    aggregate._run_pipeline must:
    1. Not crash.
    2. Set audit_status="partial".
    3. Set blocked_reason="subsystem_failure".
    4. Populate coverage.notes with the error.
    5. Produce a 100% valid JSON-schema report.
    """
    mock_client = MagicMock()
    mock_client.get.return_value = PageResult(
        url="https://example.com",
        status_code=200,
        html="<html><body><h1>Test</h1></body></html>",
        soup=BeautifulSoup("<html><body><h1>Test</h1></body></html>", "html.parser"),
    )
    mock_client.robots.get_disallowed_ai_agents.return_value = []
    mock_client.robots.is_allowed.return_value = True

    # Patch crawl_audit to return minimal successful crawl
    crawl_mock_result = {
        "domain": "crawl-render-access",
        "frontier": ["https://example.com"],
        "pages_discovered": 1,
        "pages_analyzed": 1,
        "page_results": {
            "https://example.com": PageResult(
                url="https://example.com",
                status_code=200,
                html="<html><body><h1>Test</h1></body></html>",
                soup=BeautifulSoup("<html><body><h1>Test</h1></body></html>", "html.parser"),
            )
        },
        "findings": [],
        "errors": [],
        "coverage": {
            "pages_audited": 1,
            "pages_in_sitemap": None,
            "budget_limited": False,
        },
    }

    with patch("crawl_audit.run_audit", return_value=crawl_mock_result), \
         patch("sfe_audit.run_audit", side_effect=RuntimeError("Simulated SFE engine crash")):
        report = _run_pipeline(
            target_url="https://example.com",
            max_pages=5,
            timeout_s=30,
            client=mock_client,
            t_start=time.monotonic(),
        )

    assert report["audit_status"] == "partial"
    assert report["blocked_reason"] == "subsystem_failure"
    assert "structured-fact-extraction" in report["audit_status_message"]
    assert "Simulated SFE engine crash" in report["coverage"]["structured_fact_extraction"]["notes"]

    valid, errors = validate_report(report)
    assert valid, f"Report failed validation under subsystem crash: {errors}"


def test_orchestrator_timeout_budget_partial_status():
    """When domain runner is skipped due to timeout exhaustion,
    aggregate._run_pipeline must report audit_status="partial" with
    blocked_reason="timeout_budget_exhausted" and valid schema.
    """
    mock_client = MagicMock(spec=HttpClient)
    crawl_mock_result = {
        "domain": "crawl-render-access",
        "frontier": ["https://example.com"],
        "pages_discovered": 1,
        "pages_analyzed": 1,
        "page_results": {
            "https://example.com": PageResult(
                url="https://example.com",
                status_code=200,
                soup=BeautifulSoup("<html><body><h1>Test</h1></body></html>", "html.parser"),
            )
        },
        "findings": [],
        "errors": [],
    }

    # Set deadline already expired before downstream
    deadline = AuditDeadline.from_budget(1, started_at=time.monotonic() - 10)

    with patch("crawl_audit.run_audit", return_value=crawl_mock_result):
        report = _run_pipeline(
            target_url="https://example.com",
            max_pages=5,
            timeout_s=30,
            client=mock_client,
            t_start=time.monotonic(),
            deadline=deadline,
        )

    assert report["audit_status"] == "partial"
    assert report["blocked_reason"] == "timeout_budget_exhausted"

    valid, errors = validate_report(report)
    assert valid, f"Report failed validation under timeout exhaustion: {errors}"
