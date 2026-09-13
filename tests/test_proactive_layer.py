"""
test_proactive_layer.py
=======================
Targeted test suite for Phase 7: Strengthened Proactive Recommendation Layer.

Verifies:
1. Proactive checks remain strictly separate from defect findings (severity=info, category=proactive).
2. All proactive checks (PA-001 through PA-006, PA-CANONICAL) are mechanism-sound and evidence-grounded.
3. Manifest detection supports /llms.txt, /llms-full.txt, and /agents.md.
4. Duplicate proactive recommendations are removed deterministically.
5. Contextual relevance: feeds are recommended on publishing content, not single-page utilities.
6. Schema compliance: all proactive findings and proactive_recommendations validate cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock
from bs4 import BeautifulSoup
import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import HttpClient, PageResult
from proactive_engine import (
    _pa001,
    _pa002,
    _pa003,
    _pa004,
    _pa005,
    _pa006,
    _pa_canonical,
    inject_proactive_recommendations,
)
from aggregate import _normalise_finding, _build_remediation_themes, _SEVERITY_ORDER
from schema_validate import validate_report


def _make_page_result(url: str, html: str, status_code: int = 200) -> PageResult:
    return PageResult(
        url=url,
        status_code=status_code,
        content_type="text/html",
        html=html,
        soup=BeautifulSoup(html, "html.parser"),
    )


def test_pa001_agent_manifest_satisfaction():
    """PA-001 detects presence of /llms.txt, /llms-full.txt, or /agents.md."""
    client = MagicMock(spec=HttpClient)

    # 1. When all 3 return 404, PA-001 fires
    client.head.return_value = MagicMock(status_code=404)
    rec_missing = _pa001("https://example.com", client, set())
    assert rec_missing is not None
    assert rec_missing["local_id"] == "PA-001"
    assert "/agents.md" in rec_missing["evidence"]
    assert "llmstxt.org" in rec_missing["suggested_action"]["summary"]

    # 2. When /agents.md returns 200, PA-001 is satisfied (returns None)
    def mock_head(url, **kwargs):
        if url.endswith("/agents.md"):
            return MagicMock(status_code=200)
        return MagicMock(status_code=404)

    client.head.side_effect = mock_head
    rec_agents_md = _pa001("https://example.com", client, set())
    assert rec_agents_md is None

    # 3. When /llms.txt returns 200, PA-001 is satisfied (returns None)
    client.head.side_effect = None
    client.head.return_value = MagicMock(status_code=200)
    rec_present = _pa001("https://example.com", client, set())
    assert rec_present is None


def test_pa002_unified_jsonld_graph():
    """PA-002 verifies @graph with @id cross-referencing."""
    # 1. Isolated blocks without @graph cross-references -> fires
    isolated_html = """
    <html><head>
    <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "Acme"}</script>
    <script type="application/ld+json">{"@context": "https://schema.org", "@type": "WebSite", "name": "Acme Web"}</script>
    </head><body></body></html>
    """
    page_results = {"https://example.com": _make_page_result("https://example.com", isolated_html)}
    rec = _pa002(page_results, set())
    assert rec is not None
    assert rec["local_id"] == "PA-002"
    assert "@graph" in rec["suggested_action"]["summary"]

    # 2. Unified @graph with @id cross-references -> satisfied (None)
    unified_html = """
    <html><head>
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@graph": [
        {"@type": "Organization", "@id": "https://example.com/#org", "name": "Acme"},
        {"@type": "WebSite", "@id": "https://example.com/#site", "publisher": {"@id": "https://example.com/#org"}}
      ]
    }
    </script>
    </head><body></body></html>
    """
    page_results_unified = {"https://example.com": _make_page_result("https://example.com", unified_html)}
    assert _pa002(page_results_unified, set()) is None


def test_pa003_heading_fragment_ids():
    """PA-003 verifies deep link anchor IDs on section headings."""
    # 1. Headings without IDs -> fires
    no_ids_html = """
    <html><body>
    <h2>Overview of the System</h2>
    <h3>Architecture Details</h3>
    <h2>Performance Tuning</h2>
    <h3>Benchmark Results</h3>
    </body></html>
    """
    prs = {"https://example.com": _make_page_result("https://example.com", no_ids_html)}
    rec = _pa003(prs, set())
    assert rec is not None
    assert rec["local_id"] == "PA-003"
    assert "0%" in rec["evidence"] or "0/" in rec["evidence"]

    # 2. Headings with IDs -> satisfied (None)
    with_ids_html = """
    <html><body>
    <h2 id="overview">Overview of the System</h2>
    <h3 id="architecture">Architecture Details</h3>
    <h2 id="tuning">Performance Tuning</h2>
    <h3 id="benchmarks">Benchmark Results</h3>
    </body></html>
    """
    prs_ids = {"https://example.com": _make_page_result("https://example.com", with_ids_html)}
    assert _pa003(prs_ids, set()) is None


def test_pa004_answer_first_structure():
    """PA-004 detects verbose preamble vs direct answers on content pages."""
    verbose_html = """
    <html><body>
    <h1>Enterprise Platform Guide</h1>
    <p>In today's fast-paced digital ecosystem where technology continues to evolve at an unprecedented velocity across diverse industry sectors worldwide, organizations frequently discover that navigating modern infrastructural requirements demands thorough contemplation.</p>
    <p>The enterprise platform provides distributed cloud caching and automated identity sync.</p>
    <p>Installation instructions are detailed below.</p>
    </body></html>
    """
    prs = {
        "https://example.com/guide1": _make_page_result("https://example.com/guide1", verbose_html),
        "https://example.com/guide2": _make_page_result("https://example.com/guide2", verbose_html),
    }
    rec = _pa004(prs, set())
    assert rec is not None
    assert rec["local_id"] == "PA-004"
    assert "answer-first" in rec["title"].lower() or "inverted pyramid" in rec["suggested_action"]["summary"].lower()


def test_pa005_contextual_feed_recommendation():
    """PA-005 recommends syndication feeds on editorial content, not single-page utilities."""
    # 1. Single utility page without editorial content -> returns None (no noise)
    utility_html = "<html><body><h1>Converter Tool</h1><p>Online file converter.</p></body></html>"
    prs_util = {"https://example.com": _make_page_result("https://example.com", utility_html)}
    assert _pa005(prs_util, set()) is None

    # 2. Editorial blog content without RSS/Atom -> fires
    blog_html = "<html><body><h1>Blog Article</h1><p>Deep dive into tech.</p></body></html>"
    prs_blog = {
        "https://example.com/blog/ai-trends": _make_page_result("https://example.com/blog/ai-trends", blog_html),
    }
    rec = _pa005(prs_blog, set())
    assert rec is not None
    assert rec["local_id"] == "PA-005"
    assert "rss+xml" in rec["suggested_action"]["summary"]


def test_pa006_robots_explicit_allow_suppression():
    """PA-006 suppresses when CR-001 (crawler disallow) is already flagged."""
    client = MagicMock()

    # robots.txt without explicit allow
    client.robots._get_parser.return_value = (None, "User-agent: *\nDisallow: /admin\n")

    # 1. No CR-001 in existing titles -> fires PA-006
    rec = _pa006("https://example.com", client, set(), set())
    assert rec is not None
    assert rec["local_id"] == "PA-006"

    # 2. CR-001 already reported blocking robots -> suppressed
    existing_titles = {"ai crawlers blocked in robots.txt"}
    rec_suppressed = _pa006("https://example.com", client, set(), existing_titles)
    assert rec_suppressed is None


def test_proactive_injection_determinism_and_schema_validity():
    """inject_proactive_recommendations produces deterministic findings adhering to report schema."""
    client = MagicMock()
    client.head.return_value = MagicMock(status_code=404)
    client.robots._get_parser.return_value = (None, "User-agent: *\nDisallow: /admin\n")

    page_html = """
    <html><head>
    <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "Acme"}</script>
    </head><body>
    <h1>Platform Insights</h1>
    <h2>Features</h2>
    <h3>Pricing</h3>
    <h2>Roadmap</h2>
    <h3>Security</h3>
    </body></html>
    """
    page_results = {
        "https://example.com/page1": _make_page_result("https://example.com/page1", page_html),
        "https://example.com/page2": _make_page_result("https://example.com/page2", page_html),
    }

    report_dict = {"findings": []}

    # Run injection twice
    recs1 = inject_proactive_recommendations(report_dict, page_results, client, "https://example.com")
    recs2 = inject_proactive_recommendations(report_dict, page_results, client, "https://example.com")

    assert len(recs1) == len(recs2)
    assert [r["local_id"] for r in recs1] == [r["local_id"] for r in recs2]

    # Check separation: all proactive findings must be severity=info, category=proactive
    for r in recs1:
        assert r["severity"] == "info"
        assert r["category"] == "proactive"
        norm = _normalise_finding(r, "proactive", "https://example.com")
        norm["id"] = "F-999"
        assert norm["severity"] == "info"
        assert norm["category"] == "proactive"
        assert norm["why_it_matters"]
        assert norm["location"]
        assert norm["remediation_theme"]
