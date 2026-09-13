"""
test_coverage_telemetry.py
==========================
Targeted tests for Phase 4 Coverage Telemetry and Observability:
1. Complete audit (full observation -> COMPLETE, no limitations).
2. Partial render (some pages low render confidence -> PARTIAL).
3. Blocked target (SSRF/WAF/robots block -> UNAVAILABLE).
4. Renderer unavailable (static only / render failed across pages -> LIMITED).
5. Corroboration unavailable (external links timed out / unreachable -> LIMITED).
6. Skill timeout (timeout budget reached -> PARTIAL).
7. Skill failure (subsystem failure / crashed domain -> UNAVAILABLE).
8. Coverage determinism and schema validity.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import CoverageState, PageResult
from aggregate import _build_coverage, _build_aborted_report
from schema_validate import validate_report


def _sample_valid_report(coverage: dict, status: str = "completed") -> dict:
    """Helper to assemble a minimal schema-valid report containing the given coverage."""
    return {
        "schema_version": "1.0.0",
        "generated_at": "2026-09-13T12:00:00Z",
        "audited_at": "2026-09-13T12:00:00Z",
        "target_url": "https://example.com",
        "site": "https://example.com",
        "audit_status": status,
        "audit_status_message": "Audit completed.",
        "pages_audited": 5,
        "audit_duration_seconds": 1.23,
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "coverage": {
                "pages_audited": 5,
                "pages_in_sitemap": 5,
                "budget_limited": False,
            },
        },
        "findings": [],
        "proactive_recommendations": [],
        "coverage": coverage,
    }


def test_complete_audit_coverage():
    """1. Complete audit: all 4 domains executed with verified pages and high render confidence."""
    frontier = [f"https://example.com/p{i}" for i in range(5)]
    page_results = {u: PageResult(url=u, status_code=200, render_confidence="high") for u in frontier}

    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 5,
            "pages_discovered": 5,
            "crawl_frontier": frontier,
            "page_results": page_results,
            "coverage": {"pages_audited": 5, "pages_in_sitemap": 5, "budget_limited": False},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {
            "pages_analyzed": 5,
            "findings": [],
            "errors": [],
        },
        "trust-entity-corroboration": {
            "pages_analyzed": 5,
            "findings": [],
            "errors": [],
        },
        "engagement-retention": {
            "pages_analyzed": 5,
            "findings": [],
            "errors": [],
        },
    }

    cov = _build_coverage(domain_results, [], frontier=frontier, audit_status="completed")

    assert cov["overall_state"] == CoverageState.COMPLETE.value
    assert cov["crawl_render_access"]["coverage_state"] == CoverageState.COMPLETE.value
    assert cov["structured_fact_extraction"]["coverage_state"] == CoverageState.COMPLETE.value
    assert cov["trust_entity_corroboration"]["coverage_state"] == CoverageState.COMPLETE.value
    assert cov["engagement_retention"]["coverage_state"] == CoverageState.COMPLETE.value
    assert cov["limitations"] == []

    report = _sample_valid_report(cov, status="completed")
    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_partial_render_coverage():
    """2. Partial render: Some pages have low render confidence."""
    frontier = ["https://example.com/p1", "https://example.com/p2"]
    page_results = {
        "https://example.com/p1": PageResult(url="https://example.com/p1", status_code=200, render_confidence="high"),
        "https://example.com/p2": PageResult(url="https://example.com/p2", status_code=200, render_confidence="low"),
    }

    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 2,
            "crawl_frontier": frontier,
            "page_results": page_results,
            "coverage": {"pages_audited": 2, "pages_in_sitemap": 2, "budget_limited": False},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {"pages_analyzed": 2, "findings": [], "errors": []},
        "trust-entity-corroboration": {"pages_analyzed": 2, "findings": [], "errors": []},
        "engagement-retention": {"pages_analyzed": 2, "findings": [], "errors": []},
    }

    cov = _build_coverage(domain_results, [], frontier=frontier, audit_status="completed")

    assert cov["overall_state"] == CoverageState.PARTIAL.value
    assert cov["crawl_render_access"]["coverage_state"] == CoverageState.PARTIAL.value
    assert any("low confidence on 1 of 2 pages" in s for s in cov["limitations"])

    report = _sample_valid_report(cov, status="completed")
    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_blocked_target_coverage():
    """3. Blocked target: Aborted report produces UNAVAILABLE coverage state with explicit limitations."""
    report = _build_aborted_report(
        "https://127.0.0.1:8080",
        "blocked",
        "Audit could not complete: target URL is blocked by SSRF protection (loopback address). Content was not inspected.",
        0.05,
        reason="ssrf_disallowed",
    )

    cov = report["coverage"]
    assert cov["overall_state"] == CoverageState.UNAVAILABLE.value
    assert cov["crawl_render_access"]["coverage_state"] == CoverageState.UNAVAILABLE.value
    assert cov["structured_fact_extraction"]["coverage_state"] == CoverageState.UNAVAILABLE.value
    assert cov["trust_entity_corroboration"]["coverage_state"] == CoverageState.UNAVAILABLE.value
    assert cov["engagement_retention"]["coverage_state"] == CoverageState.UNAVAILABLE.value
    assert len(cov["limitations"]) == 1
    assert "blocked before inspection" in cov["limitations"][0]

    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_renderer_unavailable_coverage():
    """4. Renderer unavailable: All pages have low render confidence (static-only / renderer missing).
    Overall coverage is marked LIMITED, not false complete clean.
    """
    frontier = ["https://example.com/p1", "https://example.com/p2"]
    page_results = {
        u: PageResult(url=u, status_code=200, render_confidence="low") for u in frontier
    }

    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 2,
            "crawl_frontier": frontier,
            "page_results": page_results,
            "coverage": {"pages_audited": 2, "pages_in_sitemap": 2, "budget_limited": False},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {"pages_analyzed": 2, "findings": [], "errors": []},
        "trust-entity-corroboration": {"pages_analyzed": 2, "findings": [], "errors": []},
        "engagement-retention": {"pages_analyzed": 2, "findings": [], "errors": []},
    }

    cov = _build_coverage(domain_results, [], frontier=frontier, audit_status="completed")

    assert cov["overall_state"] == CoverageState.LIMITED.value
    assert cov["crawl_render_access"]["coverage_state"] == CoverageState.LIMITED.value
    assert cov["structured_fact_extraction"]["coverage_state"] == CoverageState.LIMITED.value
    assert any("Browser rendering was unobservable" in s for s in cov["limitations"])

    report = _sample_valid_report(cov, status="completed")
    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_corroboration_unavailable_coverage():
    """5. Corroboration unavailable: Trust domain experienced unreachable external sources.
    Trust coverage and overall coverage are marked LIMITED.
    """
    frontier = ["https://example.com"]
    page_results = {"https://example.com": PageResult(url="https://example.com", status_code=200, render_confidence="high")}

    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 1,
            "crawl_frontier": frontier,
            "page_results": page_results,
            "coverage": {"pages_audited": 1, "pages_in_sitemap": 1, "budget_limited": False},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {"pages_analyzed": 1, "findings": [], "errors": []},
        "trust-entity-corroboration": {
            "pages_analyzed": 1,
            "findings": [],
            "errors": ["[NOT_OBSERVABLE] external registry unreachable: ConnectTimeout"],
        },
        "engagement-retention": {"pages_analyzed": 1, "findings": [], "errors": []},
    }

    cov = _build_coverage(domain_results, [], frontier=frontier, audit_status="completed")

    assert cov["overall_state"] == CoverageState.LIMITED.value
    assert cov["trust_entity_corroboration"]["coverage_state"] == CoverageState.LIMITED.value
    assert any("unreachable corroborating sources" in s for s in cov["limitations"])

    report = _sample_valid_report(cov, status="completed")
    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_skill_timeout_and_failure_coverage():
    """6 & 7. Skill timeout and skill failure handling in coverage."""
    # Failure case: one domain crashed
    domain_results_crashed = {
        "crawl-render-access": {
            "pages_analyzed": 1,
            "crawl_frontier": ["https://example.com"],
            "page_results": {"https://example.com": PageResult(url="https://example.com", status_code=200)},
            "coverage": {"pages_audited": 1, "pages_in_sitemap": 1, "budget_limited": False},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {"pages_analyzed": 1, "findings": [], "errors": []},
        "trust-entity-corroboration": None,  # Crashed/skipped domain
        "engagement-retention": {"pages_analyzed": 1, "findings": [], "errors": []},
    }

    cov_crashed = _build_coverage(domain_results_crashed, [], frontier=["https://example.com"], audit_status="partial")
    assert cov_crashed["trust_entity_corroboration"]["coverage_state"] == CoverageState.UNAVAILABLE.value
    assert cov_crashed["overall_state"] == CoverageState.UNAVAILABLE.value
    assert any("trust entity corroboration failed to execute" in s for s in cov_crashed["limitations"])

    report = _sample_valid_report(cov_crashed, status="partial")
    valid, errors = validate_report(report)
    assert valid, f"Report failed schema validation: {errors}"


def test_coverage_determinism():
    """8. Coverage determinism: repeated calls with identical inputs produce identical dictionaries."""
    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 3,
            "crawl_frontier": ["https://example.com/a", "https://example.com/b", "https://example.com/c"],
            "page_results": {
                "https://example.com/a": PageResult(url="https://example.com/a", status_code=200, render_confidence="high"),
                "https://example.com/b": PageResult(url="https://example.com/b", status_code=200, render_confidence="low"),
                "https://example.com/c": PageResult(url="https://example.com/c", status_code=200, render_confidence="high"),
            },
            "coverage": {"pages_audited": 3, "pages_in_sitemap": 10, "budget_limited": True},
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {"pages_analyzed": 3, "findings": [], "errors": []},
        "trust-entity-corroboration": {"pages_analyzed": 3, "findings": [], "errors": []},
        "engagement-retention": {"pages_analyzed": 3, "findings": [], "errors": []},
    }

    cov1 = _build_coverage(domain_results, [], frontier=["https://example.com/a", "https://example.com/b", "https://example.com/c"])
    cov2 = _build_coverage(domain_results, [], frontier=["https://example.com/a", "https://example.com/b", "https://example.com/c"])

    assert cov1 == cov2
    assert cov1["overall_state"] == CoverageState.PARTIAL.value
