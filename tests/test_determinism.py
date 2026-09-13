"""
test_determinism.py
===================
Tests for execution determinism and inter-skill contracts:
1. Repeatability: 10 repeated runs of the audit pipeline produce 100% identical findings,
   finding IDs, severities, evidence, and categories (excluding metadata timestamps).
2. Frontier order independence: Permuting/reversing crawl frontier order yields identical
   findings and sampled evidence in SFE, TEC, and ER.
3. Canonical total ordering: Findings sort canonically and produce stable sequential IDs (F-001..F-NNN).
4. Deduplication stability: Deduplication order is deterministic regardless of candidate arrival order.
5. Skill contract boundaries: Upstream crashes, None outputs, or malformed dicts are safely
   sanitized without crashing the pipeline.
6. Concurrent execution: Multi-threaded runs produce identical outputs without cross-contamination.
"""

from __future__ import annotations

import copy
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
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
    RenderState,
)
import sfe_audit
import tec_audit
import er_audit
from aggregate import (
    _sort_findings,
    _assign_ids,
    _deduplicate,
    _resolve_related_to,
    _validate_and_sanitize_skill_output,
    _run_pipeline,
)
from schema_validate import validate_report


def _create_mock_environment():
    """Create a repeatable synthetic website environment with HTML and PageResults."""
    home_html = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Acme Corp - Official Home</title>
        <meta name="description" content="Acme Corp provides leading-edge cloud solutions.">
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "Acme Corp",
            "url": "https://example.com",
            "logo": "https://example.com/logo.png",
            "sameAs": [
                "https://www.linkedin.com/company/acme",
                "https://en.wikipedia.org/wiki/Acme_Corp",
                "https://www.wikidata.org/wiki/Q12345"
            ]
        }
        </script>
    </head>
    <body>
        <nav aria-label="Main Navigation">
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/pricing">Pricing</a>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </nav>
        <main>
            <h1>Welcome to Acme Corp</h1>
            <p>We build exceptional developer tools and infrastructure.</p>
        </main>
    </body>
    </html>"""

    products_html = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Acme Products - Tools for Devs</title>
        <meta name="description" content="Browse our developer tools.">
    </head>
    <body>
        <nav aria-label="Main Navigation">
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/pricing">Pricing</a>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </nav>
        <main>
            <h1>Developer Tools</h1>
            <p>Explore our suite of scalable tools.</p>
            <a href="/checkout" class="btn">Get Started</a>
        </main>
    </body>
    </html>"""

    about_html = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>About Acme Corp</title>
    </head>
    <body>
        <nav aria-label="Main Navigation">
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/pricing">Pricing</a>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </nav>
        <main>
            <h1>About Us</h1>
            <p>Founded in 2020, Acme Corp is accredited by ISO 9001 certified bodies.</p>
            <h2>How does it work?</h2>
            <p>Our distributed system handles high throughput.</p>
            <h2>What is the pricing?</h2>
            <p>Plans start at $10/mo.</p>
        </main>
    </body>
    </html>"""

    home_soup = BeautifulSoup(home_html, "html.parser")
    products_soup = BeautifulSoup(products_html, "html.parser")
    about_soup = BeautifulSoup(about_html, "html.parser")

    pages = {
        "https://example.com/": PageResult(
            url="https://example.com/",
            status_code=200,
            html=home_html,
            soup=home_soup,
            render_state=RenderState.CONFIRMED,
        ),
        "https://example.com/products": PageResult(
            url="https://example.com/products",
            status_code=200,
            html=products_html,
            soup=products_soup,
            render_state=RenderState.CONFIRMED,
        ),
        "https://example.com/about": PageResult(
            url="https://example.com/about",
            status_code=200,
            html=about_html,
            soup=about_soup,
            render_state=RenderState.CONFIRMED,
        ),
    }

    frontier = [
        "https://example.com/",
        "https://example.com/products",
        "https://example.com/about",
    ]

    mock_client = MagicMock(spec=HttpClient)
    mock_client._allow_private_ips = False
    mock_client._deadline = AuditDeadline.from_budget(60)

    def _get(url, **kwargs):
        return pages.get(url, PageResult(url=url, status_code=404))

    def _head(url, **kwargs):
        res = MagicMock()
        res.status_code = 200
        return res

    mock_client.get.side_effect = _get
    mock_client.head.side_effect = _head

    return frontier, pages, mock_client


def _strip_variable_metadata(report: dict) -> dict:
    """Strip run-dependent timestamps and durations for semantic comparison."""
    rep = copy.deepcopy(report)
    rep.pop("generated_at", None)
    rep.pop("audited_at", None)
    rep.pop("audit_duration_seconds", None)
    return rep


def test_repeatability_10_runs_identical():
    """Verify that 10 consecutive runs of the audit pipeline on identical inputs
    produce 100% byte-for-byte identical output findings, IDs, and severities.
    """
    frontier, pages, client = _create_mock_environment()

    reports = []
    raw_reports = []
    for _ in range(10):
        # Re-mock crawl_audit to return consistent frontier & pages
        with patch("crawl_audit.run_audit") as mock_crawl:
            mock_crawl.return_value = {
                "domain": "crawl-render-access",
                "pages_analyzed": 3,
                "pages_discovered": 3,
                "errors": [],
                "findings": [],
                "proactive_candidates": [],
                "crawl_frontier": list(frontier),
                "page_results": dict(pages),
            }
            rep = _run_pipeline(
                target_url="https://example.com/",
                max_pages=15,
                timeout_s=60,
                client=client,
                t_start=100.0,
            )
            raw_reports.append(rep)
            reports.append(_strip_variable_metadata(rep))

    first_json = json.dumps(reports[0], sort_keys=True)
    for i, rep in enumerate(reports[1:], start=2):
        rep_json = json.dumps(rep, sort_keys=True)
        assert rep_json == first_json, f"Run {i} deviated from Run 1!"

    # Verify original report is valid against schema
    is_valid, errors = validate_report(raw_reports[0])
    assert is_valid, f"Report failed schema validation: {errors}"


def test_frontier_order_independence_in_skills():
    """Verify that permuting or reversing the frontier order given to SFE, TEC, and ER
    produces identical findings, evidence, and severities.
    """
    frontier, pages, client = _create_mock_environment()
    rev_frontier = list(reversed(frontier))

    # Test SFE
    sfe_res_orig = sfe_audit.run_audit(
        "https://example.com/", client, crawl_frontier=frontier, page_results=pages
    )
    sfe_res_rev = sfe_audit.run_audit(
        "https://example.com/", client, crawl_frontier=rev_frontier, page_results=pages
    )
    # Sort findings canonically for fair comparison
    sfe_findings_orig = _sort_findings(sfe_res_orig["findings"])
    sfe_findings_rev = _sort_findings(sfe_res_rev["findings"])
    assert json.dumps(sfe_findings_orig, sort_keys=True) == json.dumps(sfe_findings_rev, sort_keys=True)

    # Test TEC
    tec_res_orig = tec_audit.run_audit(
        "https://example.com/", client, crawl_frontier=frontier, page_results=pages
    )
    tec_res_rev = tec_audit.run_audit(
        "https://example.com/", client, crawl_frontier=rev_frontier, page_results=pages
    )
    tec_findings_orig = _sort_findings(tec_res_orig["findings"])
    tec_findings_rev = _sort_findings(tec_res_rev["findings"])
    assert json.dumps(tec_findings_orig, sort_keys=True) == json.dumps(tec_findings_rev, sort_keys=True)

    # Test ER
    er_res_orig = er_audit.run_audit(
        "https://example.com/", client, crawl_frontier=frontier, page_results=pages
    )
    er_res_rev = er_audit.run_audit(
        "https://example.com/", client, crawl_frontier=rev_frontier, page_results=pages
    )
    er_findings_orig = _sort_findings(er_res_orig["findings"])
    er_findings_rev = _sort_findings(er_res_rev["findings"])
    assert json.dumps(er_findings_orig, sort_keys=True) == json.dumps(er_findings_rev, sort_keys=True)


def test_canonical_finding_sort_and_id_assignment():
    """Verify that _sort_findings uses a total ordering key so that any arbitrary
    input arrival order produces the exact same sorted order and stable F-001..F-NNN IDs.
    """
    f1 = {"severity": "high", "category": "discoverability", "local_id": "SF-001", "title": "Alpha defect", "evidence": "page 1"}
    f2 = {"severity": "high", "category": "discoverability", "local_id": "SF-001", "title": "Beta defect", "evidence": "page 2"}
    f3 = {"severity": "medium", "category": "engagement", "local_id": "ER-001", "title": "Missing H1", "evidence": "page 3"}
    f4 = {"severity": "critical", "category": "discoverability", "local_id": "CR-001", "title": "Robots block", "evidence": "robots.txt"}

    list_a = [f1, f2, f3, f4]
    list_b = [f3, f4, f2, f1]
    list_c = [f4, f1, f3, f2]

    sorted_a = _assign_ids(_sort_findings(list_a))
    sorted_b = _assign_ids(_sort_findings(list_b))
    sorted_c = _assign_ids(_sort_findings(list_c))

    json_a = json.dumps(sorted_a, sort_keys=True)
    json_b = json.dumps(sorted_b, sort_keys=True)
    json_c = json.dumps(sorted_c, sort_keys=True)

    assert json_a == json_b == json_c
    assert sorted_a[0]["id"] == "F-001"
    assert sorted_a[0]["title"] == "Robots block"  # critical comes first
    assert sorted_a[1]["id"] == "F-002"
    assert sorted_a[1]["title"] == "Alpha defect"
    assert sorted_a[2]["id"] == "F-003"
    assert sorted_a[2]["title"] == "Beta defect"
    assert sorted_a[3]["id"] == "F-004"
    assert sorted_a[3]["title"] == "Missing H1"


def test_deduplication_stability():
    """Verify that deduplication produces identical output regardless of arrival order."""
    f1 = {"severity": "high", "category": "discoverability", "local_id": "SF-001", "title": "Duplicate Check", "evidence": "Snippet A"}
    f2 = {"severity": "high", "category": "discoverability", "local_id": "SF-001", "title": "Duplicate Check", "evidence": "Snippet A"}
    f3 = {"severity": "medium", "category": "engagement", "local_id": "ER-001", "title": "Unique Check", "evidence": "Snippet B"}

    forward = _assign_ids(_sort_findings(_deduplicate(_sort_findings([f1, f2, f3]))))
    reverse = _assign_ids(_sort_findings(_deduplicate(_sort_findings([f3, f2, f1]))))

    assert json.dumps(forward, sort_keys=True) == json.dumps(reverse, sort_keys=True)
    assert len(forward) == 2


def test_skill_output_sanitizer():
    """Verify _validate_and_sanitize_skill_output enforces contract without crashing
    when given None, non-dict, missing fields, or corrupt items.
    """
    # 1. None output
    res_none = _validate_and_sanitize_skill_output(None, "structured-fact-extraction")
    assert res_none["domain"] == "structured-fact-extraction"
    assert res_none["pages_analyzed"] == 0
    assert res_none["findings"] == []
    assert len(res_none["errors"]) == 1
    assert "returned non-dict" in res_none["errors"][0]

    # 2. String output
    res_str = _validate_and_sanitize_skill_output("crash traceback string", "trust-entity-corroboration")
    assert res_str["domain"] == "trust-entity-corroboration"
    assert res_str["findings"] == []

    # 3. Corrupt findings list (mixed None and ints)
    corrupt_dict = {
        "domain": "engagement-retention",
        "findings": [None, 42, "malformed", {"local_id": "ER-001", "title": "Valid"}],
        "pages_analyzed": "not_an_int",
    }
    res_corrupt = _validate_and_sanitize_skill_output(corrupt_dict, "engagement-retention")
    assert res_corrupt["pages_analyzed"] == 0
    assert len(res_corrupt["findings"]) == 1
    assert res_corrupt["findings"][0]["title"] == "Valid"

    # 4. Proactive candidates corrupted
    corrupt_proactive = {
        "domain": "structured-fact-extraction",
        "proactive_candidates": "not_a_list",
    }
    res_pro = _validate_and_sanitize_skill_output(corrupt_proactive, "structured-fact-extraction")
    assert res_pro["proactive_candidates"] == []


def test_concurrent_execution_stability():
    """Verify that multiple concurrent threads running the pipeline produce identical,
    uncorrupted results.
    """
    frontier, pages, client = _create_mock_environment()

    def _run_single():
        rep = _run_pipeline(
            target_url="https://example.com/",
            max_pages=15,
            timeout_s=60,
            client=client,
            t_start=100.0,
        )
        return _strip_variable_metadata(rep)

    with patch("crawl_audit.run_audit") as mock_crawl:
        mock_crawl.return_value = {
            "domain": "crawl-render-access",
            "pages_analyzed": 3,
            "pages_discovered": 3,
            "errors": [],
            "findings": [],
            "proactive_candidates": [],
            "crawl_frontier": list(frontier),
            "page_results": dict(pages),
        }
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_run_single) for _ in range(4)]
            results = [f.result() for f in futures]

    first_res = json.dumps(results[0], sort_keys=True)
    for i, res in enumerate(results[1:], start=2):
        assert json.dumps(res, sort_keys=True) == first_res, f"Concurrent run {i} differed from run 1!"
