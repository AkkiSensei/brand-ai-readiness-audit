"""
test_live_generalization_fixes.py
=================================
Adversarial test suite verifying the 5 live-generalization bug fixes:
1. 403/429/WAF crawl-failure cascade prevention (zero false DOM findings)
2. URL canonicalization and crawl-identity deduplication
3. Binding remediation directly to actual observed evidence (no wrong-agent recommendations)
4. Trust & Entity Corroboration coverage on sites with no, partial, or malformed JSON-LD
5. Coverage telemetry precision (checks_run reflects checks attempted, not len(findings))
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest
from bs4 import BeautifulSoup

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import (
    FetchState,
    PageResult,
    canonicalize_url,
    HttpClient,
)
from crawl_audit import run_audit as cra_audit
from sfe_audit import run_audit as sfe_audit
from er_audit import run_audit as er_audit
from tec_audit import (
    run_audit as tec_audit,
    _check_tc001,
    _check_tc004_tc006,
)
from aggregate import (
    run_audit as orchestrator_audit,
    _resolve_finding_metadata,
    _normalise_finding,
    _build_coverage,
)
from schema_validate import validate_report


# ==============================================================================
# 1. 403 / 429 / WAF CRAWL-FAILURE CASCADE PREVENTION
# ==============================================================================

class DummyHttpClient:
    """Mock client for testing."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self._deadline = None

    def get(self, url, **kwargs):
        if url in self.responses:
            return self.responses[url]
        return PageResult(
            url=url,
            status_code=200,
            fetch_state=FetchState.FETCHED_OK,
            soup=BeautifulSoup("<html><body><h1>Hello World</h1><p>Test</p></body></html>", "html.parser"),
            html="<html><body><h1>Hello World</h1><p>Test</p></body></html>",
        )


def test_crawl_failure_cascade_prevention_on_403_and_429():
    """A site returning 403 or 429 must NOT generate false DOM findings
    such as missing H1, missing viewport, missing navigation, or missing schema."""
    target = "https://example-blocked.com"
    html_403 = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>"
    page_403 = PageResult(
        url=target,
        status_code=403,
        fetch_state=FetchState.HTTP_ERROR,
        soup=BeautifulSoup(html_403, "html.parser"),
        html=html_403,
    )
    page_results = {target: page_403}
    frontier = [target]

    client = DummyHttpClient(responses={target: page_403})

    # Test downstream SFE audit directly
    sfe_res = sfe_audit(target, client, crawl_frontier=frontier, page_results=page_results)
    assert len(sfe_res["findings"]) == 0, f"SFE emitted false findings on 403: {sfe_res['findings']}"
    assert sfe_res["checks_attempted"] == 0
    assert sfe_res["checks_skipped"] == 8

    # Test downstream ER audit directly
    er_res = er_audit(target, client, crawl_frontier=frontier, page_results=page_results)
    assert len(er_res["findings"]) == 0, f"ER emitted false findings on 403: {er_res['findings']}"
    assert er_res["checks_attempted"] == 0
    assert er_res["checks_skipped"] == 8

    # Test downstream TEC audit directly
    tec_res = tec_audit(target, client, crawl_frontier=frontier, page_results=page_results)
    assert len(tec_res["findings"]) == 0, f"TEC emitted false findings on 403: {tec_res['findings']}"
    assert tec_res["checks_attempted"] == 0
    assert tec_res["checks_skipped"] == 6


def test_rate_limited_page_fetch_state():
    """Verify rate-limited page state is properly assigned and excluded from DOM detectors."""
    pr_rate = PageResult(
        url="https://example.com/api/test",
        status_code=429,
        fetch_state=FetchState.RATE_LIMITED,
        soup=BeautifulSoup("<html><body>Too Many Requests</body></html>", "html.parser"),
    )
    assert pr_rate.is_usable_content is False
    assert pr_rate.effective_fetch_state == FetchState.RATE_LIMITED

    pr_waf = PageResult(
        url="https://example.com/login",
        status_code=403,
        fetch_state=FetchState.WAF_BLOCKED,
        soup=BeautifulSoup("<html><body>Attention Required! | Cloudflare</body></html>", "html.parser"),
    )
    assert pr_waf.is_usable_content is False
    assert pr_waf.effective_fetch_state == FetchState.WAF_BLOCKED


# ==============================================================================
# 2. URL CANONICALIZATION & ADVERSARIAL CASES
# ==============================================================================

def test_canonicalize_url_root_and_trailing_slashes():
    """Root URLs and path URLs must normalize safely without duplicate crawl slots."""
    assert canonicalize_url("https://example.com") == "https://example.com/"
    assert canonicalize_url("https://example.com/") == "https://example.com/"
    assert canonicalize_url("http://example.com") == "http://example.com/"

    # Subpaths: strip trailing slash for consistent route identity
    assert canonicalize_url("https://example.com/about/") == "https://example.com/about"
    assert canonicalize_url("https://example.com/about") == "https://example.com/about"
    assert canonicalize_url("https://example.com/deep/path/") == "https://example.com/deep/path"


def test_canonicalize_url_fragments_and_case():
    """Strip fragments and lower-case scheme/host."""
    assert canonicalize_url("HTTPS://EXAMPLE.COM/about#team") == "https://example.com/about"
    assert canonicalize_url("https://Example.Com:443/products") == "https://example.com/products"
    assert canonicalize_url("http://example.com:80/home") == "http://example.com/home"
    assert canonicalize_url("https://example.com:8443/home") == "https://example.com:8443/home"


def test_canonicalize_url_preserves_query_semantics():
    """Do NOT strip or break query strings that define distinct page semantics."""
    assert canonicalize_url("https://example.com/shop?cat=shoes&sort=price") == "https://example.com/shop?cat=shoes&sort=price"
    assert canonicalize_url("https://example.com/search?q=AI+Readiness#results") == "https://example.com/search?q=AI+Readiness"


def test_canonicalize_redundant_slashes():
    """Handle multi-slash paths without breaking protocol."""
    assert canonicalize_url("https://example.com//catalog///item") == "https://example.com/catalog/item"


# ==============================================================================
# 3. BIND REMEDIATION TO ACTUAL EVIDENCE
# ==============================================================================

def test_remediation_bound_to_specific_blocked_crawler():
    """If evidence says Bytespider is blocked, remediation MUST mention Bytespider,
    and MUST NOT mention GPTBot / Google-Extended unless they were in the evidence."""
    raw_finding = {
        "local_id": "CR-001",
        "title": "AI search engine crawler access is blocked or restricted",
        "severity": "critical",
        "evidence": {
            "url": "https://example.com/robots.txt",
            "blocked_count": 1,
            "blocked_sample": [{"agent": "Bytespider", "line": 12}],
        },
    }
    meta = _resolve_finding_metadata("CR-001", raw_finding["title"], raw_finding)
    action = meta.get("default_action", "")
    assert "Bytespider" in action, f"Expected 'Bytespider' in action, got: {action}"
    assert "GPTBot" not in action, f"Should NOT mention GPTBot when only Bytespider blocked: {action}"
    assert "Google-Extended" not in action, f"Should NOT mention Google-Extended: {action}"

    # Also test normalization
    norm = _normalise_finding(raw_finding, "crawl-render-access", "https://example.com")
    act_summary = norm["suggested_action"]["summary"]
    assert "Bytespider" in act_summary
    assert "GPTBot" not in act_summary


def test_remediation_bound_to_waf_evidence():
    """If evidence detects a Cloudflare challenge, remediation should mention Cloudflare."""
    raw_finding = {
        "local_id": "CR-002",
        "title": "Edge WAF / Anti-Bot challenge detected",
        "severity": "critical",
        "evidence": {
            "waf": "Cloudflare",
            "signature": "cloudflare-turnstile",
        },
    }
    meta = _resolve_finding_metadata("CR-002", raw_finding["title"], raw_finding)
    action = meta.get("default_action", "")
    assert "Cloudflare" in action, f"Expected 'Cloudflare' in action, got: {action}"


# ==============================================================================
# 4. TRUST & ENTITY CORROBORATION COVERAGE ON UNSEEN FIXTURES
# ==============================================================================

def test_tec_fixture_a_org_jsonld_with_sameas():
    """Fixture A: Organization JSON-LD exists with valid sameAs and address -> no TC-001 or TC-004 finding."""
    html = """
    <html>
    <head>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "Acme Global Industries",
            "url": "https://example.com",
            "sameAs": [
                "https://www.wikidata.org/wiki/Q12345",
                "https://en.wikipedia.org/wiki/Acme_Global"
            ],
            "address": {
                "@type": "PostalAddress",
                "streetAddress": "123 Main St",
                "addressLocality": "San Jose",
                "addressRegion": "CA",
                "postalCode": "95110",
                "addressCountry": "US"
            }
        }
        </script>
    </head>
    <body><h1>Acme Global</h1></body>
    </html>
    """
    pr = PageResult(
        url="https://example.com",
        status_code=200,
        fetch_state=FetchState.FETCHED_OK,
        soup=BeautifulSoup(html, "html.parser"),
        html=html,
    )
    client = DummyHttpClient({"https://example.com": pr})
    findings = _check_tc001(["https://example.com"], {"https://example.com": pr}, client)
    assert len(findings) == 0, f"Unexpected TC-001 finding: {findings}"

    f_tc4 = _check_tc004_tc006(["https://example.com"], {"https://example.com": pr})
    tc4_ambig = [f for f in f_tc4 if (f.get("local_id") or f.get("id")) == "TC-004"]
    assert len(tc4_ambig) == 0, f"Unexpected TC-004 finding: {tc4_ambig}"


def test_tec_fixture_b_org_jsonld_without_sameas():
    """Fixture B: JSON-LD exists but lacks sameAs -> TC-001 fires for missing sameAs."""
    html = """
    <html>
    <head>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "Beta Corp",
            "url": "https://example.com"
        }
        </script>
    </head>
    <body><h1>Beta Corp</h1></body>
    </html>
    """
    pr = PageResult(
        url="https://example.com",
        status_code=200,
        fetch_state=FetchState.FETCHED_OK,
        soup=BeautifulSoup(html, "html.parser"),
        html=html,
    )
    client = DummyHttpClient({"https://example.com": pr})
    findings = _check_tc001(["https://example.com"], {"https://example.com": pr}, client)
    assert any((f.get("local_id") or f.get("id")) == "TC-001" and "sameAs" in f["title"] for f in findings)


def test_tec_fixture_c_casing_variants():
    """Fixture C: JSON-LD exists with excessive casing variants -> TC-004 fires."""
    html1 = """
    <html><head><script type="application/ld+json">
    {"@context": "https://schema.org", "@type": "Organization", "name": "ACME", "sameAs": ["https://wikidata.org/wiki/Q1"]}
    </script></head><body><h1>ACME</h1></body></html>
    """
    html2 = """
    <html><head><script type="application/ld+json">
    {"@context": "https://schema.org", "@type": "Organization", "name": "Acme", "sameAs": ["https://wikidata.org/wiki/Q1"]}
    </script></head><body><h1>Acme</h1></body></html>
    """
    html3 = """
    <html><head><script type="application/ld+json">
    {"@context": "https://schema.org", "@type": "Organization", "name": "acme", "sameAs": ["https://wikidata.org/wiki/Q1"]}
    </script></head><body><h1>acme</h1></body></html>
    """
    u1, u2, u3 = "https://example.com/p1", "https://example.com/p2", "https://example.com/p3"
    pr1 = PageResult(url=u1, status_code=200, fetch_state=FetchState.FETCHED_OK, soup=BeautifulSoup(html1, "html.parser"), html=html1)
    pr2 = PageResult(url=u2, status_code=200, fetch_state=FetchState.FETCHED_OK, soup=BeautifulSoup(html2, "html.parser"), html=html2)
    pr3 = PageResult(url=u3, status_code=200, fetch_state=FetchState.FETCHED_OK, soup=BeautifulSoup(html3, "html.parser"), html=html3)
    pages = {u1: pr1, u2: pr2, u3: pr3}
    findings = _check_tc004_tc006([u1, u2, u3], pages)
    assert any((f.get("local_id") or f.get("id")) == "TC-004" and "capitalisation" in f["title"].lower() for f in findings)


def test_tec_fixture_d_no_jsonld_with_html_profiles():
    """Fixture D: Site has NO JSON-LD, but HTML contains official LinkedIn profile link.
    TC-001 must identify this unlinked profile without duplicating SF-001 or crashing."""
    html = """
    <html>
    <head><title>Gamma Solutions | Enterprise AI</title></head>
    <body>
        <h1>Gamma Solutions</h1>
        <p>Contact us at 100 Innovation Way, Suite 400, Austin, TX 78701.</p>
        <footer>
            <a href="https://www.linkedin.com/company/gamma-solutions-corp">LinkedIn</a>
            <a href="https://twitter.com/gammasolutions">Twitter</a>
        </footer>
    </body>
    </html>
    """
    u = "https://example.com"
    pr = PageResult(
        url=u,
        status_code=200,
        fetch_state=FetchState.FETCHED_OK,
        soup=BeautifulSoup(html, "html.parser"),
        html=html,
    )
    client = DummyHttpClient({u: pr})
    findings = _check_tc001([u], {u: pr}, client)
    assert len(findings) == 1
    f = findings[0]
    assert (f.get("local_id") or f.get("id")) == "TC-001"
    assert "linkedin.com/company/gamma-solutions-corp" in f["evidence"]

    # Since the site has an address and external profiles in HTML, TC-004 should NOT double-penalize
    tc4_findings = _check_tc004_tc006([u], {u: pr})
    assert len(tc4_findings) == 0, f"Expected 0 TC-004 findings when entity has HTML grounding, got: {tc4_findings}"


def test_tec_fixture_e_malformed_jsonld():
    """Fixture E: Malformed JSON-LD should be caught gracefully without unhandled exceptions."""
    html = """
    <html>
    <head>
        <script type="application/ld+json">
        { "not": "valid" "json": 123,, }
        </script>
    </head>
    <body><h1>Broken JSON-LD</h1></body>
    </html>
    """
    u = "https://example.com/malformed"
    pr = PageResult(
        url=u,
        status_code=200,
        fetch_state=FetchState.FETCHED_OK,
        soup=BeautifulSoup(html, "html.parser"),
        html=html,
    )
    client = DummyHttpClient({u: pr})
    # Must not raise an exception
    res = tec_audit(u, client, crawl_frontier=[u], page_results={u: pr})
    assert "domain" in res
    assert res["checks_attempted"] == 6


# ==============================================================================
# 5. COVERAGE TELEMETRY ACCURACY
# ==============================================================================

def test_coverage_telemetry_checks_run_not_len_findings():
    """Verify that checks_run represents checks evaluated/attempted, NOT len(findings)."""
    # Simulate a domain result with 8 attempted checks and 0 findings
    domain_results = {
        "crawl-render-access": {
            "pages_analyzed": 3,
            "pages_discovered": 3,
            "checks_available": 8,
            "checks_attempted": 8,
            "checks_skipped": 0,
            "checks_blocked": 0,
            "findings": [],
            "errors": [],
        },
        "structured-fact-extraction": {
            "pages_analyzed": 3,
            "pages_discovered": 3,
            "checks_available": 8,
            "checks_attempted": 8,
            "checks_skipped": 0,
            "checks_blocked": 0,
            "findings": [],
            "errors": [],
        },
        "trust-entity-corroboration": {
            "pages_analyzed": 3,
            "pages_discovered": 3,
            "checks_available": 6,
            "checks_attempted": 6,
            "checks_skipped": 0,
            "checks_blocked": 0,
            "findings": [],
            "errors": [],
        },
        "engagement-retention": {
            "pages_analyzed": 3,
            "pages_discovered": 3,
            "checks_available": 8,
            "checks_attempted": 8,
            "checks_skipped": 0,
            "checks_blocked": 0,
            "findings": [],
            "errors": [],
        },
    }

    cov = _build_coverage(domain_results, [], frontier=["https://example.com"])
    cra_cov = cov["crawl_render_access"]
    assert cra_cov["checks_run"] == 8, f"checks_run should be 8, not 0 findings: {cra_cov['checks_run']}"
    assert cra_cov["findings_produced"] == 0
    assert cra_cov["checks_available"] == 8
    assert cra_cov["checks_attempted"] == 8
    assert cra_cov["checks_skipped"] == 0

    sfe_cov = cov["structured_fact_extraction"]
    assert sfe_cov["checks_run"] == 8
    assert sfe_cov["findings_produced"] == 0

    tec_cov = cov["trust_entity_corroboration"]
    assert tec_cov["checks_run"] == 6
    assert tec_cov["findings_produced"] == 0


def test_schema_validates_new_coverage_telemetry():
    """Ensure report with full coverage telemetry validates against report.schema.json."""
    sample_report = {
        "schema_version": "2.0.0",
        "generated_at": "2026-09-13T12:00:00Z",
        "audited_at": "2026-09-13T12:00:00Z",
        "target_url": "https://example.com",
        "site": "example.com",
        "audit_status": "completed",
        "pages_audited": 1,
        "audit_duration_seconds": 1.25,
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "coverage": {
                "pages_audited": 1,
                "pages_in_sitemap": None,
                "budget_limited": False,
            },
        },
        "findings": [],
        "proactive_recommendations": [
            "Deploy /llms.txt manifest to guide autonomous AI search crawlers to authoritative content."
        ],
        "remediation_themes": [],
        "coverage": {
            "crawl_render_access": {
                "pages_checked": 1,
                "checks_run": 8,
                "checks_available": 8,
                "checks_attempted": 8,
                "checks_skipped": 0,
                "checks_blocked": 0,
                "findings_produced": 0,
                "errors": 0,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "COMPLETE",
            },
            "structured_fact_extraction": {
                "pages_checked": 1,
                "checks_run": 8,
                "checks_available": 8,
                "checks_attempted": 8,
                "checks_skipped": 0,
                "checks_blocked": 0,
                "findings_produced": 0,
                "errors": 0,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "COMPLETE",
            },
            "trust_entity_corroboration": {
                "pages_checked": 1,
                "checks_run": 6,
                "checks_available": 6,
                "checks_attempted": 6,
                "checks_skipped": 0,
                "checks_blocked": 0,
                "findings_produced": 0,
                "errors": 0,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "COMPLETE",
            },
            "engagement_retention": {
                "pages_checked": 1,
                "checks_run": 8,
                "checks_available": 8,
                "checks_attempted": 8,
                "checks_skipped": 0,
                "checks_blocked": 0,
                "findings_produced": 0,
                "errors": 0,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "COMPLETE",
            },
            "pages_with_low_render_confidence": 0,
            "render_confidence": "high",
            "overall_state": "COMPLETE",
            "limitations": [],
        },
    }
    is_valid, errors = validate_report(sample_report)
    assert is_valid, f"Validation failed with errors: {errors}"
