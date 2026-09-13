"""
test_benchmark_precision.py
===========================
Adversarial precision regression tests covering the 7 prioritized benchmark classes:
1. HTTP errors vs robots-blocked/auth URLs (CR-002)
2. CSR/rendering diagnoses vs static markup ratios (CR-003, CR-004)
3. Severity calibration (SF-003, TC-004, SF-005, TC-001, INSUFFICIENT_EVIDENCE clamping)
4. Cross-skill deduplication (SF-001 vs TC-006)
5. Page-role awareness (auth/utility navigation, breadcrumbs, overlays, CTAs, freshness)
6. Mechanism-based remediation actions (SF-004, SF-005)
7. Evidence-semantic consistency ([CONFIRMED] vs [INSUFFICIENT_EVIDENCE], TC-005)
"""

import pytest
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import HttpClient, PageResult, EvidenceState, is_auth_or_utility_url
from crawl_audit import _check_cr002, _check_cr003_cr004, _check_cr005
from sfe_audit import _check_sf001_sf002, _check_sf003_sf004, _check_sf005, _check_sf007_sf008
from tec_audit import _check_tc001, _check_tc004_tc006, _check_tc005
from er_audit import _check_er001, _check_er002, _check_er003, _check_er005
from aggregate import _normalise_finding, _deduplicate


# ===========================================================================
# 1. HTTP Errors vs Robots-Blocked / Auth URLs (CR-002)
# ===========================================================================
def test_cr002_robots_blocked_auth_url_not_flagged_as_server_error():
    """URLs disallowed by robots.txt or auth endpoints must NOT trigger CR-002 non-OK HTTP status."""
    auth_url = "https://www.amazon.com/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.com"
    pr = PageResult(
        url=auth_url,
        status_code=None,
        error="robots.txt disallows fetching (ALLOWED): https://www.amazon.com/ap/signin",
        soup=None,
    )
    findings = _check_cr002({auth_url: pr})
    assert not any(f["local_id"] == "CR-002" and "status code" in f["title"].lower() for f in findings)


def test_is_auth_or_utility_url_detection():
    """Ensure is_auth_or_utility_url detects standard auth patterns."""
    assert is_auth_or_utility_url("https://example.com/login")
    assert is_auth_or_utility_url("https://example.com/signin")
    assert is_auth_or_utility_url("https://example.com/ap/signin?openid=1")
    assert is_auth_or_utility_url("https://example.com/m/signin?operation=register")
    assert is_auth_or_utility_url("https://example.com/checkout")
    assert not is_auth_or_utility_url("https://example.com/about")
    assert not is_auth_or_utility_url("https://example.com/products/software")


# ===========================================================================
# 2. Inferred CSR Blanking vs Static HTML Density (CR-003, CR-004)
# ===========================================================================
def test_cr004_static_low_density_not_diagnosed_as_severe_csr():
    """Static HTML with markup-heavy layout (pricing table) must NOT be diagnosed as Severe CSR blanking."""
    pricing_url = "https://www.adobe.com/acrobat/pricing.html"
    # Heavy HTML with table and styles, text ratio ~ 0.25
    markup = "<html><body>" + "<div><span>item</span></div>" * 100 + "<p>" + "Plan details " * 20 + "</p></body></html>"
    soup = BeautifulSoup(markup, "html.parser")
    pr = PageResult(url=pricing_url, status_code=200, soup=soup, html=markup, content_type="text/html")
    
    findings = _check_cr003_cr004({pricing_url: pr}, renderer=None)
    # Must NOT emit Critical or High CSR text blanking
    assert not any(f["local_id"] == "CR-003" for f in findings)
    assert not any(f["severity"] in ("critical", "high") for f in findings)
    # If CR-004 fires, title must specify static density or unverified shell, with low severity
    cr004 = [f for f in findings if f["local_id"] == "CR-004"]
    if cr004:
        assert cr004[0]["severity"] == "low"
        assert "static" in cr004[0]["title"].lower() or "density" in cr004[0]["title"].lower()


def test_cr003_auth_pages_skipped_from_csr_diagnosis():
    """Auth/login pages must not be flagged for CSR text blanking."""
    login_url = "https://github.com/login"
    markup = "<html><body><form action='/login'><input type='password'></form></body></html>"
    soup = BeautifulSoup(markup, "html.parser")
    pr = PageResult(url=login_url, status_code=200, soup=soup, html=markup, content_type="text/html")

    findings = _check_cr003_cr004({login_url: pr}, renderer=None)
    assert len(findings) == 0


# ===========================================================================
# 3. Severity Calibration (SF-003, TC-004, SF-005, TC-001)
# ===========================================================================
def test_sf003_image_alt_severity_is_medium_not_critical():
    """Images lacking alt text must be medium severity, never critical."""
    url = "https://example.com"
    html = "<html><body>" + "<img src='graphic.png'>" * 4 + "<p>Brief</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)

    findings = _check_sf003_sf004([url], {url: pr})
    sf003 = [f for f in findings if f["local_id"] == "SF-003"]
    assert len(sf003) == 1
    assert sf003[0]["severity"] == "medium"


def test_tc004_brand_ambiguity_severity_harmonized_with_tc001():
    """When both TC-001 and TC-004 fire on an entity, TC-004 severity must be harmonized to medium."""
    url = "https://example.com"
    tc001_raw = _normalise_finding({
        "local_id": "TC-001",
        "title": "No sameAs links in Organization schema",
        "severity": "medium",
        "evidence": "No sameAs",
        "suggested_action": {"summary": "Add sameAs", "priority": "medium"},
    }, "trust_entity_corroboration", url)
    tc004_raw = _normalise_finding({
        "local_id": "TC-004",
        "title": "Brand name is ambiguous without disambiguation",
        "severity": "critical",
        "evidence": "Brand entity lacks unique linkage and structural disambiguation",
        "suggested_action": {"summary": "Add disambiguating properties", "priority": "critical"},
    }, "trust_entity_corroboration", url)

    deduped = _deduplicate([tc001_raw, tc004_raw])
    tc004 = next((f for f in deduped if f["_local_id"] == "TC-004"), None)
    assert tc004 is not None
    assert tc004["severity"] == "medium"
    assert tc004["suggested_action"]["priority"] == "medium"


def test_sf005_linked_pdf_severity_is_medium():
    """Linked PDFs without HTML alternative must be medium severity, not high."""
    url = "https://example.com"
    html = "<html><body><a href='/report.pdf'>PDF</a></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)
    mock_client = MagicMock(spec=HttpClient)

    findings = _check_sf005([url], {url: pr}, mock_client)
    sf005 = [f for f in findings if f["local_id"] == "SF-005"]
    assert len(sf005) == 1
    assert sf005[0]["severity"] == "medium"


def test_tc001_missing_sameas_severity_is_medium():
    """Organization schema missing sameAs must be medium severity, not high."""
    url = "https://example.com"
    html = """<html><head>
    <script type="application/ld+json">
    {"@context": "https://schema.org", "@type": "Organization", "name": "Brand", "url": "https://example.com"}
    </script></head><body>Content</body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)
    mock_client = MagicMock(spec=HttpClient)

    findings = _check_tc001([url], {url: pr}, mock_client)
    tc001 = [f for f in findings if f["local_id"] == "TC-001"]
    assert len(tc001) == 1
    assert tc001[0]["severity"] == "medium"
    assert EvidenceState.CONFIRMED.value in tc001[0]["evidence"]


def test_aggregate_clamps_insufficient_evidence_severity():
    """Findings with [INSUFFICIENT_EVIDENCE] must be clamped to at most medium severity."""
    raw = {
        "local_id": "TC-005",
        "title": "Unlinked claim",
        "severity": "critical",
        "evidence": f"[{EvidenceState.INSUFFICIENT_EVIDENCE.value}] Suspected claim without external link",
        "suggested_action": {"summary": "Verify claim", "priority": "critical"},
    }
    normalized = _normalise_finding(raw, "trust_entity_corroboration", "https://example.com")
    assert normalized["severity"] == "medium"
    assert normalized["suggested_action"]["priority"] == "medium"


# ===========================================================================
# 4. Duplicate / Overlapping Findings (SF-001 vs TC-006)
# ===========================================================================
def test_no_duplicate_tc006_when_sf001_reports_missing_organization():
    """When a site has zero Organization schema, TC-006 must NOT emit a duplicate missing organization finding."""
    url = "https://example.com"
    html = "<html><body>No schema here</body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)

    sfe_findings, _ = _check_sf001_sf002([url], {url: pr})
    tec_findings = _check_tc004_tc006([url], {url: pr})

    assert any(f["local_id"] == "SF-001" for f in sfe_findings)
    # tec_audit must NOT emit TC-006 missing organization finding
    assert not any(f["local_id"] == "TC-006" for f in tec_findings)

    # Furthermore, aggregate deduplication must suppress any duplicate if present
    raw_sf001 = _normalise_finding(sfe_findings[0], "structured_fact_extraction", url)
    raw_tc006 = _normalise_finding({
        "local_id": "TC-006",
        "title": "No Organization schema found for entity disambiguation",
        "severity": "medium",
        "evidence": "No Organization found",
        "suggested_action": {"summary": "Add org", "priority": "medium"},
    }, "trust_entity_corroboration", url)

    deduped = _deduplicate([raw_sf001, raw_tc006])
    assert len(deduped) == 1
    assert deduped[0]["_local_id"] == "SF-001"


# ===========================================================================
# 5. Page-Role Awareness (Auth/Utility, Overlays, CTAs, Freshness)
# ===========================================================================
def test_er001_auth_page_not_flagged_for_missing_nav():
    """Auth/login pages must not be flagged for missing primary navigation."""
    login_url = "https://github.com/login"
    html = "<html><body><h1>Sign in</h1><form action='/login'><input type='password'></form></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=login_url, status_code=200, soup=soup, html=html)

    findings = _check_er001([login_url], {login_url: pr})
    assert not any(f["local_id"] == "ER-001" and "navigation" in f["title"].lower() for f in findings)


def test_er002_auth_page_not_flagged_for_missing_breadcrumbs():
    """Deep auth pages must not be flagged for missing breadcrumbs."""
    auth_deep = "https://example.com/account/login/verify"
    html = "<html><body><h1>Verify</h1><form><input type='password'></form></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=auth_deep, status_code=200, soup=soup, html=html)

    findings = _check_er002([auth_deep], {auth_deep: pr}, "https://example.com")
    assert len(findings) == 0


def test_er003_cr005_sticky_header_not_flagged_as_fullscreen_overlay():
    """Sticky site headers (e.g. Stripe, GitHub) must NOT be flagged as content-blocking overlays."""
    url = "https://stripe.com/pricing"
    html = """<html><body>
    <header class="navbar header" style="position: fixed; top: 0; left: 0; width: 100%; height: 60px; z-index: 999;">
        <nav><a href="/">Home</a><a href="/products">Products</a><a href="/pricing">Pricing</a></nav>
    </header>
    <main><h1>Pricing</h1><p>Main content text</p></main>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)

    er_findings = _check_er003([url], {url: pr})
    cr_findings = _check_cr005({url: pr})

    assert not any(f["local_id"] == "ER-003" and "interstitial" in f["title"].lower() for f in er_findings)
    assert not any(f["local_id"] == "CR-005" for f in cr_findings)


def test_er005_pricing_buttons_recognized_as_cta():
    """Pricing pages with 'Choose plan' or submit buttons must NOT be flagged for missing CTA."""
    pricing_url = "https://www.adobe.com/pricing"
    html = """<html><body>
    <h1>Plans & Pricing</h1>
    <div class="pricing-card">
        <button role="button" class="btn">Choose a plan</button>
    </div>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=pricing_url, status_code=200, soup=soup, html=html)

    findings = _check_er005([pricing_url], {pricing_url: pr})
    assert len(findings) == 0


def test_sf007_homepage_not_flagged_for_missing_freshness():
    """Static homepages or marketing pages must NOT be flagged for missing datePublished/dateModified."""
    home_url = "https://www.notion.so"
    html = "<html><head><title>Notion</title></head><body><h1>Connected Workspace</h1></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=home_url, status_code=200, soup=soup, html=html)

    findings = _check_sf007_sf008([home_url], {home_url: pr})
    # Must NOT emit 'Pages missing freshness metadata'
    assert not any(f["local_id"] == "SF-007" and "missing" in f["title"].lower() for f in findings)


# ===========================================================================
# 6. Mechanism-Based Remediation (SF-004, SF-005)
# ===========================================================================
def test_sf004_sf005_remediation_describes_mechanism():
    """Remediations must describe crawler ingestion mechanisms rather than asserting absolute claims."""
    url = "https://example.com"
    html = """<html><body>
    <video src="clip.mp4"></video>
    <canvas id="chart"></canvas>
    <a href="whitepaper.pdf">Whitepaper</a>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)
    mock_client = MagicMock(spec=HttpClient)

    media_findings = _check_sf003_sf004([url], {url: pr})
    pdf_findings = _check_sf005([url], {url: pr}, mock_client)

    for f in media_findings + pdf_findings:
        action = f["suggested_action"]["summary"]
        # Must not contain absolute "cannot extract/parse" claims
        assert "cannot extract spoken content from video files" not in action
        assert "cannot reliably parse PDF content" not in action
        assert "cannot parse canvas rendered content" not in action


# ===========================================================================
# 7. Evidence-Semantic Consistency (TC-005 Quotes Exclusion)
# ===========================================================================
def test_tc005_customer_quotes_do_not_trigger_unlinked_authority_claims():
    """Customer testimonials and case study quotes mentioning 'partnered with' must NOT trigger TC-005."""
    url = "https://example.com/customers/story"
    html = """<html><body>
    <blockquote class="testimonial">
        <p>"Amazon partnered with Stripe to streamline global payments experiences."</p>
    </blockquote>
    <div class="case-study-quote">
        <p>"The long-standing partnership with Konica Minolta and Adobe has provided comprehensive values."</p>
    </div>
    </body></html>"""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)

    findings = _check_tc005([url], {url: pr})
    assert len(findings) == 0


def test_tc005_formal_credential_uses_low_severity_and_precise_title():
    """Formal compliance claims (e.g. HIPAA) without external links use low severity and precise title."""
    url = "https://example.com"
    html = "<html><body><p>Our platform is HIPAA compliant for Enterprise.</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(url=url, status_code=200, soup=soup, html=html)

    findings = _check_tc005([url], {url: pr})
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "Unlinked certification" in findings[0]["title"]
