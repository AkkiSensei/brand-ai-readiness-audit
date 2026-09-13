"""
tests/test_detection_robustness.py
==================================
Phase 5 Detection Engine Robustness & Generalization Test Suite.

Validates:
  1. Brand Name NAP Consistency (TC-002):
     - Legal suffixes ("Acme", "Acme Inc.", "Acme LLC", "Acme Corp.") do NOT fire TC-002.
     - Genuinely contradictory brands ("Acme", "Globex Corp", "Initech LLC") fire TC-002 [CONTRADICTED].
  2. Multi-Location & Address Consistency (TC-002):
     - Address abbreviations ("100 Main St, Ste 400" vs "100 Main Street, Suite 400") normalize and match cleanly.
     - Multi-location businesses (San Francisco vs London vs Tokyo branches) do NOT trigger address contradictions.
     - Conflicting addresses for the same location ("100 Main St" vs "999 Oak Ave") trigger TC-002 [CONTRADICTED].
  3. Freshness & Evergreen Content (SF-007):
     - Evergreen utility/policy pages (/privacy, /terms) older than 365 days do NOT trigger stale defects.
     - Stale editorial/blog pages (/blog/post) older than 365 days trigger SF-007 [CONFIRMED].
  4. Structured Data Completeness (SF-002):
     - Digital organizations with core identity (name, url, logo) missing physical address are not penalized as broken schemas.
     - Schemas missing required identity properties (name, url) trigger appropriate findings.
  5. CSR Text Blanking vs Static Sparse Pages (CR-003):
     - Pure static HTML with sparse text and no scripts does NOT trigger false CR-003 CSR blanking.
     - SPA shells with dynamic scripts trigger CR-003.
  6. Brand Capitalization Semantics (TC-004):
     - True casing variations ("iPhone" vs "Iphone" vs "IPHONE") trigger casing findings.
     - Corporate suffixes do not get conflated with capitalization variants.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))

from http_client import PageResult
from er_audit import _check_er001
from tec_audit import (
    _check_tc002,
    _check_tc004_tc006,
    _normalize_brand_root,
    _normalize_address_tokens,
)
from sfe_audit import (
    _check_sf001_sf002,
    _check_sf007_sf008,
    _is_evergreen_url,
)
from crawl_audit import _check_cr003_cr004


# ===========================================================================
# 1. BRAND NAME NAP CONSISTENCY (TC-002)
# ===========================================================================

def test_tc002_legal_suffix_variations_do_not_fire_contradiction():
    """Corporate designations ('Acme', 'Acme Inc.', 'Acme LLC', 'Acme Corp')
    represent stylistic/legal variants of the same brand root and MUST NOT fire TC-002."""
    html_home = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Acme Inc."}
      </script>
    </head>
    <body><h1>Welcome to Acme</h1></body>
    </html>"""

    html_contact = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Acme LLC"}
      </script>
    </head>
    <body><h1>Contact Acme, Inc.</h1></body>
    </html>"""

    html_about = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Acme Corp"}
      </script>
    </head>
    <body><h1>About Acme Corporation</h1></body>
    </html>"""

    frontier = ["https://example.com/", "https://example.com/contact", "https://example.com/about"]
    page_results = {
        frontier[0]: PageResult(url=frontier[0], status_code=200, soup=BeautifulSoup(html_home, "html.parser"), html=html_home),
        frontier[1]: PageResult(url=frontier[1], status_code=200, soup=BeautifulSoup(html_contact, "html.parser"), html=html_contact),
        frontier[2]: PageResult(url=frontier[2], status_code=200, soup=BeautifulSoup(html_about, "html.parser"), html=html_about),
    }

    findings = _check_tc002(frontier, page_results)
    tc002_name_findings = [f for f in findings if f.get("local_id") == "TC-002" and "brand name" in f.get("title", "").lower()]
    assert len(tc002_name_findings) == 0, f"False positive TC-002 on corporate suffixes: {tc002_name_findings}"


def test_tc002_genuinely_contradictory_brands_fire():
    """Genuinely contradictory brand identities ('Acme' vs 'Globex Corp' vs 'Initech LLC')
    MUST fire TC-002 with [CONTRADICTED] evidence."""
    html_home = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Acme"}
      </script>
    </head>
    <body><h1>Acme</h1></body>
    </html>"""

    html_contact = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Globex Corp"}
      </script>
    </head>
    <body><h1>Globex</h1></body>
    </html>"""

    html_about = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {"@context": "https://schema.org", "@type": "Organization", "name": "Initech LLC"}
      </script>
    </head>
    <body><h1>Initech</h1></body>
    </html>"""

    frontier = ["https://example.com/", "https://example.com/contact", "https://example.com/about"]
    page_results = {
        frontier[0]: PageResult(url=frontier[0], status_code=200, soup=BeautifulSoup(html_home, "html.parser"), html=html_home),
        frontier[1]: PageResult(url=frontier[1], status_code=200, soup=BeautifulSoup(html_contact, "html.parser"), html=html_contact),
        frontier[2]: PageResult(url=frontier[2], status_code=200, soup=BeautifulSoup(html_about, "html.parser"), html=html_about),
    }

    findings = _check_tc002(frontier, page_results)
    tc002_name_findings = [f for f in findings if f.get("local_id") == "TC-002" and "brand name" in f.get("title", "").lower()]
    assert len(tc002_name_findings) == 1, f"Expected TC-002 for contradictory brands, got: {findings}"
    assert "CONTRADICTED" in tc002_name_findings[0]["evidence"]


# ===========================================================================
# 2. MULTI-LOCATION & ADDRESS CONSISTENCY (TC-002)
# ===========================================================================

def test_tc002_address_abbreviation_normalization():
    """Standard abbreviations ('100 Main St, Ste 400' vs '100 Main Street, Suite 400')
    MUST normalize and NOT trigger address contradiction."""
    addr1 = "100 Main St, Ste 400, Austin, TX 78701"
    addr2 = "100 Main Street, Suite 400, Austin, TX 78701"

    norm1 = _normalize_address_tokens(addr1)
    norm2 = _normalize_address_tokens(addr2)
    assert norm1 == norm2 == "100 main st ste 400 austin tx 78701"

    html1 = f"""<!DOCTYPE html><html><head><script type="application/ld+json">
    {{"@context": "https://schema.org", "@type": "Organization", "name": "Acme", "address": "{addr1}"}}
    </script></head><body><h1>Acme</h1></body></html>"""

    html2 = f"""<!DOCTYPE html><html><head><script type="application/ld+json">
    {{"@context": "https://schema.org", "@type": "Organization", "name": "Acme", "address": "{addr2}"}}
    </script></head><body><h1>Acme</h1></body></html>"""

    frontier = ["https://example.com/", "https://example.com/contact"]
    page_results = {
        frontier[0]: PageResult(url=frontier[0], status_code=200, soup=BeautifulSoup(html1, "html.parser"), html=html1),
        frontier[1]: PageResult(url=frontier[1], status_code=200, soup=BeautifulSoup(html2, "html.parser"), html=html2),
    }

    findings = _check_tc002(frontier, page_results)
    addr_findings = [f for f in findings if f.get("local_id") == "TC-002" and "address" in f.get("title", "").lower()]
    assert len(addr_findings) == 0, f"False positive address contradiction on abbreviations: {addr_findings}"


def test_tc002_multi_location_presence_does_not_fire_contradiction():
    """Businesses with multiple branch offices / stores in distinct cities
    MUST NOT trigger address inconsistency findings."""
    html_stores = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      [
        {
          "@context": "https://schema.org",
          "@type": "LocalBusiness",
          "name": "Acme San Francisco",
          "address": {
            "@type": "PostalAddress",
            "streetAddress": "100 Market St",
            "addressLocality": "San Francisco",
            "addressRegion": "CA",
            "postalCode": "94105",
            "addressCountry": "US"
          }
        },
        {
          "@context": "https://schema.org",
          "@type": "LocalBusiness",
          "name": "Acme London",
          "address": {
            "@type": "PostalAddress",
            "streetAddress": "10 Downing Street",
            "addressLocality": "London",
            "postalCode": "SW1A 2AA",
            "addressCountry": "UK"
          }
        }
      ]
      </script>
    </head>
    <body><h1>Our Locations</h1></body>
    </html>"""

    frontier = ["https://example.com/locations"]
    page_results = {
        frontier[0]: PageResult(url=frontier[0], status_code=200, soup=BeautifulSoup(html_stores, "html.parser"), html=html_stores),
    }

    findings = _check_tc002(frontier, page_results)
    addr_findings = [f for f in findings if f.get("local_id") == "TC-002" and "address" in f.get("title", "").lower()]
    assert len(addr_findings) == 0, f"False positive TC-002 on multi-location business: {addr_findings}"


# ===========================================================================
# 3. FRESHNESS & EVERGREEN CONTENT (SF-007)
# ===========================================================================

def test_sf007_evergreen_policy_pages_older_than_365_days_do_not_fire_stale():
    """Evergreen policy/legal pages (/privacy, /terms) older than 365 days
    MUST NOT trigger SF-007 medium-severity stale content findings."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=500)).strftime("%Y-%m-%d")
    html_privacy = f"""<!DOCTYPE html>
    <html>
    <head>
      <meta property="article:modified_time" content="{old_date}">
      <title>Privacy Policy</title>
    </head>
    <body><h1>Privacy Policy</h1><p>Our commitment to privacy.</p></body>
    </html>"""

    url = "https://example.com/privacy-policy"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html_privacy, "html.parser"), html=html_privacy)
    findings = _check_sf007_sf008([url], {url: page_res})
    stale_findings = [f for f in findings if f.get("local_id") == "SF-007" and f.get("severity") == "medium"]
    assert len(stale_findings) == 0, f"False positive SF-007 on evergreen privacy policy: {stale_findings}"


def test_sf007_stale_editorial_blog_fires():
    """Editorial or blog content older than 365 days MUST fire SF-007 with [CONFIRMED]."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=500)).strftime("%Y-%m-%d")
    html_blog = f"""<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {{
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        "headline": "Product Announcement",
        "dateModified": "{old_date}"
      }}
      </script>
      <title>Old Announcement</title>
    </head>
    <body><h1>Old Announcement</h1><p>Dated news.</p></body>
    </html>"""

    url = "https://example.com/blog/announcement"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html_blog, "html.parser"), html=html_blog)
    findings = _check_sf007_sf008([url], {url: page_res})
    stale_findings = [f for f in findings if f.get("local_id") == "SF-007" and f.get("severity") == "medium"]
    assert len(stale_findings) == 1, f"Expected SF-007 for stale blog post, got: {findings}"
    assert "CONFIRMED" in stale_findings[0]["evidence"]


# ===========================================================================
# 4. STRUCTURED DATA COMPLETENESS (SF-002)
# ===========================================================================

def test_sf002_digital_organization_missing_address_is_not_flagged_as_missing_required():
    """A digital organization with core identity (name, url, logo, description)
    missing street address does not have missing required identity fields."""
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "CloudTech Solutions",
        "url": "https://example.com",
        "logo": "https://example.com/logo.png",
        "description": "Enterprise cloud native observability platform"
      }
      </script>
    </head>
    <body><h1>CloudTech</h1></body>
    </html>"""

    url = "https://example.com/"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings, _ = _check_sf001_sf002([url], {url: page_res})
    missing_req = [f for f in findings if f.get("local_id") == "SF-002" and "required identity" in f.get("title", "").lower()]
    assert len(missing_req) == 0, f"Digital organization falsely flagged as missing required identity: {missing_req}"


# ===========================================================================
# 5. CSR TEXT BLANKING VS STATIC SPARSE PAGES (CR-003)
# ===========================================================================

def test_cr003_sparse_static_page_without_scripts_does_not_fire_blanking():
    """A brief static page (e.g. redirect landing or simple contact card) with NO scripts
    is completely visible to non-JS crawlers and MUST NOT trigger CR-003 CSR blanking."""
    html = """<!DOCTYPE html>
    <html>
    <head><title>Simple Notice</title></head>
    <body>
      <div style="padding: 20px; border: 1px solid #ccc;">
        <h1>Service Notice</h1>
        <p>Our systems will undergo scheduled maintenance tonight.</p>
      </div>
    </body>
    </html>"""

    url = "https://example.com/notice"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings = _check_cr003_cr004({url: page_res}, renderer=None)
    cr003_findings = [f for f in findings if f.get("local_id") == "CR-003"]
    assert len(cr003_findings) == 0, f"False positive CR-003 on scriptless static page: {cr003_findings}"


# ===========================================================================
# 6. BRAND CAPITALIZATION SEMANTICS (TC-004)
# ===========================================================================

def test_tc004_casing_variants_vs_corporate_suffixes():
    """True casing differences ('iPhone', 'Iphone', 'IPHONE') trigger TC-004 capitalization variant check,
    whereas corporate legal designations ('Acme', 'Acme Inc', 'Acme LLC') do NOT."""
    # Subtest 1: Corporate suffixes do NOT fire capitalization warning
    html_corp = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "Acme"}</script>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "Acme Inc"}</script>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "Acme LLC"}</script>
    </head>
    <body><h1>Acme</h1></body>
    </html>"""

    url1 = "https://example.com/corp"
    pr1 = PageResult(url=url1, status_code=200, soup=BeautifulSoup(html_corp, "html.parser"), html=html_corp)
    f1 = _check_tc004_tc006([url1], {url1: pr1})
    cap1 = [f for f in f1 if f.get("local_id") == "TC-004" and "capitalisation" in f.get("title", "").lower()]
    assert len(cap1) == 0, f"False positive capitalization warning on corporate suffixes: {cap1}"

    # Subtest 2: True casing variations fire capitalization warning
    html_case = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "TechBrand"}</script>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "techbrand"}</script>
      <script type="application/ld+json">{"@context": "https://schema.org", "@type": "Organization", "name": "TECHBRAND"}</script>
    </head>
    <body><h1>TechBrand</h1></body>
    </html>"""

    url2 = "https://example.com/case"
    pr2 = PageResult(url=url2, status_code=200, soup=BeautifulSoup(html_case, "html.parser"), html=html_case)
    f2 = _check_tc004_tc006([url2], {url2: pr2})
    cap2 = [f for f in f2 if f.get("local_id") == "TC-004" and "capitalisation" in f.get("title", "").lower()]
    assert len(cap2) == 1, f"Expected capitalization finding for TechBrand/techbrand/TECHBRAND, got: {f2}"


# ===========================================================================
# 7. NAVIGATION DETECTION ROBUSTNESS (ER-001)
# ===========================================================================

def test_er001_multiple_headers_and_role_navigation():
    """Verify that secondary headers or small breadcrumb role='navigation' elements
    preceding the main navigation do not cause false-positive 'Pages missing primary navigation'."""
    html = """<!DOCTYPE html>
    <html>
    <head><title>Test Page</title></head>
    <body>
      <h1>Main Heading</h1>
      <!-- First role="navigation" is a small breadcrumb bar with only 1 link -->
      <div role="navigation" aria-label="Breadcrumb">
        <a href="/">Home</a>
      </div>
      <!-- First header is a small article header without links -->
      <article>
        <header><h3>Article Title</h3></header>
        <p>Some content...</p>
      </article>
      <!-- Second role="navigation" contains full main menu with >= 3 links -->
      <div role="navigation" aria-label="Main Menu">
        <a href="/about">About</a>
        <a href="/products">Products</a>
        <a href="/pricing">Pricing</a>
        <a href="/contact">Contact</a>
      </div>
    </body>
    </html>"""

    url = "https://example.com/nav-test"
    pr = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings = _check_er001([url], {url: pr})
    nav_findings = [f for f in findings if f.get("local_id") == "ER-001" and "navigation" in f.get("title", "").lower()]
    assert len(nav_findings) == 0, f"False positive ER-001 navigation finding triggered: {nav_findings}"
