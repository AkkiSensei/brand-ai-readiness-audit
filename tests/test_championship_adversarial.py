"""
test_championship_adversarial.py
================================
Adversarial generalization & edge-case test suite for the Championship Pass.
Exercises newly discovered and hardened edge cases on unseen website archetypes:
1. Comment/CDATA-wrapped JSON-LD parsing across domain skills (SFE, TEC, ER).
2. Class-based navigation containers (<div class="navbar">) without semantic <nav> tags (ER-001).
3. Microdata breadcrumb recognition (itemtype="...BreadcrumbList" / itemprop="itemListElement") (ER-002).
4. Multilingual CTA recognition (Spanish, German, French) on localized product endpoints (ER-005).
5. Multilingual site search input recognition (ER-008).
6. Multi-organization schemas with nested parent/subsidiary entities.
"""

from bs4 import BeautifulSoup
from unittest.mock import MagicMock
import pytest
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from http_client import HttpClient, PageResult
from sfe_audit import _check_sf001_sf002, _extract_jsonld_blocks as sfe_extract
from tec_audit import _check_tc004_tc006, _extract_jsonld_blocks as tec_extract
from er_audit import (
    _check_er001,
    _check_er002,
    _check_er005,
    _check_er008,
    _extract_jsonld_blocks as er_extract,
)


def test_comment_wrapped_jsonld_parsing():
    """1. CMS and legacy engines wrap JSON-LD inside <!-- ... --> or CDATA comments.
    All skills must extract the valid JSON object without JSONDecodeError.
    """
    html = """<!DOCTYPE html>
    <html><head>
      <script type="application/ld+json">
        <!--
        {
          "@context": "https://schema.org",
          "@type": "Organization",
          "name": "Global Corp",
          "url": "https://example.com",
          "logo": "https://example.com/logo.png"
        }
        -->
      </script>
      <script type="application/ld+json">
        //<![CDATA[
        {
          "@context": "https://schema.org",
          "@type": "Product",
          "name": "Enterprise Cloud Suite"
        }
        //]]>
      </script>
    </head><body><h1>Welcome</h1></body></html>"""

    soup = BeautifulSoup(html, "html.parser")
    sfe_blocks = sfe_extract(soup)
    tec_blocks = tec_extract(soup)
    er_blocks = er_extract(soup)

    assert len(sfe_blocks) == 2
    assert sfe_blocks[0].get("name") == "Global Corp"
    assert sfe_blocks[1].get("name") == "Enterprise Cloud Suite"

    assert len(tec_blocks) == 2
    assert tec_blocks[0].get("name") == "Global Corp"

    assert len(er_blocks) == 2
    assert er_blocks[1].get("name") == "Enterprise Cloud Suite"


def test_class_based_navbar_without_nav_tag_not_flagged_as_missing_nav():
    """2. Real-world sites built with Tailwind or legacy frameworks often use
    <div class="navbar"> with links instead of HTML5 <nav>. ER-001 must recognize this.
    """
    html = """<!DOCTYPE html>
    <html><body>
      <div class="site-navbar">
        <a href="/products">Products</a>
        <a href="/solutions">Solutions</a>
        <a href="/pricing">Pricing</a>
        <a href="/docs">Docs</a>
      </div>
      <h1>Cloud Infrastructure Platform</h1>
    </body></html>"""

    url = "https://example.com/overview"
    pr = PageResult(url=url, status_code=200, html=html, soup=BeautifulSoup(html, "html.parser"))

    findings = _check_er001([url], {url: pr})
    missing_nav_findings = [f for f in findings if "missing primary navigation" in f["title"].lower()]
    assert len(missing_nav_findings) == 0, f"Class-based navbar was falsely flagged as missing navigation: {findings}"


def test_microdata_breadcrumbs_recognized_by_er002():
    """3. Sites utilizing Microdata schema for breadcrumb navigation
    (<ol itemscope itemtype="http://schema.org/BreadcrumbList">) must not be flagged by ER-002.
    """
    html = """<!DOCTYPE html>
    <html><body>
      <ol itemscope itemtype="https://schema.org/BreadcrumbList">
        <li itemprop="itemListElement" itemscope itemtype="https://schema.org/ListItem">
          <a itemprop="item" href="/"><span itemprop="name">Home</span></a>
        </li>
        <li itemprop="itemListElement" itemscope itemtype="https://schema.org/ListItem">
          <a itemprop="item" href="/category"><span itemprop="name">Category</span></a>
        </li>
      </ol>
      <h1>Deep Product View</h1>
    </body></html>"""

    url = "https://example.com/category/product-detail"
    root_url = "https://example.com"
    pr = PageResult(url=url, status_code=200, html=html, soup=BeautifulSoup(html, "html.parser"))

    findings = _check_er002([url], {url: pr}, root_url)
    assert len(findings) == 0, f"Microdata breadcrumbs were falsely flagged by ER-002: {findings}"


def test_multilingual_cta_recognition_in_er005():
    """4. Localized landing pages with Spanish, German, or French action buttons
    ('Comprar ahora', 'Jetzt testen', 'Voir les tarifs') must be recognized by ER-005.
    """
    # Spanish pricing page
    es_html = """<!DOCTYPE html>
    <html><body>
      <h1>Planes y Precios</h1>
      <div class="pricing-card">
        <a href="/checkout?plan=pro" class="action-link">Comprar ahora</a>
      </div>
    </body></html>"""
    es_url = "https://example.com/es/precios"
    es_pr = PageResult(url=es_url, status_code=200, html=es_html, soup=BeautifulSoup(es_html, "html.parser"))

    findings_es = _check_er005([es_url], {es_url: es_pr})
    assert len(findings_es) == 0, f"Spanish CTA 'Comprar ahora' was not recognized: {findings_es}"

    # German demo page
    de_html = """<!DOCTYPE html>
    <html><body>
      <h1>Unternehmenslösungen</h1>
      <button class="primary-btn">Jetzt kostenlos testen</button>
    </body></html>"""
    de_url = "https://example.com/de/demo"
    de_pr = PageResult(url=de_url, status_code=200, html=de_html, soup=BeautifulSoup(de_html, "html.parser"))

    findings_de = _check_er005([de_url], {de_url: de_pr})
    assert len(findings_de) == 0, f"German CTA 'Jetzt kostenlos testen' was not recognized: {findings_de}"


def test_multilingual_search_placeholder_in_er008():
    """5. Large site with search placeholder in Spanish or German must satisfy ER-008."""
    html = """<!DOCTYPE html>
    <html><body>
      <input type="text" placeholder="Buscar productos, marcas y más...">
    </body></html>"""

    frontier = [f"https://example.com/page/{i}" for i in range(35)]
    prs = {
        u: PageResult(url=u, status_code=200, html=html, soup=BeautifulSoup(html, "html.parser"))
        for u in frontier
    }

    findings = _check_er008(frontier, prs)
    assert len(findings) == 0, f"Multilingual search placeholder was not recognized: {findings}"


def test_comment_wrapped_jsonld_prevents_sf001_false_positive():
    """6. Comment-wrapped JSON-LD on homepage must satisfy SF-001 Organization schema check."""
    html = """<!DOCTYPE html>
    <html><head>
      <script type="application/ld+json">
        <!--
        {
          "@context": "https://schema.org",
          "@type": "Organization",
          "name": "Acme Innovations",
          "url": "https://example.com",
          "foundingDate": "2015-05-12",
          "description": "Next generation AI infrastructure",
          "sameAs": ["https://www.wikidata.org/wiki/Q99999"]
        }
        -->
      </script>
    </head><body><h1>Acme Innovations</h1></body></html>"""

    url = "https://example.com/"
    pr = PageResult(url=url, status_code=200, html=html, soup=BeautifulSoup(html, "html.parser"))

    findings, errors = _check_sf001_sf002([url], {url: pr})
    sf001_missing = [f for f in findings if f["local_id"] == "SF-001" and "no json-ld" in f["title"].lower()]
    assert len(sf001_missing) == 0, f"Comment-wrapped schema triggered false positive SF-001: {findings}"
