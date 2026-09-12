"""
tests/test_generalization.py
============================
P1 Generalization Hardening Test Suite.

Validates:
  1. TC-004 Structural Disambiguation (replaces closed English dictionary):
     - Case A (False-negative fix): Common names not in old dictionary ("Diamond", "Sunrise", "Cloud Nine", "Bharat")
       without disambiguation -> TC-004 FIRES.
     - Case B (False-positive fix): Old dictionary words ("Apple", "Amazon") with strong disambiguation (Wikidata sameAs,
       PostalAddress, foundingDate) -> TC-004 does NOT fire.
     - Case C (i18n / Non-English): Culturally diverse/non-English names ("Hikari", "Komorebi") evaluated structurally
       rather than by language dictionary.
     - Case D (Fully disambiguated): Entity with name, legalName, sameAs, address, foundingDate -> TC-004 absent.
     - Case E (No entity): Page without Organization JSON-LD -> TC-004 absent.
     - Case F (Missing sameAs but strongly disambiguated): Entity lacking sameAs but with address, foundingDate, legalName ->
       TC-001 fires, but TC-004 does NOT fire.
  2. TC-002 International Address & PostalAddress Coverage:
     - India format: "123 MG Road, Bengaluru, Karnataka 560001, India" extracted from visible text.
     - UK format: "10 Downing Street, London SW1A 2AA, United Kingdom" extracted from visible text.
     - EU format: "Speicherstrasse 55, 60327 Frankfurt am Main, Germany" extracted from visible text.
     - Structured PostalAddress: JSON-LD PostalAddress correctly extracted even with unusual prose.
     - False-Positive Protection: Product SKUs, order IDs, phone numbers, prices, dates NOT matched as addresses.
"""

from __future__ import annotations

import sys
from pathlib import Path
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))

import hashlib
from http_client import HttpClient, PageResult
from tec_audit import (
    _check_tc001,
    _check_tc002,
    _check_tc004_tc006,
    _format_postal_address,
    _is_kg_entity_link,
    _has_disambiguating_evidence,
    _ADDR_STREET_FIRST,
    _ADDR_EU,
    _ADDR_UK_POSTCODE,
)
from er_audit import _check_er004, BROKEN_LINK_SAMPLE_SIZE


# ===========================================================================
# 1. TC-004 STRUCTURAL DISAMBIGUATION TESTS
# ===========================================================================

def test_tc004_case_a_unambiguous_names_not_in_old_dictionary_fire():
    """Case A: Names not in the old 27-word dictionary ('Diamond', 'Sunrise',
    'Cloud Nine', 'Bharat') without disambiguation MUST fire TC-004."""
    test_names = ["Diamond", "Sunrise", "Cloud Nine", "Bharat"]
    for name in test_names:
        html = f"""<!DOCTYPE html>
        <html>
        <head>
          <script type="application/ld+json">
          {{
            "@context": "https://schema.org",
            "@type": "Organization",
            "name": "{name}"
          }}
          </script>
        </head>
        <body>
          <h1>Welcome to {name}</h1>
          <p>Explore our products and solutions.</p>
        </body>
        </html>"""
        url = "https://example.com"
        page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
        findings = _check_tc004_tc006([url], {url: page_res})
        tc004_findings = [f for f in findings if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]
        assert len(tc004_findings) == 1, f"Expected TC-004 for '{name}', got: {findings}"
        assert name in tc004_findings[0]["evidence"]


def test_tc004_case_b_old_dictionary_word_with_strong_disambiguation_does_not_fire():
    """Case B: Old dictionary word ('Apple') with strong disambiguation (Wikidata sameAs,
    address, foundingDate) MUST NOT fire TC-004."""
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Apple",
        "legalName": "Apple Inc.",
        "foundingDate": "1976-04-01",
        "address": {
          "@type": "PostalAddress",
          "streetAddress": "One Apple Park Way",
          "addressLocality": "Cupertino",
          "addressRegion": "CA",
          "postalCode": "95014",
          "addressCountry": "US"
        },
        "sameAs": [
          "https://www.wikidata.org/wiki/Q312",
          "https://en.wikipedia.org/wiki/Apple_Inc."
        ]
      }
      </script>
    </head>
    <body>
      <h1>Apple</h1>
    </body>
    </html>"""
    url = "https://example.com"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings = _check_tc004_tc006([url], {url: page_res})
    tc004_findings = [f for f in findings if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]
    assert len(tc004_findings) == 0, f"TC-004 fired unexpectedly on fully disambiguated Apple: {tc004_findings}"


def test_tc004_case_c_non_english_culturally_diverse_names():
    """Case C: Non-English/transliterated brand names behave strictly based on
    structural disambiguation, not language dictionaries."""
    # Sub-case C1: "Hikari" without disambiguation -> FIRES
    html_unambig = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Hikari"
      }
      </script>
    </head>
    <body><h1>Hikari</h1></body>
    </html>"""
    url = "https://example.com"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html_unambig, "html.parser"), html=html_unambig)
    findings = _check_tc004_tc006([url], {url: page_res})
    tc004 = [f for f in findings if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]
    assert len(tc004) == 1, f"Expected TC-004 for undisambiguated 'Hikari', got: {findings}"

    # Sub-case C2: "Hikari" with disambiguating description and address -> PASSES
    html_disambig = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Hikari",
        "disambiguatingDescription": "Specialist aquatic nutrition and fish biology laboratory founded in Himeji",
        "address": {
          "@type": "PostalAddress",
          "addressLocality": "Himeji",
          "addressCountry": "JP"
        }
      }
      </script>
    </head>
    <body><h1>Hikari</h1></body>
    </html>"""
    page_res2 = PageResult(url=url, status_code=200, soup=BeautifulSoup(html_disambig, "html.parser"), html=html_disambig)
    findings2 = _check_tc004_tc006([url], {url: page_res2})
    tc004_2 = [f for f in findings2 if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]
    assert len(tc004_2) == 0, f"TC-004 fired unexpectedly on structurally disambiguated Hikari: {tc004_2}"


def test_tc004_case_d_fully_disambiguated_entity():
    """Case D: Fully disambiguated entity with name, legalName, sameAs, address, foundingDate -> TC-004 absent."""
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "PanEuro Logistics International",
        "legalName": "PanEuro Freight & Supply Chain Solutions SE",
        "foundingDate": "2008-05-14",
        "address": {
          "@type": "PostalAddress",
          "streetAddress": "Speicherstrasse 55",
          "addressLocality": "Frankfurt am Main",
          "postalCode": "60327",
          "addressCountry": "DE"
        },
        "sameAs": ["https://www.wikidata.org/wiki/Q1000001"]
      }
      </script>
    </head>
    <body><h1>PanEuro</h1></body>
    </html>"""
    url = "https://example.com"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings = _check_tc004_tc006([url], {url: page_res})
    tc004 = [f for f in findings if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]
    assert len(tc004) == 0, f"TC-004 fired on fully disambiguated entity: {tc004}"


def test_tc004_case_e_no_entity_evidence():
    """Case E: Page without an Organization/brand identity block MUST NOT trigger TC-004."""
    html = """<!DOCTYPE html>
    <html>
    <body>
      <h1>Generic Common Article</h1>
      <p>Apple orange banana shell mercury diamond horizon.</p>
    </body>
    </html>"""
    url = "https://example.com"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    findings = _check_tc004_tc006([url], {url: page_res})
    tc004 = [f for f in findings if f.get("local_id") == "TC-004"]
    assert len(tc004) == 0, f"TC-004 fired on page with no entity: {tc004}"


def test_tc004_case_f_missing_sameas_but_strongly_disambiguated():
    """Case F: Missing sameAs but strongly disambiguated entity (address + foundingDate + legalName):
    TC-001 fires (missing sameAs), but TC-004 MUST NOT fire."""
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Cloud Nine",
        "legalName": "Cloud Nine Hospitality Private Limited",
        "foundingDate": "2015-08-20",
        "address": {
          "@type": "PostalAddress",
          "streetAddress": "123 MG Road",
          "addressLocality": "Bengaluru",
          "postalCode": "560001",
          "addressCountry": "IN"
        }
      }
      </script>
    </head>
    <body><h1>Cloud Nine Resorts</h1></body>
    </html>"""
    url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)

    tc001_findings = _check_tc001([url], {url: page_res}, mock_client)
    tc004_findings = _check_tc004_tc006([url], {url: page_res})

    tc001 = [f for f in tc001_findings if f.get("local_id") == "TC-001"]
    tc004 = [f for f in tc004_findings if f.get("local_id") == "TC-004" and f.get("severity") == "critical"]

    # TC-001 fires because sameAs is absent
    assert len(tc001) >= 1, "TC-001 should fire for missing sameAs"
    # TC-004 does NOT fire because entity is strongly grounded by address + legalName + foundingDate
    assert len(tc004) == 0, f"TC-004 should NOT fire on strongly disambiguated entity: {tc004}"


# ===========================================================================
# 2. TC-002 INTERNATIONAL ADDRESS EXTRACTION TESTS
# ===========================================================================

def test_tc002_india_address_extraction():
    """Verify Indian format address is extracted from visible prose text."""
    html = """<!DOCTYPE html>
    <html>
    <body>
      <h1>Contact Us</h1>
      <p>Corporate Headquarters: 123 MG Road, Bengaluru, Karnataka 560001, India</p>
      <p>Phone: +91 80 2345 6789</p>
    </body>
    </html>"""
    url = "https://example.com/contact"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    matches = _ADDR_STREET_FIRST.findall(html)
    assert len(matches) > 0, f"Expected Indian address match in prose: {matches}"
    assert "MG Road" in matches[0]


def test_tc002_uk_address_extraction():
    """Verify UK format address with postcode is extracted from visible text."""
    html = """<!DOCTYPE html>
    <html>
    <body>
      <h1>Prime Minister's Office</h1>
      <p>Official address: 10 Downing Street, London SW1A 2AA, United Kingdom</p>
    </body>
    </html>"""
    url = "https://example.com/contact"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    matches_street = _ADDR_STREET_FIRST.findall(html)
    matches_postcode = _ADDR_UK_POSTCODE.findall(html)
    assert len(matches_street) > 0 or len(matches_postcode) > 0, "Expected UK address match"


def test_tc002_eu_address_extraction():
    """Verify European street-name-first format with postcode is extracted from visible text."""
    html = """<!DOCTYPE html>
    <html>
    <body>
      <h1>Europazentrale</h1>
      <p>Besuchen Sie uns: Speicherstrasse 55, 60327 Frankfurt am Main, Germany</p>
    </body>
    </html>"""
    url = "https://example.com/contact"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    matches = _ADDR_EU.findall(html)
    assert len(matches) > 0, f"Expected EU street-name-first match: {matches}"
    assert "Speicherstrasse 55" in matches[0]


def test_tc002_structured_postal_address_handling():
    """Verify structured Schema.org PostalAddress is extracted even when prose is unusual."""
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Global Tech",
        "address": {
          "@type": "PostalAddress",
          "streetAddress": "Cyber Gateway, Level 4, Hi-Tech City Phase 2",
          "addressLocality": "Hyderabad",
          "addressRegion": "Telangana",
          "postalCode": "500081",
          "addressCountry": "IN"
        }
      }
      </script>
    </head>
    <body>
      <h1>Welcome</h1>
      <p>We work from the cloud with unusual distributed nodes.</p>
    </body>
    </html>"""
    url = "https://example.com"
    page_res = PageResult(url=url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)

    # Test _format_postal_address helper directly
    addr_dict = {
        "streetAddress": "Cyber Gateway, Level 4, Hi-Tech City Phase 2",
        "addressLocality": "Hyderabad",
        "addressRegion": "Telangana",
        "postalCode": "500081",
        "addressCountry": "IN",
    }
    formatted = _format_postal_address(addr_dict)
    assert "Cyber Gateway" in formatted
    assert "Hyderabad" in formatted
    assert "500081" in formatted
    assert "IN" in formatted

    # Test extraction via _check_tc002 on 2 pages with slight mismatch
    html2 = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Global Tech",
        "address": {
          "@type": "PostalAddress",
          "streetAddress": "Totally Different Road 999",
          "addressLocality": "Mumbai",
          "postalCode": "400001",
          "addressCountry": "IN"
        }
      }
      </script>
    </head>
    <body><h1>About</h1></body>
    </html>"""
    url2 = "https://example.com/about"
    page_res2 = PageResult(url=url2, status_code=200, soup=BeautifulSoup(html2, "html.parser"), html=html2)

    findings = _check_tc002([url, url2], {url: page_res, url2: page_res2})
    addr_findings = [f for f in findings if "Inconsistent address" in f.get("title", "")]
    assert len(addr_findings) == 1, f"Expected TC-002 address inconsistency finding, got: {findings}"


def test_tc002_false_positive_protection():
    """Verify that product numbers, order IDs, phone numbers, prices, and dates
    are NOT matched as addresses."""
    negative_samples = [
        "Product SKU: PROD-9988123-X",
        "Order #987654321 was confirmed on 2026-03-12.",
        "Phone: +1 (555) 123-4567 or +91 98765 43210",
        "Total price: $1,250.00 or EUR 999.00 inclusive of taxes.",
        "Meeting scheduled on March 15, 2026 at 14:00 GMT.",
        "Tracking number: 1Z9999999999999999",
        "Invoice No: INV-2026-004412",
    ]

    for sample in negative_samples:
        street_hits = _ADDR_STREET_FIRST.findall(sample)
        eu_hits = _ADDR_EU.findall(sample)
        uk_hits = _ADDR_UK_POSTCODE.findall(sample)
        all_hits = street_hits + eu_hits + uk_hits
        assert len(all_hits) == 0, f"False positive address match on non-address text: '{sample}' -> {all_hits}"


# ===========================================================================
# 3. KNOWLEDGE GRAPH LINKAGE HELPER TESTS
# ===========================================================================

def test_is_kg_entity_link():
    """Verify knowledge graph link validator recognizes canonical Wikidata and Wikipedia entities."""
    # Positive
    assert _is_kg_entity_link("https://www.wikidata.org/wiki/Q312") is True
    assert _is_kg_entity_link("https://wikidata.org/entity/Q1000001") is True
    assert _is_kg_entity_link("https://en.wikipedia.org/wiki/Apple_Inc.") is True
    assert _is_kg_entity_link("https://de.wikipedia.org/wiki/PanEuro_Logistics") is True
    assert _is_kg_entity_link("https://www.crunchbase.com/organization/apple") is True

    # Negative (social media or non-entity links)
    assert _is_kg_entity_link("https://twitter.com/apple") is False
    assert _is_kg_entity_link("https://facebook.com/apple") is False
    assert _is_kg_entity_link("https://linkedin.com/company/apple") is False
    assert _is_kg_entity_link("https://example.com/about") is False
    assert _is_kg_entity_link("") is False


# ===========================================================================
# 3. ER-004 DETERMINISTIC LINK SAMPLING & BIAS ELIMINATION
# ===========================================================================

def test_er004_reproducibility():
    """ER-004 deterministic sampling reproducibility:
    1. 120 URLs distributed across letters /a... through /z...
    2. Sample runs #1, #2, #3 must be 100% identical.
    3. Late-alphabet URLs (/s..., /t..., /z...) MUST appear in the sample,
       proving alphabetical bias is eliminated.
    """
    urls = [f"https://example.com/{chr(97 + (i % 26))}_section_page_{i:03d}" for i in range(120)]
    html = "<html><body>" + "".join(f'<a href="{u}">link</a>' for u in urls) + "</body></html>"
    pr = PageResult(url="https://example.com", status_code=200, soup=BeautifulSoup(html, "html.parser"))

    mock_client = MagicMock()
    mock_client.head.return_value = MagicMock(status_code=200, error=None)

    # Run 1
    mock_client.reset_mock()
    _check_er004(["https://example.com"], {"https://example.com": pr}, mock_client, "https://example.com")
    run1_calls = [c[0][0] for c in mock_client.head.call_args_list]

    # Run 2
    mock_client.reset_mock()
    _check_er004(["https://example.com"], {"https://example.com": pr}, mock_client, "https://example.com")
    run2_calls = [c[0][0] for c in mock_client.head.call_args_list]

    # Run 3
    mock_client.reset_mock()
    _check_er004(["https://example.com"], {"https://example.com": pr}, mock_client, "https://example.com")
    run3_calls = [c[0][0] for c in mock_client.head.call_args_list]

    # Evidence 1: Identical across all three runs
    assert run1_calls == run2_calls, "Run 1 and Run 2 differ!"
    assert run2_calls == run3_calls, "Run 2 and Run 3 differ!"
    assert len(run1_calls) == BROKEN_LINK_SAMPLE_SIZE, f"Expected sample size {BROKEN_LINK_SAMPLE_SIZE}, got {len(run1_calls)}"

    # Evidence 2: Late-alphabet URLs (/s.. through /z..) are present
    late_urls = [u for u in run1_calls if u.split("/")[-1].split("_")[0] in "stuvwxyz"]
    assert len(late_urls) >= 3, f"Expected late-alphabet URLs in sample, got {late_urls}"


def test_er004_bias_elimination():
    """ER-004 bias elimination proof:
    Under old strategy: sorted(all_internal_links)[:25] selects exclusively the
    first 25 URLs alphabetically (/a... to /c...). Any broken links late in the
    alphabet (/support, /terms, /warranty, /z...) are permanently missed.

    Under new SHA-256 key strategy:
    URLs across the entire alphabet have uniform opportunity to be sampled.
    When broken links exist among late-alphabet pages, the new strategy samples
    them and fires ER-004, whereas the old alphabetical strategy permanently misses them.
    """
    all_urls = [f"https://example.com/{chr(97 + (i % 26))}_item_{i:03d}" for i in range(100)]

    # Compute samples under old vs new strategy
    old_strategy_sample = sorted(all_urls)[:BROKEN_LINK_SAMPLE_SIZE]
    new_strategy_sample = sorted(
        all_urls, key=lambda u: hashlib.sha256(u.encode("utf-8")).hexdigest()
    )[:BROKEN_LINK_SAMPLE_SIZE]

    # Prove old strategy only selects early alphabet (letters a, b, c, d, e)
    old_letters = set(u.split("/")[-1][0] for u in old_strategy_sample)
    assert max(old_letters) <= "g", f"Old strategy selected surprisingly late letters: {old_letters}"

    # Prove new strategy covers wide range of the alphabet including s..z
    new_letters = set(u.split("/")[-1][0] for u in new_strategy_sample)
    assert any(letter in "stuvwxyz" for letter in new_letters), f"New strategy missing late letters: {new_letters}"

    # Pick a URL that is in new_strategy_sample but NOT in old_strategy_sample
    broken_candidate = [
        u for u in new_strategy_sample
        if u not in old_strategy_sample and u.split("/")[-1][0] in "stuvwxyz"
    ][0]

    html = "<html><body>" + "".join(f'<a href="{u}">link</a>' for u in all_urls) + "</body></html>"
    pr = PageResult(url="https://example.com", status_code=200, soup=BeautifulSoup(html, "html.parser"))

    # Mock HTTP client: return 404 for broken_candidate, 200 for all others
    mock_client = MagicMock()
    def mock_head(url):
        if url == broken_candidate:
            return MagicMock(status_code=404, error=None)
        return MagicMock(status_code=200, error=None)
    mock_client.head.side_effect = mock_head

    # Run audit with new strategy
    findings = _check_er004(
        ["https://example.com"],
        {"https://example.com": pr},
        mock_client,
        "https://example.com",
    )

    # ER-004 should be found because broken_candidate was sampled
    er004_findings = [f for f in findings if f.get("local_id") == "ER-004"]
    assert len(er004_findings) == 1, "Expected ER-004 finding under new SHA-256 sampling"
    assert broken_candidate in er004_findings[0]["evidence"]

    # Prove old strategy would have completely missed it
    assert broken_candidate not in old_strategy_sample


if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING GENERALIZATION & ER-004 SAMPLING TESTS")
    print("=" * 60)
    test_tc004_case_a_unambiguous_names_not_in_old_dictionary_fire()
    print("PASS: TC-004 Case A (Names not in old dictionary fire without disambiguation)")
    test_tc004_case_b_old_dictionary_word_with_strong_disambiguation_does_not_fire()
    print("PASS: TC-004 Case B (Old dictionary word with disambiguation does NOT fire)")
    test_tc004_case_c_non_english_culturally_diverse_names()
    print("PASS: TC-004 Case C (Non-English / culturally diverse names evaluated structurally)")
    test_tc004_case_d_fully_disambiguated_entity()
    print("PASS: TC-004 Case D (Fully disambiguated entity does NOT fire)")
    test_tc004_case_e_no_entity_evidence()
    print("PASS: TC-004 Case E (No entity evidence does NOT fire)")
    test_tc004_case_f_missing_sameas_but_strongly_disambiguated()
    print("PASS: TC-004 Case F (Missing sameAs but strongly disambiguated fires TC-001, NOT TC-004)")
    test_tc002_india_address_extraction()
    print("PASS: TC-002 India address extraction")
    test_tc002_uk_address_extraction()
    print("PASS: TC-002 UK address extraction")
    test_tc002_eu_address_extraction()
    print("PASS: TC-002 EU address extraction")
    test_tc002_structured_postal_address_handling()
    print("PASS: TC-002 Structured PostalAddress handling")
    test_tc002_false_positive_protection()
    print("PASS: TC-002 False-positive protection (SKUs, IDs, phones, prices, dates rejected)")
    test_is_kg_entity_link()
    print("PASS: Knowledge graph linkage helper (_is_kg_entity_link)")
    test_er004_reproducibility()
    print("PASS: ER-004 Reproducibility (Runs #1, #2, #3 identical across 120 URLs; late-alphabet sampled)")
    test_er004_bias_elimination()
    print("PASS: ER-004 Bias Elimination (Late-alphabet broken link caught by SHA-256; missed by sorted slice)")
    print("=" * 60)
    print("ALL GENERALIZATION & ER-004 TESTS PASSED SUCCESSFULLY")
    print("=" * 60)
