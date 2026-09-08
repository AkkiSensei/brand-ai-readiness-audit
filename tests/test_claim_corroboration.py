"""
test_claim_corroboration.py
===========================
Targeted semantic tests for TC-003 and TC-005 authority claim corroboration.

Validates:
  Case A: Broken sameAs URL only -> TC-003 and TC-005 must NOT fire.
  Case B: Authority claim + broken outbound link -> TC-003 fires (HEAD request verified).
  Case C: Authority claim without outbound link -> TC-005 fires (even with populated sameAs).
  Case D: False-positive phrases ("partner with us", "certification course") -> Neither fires.
"""

from __future__ import annotations

import sys
from pathlib import Path
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))

from http_client import HttpClient, PageResult
from tec_audit import _check_tc001, _check_tc003, _check_tc005, run_audit


def test_case_a_sameas_only():
    """Case A: Page contains a broken sameAs URL but NO textual authority claims.
    TC-001 may fire, but TC-003 and TC-005 must NOT fire.
    """
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Acme Widgets",
        "url": "https://example.com",
        "sameAs": ["https://broken-profile.example.org/acme"]
      }
      </script>
    </head>
    <body>
      <h1>Acme Widgets</h1>
      <p>Welcome to our standard widgets catalogue.</p>
    </body>
    </html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    mock_client.head.return_value = PageResult(url="https://broken-profile.example.org/acme", status_code=404)

    page_res = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: page_res}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    assert len(tc003_findings) == 0, f"TC-003 fired unexpectedly on sameAs: {tc003_findings}"
    assert len(tc005_findings) == 0, f"TC-005 fired unexpectedly on sameAs: {tc005_findings}"
    # Verify that mock_client.head was NOT called for claim corroboration
    assert mock_client.head.call_count == 0, "HEAD request was made despite no authority claims present"
    print("PASS: Case A (sameAs only does not trigger TC-003 or TC-005)")


def test_case_b_claim_with_broken_link():
    """Case B: External accreditation claim + broken outbound verification link.
    TC-003 must fire; HTTP HEAD request must be performed against the claim URL.
    """
    claim_link = "https://accreditation-board.org/verify/acme123"
    html = f"""<!DOCTYPE html>
    <html>
    <body>
      <h1>Acme Services</h1>
      <p>Certified by Example Organization. <a href="{claim_link}">Verify our accreditation</a></p>
    </body>
    </html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)
    mock_client.head.return_value = PageResult(url=claim_link, status_code=404)

    page_res = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: page_res}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    # Prove actual HTTP HEAD request made to the claim URL
    mock_client.head.assert_called_once_with(claim_link)

    assert len(tc003_findings) == 1, f"Expected 1 TC-003 finding, got: {tc003_findings}"
    assert tc003_findings[0]["local_id"] == "TC-003"
    assert "404" in tc003_findings[0]["evidence"]
    assert len(tc005_findings) == 0, f"TC-005 should not fire when link exists: {tc005_findings}"
    print("PASS: Case B (Claim with broken outbound link triggers TC-003 with actual HEAD call)")


def test_case_c_claim_without_link():
    """Case C: Authority claim without outbound verification link.
    TC-005 must fire even when sameAs is populated.
    """
    html = """<!DOCTYPE html>
    <html>
    <head>
      <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "Acme Services",
        "url": "https://example.com",
        "sameAs": ["https://wikidata.org/wiki/Q12345"]
      }
      </script>
    </head>
    <body>
      <h1>Acme Services</h1>
      <p>We are an authorized partner of Global Tech Corp.</p>
    </body>
    </html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)

    page_res = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: page_res}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    assert len(tc003_findings) == 0, f"TC-003 should not fire when no link: {tc003_findings}"
    assert len(tc005_findings) == 1, f"Expected 1 TC-005 finding, got: {tc005_findings}"
    assert tc005_findings[0]["local_id"] == "TC-005"
    assert "authorized partner" in tc005_findings[0]["evidence"].lower()
    print("PASS: Case C (Claim without link triggers TC-005 independently of sameAs)")


def test_case_d_generic_non_authority_phrases():
    """Case D: Non-authority generic phrases ("partner with us", "certification course").
    Neither TC-003 nor TC-005 may fire.
    """
    html = """<!DOCTYPE html>
    <html>
    <body>
      <h1>Acme Training</h1>
      <p>Interested in collaborating? Partner with us!</p>
      <p>Enroll in our professional certification training course today.</p>
      <p><a href="/partner-portal">Partner portal login</a></p>
      <p><a href="/member-area">Become a member today</a></p>
    </body>
    </html>"""

    page_url = "https://example.com"
    mock_client = MagicMock(spec=HttpClient)

    page_res = PageResult(url=page_url, status_code=200, soup=BeautifulSoup(html, "html.parser"), html=html)
    page_results = {page_url: page_res}
    frontier = [page_url]

    tc003_findings = _check_tc003(frontier, page_results, mock_client)
    tc005_findings = _check_tc005(frontier, page_results)

    assert len(tc003_findings) == 0, f"TC-003 fired on generic text: {tc003_findings}"
    assert len(tc005_findings) == 0, f"TC-005 fired on generic text: {tc005_findings}"
    print("PASS: Case D (Generic non-authority phrases do NOT trigger TC-003 or TC-005)")


if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING TARGETED CLAIM CORROBORATION TESTS (TC-003 & TC-005)")
    print("=" * 60)
    test_case_a_sameas_only()
    test_case_b_claim_with_broken_link()
    test_case_c_claim_without_link()
    test_case_d_generic_non_authority_phrases()
    print("=" * 60)
    print("ALL TARGETED CLAIM CORROBORATION TESTS PASSED")
    print("=" * 60)
