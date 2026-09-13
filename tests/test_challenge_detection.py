"""
test_challenge_detection.py
===========================
Adversarial test suite for HTTP-200 challenge/interstitial detection hardening.

Proves:
  1. Unknown-vendor HTTP-200 WAF challenges are classified as UNUSABLE_CHALLENGE
  2. JS challenge shells (script-only bodies) are detected
  3. Repeated-content fingerprint clustering reclassifies all URLs in a cluster
  4. CAPTCHA/interstitial pages are detected
  5. Redirect-to-challenge chains produce no secondary DOM findings
  6. Legitimate sparse pages are NOT falsely detected
  7. Legitimate SPA shells are NOT falsely detected
  8. Minimal real landing pages are NOT falsely detected
  9-12. Downstream sub-skills (SFE, ER, TEC) emit ZERO findings on challenge pages
        and report checks_blocked == checks_available
"""

from __future__ import annotations

import sys
from pathlib import Path
from copy import deepcopy
import pytest
from bs4 import BeautifulSoup

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))

from http_client import (
    FetchState,
    PageResult,
    detect_challenge_page,
    detect_challenge_cluster,
    CHALLENGE_MIN_SIGNALS,
)
from sfe_audit import run_audit as sfe_audit
from er_audit import run_audit as er_audit
from tec_audit import run_audit as tec_audit


# ==============================================================================
# Helpers / Fixtures
# ==============================================================================

def _make_pr(
    url: str,
    html: str,
    status_code: int = 200,
    fetch_state: FetchState | None = None,
) -> PageResult:
    """Build a PageResult with html and pre-parsed soup."""
    soup = BeautifulSoup(html, "html.parser")
    pr = PageResult(
        url=url,
        status_code=status_code,
        html=html,
        soup=soup,
        fetch_state=fetch_state,
    )
    return pr


# ── Challenge HTML fixtures ────────────────────────────────────────────────────

# Unknown-vendor HTTP-200 WAF challenge: generic "Checking your browser" shell.
# No vendor names. Just behavioral signals: challenge title, script-dominant,
# low content density, no semantic elements, zero links.
_UNKNOWN_VENDOR_CHALLENGE_HTML = """\
<!DOCTYPE html>
<html>
<head>
<title>Checking your browser</title>
<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/managed/v1"></script>
<script>
(function(){
  var __chal = window.__chal || {};
  __chal.t = +new Date(); __chal.k = "ABCDEF1234567890ABCDEF1234567890";
  var _script_payload = "eJxNUNtqwzAM..."; // 4kb of obfuscated JS
  var x=0;for(var i=0;i<10000;i++){x+=Math.random()*i;}
  window.__chal = __chal;
})();
</script>
</head>
<body>
<div id="chal-container">
  <noscript>Please enable JavaScript to continue.</noscript>
  <form method="POST" action="/chal-verify">
    <input type="hidden" name="_chal_token" value="abc123xyz789">
    <input type="hidden" name="_chal_ts" value="1700000000">
  </form>
</div>
</body>
</html>
"""

# JS challenge shell: body is purely script and hidden form, nothing visible
_JS_SHELL_CHALLENGE_HTML = """\
<!DOCTYPE html>
<html>
<head>
<title>Just a moment...</title>
</head>
<body>
<script>
// bot-detection runtime v9.2.1
!function(e){"use strict";var t=function(){this._q=[];this.push=function(e){this._q.push(e)};};
var n=new t; var r=e.botd=new Botd({token:"XXXX",environment:"production"});
r.detect().then(function(e){if(!e.bot){n.push("ok");}});
// much larger payload would be here in production
var payload="A".repeat(2000);
</script>
<form id="challenge-form" action="/_challenge/submit" method="POST">
  <input type="hidden" name="jschl_vc" value="abc123">
  <input type="hidden" name="pass" value="1234-abcdef">
  <input type="hidden" name="jschl_answer" value="">
</form>
<script>
  setTimeout(function(){
    var t=document.getElementById("challenge-form");
    var a=document.createElement("input");
    a.type="hidden";a.name="jschl_answer";
    a.value=(window.__cf_chl_opt||{}).cRay||"";
    t.appendChild(a);t.submit();
  }, 4000);
</script>
</body>
</html>
"""

# CAPTCHA page: visible CAPTCHA challenge text
_CAPTCHA_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Security Check</title></head>
<body>
<div class="captcha-wrapper">
  <h2>Please complete the security check</h2>
  <div class="g-recaptcha" data-sitekey="XXXXX"></div>
  <form method="POST" action="/verify-captcha">
    <input type="hidden" name="response_token" value="">
  </form>
</div>
<script src="https://www.google.com/recaptcha/api.js"></script>
</body>
</html>
"""

# Legitimate sparse page: minimal content but real h1, real paragraph, real nav
_LEGITIMATE_SPARSE_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Contact Us - Acme Corp</title></head>
<body>
<nav><a href="/">Home</a> | <a href="/products">Products</a></nav>
<main>
  <h1>Contact Acme Corp</h1>
  <p>Reach us at hello@acme.com or call +1-800-555-1234.</p>
  <a href="mailto:hello@acme.com">Email us</a>
</main>
</body>
</html>
"""

# Legitimate SPA shell: has app div but NOT a challenge.
# Key: it has a real <title> with a brand name, a real meta description,
# and does NOT trigger enough behavioral signals.
_LEGITIMATE_SPA_SHELL_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Acme Corp - Modern analytics platform">
  <title>Acme Analytics Dashboard</title>
  <link rel="stylesheet" href="/assets/main.css">
</head>
<body>
  <div id="app"><!-- React will mount here --></div>
  <script src="/assets/bundle.js"></script>
</body>
</html>
"""

# Minimal real landing page: sparse but legitimate
_MINIMAL_REAL_LANDING_HTML = """\
<!DOCTYPE html>
<html>
<head>
  <title>Welcome to Startup Inc.</title>
  <meta name="description" content="Startup Inc. builds better software.">
</head>
<body>
<header><nav><a href="/">Home</a><a href="/about">About</a></nav></header>
<main>
  <h1>Build Better Software</h1>
  <p>Startup Inc. provides enterprise-grade tools for modern development teams.</p>
  <a href="/signup" class="btn">Get Started Free</a>
</main>
</body>
</html>
"""

# Repeated challenge content (same shell returned for 3+ different URLs)
_REPEATED_CHALLENGE_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
<div class="block-page">
  <p>Your IP has been flagged for automated access. Please verify you are human.</p>
  <form action="/unblock" method="POST">
    <input type="hidden" name="token" value="abc123">
  </form>
</div>
<script>
window.onload=function(){setTimeout(function(){document.forms[0].submit();},3000);}
var payload="B".repeat(1500);
</script>
</body>
</html>
"""


class _DummyClient:
    """Minimal mock HttpClient for sub-skill testing."""
    def __init__(self, responses: dict):
        self.responses = responses
        self._deadline = None

    def get(self, url, **kwargs):
        if url in self.responses:
            return self.responses[url]
        return PageResult(url=url, status_code=200, fetch_state=FetchState.FETCHED_OK)


# ==============================================================================
# 1. Unknown-vendor HTTP-200 challenge detection
# ==============================================================================

def test_unknown_vendor_challenge_detected():
    """An unknown-vendor HTTP-200 WAF challenge must be classified UNUSABLE_CHALLENGE."""
    is_chal, conf, signals = detect_challenge_page(
        _UNKNOWN_VENDOR_CHALLENGE_HTML,
        BeautifulSoup(_UNKNOWN_VENDOR_CHALLENGE_HTML, "html.parser"),
        url="https://example.com/",
    )
    assert is_chal, (
        f"Expected UNUSABLE_CHALLENGE but got is_challenge=False. "
        f"Signals fired: {signals}. "
        f"Threshold: {CHALLENGE_MIN_SIGNALS}"
    )
    assert conf > 0.4, f"Expected confidence > 0.4, got {conf}"
    assert len(signals) >= CHALLENGE_MIN_SIGNALS


# ==============================================================================
# 2. JS-only challenge shell detection
# ==============================================================================

def test_js_shell_challenge_detected():
    """A JS-only body with hidden challenge form and no visible content must be detected."""
    is_chal, conf, signals = detect_challenge_page(
        _JS_SHELL_CHALLENGE_HTML,
        BeautifulSoup(_JS_SHELL_CHALLENGE_HTML, "html.parser"),
        url="https://example.com/product",
    )
    assert is_chal, (
        f"JS shell should be classified as UNUSABLE_CHALLENGE. "
        f"Signals: {signals}"
    )
    assert len(signals) >= CHALLENGE_MIN_SIGNALS


# ==============================================================================
# 3. Fingerprint-based cluster detection
# ==============================================================================

def test_repeated_content_fingerprint_clustering():
    """Three different URLs returning the same challenge shell must form a cluster
    and all be reclassified as UNUSABLE_CHALLENGE."""
    urls = [
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/page3",
    ]
    page_results = {url: _make_pr(url, _REPEATED_CHALLENGE_HTML) for url in urls}

    clusters = detect_challenge_cluster(page_results, min_cluster_size=3)

    assert len(clusters) >= 1, f"Expected at least 1 challenge cluster, got {len(clusters)}"

    total_clustered = sum(len(v) for v in clusters.values())
    assert total_clustered >= 3, f"Expected ≥3 URLs in clusters, got {total_clustered}"

    # Verify all clustered pages are now marked UNUSABLE_CHALLENGE
    for url in urls:
        pr = page_results[url]
        assert pr.fetch_state == FetchState.UNUSABLE_CHALLENGE, (
            f"Expected {url} to be UNUSABLE_CHALLENGE after clustering, "
            f"got {pr.fetch_state}"
        )


def test_cluster_minimum_size_enforced():
    """Two different URLs with the same content must NOT form a cluster (below min=3)."""
    urls = [
        "https://example.com/a",
        "https://example.com/b",
    ]
    page_results = {url: _make_pr(url, _REPEATED_CHALLENGE_HTML) for url in urls}
    clusters = detect_challenge_cluster(page_results, min_cluster_size=3)

    # With only 2 URLs, no cluster should form
    assert len(clusters) == 0, (
        f"Should NOT cluster when only 2 URLs share the fingerprint (min=3). "
        f"Got clusters: {clusters}"
    )
    for url in urls:
        assert page_results[url].fetch_state != FetchState.UNUSABLE_CHALLENGE, (
            f"{url} should NOT be reclassified with only 2-URL group"
        )


# ==============================================================================
# 4. CAPTCHA/interstitial page detection
# ==============================================================================

def test_captcha_page_detected():
    """CAPTCHA interstitial page must be classified as UNUSABLE_CHALLENGE."""
    is_chal, conf, signals = detect_challenge_page(
        _CAPTCHA_HTML,
        BeautifulSoup(_CAPTCHA_HTML, "html.parser"),
        url="https://example.com/login",
    )
    assert is_chal, (
        f"CAPTCHA page should be classified as UNUSABLE_CHALLENGE. Signals: {signals}"
    )


# ==============================================================================
# 5. Redirect-to-challenge: no secondary DOM findings cascade
# ==============================================================================

def test_redirect_to_challenge_no_cascade():
    """A challenge page reached via redirect must produce zero downstream findings."""
    target = "https://example.com/"
    challenge_pr = _make_pr(
        target,
        _UNKNOWN_VENDOR_CHALLENGE_HTML,
        status_code=200,
        fetch_state=FetchState.UNUSABLE_CHALLENGE,
    )
    challenge_pr.redirect_chain = ["https://example.com/challenge"]
    page_results = {target: challenge_pr}
    frontier = [target]
    client = _DummyClient({target: challenge_pr})

    sfe_res = sfe_audit(target, client, crawl_frontier=frontier, page_results=page_results)
    er_res = er_audit(target, client, crawl_frontier=frontier, page_results=page_results)
    tec_res = tec_audit(target, client, crawl_frontier=frontier, page_results=page_results)

    assert sfe_res["findings"] == [], f"SFE should emit 0 findings on challenge. Got: {sfe_res['findings']}"
    assert er_res["findings"] == [], f"ER should emit 0 findings on challenge. Got: {er_res['findings']}"
    assert tec_res["findings"] == [], f"TEC should emit 0 findings on challenge. Got: {tec_res['findings']}"


# ==============================================================================
# 6. Legitimate sparse page — NOT falsely classified
# ==============================================================================

def test_legitimate_sparse_not_falsely_challenged():
    """A genuine sparse page with real h1, paragraph, nav, and link must NOT be
    classified as UNUSABLE_CHALLENGE (false-positive guard)."""
    is_chal, conf, signals = detect_challenge_page(
        _LEGITIMATE_SPARSE_HTML,
        BeautifulSoup(_LEGITIMATE_SPARSE_HTML, "html.parser"),
        url="https://acme.com/contact",
    )
    assert not is_chal, (
        f"Legitimate sparse page must NOT be classified as challenge. "
        f"Signals fired: {signals} (threshold: {CHALLENGE_MIN_SIGNALS})"
    )


# ==============================================================================
# 7. Legitimate SPA shell — NOT falsely classified
# ==============================================================================

def test_legitimate_spa_shell_not_falsely_challenged():
    """A genuine SPA shell with a brand title, meta description, and stylesheet link
    must NOT be classified as UNUSABLE_CHALLENGE."""
    is_chal, conf, signals = detect_challenge_page(
        _LEGITIMATE_SPA_SHELL_HTML,
        BeautifulSoup(_LEGITIMATE_SPA_SHELL_HTML, "html.parser"),
        url="https://acme.com/",
    )
    assert not is_chal, (
        f"Legitimate SPA shell must NOT be classified as challenge. "
        f"Signals fired: {signals} (threshold: {CHALLENGE_MIN_SIGNALS})"
    )


# ==============================================================================
# 8. Minimal real landing page — NOT falsely classified
# ==============================================================================

def test_minimal_real_landing_not_falsely_challenged():
    """A minimal but real landing page with h1, paragraph, CTA link, and nav
    must NOT be classified as UNUSABLE_CHALLENGE."""
    is_chal, conf, signals = detect_challenge_page(
        _MINIMAL_REAL_LANDING_HTML,
        BeautifulSoup(_MINIMAL_REAL_LANDING_HTML, "html.parser"),
        url="https://startup.io/",
    )
    assert not is_chal, (
        f"Minimal real landing page must NOT be classified as challenge. "
        f"Signals fired: {signals} (threshold: {CHALLENGE_MIN_SIGNALS})"
    )


# ==============================================================================
# 9. SFE emits zero findings on challenge page
# ==============================================================================

def test_challenge_page_no_sfe_findings():
    """SFE must emit zero findings when all frontier URLs are UNUSABLE_CHALLENGE."""
    target = "https://example.com/"
    pr = _make_pr(target, _JS_SHELL_CHALLENGE_HTML, fetch_state=FetchState.UNUSABLE_CHALLENGE)
    page_results = {target: pr}
    frontier = [target]
    client = _DummyClient({target: pr})

    result = sfe_audit(target, client, crawl_frontier=frontier, page_results=page_results)

    assert result["findings"] == [], f"SFE must emit 0 findings on JS shell. Got: {result['findings']}"
    assert result["checks_attempted"] == 0, f"SFE checks_attempted must be 0, got {result['checks_attempted']}"
    assert result["checks_blocked"] == result["checks_available"], (
        f"SFE checks_blocked must equal checks_available. "
        f"blocked={result['checks_blocked']} available={result['checks_available']}"
    )


# ==============================================================================
# 10. ER emits zero findings on challenge page
# ==============================================================================

def test_challenge_page_no_er_findings():
    """ER must emit zero findings (no missing H1, no missing nav, etc.) when
    all frontier URLs are UNUSABLE_CHALLENGE."""
    target = "https://example.com/"
    pr = _make_pr(target, _UNKNOWN_VENDOR_CHALLENGE_HTML, fetch_state=FetchState.UNUSABLE_CHALLENGE)
    page_results = {target: pr}
    frontier = [target]
    client = _DummyClient({target: pr})

    result = er_audit(target, client, crawl_frontier=frontier, page_results=page_results)

    assert result["findings"] == [], f"ER must emit 0 findings on challenge. Got: {result['findings']}"
    assert result["checks_attempted"] == 0, f"ER checks_attempted must be 0, got {result['checks_attempted']}"
    assert result["checks_blocked"] == result["checks_available"], (
        f"ER checks_blocked must equal checks_available. "
        f"blocked={result['checks_blocked']} available={result['checks_available']}"
    )


# ==============================================================================
# 11. TEC emits zero findings on challenge page
# ==============================================================================

def test_challenge_page_no_tec_findings():
    """TEC must emit zero findings when all frontier URLs are UNUSABLE_CHALLENGE."""
    target = "https://example.com/"
    pr = _make_pr(target, _CAPTCHA_HTML, fetch_state=FetchState.UNUSABLE_CHALLENGE)
    page_results = {target: pr}
    frontier = [target]
    client = _DummyClient({target: pr})

    result = tec_audit(target, client, crawl_frontier=frontier, page_results=page_results)

    assert result["findings"] == [], f"TEC must emit 0 findings on challenge. Got: {result['findings']}"
    assert result["checks_attempted"] == 0, f"TEC checks_attempted must be 0, got {result['checks_attempted']}"
    assert result["checks_blocked"] == result["checks_available"], (
        f"TEC checks_blocked must equal checks_available. "
        f"blocked={result['checks_blocked']} available={result['checks_available']}"
    )


# ==============================================================================
# 12. checks_blocked == checks_available on UNUSABLE_CHALLENGE
# ==============================================================================

def test_checks_blocked_set_on_challenge():
    """When a challenge page is encountered, ALL sub-skills must report
    checks_blocked == checks_available (not checks_skipped)."""
    target = "https://example.com/"
    # Use a PageResult where fetch_state is explicitly set to UNUSABLE_CHALLENGE
    pr = _make_pr(target, _REPEATED_CHALLENGE_HTML, fetch_state=FetchState.UNUSABLE_CHALLENGE)
    page_results = {target: pr}
    frontier = [target]
    client = _DummyClient({target: pr})

    for audit_fn, domain, expected_checks in [
        (sfe_audit, "structured-fact-extraction", 8),
        (er_audit, "engagement-retention", 8),
        (tec_audit, "trust-entity-corroboration", 6),
    ]:
        result = audit_fn(target, client, crawl_frontier=frontier, page_results=page_results)
        assert result["checks_blocked"] == expected_checks, (
            f"{domain}: expected checks_blocked={expected_checks}, "
            f"got {result['checks_blocked']}"
        )
        assert result["checks_skipped"] == 0, (
            f"{domain}: challenge should set checks_BLOCKED not checks_SKIPPED. "
            f"checks_skipped={result['checks_skipped']}"
        )
        assert result["findings"] == [], (
            f"{domain}: no findings on UNUSABLE_CHALLENGE page. Got: {result['findings']}"
        )
