"""
test_finding_usefulness.py
==========================
Targeted test suite for Phase 6: Finding Usefulness, Actionability & Lightweight Grouping.

Verifies:
1. Every major finding communicates:
   - WHAT is wrong (specific title)
   - WHERE it was observed (location)
   - WHAT evidence supports it (evidence with provenance prefix)
   - WHY it matters (why_it_matters / technical mechanism)
   - HOW to fix it (suggested_action with concrete steps)
2. Remediations are concrete:
   - No generic advice ("Improve SEO", "Add more content", "Optimize website")
   - Exact asset type, target location, and mechanism explaining why it helps
3. Lightweight grouping:
   - Findings sharing a remediation theme are grouped under remediation_themes
   - No causal graphs or unsupported causal reasoning
   - Original findings, local IDs, and evidence remain completely preserved and unhidden
4. Prioritization:
   - Reflects impact and evidence strength
   - Priority bounded to 'medium' for INSUFFICIENT_EVIDENCE and NOT_OBSERVABLE
5. Deterministic ordering:
   - Remediation themes and findings maintain deterministic sorting across repeated executions
6. Contradictory and duplicate findings:
   - Handled cleanly without data loss or crashes
7. Full report schema validity.
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))

from aggregate import (
    _normalise_finding,
    _build_remediation_themes,
    _FINDING_REMEDIATION_METADATA,
    _SEVERITY_ORDER,
    _run_pipeline,
    _build_aborted_report,
)
from schema_validate import validate_report


def test_every_major_finding_has_5_core_components():
    """Each finding must communicate WHAT, WHERE, EVIDENCE, WHY, and HOW."""
    sample_lids = [
        "CR-001", "CR-002", "CR-003", "CR-004", "CR-005", "CR-006", "CR-007", "CR-008",
        "SF-001", "SF-002", "SF-003", "SF-004", "SF-005", "SF-006", "SF-007", "SF-008",
        "TC-001", "TC-002", "TC-003", "TC-004", "TC-005", "TC-006",
        "ER-001", "ER-002", "ER-003", "ER-004", "ER-005", "ER-006", "ER-007", "ER-008",
        "PA-001", "PA-002", "PA-003", "PA-004", "PA-005", "PA-006", "PA-CANONICAL",
    ]

    for lid in sample_lids:
        raw = {
            "local_id": lid,
            "title": f"Test Finding for {lid}",
            "evidence": f"[CONFIRMED] Observed issue on {lid}",
            "severity": "high",
        }
        norm = _normalise_finding(raw, "test-domain", "https://example.com")

        # 1. WHAT is wrong
        assert norm["title"] and len(norm["title"]) >= 5
        # 2. WHERE it was observed
        assert norm["location"] and len(norm["location"]) >= 3
        # 3. WHAT evidence supports it
        assert "[CONFIRMED]" in str(norm["evidence"])
        # 4. WHY it matters
        assert norm["why_it_matters"] and len(norm["why_it_matters"]) >= 10
        # 5. HOW to fix it
        action = norm["suggested_action"]
        assert isinstance(action, dict)
        assert action["summary"] and len(action["summary"]) >= 10
        assert action["priority"] in _SEVERITY_ORDER


def test_concrete_remediations_no_generic_advice():
    """Verify that remediations avoid generic filler like 'Improve SEO' or 'Optimize website'."""
    forbidden_generic_phrases = [
        "improve seo",
        "add more content",
        "optimize website",
        "fix website",
        "improve ranking",
    ]

    for lid, meta in _FINDING_REMEDIATION_METADATA.items():
        action_text = meta.get("default_action", "").lower()
        why_text = meta.get("why_it_matters", "").lower()

        for phrase in forbidden_generic_phrases:
            assert phrase not in action_text, f"{lid} default_action contains generic phrase: '{phrase}'"
            assert phrase not in why_text, f"{lid} why_it_matters contains generic phrase: '{phrase}'"

        # Remediation must name concrete technical assets
        assert any(
            token in action_text for token in [
                "robots.txt", "schema.org", "json-ld", "waf", "ssr", "dom", "http", "html",
                "canonical", "metadata", "sitemap", "dns", "og:", "faq", "author", "api",
                "date", "template", "link", "heading", "h1", "nap", "llms.txt", "rss", "atom",
                "feed", "entity", "header", "url", "crawler", "agent", "status", "json",
                "postaladdress", "brand", "e.164", "phone", "structured", "dimensions", "layout", "images",
            ]
        ), f"{lid} default_action lacks concrete technical target: {action_text}"


def test_lightweight_grouping_shared_remediation():
    """Findings sharing the same theme are grouped under remediation_themes without data loss."""
    findings = [
        {
            "id": "F-001",
            "local_id": "CR-001",
            "title": "AI crawlers blocked by robots.txt",
            "severity": "critical",
            "remediation_theme": "Crawler Access Governance",
            "location": "/robots.txt at domain root",
            "suggested_action": {
                "summary": "Update /robots.txt to permit AI crawlers",
                "priority": "critical",
                "location": "/robots.txt at domain root",
            },
        },
        {
            "id": "F-002",
            "local_id": "CR-002",
            "title": "Active WAF challenge blocking automated agents",
            "severity": "high",
            "remediation_theme": "Crawler Access Governance",
            "location": "Edge CDN / WAF configuration",
            "suggested_action": {
                "summary": "Configure edge WAF to exempt verified AI crawler user-agents",
                "priority": "high",
                "location": "Edge CDN / WAF configuration",
            },
        },
        {
            "id": "F-003",
            "local_id": "SF-001",
            "title": "Missing Organization Schema",
            "severity": "medium",
            "remediation_theme": "Structured Entity Schema",
            "location": "Homepage <head> HTML",
            "suggested_action": {
                "summary": "Inject JSON-LD Organization schema into homepage <head>",
                "priority": "medium",
                "location": "Homepage <head> HTML",
            },
        },
    ]

    themes = _build_remediation_themes(findings)
    assert len(themes) == 2

    # Verify Crawler Access Governance group
    crawling_theme = next(t for t in themes if t["theme"] == "Crawler Access Governance")
    assert crawling_theme["finding_ids"] == ["F-001", "F-002"]
    assert crawling_theme["priority"] == "critical"
    assert "/robots.txt" in crawling_theme["primary_action"] or "WAF" in crawling_theme["primary_action"]
    assert crawling_theme["target_asset"]

    # Verify Structured Entity Schema group
    schema_theme = next(t for t in themes if t["theme"] == "Structured Entity Schema")
    assert schema_theme["finding_ids"] == ["F-003"]
    assert schema_theme["priority"] == "medium"
    assert "Organization" in schema_theme["primary_action"]

    # Critical requirement: Original findings are NOT hidden or mutated
    assert len(findings) == 3
    assert findings[0]["id"] == "F-001"
    assert findings[1]["id"] == "F-002"
    assert findings[2]["id"] == "F-003"


def test_prioritization_bounds_unverified_evidence():
    """Phase 6D: INSUFFICIENT_EVIDENCE or NOT_OBSERVABLE bounds suggested_action priority."""
    # Unverified evidence should not remain critical/high priority
    raw_insufficient = {
        "local_id": "SF-001",
        "title": "Unverified schema gap",
        "severity": "high",
        "evidence": "[INSUFFICIENT_EVIDENCE] Structured data could not be parsed on timeout page",
        "suggested_action": {
            "summary": "Inject Organization schema",
            "priority": "high",
        },
    }
    norm_insufficient = _normalise_finding(raw_insufficient, "test-domain", "https://example.com")
    assert norm_insufficient["suggested_action"]["priority"] == "medium"

    # Confirmed evidence keeps high priority
    raw_confirmed = {
        "local_id": "SF-001",
        "title": "Confirmed schema gap",
        "severity": "high",
        "evidence": "[CONFIRMED] Zero schema.org microdata or JSON-LD observed in homepage HTML",
        "suggested_action": {
            "summary": "Inject Organization schema",
            "priority": "high",
        },
    }
    norm_confirmed = _normalise_finding(raw_confirmed, "test-domain", "https://example.com")
    assert norm_confirmed["suggested_action"]["priority"] == "high"


def test_contradictory_findings_preserved_without_causal_collapse():
    """Contradictory findings from different scopes/probes are preserved alongside each other."""
    f1 = {
        "id": "F-001",
        "local_id": "SF-002",
        "title": "NAP inconsistency detected across pages",
        "severity": "medium",
        "evidence": "[CONTRADICTED] Contact address '123 Main St' differs from footer '456 Market St'",
        "location": "Contact Page vs Footer HTML",
        "suggested_action": {"summary": "Harmonize NAP address across templates", "priority": "medium"},
    }
    f2 = {
        "id": "F-002",
        "local_id": "SF-003",
        "title": "Structured NAP confirmed on location page",
        "severity": "info",
        "evidence": "[CONFIRMED] Schema.org PostalAddress matches Google Maps CID",
        "location": "Locations Page JSON-LD",
        "suggested_action": {"summary": "Maintain verified structured address", "priority": "info"},
    }

    themes = _build_remediation_themes([f1, f2])
    assert len(themes) >= 1
    # Both findings retained with their distinct evidence intact
    all_fids = [fid for t in themes for fid in t["finding_ids"]]
    assert "F-001" in all_fids
    assert "F-002" in all_fids


def test_deterministic_ordering_of_themes():
    """Themes and findings order must be 100% deterministic regardless of input list order."""
    f_high = {
        "id": "F-001",
        "title": "High priority issue",
        "severity": "high",
        "remediation_theme": "Theme B",
        "suggested_action": {"summary": "Fix B", "priority": "high"},
    }
    f_crit = {
        "id": "F-002",
        "title": "Critical issue",
        "severity": "critical",
        "remediation_theme": "Theme A",
        "suggested_action": {"summary": "Fix A", "priority": "critical"},
    }
    f_low = {
        "id": "F-003",
        "title": "Low issue",
        "severity": "low",
        "remediation_theme": "Theme C",
        "suggested_action": {"summary": "Fix C", "priority": "low"},
    }

    # Run in order 1
    run1 = _build_remediation_themes([f_high, f_crit, f_low])
    # Run in reversed order
    run2 = _build_remediation_themes([f_low, f_high, f_crit])

    assert [t["theme"] for t in run1] == ["Theme A", "Theme B", "Theme C"]
    assert [t["theme"] for t in run1] == [t["theme"] for t in run2]
    assert [t["priority"] for t in run1] == ["critical", "high", "low"]


def test_aborted_report_includes_remediation_themes_and_validates():
    """Aborted reports with findings (e.g. site-wide block) include compliant remediation_themes."""
    blocked_finding = {
        "local_id": "CR-001",
        "title": "Robots.txt disallows crawler access",
        "severity": "critical",
        "evidence": "[CONFIRMED] robots.txt disallows all User-agents on /",
    }
    report = _build_aborted_report(
        target_url="https://blocked.example.com",
        status="blocked",
        message="robots.txt disallows crawler access to root",
        elapsed=0.5,
        reason="robots_disallowed",
        findings=[blocked_finding],
    )

    assert "remediation_themes" in report
    themes = report["remediation_themes"]
    assert len(themes) == 1
    assert themes[0]["theme"] == "Crawler Access Governance"
    assert themes[0]["finding_ids"] == ["F-001"]
    assert themes[0]["priority"] == "critical"

    # Strict schema validation
    valid, errors = validate_report(report)
    assert valid, f"Validation errors: {errors}"


def test_semantic_correctness_multi_condition_findings():
    """Verify that multi-condition checks resolve to distinct, semantically correct technical assets and locations."""
    # 1. CR-002: WAF vs Non-OK status codes vs Redirect chains
    f_waf = _normalise_finding({"local_id": "CR-002", "title": "WAF / anti-bot challenge blocking crawler access", "severity": "critical"}, "crawl", "https://example.com")
    assert f_waf["suggested_action"]["asset_type"] == "WAF / Bot Defense Rules"
    assert "Edge CDN" in f_waf["location"]

    f_status = _normalise_finding({"local_id": "CR-002", "title": "Pages returning non-OK HTTP status codes", "severity": "high"}, "crawl", "https://example.com")
    assert f_status["suggested_action"]["asset_type"] == "Web Server / HTTP Route"
    assert "Internal page URLs" in f_status["location"]
    assert "4xx" in f_status["why_it_matters"]

    f_redirs = _normalise_finding({"local_id": "CR-002", "title": "Excessive redirect chains detected", "severity": "low"}, "crawl", "https://example.com")
    assert f_redirs["suggested_action"]["asset_type"] == "HTTP Redirect Configuration"
    assert "redirect" in f_redirs["why_it_matters"].lower()

    # 2. CR-005: Geolocation modal vs Paywall/fullscreen modal
    f_geo = _normalise_finding({"local_id": "CR-005", "title": "Geolocation or location-selection gate blocking catalog content", "severity": "high"}, "crawl", "https://example.com")
    assert f_geo["suggested_action"]["asset_type"] == "Location Selector / Modal Dialog"
    assert "pincode" in f_geo["why_it_matters"].lower() or "geolocation" in f_geo["why_it_matters"].lower()

    # 3. CR-006: Sitemap missing vs Sitemap not declared in robots.txt
    f_sm_decl = _normalise_finding({"local_id": "CR-006", "title": "Sitemap not declared in robots.txt", "severity": "medium"}, "crawl", "https://example.com")
    assert f_sm_decl["suggested_action"]["asset_type"] == "robots.txt Sitemap Directive"
    assert "/robots.txt" in f_sm_decl["location"]

    # 4. CR-007: Crawl-delay vs Missing lastmod
    f_cd = _normalise_finding({"local_id": "CR-007", "title": "Excessive Crawl-delay in robots.txt", "severity": "low"}, "crawl", "https://example.com")
    assert f_cd["suggested_action"]["asset_type"] == "robots.txt Crawl-delay Directive"
    assert "/robots.txt" in f_cd["location"]

    # 5. SF-004: Canvas vs Video caption tracks
    f_canvas = _normalise_finding({"local_id": "SF-004", "title": "Canvas elements without accessible fallback content", "severity": "medium"}, "sfe", "https://example.com")
    assert "Canvas" in f_canvas["location"]

    f_video = _normalise_finding({"local_id": "SF-004", "title": "Video elements without caption tracks", "severity": "medium"}, "sfe", "https://example.com")
    assert f_video["suggested_action"]["asset_type"] == "HTML5 <video> Element / WebVTT Track"
    assert "<video>" in f_video["location"]
    assert "captions" in f_video["why_it_matters"]

    # 6. SF-008: Duplicate titles vs Duplicate meta descriptions
    f_titles = _normalise_finding({"local_id": "SF-008", "title": "Duplicate or generic page titles detected", "severity": "medium"}, "sfe", "https://example.com")
    assert f_titles["suggested_action"]["asset_type"] == "HTML <title> Tag"

    f_descs = _normalise_finding({"local_id": "SF-008", "title": "Duplicate meta descriptions detected", "severity": "medium"}, "sfe", "https://example.com")
    assert f_descs["suggested_action"]["asset_type"] == "HTML <meta name='description'> Tag"
    assert "meta" in f_descs["location"].lower()

    # 7. TC-002: Phone vs Address vs Brand Name
    f_phone = _normalise_finding({"local_id": "TC-002", "title": "Inconsistent phone numbers across pages", "severity": "medium"}, "tec", "https://example.com")
    assert f_phone["suggested_action"]["asset_type"] == "Phone Number / contactPoint Schema"

    f_addr = _normalise_finding({"local_id": "TC-002", "title": "Inconsistent address information across pages", "severity": "medium"}, "tec", "https://example.com")
    assert f_addr["suggested_action"]["asset_type"] == "PostalAddress Schema & HTML Text"

    # 8. TC-004: Ambiguity vs Capitalization variants
    f_caps = _normalise_finding({"local_id": "TC-004", "title": "Brand name appears in too many capitalisation variants", "severity": "medium"}, "tec", "https://example.com")
    assert f_caps["suggested_action"]["asset_type"] == "Brand Name Styling"

    # 9. ER-001: Missing H1 vs Primary navigation vs Multiple H1
    f_h1 = _normalise_finding({"local_id": "ER-001", "title": "Pages missing visible H1 heading", "severity": "high"}, "er", "https://example.com")
    assert f_h1["suggested_action"]["asset_type"] == "HTML <h1> Heading"

    f_nav = _normalise_finding({"local_id": "ER-001", "title": "Pages missing primary navigation", "severity": "medium"}, "er", "https://example.com")
    assert f_nav["suggested_action"]["asset_type"] == "HTML <nav> Navigation Container"
    assert "nav" in f_nav["location"].lower() or "header" in f_nav["location"].lower()

    # 10. ER-003: Full-page overlay vs Cookie banner vs Newsletter modal
    f_cookie = _normalise_finding({"local_id": "ER-003", "title": "Cookie consent banner detected on pages", "severity": "medium"}, "er", "https://example.com")
    assert f_cookie["suggested_action"]["asset_type"] == "Cookie Consent Banner"

    f_news = _normalise_finding({"local_id": "ER-003", "title": "Newsletter subscription modal detected", "severity": "low"}, "er", "https://example.com")
    assert f_news["suggested_action"]["asset_type"] == "Newsletter Subscription Modal"

