"""
er_audit.py
===========
Domain sub-skill: Engagement & Retention (ER-001 -> ER-008)

Audits above-the-fold orientation, interstitial/modal detection, broken link
ratio, responsive layout, CTA presence, breadcrumbs, and search functionality
across the crawl frontier.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "crawl-render-access"
    / "scripts"
)
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from http_client import (
    HttpClient,
    PageResult,
    normalise_url,
    is_same_origin,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_THRESH_PATH = (
    Path(__file__).resolve().parents[2]
    / "audit-orchestrator"
    / "references"
    / "thresholds.json"
)


def _load_thresholds() -> dict:
    try:
        return json.loads(_THRESH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_T = _load_thresholds()
_ENG = _T.get("engagement", {})

OVERLAY_THRESH: float = float(_ENG.get("overlay_coverage_threshold", 0.60))
H1_REQUIRED: bool = bool(_ENG.get("above_fold_h1_required", True))
NAV_MIN_LINKS: int = int(_ENG.get("nav_links_min_count", 3))
CLS_THRESH: float = float(_ENG.get("cls_threshold", 0.10))
Z_INDEX_THRESH: int = int(_ENG.get("interstitial_z_index_threshold", 100))
INTERSTITIAL_DELAY_MS: int = int(_ENG.get("interstitial_delay_ms_threshold", 2000))
VIEWPORT_WAIT_MS: int = int(_ENG.get("viewport_stable_wait_ms", 1500))

BROKEN_LINK_SAMPLE_SIZE: int = int(_ENG.get("broken_link_sample_size", 25))
BROKEN_LINK_RATIO_THRESHOLD: float = float(_ENG.get("broken_link_ratio_threshold", 0.05))
SEARCH_PAGE_THRESHOLD: int = int(_ENG.get("search_page_threshold", 30))
BREADCRUMB_MIN_DEPTH: int = int(_ENG.get("breadcrumb_min_depth", 2))

# Overlay / interstitial CSS and class patterns
_OVERLAY_CLASS_RE = re.compile(
    r"modal|overlay|popup|lightbox|interstitial|dialog|cookie[-_]?banner|"
    r"cookie[-_]?consent|gdpr|cc[-_]?banner|subscribe[-_]?popup|"
    r"newsletter[-_]?modal|paywall|reg[-_]?wall",
    re.IGNORECASE,
)
_FIXED_STYLE_RE = re.compile(
    r"position\s*:\s*(fixed|sticky)", re.IGNORECASE
)
_FULLSCREEN_RE = re.compile(
    r"(width\s*:\s*100\s*(%|vw)|height\s*:\s*100\s*(%|vh)|inset\s*:\s*0)",
    re.IGNORECASE,
)
_CTA_RE = re.compile(
    r"(buy|shop|order|subscribe|sign\s*up|get\s+started|try\s+free|"
    r"add\s+to\s+cart|book\s+now|contact\s+us|learn\s+more|"
    r"request\s+a?\s*demo|start\s+free|download|enroll)",
    re.IGNORECASE,
)

# JSON-LD helpers
def _extract_jsonld_blocks(soup: Any) -> list[dict]:
    blocks: list[dict] = []
    if soup is None:
        return blocks
    for script in soup.find_all("script", type="application/ld+json"):
        raw = script.string
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        blocks.append(item)
            elif isinstance(data, dict):
                if "@graph" in data:
                    graph = data["@graph"]
                    if isinstance(graph, list):
                        for item in graph:
                            if isinstance(item, dict):
                                blocks.append(item)
                    elif isinstance(graph, dict):
                        blocks.append(graph)
                else:
                    blocks.append(data)
        except (json.JSONDecodeError, TypeError):
            pass
    return blocks


def _get_types(block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    t = block.get("@type", "")
    if isinstance(t, list):
        return [str(x).strip() for x in t if x]
    return [str(t).strip()] if t else []


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------
def _finding(
    local_id: str,
    title: str,
    severity: str,
    evidence: str,
    action: str,
    related: list[str] | None = None,
    pages_affected: int | None = None,
    pages_checked: int | None = None,
    source: str = "static",
) -> dict:
    d = {
        "local_id": local_id,
        "title": title,
        "severity": severity,
        "category": "engagement",
        "evidence": evidence,
        "suggested_action": {"summary": action, "priority": severity},
        "related_to": related or [],
        "source": source,
    }
    if pages_affected is not None:
        d["pages_affected"] = pages_affected
    if pages_checked is not None:
        d["pages_checked"] = pages_checked
    return d


# ---------------------------------------------------------------------------
# URL depth helper
# ---------------------------------------------------------------------------
def _url_depth(url: str, root_url: str) -> int:
    """Estimate URL depth by counting path segments beyond the root."""
    try:
        root_parsed = urllib.parse.urlparse(root_url)
        parsed = urllib.parse.urlparse(url)
        root_segments = [s for s in root_parsed.path.split("/") if s]
        segments = [s for s in parsed.path.split("/") if s]
        return max(0, len(segments) - len(root_segments))
    except Exception:
        return 0


def _is_html_page(pr: Optional[PageResult]) -> bool:
    """Return True if the PageResult represents an HTML document."""
    if not pr:
        return False
    if hasattr(pr, "is_html"):
        return pr.is_html
    ct = (pr.content_type or "").lower()
    if ct:
        return "text/html" in ct or "application/xhtml+xml" in ct
    parsed = urllib.parse.urlparse(pr.url or "")
    path = parsed.path.lower()
    non_html_exts = (
        ".md", ".markdown", ".txt", ".xml", ".json", ".pdf",
        ".csv", ".tsv", ".yaml", ".yml", ".rss", ".atom"
    )
    return not any(path.endswith(ext) for ext in non_html_exts)


# ===================================================================
# CHECK FUNCTIONS
# ===================================================================

def _check_er001(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """ER-001 (high): Missing H1 or primary navigation above the fold."""
    findings: list[dict] = []
    try:
        html_pages = [u for u in frontier if _is_html_page(page_results.get(u))]
        if not html_pages:
            return findings

        missing_h1: list[str] = []
        missing_nav: list[str] = []
        multiple_h1: list[str] = []

        for url in html_pages:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # H1 check
            h1_tags = pr.soup.find_all("h1")
            if not h1_tags:
                missing_h1.append(url)
            elif len(h1_tags) > 1:
                multiple_h1.append(url)

            # Visible H1 (not hidden)
            if h1_tags:
                all_hidden = True
                for h1 in h1_tags:
                    style = h1.get("style", "")
                    if "display:none" not in style.replace(" ", "").lower() and \
                       "visibility:hidden" not in style.replace(" ", "").lower():
                        all_hidden = False
                        break
                if all_hidden:
                    missing_h1.append(url)

            # Navigation check
            nav_tags = pr.soup.find_all("nav")
            has_nav = False
            for nav in nav_tags:
                links = nav.find_all("a")
                if len(links) >= NAV_MIN_LINKS:
                    has_nav = True
                    break

            # Fallback: check for header with links
            if not has_nav:
                header = pr.soup.find("header")
                if header:
                    links = header.find_all("a")
                    if len(links) >= NAV_MIN_LINKS:
                        has_nav = True

            # Fallback: role="navigation"
            if not has_nav:
                role_nav = pr.soup.find(attrs={"role": "navigation"})
                if role_nav:
                    links = role_nav.find_all("a")
                    if len(links) >= NAV_MIN_LINKS:
                        has_nav = True

            if not has_nav:
                missing_nav.append(url)

        if missing_h1:
            findings.append(_finding(
                "ER-001",
                "Pages missing visible H1 heading",
                "high",
                f"{len(missing_h1)} page(s) lack a visible <h1> element: "
                + "; ".join(missing_h1[:5]),
                "Add a clear, descriptive <h1> heading to every page. The H1 "
                "should appear above the fold and summarise the page topic "
                "for both users and AI crawlers.",
                related=["CR-003"],
                pages_affected=len(missing_h1),
                pages_checked=len(html_pages),
            ))

        if missing_nav:
            findings.append(_finding(
                "ER-001",
                "Pages missing primary navigation",
                "medium",
                f"{len(missing_nav)} page(s) lack <nav> or recognisable "
                f"navigation with >= {NAV_MIN_LINKS} links: "
                + "; ".join(missing_nav[:5]),
                "Add semantic <nav> elements with at least "
                f"{NAV_MIN_LINKS} internal links for site-wide navigation.",
                pages_affected=len(missing_nav),
                pages_checked=len(html_pages),
            ))

        if multiple_h1:
            findings.append(_finding(
                "ER-001",
                "Multiple H1 tags on a single page",
                "low",
                f"{len(multiple_h1)} page(s) have more than one <h1>: "
                + "; ".join(multiple_h1[:5]),
                "Use a single <h1> per page. Use <h2>-<h6> for sub-sections "
                "to maintain a clear heading hierarchy.",
                pages_affected=len(multiple_h1),
                pages_checked=len(html_pages),
            ))

    except Exception as exc:
        logger.debug("ER-001 error: %s", exc)
    return findings


def _check_er002(
    frontier: list[str],
    page_results: dict[str, PageResult],
    root_url: str,
) -> list[dict]:
    """ER-002 (medium): Breadcrumbs missing on deep pages."""
    findings: list[dict] = []
    try:
        deep_pages_without_breadcrumbs: list[str] = []

        for url in frontier:
            depth = _url_depth(url, root_url)
            if depth < BREADCRUMB_MIN_DEPTH:
                continue

            pr = page_results.get(url)
            if not pr or not pr.soup or not _is_html_page(pr):
                continue

            has_breadcrumb = False

            # Check JSON-LD BreadcrumbList
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if "BreadcrumbList" in _get_types(block):
                    has_breadcrumb = True
                    break

            # Check HTML breadcrumb nav
            if not has_breadcrumb:
                for nav in pr.soup.find_all("nav"):
                    aria = (nav.get("aria-label") or "").lower()
                    if "breadcrumb" in aria:
                        has_breadcrumb = True
                        break
                    classes = " ".join(nav.get("class", [])).lower()
                    if "breadcrumb" in classes:
                        has_breadcrumb = True
                        break

            # Check for any element with breadcrumb class/role
            if not has_breadcrumb:
                bc_elem = pr.soup.find(
                    attrs={"class": re.compile(r"breadcrumb", re.I)}
                ) or pr.soup.find(
                    attrs={"role": "navigation", "aria-label": re.compile(r"breadcrumb", re.I)}
                )
                if bc_elem:
                    has_breadcrumb = True

            if not has_breadcrumb:
                deep_pages_without_breadcrumbs.append(url)

        if deep_pages_without_breadcrumbs:
            findings.append(_finding(
                "ER-002",
                "Deep pages missing breadcrumb navigation",
                "medium",
                f"{len(deep_pages_without_breadcrumbs)} page(s) at depth >= 2 "
                "lack breadcrumb navigation (HTML or BreadcrumbList schema): "
                + "; ".join(deep_pages_without_breadcrumbs[:5]),
                "Add BreadcrumbList JSON-LD structured data and visible "
                "breadcrumb <nav> (with aria-label='breadcrumb') to pages "
                "deeper than the homepage.",
            ))

    except Exception as exc:
        logger.debug("ER-002 error: %s", exc)
    return findings


def _check_er003(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """ER-003 (high): Post-load interstitial / overlay detection."""
    findings: list[dict] = []
    try:
        overlay_pages: list[str] = []
        cookie_pages: list[str] = []
        newsletter_pages: list[str] = []

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup or not _is_html_page(pr):
                continue

            for elem in pr.soup.find_all(True):
                classes = " ".join(elem.get("class", [])).lower()
                elem_id = (elem.get("id") or "").lower()
                style = (elem.get("style") or "").lower()
                combined_attrs = f"{classes} {elem_id}"

                # Cookie / GDPR banners — only flag if intrusive full-screen blocking overlay
                if re.search(r"cookie|gdpr|cc[-_]?banner|consent", combined_attrs):
                    is_fixed = bool(_FIXED_STYLE_RE.search(style))
                    is_full = bool(_FULLSCREEN_RE.search(style))
                    high_z = False
                    z_match = re.search(r"z-index\s*:\s*(\d+)", style)
                    if z_match:
                        high_z = int(z_match.group(1)) > Z_INDEX_THRESH
                    if is_full or (is_fixed and high_z and ("height: 100%" in style or "height:100%" in style or "inset: 0" in style)):
                        if url not in cookie_pages:
                            cookie_pages.append(url)
                    continue

                # Newsletter modals
                if re.search(r"newsletter|subscribe[-_]?popup|signup[-_]?modal", combined_attrs):
                    if url not in newsletter_pages:
                        newsletter_pages.append(url)
                    continue

                # Full-page overlays
                is_fixed = bool(_FIXED_STYLE_RE.search(style))
                is_full = bool(_FULLSCREEN_RE.search(style))
                high_z = False
                z_match = re.search(r"z-index\s*:\s*(\d+)", style)
                if z_match:
                    high_z = int(z_match.group(1)) > Z_INDEX_THRESH

                if is_fixed and (is_full or high_z):
                    if url not in overlay_pages:
                        overlay_pages.append(url)
                    continue

                # Class-based overlay detection
                if _OVERLAY_CLASS_RE.search(combined_attrs):
                    if is_fixed or high_z:
                        if url not in overlay_pages:
                            overlay_pages.append(url)

        if overlay_pages:
            findings.append(_finding(
                "ER-003",
                "Full-page interstitial overlay detected",
                "high",
                f"{len(overlay_pages)} page(s) have fixed/absolute overlays "
                f"with high z-index (> {Z_INDEX_THRESH}) that may obscure "
                "content: " + "; ".join(overlay_pages[:5]),
                "Remove or defer full-page interstitials. Use dismissible "
                "banners that do not cover more than 50% of the viewport. "
                "Ensure main content is immediately accessible to AI crawlers.",
                related=["CR-005"],
            ))

        if cookie_pages:
            findings.append(_finding(
                "ER-003",
                "Cookie consent banner detected on pages",
                "medium",
                f"{len(cookie_pages)} page(s) have cookie/GDPR consent "
                "elements: " + "; ".join(cookie_pages[:5]),
                "Ensure cookie banners do not cover the main content area. "
                "Use a small fixed banner rather than a full-page overlay.",
            ))

        if newsletter_pages:
            findings.append(_finding(
                "ER-003",
                "Newsletter subscription modal detected",
                "low",
                f"{len(newsletter_pages)} page(s) have newsletter/subscribe "
                "modal elements: " + "; ".join(newsletter_pages[:5]),
                "Delay newsletter modals until after meaningful user "
                "interaction. Avoid showing them to crawler user-agents.",
            ))

    except Exception as exc:
        logger.debug("ER-003 error: %s", exc)
    return findings


def _check_er004(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
    root_url: str,
    t_start: float | None = None,
    timeout_s: float | None = None,
) -> list[dict]:
    """ER-004 (medium/high): Broken internal link ratio."""
    findings: list[dict] = []
    try:
        # Collect all internal links across pages
        all_internal_links: list[str] = []
        seen_links: set[str] = set()

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            for a_tag in pr.soup.find_all("a", href=True):
                href = a_tag["href"]
                abs_url = normalise_url(href, url)
                if not abs_url or abs_url in seen_links:
                    continue
                if is_same_origin(abs_url, root_url):
                    seen_links.add(abs_url)
                    all_internal_links.append(abs_url)

        if not all_internal_links:
            return findings

        # Sample up to 25 links deterministically (sorted slice — same input → same output)
        sample_size = min(BROKEN_LINK_SAMPLE_SIZE, len(all_internal_links))
        if len(all_internal_links) > BROKEN_LINK_SAMPLE_SIZE:
            sample = sorted(all_internal_links)[:BROKEN_LINK_SAMPLE_SIZE]
        else:
            sample = all_internal_links

        broken: list[str] = []
        for link in sample:
            if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
                break
            # Check if we already have this result
            pr = page_results.get(link)
            if pr:
                if pr.status_code and pr.status_code >= 400:
                    broken.append(f"{link} (HTTP {pr.status_code})")
                elif pr.status_code is None and pr.error:
                    broken.append(f"{link} ({pr.error[:60]})")
                continue

            # HEAD check for uncrawled links
            try:
                head = http_client.head(link)
                if head.status_code and head.status_code >= 400:
                    broken.append(f"{link} (HTTP {head.status_code})")
                elif head.status_code is None and head.error:
                    broken.append(f"{link} ({head.error[:60]})")
            except Exception:
                broken.append(f"{link} (request failed)")

        ratio = len(broken) / sample_size if sample_size > 0 else 0
        if broken and ratio > BROKEN_LINK_RATIO_THRESHOLD:
            severity = "high" if ratio > 0.15 else "medium"
            findings.append(_finding(
                "ER-004",
                "High broken internal link ratio",
                severity,
                f"{len(broken)}/{sample_size} sampled internal links are "
                f"broken ({ratio:.0%}): " + "; ".join(broken[:5]),
                "Audit and fix all broken internal links. Use a link checker "
                "tool to identify and correct or remove dead links across "
                "the site. Broken links degrade AI-engine trust.",
                related=["CR-002"],
            ))
        elif broken:
            findings.append(_finding(
                "ER-004",
                "Broken internal links detected",
                "medium",
                f"{len(broken)} broken link(s) found in sample of "
                f"{sample_size}: " + "; ".join(broken[:5]),
                "Fix broken internal links to maintain site integrity. "
                "Even a small number of dead links reduces crawler "
                "confidence in content quality.",
                related=["CR-002"],
            ))

    except Exception as exc:
        logger.debug("ER-004 error: %s", exc)
    return findings


def _check_er005(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """ER-005 (medium): CTA presence on product/landing pages."""
    findings: list[dict] = []
    try:
        # Identify product/landing pages
        product_pages: list[str] = []
        pages_without_cta: list[str] = []

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup or not _is_html_page(pr):
                continue

            lower = url.lower()
            is_product_like = any(
                seg in lower
                for seg in ("/product", "/service", "/pricing", "/plan",
                            "/demo", "/trial", "/shop", "/store", "/offer")
            )

            # Also detect via JSON-LD Product type
            if not is_product_like:
                blocks = _extract_jsonld_blocks(pr.soup)
                for block in blocks:
                    types = _get_types(block)
                    if any(t.lower() in ("product", "offer", "service")
                           for t in types):
                        is_product_like = True
                        break

            if not is_product_like:
                continue
            product_pages.append(url)

            # Check for CTA elements
            has_cta = False
            for tag in pr.soup.find_all(["a", "button"]):
                text = tag.get_text(strip=True)
                if _CTA_RE.search(text):
                    has_cta = True
                    break
                # Check aria-label
                aria = tag.get("aria-label", "")
                if _CTA_RE.search(aria):
                    has_cta = True
                    break

            if not has_cta:
                pages_without_cta.append(url)

        if pages_without_cta:
            findings.append(_finding(
                "ER-005",
                "Product/landing pages missing clear CTA",
                "medium",
                f"{len(pages_without_cta)}/{len(product_pages)} "
                "product/landing page(s) lack a recognisable call-to-action "
                "button or link: " + "; ".join(pages_without_cta[:5]),
                "Add clear, above-the-fold CTA buttons (e.g., 'Buy Now', "
                "'Get Started', 'Request Demo') to product and landing pages. "
                "CTAs signal page purpose to AI engines.",
            ))

    except Exception as exc:
        logger.debug("ER-005 error: %s", exc)
    return findings


def _check_er006_er007(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """ER-006/ER-007 (high): Responsive layout — viewport meta and mobile."""
    findings: list[dict] = []
    try:
        html_pages = [u for u in frontier if _is_html_page(page_results.get(u))]
        if not html_pages:
            return findings

        missing_viewport: list[str] = []
        bad_viewport: list[str] = []

        for url in html_pages:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # Check <meta name="viewport">
            vp_meta = pr.soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
            if not vp_meta:
                missing_viewport.append(url)
            else:
                content = (vp_meta.get("content") or "").lower()
                # Check for problematic viewport settings
                if "user-scalable=no" in content.replace(" ", ""):
                    bad_viewport.append(url)
                elif "maximum-scale=1" in content.replace(" ", ""):
                    bad_viewport.append(url)

            # Heuristic: detect potential horizontal overflow
            # Look for fixed-width elements wider than 375px
            for elem in pr.soup.find_all(style=True):
                style = elem.get("style", "")
                width_match = re.search(
                    r"(?:min-)?width\s*:\s*(\d+)\s*px", style, re.IGNORECASE
                )
                if width_match:
                    width = int(width_match.group(1))
                    if width > 375:
                        # Potentially overflows mobile
                        pass  # Not severe enough to flag alone

        if missing_viewport:
            findings.append(_finding(
                "ER-006",
                "Pages missing viewport meta tag",
                "high",
                f"{len(missing_viewport)} page(s) lack "
                '<meta name="viewport"> tag: '
                + "; ".join(missing_viewport[:5]),
                'Add <meta name="viewport" content="width=device-width, '
                'initial-scale=1"> to all pages. Without it, mobile '
                "rendering is unpredictable and AI engines may deprioritise "
                "the content.",
                pages_affected=len(missing_viewport),
                pages_checked=len(html_pages),
            ))

        if bad_viewport:
            findings.append(_finding(
                "ER-007",
                "Viewport meta restricts user zoom",
                "medium",
                f"{len(bad_viewport)} page(s) set user-scalable=no or "
                "maximum-scale=1: " + "; ".join(bad_viewport[:5]),
                "Remove user-scalable=no and maximum-scale=1 from viewport "
                "meta. Allow users to zoom for accessibility compliance and "
                "improved mobile experience signals.",
                pages_affected=len(bad_viewport),
                pages_checked=len(html_pages),
            ))

    except Exception as exc:
        logger.debug("ER-006/007 error: %s", exc)
    return findings


def _check_er008(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """ER-008 (low): Search functionality for large sites."""
    findings: list[dict] = []
    try:
        html_pages = [u for u in frontier if _is_html_page(page_results.get(u))]
        if len(html_pages) < SEARCH_PAGE_THRESHOLD:
            return findings

        has_search = False

        for url in html_pages:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # Check JSON-LD SearchAction
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                action = block.get("potentialAction", {})
                if isinstance(action, dict):
                    if action.get("@type") == "SearchAction":
                        has_search = True
                        break
                elif isinstance(action, list):
                    for a in action:
                        if isinstance(a, dict) and a.get("@type") == "SearchAction":
                            has_search = True
                            break
            if has_search:
                break

            # Check for search input elements
            search_input = pr.soup.find(
                "input", attrs={"type": re.compile(r"^search$", re.I)}
            )
            if search_input:
                has_search = True
                break

            # Check for search forms
            search_form = pr.soup.find(
                "form", attrs={"role": re.compile(r"^search$", re.I)}
            )
            if search_form:
                has_search = True
                break

            # Check aria-label on inputs
            for inp in pr.soup.find_all("input"):
                aria = (inp.get("aria-label") or "").lower()
                placeholder = (inp.get("placeholder") or "").lower()
                if "search" in aria or "search" in placeholder:
                    has_search = True
                    break
            if has_search:
                break

        if not has_search:
            findings.append(_finding(
                "ER-008",
                "No site search functionality detected on large site",
                "low",
                f"Site has {len(html_pages)} HTML pages but no search input, "
                "SearchAction schema, or search form was found.",
                "Add a site search feature with SearchAction structured data "
                "(potentialAction on WebSite schema). This enables AI engines "
                "to reference your internal search capability.",
            ))

    except Exception as exc:
        logger.debug("ER-008 error: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# Proactive recommendations
# ---------------------------------------------------------------------------
def _proactive(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    recs: list[dict] = []
    try:
        # Check for presence of AI agent manifests (agents.md, llms.txt)
        for url in frontier:
            lower = url.lower()
            if any(lower.endswith(name) for name in ("/agents.md", "/llms.txt", "/llms-full.txt")):
                pr = page_results.get(url)
                if pr and pr.status_code and 200 <= pr.status_code < 300:
                    recs.append({
                        "title": "Maintain and expand agent documentation manifest",
                        "rationale": f"Detected accessible AI manifest at {url}. "
                                     "Providing structured documentation for LLM agents "
                                     "significantly improves brand representation in AI search.",
                        "priority": "low",
                    })
                    break

        # Check for aria-label on nav elements
        nav_missing_aria: int = 0
        nav_total: int = 0
        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup or not _is_html_page(pr):
                continue
            for nav in pr.soup.find_all("nav"):
                nav_total += 1
                if not nav.get("aria-label") and not nav.get("aria-labelledby"):
                    nav_missing_aria += 1

        if nav_missing_aria > 0:
            recs.append({
                "title": "Add aria-label to navigation elements",
                "rationale": f"{nav_missing_aria}/{nav_total} <nav> elements "
                             "lack aria-label. Labelling navigation regions "
                             "improves accessibility and helps AI engines "
                             "understand page structure.",
                "priority": "low",
            })

        # Suggest skip-to-content link
        has_skip = False
        for url in frontier[:3]:
            pr = page_results.get(url)
            if not pr or not pr.soup or not _is_html_page(pr):
                continue
            for a in pr.soup.find_all("a", href=True):
                text = a.get_text(strip=True).lower()
                if "skip" in text and ("content" in text or "main" in text):
                    has_skip = True
                    break
        if not has_skip:
            recs.append({
                "title": "Add skip-to-content navigation link",
                "rationale": "A 'Skip to main content' link improves "
                             "accessibility and signals good UX practices "
                             "to AI quality evaluators.",
                "priority": "low",
            })

    except Exception as exc:
        logger.debug("Proactive recs error: %s", exc)
    return recs


def _check_rendered_engagement(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """Detect engagement elements (CTAs or interactive overlays) post-rendering."""
    findings: list[dict] = []
    rendered_cta_pages: list[str] = []

    for url in frontier:
        pr = page_results.get(url)
        if pr and pr.rendered_soup:
            static_ctas = 0
            if pr.soup:
                for el in pr.soup.find_all(["a", "button"]):
                    text = el.get_text(strip=True)
                    if _CTA_RE.search(text):
                        static_ctas += 1

            rendered_ctas = 0
            for el in pr.rendered_soup.find_all(["a", "button"]):
                text = el.get_text(strip=True)
                if _CTA_RE.search(text):
                    rendered_ctas += 1

            if static_ctas == 0 and rendered_ctas > 0:
                rendered_cta_pages.append(url)

    if rendered_cta_pages:
        findings.append(_finding(
            "ER-005",
            "Dynamic call-to-action (CTA) elements detected post-rendering",
            "info",
            f"Primary conversion CTAs appear exclusively in post-JS rendered DOM on "
            f"{len(rendered_cta_pages)} page(s): " + "; ".join(rendered_cta_pages[:3]) +
            ", but are absent in raw static HTML.",
            "Ensure primary user action buttons and links are present in static HTML "
            "markup to allow AI agents to navigate conversion paths.",
            pages_affected=len(rendered_cta_pages),
            pages_checked=len(frontier),
            source="rendered",
        ))
    return findings


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================
def run_audit(target_url: str, http_client: HttpClient, **kwargs: Any) -> dict:
    """Execute Engagement & Retention checks ER-001 -> ER-008."""
    frontier: list[str] = kwargs.get("crawl_frontier", [target_url])
    page_results: dict[str, PageResult] = kwargs.get("page_results", {})

    if not page_results:
        for url in frontier:
            try:
                pr = http_client.get(url)
                page_results[pr.url or url] = pr
            except Exception as exc:
                page_results[url] = PageResult(url=url, error=str(exc))

    errors: list[str] = []
    findings: list[dict] = []

    timeout_s = kwargs.get("timeout_s", None)
    t_start = kwargs.get("t_start", None)

    findings.extend(_check_er001(frontier, page_results))
    findings.extend(_check_er002(frontier, page_results, target_url))
    findings.extend(_check_er003(frontier, page_results))
    findings.extend(_check_er004(frontier, page_results, http_client, target_url, t_start=t_start, timeout_s=timeout_s))
    findings.extend(_check_er005(frontier, page_results))
    findings.extend(_check_er006_er007(frontier, page_results))
    findings.extend(_check_er008(frontier, page_results))
    findings.extend(_check_rendered_engagement(frontier, page_results))

    proactive = _proactive(frontier, page_results)

    return {
        "domain": "engagement-retention",
        "pages_analyzed": sum(
            1 for u in frontier if u in page_results and
            page_results[u].status_code and
            200 <= page_results[u].status_code < 400
        ),
        "pages_discovered": len(frontier),
        "errors": errors,
        "findings": findings,
        "proactive_candidates": proactive,
    }
