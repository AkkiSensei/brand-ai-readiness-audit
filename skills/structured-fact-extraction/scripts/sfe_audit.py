"""
sfe_audit.py
============
Domain sub-skill: Structured Fact Extraction (SF-001 -> SF-008)

Validates Schema.org JSON-LD markup, detects facts trapped in images/canvas/PDFs,
and inspects document freshness metadata across the crawl frontier.
"""

from __future__ import annotations

import json
import logging
import re
import string
import sys
import urllib.parse
from collections import Counter
from itertools import combinations
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2]
    / "crawl-render-access"
    / "scripts"
)
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from http_client import HttpClient, PageResult, normalise_url

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
_SD = _T.get("structured_data", {})

MIN_ORG_FIELDS: int = int(_SD.get("min_jsonld_fields_organization", 4))
MIN_PROD_FIELDS: int = int(_SD.get("min_jsonld_fields_product", 3))
STALE_DAYS: int = int(_SD.get("freshness_stale_age_days", 365))
MAX_AGE_DAYS: int = int(_SD.get("freshness_max_age_days", 180))
IMG_TEXT_RATIO: float = float(_SD.get("image_text_ratio_threshold", 0.40))

# Regex patterns for facts that should be in machine-readable text
_PRICE_RE = re.compile(
    r"(?:(?:USD|EUR|GBP|INR|CAD|AUD)\s*\d|[\$\u20ac\u00a3\u20b9]\s*\d{1,3}(?:[,\.]\d{2,3})*)",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s\-\.]?)?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}"
)
_ADDRESS_RE = re.compile(
    r"\d{1,5}\s+[\w\s]{3,40}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct)",
    re.IGNORECASE,
)

# Required fields per schema type
_ORG_REQUIRED = {"name", "url"}
_ORG_RECOMMENDED = {"logo", "sameAs", "contactPoint", "address"}
_PRODUCT_REQUIRED = {"name"}
_PRODUCT_RECOMMENDED = {"image", "description", "offers", "brand", "sku"}


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
) -> dict:
    d = {
        "local_id": local_id,
        "title": title,
        "severity": severity,
        "category": "discoverability",
        "evidence": evidence,
        "suggested_action": {"summary": action, "priority": severity},
        "related_to": related or [],
    }
    if pages_affected is not None:
        d["pages_affected"] = pages_affected
    if pages_checked is not None:
        d["pages_checked"] = pages_checked
    return d


# ---------------------------------------------------------------------------
# JSON-LD extraction helpers
# ---------------------------------------------------------------------------
def _extract_jsonld_blocks(soup: Any) -> list[dict]:
    """Extract and parse all JSON-LD blocks from a page."""
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
                    else:
                        blocks.append({"_parse_error": True, "_raw": str(item)[:500]})
            elif isinstance(data, dict):
                # Handle @graph
                if "@graph" in data:
                    graph = data["@graph"]
                    if isinstance(graph, list):
                        for item in graph:
                            if isinstance(item, dict):
                                blocks.append(item)
                            else:
                                blocks.append({"_parse_error": True, "_raw": str(item)[:500]})
                    elif isinstance(graph, dict):
                        blocks.append(graph)
                    else:
                        blocks.append({"_parse_error": True, "_raw": str(graph)[:500]})
                else:
                    blocks.append(data)
            else:
                # Primitive JSON-LD root (string, integer, boolean, null)
                blocks.append({"_parse_error": True, "_raw": str(data)[:500]})
        except (json.JSONDecodeError, TypeError):
            blocks.append({"_parse_error": True, "_raw": raw[:500]})
    return blocks


def _get_types(block: Any) -> list[str]:
    """Return normalised @type values from a JSON-LD block."""
    if not isinstance(block, dict):
        return []
    t = block.get("@type", "")
    if isinstance(t, list):
        return [str(x).strip() for x in t if x]
    return [str(t).strip()] if t else []


def _count_fields(block: Any, field_set: set[str]) -> int:
    """Count how many of the expected fields are present and non-empty."""
    if not isinstance(block, dict):
        return 0
    count = 0
    for key in field_set:
        val = block.get(key)
        if val is not None and val != "" and val != []:
            count += 1
    return count


def _find_entities(
    data: Any,
    target_types: tuple[str, ...],
    max_depth: int = 3,
    current_path: str = "",
) -> list[tuple[dict, str]]:
    """Recursively search for objects matching target @type values up to max_depth."""
    results: list[tuple[dict, str]] = []
    if not isinstance(data, (dict, list)) or max_depth < 0:
        return results
    if isinstance(data, list):
        for idx, item in enumerate(data):
            results.extend(_find_entities(item, target_types, max_depth - 1, f"{current_path}[{idx}]"))
    elif isinstance(data, dict):
        types = [t.lower() for t in _get_types(data)]
        for t in types:
            if t in target_types:
                results.append((data, current_path or "root"))
                break
        for k, v in data.items():
            if k in (
                "author", "publisher", "about", "creator", "provider",
                "founder", "sourceOrganization", "maintainer", "@graph",
                "item", "hasPart", "isPartOf", "offers",
            ):
                p = f"{current_path}.{k}" if current_path else k
                results.extend(_find_entities(v, target_types, max_depth - 1, p))
    return results


# ===================================================================
# CHECK FUNCTIONS
# ===================================================================

def _check_sf001_sf002(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> tuple[list[dict], list[str]]:
    """SF-001 (high/low): Missing JSON-LD / nested Org. SF-002 (medium): Invalid/incomplete JSON-LD."""
    findings: list[dict] = []
    errors: list[str] = []
    homepage_url = frontier[0] if frontier else ""
    homepage_has_org = False
    homepage_has_nested_org = False
    homepage_nested_org_info: list[str] = []
    pages_with_jsonld = 0
    parse_error_urls: list[str] = []
    incomplete_urls: list[str] = []
    missing_fields_detail: list[str] = []

    for url in frontier:
        pr = page_results.get(url) or page_results.get(url.rstrip("/")) or page_results.get(url + "/")
        if not pr or not pr.soup:
            continue
        blocks = _extract_jsonld_blocks(pr.soup)
        if not blocks:
            continue
        pages_with_jsonld += 1

        for block in blocks:
            if block.get("_parse_error"):
                parse_error_urls.append(url)
                continue

            is_home = (url == homepage_url or is_homepage(url, homepage_url))

            # Check for organizations (both top-level and nested)
            org_matches = _find_entities(
                block, ("organization", "localbusiness", "corporation")
            )
            for entity, path in org_matches:
                if path == "root":
                    if is_home:
                        homepage_has_org = True
                    present = _count_fields(entity, _ORG_REQUIRED | _ORG_RECOMMENDED)
                    if present < MIN_ORG_FIELDS:
                        missing = (
                            _ORG_REQUIRED | _ORG_RECOMMENDED
                        ) - set(entity.keys())
                        incomplete_urls.append(url)
                        missing_fields_detail.append(
                            f"{url}: Organization missing {', '.join(sorted(missing)[:4])}"
                        )
                else:
                    if is_home:
                        homepage_has_nested_org = True
                        org_name = entity.get("name") or "unnamed"
                        homepage_nested_org_info.append(f"{path} ({org_name})")

            # Check for products/offers/services
            prod_matches = _find_entities(
                block, ("product", "offer", "service")
            )
            for entity, path in prod_matches:
                if path == "root":
                    present = _count_fields(entity, _PRODUCT_REQUIRED | _PRODUCT_RECOMMENDED)
                    if present < MIN_PROD_FIELDS:
                        missing = (
                            _PRODUCT_REQUIRED | _PRODUCT_RECOMMENDED
                        ) - set(entity.keys())
                        incomplete_urls.append(url)
                        missing_fields_detail.append(
                            f"{url}: Product missing {', '.join(sorted(missing)[:4])}"
                        )

    # SF-001: No JSON-LD at all or no Organization on homepage
    if pages_with_jsonld == 0:
        findings.append(_finding(
            "SF-001",
            "No JSON-LD structured data found on any page",
            "high",
            f"Scanned {len(frontier)} pages; zero contained "
            "application/ld+json script blocks.",
            "Add Schema.org JSON-LD markup to at least the homepage "
            "(Organization), product pages (Product), and article pages "
            "(Article). This is critical for AI-engine fact extraction.",
        ))
    elif not homepage_has_org and not homepage_has_nested_org:
        findings.append(_finding(
            "SF-001",
            "No Organization schema on homepage",
            "high",
            "The homepage lacks a JSON-LD block with @type Organization "
            "(or LocalBusiness/Corporation). AI engines cannot reliably "
            "identify your brand entity.",
            "Add a JSON-LD Organization block to the homepage with at least "
            "name, url, logo, and sameAs properties.",
            related=["TC-001"],
        ))
    elif not homepage_has_org and homepage_has_nested_org:
        nested_desc = ", ".join(homepage_nested_org_info[:3])
        findings.append(_finding(
            "SF-001",
            "Organization schema is nested rather than top-level",
            "low",
            f"Homepage contains Organization/Corporation schema nested under {nested_desc}, "
            "but lacks a dedicated top-level Organization entity. While present, nested-only "
            "declarations can lead to ambiguous brand entity resolution by some AI crawlers.",
            "Promote the Organization schema to a top-level entity or reference it via @id "
            "on the homepage to ensure prominent brand recognition by AI search engines.",
            related=["TC-001"],
        ))

    # SF-002: Parse errors
    if parse_error_urls:
        unique_err_urls = list(set(parse_error_urls))
        findings.append(_finding(
            "SF-002",
            "Invalid JSON-LD syntax detected",
            "high",
            f"{len(unique_err_urls)} page(s) have JSON-LD blocks that "
            "fail JSON parsing: " + "; ".join(unique_err_urls[:5]),
            "Fix JSON syntax errors in application/ld+json script blocks. "
            "Validate with Google Rich Results Test.",
        ))

    # SF-002: Incomplete schemas
    if missing_fields_detail:
        findings.append(_finding(
            "SF-002",
            "JSON-LD schemas missing recommended properties",
            "medium",
            "; ".join(missing_fields_detail[:5]),
            "Add missing recommended properties to improve AI-engine "
            "understanding. Use Schema.org documentation as reference.",
            related=["SF-001"],
        ))

    return findings, errors


def _check_sf003_sf004(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """SF-003 / SF-004 (critical): Facts trapped in images, canvas, or video."""
    findings: list[dict] = []
    try:
        img_fact_pages: list[str] = []
        canvas_pages: list[str] = []
        video_no_track: list[str] = []

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # Get visible text content for comparison
            visible_text = pr.soup.get_text(separator=" ", strip=True)

            # Check images with alt text containing facts not in visible text
            for img in pr.soup.find_all("img"):
                alt = img.get("alt", "")
                if not alt or len(alt) < 10:
                    continue
                # Check if alt contains pricing, phone, or address not in text
                has_price_in_alt = bool(_PRICE_RE.search(alt))
                has_phone_in_alt = bool(_PHONE_RE.search(alt))
                has_addr_in_alt = bool(_ADDRESS_RE.search(alt))

                if has_price_in_alt or has_phone_in_alt or has_addr_in_alt:
                    # Verify these facts are also in visible text
                    price_in_text = bool(_PRICE_RE.search(visible_text))
                    phone_in_text = bool(_PHONE_RE.search(visible_text))
                    addr_in_text = bool(_ADDRESS_RE.search(visible_text))

                    if (has_price_in_alt and not price_in_text) or \
                       (has_phone_in_alt and not phone_in_text) or \
                       (has_addr_in_alt and not addr_in_text):
                        img_fact_pages.append(url)
                        break

            # Check for images with NO alt that might contain text (infographics)
            images_no_alt = pr.soup.find_all(
                "img", alt=lambda x: x is None or x.strip() == ""
            )
            # Heuristic: if multiple uncaptioned images and page is content-sparse (< 150 words)
            if len(images_no_alt) > 3:
                words = len(visible_text.split())
                if words < 150:
                    text_len = len(visible_text)
                    html_len = len(str(pr.soup))
                    ratio = text_len / html_len if html_len > 0 else 0
                    if ratio < IMG_TEXT_RATIO and url not in img_fact_pages:
                        img_fact_pages.append(url)

            # Canvas elements
            canvas_elems = pr.soup.find_all("canvas")
            for c in canvas_elems:
                fallback_text = c.get_text(strip=True)
                aria_label = c.get("aria-label", "")
                if not fallback_text and not aria_label:
                    canvas_pages.append(url)
                    break

            # Video without captions/tracks
            for video in pr.soup.find_all("video"):
                tracks = video.find_all("track")
                if not tracks:
                    video_no_track.append(url)
                    break

        if img_fact_pages:
            findings.append(_finding(
                "SF-003",
                "Key facts trapped in images without text alternatives",
                "critical",
                f"{len(img_fact_pages)} page(s) contain pricing, contact info, "
                "or other key facts only in image alt text or in images lacking "
                "alt text: " + "; ".join(img_fact_pages[:5]),
                "Extract key facts (prices, phone numbers, addresses, spec "
                "tables) from images into visible HTML text or structured data. "
                "Ensure all informational images have descriptive alt text.",
                related=["SF-004"],
            ))

        if canvas_pages:
            findings.append(_finding(
                "SF-004",
                "Canvas elements without accessible fallback content",
                "medium",
                f"{len(canvas_pages)} page(s) use <canvas> without fallback "
                "text or aria-label: " + "; ".join(canvas_pages[:5]),
                "Add fallback text content inside <canvas> tags and use "
                "aria-label for accessibility. AI crawlers cannot parse canvas "
                "rendered content.",
            ))

        if video_no_track:
            findings.append(_finding(
                "SF-004",
                "Video elements without caption tracks",
                "medium",
                f"{len(video_no_track)} page(s) have <video> elements "
                "without <track> subtitles/captions: "
                + "; ".join(video_no_track[:5]),
                "Add WebVTT caption tracks to all video elements. AI engines "
                "cannot extract spoken content from video files.",
                related=["SF-003"],
            ))

    except Exception as exc:
        logger.debug("SF-003/004 error: %s", exc)
    return findings


def _check_sf005(
    frontier: list[str],
    page_results: dict[str, PageResult],
    http_client: HttpClient,
) -> list[dict]:
    """SF-005 (high): Linked PDFs without text alternatives."""
    findings: list[dict] = []
    try:
        pdf_links: list[str] = []
        pdf_pages: list[str] = []

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue
            for a_tag in pr.soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.lower().endswith(".pdf"):
                    abs_href = normalise_url(href, url)
                    if abs_href and abs_href not in pdf_links:
                        pdf_links.append(abs_href)
                        pdf_pages.append(url)

        if pdf_links:
            # Verify PDFs exist and check if page has text alternative
            orphan_pdfs: list[str] = []
            for pdf_url, page_url in zip(pdf_links[:10], pdf_pages[:10]):
                # Check if the linking page contains visible text covering
                # the PDF content (heuristic: if the link anchor text is
                # very short like "Download PDF", the content is likely
                # only in the PDF)
                pr = page_results.get(page_url)
                if pr and pr.soup:
                    for a_tag in pr.soup.find_all("a", href=True):
                        href = a_tag["href"]
                        if href.lower().endswith(".pdf"):
                            link_text = a_tag.get_text(strip=True)
                            if len(link_text) < 30:
                                orphan_pdfs.append(pdf_url)
                                break

            if orphan_pdfs:
                findings.append(_finding(
                    "SF-005",
                    "PDFs linked without HTML text alternative content",
                    "high",
                    f"{len(orphan_pdfs)} PDF(s) are linked with minimal anchor "
                    "text, suggesting content is trapped in the PDF without an "
                    "HTML text equivalent: " + "; ".join(orphan_pdfs[:5]),
                    "Create HTML landing pages summarising each PDF's key "
                    "content. Add descriptive anchor text. AI crawlers cannot "
                    "reliably parse PDF content for citation.",
                ))

    except Exception as exc:
        logger.debug("SF-005 error: %s", exc)
    return findings


def _check_sf006(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """SF-006 (medium, proactive): Q&A headings lacking FAQPage schema."""
    findings: list[dict] = []
    try:
        qa_pages: list[str] = []
        _QA_RE = re.compile(r"\?\s*$")

        for url in frontier:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # Check if page already has FAQPage schema
            blocks = _extract_jsonld_blocks(pr.soup)
            has_faq_schema = any(
                "FAQPage" in _get_types(b) for b in blocks if not b.get("_parse_error")
            )
            if has_faq_schema:
                continue

            # Check for Q&A-shaped headings
            question_count = 0
            for tag in pr.soup.find_all(["h2", "h3", "h4"]):
                text = tag.get_text(strip=True)
                if _QA_RE.search(text) and len(text) > 10:
                    question_count += 1

            if question_count >= 2:
                qa_pages.append(f"{url} ({question_count} questions)")

        if qa_pages:
            findings.append(_finding(
                "SF-006",
                "Q&A content detected without FAQPage schema",
                "medium",
                f"{len(qa_pages)} page(s) contain question-style headings "
                "without FAQPage JSON-LD markup: " + "; ".join(qa_pages[:5]),
                "Add FAQPage structured data to pages with Q&A content. This "
                "enables rich results and improves AI-engine FAQ extraction.",
                pages_affected=len(qa_pages),
                pages_checked=len(frontier),
            ))

    except Exception as exc:
        logger.debug("SF-006 error: %s", exc)
    return findings


def _check_sf007_sf008(
    frontier: list[str],
    page_results: dict[str, PageResult],
) -> list[dict]:
    """SF-007 (medium): Stale content. SF-008 (medium): Duplicate titles/descriptions."""
    findings: list[dict] = []
    try:
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=STALE_DAYS)
        warn_cutoff = now - timedelta(days=MAX_AGE_DAYS)
        stale_pages: list[str] = []
        no_freshness: list[str] = []
        titles: Counter[str] = Counter()
        descriptions: Counter[str] = Counter()
        title_map: dict[str, list[str]] = {}
        desc_map: dict[str, list[str]] = {}

        html_pages = [u for u in frontier if page_results.get(u) and getattr(page_results[u], 'is_html', True) and page_results[u].soup]
        if not html_pages:
            return findings

        for url in html_pages:
            pr = page_results.get(url)
            if not pr or not pr.soup:
                continue

            # --- Freshness (SF-007) ---
            freshness_date: Optional[datetime] = None

            # Check JSON-LD dateModified/datePublished
            blocks = _extract_jsonld_blocks(pr.soup)
            for block in blocks:
                if block.get("_parse_error"):
                    continue
                for key in ("dateModified", "datePublished"):
                    val = block.get(key, "")
                    if val:
                        freshness_date = _parse_date(val)
                        if freshness_date:
                            break
                if freshness_date:
                    break

            # Check <meta> dateModified
            if not freshness_date:
                for name in ("article:modified_time", "article:published_time",
                             "last-modified", "date"):
                    meta = pr.soup.find("meta", attrs={"property": name}) or \
                           pr.soup.find("meta", attrs={"name": name})
                    if meta and meta.get("content"):
                        freshness_date = _parse_date(meta["content"])
                        if freshness_date:
                            break

            # Check <time> element
            if not freshness_date:
                time_el = pr.soup.find("time", datetime=True)
                if time_el:
                    freshness_date = _parse_date(time_el["datetime"])

            # Check Last-Modified header
            if not freshness_date:
                lm = pr.response_headers.get("last-modified", "")
                if lm:
                    freshness_date = _parse_http_date(lm)

            if freshness_date:
                if freshness_date < stale_cutoff:
                    stale_pages.append(url)
            else:
                no_freshness.append(url)

            # --- Titles / Descriptions (SF-008) ---
            title_tag = pr.soup.find("title")
            title_text = title_tag.get_text(strip=True) if title_tag else ""
            if title_text:
                titles[title_text] += 1
                title_map.setdefault(title_text, []).append(url)

            meta_desc = pr.soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
            desc_text = (meta_desc.get("content") or "").strip() if meta_desc else ""
            if desc_text:
                descriptions[desc_text] += 1
                desc_map.setdefault(desc_text, []).append(url)

        # SF-007 findings
        if stale_pages:
            findings.append(_finding(
                "SF-007",
                "Pages with stale content metadata",
                "medium",
                f"{len(stale_pages)} page(s) have content dated older than "
                f"{STALE_DAYS} days: " + "; ".join(stale_pages[:5]),
                "Update content freshness signals (dateModified in JSON-LD, "
                "Last-Modified header, or meta tags) when content is revised.",
                pages_affected=len(stale_pages),
                pages_checked=len(html_pages),
            ))

        if no_freshness and len(no_freshness) > len(html_pages) * 0.5:
            findings.append(_finding(
                "SF-007",
                "Pages missing freshness metadata",
                "low",
                f"{len(no_freshness)}/{len(html_pages)} pages lack any date "
                "signal (dateModified, Last-Modified, etc.).",
                "Add datePublished and dateModified properties to JSON-LD "
                "structured data or use <meta> property tags.",
                related=["SF-002"],
                pages_affected=len(no_freshness),
                pages_checked=len(html_pages),
            ))

        # SF-008: Duplicate titles
        dup_titles = {t: urls for t, urls in title_map.items() if len(urls) > 1}
        if dup_titles:
            dup_count = sum(len(u) for u in dup_titles.values())
            sample = "; ".join(
                f'"{t}" on {len(urls)} pages'
                for t, urls in list(dup_titles.items())[:3]
            )
            findings.append(_finding(
                "SF-008",
                "Duplicate or generic page titles detected",
                "medium",
                f"{dup_count} pages share duplicate <title> tags: {sample}",
                "Write unique, descriptive <title> tags for each page. "
                "Include the brand name and page-specific keywords to help "
                "AI engines distinguish page content.",
            ))

        # SF-008: Duplicate descriptions
        dup_descs = {d: urls for d, urls in desc_map.items() if len(urls) > 1}
        if dup_descs:
            dup_count = sum(len(u) for u in dup_descs.values())
            findings.append(_finding(
                "SF-008",
                "Duplicate meta descriptions detected",
                "medium",
                f"{dup_count} pages share identical meta descriptions.",
                "Write unique meta descriptions per page summarising the "
                "specific content. AI engines use these for citation context.",
            ))

    except Exception as exc:
        logger.debug("SF-007/008 error: %s", exc)
    return findings


# ---------------------------------------------------------------------------
# Date parsing helpers
# ---------------------------------------------------------------------------
def _parse_date(value: str) -> Optional[datetime]:
    """Try to parse an ISO-8601 date string."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%B %d, %Y"):
        try:
            dt = datetime.strptime(value[:25], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, IndexError):
            continue
    return None


def _parse_http_date(value: str) -> Optional[datetime]:
    """Parse RFC 7231 HTTP-date (e.g. Last-Modified header)."""
    if not value:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z",
                "%A, %d-%b-%y %H:%M:%S %Z",
                "%a %b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(value.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def is_homepage(url: str, homepage_url: str) -> bool:
    """Heuristic: is this URL the homepage?"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.path in ("", "/", "/index.html", "/index.htm")
    except Exception:
        return url == homepage_url


# ---------------------------------------------------------------------------
# Proactive recommendations
# ---------------------------------------------------------------------------
def _proactive(frontier: list[str], page_results: dict[str, PageResult]) -> list[dict]:
    recs: list[dict] = []
    try:
        # Check for missing Article schema on blog-like pages
        blog_like = 0
        has_article = 0
        for url in frontier:
            if any(seg in url.lower() for seg in ("/blog", "/news", "/article", "/post")):
                blog_like += 1
                pr = page_results.get(url)
                if pr and pr.soup:
                    blocks = _extract_jsonld_blocks(pr.soup)
                    if any("Article" in _get_types(b) or "BlogPosting" in _get_types(b)
                           for b in blocks if not b.get("_parse_error")):
                        has_article += 1

        if blog_like > 0 and has_article < blog_like:
            recs.append({
                "title": "Add Article/BlogPosting schema to blog content",
                "rationale": f"{blog_like - has_article} blog-like page(s) lack "
                             "Article structured data, reducing AI-engine citation "
                             "quality for editorial content.",
                "priority": "medium",
            })

        # Suggest WebSite SearchAction
        has_search = False
        for url in frontier:
            pr = page_results.get(url)
            if pr and pr.soup:
                blocks = _extract_jsonld_blocks(pr.soup)
                for b in blocks:
                    if "WebSite" in _get_types(b) and b.get("potentialAction"):
                        has_search = True
                        break
        if not has_search and len(frontier) > 5:
            recs.append({
                "title": "Add WebSite SearchAction structured data",
                "rationale": "A SearchAction on the WebSite schema enables AI "
                             "engines to reference your site's internal search.",
                "priority": "low",
            })

    except Exception as exc:
        logger.debug("Proactive error: %s", exc)
    return recs


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================
def run_audit(target_url: str, http_client: HttpClient, **kwargs: Any) -> dict:
    """Execute Structured Fact Extraction checks SF-001 -> SF-008."""
    frontier: list[str] = kwargs.get("crawl_frontier", [target_url])
    page_results: dict[str, PageResult] = kwargs.get("page_results", {})

    # If no page_results provided, fetch pages ourselves
    if not page_results:
        for url in frontier:
            try:
                pr = http_client.get(url)
                page_results[url] = pr
                if pr.url:
                    page_results[pr.url] = pr
            except Exception as exc:
                page_results[url] = PageResult(url=url, error=str(exc))

    errors: list[str] = []
    findings: list[dict] = []

    sf01_02, sf_errors = _check_sf001_sf002(frontier, page_results)
    findings.extend(sf01_02)
    errors.extend(sf_errors)
    findings.extend(_check_sf003_sf004(frontier, page_results))
    findings.extend(_check_sf005(frontier, page_results, http_client))
    findings.extend(_check_sf006(frontier, page_results))
    findings.extend(_check_sf007_sf008(frontier, page_results))

    proactive = _proactive(frontier, page_results)

    return {
        "domain": "structured-fact-extraction",
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
