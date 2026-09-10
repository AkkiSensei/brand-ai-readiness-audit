"""
crawl_audit.py
==============
Domain sub-skill: Crawl & Render Access (CR-001 -> CR-008)

Discovers the site crawl frontier (homepage + sitemap + internal links up to
max_pages) and audits for AI-crawler accessibility issues.

Returns ``crawl_frontier`` for consumption by peer domain skills.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Path bootstrap  -- http_client lives in the same scripts/ directory
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from http_client import (
    HttpClient,
    PlaywrightRenderer,
    PageResult,
    FrontierEntry,
    extract_text_ratio,
    normalise_url,
    is_same_origin,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Centralised thresholds
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
_CRAWL = _T.get("crawl", {})
_RENDER = _T.get("render", {})
_ROBOTS = _T.get("robots", {})
_ENGAGE = _T.get("engagement", {})

MAX_PAGES: int = int(_CRAWL.get("max_pages", 15))
MAX_DEPTH: int = int(_CRAWL.get("max_depth", 3))
SITEMAP_MAX: int = int(_CRAWL.get("sitemap_max_urls", 500))
DISALLOW_EXT: list[str] = _CRAWL.get("disallow_extensions", [])
TEXT_BLANK_THRESH: float = float(_RENDER.get("text_blanking_ratio_threshold", 0.15))
CSR_WARN_THRESH: float = float(_RENDER.get("csr_text_ratio_warning", 0.30))
OVERLAY_THRESH: float = float(_ENGAGE.get("overlay_coverage_threshold", 0.60))
AI_CRAWLERS: list[str] = _ROBOTS.get("known_ai_crawlers", [
    "GPTBot", "ChatGPT-User", "Google-Extended", "CCBot", "anthropic-ai",
])
STALE_DAYS: int = int(
    _T.get("structured_data", {}).get("freshness_stale_age_days", 365)
)


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
    """Return a finding dict conforming to the shared domain contract."""
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
# Frontier helpers
# ---------------------------------------------------------------------------
def _skip_url(url: str) -> bool:
    """Return True if the URL should be excluded from the frontier."""
    parsed = urllib.parse.urlparse(url)
    lower = parsed.path.lower()
    for ext in DISALLOW_EXT:
        if lower.endswith(ext):
            return True
    if parsed.scheme not in ("http", "https"):
        return True
    return False


def _parse_sitemap_xml(xml_text: str) -> list[str]:
    """Extract all <loc> URLs from sitemap XML."""
    urls: list[str] = []
    try:
        root = ET.fromstring(xml_text)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        for loc in root.iter(f"{ns}loc"):
            if loc.text:
                urls.append(loc.text.strip())
    except ET.ParseError:
        pass
    return urls


def _is_sitemap_index(xml_text: str) -> bool:
    try:
        root = ET.fromstring(xml_text)
        return "sitemapindex" in root.tag.lower()
    except ET.ParseError:
        return False


def _get_sitemap_lastmods(xml_text: str) -> list[Optional[str]]:
    """Return <lastmod> text for each <url> entry (None if absent)."""
    mods: list[Optional[str]] = []
    try:
        root = ET.fromstring(xml_text)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        for url_elem in root.iter(f"{ns}url"):
            lm = url_elem.find(f"{ns}lastmod")
            mods.append(lm.text.strip() if lm is not None and lm.text else None)
    except ET.ParseError:
        pass
    return mods


def _fetch_sitemap_urls(
    sitemap_url: str,
    client: HttpClient,
    visited: set[str] | None = None,
    depth: int = 0,
    t_start: float | None = None,
    timeout_s: float | None = None,
) -> tuple[list[str], str]:
    """Recursively fetch sitemap URLs. Returns (urls, raw_xml)."""
    if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
        return [], ""
    if visited is None:
        visited = set()
    if sitemap_url in visited or depth > 3:
        return [], ""
    visited.add(sitemap_url)

    result = client.get(sitemap_url, skip_robots_check=True)
    if result.error or not result.html:
        return [], ""

    raw_xml = result.html
    if _is_sitemap_index(raw_xml):
        sub_urls = _parse_sitemap_xml(raw_xml)
        all_urls: list[str] = []
        for sub in sub_urls[:10]:
            if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
                break
            child_urls, _ = _fetch_sitemap_urls(
                sub, client, visited, depth + 1, t_start=t_start, timeout_s=timeout_s,
            )
            all_urls.extend(child_urls)
            if len(all_urls) >= SITEMAP_MAX:
                break
        return all_urls[:SITEMAP_MAX], raw_xml
    else:
        return _parse_sitemap_xml(raw_xml)[:SITEMAP_MAX], raw_xml


def _extract_links(soup: Any, base_url: str) -> list[str]:
    """Extract unique same-origin <a href> links."""
    if soup is None:
        return []
    seen: set[str] = set()
    links: list[str] = []
    for a_tag in soup.find_all("a", href=True):
        abs_url = normalise_url(a_tag["href"], base_url)
        if not abs_url or abs_url in seen:
            continue
        if not is_same_origin(abs_url, base_url):
            continue
        if _skip_url(abs_url):
            continue
        seen.add(abs_url)
        links.append(abs_url)
    return links


# ---------------------------------------------------------------------------
# Frontier discovery
# ---------------------------------------------------------------------------
def _discover_frontier(
    target_url: str,
    client: HttpClient,
    max_pages: int = MAX_PAGES,
    t_start: float | None = None,
    timeout_s: float | None = None,
) -> tuple[list[str], dict[str, PageResult], list[str], str]:
    """BFS crawl to build the page frontier.

    Returns:
        frontier      -- ordered list of absolute URLs
        page_results  -- {url: PageResult} for fetched pages
        errors        -- non-fatal error messages
        sitemap_xml   -- raw XML of the first valid sitemap (for CR-006/007)
    """
    errors: list[str] = []
    page_results: dict[str, PageResult] = {}
    frontier: list[str] = []
    visited: set[str] = set()
    sitemap_xml: str = ""

    # -- 1. Fetch homepage --
    home = client.get(target_url)
    if home.error:
        errors.append(f"Homepage fetch failed: {home.error}")
    final_home = home.url or target_url
    page_results[final_home] = home
    frontier.append(final_home)
    visited.update({target_url, final_home})

    # -- 2. Sitemaps from robots.txt --
    sm_from_robots = client.robots.get_sitemaps(target_url)
    sm_candidates = list(sm_from_robots)

    # Fallback: try standard paths
    if not sm_candidates:
        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin += f":{parsed.port}"
        sm_candidates = [origin + "/sitemap.xml", origin + "/sitemap_index.xml"]

    # -- 3. Fetch sitemap URLs --
    sm_page_urls: list[str] = []
    sm_visited: set[str] = set()
    for sm_url in sm_candidates:
        if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
            errors.append("Sitemap discovery truncated: timeout budget reached")
            break
        try:
            urls, raw = _fetch_sitemap_urls(
                sm_url, client, sm_visited, t_start=t_start, timeout_s=timeout_s,
            )
            sm_page_urls.extend(urls)
            if raw and not sitemap_xml:
                sitemap_xml = raw
        except Exception as exc:
            errors.append(f"Sitemap error ({sm_url}): {exc}")

    # -- 4. Seed BFS queue --
    queue: list[tuple[str, int]] = []
    for u in sm_page_urls:
        if u not in visited and is_same_origin(u, target_url):
            queue.append((u, 1))

    if home.soup:
        for link in _extract_links(home.soup, final_home):
            if link not in visited:
                queue.append((link, 1))

    # -- 5. BFS --
    while queue and len(frontier) < max_pages:
        if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
            errors.append("Crawl frontier truncated: timeout budget reached")
            break
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if depth > MAX_DEPTH:
            continue
        if _skip_url(url):
            continue

        pr = client.get(url)
        if pr.error:
            errors.append(f"Fetch error ({url}): {pr.error}")

        final_url = pr.url or url
        page_results[final_url] = pr
        if final_url not in frontier:
            frontier.append(final_url)
        visited.add(final_url)

        if pr.soup and depth < MAX_DEPTH:
            for link in _extract_links(pr.soup, final_url):
                if link not in visited:
                    queue.append((link, depth + 1))

    return frontier, page_results, errors, sitemap_xml


# ===================================================================
# CHECK FUNCTIONS
# ===================================================================

def _check_cr001(target_url: str, client: HttpClient) -> list[dict]:
    """CR-001 (critical): AI crawler blocked in robots.txt."""
    findings: list[dict] = []
    try:
        blocked = client.robots.get_disallowed_ai_agents(target_url)
        if blocked:
            findings.append(_finding(
                "CR-001",
                "AI crawlers explicitly blocked by robots.txt",
                "critical",
                f"{len(blocked)} AI crawler(s) blocked: {', '.join(blocked)}. "
                f"These bots cannot index site content.",
                "Review robots.txt and remove or narrow Disallow rules for AI "
                "crawlers such as GPTBot and Google-Extended to allow AI-driven "
                "discovery of your brand content.",
            ))
    except Exception as exc:
        logger.debug("CR-001 error: %s", exc)
    return findings


def _check_cr002(
    page_results: dict[str, PageResult],
) -> list[dict]:
    """CR-002 (high): Non-200/301 status codes or excessive redirect chains."""
    findings: list[dict] = []
    try:
        bad_codes: list[str] = []
        long_redirects: list[str] = []
        for url, pr in page_results.items():
            if pr.status_code is not None and pr.status_code not in (200, 301):
                bad_codes.append(f"{url} -> {pr.status_code}")
            elif pr.status_code is None and pr.error:
                bad_codes.append(f"{url} -> {pr.error[:80]}")
            if len(pr.redirect_chain) > 2 or (pr.error and "redirect" in pr.error.lower()):
                long_redirects.append(
                    f"{url} ({len(pr.redirect_chain)} hops)" if pr.redirect_chain else f"{url} (redirect loop)"
                )
        total_pages = len(page_results)
        if bad_codes:
            findings.append(_finding(
                "CR-002",
                "Pages returning non-OK HTTP status codes",
                "high",
                f"{len(bad_codes)} URL(s) with unexpected status: "
                + "; ".join(bad_codes[:5])
                + ("..." if len(bad_codes) > 5 else ""),
                "Fix server responses so all public pages return 200 (OK) or "
                "use 301 for permanent redirects. Remove or correct links to "
                "pages returning 4xx/5xx errors.",
                pages_affected=len(bad_codes),
                pages_checked=total_pages,
            ))
        if long_redirects:
            findings.append(_finding(
                "CR-002",
                "Excessive redirect chains detected",
                "low",
                f"{len(long_redirects)} URL(s) with >2 redirect hops: "
                + "; ".join(long_redirects[:5]),
                "Shorten redirect chains to at most 1-2 hops to avoid crawler "
                "timeouts and wasted crawl budget.",
                related=["CR-008"],
                pages_affected=len(long_redirects),
                pages_checked=total_pages,
            ))
    except Exception as exc:
        logger.debug("CR-002 error: %s", exc)
    return findings


def _check_cr003_cr004(
    page_results: dict[str, PageResult],
    renderer: Optional[PlaywrightRenderer] = None,
) -> list[dict]:
    """CR-003 (critical) / CR-004 (high): SSR-vs-CSR text blanking."""
    findings: list[dict] = []
    try:
        severe_urls: set[str] = set()
        moderate_urls: set[str] = set()
        spa_shell_urls: set[str] = set()
        display: dict[str, str] = {}

        for url, pr in page_results.items():
            if pr.soup is None:
                continue

            raw_ratio = extract_text_ratio(pr.soup)

            # Extract visible text and word count to evaluate true content presence
            working = BeautifulSoup(str(pr.soup), "html.parser")
            for tag in working.find_all(["script", "style", "noscript", "meta", "link", "svg"]):
                tag.decompose()
            visible_text = working.get_text(separator=" ", strip=True)
            word_count = len(visible_text.split())

            # Detect empty SPA shells (app root + dynamic script + sparse initial text)
            html_str = str(pr.soup).lower()
            has_app_root = bool(
                pr.soup.find(id="root")
                or pr.soup.find(id="app")
                or pr.soup.find(id="__next")
                or pr.soup.find(id="__nuxt")
            )
            has_module_script = bool(
                re.search(r'<script[^>]*type\s*=\s*["\']module["\']', html_str)
                or "window.__initial_state__" in html_str
            )
            is_spa = bool(has_app_root and has_module_script and word_count < 80)
            if is_spa and raw_ratio < CSR_WARN_THRESH:
                spa_shell_urls.add(url)
                display.setdefault(url, f"{url} (SPA shell)")

            # Compare rendered vs raw if Playwright is available
            rendered_ratio: Optional[float] = None
            rendered_ok = False
            if renderer is not None:
                try:
                    rr = renderer.render(url)
                    if rr.rendered_soup:
                        rendered_ratio = extract_text_ratio(rr.rendered_soup)
                        rendered_ok = True
                except Exception:
                    pass

            has_substantial_text = (word_count >= 250 and len(visible_text) >= 1000)

            if rendered_ok and rendered_ratio is not None and rendered_ratio > raw_ratio:
                # Playwright execution revealed dynamic content
                disp = f"{url} (raw={raw_ratio:.2f}, rendered={rendered_ratio:.2f})"
                if rendered_ratio >= TEXT_BLANK_THRESH:
                    moderate_urls.add(url)
                    display[url] = disp
                else:
                    severe_urls.add(url)
                    display[url] = disp
            else:
                effective_ratio = raw_ratio
                if not has_substantial_text:
                    disp = f"{url} (ratio={effective_ratio:.2f})"
                    if effective_ratio < TEXT_BLANK_THRESH and (word_count < 80 or is_spa):
                        severe_urls.add(url)
                        display[url] = disp
                    elif effective_ratio < CSR_WARN_THRESH or (effective_ratio < TEXT_BLANK_THRESH and word_count < 250):
                        moderate_urls.add(url)
                        display[url] = disp

            # Tag render confidence: 'low' when text-blanking detected without successful Playwright render
            has_blanking = (not has_substantial_text) and (raw_ratio < TEXT_BLANK_THRESH or is_spa)
            if has_blanking and not rendered_ok:
                pr.render_confidence = "low"
            else:
                pr.render_confidence = "high"

        total_checked = len(page_results)
        combined_urls = severe_urls | spa_shell_urls
        if combined_urls:
            evidence_strs = [display.get(u, u) for u in sorted(combined_urls)[:5]]
            findings.append(_finding(
                "CR-003",
                "Severe CSR text blanking — content invisible to non-JS crawlers",
                "critical",
                f"{len(combined_urls)} page(s) have critically low text-to-HTML ratio "
                f"(< {TEXT_BLANK_THRESH}): " + "; ".join(evidence_strs),
                "Implement server-side rendering (SSR) or static-site generation "
                "(SSG) so content is available in the initial HTML response. "
                "Ensure critical text is not loaded exclusively via client-side "
                "JavaScript.",
                related=["CR-004"],
                pages_affected=len(combined_urls),
                pages_checked=total_checked,
            ))
        moderate_final = moderate_urls - combined_urls
        if moderate_final:
            evidence_strs = [display.get(u, u) for u in sorted(moderate_final)[:5]]
            findings.append(_finding(
                "CR-004",
                "Moderate CSR text blanking — reduced content in raw HTML",
                "high",
                f"{len(moderate_final)} page(s) have low text ratio "
                f"(< {CSR_WARN_THRESH}): " + "; ".join(evidence_strs),
                "Review pages for JS-dependent content rendering. Consider "
                "pre-rendering or dynamic rendering for AI crawlers.",
                related=["CR-003"],
                pages_affected=len(moderate_final),
                pages_checked=total_checked,
            ))
    except Exception as exc:
        logger.debug("CR-003/004 error: %s", exc)
    return findings


def _check_cr005(page_results: dict[str, PageResult]) -> list[dict]:
    """CR-005 (high): Paywall or login overlay blocking content."""
    findings: list[dict] = []
    _PAYWALL_PATTERNS = re.compile(
        r"paywall|login[-_]?wall|subscribe[-_]?wall|gated[-_]?content|"
        r"premium[-_]?content|sign[-_]?in[-_]?overlay|metered|regwall",
        re.IGNORECASE,
    )
    _OVERLAY_PATTERNS = re.compile(
        r"(position\s*:\s*(fixed|absolute).*?(width\s*:\s*100|height\s*:\s*100|"
        r"inset\s*:\s*0|top\s*:\s*0.*?left\s*:\s*0))",
        re.IGNORECASE | re.DOTALL,
    )

    try:
        flagged: list[str] = []
        for url, pr in page_results.items():
            if pr.soup is None:
                continue
            html_str = str(pr.soup)

            # Check class/id names for paywall patterns
            for el in pr.soup.find_all(True):
                classes = " ".join(el.get("class", []))
                el_id = el.get("id", "")
                if _PAYWALL_PATTERNS.search(classes) or _PAYWALL_PATTERNS.search(el_id):
                    flagged.append(url)
                    break

            # Check inline styles for full-viewport overlays
            for el in pr.soup.find_all(style=True):
                style = el.get("style", "")
                if _OVERLAY_PATTERNS.search(style):
                    z_match = re.search(r"z-index\s*:\s*(\d+)", style)
                    if z_match and int(z_match.group(1)) > 100:
                        if url not in flagged:
                            flagged.append(url)
                        break

        if flagged:
            findings.append(_finding(
                "CR-005",
                "Paywall or login overlay detected blocking content",
                "high",
                f"{len(flagged)} page(s) have paywall/login overlay patterns: "
                + "; ".join(flagged[:5]),
                "Ensure that AI crawlers can access the full page content "
                "without encountering login walls. Consider implementing "
                "metered access with first-click-free for crawler user-agents, "
                "or use structured data (CreativeWork with isAccessibleForFree).",
                related=["CR-003"],
                pages_affected=len(flagged),
                pages_checked=len(page_results),
            ))
    except Exception as exc:
        logger.debug("CR-005 error: %s", exc)
    return findings


def _check_cr006_cr007(
    target_url: str,
    client: HttpClient,
    sitemap_xml: str,
    sitemap_from_robots: bool,
) -> list[dict]:
    """CR-006 (medium) / CR-007 (low): Sitemap validation."""
    findings: list[dict] = []
    try:
        # CR-006: No sitemap at all
        if not sitemap_xml:
            findings.append(_finding(
                "CR-006",
                "No XML sitemap found",
                "high" if not sitemap_from_robots else "medium",
                "No valid XML sitemap discovered via robots.txt Sitemap "
                "directive or standard paths (/sitemap.xml).",
                "Create and submit an XML sitemap listing all canonical page "
                "URLs. Declare it in robots.txt with a Sitemap: directive and "
                "submit it via Google Search Console.",
            ))
            return findings

        # CR-006: Missing Sitemap in robots.txt
        if not sitemap_from_robots:
            findings.append(_finding(
                "CR-006",
                "Sitemap not declared in robots.txt",
                "medium",
                "A sitemap was found at a standard path but is not declared "
                "via a Sitemap: directive in robots.txt.",
                "Add a Sitemap: directive in robots.txt pointing to your "
                "sitemap URL for reliable crawler discovery.",
            ))

        # CR-007: lastmod validation
        lastmods = _get_sitemap_lastmods(sitemap_xml)
        if lastmods:
            missing_count = sum(1 for lm in lastmods if lm is None)
            missing_pct = missing_count / len(lastmods) if lastmods else 0

            if missing_pct > 0.30:
                findings.append(_finding(
                    "CR-007",
                    "Sitemap entries missing <lastmod> dates",
                    "medium",
                    f"{missing_count}/{len(lastmods)} sitemap URLs "
                    f"({missing_pct:.0%}) lack <lastmod> timestamps.",
                    "Add accurate <lastmod> dates to all sitemap entries so "
                    "crawlers can prioritise recently updated content.",
                ))

            # Check for stale lastmods
            now = datetime.now(timezone.utc)
            stale_cutoff = now - timedelta(days=STALE_DAYS)
            stale_count = 0
            for lm in lastmods:
                if lm is None:
                    continue
                try:
                    dt_str = lm[:10]
                    dt = datetime.strptime(dt_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    if dt < stale_cutoff:
                        stale_count += 1
                except (ValueError, IndexError):
                    pass

            if stale_count > 0:
                findings.append(_finding(
                    "CR-007",
                    "Sitemap contains stale <lastmod> dates",
                    "low",
                    f"{stale_count} sitemap entries have <lastmod> older "
                    f"than {STALE_DAYS} days.",
                    "Update <lastmod> timestamps when content changes. Remove "
                    "entries for permanently outdated content.",
                ))

        # Check for crawl-delay in robots.txt
        try:
            _, raw_robots = client.robots._get_parser(target_url)
            for line in raw_robots.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("crawl-delay:"):
                    val = stripped.split(":", 1)[1].strip()
                    try:
                        delay = float(val)
                        if delay > 10:
                            findings.append(_finding(
                                "CR-007",
                                "Excessive Crawl-delay in robots.txt",
                                "low",
                                f"robots.txt sets Crawl-delay: {delay}s, "
                                "which slows crawler indexing significantly.",
                                "Lower or remove the Crawl-delay directive to "
                                "allow crawlers to index your site efficiently.",
                            ))
                    except ValueError:
                        pass
                    break
        except Exception:
            pass

    except Exception as exc:
        logger.debug("CR-006/007 error: %s", exc)
    return findings


def _check_cr008(page_results: dict[str, PageResult]) -> list[dict]:
    """CR-008 (high): noindex meta tags or X-Robots-Tag on public pages."""
    findings: list[dict] = []
    try:
        noindex_pages: list[str] = []
        for url, pr in page_results.items():
            # Check X-Robots-Tag header
            xrt = pr.response_headers.get("x-robots-tag", "")
            if "noindex" in xrt.lower():
                noindex_pages.append(url)
                continue

            # Check <meta name="robots">
            if pr.soup:
                meta_robots = pr.soup.find(
                    "meta", attrs={"name": re.compile(r"^robots$", re.I)}
                )
                if meta_robots:
                    content = (meta_robots.get("content") or "").lower()
                    if "noindex" in content:
                        noindex_pages.append(url)

        if noindex_pages:
            findings.append(_finding(
                "CR-008",
                "Public pages marked with noindex directive",
                "high",
                f"{len(noindex_pages)} page(s) carry noindex (meta or "
                f"X-Robots-Tag): " + "; ".join(noindex_pages[:5]),
                "Remove noindex directives from pages you want AI engines to "
                "discover. If pages should genuinely be excluded, ensure they "
                "are not linked from navigation or sitemaps.",
                pages_affected=len(noindex_pages),
                pages_checked=len(page_results),
            ))
    except Exception as exc:
        logger.debug("CR-008 error: %s", exc)
    return findings





# ===================================================================
# Proactive recommendations
# ===================================================================
def _proactive(
    page_results: dict[str, PageResult],
    target_url: str,
) -> list[dict]:
    """Generate proactive improvement candidates."""
    recs: list[dict] = []
    try:
        # Suggest HTTPS if homepage is HTTP
        if target_url.startswith("http://"):
            recs.append({
                "title": "Migrate site to HTTPS",
                "rationale": "HTTPS is a ranking signal and required for modern "
                             "crawler trust. AI engines may deprioritise HTTP-only "
                             "sites.",
                "priority": "high",
            })

        # Suggest canonical tags if none found
        has_canonical = False
        for pr in page_results.values():
            if pr.soup and pr.soup.find("link", rel="canonical"):
                has_canonical = True
                break
        if not has_canonical:
            recs.append({
                "title": "Add rel=canonical link elements",
                "rationale": "Canonical tags prevent duplicate content issues and "
                             "consolidate link signals for AI citation engines.",
                "priority": "medium",
            })



    except Exception as exc:
        logger.debug("Proactive recs error: %s", exc)
    return recs


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================
def run_audit(target_url: str, http_client: HttpClient, **kwargs: Any) -> dict:
    """Execute Crawl & Render Access checks CR-001 -> CR-008.

    Returns the standard domain payload **plus** ``crawl_frontier`` and
    ``page_results`` for downstream skills.
    """
    max_pages = kwargs.get("max_pages", MAX_PAGES)
    renderer = kwargs.get("playwright", None)
    timeout_s = kwargs.get("timeout_s", None)
    t_start = kwargs.get("t_start", None)

    # 1. Discover frontier
    frontier, page_results, errors, sitemap_xml = _discover_frontier(
        target_url, http_client, max_pages, t_start=t_start, timeout_s=timeout_s,
    )

    # Check whether sitemap was declared in robots.txt
    sm_from_robots = bool(http_client.robots.get_sitemaps(target_url))

    # Parse sitemap to get total URL count BEFORE max_pages truncation
    sitemap_total: int | None = None
    if sitemap_xml:
        sitemap_total = len(_parse_sitemap_xml(sitemap_xml))

    budget_limited = (
        sitemap_total is not None
        and sitemap_total > max_pages
    )
    coverage = {
        "pages_audited": len(frontier),
        "pages_in_sitemap": sitemap_total,
        "budget_limited": budget_limited,
    }

    # 2. Run all checks
    findings: list[dict] = []
    checks = [
        lambda: _check_cr001(target_url, http_client),
        lambda: _check_cr002(page_results),
        lambda: _check_cr003_cr004(page_results, renderer),
        lambda: _check_cr005(page_results),
        lambda: _check_cr006_cr007(target_url, http_client, sitemap_xml, sm_from_robots),
        lambda: _check_cr008(page_results),
    ]
    for check_fn in checks:
        if t_start is not None and timeout_s is not None and (time.monotonic() - t_start >= timeout_s):
            errors.append("Crawl checks truncated: timeout budget reached")
            break
        findings.extend(check_fn())

    # 3. Proactive recommendations
    proactive = _proactive(page_results, target_url)

    return {
        "domain": "crawl-render-access",
        "pages_analyzed": sum(
            1 for pr in page_results.values()
            if pr.status_code and 200 <= pr.status_code < 400
        ),
        "pages_discovered": len(frontier),
        "errors": errors,
        "findings": findings,
        "proactive_candidates": proactive,
        "coverage": coverage,
        # Extra: shared with peer skills
        "crawl_frontier": [
            FrontierEntry(
                u,
                render_confidence=getattr(page_results.get(u), "render_confidence", "high"),
            )
            for u in frontier
        ],
        "page_results": page_results,
    }
