"""
proactive_engine.py
===================
Generates PA-001 through PA-006 proactive recommendations for the audit report.

Public API:
    inject_proactive_recommendations(
        report_dict, page_results, http_client, target_url,
    ) -> list[dict]

Each returned dict is a schema-compliant Finding with severity="info" and
category matching the closest domain.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Optional

_HTTP_DIR = (
    Path(__file__).resolve().parents[2]
    / "crawl-render-access"
    / "scripts"
)
if str(_HTTP_DIR) not in sys.path:
    sys.path.insert(0, str(_HTTP_DIR))

from http_client import HttpClient, PageResult

logger = logging.getLogger(__name__)

_THRESH_PATH = (
    Path(__file__).resolve().parent.parent / "references" / "thresholds.json"
)


def _load_thresholds() -> dict:
    try:
        return json.loads(_THRESH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_T = _load_thresholds()
_AI_CRAWLERS: list[str] = _T.get("robots", {}).get("known_ai_crawlers", [])


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _existing_finding_ids(report_dict: dict) -> set[str]:
    """Return set of local_id or id values from the existing report."""
    ids: set[str] = set()
    for f in report_dict.get("findings", []):
        for key in ("id", "local_id"):
            val = f.get(key, "")
            if val:
                ids.add(val.upper())
                ids.add(val.lower())
    return ids


def _existing_titles_lower(report_dict: dict) -> set[str]:
    """Return lowercase titles/evidence snippets from existing findings."""
    texts: set[str] = set()
    for f in report_dict.get("findings", []):
        title = f.get("title", "")
        if title:
            texts.add(title.lower())
    return texts


def _make_finding(
    pa_id: str,
    title: str,
    evidence_url: str,
    snippet: str,
    action: str,
    category: str = "proactive",
) -> dict:
    """Build a proactive finding dict matching the report schema."""
    return {
        "local_id": pa_id,
        "title": title,
        "severity": "info",
        "category": category,
        "evidence": snippet,
        "suggested_action": {"summary": action, "priority": "info"},
        "related_to": [],
    }


def _extract_jsonld_blocks(soup: Any) -> list[dict]:
    """Extract all JSON-LD blocks from a BeautifulSoup object."""
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


# ------------------------------------------------------------------
# PA-001: llms.txt / llms-full.txt
# ------------------------------------------------------------------

def _pa001(
    target_url: str,
    http_client: HttpClient,
    existing_ids: set[str],
) -> Optional[dict]:
    """Check for /llms.txt or /llms-full.txt availability."""
    try:
        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin += f":{parsed.port}"

        for path in ("/llms.txt", "/llms-full.txt"):
            url = origin + path
            try:
                result = http_client.head(url)
                if result.status_code and 200 <= result.status_code < 400:
                    return None  # File exists, no recommendation needed
            except Exception:
                continue  # Transient error; do not treat as confirmed absence

        return _make_finding(
            "PA-001",
            "No llms.txt file found for LLM-readable site description",
            target_url,
            "Neither /llms.txt nor /llms-full.txt returned a successful "
            "response. These files provide a structured site description "
            "optimised for large language models.",
            "Publish an /llms.txt file at your site root describing your "
            "brand, key offerings, and site structure in plain text format "
            "optimised for LLM consumption. See llmstxt.org for the specification.",
        )
    except Exception as exc:
        logger.debug("PA-001 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-002: Unified JSON-LD graph with @graph / @id cross-references
# ------------------------------------------------------------------

def _pa002(
    page_results: dict[str, PageResult],
    existing_ids: set[str],
) -> Optional[dict]:
    """Check for unified JSON-LD graph with @id cross-references."""
    try:
        has_graph_with_refs = False
        total_ld_pages = 0

        for url, pr in page_results.items():
            if not pr or not pr.soup:
                continue
            scripts = pr.soup.find_all("script", type="application/ld+json")
            if not scripts:
                continue
            total_ld_pages += 1

            for script in scripts:
                raw = script.string
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(data, dict):
                    continue

                # Check for meaningful @graph with @id cross-references
                graph = data.get("@graph")
                if isinstance(graph, list) and len(graph) >= 2:
                    # Collect all @id values
                    all_ids: set[str] = set()
                    for item in graph:
                        if isinstance(item, dict) and item.get("@id"):
                            all_ids.add(str(item["@id"]))

                    # Check for cross-references: any value referencing another @id
                    for item in graph:
                        if not isinstance(item, dict):
                            continue
                        for val in item.values():
                            if isinstance(val, dict) and val.get("@id") in all_ids:
                                has_graph_with_refs = True
                                break
                            if isinstance(val, str) and val in all_ids and val != item.get("@id"):
                                has_graph_with_refs = True
                                break
                        if has_graph_with_refs:
                            break
                if has_graph_with_refs:
                    break
            if has_graph_with_refs:
                break

        if has_graph_with_refs or total_ld_pages == 0:
            return None

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-002",
            "JSON-LD entities lack unified @graph with @id cross-references",
            first_url,
            f"Across {total_ld_pages} page(s) with JSON-LD, no unified @graph "
            "structure with meaningful @id cross-entity references was detected.",
            "Consolidate your JSON-LD entities into a single @graph array per "
            "page and use stable @id URIs (e.g. '#organization', '#website') "
            "to cross-reference entities. This helps AI engines understand "
            "relationships between your Organization, WebSite, and content.",
        )
    except Exception as exc:
        logger.debug("PA-002 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-003: Heading fragment IDs for deep linking
# ------------------------------------------------------------------

def _pa003(
    page_results: dict[str, PageResult],
    existing_ids: set[str],
) -> Optional[dict]:
    """Check whether section headings have id attributes for deep linking."""
    try:
        headings_total = 0
        headings_with_id = 0
        pages_checked = 0

        for url, pr in page_results.items():
            if not pr or not pr.soup:
                continue
            pages_checked += 1
            for tag in pr.soup.find_all(["h2", "h3"]):
                text = tag.get_text(strip=True)
                if len(text) < 5:
                    continue
                headings_total += 1
                if tag.get("id"):
                    headings_with_id += 1

        if headings_total < 4:
            return None  # Not enough evidence

        ratio = headings_with_id / headings_total if headings_total > 0 else 0
        if ratio >= 0.5:
            return None  # Reasonable coverage

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-003",
            "Section headings lack fragment IDs for deep linking",
            first_url,
            f"Only {headings_with_id}/{headings_total} section headings "
            f"({ratio:.0%}) across {pages_checked} page(s) have id attributes.",
            "Add stable id attributes to <h2> and <h3> headings to enable "
            "deep linking and AI-engine citation of specific sections. "
            "Use descriptive slugs (e.g. id='pricing-details').",
        )
    except Exception as exc:
        logger.debug("PA-003 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-004: Answer-first / inverted pyramid content
# ------------------------------------------------------------------

def _pa004(
    page_results: dict[str, PageResult],
    existing_ids: set[str],
) -> Optional[dict]:
    """Heuristic check for answer-first content structure."""
    try:
        article_pages = 0
        wordy_intros = 0

        _QUESTION_WORDS = re.compile(
            r"^(what|how|why|when|where|who|which|can|does|is|are|should)\b",
            re.IGNORECASE,
        )

        for url, pr in page_results.items():
            if not pr or not pr.soup:
                continue

            # Only check article-like pages (has h1 and >2 paragraphs)
            h1 = pr.soup.find("h1")
            paragraphs = pr.soup.find_all("p")
            meaningful_paras = [
                p for p in paragraphs
                if len(p.get_text(strip=True)) > 40
            ]
            if not h1 or len(meaningful_paras) < 3:
                continue

            article_pages += 1

            # Check first paragraph after h1
            first_para_text = ""
            for sib in h1.find_all_next(["p"]):
                text = sib.get_text(strip=True)
                if len(text) > 40:
                    first_para_text = text
                    break

            if not first_para_text:
                continue

            # Heuristic: long intro without direct answer signal
            words = first_para_text.split()
            if len(words) > 50 and not _QUESTION_WORDS.match(first_para_text):
                # Check if the first sentence is very long (> 200 chars without
                # a period) suggesting a verbose preamble
                first_sentence_end = first_para_text.find(".")
                if first_sentence_end > 200 or first_sentence_end == -1:
                    wordy_intros += 1

        if article_pages < 2 or wordy_intros < 2:
            return None

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-004",
            "Content pages may benefit from answer-first structure",
            first_url,
            f"{wordy_intros}/{article_pages} article-like page(s) begin "
            "with long introductory paragraphs rather than direct answers.",
            "Restructure key content pages using an inverted pyramid style: "
            "lead with the core answer or value proposition in the first "
            "paragraph, then provide supporting details. AI engines prefer "
            "concise, answer-oriented opening statements for citation.",
        )
    except Exception as exc:
        logger.debug("PA-004 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-005: RSS / Atom feed
# ------------------------------------------------------------------

def _pa005(
    page_results: dict[str, PageResult],
    existing_ids: set[str],
) -> Optional[dict]:
    """Check for RSS or Atom feed declarations."""
    try:
        for url, pr in page_results.items():
            if not pr or not pr.soup:
                continue
            for link_tag in pr.soup.find_all("link", rel="alternate"):
                link_type = (link_tag.get("type") or "").lower()
                if "rss+xml" in link_type or "atom+xml" in link_type:
                    return None  # Feed found

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-005",
            "No RSS or Atom feed detected",
            first_url,
            "No <link rel='alternate'> with type application/rss+xml or "
            "application/atom+xml was found across any crawled page.",
            "Publish an RSS or Atom feed for your blog, news, or product "
            "updates. Syndication feeds enable AI aggregators and citation "
            "engines to track your content freshness automatically.",
        )
    except Exception as exc:
        logger.debug("PA-005 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-006: Explicit AI crawler Allow: in robots.txt
# ------------------------------------------------------------------

def _pa006(
    target_url: str,
    http_client: HttpClient,
    existing_ids: set[str],
    existing_titles: set[str],
) -> Optional[dict]:
    """Check for explicit Allow: directives for AI crawlers in robots.txt."""
    try:
        # Skip if CR-001 already flagged blocking (different root cause)
        if any("blocked" in t and "robots" in t for t in existing_titles):
            return None

        _, raw_robots = http_client.robots._get_parser(target_url)
        if not raw_robots:
            return None  # No robots.txt; don't generate noise

        # Parse robots.txt for AI-crawler-specific Allow: directives
        lines = raw_robots.splitlines()
        current_agents: set[str] = set()
        ai_specific_allow = False
        ai_crawler_names_lower = {c.lower() for c in _AI_CRAWLERS}

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.lower().startswith("user-agent:"):
                agent = stripped.split(":", 1)[1].strip().lower()
                if not current_agents or agent:
                    current_agents.add(agent)
            elif stripped.lower().startswith("allow:"):
                # Check if current agent block targets an AI crawler
                if current_agents & ai_crawler_names_lower:
                    ai_specific_allow = True
                    break
                # Reset agent tracking on next directive
            else:
                if stripped.lower().startswith(("disallow:", "sitemap:", "crawl-delay:")):
                    pass
                else:
                    current_agents.clear()

        if ai_specific_allow:
            return None

        return _make_finding(
            "PA-006",
            "No explicit Allow directive for AI crawlers in robots.txt",
            target_url,
            "robots.txt does not contain any explicit Allow: directive "
            "under an AI-crawler User-agent section (e.g. GPTBot, "
            "Google-Extended). While absence of Disallow may suffice, "
            "explicit Allow signals welcoming intent.",
            "Add explicit User-agent/Allow blocks for key AI crawlers "
            "(GPTBot, Google-Extended, anthropic-ai) in robots.txt to "
            "signal that your content is open for AI indexing.",
        )
    except Exception as exc:
        logger.debug("PA-006 error: %s", exc)
        return None


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def inject_proactive_recommendations(
    report_dict: dict,
    page_results: dict[str, PageResult],
    http_client: HttpClient,
    target_url: str,
) -> list[dict]:
    """Generate PA-001..PA-006 proactive recommendations.

    Inspects existing findings to suppress duplicates.

    Returns a list of finding-like dicts with severity="info".
    """
    existing_ids = _existing_finding_ids(report_dict)
    existing_titles = _existing_titles_lower(report_dict)
    results: list[dict] = []

    rules = [
        ("PA-001", lambda: _pa001(target_url, http_client, existing_ids)),
        ("PA-002", lambda: _pa002(page_results, existing_ids)),
        ("PA-003", lambda: _pa003(page_results, existing_ids)),
        ("PA-004", lambda: _pa004(page_results, existing_ids)),
        ("PA-005", lambda: _pa005(page_results, existing_ids)),
        ("PA-006", lambda: _pa006(target_url, http_client, existing_ids, existing_titles)),
    ]

    seen_titles: set[str] = set()
    for pa_id, rule_fn in rules:
        try:
            finding = rule_fn()
            if finding is not None:
                title_lower = finding.get("title", "").lower()
                # Suppress if title closely matches an existing finding
                if title_lower in existing_titles:
                    continue
                if title_lower in seen_titles:
                    continue
                seen_titles.add(title_lower)
                results.append(finding)
        except Exception as exc:
            logger.debug("Proactive rule %s failed: %s", pa_id, exc)

    return results
