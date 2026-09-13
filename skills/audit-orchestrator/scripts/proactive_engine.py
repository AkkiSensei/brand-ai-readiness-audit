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
_HEADING_ID_RATIO_THRESH: float = float(
    _T.get("proactive", {}).get("heading_id_ratio_threshold", 0.50)
)


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
        raw = (script.string or script.get_text() or "").strip()
        if not raw:
            continue
        # Strip CDATA and HTML/JS comment wrappers commonly used by CMSs
        if raw.startswith("<!--") and raw.endswith("-->"):
            raw = raw[4:-3].strip()
        if raw.startswith("//<![CDATA[") and raw.endswith("//]]>"):
            raw = raw[11:-5].strip()
        elif raw.startswith("/*<![CDATA[*/") and raw.endswith("/*]]>*/"):
            raw = raw[13:-7].strip()
        elif raw.startswith("<![CDATA[") and raw.endswith("]]>"):
            raw = raw[9:-3].strip()
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
# PA-001: llms.txt / llms-full.txt / agents.md
# ------------------------------------------------------------------

def _pa001(
    target_url: str,
    http_client: HttpClient,
    existing_ids: set[str],
    deadline: Optional[Any] = None,
) -> Optional[dict]:
    """Check for /llms.txt, /llms-full.txt, or /agents.md availability."""
    try:
        if deadline and hasattr(deadline, "expired") and deadline.expired():
            return None
        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin += f":{parsed.port}"

        for path in ("/llms.txt", "/llms-full.txt", "/agents.md"):
            if deadline and hasattr(deadline, "expired") and deadline.expired():
                return None
            url = origin + path
            try:
                result = http_client.head(url, deadline=deadline)
                if result.status_code and 200 <= result.status_code < 400:
                    return None  # File exists, no recommendation needed
            except Exception:
                continue  # Transient error; do not treat as confirmed absence

        return _make_finding(
            "PA-001",
            "No llms.txt or agents.md manifest found for AI agent discoverability",
            target_url,
            "Neither /llms.txt, /llms-full.txt, nor /agents.md returned a successful "
            "response. These machine-readable files provide structured site summaries "
            "and documentation endpoints for LLMs and autonomous search agents.",
            "Publish an /llms.txt or /agents.md file at your site root describing your "
            "brand, core offerings, documentation endpoints, and site structure in plain "
            "Markdown format. See llmstxt.org for the standardized specification.",
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
            f"Across {total_ld_pages} page(s) with JSON-LD, schemas exist as isolated blocks "
            "without a unified @graph array or @id cross-entity references.",
            "Consolidate isolated JSON-LD script blocks into a single @graph array per "
            "page and use stable @id URIs (e.g. '#organization', '#website') "
            "to cross-reference entities. This enables AI knowledge engines to connect your "
            "Organization, WebSite, and content into an integrated knowledge graph.",
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
        if ratio >= _HEADING_ID_RATIO_THRESH:
            return None  # Reasonable coverage

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-003",
            "Section headings lack fragment IDs for deep linking and citation",
            first_url,
            f"Only {headings_with_id}/{headings_total} section headings "
            f"({ratio:.0%}) across {pages_checked} page(s) have id attributes.",
            "Add stable slug id attributes (e.g. <h2 id='pricing-details'>) "
            "to all <h2> and <h3> section headings. This enables AI answer engines (ChatGPT, "
            "Perplexity, Gemini) to deep-link directly to the specific section citing your content.",
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
        _FILLER_PREAMBLES = re.compile(
            r"^(in (today's|the modern|this)|when it comes to|it is (important|widely|essential)|as we all know|whether you are|looking for)\b",
            re.IGNORECASE,
        )

        for url, pr in page_results.items():
            if not pr or not pr.soup:
                continue

            # Only check article/content-rich pages (has h1 and >= 3 paragraphs)
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

            words = first_para_text.split()
            has_filler = bool(_FILLER_PREAMBLES.search(first_para_text))
            first_sentence_end = first_para_text.find(".")
            has_long_first_sentence = (first_sentence_end > 180 or first_sentence_end == -1)

            # Flag if opening paragraph is verbose without answering directly
            if not _QUESTION_WORDS.match(first_para_text):
                if has_filler or (len(words) > 30 and has_long_first_sentence) or len(words) > 50:
                    wordy_intros += 1

        if article_pages < 2 or wordy_intros < 2:
            return None

        first_url = next(iter(page_results), "")
        return _make_finding(
            "PA-004",
            "Content pages may benefit from answer-first structure",
            first_url,
            f"{wordy_intros}/{article_pages} content page(s) begin with long introductory "
            "preambles rather than immediate declarative answers or key fact summaries.",
            "Adopt an inverted pyramid, answer-first content structure: lead each page and major "
            "section with a concise, direct answer or key takeaway in the very first sentence. "
            "AI grounding systems (RAG) score opening text heavily when retrieving candidate "
            "passages for direct answer generation.",
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
    """Check for RSS or Atom feed declarations on content publishing sites."""
    try:
        # Check if site has news/blog/article-like content where syndication is relevant
        has_editorial_content = False
        for url in page_results:
            lower = url.lower()
            if any(seg in lower for seg in ("/blog", "/news", "/article", "/post", "/updates", "/press", "/journal")):
                has_editorial_content = True
                break

        # If no editorial content and very few pages (< 5), avoid recommending feeds unnecessarily
        if not has_editorial_content and len(page_results) < 5:
            return None

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
            "No RSS or Atom feed detected for content syndication",
            first_url,
            "No <link rel='alternate'> with type application/rss+xml or "
            "application/atom+xml was found across crawled editorial pages.",
            "Publish and link an RSS 2.0 or Atom feed (<link rel='alternate' type='application/rss+xml'>) "
            "for your blog, news, or product updates to enable real-time freshness tracking by AI aggregators.",
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
        ai_crawler_names_lower.update({
            "gptbot", "claude-web", "perplexitybot", "google-extended",
            "applebot-extended", "amazonbot", "cohere-ai", "meta-externalagent",
        })
        in_user_agent_block = False

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.lower().startswith("user-agent:"):
                if not in_user_agent_block:
                    current_agents.clear()
                    in_user_agent_block = True
                agent = stripped.split(":", 1)[1].strip().lower()
                if agent:
                    current_agents.add(agent)
            else:
                in_user_agent_block = False
                if stripped.lower().startswith("allow:"):
                    # Check if current agent block targets an AI crawler
                    if current_agents & ai_crawler_names_lower:
                        ai_specific_allow = True
                        break

        if ai_specific_allow:
            return None

        return _make_finding(
            "PA-006",
            "No explicit Allow directive for AI crawlers in robots.txt",
            target_url,
            "robots.txt does not contain an explicit Allow: directive under an "
            "AI crawler User-agent section (e.g. GPTBot, Claude-Web, PerplexityBot, Google-Extended).",
            "Add explicit User-agent and Allow: / directives for verified AI crawlers "
            "(GPTBot, Claude-Web, PerplexityBot, Google-Extended) in /robots.txt to "
            "guarantee unambiguous crawling authorization and prevent collateral blocking from wildcard rules.",
        )
    except Exception as exc:
        logger.debug("PA-006 error: %s", exc)
        return None


# ------------------------------------------------------------------
# PA-CANONICAL: rel=canonical link detection
# ------------------------------------------------------------------

def _pa_canonical(
    page_results: dict[str, PageResult],
    existing_ids: set[str],
) -> Optional[dict]:
    """Check for <link rel="canonical"> declarations across crawled pages."""
    try:
        if not page_results:
            return None
        has_canonical = False
        for pr in page_results.values():
            if pr and pr.soup and pr.soup.find("link", rel="canonical"):
                has_canonical = True
                break
        if not has_canonical:
            first_url = next(iter(page_results), "")
            return _make_finding(
                "PA-CANONICAL",
                "Add rel=canonical link elements to consolidate citation signals",
                first_url,
                "No <link rel='canonical'> element was found across any crawled page.",
                "Specify absolute, self-referential <link rel='canonical'> tags on every "
                "indexable page. Canonical tags prevent duplicate content dilution across URL "
                "parameters and tracking codes, consolidating link authority for AI citation engines.",
                category="proactive",
            )
        return None
    except Exception as exc:
        logger.debug("PA-CANONICAL error: %s", exc)
        return None


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def inject_proactive_recommendations(
    report_dict: dict,
    page_results: dict[str, PageResult],
    http_client: HttpClient,
    target_url: str,
    deadline: Optional[Any] = None,
) -> list[dict]:
    """Generate PA-001..PA-006 and canonical proactive recommendations.

    Inspects existing findings to suppress duplicates.

    Returns a list of finding-like dicts with severity="info".
    """
    existing_ids = _existing_finding_ids(report_dict)
    existing_titles = _existing_titles_lower(report_dict)
    results: list[dict] = []

    rules = [
        ("PA-001", lambda: _pa001(target_url, http_client, existing_ids, deadline=deadline)),
        ("PA-002", lambda: _pa002(page_results, existing_ids)),
        ("PA-003", lambda: _pa003(page_results, existing_ids)),
        ("PA-004", lambda: _pa004(page_results, existing_ids)),
        ("PA-005", lambda: _pa005(page_results, existing_ids)),
        ("PA-006", lambda: _pa006(target_url, http_client, existing_ids, existing_titles)),
        ("PA-CANONICAL", lambda: _pa_canonical(page_results, existing_ids)),
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
