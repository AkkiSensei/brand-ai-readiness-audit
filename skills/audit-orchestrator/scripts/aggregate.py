"""
aggregate.py
============
Audit Orchestrator — master integration entrypoint.

Coordinates crawl, downstream domain audits (SFE, TEC, ER), merges findings,
deduplicates, cross-references, scores, grades, injects proactive
recommendations, validates against the report JSON Schema, and emits the
final report.

Public API:
    run_audit(target_url, max_pages=15, timeout_s=240, **kwargs) -> dict

CLI:
    python aggregate.py <url> [--max-pages N] [--output path.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.parse
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ORCH_SCRIPTS = Path(__file__).resolve().parent
_ROOT = _ORCH_SCRIPTS.parent.parent  # skills/

_HTTP_SCRIPTS = _ROOT / "crawl-render-access" / "scripts"
_SFE_SCRIPTS = _ROOT / "structured-fact-extraction" / "scripts"
_TEC_SCRIPTS = _ROOT / "trust-entity-corroboration" / "scripts"
_ER_SCRIPTS = _ROOT / "engagement-retention" / "scripts"

for p in (_HTTP_SCRIPTS, _SFE_SCRIPTS, _TEC_SCRIPTS, _ER_SCRIPTS, _ORCH_SCRIPTS):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from http_client import AuditDeadline, HttpClient, PageResult, PlaywrightRenderer, is_ssrf_disallowed, CoverageState  # type: ignore[import]
import crawl_audit  # type: ignore[import]
import sfe_audit  # type: ignore[import]
import tec_audit  # type: ignore[import]
import er_audit  # type: ignore[import]

from proactive_engine import inject_proactive_recommendations  # type: ignore[import]
from schema_validate import validate_report  # type: ignore[import]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_THRESH_PATH = _ORCH_SCRIPTS.parent / "references" / "thresholds.json"


def _load_thresholds() -> dict:
    try:
        return json.loads(_THRESH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


# Map from domain runner "domain" string -> schema category key
_DOMAIN_TO_CATEGORY: dict[str, str] = {
    "crawl-render-access": "crawl_render_access",
    "structured-fact-extraction": "structured_fact_extraction",
    "trust-entity-corroboration": "trust_entity_corroboration",
    "engagement-retention": "engagement_retention",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_FINDING_REMEDIATION_METADATA: dict[str, dict[str, str]] = {
    # Crawl & Render Access
    "CR-001": {
        "theme": "Crawler Access Governance",
        "asset_type": "robots.txt",
        "location": "/robots.txt at domain root",
        "why_it_matters": "AI search engines (ChatGPT, Claude, Perplexity, Gemini) obey robots.txt; blocking their user-agents completely eliminates your site from real-time AI knowledge retrieval and citation.",
        "default_action": "Update /robots.txt to permit major AI crawler user-agents (GPTBot, Claude-Web, PerplexityBot, Google-Extended, Applebot-Extended) to access indexable public pages.",
    },
    "CR-002": {
        "theme": "Crawler Access Governance",
        "asset_type": "WAF / Bot Defense Rules",
        "location": "Edge CDN / WAF configuration",
        "why_it_matters": "Active WAF or CAPTCHA challenges prevent automated AI search crawlers from fetching page HTML, causing immediate crawl abortion or classification as dead pages.",
        "default_action": "Configure edge WAF (Cloudflare, AWS WAF, Akamai) to exempt verified AI crawler user-agents and IP blocks from interactive JavaScript/CAPTCHA challenges.",
    },
    "CR-003": {
        "theme": "Render Architecture",
        "asset_type": "Frontend SSR / SSG Framework",
        "location": "Frontend application build & rendering pipeline",
        "why_it_matters": "AI crawlers that do not execute client-side JavaScript encounter a blank shell (0-15% text), rendering your core brand narrative and products completely invisible.",
        "default_action": "Implement server-side rendering (SSR) or static site generation (SSG) so that primary content, headings, and text are embedded in the initial HTML payload.",
    },
    "CR-004": {
        "theme": "Render Architecture",
        "asset_type": "Component Hydration Pipeline",
        "location": "Component templates and page data loaders",
        "why_it_matters": "Dynamic client-side hydration delays content availability, risking truncated or empty text snapshots when AI crawlers apply short rendering execution budgets.",
        "default_action": "Pre-render critical content sections into the initial HTML response rather than hydrating them exclusively via client-side API requests.",
    },
    "CR-005": {
        "theme": "Paywall & Overlay Governance",
        "asset_type": "Modal / Overlay Styles",
        "location": "Viewport modal overlays and CSS dialogs",
        "why_it_matters": "Obtrusive modals covering >60% of the viewport obstruct page content during visual and DOM indexing, triggering automated paywall or low-quality classifications.",
        "default_action": "Ensure core content is accessible in the underlying DOM and avoid full-viewport blocking overlays for unauthenticated crawler sessions.",
    },
    "CR-006": {
        "theme": "Sitemap & Crawler Guidance",
        "asset_type": "XML Sitemap (sitemap.xml)",
        "location": "/sitemap.xml at domain root or referenced in /robots.txt",
        "why_it_matters": "XML sitemaps are the primary discovery mechanism for AI crawlers; without one, AI search engines rely solely on link traversal and miss deep or recently-added pages.",
        "default_action": "Create a valid XML sitemap at /sitemap.xml, submit it to major search engines, and reference it from /robots.txt via a Sitemap: directive.",
    },
    "CR-007": {
        "theme": "Sitemap & Crawler Guidance",
        "asset_type": "XML Sitemap <lastmod> and robots.txt Crawl-delay",
        "location": "/sitemap.xml <lastmod> tags and /robots.txt Crawl-delay directive",
        "why_it_matters": "Missing or stale <lastmod> dates prevent AI crawlers from prioritizing recently-updated pages for re-indexing. Excessive Crawl-delay values throttle AI search engines below their efficient operating cadence.",
        "default_action": "Populate accurate <lastmod> dates in sitemap.xml for every URL. Remove or reduce robots.txt Crawl-delay directives to 10 seconds or less for AI crawler user-agents.",
    },
    "CR-008": {
        "theme": "Crawl Budget & Link Health",
        "asset_type": "HTML <meta name='robots'> / X-Robots-Tag Header",
        "location": "Page <head> meta robots tag or X-Robots-Tag HTTP response header",
        "why_it_matters": "noindex directives instruct all crawlers to drop the page from indexing; public brand pages with noindex are invisible to AI search engines regardless of content quality.",
        "default_action": "Remove noindex directives from public-facing brand pages. Audit <meta name='robots'> tags and X-Robots-Tag headers across the site to ensure only private/admin pages are excluded from indexation.",
    },

    # Structured Fact Extraction
    "SF-001": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD Script Block",
        "location": "Homepage <head>",
        "why_it_matters": "Schema.org Organization structured data provides unambiguous brand identity declarations directly into AI engine knowledge graph builders.",
        "default_action": "Add a <script type='application/ld+json'> block to the homepage <head> defining Schema.org Organization (name, url, logo, description, sameAs).",
    },
    "SF-002": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD Structured Data",
        "location": "Page <head> application/ld+json script blocks",
        "why_it_matters": "Malformed syntax or incomplete schema properties prevent AI semantic parsers from extracting reliable structured entities.",
        "default_action": "Fix JSON syntax errors and add recommended Schema.org properties; validate schemas using Google's Rich Results Test or Schema.org Validator.",
    },
    "SF-003": {
        "theme": "Machine-Readable Fact Extraction",
        "asset_type": "Semantic HTML Text",
        "location": "Image elements and infographic graphics",
        "why_it_matters": "Numerical data, pricing, and contact information trapped inside raster graphics cannot be indexed by text-only AI retrieval pipelines.",
        "default_action": "Present key facts, pricing, and contact details as selectable semantic HTML text (e.g. <table>, <dl>) alongside descriptive alt attributes.",
    },
    "SF-004": {
        "theme": "Machine-Readable Fact Extraction",
        "asset_type": "Semantic HTML Text",
        "location": "Canvas elements and infographic containers",
        "why_it_matters": "HTML5 <canvas> elements are opaque bitmaps to AI crawlers unless backed by structured text fallbacks or ARIA labels.",
        "default_action": "Provide accessible semantic HTML text fallbacks or structured JSON-LD data for all metrics rendered within canvas elements.",
    },
    "SF-005": {
        "theme": "Machine-Readable Fact Extraction",
        "asset_type": "HTML Landing Pages",
        "location": "Document download links and resource libraries",
        "why_it_matters": "AI crawlers frequently deprioritize or skip binary PDF downloads; content trapped in PDFs without HTML summaries rarely earns direct attribution.",
        "default_action": "Create HTML summary pages with descriptive anchor text covering the key insights and data contained in linked PDF reports.",
    },
    "SF-006": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD FAQPage Markup",
        "location": "FAQ and help center pages",
        "why_it_matters": "FAQPage structured data enables direct extraction of question-answer pairs for conversational AI responses and rich snippets.",
        "default_action": "Wrap Q&A content in Schema.org FAQPage JSON-LD markup enclosing explicit Question and Answer entities.",
    },
    "SF-007": {
        "theme": "Content Freshness Signals",
        "asset_type": "JSON-LD / HTTP Headers",
        "location": "Article templates, dateModified JSON-LD, Last-Modified header",
        "why_it_matters": "AI models prioritize fresh, verified sources; stale dates (>365 days) on editorial content signal decay and diminish citation frequency.",
        "default_action": "Update dateModified in JSON-LD and configure Last-Modified HTTP headers whenever revising editorial or article content.",
    },
    "SF-008": {
        "theme": "Page Disambiguation & Metadata",
        "asset_type": "HTML <title> Tag",
        "location": "Page <head> <title> and <meta name='description'>",
        "why_it_matters": "Duplicate or generic page titles prevent AI retrieval systems from distinguishing between distinct topics across your site.",
        "default_action": "Write unique, descriptive <title> tags combining page-specific topic keywords and brand name for every crawled URL.",
    },

    # Trust & Entity Corroboration
    "TC-001": {
        "theme": "External Entity Corroboration",
        "asset_type": "JSON-LD sameAs Array",
        "location": "Organization JSON-LD in homepage <head>",
        "why_it_matters": "sameAs links connect your brand to authoritative global knowledge graph nodes (Wikidata, Wikipedia, LinkedIn), confirming corporate legitimacy to AI evaluators.",
        "default_action": "Add an array of authoritative profile URLs (Wikidata entity, Wikipedia article, LinkedIn organization, Crunchbase) to sameAs in Organization JSON-LD.",
    },
    "TC-002": {
        "theme": "External Entity Corroboration",
        "asset_type": "HTML Text & PostalAddress Schema",
        "location": "Footer, contact page, and JSON-LD Organization block",
        "why_it_matters": "Conflicting Name, Address, or Phone (NAP) details across pages erode entity confidence scores in AI knowledge bases.",
        "default_action": "Standardize brand name spelling, E.164 phone format, and PostalAddress structured data consistently across all pages.",
    },
    "TC-003": {
        "theme": "External Entity Corroboration",
        "asset_type": "Outbound Verification Links",
        "location": "Accreditation and certification claim links",
        "why_it_matters": "Broken links to accreditation registries cast doubt on claimed credentials and may trigger trust penalties in AI evaluation algorithms.",
        "default_action": "Update outbound accreditation links to ensure all verification targets resolve with HTTP 200/301 responses.",
    },
    "TC-004": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD Organization Schema",
        "location": "Organization JSON-LD in homepage <head>",
        "why_it_matters": "Common-word or ungrounded brand names suffer entity collisions in LLMs unless grounded by Wikidata links, legalName, address, and foundingDate.",
        "default_action": "Add disambiguating properties to Organization JSON-LD: link to Wikidata in sameAs, declare legalName, foundingDate, and physical address.",
    },
    "TC-005": {
        "theme": "External Entity Corroboration",
        "asset_type": "Outbound Authority Links",
        "location": "Trust badges and partnership claims",
        "why_it_matters": "Unsubstantiated authority or partnership claims cannot be corroborated by automated AI fact-checking systems.",
        "default_action": "Attach outbound links pointing to official partner directories or licensing boards for all claimed credentials.",
    },
    "TC-006": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD Disambiguators",
        "location": "Organization JSON-LD in homepage <head>",
        "why_it_matters": "Missing corporate identifiers (taxID, legalName, foundingDate) reduce entity resolution certainty in business AI platforms.",
        "default_action": "Enrich Organization JSON-LD with foundingDate, legalName, and official corporate registry identifiers.",
    },

    # Engagement & Retention
    "ER-001": {
        "theme": "Semantic Document Hierarchy",
        "asset_type": "HTML <h1> Heading",
        "location": "Page main template body above the fold",
        "why_it_matters": "An explicit H1 heading gives AI summarizers and passage-ranking models the authoritative primary topic of the document.",
        "default_action": "Add a single, prominent <h1> element above the fold that clearly summarizes the primary page subject.",
    },
    "ER-002": {
        "theme": "Semantic Document Hierarchy",
        "asset_type": "HTML BreadcrumbList / Schema.org BreadcrumbList",
        "location": "Page navigation header or breadcrumb trail on deep pages",
        "why_it_matters": "Breadcrumb navigation enables AI engines to understand site hierarchy and content taxonomy; deep pages without breadcrumbs appear contextually isolated, reducing passage ranking.",
        "default_action": "Add visible breadcrumb navigation with Schema.org BreadcrumbList JSON-LD markup to all pages at depth >= 2 in the URL hierarchy.",
    },
    "ER-003": {
        "theme": "Paywall & Overlay Governance",
        "asset_type": "CSS Overlay / Modal Dialog",
        "location": "Page viewport — post-load modal or overlay elements",
        "why_it_matters": "Full-page overlays (cookie banners, subscription popups, GDPR notices) that cover >60% of the viewport obstruct AI crawler DOM inspection and content extraction.",
        "default_action": "Configure overlays to fire only on user interaction or after a delay; ensure the main content DOM is accessible without overlay dismissal. Avoid blocking overlays for non-human crawler sessions.",
    },
    "ER-004": {
        "theme": "Crawl Budget & Link Health",
        "asset_type": "HTML Hyperlinks",
        "location": "Navigation menus, footer links, and in-content anchors",
        "why_it_matters": "Internal 404 links waste crawler budget, trap bots in dead ends, and prevent indexation of linked brand resources.",
        "default_action": "Fix or remove broken internal links returning 4xx/5xx status codes to restore uninterrupted crawl traversability.",
    },
    "ER-005": {
        "theme": "Content Orientation & Conversion",
        "asset_type": "HTML Button / CTA Element",
        "location": "Product, landing, and service pages — primary action area",
        "why_it_matters": "Clear call-to-action (CTA) elements signal page intent to AI content classifiers and confirm the page's transactional vs informational role in the site taxonomy.",
        "default_action": "Add prominent, recognizable html CTA buttons (e.g. 'Buy Now', 'Get Started', 'Request Demo') above the fold on product and landing pages. Link each CTA to the canonical url for the action destination.",
    },
    "ER-006": {
        "theme": "Mobile & Responsive Accessibility",
        "asset_type": "HTML <meta name='viewport'> Tag",
        "location": "Page <head> viewport meta tag",
        "why_it_matters": "Missing viewport meta tags prevent mobile-optimized rendering; many AI crawlers and headless browsers use mobile viewport emulation, causing layout failures that truncate indexable content.",
        "default_action": "Add <meta name='viewport' content='width=device-width, initial-scale=1'> to the <head> of every HTML page.",
    },
    "ER-007": {
        "theme": "Mobile & Responsive Accessibility",
        "asset_type": "HTML <meta name='viewport'> user-scalable parameter",
        "location": "Page <head> viewport meta content attribute",
        "why_it_matters": "user-scalable=no and maximum-scale=1 restrict accessibility and violate browser accessibility guidelines; headless rendering engines may also encounter layout calculation errors on such pages.",
        "default_action": "Remove user-scalable=no and maximum-scale=1 from all html viewport meta header tags to restore zoom and layout accessibility.",
    },
    "ER-008": {
        "theme": "Content Orientation & Conversion",
        "asset_type": "HTML Search Input / Schema.org SearchAction",
        "location": "Site header, navigation bar, or SearchAction JSON-LD",
        "why_it_matters": "Large sites without discoverable search functionality reduce user retention and deny AI engines a structured site-search declaration (SearchAction), preventing integration into AI assistant search flows.",
        "default_action": "Add a visible search input or SearchBar to the site navigation and declare Schema.org SearchAction in WebSite JSON-LD to expose search capability to AI agents.",
    },

    # Proactive
    "PA-001": {
        "theme": "AI Agent Protocol Adoption",
        "asset_type": "Markdown Protocol Manifest",
        "location": "/llms.txt or /agents.md at domain root",
        "why_it_matters": "Curated machine-readable Markdown manifests provide LLMs and autonomous agents with concise, hallucination-free brand overviews and documentation endpoints.",
        "default_action": "Publish an /llms.txt or /agents.md file at site root adhering to the standardized llmstxt.org specification.",
    },
    "PA-002": {
        "theme": "Structured Entity Schema",
        "asset_type": "JSON-LD @graph Schema",
        "location": "Page <head> application/ld+json",
        "why_it_matters": "Consolidating isolated JSON-LD script blocks into a unified @graph array with persistent @id URIs establishes explicit entity-relationship topologies for AI knowledge graphs.",
        "default_action": "Unify page JSON-LD into a single @graph array using stable @id URIs (e.g. #organization, #website) for cross-entity references.",
    },
    "PA-003": {
        "theme": "Semantic Document Hierarchy",
        "asset_type": "HTML Heading id Attributes",
        "location": "Section headings (h2, h3)",
        "why_it_matters": "Persistent fragment identifier IDs on headings allow AI answer engines (ChatGPT, Perplexity, Gemini) to deep-link directly to the specific factual paragraph answering a query.",
        "default_action": "Add descriptive slug id attributes (e.g. <h2 id='pricing-details'>) to all major section headings.",
    },
    "PA-004": {
        "theme": "Semantic Document Hierarchy",
        "asset_type": "Content Structure & Copy",
        "location": "Article & guide introductory sections",
        "why_it_matters": "Leading with direct, declarative answers (inverted pyramid) maximizes RAG semantic retrieval scoring and ensures AI engines extract answers without truncation.",
        "default_action": "Adopt an answer-first structure: place concise, definitive answers in the opening paragraph and section headings before providing supporting context.",
    },
    "PA-005": {
        "theme": "Content Freshness Signals",
        "asset_type": "Syndication Feed (RSS/Atom)",
        "location": "Page <head> <link rel='alternate'>",
        "why_it_matters": "Syndication feeds provide AI aggregators and search engines with real-time push notifications of updated articles, products, and announcements.",
        "default_action": "Publish and link an RSS 2.0 or Atom feed (<link rel='alternate' type='application/rss+xml'>) to signal ongoing content freshness.",
    },
    "PA-006": {
        "theme": "Crawler Access Governance",
        "asset_type": "robots.txt Directives",
        "location": "/robots.txt at domain root",
        "why_it_matters": "Explicit Allow directives for verified AI crawlers eliminate any ambiguity about site indexing policies and prevent accidental blocking from broad wildcard rules.",
        "default_action": "Add explicit User-agent / Allow: blocks for major AI search crawlers (GPTBot, Claude-Web, PerplexityBot, Google-Extended).",
    },
    "PA-CANONICAL": {
        "theme": "Crawl Budget & Link Health",
        "asset_type": "HTML <link rel='canonical'>",
        "location": "Page <head>",
        "why_it_matters": "Canonical links prevent duplicate content fragmentation across query parameters, tracking tags, and alternate protocols.",
        "default_action": "Specify absolute, self-referential <link rel='canonical'> tags on every indexable page.",
    },
}


def _resolve_finding_metadata(lid: str, title: str, raw: dict) -> dict[str, str]:
    """Resolve exact remediation metadata for a finding, taking into account
    sub-finding titles within multi-condition check IDs (e.g. CR-002, CR-005, CR-006,
    CR-007, SF-004, SF-008, TC-002, TC-004, ER-001, ER-003, ER-004)."""
    base = dict(_FINDING_REMEDIATION_METADATA.get(lid, {}))
    t_lower = (title or "").lower()

    if lid == "CR-002":
        if "non-ok" in t_lower or "status" in t_lower:
            base["theme"] = "Crawl Budget & Link Health"
            base["asset_type"] = "Web Server / HTTP Route"
            base["location"] = "Internal page URLs returning 4xx/5xx status codes"
            base["why_it_matters"] = "Internal URLs returning 4xx or 5xx status codes waste crawler budget and lead AI search engines into dead ends, preventing content indexing."
            base["default_action"] = "Fix server responses so all public pages return 200 (OK) or 301 redirects, and remove or update links to non-existent resources."
        elif "redirect" in t_lower:
            base["theme"] = "Crawl Budget & Link Health"
            base["asset_type"] = "HTTP Redirect Configuration"
            base["location"] = "Edge CDN / Web Server redirect rules"
            base["why_it_matters"] = "Redirect chains exceeding 2 hops increase latency, exhaust crawler fetch budgets, and risk crawler abandonment before the final destination page is reached."
            base["default_action"] = "Shorten redirect chains to direct 1-hop 301 redirects pointing directly to the final canonical destination URL."

    elif lid == "CR-005":
        if "geolocation" in t_lower or "location-selection" in t_lower or "pincode" in t_lower:
            base["asset_type"] = "Location Selector / Modal Dialog"
            base["location"] = "Location picker modal or pincode gating overlay"
            base["why_it_matters"] = "Mandatory geolocation or pincode gating blocks autonomous AI crawlers from accessing catalog content, rendering entire product lines unindexable."
            base["default_action"] = "Serve a default, national, or location-agnostic catalog view for unauthenticated AI crawler sessions without requiring location selection."
        elif "full-viewport" in t_lower or "overlay" in t_lower:
            base["asset_type"] = "CSS Overlay / Modal Dialog"
            base["location"] = "Viewport modal overlays and CSS dialogs"
            base["why_it_matters"] = "Full-page blocking overlays with high z-index obscure page content during automated crawler DOM inspection and rendering."
            base["default_action"] = "Ensure core content is accessible in the underlying DOM and avoid full-viewport blocking overlays for unauthenticated crawler sessions."

    elif lid == "CR-006":
        if "declared" in t_lower or "robots.txt" in t_lower:
            base["asset_type"] = "robots.txt Sitemap Directive"
            base["location"] = "/robots.txt at domain root"
            base["why_it_matters"] = "Omitting the Sitemap: directive from /robots.txt delays or prevents AI crawlers from discovering your XML sitemap endpoint automatically."
            base["default_action"] = "Add a 'Sitemap: https://yourdomain.com/sitemap.xml' directive to /robots.txt for reliable crawler discovery."

    elif lid == "CR-007":
        if "crawl-delay" in t_lower:
            base["theme"] = "Crawler Access Governance"
            base["asset_type"] = "robots.txt Crawl-delay Directive"
            base["location"] = "/robots.txt Crawl-delay directive"
            base["why_it_matters"] = "Excessive Crawl-delay values (>10s) severely throttle AI search crawlers below their efficient indexing cadence, delaying updates."
            base["default_action"] = "Lower or remove the Crawl-delay directive in /robots.txt for verified AI crawler user-agents."
        elif "stale" in t_lower:
            base["asset_type"] = "XML Sitemap <lastmod> Timestamps"
            base["location"] = "/sitemap.xml <url><lastmod> tags"
            base["why_it_matters"] = "Stale <lastmod> dates (>365 days) indicate unmaintained content, causing AI search engines to downgrade citation and re-crawling priority."
            base["default_action"] = "Update <lastmod> timestamps when revising pages, and prune obsolete entries from sitemap.xml."
        elif "missing" in t_lower:
            base["asset_type"] = "XML Sitemap <lastmod> Timestamps"
            base["location"] = "/sitemap.xml <url><lastmod> tags"
            base["why_it_matters"] = "Missing <lastmod> dates prevent AI search engines from determining which pages have updated, leading to stale indexation."
            base["default_action"] = "Populate accurate W3C Datetime <lastmod> timestamps for all entries in /sitemap.xml."

    elif lid == "SF-004":
        if "video" in t_lower or "caption" in t_lower or "track" in t_lower:
            base["asset_type"] = "HTML5 <video> Element / WebVTT Track"
            base["location"] = "Page video elements (<video>)"
            base["why_it_matters"] = "Video elements without subtitle/caption tracks (<track kind='captions'>) prevent AI crawlers from indexing spoken dialogue and multimedia transcripts."
            base["default_action"] = "Add WebVTT caption tracks (<track kind='captions'>) to all video elements or provide a visible HTML transcript."

    elif lid == "SF-008":
        if "description" in t_lower:
            base["asset_type"] = "HTML <meta name='description'> Tag"
            base["location"] = "Page <head> <meta name='description'>"
            base["why_it_matters"] = "Duplicate meta descriptions across distinct URLs hinder AI search engines and summarizers from generating accurate snippet previews for citation."
            base["default_action"] = "Write unique, content-specific meta descriptions for each indexable page."

    elif lid == "TC-002":
        if "phone" in t_lower:
            base["asset_type"] = "Phone Number / contactPoint Schema"
            base["location"] = "Contact pages, footer, and Organization schema"
            base["why_it_matters"] = "Multiple conflicting phone numbers cause AI entity resolution systems to downgrade contact authenticity and customer service trust."
            base["default_action"] = "Standardize phone numbers to E.164 format (+1-555-123-4567) consistently across all pages and JSON-LD contactPoint."
        elif "address" in t_lower:
            base["asset_type"] = "PostalAddress Schema & HTML Text"
            base["location"] = "Footer, contact page, and JSON-LD PostalAddress"
            base["why_it_matters"] = "Discrepancies in physical address formatting or values undermine local entity trust and geographic grounding in AI knowledge bases."
            base["default_action"] = "Standardize address formatting across all pages and JSON-LD using consistent PostalAddress properties."
        elif "brand name" in t_lower or "name" in t_lower:
            base["asset_type"] = "Brand Name Declarations"
            base["location"] = "Page titles, headers, and Organization schema"
            base["why_it_matters"] = "Conflicting brand name spelling or root variants across pages erode entity confidence scores in AI knowledge bases."
            base["default_action"] = "Standardize brand name spelling across all pages and JSON-LD structured data."

    elif lid == "TC-004":
        if "capitalisation" in t_lower or "spelling" in t_lower or "variant" in t_lower:
            base["theme"] = "External Entity Corroboration"
            base["asset_type"] = "Brand Name Styling"
            base["location"] = "Page headings, text content, and metadata"
            base["why_it_matters"] = "Inconsistent brand capitalization across pages causes AI tokenizers and entity linkers to fragment brand mentions into separate entities."
            base["default_action"] = "Standardize brand capitalization across all pages and declare alternateName in Organization JSON-LD for official abbreviations."

    elif lid == "ER-001":
        if "navigation" in t_lower or "nav" in t_lower:
            base["asset_type"] = "HTML <nav> Navigation Container"
            base["location"] = "Site header / primary navigation bar"
            base["why_it_matters"] = "Lack of primary navigation prevents AI crawlers and users from understanding site architecture and traversing top-level sections."
            base["default_action"] = "Add a semantic <nav> element with primary internal links to major site sections."
        elif "multiple" in t_lower:
            base["asset_type"] = "HTML <h1> Heading"
            base["location"] = "Page template headings"
            base["why_it_matters"] = "Multiple H1 elements create ambiguity in document topic hierarchy for AI passage-ranking models."
            base["default_action"] = "Retain a single authoritative <h1> per page and convert secondary section headings to <h2>-<h6>."

    elif lid == "ER-003":
        if "cookie" in t_lower or "gdpr" in t_lower or "consent" in t_lower:
            base["asset_type"] = "Cookie Consent Banner"
            base["location"] = "Page viewport — bottom/floating banner"
            base["why_it_matters"] = "Intrusive full-screen blocking consent overlays prevent content rendering and crawler indexing until dismissed."
            base["default_action"] = "Ensure cookie banner HTML elements do not cover the main content DOM area. Use a non-blocking footer banner rather than a full-viewport modal."
        elif "newsletter" in t_lower or "subscription" in t_lower or "signup" in t_lower:
            base["asset_type"] = "Newsletter Subscription Modal"
            base["location"] = "Page viewport modal dialog"
            base["why_it_matters"] = "Post-load newsletter modals interrupt crawler DOM extraction and cause layout instability."
            base["default_action"] = "Delay newsletter modals until after meaningful user interaction, and suppress them for crawler user-agents."

    elif lid == "ER-004":
        if "ratio" in t_lower:
            base["why_it_matters"] = "A high proportion (>5%) of broken internal links traps AI crawlers and severely degrades domain trust scores."
            base["default_action"] = "Audit and fix all broken internal links across the site to restore crawl traversability."

    return base


# ===================================================================
# NORMALISATION: domain findings -> schema findings
# ===================================================================

def _normalise_finding(raw: Any, domain_name: str, target_url: str) -> dict:
    """Convert a Step-2 domain finding into the report-schema Finding shape."""
    if not isinstance(raw, dict):
        raw = {"title": str(raw), "evidence": str(raw)}

    lid = raw.get("local_id", "")

    # Title: clamp length
    title = str(raw.get("title", "Untitled finding"))[:120]
    if len(title) < 5:
        title = title.ljust(5, ".")

    meta = _resolve_finding_metadata(lid, title, raw)

    # Category normalisation
    raw_cat = raw.get("category", "")
    valid_cats = {
        "discoverability", "engagement", "proactive",
        "crawl_render_access", "structured_fact_extraction",
        "trust_entity_corroboration", "engagement_retention",
    }
    if raw_cat in valid_cats:
        category = raw_cat
    else:
        category = _DOMAIN_TO_CATEGORY.get(domain_name, "discoverability")

    # Evidence: keep string or dict, ensure length >= 3
    raw_evidence = raw.get("evidence", "")
    if isinstance(raw_evidence, str):
        evidence = raw_evidence if len(raw_evidence) >= 3 else raw_evidence.ljust(3, ".")
    elif isinstance(raw_evidence, dict):
        if "url" not in raw_evidence:
            raw_evidence["url"] = target_url
        evidence = raw_evidence
    else:
        evidence = str(raw_evidence)
        if len(evidence) < 3:
            evidence = evidence.ljust(3, ".")

    severity = raw.get("severity", "info")
    if severity not in _SEVERITY_ORDER:
        severity = "info"

    why_it_matters = raw.get("why_it_matters") or meta.get("why_it_matters") or "Impacts AI discovery and fact extraction."
    location = raw.get("location") or meta.get("location") or "Audited page content"
    remediation_theme = raw.get("remediation_theme") or meta.get("theme") or "General AI Readiness"
    asset_type = raw.get("asset_type") or meta.get("asset_type") or "Web asset"

    # Suggested action: object with summary and priority
    raw_action = raw.get("suggested_action", {})
    if isinstance(raw_action, dict):
        summary_str = str(raw_action.get("summary", "")).strip()
        prio_str = str(raw_action.get("priority", severity)).strip()
        if len(summary_str) < 5:
            summary_str = meta.get("default_action") or summary_str.ljust(5, ".") or "Review and address this finding."
        if prio_str not in _SEVERITY_ORDER:
            prio_str = severity if severity in _SEVERITY_ORDER else "info"
    elif isinstance(raw_action, str):
        summary_str = raw_action.strip()
        if len(summary_str) < 5:
            summary_str = meta.get("default_action") or summary_str.ljust(5, ".") or "Review and address this finding."
        prio_str = severity
    else:
        summary_str = meta.get("default_action") or "Review and address this finding."
        prio_str = severity

    # Prioritization check (Phase 6D):
    # Ensure priority reflects evidence strength:
    ev_str = str(evidence)
    if "[INSUFFICIENT_EVIDENCE]" in ev_str or "[NOT_OBSERVABLE]" in ev_str:
        if prio_str in ("critical", "high"):
            prio_str = "medium"

    suggested_action = {
        "summary": summary_str,
        "priority": prio_str,
        "remediation_theme": remediation_theme,
        "location": location,
        "asset_type": asset_type,
        "mechanism": why_it_matters,
    }

    finding = {
        "_local_id": lid,
        "local_id": lid,
        "_domain": domain_name,
        "_related_to_local": list(raw.get("related_to", [])),
        "id": "",  # assigned after dedup + ordering
        "title": title,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "suggested_action": suggested_action,
        "related_to": [],
        "location": location,
        "why_it_matters": why_it_matters,
        "remediation_theme": remediation_theme,
    }

    if "source" in raw and raw["source"] in ("static", "rendered"):
        finding["source"] = raw["source"]

    pages_affected = raw.get("pages_affected")
    pages_checked = raw.get("pages_checked")
    if (
        pages_affected is not None
        and pages_checked is not None
        and pages_checked > 0
    ):
        conf = round(pages_affected / pages_checked, 2)
        finding["confidence"] = max(0.0, min(1.0, conf))

    return finding


# ===================================================================
# DEDUPLICATION
# ===================================================================

def _dedup_key(finding: dict) -> str:
    """Compute a normalised dedup key for a finding."""
    parts = [
        finding.get("category", ""),
        finding.get("severity", ""),
        finding.get("_local_id", ""),
        finding.get("title", "").lower().strip()[:120],
    ]
    return "|".join(parts)



def _deduplicate(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings, keeping the first occurrence."""
    seen: set[str] = set()
    result: list[dict] = []
    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


# ===================================================================
# ORDERING + ID ASSIGNMENT
# ===================================================================

def _sort_findings(findings: list[dict]) -> list[dict]:
    """Sort canonically by severity (critical first), category, local_id, title, and evidence.
    
    Establishes a complete total order so that no two findings ever have an
    ambiguous or arrival-dependent relative ordering.
    """
    def sort_key(f: dict) -> tuple:
        sev = f.get("severity", "info")
        sev_idx = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 99
        cat = str(f.get("category", ""))
        lid = str(f.get("_local_id", "") or f.get("local_id", ""))
        title = str(f.get("title", ""))
        ev = f.get("evidence", "")
        ev_str = json.dumps(ev, sort_keys=True) if isinstance(ev, (dict, list)) else str(ev)
        return (sev_idx, cat, lid, title, ev_str)
    return sorted(findings, key=sort_key)


def _assign_ids(findings: list[dict]) -> list[dict]:
    """Assign sequential F-001..F-NNN IDs after dedup+sort."""
    for i, f in enumerate(findings, start=1):
        f["id"] = f"F-{i:03d}"
    return findings


# ===================================================================
# CROSS-REFERENCING
# ===================================================================

def _resolve_related_to(findings: list[dict]) -> list[dict]:
    """Resolve _related_to_local references to final F-XXX IDs."""
    # Build local_id -> final_id map
    local_to_final: dict[str, str] = {}
    for f in findings:
        lid = f.get("_local_id", "") or f.get("local_id", "")
        if lid:
            local_to_final[lid] = f["id"]

    final_ids = {f["id"] for f in findings}

    for f in findings:
        related_local = f.get("_related_to_local", [])
        resolved: list[str] = []
        for ref in related_local:
            if ref in final_ids and ref != f["id"]:
                resolved.append(ref)
            else:
                final = local_to_final.get(ref)
                if final and final != f["id"] and final in final_ids:
                    resolved.append(final)
        # Deduplicate and sort canonically
        unique_resolved = sorted(set(resolved))
        f["related_to"] = unique_resolved

    return findings


def _clean_internal_fields(findings: list[dict]) -> list[dict]:
    """Remove internal _-prefixed fields before schema validation."""
    for f in findings:
        for key in list(f.keys()):
            if key.startswith("_"):
                del f[key]
    return findings


# ===================================================================
# COVERAGE
# ===================================================================

def _build_coverage(
    domain_results: dict[str, dict | None],
    findings: list[dict],
    frontier: Optional[list] = None,
    audit_status: Optional[str] = None,
    blocked_reason: Optional[str] = None,
) -> dict:
    """Build per-domain SkillCoverage objects and surface compact, deterministic coverage states."""
    coverage: dict[str, Any] = {}
    limitations: list[str] = []

    crawl_res = domain_results.get("crawl-render-access") or {}
    crawl_frontier = frontier if frontier is not None else crawl_res.get("crawl_frontier", [])
    page_results = crawl_res.get("page_results", {})

    low_conf_count = 0
    for u in crawl_frontier:
        conf = getattr(u, "render_confidence", None)
        if conf is None and isinstance(u, dict):
            conf = u.get("render_confidence")
        if conf is None and isinstance(u, str) and u in page_results:
            conf = getattr(page_results[u], "render_confidence", None)
        if conf == "low":
            low_conf_count += 1

    pages_audited = crawl_res.get("pages_analyzed", 0)
    total_pages = len(crawl_frontier) if crawl_frontier else max(
        1, crawl_res.get("pages_discovered", 1)
    )
    crawl_cov = crawl_res.get("coverage") or {}
    budget_limited = crawl_cov.get("budget_limited", False)
    pages_in_sitemap = crawl_cov.get("pages_in_sitemap")

    # Evaluate crawl_render_access state
    if pages_audited == 0:
        cra_state = CoverageState.UNAVAILABLE.value
        limitations.append("Crawl and rendering could not inspect any pages (UNAVAILABLE).")
    elif low_conf_count == pages_audited:
        cra_state = CoverageState.LIMITED.value
        limitations.append(
            "Browser rendering was unobservable or failed across all audited pages; "
            "dynamic client-side JS content was not inspected (LIMITED)."
        )
    elif budget_limited:
        cra_state = CoverageState.PARTIAL.value
        if pages_in_sitemap:
            limitations.append(
                f"Crawl bounded to {pages_audited} of {pages_in_sitemap} sitemap pages due to crawl budget (PARTIAL)."
            )
        else:
            limitations.append(
                f"Crawl bounded to {pages_audited} pages due to crawl budget (PARTIAL)."
            )
    elif low_conf_count > 0:
        cra_state = CoverageState.PARTIAL.value
        limitations.append(
            f"Browser rendering observed with low confidence on {low_conf_count} of {pages_audited} pages (PARTIAL)."
        )
    else:
        cra_state = CoverageState.COMPLETE.value

    domain_states: dict[str, str] = {"crawl-render-access": cra_state}

    for domain_key, schema_key in [
        ("crawl-render-access", "crawl_render_access"),
        ("structured-fact-extraction", "structured_fact_extraction"),
        ("trust-entity-corroboration", "trust_entity_corroboration"),
        ("engagement-retention", "engagement_retention"),
    ]:
        result = domain_results.get(domain_key)
        if result is None:
            coverage[schema_key] = {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 1,
                "notes": "Domain audit was skipped or failed.",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": CoverageState.UNAVAILABLE.value,
            }
            domain_states[domain_key] = CoverageState.UNAVAILABLE.value
            domain_label = schema_key.replace("_", " ")
            limitations.append(f"{domain_label} failed to execute (UNAVAILABLE).")
        elif schema_key == "crawl_render_access":
            errors_list = result.get("errors", [])
            cov_entry: dict[str, Any] = {
                "pages_checked": pages_audited,
                "checks_run": len(result.get("findings", [])),
                "errors": len(errors_list),
                "render_confidence": "low" if low_conf_count > 0 else "high",
                "pages_with_low_render_confidence": low_conf_count,
                "coverage_state": cra_state,
            }
            if errors_list:
                cov_entry["notes"] = "; ".join(str(e) for e in errors_list[:3])
            elif low_conf_count > 0:
                pct = round((low_conf_count / total_pages) * 100)
                cov_entry["notes"] = (
                    f"{low_conf_count} of {total_pages} page(s) ({pct}%) had low render confidence "
                    "(text blanking detected without successful JS render)."
                )
            coverage[schema_key] = cov_entry
        else:
            pages_checked = result.get("pages_analyzed", 0)
            errors_list = result.get("errors", [])
            domain_low_conf = min(low_conf_count, pages_checked) if pages_checked > 0 else 0

            # Determine domain coverage state
            domain_label = schema_key.replace("_", " ")
            if pages_checked == 0:
                dom_state = CoverageState.UNAVAILABLE.value
                limitations.append(f"{domain_label} did not inspect any pages (UNAVAILABLE).")
            elif any("unreachable" in str(e).lower() or "NOT_OBSERVABLE" in str(e) for e in errors_list):
                dom_state = CoverageState.LIMITED.value
                limitations.append(
                    f"{domain_label} had unreachable corroborating sources; claims could not be verified (LIMITED)."
                )
            elif cra_state == CoverageState.LIMITED.value:
                dom_state = CoverageState.LIMITED.value
                limitations.append(
                    f"{domain_label} evaluated unrendered static HTML; client-side entities were unobservable (LIMITED)."
                )
            elif errors_list:
                dom_state = CoverageState.PARTIAL.value
                limitations.append(f"{domain_label} encountered soft errors during execution (PARTIAL).")
            elif cra_state == CoverageState.PARTIAL.value:
                dom_state = CoverageState.PARTIAL.value
            else:
                dom_state = CoverageState.COMPLETE.value

            domain_states[domain_key] = dom_state

            cov_entry = {
                "pages_checked": pages_checked,
                "checks_run": len(result.get("findings", [])),
                "errors": len(errors_list),
                "render_confidence": "low" if domain_low_conf > 0 else "high",
                "pages_with_low_render_confidence": domain_low_conf,
                "coverage_state": dom_state,
            }
            if errors_list:
                cov_entry["notes"] = "; ".join(str(e) for e in errors_list[:3])
            elif domain_low_conf > 0:
                pct = round((domain_low_conf / total_pages) * 100)
                cov_entry["notes"] = (
                    f"{domain_low_conf} of {total_pages} page(s) ({pct}%) had low render confidence; "
                    f"{domain_label} checks ran on unrendered content rather than passing verified checks."
                )
            coverage[schema_key] = cov_entry

    coverage["pages_with_low_render_confidence"] = low_conf_count
    coverage["render_confidence"] = "low" if low_conf_count > 0 else "high"

    # Determine overall_state
    if any(s == CoverageState.UNAVAILABLE.value for s in domain_states.values()) or audit_status == "blocked":
        overall_state = CoverageState.UNAVAILABLE.value
    elif any(s == CoverageState.LIMITED.value for s in domain_states.values()):
        overall_state = CoverageState.LIMITED.value
    elif any(s == CoverageState.PARTIAL.value for s in domain_states.values()):
        overall_state = CoverageState.PARTIAL.value
    else:
        overall_state = CoverageState.COMPLETE.value

    coverage["overall_state"] = overall_state
    coverage["limitations"] = limitations

    return coverage


# ===================================================================
# PROACTIVE_RECOMMENDATIONS (string list for schema)
# ===================================================================

def _build_proactive_strings(
    domain_results: dict[str, dict | None],
) -> list[str]:
    """Collect proactive_candidates from domain runners in canonical order as plain strings."""
    strings: list[str] = []
    seen: set[str] = set()
    canonical_domain_order = [
        "crawl-render-access",
        "structured-fact-extraction",
        "trust-entity-corroboration",
        "engagement-retention",
    ]
    for domain_name in canonical_domain_order:
        result = domain_results.get(domain_name)
        if result is None:
            continue
        for rec in result.get("proactive_candidates", []):
            if isinstance(rec, dict):
                text = rec.get("title", "")
                rationale = rec.get("rationale", "")
                if text and rationale:
                    full = f"{text}: {rationale}"
                elif text:
                    full = text
                else:
                    full = rationale
            elif isinstance(rec, str):
                full = rec
            else:
                continue
            full = full.strip()
            if full and full not in seen and len(full) >= 10:
                seen.add(full)
                strings.append(full)
    return strings


# ===================================================================
# REMEDIATION THEMES (Lightweight grouping by action & target asset)
# ===================================================================

def _build_remediation_themes(findings: list[dict]) -> list[dict]:
    """Group findings into deterministic remediation themes sharing common actions/assets.

    No causal graph is created; original findings remain unhidden.
    Priority reflects highest finding severity/action priority in the theme.
    Ordering is deterministic: priority descending, then theme name ascending.
    """
    if not findings:
        return []

    theme_groups: dict[str, list[dict]] = {}
    for f in findings:
        th_name = f.get("remediation_theme") or "General AI Readiness"
        theme_groups.setdefault(th_name, []).append(f)

    themes: list[dict] = []
    for th_name, group_findings in theme_groups.items():
        finding_ids = [f["id"] for f in group_findings if f.get("id")]
        if not finding_ids:
            continue

        def _get_prio(f: dict) -> str:
            act = f.get("suggested_action")
            if isinstance(act, dict) and act.get("priority") in _SEVERITY_ORDER:
                return act["priority"]
            sev = f.get("severity")
            if sev in _SEVERITY_ORDER:
                return sev
            return "info"

        best_prio_idx = min(_SEVERITY_ORDER.index(_get_prio(f)) for f in group_findings)
        highest_prio = _SEVERITY_ORDER[best_prio_idx]

        sorted_group = sorted(
            group_findings,
            key=lambda f: (_SEVERITY_ORDER.index(_get_prio(f)), f.get("id", ""))
        )
        lead_finding = sorted_group[0]
        lead_action = lead_finding.get("suggested_action")
        if isinstance(lead_action, dict):
            primary_act = lead_action.get("summary") or lead_finding.get("title", "")
            target_asset = lead_action.get("location") or lead_finding.get("location") or "Target domain asset"
        else:
            primary_act = lead_finding.get("title", "Review and address findings.")
            target_asset = lead_finding.get("location") or "Target domain asset"

        themes.append({
            "theme": th_name,
            "finding_ids": finding_ids,
            "primary_action": primary_act,
            "target_asset": target_asset,
            "priority": highest_prio,
        })

    themes.sort(key=lambda t: (_SEVERITY_ORDER.index(t["priority"]), t["theme"]))
    return themes


# ===================================================================
# SITE-WIDE BLOCK DETECTION
# ===================================================================

def _is_site_wide_block(crawl_result: dict) -> bool:
    """Check if CR-001 indicates a site-wide critical block."""
    for f in crawl_result.get("findings", []):
        lid = f.get("local_id", "")
        sev = f.get("severity", "")
        if lid == "CR-001" and sev == "critical":
            ev = f.get("evidence", "")
            if isinstance(ev, str):
                blocked_count_match = re.search(r"(\d+)\s+AI\s+crawler", ev)
                if blocked_count_match:
                    count = int(blocked_count_match.group(1))
                    # Site-wide if majority (>= 10 of 14) crawlers are blocked
                    if count >= 10:
                        return True
    return False


# ===================================================================
# ABORTED REPORT BUILDER (SSRF, UNREACHABLE)
# ===================================================================

def _build_aborted_report(
    target_url: str,
    status: str,
    message: str,
    elapsed: float,
    reason: Optional[str] = None,
    findings: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """Build a compliant report for blocked or unreachable targets."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_findings = findings or []
    norm_findings = []
    for idx, f in enumerate(raw_findings, 1):
        nf = _normalise_finding(f, "crawl-render-access", target_url)
        nf["id"] = f"F-{idx:03d}"
        norm_findings.append(nf)
    norm_findings = _clean_internal_fields(norm_findings)

    sev_counts: Counter[str] = Counter()
    for f in norm_findings:
        sev_counts[f.get("severity", "info")] += 1

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": now_iso,
        "audited_at": now_iso,
        "target_url": target_url,
        "site": target_url,
        "audit_status": status,
        "audit_status_message": message,
        "pages_audited": 0,
        "audit_duration_seconds": max(0.0, round(elapsed, 2)),
        "summary": {
            "total_findings": len(norm_findings),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
            "coverage": {
                "pages_audited": 0,
                "pages_in_sitemap": None,
                "budget_limited": False,
            },
        },
        "findings": norm_findings,
        "proactive_recommendations": [],
        "remediation_themes": _build_remediation_themes(norm_findings),
        "coverage": {
            "crawl_render_access": {
                "pages_checked": 0,
                "checks_run": 1 if norm_findings else 0,
                "errors": 1,
                "notes": message,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "UNAVAILABLE",
            },
            "structured_fact_extraction": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "UNAVAILABLE",
            },
            "trust_entity_corroboration": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "UNAVAILABLE",
            },
            "engagement_retention": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
                "coverage_state": "UNAVAILABLE",
            },
            "pages_with_low_render_confidence": 0,
            "render_confidence": "high",
            "overall_state": "UNAVAILABLE",
            "limitations": [f"Audit was blocked before inspection: {message} (UNAVAILABLE)."],
        },
    }
    if reason:
        report["blocked_reason"] = reason

    # Ensure schema validity on aborted reports
    valid, validation_errors = validate_report(report)
    if not valid:
        logger.warning("Aborted report schema validation failed: %s", validation_errors)
        dur = report.get("audit_duration_seconds")
        if not isinstance(dur, (int, float)) or dur < 0:
            report["audit_duration_seconds"] = 0.0
        for f in report.get("findings", []):
            if "evidence" not in f or not f["evidence"]:
                f["evidence"] = f"Audited on {target_url}"
            if "suggested_action" not in f or not isinstance(f["suggested_action"], dict):
                f["suggested_action"] = {
                    "summary": "Review and address this finding.",
                    "priority": f.get("severity", "info"),
                }
            if "related_to" not in f or not isinstance(f["related_to"], list):
                f["related_to"] = []
        validate_report(report)

    return report


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================

def run_audit(
    target_url: str,
    max_pages: int = 15,
    timeout_s: int = 240,
    render_js: bool = False,
    renderer: Optional[PlaywrightRenderer] = None,
    allow_private_ips: bool = False,
    **kwargs: Any,
) -> dict:
    """Orchestrate the complete AI-readiness audit pipeline.

    Returns a fully validated JSON-Schema-compliant report dict.
    """
    t_start = time.monotonic()
    deadline: Optional[AuditDeadline] = kwargs.get("deadline")
    if deadline is None:
        deadline = AuditDeadline.from_budget(timeout_s, started_at=t_start)
    else:
        # Honor deadline's start time, but never allow future start times
        t_start = min(deadline.started_at, t_start)

    if "render_js" in kwargs:
        render_js = bool(kwargs["render_js"])
    if "renderer" in kwargs and kwargs["renderer"] is not None:
        renderer = kwargs["renderer"]
    if "allow_private_ips" in kwargs:
        allow_private_ips = bool(kwargs["allow_private_ips"])

    # --- Initialise HTTP client ---
    target_host = urllib.parse.urlparse(target_url).hostname or ""
    # Only permit loopback/private target destinations when explicitly passed via allow_private_ips=True
    is_local_target = bool(allow_private_ips) and (target_host in ("127.0.0.1", "localhost", "::1"))

    # Fast SSRF abort for disallowed targets
    if not is_local_target:
        disallowed, reason = is_ssrf_disallowed(target_host)
        if disallowed:
            elapsed = max(0.0, time.monotonic() - t_start)
            return _build_aborted_report(
                target_url,
                "blocked",
                f"Audit could not complete: target URL is blocked by SSRF protection ({reason}). Content was not inspected.",
                elapsed,
                reason="ssrf_disallowed",
            )

    client = HttpClient(allow_private_ips=is_local_target, deadline=deadline)

    own_renderer = False
    if render_js and renderer is None:
        try:
            renderer = PlaywrightRenderer(
                rate_limiter=client._limiter,
                robots_cache=client.robots,
                allow_private_ips=client._allow_private_ips,
                deadline=deadline,
                session=client._session,
                pin_manager=client._pin_manager,
            )
            own_renderer = True
        except Exception as exc:
            logger.warning("Failed to initialize PlaywrightRenderer: %s", exc)
            renderer = None
    elif renderer is not None:
        renderer.set_deadline(deadline)

    try:
        return _run_pipeline(
            target_url, max_pages, timeout_s, client, t_start,
            renderer=renderer, deadline=deadline,
        )
    finally:
        client.close()
        if own_renderer and renderer is not None:
            try:
                renderer.close()
            except Exception:
                pass


def _validate_and_sanitize_skill_output(raw_result: Any, domain_name: str) -> dict:
    """Validate and sanitize output from a domain audit runner.
    
    Guarantees that the orchestrator receives a well-formed dict matching:
      - domain: str
      - pages_analyzed: int >= 0
      - pages_discovered: int >= 0
      - errors: list[str]
      - findings: list[dict]
      - proactive_candidates: list
    Tolerates None, non-dict payloads, missing keys, and malformed findings.
    """
    if not isinstance(raw_result, dict):
        err = f"Domain {domain_name} returned non-dict payload of type {type(raw_result).__name__}"
        logger.warning(err)
        return {
            "domain": domain_name,
            "pages_analyzed": 0,
            "pages_discovered": 0,
            "errors": [err],
            "findings": [],
            "proactive_candidates": [],
        }

    try:
        pages_analyzed = max(0, int(raw_result.get("pages_analyzed", 0) or 0))
    except (ValueError, TypeError):
        pages_analyzed = 0

    try:
        pages_discovered = max(0, int(raw_result.get("pages_discovered", 0) or 0))
    except (ValueError, TypeError):
        pages_discovered = 0

    proactive_raw = raw_result.get("proactive_candidates", [])
    if isinstance(proactive_raw, (list, tuple)):
        proactive = list(proactive_raw)
    else:
        proactive = []

    sanitized: dict[str, Any] = {
        "domain": str(raw_result.get("domain", domain_name)),
        "pages_analyzed": pages_analyzed,
        "pages_discovered": pages_discovered,
        "errors": [str(e) for e in raw_result.get("errors", []) if e is not None],
        "findings": [],
        "proactive_candidates": proactive,
    }

    # Pass through optional crawl-render-access fields if present
    for opt_key in (
        "crawl_frontier", "page_results", "coverage", "network_requests",
        "performance_metrics", "rendered_word_count", "static_word_count", "csr_blanking_ratio"
    ):
        if opt_key in raw_result:
            sanitized[opt_key] = raw_result[opt_key]

    raw_findings = raw_result.get("findings", [])
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if isinstance(f, dict):
                sanitized["findings"].append(f)
            else:
                logger.warning("Ignoring non-dict finding in domain %s: %r", domain_name, f)

    return sanitized


def _run_pipeline(
    target_url: str,
    max_pages: int,
    timeout_s: int,
    client: HttpClient,
    t_start: float,
    renderer: Optional[PlaywrightRenderer] = None,
    deadline: Optional[AuditDeadline] = None,
) -> dict:
    """Internal pipeline — separated for testability."""
    domain_results: dict[str, dict | None] = {
        "crawl-render-access": None,
        "structured-fact-extraction": None,
        "trust-entity-corroboration": None,
        "engagement-retention": None,
    }
    all_errors: list[str] = []

    # ==============================================================
    # STEP 1: Crawl audit (produces frontier)
    # ==============================================================
    try:
        crawl_raw = crawl_audit.run_audit(
            target_url, client, max_pages=max_pages, timeout_s=timeout_s, t_start=t_start,
            renderer=renderer, deadline=deadline,
        )
        crawl_result = _validate_and_sanitize_skill_output(crawl_raw, "crawl-render-access")
        domain_results["crawl-render-access"] = crawl_result
    except Exception as exc:
        all_errors.append(f"crawl-render-access crashed: {exc}")
        crawl_result = {
            "findings": [], "errors": [str(exc)],
            "crawl_frontier": [target_url], "page_results": {},
            "pages_analyzed": 0, "pages_discovered": 0,
            "proactive_candidates": [], "domain": "crawl-render-access",
        }
        domain_results["crawl-render-access"] = crawl_result

    frontier: list[str] = crawl_result.get("crawl_frontier", [target_url])
    page_results: dict[str, PageResult] = crawl_result.get("page_results", {})

    # ==============================================================
    # STEP 2: Early abort on blocked/failed crawl
    # ==============================================================
    pages_analyzed = crawl_result.get("pages_analyzed", 0)
    if pages_analyzed == 0:
        elapsed = max(0.0, time.monotonic() - t_start)

        # 1. Total connection failure / host refused / DNS failure / timeout
        if not page_results or all(pr.status_code is None for pr in page_results.values()):
            errors_list = [pr.error for pr in page_results.values() if pr.error]
            if not errors_list:
                errors_list = crawl_result.get("errors", [])
            err_msg = "; ".join(errors_list[:3]) or "Target connection failed."
            return _build_aborted_report(
                target_url,
                status="blocked",
                message=f"Audit could not complete: connection to target failed ({err_msg}). No content could be inspected.",
                elapsed=elapsed,
                reason="connection_failed",
            )

        # 2. Site-wide robots disallow
        if any(pr.error and "robots.txt disallows" in pr.error for pr in page_results.values()):
            robots_findings = [f for f in crawl_result.get("findings", []) if f.get("local_id") == "CR-001"]
            return _build_aborted_report(
                target_url,
                status="blocked",
                message="Audit could not complete: robots.txt disallows crawler access to root. Content was not inspected.",
                elapsed=elapsed,
                reason="robots_disallowed",
                findings=robots_findings,
            )

        # 3. All attempted pages returned active WAF / anti-bot challenge
        waf_findings = [
            f for f in crawl_result.get("findings", [])
            if f.get("local_id") == "CR-002" and f.get("severity") == "critical"
        ]
        if waf_findings and all(pr.status_code in (403, 429, 503, 202) for pr in page_results.values()):
            return _build_aborted_report(
                target_url,
                status="blocked",
                message="Audit blocked: target site presented active WAF / anti-bot challenge on all attempted requests.",
                elapsed=elapsed,
                reason="waf_bot_challenge",
                findings=waf_findings,
            )

    # ==============================================================
    # STEP 3: Site-wide block short-circuit
    # ==============================================================
    site_blocked = _is_site_wide_block(crawl_result)

    # ==============================================================
    # STEP 4: Downstream domain audits
    # ==============================================================
    downstream = [
        ("structured-fact-extraction", sfe_audit),
        ("trust-entity-corroboration", tec_audit),
        ("engagement-retention", er_audit),
    ]

    for domain_name, module in downstream:
        if site_blocked:
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": ["Skipped: site-wide AI-crawler block detected."],
                "findings": [],
                "proactive_candidates": [],
            }
            continue

        # Check timeout budget
        elapsed = max(0.0, time.monotonic() - t_start)
        if (deadline and deadline.expired()) or elapsed >= timeout_s:
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": ["Skipped: timeout budget exhausted."],
                "findings": [],
                "proactive_candidates": [],
            }
            continue

        try:
            raw_res = module.run_audit(
                target_url,
                client,
                crawl_frontier=frontier,
                page_results=page_results,
                timeout_s=timeout_s,
                t_start=t_start,
                deadline=deadline,
            )
            domain_results[domain_name] = _validate_and_sanitize_skill_output(raw_res, domain_name)
        except Exception as exc:
            all_errors.append(f"{domain_name} crashed: {exc}")
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": [f"Domain runner exception: {exc}"],
                "findings": [],
                "proactive_candidates": [],
            }

    # ==============================================================
    # STEP 4: Merge findings from all domains
    # ==============================================================
    merged: list[dict] = []
    for domain_name, result in domain_results.items():
        if result is None:
            continue
        for raw_finding in result.get("findings", []):
            normalised = _normalise_finding(raw_finding, domain_name, target_url)
            merged.append(normalised)

    # ==============================================================
    # STEP 5: Canonical Sort then Deduplicate
    # ==============================================================
    # Canonical sort first so deduplication order is 100% deterministic
    merged_sorted = _sort_findings(merged)
    deduped = _deduplicate(merged_sorted)
    sorted_findings = _sort_findings(deduped)

    # ==============================================================
    # STEP 7: Assign sequential IDs
    # ==============================================================
    sorted_findings = _assign_ids(sorted_findings)

    # ==============================================================
    # STEP 8: Resolve related_to cross-references
    # ==============================================================
    sorted_findings = _resolve_related_to(sorted_findings)

    # ==============================================================
    # STEP 9: Build intermediate report for proactive engine
    # ==============================================================
    interim_report = {"findings": sorted_findings}

    # ==============================================================
    # STEP 10: Proactive recommendations (PA-001..PA-006)
    # ==============================================================
    proactive_findings = inject_proactive_recommendations(
        interim_report, page_results, client, target_url, deadline=deadline,
    )

    # Normalise proactive findings
    for pf in proactive_findings:
        norm = _normalise_finding(pf, "proactive", target_url)
        norm["severity"] = "info"
        norm["category"] = "proactive"
        sorted_findings.append(norm)

    # Re-deduplicate after proactive injection using canonical sorting
    sorted_findings = _sort_findings(sorted_findings)
    sorted_findings = _deduplicate(sorted_findings)
    sorted_findings = _sort_findings(sorted_findings)

    # Re-assign IDs sequentially (gap-free)
    sorted_findings = _assign_ids(sorted_findings)

    # Re-resolve references
    sorted_findings = _resolve_related_to(sorted_findings)

    # Clean internal fields
    sorted_findings = _clean_internal_fields(sorted_findings)

    # ==============================================================
    # STEP 12: Summary
    # ==============================================================
    sev_counts: Counter[str] = Counter()
    for f in sorted_findings:
        sev_counts[f.get("severity", "info")] += 1

    summary = {
        "total_findings": len(sorted_findings),
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "medium": sev_counts.get("medium", 0),
        "low": sev_counts.get("low", 0),
        "info": sev_counts.get("info", 0),
    }

    # Propagate crawl coverage into summary
    crawl_cov = (domain_results.get("crawl-render-access") or {}).get("coverage")
    if crawl_cov is not None:
        summary["coverage"] = crawl_cov
    else:
        summary["coverage"] = {
            "pages_audited": 0,
            "pages_in_sitemap": None,
            "budget_limited": False,
        }

    # ==============================================================
    # STEP 13: Assess status & subsystem execution
    # ==============================================================
    elapsed = max(0.0, time.monotonic() - t_start)

    timeout_skipped = any(
        res and any("timeout budget" in str(e).lower() for e in res.get("errors", []))
        for res in domain_results.values()
    )
    subsystem_failures = [
        domain_name for domain_name, res in domain_results.items()
        if res and any("exception" in str(e).lower() or "crashed" in str(e).lower() for e in res.get("errors", []))
    ]
    if timeout_skipped:
        overall_status = "partial"
        blocked_reason = "timeout_budget_exhausted"
        status_msg = "Audit completed partially: timeout budget was reached before all domain checks finished."
    elif subsystem_failures or all_errors:
        overall_status = "partial"
        blocked_reason = "subsystem_failure"
        failed_list = ", ".join(subsystem_failures) if subsystem_failures else "subsystem error"
        status_msg = f"Audit completed partially: failures in subsystem(s) [{failed_list}]."
    else:
        overall_status = "completed"
        blocked_reason = None
        status_msg = "Audit completed successfully."

    # ==============================================================
    # STEP 14: Coverage
    # ==============================================================
    coverage = _build_coverage(
        domain_results,
        sorted_findings,
        frontier=frontier,
        audit_status=overall_status,
        blocked_reason=blocked_reason,
    )

    # ==============================================================
    # STEP 15: Proactive recommendations & Remediation themes
    # ==============================================================
    proactive_strings = _build_proactive_strings(domain_results)
    remediation_themes = _build_remediation_themes(sorted_findings)

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_url": target_url,
        "site": target_url,
        "audit_status": overall_status,
        "audit_status_message": status_msg,
        "pages_audited": (
            (domain_results.get("crawl-render-access") or {}).get("pages_analyzed")
            or len(frontier)
        ),
        "audit_duration_seconds": max(0.0, round(elapsed, 2)),
        "summary": summary,
        "findings": sorted_findings,
        "proactive_recommendations": proactive_strings,
        "remediation_themes": remediation_themes,
        "coverage": coverage,
    }
    if blocked_reason is not None:
        report["blocked_reason"] = blocked_reason

    # Add optional rendered metrics if available from crawl_result
    crawl_res = domain_results.get("crawl-render-access") or {}
    if crawl_res.get("network_requests") is not None:
        report["network_requests"] = crawl_res["network_requests"]
    if crawl_res.get("performance_metrics") is not None:
        report["performance_metrics"] = crawl_res["performance_metrics"]
    if crawl_res.get("rendered_word_count") is not None:
        report["rendered_word_count"] = crawl_res["rendered_word_count"]
    if crawl_res.get("static_word_count") is not None:
        report["static_word_count"] = crawl_res["static_word_count"]
    if crawl_res.get("csr_blanking_ratio") is not None:
        report["csr_blanking_ratio"] = crawl_res["csr_blanking_ratio"]

    # ==============================================================
    # STEP 16: Schema validation & Repair
    # ==============================================================
    valid, validation_errors = validate_report(report)
    if not valid:
        logger.warning("Report schema validation failed: %s", validation_errors)
        # Attempt repair: guarantee non-negative duration
        dur = report.get("audit_duration_seconds")
        if not isinstance(dur, (int, float)) or dur < 0:
            report["audit_duration_seconds"] = max(0.0, round(time.monotonic() - t_start, 2))
        # Ensure all findings have required fields
        for f in report["findings"]:
            if "evidence" not in f or not f["evidence"]:
                f["evidence"] = f"Audited on {target_url}"
            if "suggested_action" not in f or not isinstance(f["suggested_action"], dict):
                f["suggested_action"] = {
                    "summary": "Review and address this finding.",
                    "priority": f.get("severity", "info"),
                }
            if "related_to" not in f or not isinstance(f["related_to"], list):
                f["related_to"] = []
        # Re-validate
        valid, validation_errors = validate_report(report)
        if not valid:
            logger.error("Report still invalid after repair: %s", validation_errors)

    return report


# ===================================================================
# CLI
# ===================================================================

def _cli() -> None:
    """Command-line interface for the audit orchestrator."""
    # Send logging to stderr so stdout is clean JSON
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Brand AI Readiness Audit — orchestrator",
    )
    parser.add_argument("url", help="Target URL to audit")
    parser.add_argument(
        "--max-pages", type=int, default=15,
        help="Maximum pages to crawl (default: 15)",
    )
    parser.add_argument(
        "--render-js", action="store_true", default=False,
        help="Enable Playwright headless JS rendering (default: False)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Path to write JSON report (default: stdout)",
    )
    args = parser.parse_args()

    report = run_audit(
        target_url=args.url,
        max_pages=args.max_pages,
        render_js=args.render_js,
    )

    report_json = json.dumps(report, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_json, encoding="utf-8")
        print(f"Report written to {out_path}", file=sys.stderr)
    else:
        print(report_json)


if __name__ == "__main__":
    _cli()
