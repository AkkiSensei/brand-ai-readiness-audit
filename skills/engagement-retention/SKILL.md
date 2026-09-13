---
name: engagement-retention
version: 1.0.0
description: >
  Domain sub-skill that audits above-the-fold navigation and H1 orientation,
  detects post-load interstitials and modals that degrade AI-readable content,
  and measures viewport layout stability (CLS proxy).
entrypoint: false
tags:
  - UX
  - engagement
  - interstitial
  - CLS
  - above-the-fold
  - navigation
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
  - playwright>=1.43.0
allowed-tools: Read
---

# Engagement & Retention

## Purpose

AI engines consider user-experience signals when evaluating content quality.
This skill audits three pillars:

1. **Above-the-Fold Orientation** — Verify that the primary `<h1>`, primary
   navigation, and a clear brand signal appear within the initial viewport
   without scrolling, using both static HTML analysis and optional Playwright.
2. **Post-Load Interstitial Detection** — Detect full-page overlays, cookie
   consent banners, newsletter modals, and GDPR notices that cover a
   significant portion of the viewport after page load, potentially obscuring
   main content from crawlers.
3. **Viewport Stability** — Heuristically proxy Cumulative Layout Shift (CLS)
   by detecting dynamically injected elements with absolute/fixed positioning
   that appear after initial render.

## Inputs

| Parameter | Type | Description |
|-----------|------|-------------|
| `target_url` | `str` | Root URL of the brand website under audit |
| `http_client` | `HttpClient` | Shared SSRF-safe HTTP client from crawl-render-access |
| `crawl_frontier` | `list[str]` | Ordered list of discovered page URLs from crawl-render-access |
| `page_results` | `dict[str, PageResult]` | Pre-fetched parsed DOM results keyed by URL |
| `timeout_s` | `int` | Global audit wall-clock budget in seconds (default 240) |
| `t_start` | `float` | `time.monotonic()` timestamp of audit start |
| `deadline` | `AuditDeadline` | Monotonic deadline object for bounded sub-skill execution |

## Output

Returns a `dict` with:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `str` | `"engagement-retention"` |
| `pages_analyzed` | `int` | Number of pages inspected by this skill |
| `pages_discovered` | `int` | Number of pages in the crawl frontier |
| `errors` | `list[str]` | Any non-fatal errors encountered |
| `findings` | `list[dict]` | Domain findings (ER-001..ER-008); each has `local_id`, `title`, `severity`, `category`, `evidence`, `suggested_action`, `related_to` |
| `proactive_candidates` | `list` | Structural observations passed to the proactive recommendation engine |

## Checks & Finding IDs

| Check ID | Finding Title | Severity | Trigger Condition |
|----------|---------------|----------|-------------------|
| `ER-001` | Pages missing visible H1 heading | high | Zero visible `<h1>` element above the fold |
| `ER-001` | Pages missing primary navigation | medium | Lack of `<nav>` or navigation container with >=3 links |
| `ER-001` | Multiple H1 tags on a single page | low | More than one `<h1>` heading found on a single page |
| `ER-002` | Deep pages missing breadcrumb navigation | medium | Page at depth >= 2 lacks BreadcrumbList schema or breadcrumb `<nav>` |
| `ER-003` | Full-page interstitial overlay detected | high | Fixed/absolute overlay with high z-index obscuring content |
| `ER-003` | Cookie consent banner detected on pages | medium | Intrusive full-screen blocking consent overlay |
| `ER-003` | Newsletter subscription modal detected | low | Newsletter / signup popup detected |
| `ER-004` | High broken internal link ratio | info | Broken internal link ratio > 5% |
| `ER-004` | Broken internal links detected | medium | Sampled internal links return 4xx/5xx |
| `ER-005` | Product/landing pages missing clear CTA | medium | Conversion page lacks recognizable call-to-action button |
| `ER-006` | Pages missing viewport meta tag | high | HTML page lacks `<meta name="viewport">` |
| `ER-007` | Viewport meta restricts user zoom | medium | Viewport specifies `user-scalable=no` or `maximum-scale=1` |
| `ER-008` | No site search functionality detected on large site | low | Site with >30 crawled pages lacks search input or SearchAction schema |

## References

- `scripts/er_audit.py` — Engagement & retention runner (Step 2).
- `scripts/http_client.py` — Shared HTTP & Playwright client.
- [Core Web Vitals — CLS](https://web.dev/cls/)
- [Google interstitial guidelines](https://developers.google.com/search/blog/2016/08/helping-users-easily-access-content-on)
