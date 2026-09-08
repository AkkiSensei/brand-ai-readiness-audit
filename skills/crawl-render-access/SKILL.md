---
name: crawl-render-access
version: 1.0.0
description: >
  Domain sub-skill that audits a brand website for AI-crawler accessibility,
  covering robots.txt AI bot policies, SSR vs CSR text blanking ratios, HTTP
  status codes across internal links, XML sitemap completeness and freshness,
  and multilingual hreflang tag detection.
entrypoint: false
tags:
  - crawlability
  - robots.txt
  - SSR
  - CSR
  - sitemap
  - http
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
allowed-tools: Read
---

# Crawl & Render Access

## Purpose

Determines whether AI search engines can reliably discover, access, and render
the brand's content. Covers four audit pillars:

1. **robots.txt AI Bot Policies** — Identify which known AI crawlers are
   explicitly disallowed and whether wildcard rules inadvertently block them.
2. **SSR vs CSR Text Blanking** — Compare raw HTML text ratio against
   post-render DOM text ratio to detect content that is invisible to
   non-JavaScript crawlers.
3. **HTTP Status Codes** — Crawl internal links to find broken pages
   (4xx/5xx), excessive redirect chains, and non-canonical URL patterns.
4. **Sitemap Completeness** — Validate XML sitemap presence, structure,
   `<lastmod>` freshness, and coverage relative to crawled links.

## Inputs

Provided by the audit-orchestrator:

| Parameter       | Type        | Description                              |
|-----------------|-------------|------------------------------------------|
| `target_url`    | string      | Root URL of the brand website.           |
| `http_client`   | HttpClient  | Shared, rate-limited HTTP client.        |
| `playwright`    | PlaywrightRenderer | Optional renderer for CSR detection. |
| `max_pages`     | int         | Max pages to crawl.                      |

## Outputs

A list of `Finding` objects (conforming to the report schema) plus
a `SkillCoverage` dict.

## Checks & Finding IDs

| Check ID | Finding Title | Severity | Trigger Condition |
|----------|---------------|----------|-------------------|
| `CR-001` | AI crawlers explicitly blocked by robots.txt | critical | Known AI crawler (GPTBot, etc.) blocked in robots.txt |
| `CR-002` | Pages returning non-OK HTTP status codes | high | Internal page returns 4xx, 5xx, or network error |
| `CR-002` | Excessive redirect chains detected | low | Redirect chain length > 2 hops or redirect loop |
| `CR-003` | Severe CSR text blanking — content invisible to non-JS crawlers | critical | Raw HTML text ratio < 0.15 or empty SPA shell |
| `CR-004` | Moderate CSR text blanking — reduced content in raw HTML | high | Text ratio between 0.15 and 0.30 |
| `CR-005` | Paywall or login overlay detected blocking content | high | Overlay / paywall obscures main body content |
| `CR-006` | No XML sitemap found | high | No sitemap at standard locations or in robots.txt |
| `CR-006` | Sitemap not declared in robots.txt | medium | Sitemap exists but not referenced in robots.txt |
| `CR-007` | Sitemap entries missing `<lastmod>` dates | medium | >30% of sitemap URLs lack `<lastmod>` |
| `CR-007` | Sitemap contains stale `<lastmod>` dates | low | `<lastmod>` older than freshness threshold |
| `CR-007` | Excessive Crawl-delay in robots.txt | low | Crawl-delay > 10 seconds |
| `CR-008` | Public pages marked with noindex directive | high | Meta robots or X-Robots-Tag specifies noindex |

## References

- `scripts/http_client.py`         — Shared HTTP & Playwright client.
- `scripts/crawl_audit.py`         — Main crawl audit runner (Step 2).
- `references/`                    — Mirrors thresholds.json symlink.
- [Google robots.txt spec](https://developers.google.com/search/docs/crawling-indexing/robots/intro)
- [Sitemaps protocol](https://www.sitemaps.org/protocol.html)
