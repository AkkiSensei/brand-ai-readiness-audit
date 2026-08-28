---
name: crawl-render-access
version: 1.0.0
description: >
  Domain sub-skill that audits a brand website for AI-crawler accessibility,
  covering robots.txt AI bot policies, SSR vs CSR text blanking ratios, HTTP
  status codes across internal links, and XML sitemap completeness and freshness.
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

| Finding ID                        | Severity | Trigger Condition                                |
|-----------------------------------|----------|--------------------------------------------------|
| `robots-blocks-ai-crawler`        | critical | Known AI crawler blocked in robots.txt           |
| `robots-wildcard-blocks-all`      | high     | `User-agent: *` with broad Disallow rules        |
| `no-sitemap-declared`             | high     | No Sitemap directive in robots.txt or standard paths |
| `sitemap-missing-lastmod`         | medium   | >30% of sitemap URLs lack `<lastmod>`            |
| `sitemap-stale-lastmod`           | medium   | `<lastmod>` older than freshness threshold       |
| `csr-text-blanking-severe`        | high     | Text ratio < text_blanking_ratio_threshold       |
| `csr-text-blanking-moderate`      | medium   | Text ratio between threshold and warning value   |
| `broken-internal-link`            | medium   | Internal URL returns 4xx or 5xx                  |
| `excessive-redirect-chain`        | low      | Redirect chain length > 2                        |
| `http-not-redirected-to-https`    | high     | http:// root does not redirect to https://       |

## References

- `scripts/http_client.py`         — Shared HTTP & Playwright client.
- `scripts/crawl_audit.py`         — Main crawl audit runner (Step 2).
- `references/`                    — Mirrors thresholds.json symlink.
- [Google robots.txt spec](https://developers.google.com/search/docs/crawling-indexing/robots/intro)
- [Sitemaps protocol](https://www.sitemaps.org/protocol.html)
