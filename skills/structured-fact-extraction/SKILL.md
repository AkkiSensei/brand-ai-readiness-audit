---
name: structured-fact-extraction
version: 1.0.0
description: >
  Domain sub-skill that validates Schema.org JSON-LD structured data markup,
  detects factual content trapped inside images, canvas elements, or PDFs
  that AI crawlers cannot read, and inspects document freshness metadata.
entrypoint: false
tags:
  - schema.org
  - json-ld
  - structured-data
  - metadata
  - accessibility
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
allowed-tools: Read
---

# Structured Fact Extraction

## Purpose

Ensures that factual brand content is machine-readable by AI engines, covering:

1. **Schema.org JSON-LD Validation** — Parse and validate JSON-LD blocks for
   required properties, type correctness, and common schema errors for
   Organization, Product, FAQPage, BreadcrumbList, and Article types.
2. **Image/Canvas/PDF Fact Detection** — Heuristically detect key data
   (phone numbers, addresses, prices, dates) that exists only inside image
   `alt`-text, `<canvas>` elements, or linked PDFs.
3. **Freshness Metadata** — Inspect `<meta>` tags, `<time>` elements, HTTP
   `Last-Modified` headers, and JSON-LD `dateModified` fields for content age.

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
| `domain` | `str` | `"structured-fact-extraction"` |
| `pages_analyzed` | `int` | Number of pages inspected by this skill |
| `pages_discovered` | `int` | Number of pages in the crawl frontier |
| `errors` | `list[str]` | Any non-fatal errors encountered |
| `findings` | `list[dict]` | Domain findings (SF-001..SF-008); each has `local_id`, `title`, `severity`, `category`, `evidence`, `suggested_action`, `related_to` |
| `proactive_candidates` | `list` | Structural observations passed to the proactive recommendation engine |

## Checks & Finding IDs

| Check ID | Finding Title | Severity | Trigger Condition |
|----------|---------------|----------|-------------------|
| `SF-001` | No JSON-LD structured data found on any page | high | Zero valid JSON-LD script tags found on crawled pages |
| `SF-001` | No Organization schema on homepage | high | Homepage lacks Organization or LocalBusiness schema |
| `SF-001` | Organization schema is nested rather than top-level | low | Organization entity exists only as sub-property |
| `SF-002` | Invalid JSON-LD syntax detected | high | JSON-LD block fails JSON parser |
| `SF-002` | JSON-LD schemas missing recommended properties | medium | Missing recommended schema fields (logo, contactPoint, etc.) |
| `SF-003` | Key facts trapped in images without text alternatives | critical | Important pricing, contact, or specification facts only in images |
| `SF-004` | Canvas elements without accessible fallback content | medium | `<canvas>` elements lack fallback DOM text |
| `SF-004` | Video elements without caption tracks | medium | `<video>` elements lack `<track kind="captions">` |
| `SF-005` | PDFs linked without HTML text alternative content | high | Linked PDF documents lack HTML summary or transcript |
| `SF-006` | Q&A content detected without FAQPage schema | medium | FAQ/Q&A patterns detected in HTML without FAQPage JSON-LD |
| `SF-007` | Pages with stale content metadata | medium | Content `dateModified` older than stale threshold (365 days) |
| `SF-007` | Pages missing freshness metadata | low | No `dateModified`, `Last-Modified`, or freshness date signals |
| `SF-008` | Duplicate or generic page titles detected | medium | Identical or boilerplate `<title>` across multiple pages |
| `SF-008` | Duplicate meta descriptions detected | medium | Identical meta descriptions across multiple distinct URLs |

## References

- `scripts/sfe_audit.py` — Main structured-fact-extraction runner (Step 2).
- [Schema.org](https://schema.org)
- [JSON-LD spec](https://json-ld.org/)
