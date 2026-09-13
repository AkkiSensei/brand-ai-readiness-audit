---
name: trust-entity-corroboration
version: 1.0.0
description: >
  Domain sub-skill that validates the brand's knowledge-graph entity linkage
  (sameAs), NAP (Name/Address/Phone) consistency across pages, and applies
  brand disambiguation heuristics to detect conflicting brand signals.
entrypoint: false
tags:
  - entity
  - knowledge-graph
  - NAP
  - sameAs
  - trust
  - disambiguation
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
allowed-tools: Read
---

# Trust & Entity Corroboration

## Purpose

AI engines rank brands higher when their identity is unambiguously corroborated
across multiple authoritative sources. This skill audits three pillars:

1. **sameAs Entity Graph Linkage** — Extract `sameAs` URLs from JSON-LD and
   verify they resolve to live, authoritative external profiles (Wikipedia,
   Wikidata, LinkedIn, Crunchbase, social media).
2. **NAP Consistency** — Extract Name, Address, and Phone Number across all
   crawled pages and structured data, compute cross-page consistency scores,
   and flag contradictions.
3. **Brand Disambiguation Heuristics** — Detect inconsistent brand name
   capitalisation, multiple operating names without `alternateName` markup,
   and absent `legalName` fields.

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
| `domain` | `str` | `"trust-entity-corroboration"` |
| `pages_analyzed` | `int` | Number of pages inspected by this skill |
| `pages_discovered` | `int` | Number of pages in the crawl frontier |
| `errors` | `list[str]` | Any non-fatal errors encountered |
| `findings` | `list[dict]` | Domain findings (TC-001..TC-006); each has `local_id`, `title`, `severity`, `category`, `evidence`, `suggested_action`, `related_to` |
| `proactive_candidates` | `list` | Structural observations passed to the proactive recommendation engine |

## Checks & Finding IDs

| Check ID | Finding Title | Severity | Trigger Condition |
|----------|---------------|----------|-------------------|
| `TC-001` | No sameAs links in Organization schema | high | Organization schema lacks `sameAs` array |
| `TC-001` | Invalid sameAs URLs in Organization schema | medium | Malformed or non-absolute sameAs URL strings |
| `TC-001` | Insufficient sameAs external links | medium | Fewer than required authoritative sameAs links |
| `TC-002` | Inconsistent brand name across pages | high | Brand name varies across pages beyond threshold |
| `TC-002` | Inconsistent phone numbers across pages | medium | Multiple conflicting phone numbers detected |
| `TC-002` | Inconsistent address information across pages | medium | Address discrepancies across crawled pages |
| `TC-003` | Claimed external partner or accreditation links are broken | high | Outbound verification links for claimed accreditation, certification, or partnership return broken 4xx/5xx HTTP errors |
| `TC-004` | Brand name is ambiguous without disambiguation | critical | Brand entity lacks external knowledge graph linkage (Wikidata/Wikipedia) and structural disambiguation (legalName, address, foundingDate, or description) |
| `TC-004` | Brand name appears in too many capitalisation variants | medium | Brand name found in >2 distinct capitalization styles |
| `TC-005` | Authority or partnership claims lack external verification links | medium | Site presents authority or partnership claims but provides zero verifiable external outbound links |
| `TC-006` | Organization schema missing disambiguation properties | medium | Organization schema lacks `legalName`, `description`, or identifier |
| `TC-006` | No Organization schema found for entity disambiguation | medium | Zero Organization JSON-LD found for brand disambiguation |

## References

- `scripts/tec_audit.py` — Trust & entity corroboration runner (Step 2).
- [Schema.org sameAs](https://schema.org/sameAs)
- [Google Entity disambiguation](https://developers.google.com/search/docs/appearance/structured-data/organization)
