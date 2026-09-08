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

## Checks & Finding IDs

| Check ID | Finding Title | Severity | Trigger Condition |
|----------|---------------|----------|-------------------|
| `TC-001` | No sameAs links in Organization schema | high | Organization schema lacks `sameAs` array |
| `TC-001` | Invalid sameAs URLs in Organization schema | medium | Malformed or non-absolute sameAs URL strings |
| `TC-001` | Insufficient sameAs external links | medium | Fewer than required authoritative sameAs links |
| `TC-002` | Inconsistent brand name across pages | high | Brand name varies across pages beyond threshold |
| `TC-002` | Inconsistent phone numbers across pages | medium | Multiple conflicting phone numbers detected |
| `TC-002` | Inconsistent address information across pages | medium | Address discrepancies across crawled pages |
| `TC-003` | Third-party entity claims could not be corroborated | high | On-site entity claims (e.g. Wikipedia, Wikidata, LinkedIn) failed external verification |
| `TC-004` | Brand name is ambiguous without disambiguation | critical | Common dictionary word brand without legalName or disambiguatingDescription |
| `TC-004` | Brand name appears in too many capitalisation variants | medium | Brand name found in >2 distinct capitalization styles |
| `TC-005` | No external entity claims could be verified | medium | None of the claimed entity links could be independently verified |
| `TC-006` | Organization schema missing disambiguation properties | medium | Organization schema lacks `legalName`, `description`, or identifier |
| `TC-006` | No Organization schema found for entity disambiguation | medium | Zero Organization JSON-LD found for brand disambiguation |

## References

- `scripts/tec_audit.py` — Trust & entity corroboration runner (Step 2).
- [Schema.org sameAs](https://schema.org/sameAs)
- [Google Entity disambiguation](https://developers.google.com/search/docs/appearance/structured-data/organization)
