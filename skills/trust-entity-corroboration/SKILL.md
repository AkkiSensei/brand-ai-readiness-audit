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
allowed-tools:
  - Bash
  - Read
  - Write
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

| Finding ID                         | Severity | Trigger Condition                                |
|------------------------------------|----------|--------------------------------------------------|
| `no-sameas-links`                  | high     | No `sameAs` property in any JSON-LD block        |
| `sameas-unresolvable`              | medium   | A `sameAs` URL returns non-2xx status            |
| `nap-inconsistent-name`            | high     | Brand name varies across pages beyond threshold  |
| `nap-inconsistent-address`         | medium   | Address format inconsistent across pages         |
| `nap-inconsistent-phone`           | medium   | Phone number format inconsistent across pages    |
| `missing-legal-name`              | low      | `legalName` absent from Organization schema      |
| `missing-alternate-name`          | low      | Multiple name variants without `alternateName`   |
| `brand-name-too-many-variants`    | medium   | Brand name appears in >N distinct capitalisations|

## References

- `scripts/tec_audit.py` — Trust & entity corroboration runner (Step 2).
- [Schema.org sameAs](https://schema.org/sameAs)
- [Google Entity disambiguation](https://developers.google.com/search/docs/appearance/structured-data/organization)
