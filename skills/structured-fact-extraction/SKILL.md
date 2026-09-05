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

## Checks & Finding IDs

| Finding ID                         | Severity | Trigger Condition                                |
|------------------------------------|----------|--------------------------------------------------|
| `missing-jsonld-organization`      | high     | No Organization schema on homepage               |
| `invalid-jsonld-syntax`            | high     | JSON-LD block fails JSON parse                   |
| `jsonld-missing-required-field`    | medium   | Required schema property absent                  |
| `facts-in-images-only`             | medium   | Key facts found only in image content attributes |
| `canvas-element-detected`          | medium   | `<canvas>` element with no accessible fallback   |
| `pdf-linked-no-text-alternative`   | low      | Linked PDF has no HTML text equivalent           |
| `stale-content-metadata`           | medium   | Page freshness older than stale threshold        |
| `missing-freshness-metadata`       | low      | No `dateModified`, `Last-Modified`, or equivalent|

## References

- `scripts/sfe_audit.py` — Main structured-fact-extraction runner (Step 2).
- [Schema.org](https://schema.org)
- [JSON-LD spec](https://json-ld.org/)
