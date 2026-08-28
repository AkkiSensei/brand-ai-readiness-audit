---
name: audit-orchestrator
version: 1.0.0
description: >
  Entrypoint skill that coordinates end-to-end AI-readiness audits for brand
  websites. Delegates crawl, structured-data, entity, and engagement checks to
  four domain sub-skills; deduplicates findings; injects proactive
  recommendations; computes an overall score; and validates the final report
  against report.schema.json.
entrypoint: true
tags:
  - orchestration
  - coordination
  - validation
  - deduplication
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
  - jsonschema>=4.21.0
  - playwright>=1.43.0
---

# Audit Orchestrator

## Purpose

The **Audit Orchestrator** is the single entrypoint for the `brand-ai-readiness-audit`
marketplace. It accepts a target URL, coordinates the four domain sub-skills in the
correct execution order, aggregates their findings, deduplicates overlapping issues,
computes a weighted overall score, injects proactive recommendations, and produces a
final JSON report that is validated against `references/report.schema.json`.

## Inputs

| Parameter       | Type   | Required | Description                                      |
|-----------------|--------|----------|--------------------------------------------------|
| `target_url`    | string | Yes      | Root URL of the brand website to audit.          |
| `max_pages`     | int    | No       | Override for maximum pages to crawl (default 15).|
| `use_playwright`| bool   | No       | Enable Playwright rendering (default false).     |
| `output_file`   | string | No       | Path to write the JSON report (stdout if omitted).|

## Outputs

A JSON document conforming to `references/report.schema.json` containing:
- `summary` — severity counts and composite score.
- `findings` — deduplicated, severity-sorted list of all issues.
- `proactive_recommendations` — strategic advice not tied to specific findings.
- `coverage` — per-skill page and check counts.

## Execution Flow

```
audit-orchestrator
       │
       ├─ crawl-render-access       (robots.txt, SSR/CSR, status codes, sitemaps)
       ├─ structured-fact-extraction (JSON-LD, image facts, freshness)
       ├─ trust-entity-corroboration (sameAs, NAP, disambiguation)
       └─ engagement-retention      (above-fold, interstitials, viewport stability)
       │
       └─ deduplicate → score → recommend → validate → emit report
```

## References

- `references/report.schema.json` — JSON Schema for the output report.
- `references/thresholds.json`    — Centralised heuristic constants.
- `scripts/`                      — Orchestration and scoring scripts.
