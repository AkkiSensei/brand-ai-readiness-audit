---
name: audit-orchestrator
version: 1.0.0
description: >
  Entrypoint skill that coordinates end-to-end AI-readiness audits for brand
  websites. Delegates crawl, structured-data, entity, and engagement checks to
  four domain sub-skills; deduplicates findings; injects proactive
  recommendations (PA-001..PA-006); computes a composite score and grade;
  validates the final report against report.schema.json.
entrypoint: true
tags:
  - orchestration
  - coordination
  - validation
  - deduplication
  - scoring
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
  - jsonschema>=4.21.0
  - playwright>=1.43.0
allowed-tools: Read Write
---

# Audit Orchestrator

## Purpose

The **Audit Orchestrator** is the single entrypoint for the `brand-ai-readiness-audit`
marketplace. It accepts a target URL, coordinates the four domain sub-skills in the
correct execution order, merges and deduplicates findings, computes a weighted
composite readiness score with letter grade, injects proactive recommendations, and
produces a final JSON report validated against `references/report.schema.json`.

## Inputs

| Parameter       | Type   | Required | Description                                      |
|-----------------|--------|----------|--------------------------------------------------|
| `target_url`    | string | Yes      | Root URL of the brand website to audit.           |
| `max_pages`     | int    | No       | Maximum pages to crawl (default 15).              |
| `timeout_s`     | int    | No       | Overall execution budget in seconds (default 240).|

## CLI Usage

```bash
# Print JSON report to stdout
python aggregate.py https://example.com

# Limit crawl scope
python aggregate.py https://example.com --max-pages 10

# Write report to file
python aggregate.py https://example.com --output report.json

# Combined
python aggregate.py https://example.com --max-pages 10 --output report.json
```

**stdout** contains only valid JSON. Diagnostics go to stderr.

## Execution Lifecycle

```
target_url
    |
    v
HttpClient (rate-limited, robots-compliant)
    |
    v
crawl_audit.run_audit(target_url, client, max_pages=N)
    |
    +-- crawl_frontier (list[str])
    +-- page_results (dict[str, PageResult])
    |
    v
Site-wide robots block detection (CR-001 critical)
    |
    +-- If blocked: skip downstream, emit graceful report
    |
    v
sfe_audit.run_audit(target_url, client, crawl_frontier=..., page_results=...)
tec_audit.run_audit(target_url, client, crawl_frontier=..., page_results=...)
er_audit.run_audit(target_url, client, crawl_frontier=..., page_results=...)
    |
    v
Merge all domain findings
    |
    v
Deduplicate (by local_id + category + severity + normalised title)
    |
    v
Sort by severity: critical > high > medium > low > info
    |
    v
Assign sequential IDs: F-001, F-002, ..., F-NNN
    |
    v
Resolve related_to cross-references to final IDs
    |
    v
Proactive recommendations (PA-001..PA-006)
  PA-001: llms.txt / llms-full.txt availability
  PA-002: Unified JSON-LD @graph with @id cross-references
  PA-003: Heading fragment IDs for deep linking
  PA-004: Answer-first / inverted pyramid content structure
  PA-005: RSS / Atom feed availability
  PA-006: Explicit AI crawler Allow: in robots.txt
    |
    v
Re-deduplicate + re-sort + re-assign IDs (F-001..F-NNN)
    |
    v
Composite readiness score (0-100)
  - Domain weights from thresholds.json
  - Severity penalty deductions per finding
    |
    v
Letter grade: A (>=85), B (>=70), C (>=55), D (>=40), F (<40)
    |
    v
Summary counts + coverage metadata
    |
    v
Schema validation against report.schema.json
    |
    v
Final JSON report
```

## Output

A JSON document conforming to `references/report.schema.json` containing:

- `schema_version` — Schema version string (e.g. "1.0.0").
- `generated_at` — ISO-8601 UTC timestamp.
- `target_url` — Audited root URL.
- `pages_audited` — Total pages analysed across all domains.
- `audit_duration_seconds` — Wall-clock execution time.
- `summary` — Severity counts, composite score, and letter grade.
- `findings` — Deduplicated, severity-sorted findings with sequential IDs (`F-001`..`F-NNN`), category (`discoverability`, `engagement`, `proactive`), evidence string/object, structured `suggested_action` (`{summary, priority}`), and `related_to` cross-references.
- `proactive_recommendations` — Strategic advice strings from domain runners.
- `coverage` — Per-domain pages_checked, checks_run, and error counts.

## Scripts

| File                     | Purpose                                                  |
|--------------------------|----------------------------------------------------------|
| `scripts/aggregate.py`   | Main orchestrator and CLI entrypoint.                    |
| `scripts/proactive_engine.py` | PA-001..PA-006 proactive recommendation generator.  |
| `scripts/schema_validate.py`  | Report schema validation (jsonschema + fallback).   |

## References

- `references/report.schema.json` — JSON Schema for the output report.
- `references/thresholds.json` — Centralised heuristic constants and scoring weights.
