# Brand AI-Readiness Audit Marketplace

> **Autonomous, deterministic evaluation marketplace for benchmarking public brand websites against AI search, generative-answer, and citation engine ingest pipelines.**  
> Built for the **Adobe University Hackathon 2026 — Round 3**.  
> Designated Entrypoint: `skills/audit-orchestrator/scripts/aggregate.py`

---

## What the Project Is & Problem It Solves

Traditional search engines rank keyword-matched URLs for humans to click. Modern generative AI engines (**ChatGPT Search**, **Claude**, **Perplexity**, **Google Gemini**, **Microsoft Copilot**) operate differently: they ingest content into context chunks, extract factual assertions into knowledge graphs, verify claims across third-party sources, and synthesize direct conversational answers with citations.

When a brand website blocks AI user-agents, serves blank client-rendered JavaScript shells, traps pricing or specs in raster images, or lacks Schema.org entity linkages, AI engines cannot ingest the site. This leads to **omission from AI search**, **entity confusion**, or **hallucinated brand facts**.

This marketplace autonomously inspects any public brand website, evaluates **30 defect heuristics** across five skill domains, and produces an objective, evidence-backed, schema-validated JSON audit report with actionable remediation guidance and **7 proactive AI-readiness recommendations**.

---

## Core Value Proposition

| Dimension | Typical Approach | This Marketplace |
|---|---|---|
| **Determinism** | Non-deterministic LLM grading | **100% deterministic** rule-based analysis; identical inputs → identical reports |
| **Model footprint** | Gigabytes of weights or costly API keys | **Zero model weights**; pure Python rules |
| **Execution speed** | 60–180 s due to API latency | **Sub-15 s** typical; global 240 s hard deadline |
| **Security posture** | Blind HTTP fetchers | **SSRF-hardened** + socket-level DNS pinning |
| **Link sampling** | Random or alphabetically biased | **SHA-256 deterministic** uniform sampling |

---

## The Five Skills & How They Compose

```
                         [Target URL]
                               │
                               ▼
                   ┌───────────────────────┐
                   │      HttpClient       │  SSRF validation, socket DNS pinning
                   └───────────┬───────────┘
                               │
                               ▼
                   ┌───────────────────────┐
                   │  crawl-render-access  │  CR-001..CR-008: robots, WAF, SSR/CSR, sitemaps
                   └───────────┬───────────┘
                               │
               Frontier URLs + Pre-Parsed DOMs
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
 ┌────────────────────┐ ┌─────────────────┐ ┌──────────────────────┐
 │structured-fact-    │ │trust-entity-    │ │engagement-retention  │
 │extraction          │ │corroboration    │ │ER-001..ER-008        │
 │SF-001..SF-008      │ │TC-001..TC-006   │ │                      │
 └─────────┬──────────┘ └──────┬──────────┘ └──────────┬───────────┘
           └───────────────────┼───────────────────────┘
                               │
                               ▼
                   ┌───────────────────────┐
                   │   audit-orchestrator  │  aggregate.py (Designated Entrypoint)
                   │  • Finding dedup      │
                   │  • Global ID assign   │  F-001..F-NNN
                   │  • Proactive engine   │  PA-001..PA-006, PA-CANONICAL
                   │  • Remediation themes │
                   │  • Schema validation  │  JSON Schema Draft-07
                   └───────────┬───────────┘
                               │
                        [Final JSON Report]
```

### Skill Responsibilities

1. **`audit-orchestrator`** — Designated entrypoint (`aggregate.py`). Coordinates the causal pipeline, dispatches sub-skills, deduplicates findings, assigns sequential global IDs (`F-001..F-NNN`), groups remediation themes, runs the proactive recommendation engine, and validates the output against `report.schema.json`.

2. **`crawl-render-access`** (`CR-001`..`CR-008`) — Audits `robots.txt` for AI crawler policies, detects WAF/bot blocking, measures SSR-vs-CSR text-blanking ratios, validates HTTP status/redirect chains, checks XML sitemap presence and `<lastmod>` freshness, and flags conflicting `noindex` directives.

3. **`structured-fact-extraction`** (`SF-001`..`SF-008`) — Validates Schema.org JSON-LD syntax for `Organization`, `Product`, and `FAQPage` types; detects brand facts trapped in `<img>` without alt text, uncaptioned `<canvas>`/`<video>`, and orphan PDFs; checks content temporal freshness.

4. **`trust-entity-corroboration`** (`TC-001`..`TC-006`) — Audits authoritative `sameAs` entity links (Wikidata, Wikipedia, LinkedIn), verifies multi-page Name/Address/Phone (NAP) consistency, and validates outbound accreditation links via safe HTTP HEAD requests.

5. **`engagement-retention`** (`ER-001`..`ER-008`) — Audits heading hierarchy (`<h1>` presence and strict ordering), flags intrusive modal overlays, tests internal link health via SHA-256-sampled URLs, verifies CTA visibility, checks mobile viewport declarations, and flags unsized media assets (CLS risk).

---

## What Output It Produces

Every finding conforms to a unified, schema-validated contract:

```json
{
  "id": "F-001",
  "local_id": "CR-001",
  "title": "AI crawler blocked by robots.txt",
  "severity": "critical",
  "category": "discoverability",
  "evidence": "robots.txt explicitly disallows GPTBot via directive: Disallow: /",
  "location": "https://example.com/robots.txt",
  "why_it_matters": "Blocking AI crawlers prevents generative engines from indexing or citing brand content.",
  "remediation_theme": "Crawler Access Governance",
  "suggested_action": {
    "summary": "Update robots.txt to allow verified AI crawlers access to public content.",
    "priority": "critical",
    "asset_type": "robots.txt",
    "location": "/robots.txt",
    "mechanism": "AI search engines respect RFC 9309 robots directives."
  },
  "related_to": []
}
```

Findings are clustered into **Remediation Themes** (e.g., *Crawler Access Governance*, *Render Architecture*, *Schema.org Structured Data*, *Entity Authority & Corroboration*), giving engineering teams consolidated priorities instead of fragmented alerts.

### Proactive Recommendations

Beyond defect detection, the engine emits forward-looking proactive signals:
- **`PA-001`**: Deploy `/llms.txt` or `/agents.md` manifests for LLM agents.
- **`PA-002`**: Consolidate JSON-LD into a unified `@graph` with `@id` cross-references.
- **`PA-003`**: Add `id` slug attributes to headings for citation deep-linking.
- **`PA-004`**: Structure article intros with answer-first (inverted pyramid) summaries.
- **`PA-005`**: Expose RSS/Atom feeds for real-time content freshness tracking.
- **`PA-006`**: Declare explicit `Allow:` directives for verified AI crawlers.
- **`PA-CANONICAL`**: Declare `<link rel="canonical">` tags to prevent index dilution.

---

## How to Run

### Prerequisites
```bash
pip install -r requirements.txt

# Optional: install Playwright for headless JS rendering
playwright install chromium
```

### CLI
```bash
# Standard audit — emits schema-validated JSON to stdout
python skills/audit-orchestrator/scripts/aggregate.py https://example.com

# Save report to file
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --output report.json

# Limit crawl depth
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --max-pages 10

# Enable optional Playwright headless DOM rendering
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --render-js
```

### Tests
```bash
# Run all 274 automated regression tests
python -m pytest tests/

# Multi-domain dry-run smoke test
python tests/dry_run_test.py

# Comprehensive stress suite (security, resource, degradation, determinism)
python tests/run_validation_stress.py
```

---

## Major Security & Safety Guarantees

- **Strictly read-only**: Zero `POST`/`PUT`/`DELETE` requests; never submits forms, never authenticates, never alters state.
- **SSRF-hardened**: Pre-flight IP validation blocks loopback (`127.0.0.0/8`, `::1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and cloud metadata endpoints (`169.254.169.254`).
- **Socket-level DNS pinning**: `DestinationPinningManager` resolves DNS once, validates the IP, then binds the socket directly to that IP — neutralizing TOCTOU DNS-rebinding attacks.
- **RFC 9309 compliance**: Honors `robots.txt` directives; fails closed on 5xx fetch errors.
- **Monotonic deadline**: Global `AuditDeadline` (default 240 s) ensures bounded execution; never hangs indefinitely.
- **Scheme allowlist**: Only `http://` and `https://` are accepted; `file://`, `gopher://`, `dict://` are rejected before any connection attempt.

---

## Architectural Documentation

For full technical context — problem framing, pipeline diagrams, heuristic catalog, evidence model, remediation model, proactive recommendation model, security boundaries, generalization strategy, limitations, and the Adobe Round 3 compliance matrix — see [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

---

## License

MIT License. Developed for the **Adobe University Hackathon 2026 — Round 3**.
