# Project Development Context & Historical Architecture Log

> **Purpose**: This document is the engineering history log for this repository. It records *why* specific design choices, hardening decisions, and bug fixes were made, grounded in commit history (`git log`) and real-site empirical testing. It is intentionally distinct from `PROJECT_CONTEXT.md`, which is the forward-facing technical specification. Read this document when debugging unexpected behavior, tracing a design decision to its origin, or understanding the evolution of edge-case handling.

---

## 1. Problem Statement & Hackathon Context

This project was built for the **Adobe University Hackathon 2026 — Round 3**.

### The Core Mandate
1. **Agent Skill Marketplace Architecture**: Decompose website evaluation into an autonomous, modular collection of interoperable skills adhering to the `agentskills.io` standard (`marketplace.json`, distinct `skills/*` folders with `SKILL.md` instructions).
2. **Dual-Pillar Scope**:
   * **Pillar 1: AI Discoverability**: Ensure autonomous AI fetchers, search crawlers (ChatGPT/SearchGPT, Claude-Web, PerplexityBot, Google Gemini), and knowledge extractors can discover, render, parse, and verify brand content.
   * **Pillar 2: On-Site Engagement & Retention**: Ensure that once users or agents land on the site, content is stable, accessible, unobstructed by aggressive interstitials, and hierarchically navigable.
3. **Strict Machine Usability**: Outputs must be pure, machine-parsable JSON conforming to a strict JSON Schema (`report.schema.json`) with deterministic attribution, clear severity ratings, and concrete remediations.

---

## 2. Initial Architecture Decisions

### 2.1 The 5-Skill Decomposition
Rather than building a monolithic crawler/auditor script, the system was decoupled into 1 entrypoint orchestrator and 4 domain skills matching the causal stages of AI ingestion:

```text
Target URL
   │
   ▼
[crawl-render-access] (CR-001..CR-008)
   │  Transport, HTTP codes, robots.txt, sitemaps, CSR vs SSR text blanking
   │
   ├─► Frontier URLs & Pre-Parsed BeautifulSoup DOMs
   │
   ├────────────────────────┬────────────────────────┐
   ▼                        ▼                        ▼
[structured-fact-       [trust-entity-           [engagement-
 extraction]             corroboration]           retention]
 (SF-001..SF-008)        (TC-001..TC-006)         (ER-001..ER-008)
 Schema.org JSON-LD,     sameAs authority links,  Visible H1, nav,
 trapped facts in imgs,  NAP consistency, brand   overlays, viewports,
 freshness metadata      disambiguation, claims   broken link ratios
   │                        │                        │
   └────────────────────────┼────────────────────────┘
                            │ Raw Domain Findings
                            ▼
                  [audit-orchestrator] (aggregate.py)
                   - Multi-attribute deduplication
                   - Severity sorting (critical -> info)
                   - Sequential ID assignment (F-001..F-NNN)
                   - related_to reference resolution
                   - Proactive recommendation injection (PA-001..PA-006)
                   - JSON schema validation (report.schema.json)
```

### 2.2 Key Architectural Tenets
* **Single Network Pass**: `crawl-render-access` executes network discovery and populates in-memory `PageResult` objects with parsed DOMs (`BeautifulSoup`). Downstream skills analyze these pre-parsed objects in memory—zero redundant network round-trips.
* **Deterministic Rule Execution**: Reject ungrounded LLM prompting in the audit loop. All heuristics evaluate concrete HTTP, HTML, and JSON-LD primitives. Running the audit multiple times against identical content produces deterministic, identical findings.
* **Bounded Operational Footprint**: Enforces strict per-host rate limiting (1.0 req/s), maximum page budget (default 15), maximum response size (5 MB), and global wall-clock timeout budgets (default 240s).

---

## 3. Engineering & Hardening History (Git Evolution)

The codebase evolved through distinct hardening phases, documented in commit history:

### Phase 1: Foundation & Initial Contract (`ca32bec`, `007a193`, `0b3b72e`)
* **Scaffolded Marketplace**: Defined `marketplace.json`, core `HttpClient` with token-bucket `RateLimiter` and `RobotsTxtCache`, and initialized the 5 skills.
* **Built Rule Suite**: Implemented 30 defect checks across the 4 domains and 6 proactive recommendations (`PA-001`..`PA-006`).
* **Created Archetype & Chaos Suites**:
  * `tests/test_archetypes.py`: Local ephemeral HTTP server serving synthetic site archetypes (SPA, E-commerce, Legacy, Blog, Paywall).
  * `tests/test_chaos.py`: Adversarial fixtures (Zero-byte HTML, Garbage DOM / primitive JSON-LD, Infinite redirect loops).

### Phase 2: Structural Integrity & False-Positive Elimination (`73b8fba` through `dfe7988`)
* **Sitemap Cross-Contamination Bug**: In early archetype runs, the mock HTTP server retained cached sitemap state across test cases, causing later archetypes to inherit URLs from earlier fixtures. Resolved by isolating fixture requests and resetting mock server handler state.
* **Pages Audited Aggregation Bug (`a7255c3`)**: `pages_audited` in the summary occasionally mismatched the number of pages analyzed across sub-skills due to crawl frontier filtering. Fixed to consistently report analyzed pages.
* **SF-001 Nested Organization False Positive (`a7255c3`)**: Many enterprise sites nest their `Organization` schema inside a top-level `@graph` or inside `WebSite` / `ItemPage` blocks. The original parser only checked top-level JSON-LD objects, flagging compliant sites as missing Organization schema. SFE was updated to recursively traverse JSON-LD trees and `@graph` arrays.
* **Archetype Realism & CR-003 Drift (`5741e24`, `dfe7988`)**: The initial e-commerce fixture triggered false-positive CSR blanking (`CR-003`) because product description text was too sparse relative to HTML tags. Expanded body text and adjusted text-ratio thresholds (`0.15` severe, `0.30` warning) in `thresholds.json`.

### Phase 3: Contract Harmonization & Claim Semantics (`6e024c9`, `9af10c1`, `5266e04`, `49aba6c`)
* **TC-003 vs TC-005 Semantic Separation (`5266e04`, `f1db612`)**: Previous code conflated `sameAs` URL validity with outbound accreditation claim checking. Rewrote checks so that `TC-003` verifies outbound links adjacent to specific authority claims ("certified by", "partnered with") via rate-limited HEAD requests, while `TC-005` flags claims lacking any outbound verification links. Added false-positive regex suppression (`_FP_RE`) for generic commercial phrases ("partner with us", "certification course").
* **Schema Contract Gap (`49aba6c`)**: Downstream consumers expected `site` and `audited_at` fields in addition to `target_url` and `generated_at`. Added both fields as first-class schema citizens and proved determinism (identical SHA-256 across runs).
* **Finding Confidence Metric (`03c02d2`, `b81a9a3`)**: For multi-page checks, added an optional `confidence` field (`0.0` to `1.0`), computed as `pages_affected / pages_checked`.

### Phase 4: Architectural Hardening & Adversarial Resilience (`6b482b7`, `9355eb3`, `47fe088`)
Comprehensive stress testing across challenging web architectures (Single-Page Apps, Quick-commerce, FinTech/Banking, Healthcare, SaaS, EdTech) surfaced critical edge-case failure modes:
1. **SSRF Sinkhole Mitigation**:
   * *Challenge*: Hostnames resolving via DNS to private or loopback ranges (e.g., `127.0.0.1` DNS sinkholes).
   * *Hardening*: `HttpClient` and `aggregate.py` implemented fast pre-flight SSRF IP validation (`is_ssrf_disallowed`), immediately halting with `audit_status="blocked"` and `blocked_reason="ssrf_disallowed"`, preventing socket connections to private/loopback subnets.
2. **Active WAF & Bot Challenges**:
   * *Challenge*: Edge gateways returning 403/429/503 responses with challenge payloads (`cf-chl-bypass`, `challenge-platform`, `errors.edgesuite.net`).
   * *Hardening*: Added `_is_waf_challenge` in `crawl_audit.py` to recognize bot-defense headers and HTML signatures. If all pages hit WAF challenges, the orchestrator sets `audit_status="blocked"` and `blocked_reason="waf_bot_challenge"`.
3. **Geolocation / Pincode Gates**:
   * *Challenge*: Delivery and regional portals rendering full-viewport location pickers or modal dialogs that block AI crawlers from seeing catalog items.
   * *Hardening*: Added `CR-005` location-gate heuristics (`_GEO_PATTERNS`, `LocationBar__Container`, `pincode-picker`).
4. **Socket Timeout & Compounding Retries**:
   * *Challenge*: Firewalls that drop TCP packets (SYN/read blackhole), causing standard requests to hang until socket timeout, compounded by retries.
   * *Hardening*: Enforced strict connection (5s) and read (8s) timeouts. Threaded domain-level timeout budget checks (`t_start` / `timeout_s`) through all check loops, enabling graceful fallback to `audit_status="partial"` (`timeout_budget_exhausted`).
5. **Consolidation into Permanent Test Suites**:
   * Added `10_waf_challenge.html` and `11_geo_gate.html` to `tests/test_archetypes.py` (expanding matrix to 11/11).
   * Added `/blackhole` hostile socket hang to `tests/test_chaos.py` (expanding chaos to 4/4).

### Phase 5: Scoring Governance & Triage Separation (`ee074ed`, `9355eb3`, `47fe088`, `b81a9a3`)
* **The Governance Decision**: Earlier prototypes calculated a synthetic 0–100 overall score and letter grade (A–F). However, the hackathon specification requires objective finding discovery and category severity distributions, not ungrounded composite formulas.
* **The Resolution**:
  * Synthetic scores and grades were permanently excised from the core marketplace report schema (`report.schema.json`).
  * An internal triage CLI was created at `tools/internal_batch_summary.py` (outside `skills/` and excluded from submission) strictly for sorting bulk offline batch runs.

### Phase 6: Self-Identified Risk Resolution (`b81a9a3`)
* **Blank-Root SPA Geolocation Gates**: Verified behavior when a site is both an SPA and has a geo-gate. Created fixture `tests/fixtures/12_spa_blank_geogate.html`. Proved that an empty root (`<div id="root"></div>`) correctly fires CSR text blanking (`CR-003`) and marks `render_confidence="low"` rather than falsely triggering DOM-based geo-gate patterns.
* **Accidental Co-Firing on `11_geo_gate.html`**: The geo-gate fixture accidentally co-fired `CR-004` (moderate CSR blanking) because fixture text was too brief (ratio 0.27 < 0.30). Added sufficient body text (ratio 0.46) to isolate the check cleanly.
* **Robots Budget Guard**: Confirmed that `robots.txt` fetching is strictly bounded by per-request `request_timeout_seconds` (8.0s) and cannot exhaust the global 240s crawl budget.

### Phase 7: Demo-Readiness Pass (`0ac99c7`)
* **Clean CLI Verification**: Confirmed that `skills/audit-orchestrator/scripts/aggregate.py` executes cleanly from any CWD without requiring manual `PYTHONPATH` or `sys.path` hacks.
* **Dependency Formalization**: Created project-level `requirements.txt` containing all required third-party libraries (`requests`, `beautifulsoup4`, `lxml`, `jsonschema`, `pytest`).
* **Cross-Page Deduplication Risk**:
  * *Investigation*: Checked if `_dedup_key`'s title slice (`title[:80]`) could cause distinct findings to collapse.
  * *Fix*: Expanded slice to `[:120]` matching the JSON Schema maximum title length, and confirmed via multi-page fixtures that findings aggregate by design (`pages_affected` count + sample URLs).
* **Edge CDN Connection Tarpitting Resilience**:
  * Evaluated resilience against edge CDNs enforcing TLS connection tarpitting (repeated SSL renegotiations until read timeout).
  * The orchestrator cleanly aborts with `audit_status="blocked"`, `blocked_reason="connection_failed"`, emitting 100% schema-valid output within the configured deadline.
* **Schema Validation CLI**: Added `_cli()` to `schema_validate.py` to allow one-line schema compliance checks on saved reports.

---

## 4. Empirical Ground Truth: Synthetic Archetypes & Adversarial Sandboxes

To ensure deterministic verification and coverage across edge-case architectures:

| Archetype / Scenario | Category | Tested Behavior | Outcome |
| :--- | :--- | :--- | :--- |
| `1_spa.html` | Client-Side Rendering | CSR text blanking & hydration detection | PASS: Triggers CR-003, CR-004 appropriately. |
| `2_ecommerce.html` | E-Commerce Catalog | Structured product & schema extraction | PASS: Extracts Product, Offer, MerchantReturnPolicy. |
| `3_legacy.html` | Legacy Web | HTML without structured data | PASS: Gracefully identifies schema and metadata absence. |
| `4_blog.html` | Content Publishing | Article metadata & author corroboration | PASS: Corroborates Article schema and author entities. |
| `5_paywall.html` | Gated Access | Paywall & subscription detection | PASS: Flags gated content and restricted crawler visibility. |
| `6_hydration.html` | SSR / Hydration | Mismatch and delayed DOM rendering | PASS: Assesses hydration stability and content availability. |
| `7_cookie_banner.html` | Consent Modals | Viewport overlay detection | PASS: Identifies non-blocking consent elements. |
| `8_i18n.html` | Internationalization | Multi-language & hreflang detection | PASS: Audits hreflang tagging and regional alternate links. |
| `10_waf_challenge.html` | Bot Mitigation | Challenge interstitial detection | PASS: Identifies Cloudflare/Akamai challenge markers. |
| `11_geo_gate.html` | Geolocation Gate | Pincode / regional overlay detection | PASS: Triggers CR-005 location-gate finding. |
| `12_spa_blank_geogate.html` | Blank Root SPA | Distinguishing blank CSR from geo-gate | PASS: Correctly flags CSR blanking without false geo-gate. |
| **Chaos Fixtures (4)** | Pathological Test Bed | Crash & hang resilience | 4/4 PASS in `tests/test_chaos.py` (Zero-byte, Garbage DOM/JSON-LD, Redirect loop, TCP blackhole). |

---

## 5. Current Test Suite Composition

The repository maintains an automated, regression-tested verification harness:

1. **`python tests/dry_run_test.py`**:
   * *Scope*: Smoke test executing `run_audit()` across all 4 domain skills against an integration endpoint.
   * *Validates*: Emitted payload keys (`domain`, `pages_analyzed`, `errors`, `findings`, `proactive_candidates`), type contracts, and error resilience.
2. **`python tests/test_archetypes.py`**:
   * *Scope*: Spawns a local HTTP server on `127.0.0.1` and executes the orchestrator against 11 archetypes.
   * *Validates*: Expected rule triggers and non-triggers, zero false-positive regressions, gap-free finding IDs, schema validity.
3. **`python tests/test_chaos.py`**:
   * *Scope*: Pathological server simulation.
   * *Validates*: Zero unhandled crashes, bounded socket timeout (< 12.0s), infinite redirect handling, schema compliance under toxic inputs.
4. **`python tests/test_end_to_end.py`**:
   * *Scope*: Full CLI execution against integration test endpoint.
   * *Validates*: Exit code 0, pure JSON stdout, summary field consistency, sequential ID ordering, strict `report.schema.json` conformance.
5. **`python -m pytest tests`**:
   * *Scope*: Unit and semantic tests (`test_adversarial_hardening.py`, `test_claim_corroboration.py`).
   * *Validates*: Audit status transitions, SSRF aborts, WAF signatures, and claim corroboration false-positive suppression.

---

## 6. Known Limitations & Future Work

An honest appraisal of current system boundaries:

1. **Headless Browser Execution Dependency**:
   * While `Playwright` integration is implemented (`PlaywrightRenderer` in `http_client.py`), running headless Chromium requires system browser binaries. On constrained environments without Chromium installed, the tool gracefully falls back to static HTML heuristics, which cannot evaluate runtime JavaScript rendering.
2. **Active Edge Tarpit Traversal**:
   * When commercial CDNs actively trap connections via infinite TLS renegotiation or TCP packet drops, the tool correctly protects itself from hanging via read timeouts (8s) and aborts cleanly (`connection_failed`). It does not attempt to bypass or solve CAPTCHA/proof-of-work challenges, which is by design for a polite, compliant auditor.
3. **Multi-Domain Entity Extraction Depth**:
   * `TC-003` rate-limits external claim verification to a maximum of 5 unique authority URLs per audit to prevent crawl explosion and out-of-domain denial-of-service. Sites with dozens of disparate partner claims will only have a sample verified.
4. **Sitemap Index Traversal Ceiling**:
   * `crawl_audit.py` caps sitemap index child sitemaps at 10 files and 500 total URLs (`sitemap_max_urls`) to preserve bounded runtime. Massive enterprise sites with hundreds of thousands of sitemap URLs are only sampled.
