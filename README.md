# Brand AI-Readiness Audit Marketplace

> **Autonomous, deterministic evaluation marketplace for benchmarking public brand websites against AI search, generative-answer, and citation engine ingest pipelines.**  
> Built for the **Adobe University Hackathon 2026 — Round 3**.  
> Designated Entrypoint: `skills/audit-orchestrator/scripts/aggregate.py`

---

## Quick Reference & Technical Highlights

- **Zero Pretrained Model Weights**: 100% rule-based deterministic expert analysis; zero local model weights, zero third-party LLM API keys.
- **Strictly Read-Only**: Zero mutating HTTP requests (no POST/PUT/DELETE), zero form submissions, zero authenticated operations.
- **SSRF & DNS-Rebinding Hardened**: Socket-level pre-flight DNS pinning (`DestinationPinningManager`) neutralizes TOCTOU rebinding attacks.
- **Causal Execution Pipeline**: Short-circuits on fatal transport or `robots.txt` blockers; bounds execution to a monotonic wall-clock deadline.
- **Comprehensive Schema**: Emits structured, machine-verifiable JSON adhering strictly to JSON Schema Draft-07 (`report.schema.json`).
- **Deep Technical Context**: For comprehensive problem framing, architecture, heuristic breakdowns, and compliance mapping, see [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

---

## 1. What the Project Is & Problem It Solves

Traditional search engines index keywords to rank a list of URLs for humans to click. Modern generative AI engines (**ChatGPT Search**, **Claude**, **Perplexity**, **Google Gemini**, **Microsoft Copilot**) operate under a different paradigm: they ingest content into context chunks, extract factual assertions into knowledge graphs, verify claims across third-party sources, and synthesize direct conversational answers with citations.

When a brand website blocks AI user-agents, serves blank client-rendered JavaScript shells, traps pricing/specs in raster images, or lacks Schema.org entity linkages, AI engines cannot ingest the site. This leads to **omission from AI search**, **entity confusion**, or **hallucinated brand facts**.

This marketplace autonomously inspects any public brand website, evaluates **37 technical checks** across AI discoverability and on-site engagement, and produces an objective, evidence-backed audit report with actionable remediation guidance.

---

## 2. Why It Is Technically Different

| Dimension | Typical LLM-Based Linters | Brand AI-Readiness Marketplace |
|---|---|---|
| **Determinism** | Non-deterministic; hallucinations and variable scores across runs | **100% Deterministic**: Running against static responses produces bit-identical reports |
| **Model Footprint** | Gigabytes of weights or costly third-party API dependencies | **Zero Weights**: Lightweight Python rules; submission archive is **0.21 MB** |
| **Execution Speed** | 60–180 seconds due to API latency and generation tokens | **Sub-15 Seconds**: Monotonic clock enforcement; typical runs finish in 4–10 seconds |
| **Security Posture** | Blind HTTP fetchers vulnerable to SSRF and DNS rebinding | **Hardened Transport**: IP range blocklists + socket-level DNS pinning adapter |
| **Sampling Bias** | Arbitrary or alphabetically-skewed URL crawling | **SHA-256 Uniform Sampling**: Deterministic hash-based link selection without random drift |

---

## 3. How the Five Skills Work Together

The marketplace adheres to the **agentskills.io** modular marketplace standard and is declared in `marketplace.json`:

```
                             [Target URL]
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │      HttpClient       │  (SSRF validation, socket DNS pinning)
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │  crawl-render-access  │  (CR-001 .. CR-008: robots, WAF, render, sitemaps)
                       └───────────┬───────────┘
                                   │
                      Frontier & Parsed Page Data
                                   ├──────────────────────────┐
                                   ▼                          ▼
                       ┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
                       │structured-fact-extract│  │trust-entity-corroborat│  │  engagement-retention │
                       │  (SF-001 .. SF-008)   │  │  (TC-001 .. TC-006)   │  │  (ER-001 .. ER-008)   │
                       └───────────┬───────────┘  └───────────┬───────────┘  └───────────┬───────────┘
                                   │                          │                          │
                                   └──────────────────────────┼──────────────────────────┘
                                                              ▼
                                                  ┌───────────────────────┐
                                                  │   audit-orchestrator  │  (Entrypoint: aggregate.py)
                                                  │  • Deduplication      │
                                                  │  • Proactive Engine   │  (PA-001 .. PA-006)
                                                  │  • Remediation Themes │
                                                  │  • Schema Validation  │
                                                  └───────────┬───────────┘
                                                              ▼
                                                   [Final JSON Report]
```

### Skill Responsibilities
1. **`audit-orchestrator`** (**Designated Entrypoint**): Coordinates the causal pipeline, manages crawl frontiers, deduplicates findings, runs proactive heuristics, groups remediation themes, and validates the output against `report.schema.json`.
2. **`crawl-render-access`** (`CR-001` .. `CR-008`): Audits `robots.txt` for AI crawlers, detects WAF/bot blocking, measures SSR vs CSR text-blanking ratios, inspects HTTP status/redirect chains, and checks XML sitemap freshness.
3. **`structured-fact-extraction`** (`SF-001` .. `SF-008`): Validates Schema.org JSON-LD syntax (`Organization`, `Product`, `FAQPage`), detects brand facts trapped in images/canvas/video without alt text, flags orphan PDFs, and checks content freshness.
4. **`trust-entity-corroboration`** (`TC-001` .. `TC-006`): Audits authoritative `sameAs` entity links (Wikidata, Wikipedia, LinkedIn), verifies multi-page Name/Address/Phone (NAP) consistency, and validates outbound accreditation links via safe HEAD requests.
5. **`engagement-retention`** (`ER-001` .. `ER-008`): Audits heading hierarchy (`<h1>` presence), flags intrusive modal overlays, tests internal link health, verifies CTA visibility, and checks mobile viewport declarations.

---

## 4. What Findings It Produces & How Evidence Is Generated

Every finding strictly conforms to a unified contract containing verifiable evidence and actionable remediation:

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
  "remediation_theme": "Crawler & Transport Infrastructure",
  "suggested_action": {
    "summary": "Update robots.txt to allow verified AI crawlers access to public content.",
    "priority": "critical",
    "asset_type": "robots.txt",
    "location": "/robots.txt",
    "mechanism": "AI search engines respect RFC 9309 robots directives."
  }
}
```

### Grouped Remediation Themes
Findings are synthesized into high-level **Remediation Themes** (e.g., *Crawler & Transport Infrastructure*, *Schema.org Structured Data*, *Trapped Content Remediation*), providing teams with consolidated priorities rather than fragmented alerts.

---

## 5. Proactive AI-Readiness Recommendations

Beyond flagging defects, the engine emits forward-looking proactive recommendations (`PA-001` .. `PA-006`, `PA-CANONICAL`):
- **`PA-001`**: Publishing `/llms.txt` or `/agents.md` site manifests for LLM agents.
- **`PA-002`**: Consolidating isolated JSON-LD blocks into a cohesive Schema.org `@graph` with `@id` linkages.
- **`PA-003`**: Adding slug `id` attributes to section headings for citation deep-linking.
- **`PA-004`**: Structuring article intros with answer-first (inverted pyramid) summaries.
- **`PA-005`**: Providing RSS/Atom syndication feeds for real-time freshness tracking.
- **`PA-006`**: Declaring explicit `Allow:` directives for verified AI crawlers in `robots.txt`.
- **`PA-CANONICAL`**: Declaring canonical `<link rel="canonical">` tags to prevent content dilution.

---

## 6. How the System Generalizes to Unseen Websites

The marketplace was engineered to evaluate **arbitrary, unseen websites** by evaluating structural patterns rather than overfitting to specific domains:
- **11 Verified Archetypes**: Single-Page Applications (SPA), E-Commerce catalogs, Legacy HTML portals, Editorial blogs, Paywalled content, Hydration-dependent DOMs, Cookie overlays, Internationalized (i18n) sites, WAF-challenged hosts, Geo-gated gateways, and Malformed non-HTML responses.
- **Deterministic SHA-256 Link Sampling**: When crawling large sites, internal link selection (ER-004) uses deterministic SHA-256 sorting, guaranteeing uniform URL space coverage without random drift.
- **Degradation Resilience**: If Playwright headless rendering is unavailable or blocked, the engine automatically falls back to server-side HTML heuristics.

---

## 7. Key Safety & Read-Only Guarantees

- **Passive Inspection Only**: Zero mutating HTTP methods; never submits forms, never alters cart states, never authenticates.
- **SSRF Hardened**: Blocks private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and cloud metadata services (`169.254.169.254`).
- **Socket-Level DNS Pinning**: `DestinationPinningManager` binds connections directly to validated pre-flight IPs, neutralizing TOCTOU DNS-rebinding attacks.
- **RFC 9309 Compliance**: Honors `robots.txt` directives and fails closed on 5xx errors.
- **Monotonic Execution Deadline**: Enforces global `AuditDeadline` so audits strictly terminate within host budgets.

---

## 8. How to Run the Package

### Prerequisites & Installation
```bash
# Clone the repository and install dependencies
pip install -r requirements.txt

# (Optional) Install Playwright for headless browser DOM rendering
playwright install chromium
```

### CLI Audit Execution
```bash
# 1. Standard audit (emits schema-valid JSON to stdout)
python skills/audit-orchestrator/scripts/aggregate.py https://example.com

# 2. Audit and save output directly to file
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --output report.json

# 3. Limit crawl depth and overall execution budget
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --max-pages 10 --timeout 120

# 4. Enable optional Playwright headless DOM rendering
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --render
```

---

## 9. Test & Validation Suite

Run the comprehensive test suite directly from the marketplace root:

```bash
# Run all 274 automated regression tests
python -m pytest tests/

# Run multi-domain dry-run smoke test (e-commerce, SPA, news, walled)
python tests/dry_run_test.py

# Run comprehensive stress suite (Security, Resource, Degradation, Determinism)
python tests/run_validation_stress.py
```

---

## 10. Architectural Documentation

For full architectural blueprints, causal gating diagrams, heuristic catalogs, and the Adobe Round 3 requirement compliance matrix, see [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md).

---

## License

MIT License. Developed for the **Adobe University Hackathon 2026 — Round 3**.
