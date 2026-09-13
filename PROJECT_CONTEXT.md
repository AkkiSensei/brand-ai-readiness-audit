# PROJECT CONTEXT & TECHNICAL SPECIFICATION

> **Brand AI-Readiness Audit Marketplace**  
> Built for the **Adobe University Hackathon 2026 — Round 3**  
> Designated Entrypoint: `skills/audit-orchestrator/scripts/aggregate.py`

---

## 1. Problem Framing: The Paradigm Shift in Web Discovery

### 1.1 From Lexical Search to Generative Ingestion

Over the past two decades, web discoverability was governed by keyword-centric SEO. Traditional crawlers built inverted indices; algorithms such as PageRank and BM25 matched queries against document keywords to rank lists of URLs. Human users clicked those URLs, loaded pages in browsers, and manually resolved ambiguities.

Modern AI search and generative answer engines — **ChatGPT (SearchGPT)**, **Claude**, **Perplexity**, **Google Gemini**, and **Microsoft Copilot** — operate under fundamentally different technical constraints:

$$\text{Search Ranking} \neq \text{Machine Ingestion Quality} \neq \text{Citation Readiness}$$

Generative engines deploy automated agents that:
1. Fetch and segment web content into discrete context chunks.
2. Ingest structured facts into knowledge graphs to establish entity veracity.
3. Cross-corroborate factual assertions against independent third-party sources.
4. Synthesize conversational responses with dynamically attached, verifiable citation anchors.

When an AI engine cannot reliably fetch, extract, or corroborate information from a brand website, the brand suffers **AI Hallucination**, **Entity Confusion**, or complete **Omission** from generative answers.

### 1.2 The Four Ingestion Barriers

- **Crawler Gatekeeping**: Many websites unintentionally disallow AI user-agents (`GPTBot`, `Claude-Web`, `PerplexityBot`, `Google-Extended`) in `robots.txt`, or present WAF challenges / empty CSR shells that headless fetchers cannot execute.
- **Data Entrapment**: Critical commercial facts (pricing, specs, policies) are trapped inside raster `<img>` tags without alt text, `<canvas>` elements, or unindexed binary PDFs.
- **Entity Ambiguity**: Absence of Schema.org JSON-LD or missing `sameAs` entity URIs (Wikidata, Wikipedia, LinkedIn) prevents knowledge-graph extractors from establishing high-confidence entity resolution.
- **Passage Fragmentation**: Documents lacking hierarchical heading structures (`<h1>`..`<h3>`), anchorable fragment IDs, or inverted-pyramid declarative summaries cannot be cleanly extracted for targeted citations.

---

## 2. Marketplace Architecture & Standard Compliance

The marketplace strictly complies with the **agentskills.io** open specification and the Adobe Round 3 submission standard.

```
brand-ai-readiness-audit/
├── marketplace.json                  # Marketplace manifest declaring all 5 skills & entrypoint
├── README.md                         # Primary user and judge entrypoint
├── PROJECT_CONTEXT.md                # Substantive technical context & architecture spec
├── PROJECT_DESCRIPTION.md            # Concise problem/solution description
├── CONTEXT.md                        # Engineering history & empirical ground truth
├── requirements.txt                  # Pinned runtime dependencies
├── pytest.ini                        # Pytest configuration
├── skills/
│   ├── audit-orchestrator/           # Designated entrypoint skill
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   │   ├── aggregate.py          # Master CLI orchestrator & composition engine
│   │   │   ├── proactive_engine.py   # Proactive recommendations generator
│   │   │   └── schema_validate.py    # JSON Schema Draft-07 validator
│   │   └── references/
│   │       ├── report.schema.json    # Formal JSON Schema definition
│   │       └── thresholds.json       # Configurable audit thresholds & limits
│   ├── crawl-render-access/          # Domain Sub-Skill 1
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       ├── crawl_audit.py        # Crawler, robots, WAF, sitemap, & render analysis
│   │       └── http_client.py        # SSRF-hardened, DNS-pinned HTTP transport
│   ├── structured-fact-extraction/   # Domain Sub-Skill 2
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── sfe_audit.py          # Schema.org JSON-LD & trapped fact analysis
│   ├── trust-entity-corroboration/   # Domain Sub-Skill 3
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── tec_audit.py          # sameAs, NAP consistency, & accreditation analysis
│   └── engagement-retention/         # Domain Sub-Skill 4
│       ├── SKILL.md
│       └── scripts/
│           └── er_audit.py           # Document hierarchy, overlays, CTAs, & links
└── tests/                            # Automated regression & validation test suites (299 tests)
```

### 2.1 Single Designated Entrypoint

`marketplace.json` defines exactly one entrypoint:
```json
{ "entrypoint": "skills/audit-orchestrator/scripts/aggregate.py" }
```
All multi-skill execution, inter-skill data passing, error boundary handling, and output formatting flow through `aggregate.py`.

---

## 3. Skill Responsibilities & Detection Coverage

The audit suite evaluates **30 core defect heuristics** and **7 proactive recommendations** across five distinct skills:

| Skill | Heuristics | Key Technical Checks |
|---|---|---|
| **`crawl-render-access`** | `CR-001`..`CR-008` | AI bot permissions in `robots.txt` • WAF/bot challenge detection • CSR text-blanking ratio • HTTP status codes • Redirect chain depth • XML sitemap presence & declaration • Sitemap `<lastmod>` freshness • Conflicting `noindex` directives |
| **`structured-fact-extraction`** | `SF-001`..`SF-008` | Schema.org JSON-LD presence & syntax • `Organization` schema completeness • `Product`/`Offer` schema completeness • Commercial facts in images without alt text • Uncaptioned `<canvas>`/`<video>` • Orphan binary PDFs • Content freshness (`dateModified`) • FAQ/Q&A markup (`FAQPage`) |
| **`trust-entity-corroboration`** | `TC-001`..`TC-006` | Authoritative `sameAs` entity links • NAP multi-page consistency • Outbound accreditation link verification • Entity name ambiguity • Transparent authorship/ownership signals • Machine-readable licensing declarations |
| **`engagement-retention`** | `ER-001`..`ER-008` | Semantic heading hierarchy • Intrusive modal overlay detection • Primary `<nav>` structure • SHA-256-sampled internal link health • CTA presence & clarity • Responsive mobile viewport • Cookie consent banner compliance • CLS-risk unsized media assets |
| **`audit-orchestrator`** | Composition + `PA-001`..`PA-006`, `PA-CANONICAL` | Multi-skill sequencing & frontier dispatch • Finding deduplication & global ID assignment • Remediation theme synthesis • Proactive recommendation generation • JSON Schema Draft-07 validation |

---

## 4. End-to-End Causal Audit Pipeline

The audit executes as a linear, causally-gated pipeline. AI ingestion is fundamentally hierarchical: if a lower layer fails, higher layers cannot function.

```
                         [Target URL Input]
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │   HttpClient Transport Init   │
                 │  • SSRF Address Validation    │
                 │  • Socket-Level DNS Pinning   │
                 │  • Monotonic Deadline Clock   │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │      Crawl-Render-Access      │
                 │  • Fetch & Parse robots.txt   │
                 │  • Discover XML Sitemaps      │
                 │  • Seed BFS Crawl Frontier    │
                 └───────────────┬───────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
        [Fatal Blocker?]                    [Access Permitted]
              │                                      │
              ▼                                      ▼
  ┌─────────────────────┐           ┌────────────────────────────┐
  │ Short-Circuit Exit  │           │   Bounded Frontier Crawl   │
  │ status: "blocked"   │           │   (default max 15 pages,   │
  │ Schema-Valid JSON   │           │    rate-limited 1 req/s)   │
  └─────────────────────┘           └────────────────┬───────────┘
                                                      │
                                                      ▼
                                        ┌─────────────────────────┐
                                        │  Parallel Sub-Skill Run  │
                                        │  • structured-fact-extr. │
                                        │  • trust-entity-corrobor.│
                                        │  • engagement-retention  │
                                        └─────────────┬───────────┘
                                                      │
                                                      ▼
                                        ┌─────────────────────────┐
                                        │ Canonical Merge & Dedup  │
                                        │ • Assign F-001..F-NNN    │
                                        │ • Group Remediation Theme│
                                        │ • Synthesize Proactive   │
                                        └─────────────┬───────────┘
                                                      │
                                                      ▼
                                        ┌─────────────────────────┐
                                        │  JSON Schema Validation  │
                                        │  Draft-07 report.schema  │
                                        └─────────────┬───────────┘
                                                      │
                                                      ▼
                                               [Final JSON Report]
```

### 4.1 Short-Circuit Semantics

If the target host completely disallows crawling via `robots.txt`, returns a 403 WAF challenge, or triggers an SSRF block (e.g., DNS resolves to a private IP), the orchestrator short-circuits execution. Rather than crashing or running empty downstream skills, it emits a schema-valid report with `audit_status: "blocked"` and `blocked_reason`, documenting the blocker with full evidence.

### 4.2 Single Network Pass

`crawl-render-access` executes network discovery and populates in-memory `PageResult` objects (pre-parsed BeautifulSoup DOMs). Downstream skills analyze these pre-parsed objects entirely in memory — zero redundant network round-trips.

---

## 5. Deterministic Finding Model

All analysis decisions produced by the marketplace are **deterministic**: evaluating identical fetched server responses produces identical finding sets, IDs, severities, evidence states, and remediation plans (excluding run timestamps and duration metadata). This is enforced by:

- **Rule-based heuristics only**: no LLM prompts, no random sampling, no probabilistic scoring.
- **SHA-256 link sampling**: internal URL selection in ER-004 uses `sorted(links, key=sha256_digest)[:N]`, guaranteeing uniform URL-space coverage with perfect reproducibility.
- **Identical deduplication key**: findings are deduplicated by `(local_id, title[:120])`, producing stable merged findings across multi-page runs.

---

## 6. Evidence Model

Every finding carries a non-empty `evidence` field containing a verbatim, verifiable observation extracted directly from the HTTP response or DOM:

```json
{
  "id": "F-003",
  "local_id": "SF-004",
  "title": "Critical brand information trapped in images without alt text",
  "severity": "medium",
  "category": "facts",
  "evidence": "Found 3 images containing pricing, specification, or credential keywords without descriptive alt attributes: /assets/pricing-table.png",
  "location": "https://example.com/products",
  "why_it_matters": "AI crawlers cannot reliably extract text from images without alt text, leading to omitted product pricing in AI answers.",
  "remediation_theme": "Trapped Content Remediation",
  "suggested_action": {
    "summary": "Provide descriptive alt text for images containing critical brand data, or render specifications in semantic HTML tables.",
    "priority": "medium",
    "asset_type": "Image Markup",
    "location": "https://example.com/products",
    "mechanism": "AI search engines prioritize machine-readable text over raster graphics."
  },
  "related_to": ["SF-001", "SF-005"]
}
```

Optional fields include:
- **`confidence`** (`0.0`–`1.0`): computed as `pages_affected / pages_checked` for multi-page checks.
- **`pages_affected`**: count of pages where the finding was detected.
- **`sample_urls`**: a representative list of affected page URLs.

---

## 7. Remediation Model

Rather than leaving site owners with an unstructured list of isolated warnings, the orchestrator clusters findings into **Remediation Themes** — groups with a single primary action and priority:

| Theme | Related Checks |
|---|---|
| Crawler Access Governance | CR-001, CR-002, CR-006, CR-007 |
| Render Architecture | CR-003, CR-004, CR-005 |
| Schema.org Structured Data | SF-001, SF-002, SF-003, SF-008 |
| Trapped Content Remediation | SF-004, SF-005, SF-006 |
| Content Freshness | SF-007, CR-007 |
| Entity Authority & Corroboration | TC-001, TC-002, TC-003, TC-004, TC-005, TC-006 |
| Document Presentation & Accessibility | ER-001, ER-002, ER-003, ER-004, ER-005, ER-006, ER-007, ER-008 |

Engineering teams can resolve all findings within a theme with a single coordinated sprint rather than working through an undifferentiated alert list.

---

## 8. Proactive Recommendation Model

Traditional linters are purely reactive. The Brand AI-Readiness marketplace introduces a dedicated **Proactive Recommendation Engine** that advises brands on forward-looking standards for generative AI:

1. **`PA-001` — Machine-Readable Site Manifest (`/llms.txt` or `/agents.md`)**: Deploys an authoritative, token-efficient AI site manifest at the domain root.
2. **`PA-002` — Unified Schema.org `@graph` Architecture**: Consolidates scattered JSON-LD into a single `@graph` with `@id` cross-references linking `Organization` → `Product` → `Offer` → `Person`.
3. **`PA-003` — Heading Slug Deep-Linking**: Adds deterministic `id` slugs to `<h2>` and `<h3>` tags, enabling AI engines to deep-link directly to cited paragraphs.
4. **`PA-004` — Inverted-Pyramid Declarative Summaries**: Structures article intros with answer-first summaries, maximizing passage extraction during RAG retrieval.
5. **`PA-005` — Syndication Feeds for Freshness Tracking**: Exposes RSS/Atom feeds so LLM ingestion systems can detect content updates without expensive polling crawls.
6. **`PA-006` — Explicit AI Crawler Allow Directives**: Declares explicit `Allow: /` for verified AI crawlers in `robots.txt` to remove ambiguity.
7. **`PA-CANONICAL` — Canonical URL Consolidation**: Declares `<link rel="canonical">` tags on all pages to prevent index dilution across URL variations.

---

## 9. Security & Network Boundaries

The marketplace is engineered with strict production defense-in-depth principles.

### 9.1 Strictly Read-Only

- Zero state mutations: never `POST`, `PUT`, `PATCH`, or `DELETE`.
- Never fills or submits forms.
- Never modifies shopping carts or session cookies.
- Never attempts administrative login or authentication bypass.

### 9.2 SSRF Protection & Private Network Fencing

Before any network connection, the target URL and all redirect destinations are validated against prohibited IP ranges:
- Loopback: `127.0.0.0/8`, `::1`
- RFC 1918 private subnets: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.0.0/16`, `fe80::/10`
- Cloud metadata endpoints: `169.254.169.254`, `metadata.google.internal`
- Scheme allowlist: only `http://` and `https://` permitted (`file://`, `gopher://`, `dict://` rejected)

### 9.3 Socket-Level DNS Pinning (TOCTOU Immunity)

Standard application-level SSRF checks suffer from Time-Of-Check to Time-Of-Use (TOCTOU) race conditions: an attacker-controlled DNS server can return a public IP during pre-flight validation but resolve to `127.0.0.1` milliseconds later when the socket connects.

`DestinationPinningManager` integrated into `SSRFSafeHTTPAdapter` neutralizes this:
1. DNS resolution occurs once during pre-flight validation.
2. The resolved IP is verified against SSRF blocklists.
3. The underlying socket connection is explicitly bound to the pre-validated IP.
4. Any mid-session rebinding attempt fails immediately.

### 9.4 Monotonic Global Deadline Enforcement

The orchestrator initializes an `AuditDeadline` (default 240 s) using a monotonic clock. All crawl iterations, browser renders, sub-skill dispatches, and XML parsing steps decrement from this budget. If the budget is exhausted, the engine cleanly halts and emits a valid partial report (`audit_status: "partial"`, `blocked_reason: "timeout_budget_exhausted"`).

### 9.5 Rate Limiting

A token-bucket `RateLimiter` enforces a maximum of 1 request/second per host, preventing inadvertent load on target servers.

---

## 10. Generalization Strategy

The marketplace evaluates **arbitrary, unseen public websites** by assessing structural patterns rather than overfitting to specific domains.

### 10.1 Evaluated Archetypes (11 Total)

The engine is verified against 11 synthetic and live website archetypes:

| # | Archetype | Key Checks Exercised |
|---|---|---|
| 1 | Single-Page Applications (SPA) | CR-003 (CSR blanking), render_confidence |
| 2 | E-Commerce Catalogues | SF-003 (Product/Offer schema), SF-004 |
| 3 | Legacy HTML Portals | ER-001 (heading hierarchy), SF-001 |
| 4 | Editorial & Media Blogs | PA-003, PA-004, SF-007 |
| 5 | Paywalled & Metered Content | `isAccessibleForFree` schema |
| 6 | Hydration & Dynamic DOMs | CR-003, CR-004 |
| 7 | Cookie & Privacy Overlays | ER-002 (modal detection) |
| 8 | Internationalized Sites (i18n) | Multi-language alternate links |
| 9 | WAF & Rate-Challenged Sites | CR-002, blocked status |
| 10 | Geo-Gated Gateways | CR-005, location-gate heuristics |
| 11 | Non-HTML & Malformed Assets | Graceful degradation |

### 10.2 Deterministic SHA-256 Link Sampling

When auditing large domains, link evaluation (ER-004) samples internal URLs deterministically:
```python
sorted(links, key=lambda u: hashlib.sha256(u.encode()).digest())[:N]
```
This guarantees unbiased uniform URL-space coverage and deterministic reproducibility without RNG state.

### 10.3 Degradation Resilience

If Playwright headless rendering is unavailable, the engine automatically falls back to static HTML heuristics. If a sub-skill crashes unexpectedly, the orchestrator catches the exception, logs it, and continues with remaining skills — emitting a partial but schema-valid report.

---

## 11. Limitations

An honest appraisal of current system boundaries:

1. **Headless browser dependency**: `PlaywrightRenderer` requires Chromium binaries. Without them, CSR blanking measurements fall back to static heuristics, which cannot evaluate runtime JavaScript rendering.
2. **Active edge tarpit traversal**: When CDNs (e.g., Akamai on gucci.com) enforce TLS tarpitting or TCP packet drops, the engine correctly protects itself via read timeouts (8 s) and aborts cleanly. It does not attempt CAPTCHA bypass by design.
3. **External claim verification sampling**: TC-003 rate-limits external HEAD requests to a maximum of 5 unique authority URLs per audit to prevent crawl explosion.
4. **Sitemap traversal ceiling**: Sitemap index child sitemaps are capped at 10 child sitemaps and 500 total URLs (`sitemap_max_urls`) to preserve bounded runtime.
5. **No authenticated access**: Pages behind login walls or paywalls are not audited beyond the gate detection heuristic.

---

## 12. Non-Goals

- **No neural weights**: The engine never downloads or runs LLM weights locally. All analysis is deterministic rule-based parsing.
- **No active exploitation**: An audit tool, not a penetration testing suite.
- **No CAPTCHA or paywall bypass**: Respects site security boundaries; reports access blocks rather than attempting circumvention.

---

## 13. Adobe Round 3 Compliance Matrix

| Requirement | Specification | Implementation | Status |
|---|---|---|---|
| Marketplace Root Structure | Compliant directory + `marketplace.json` | Clean root layout with all 5 skill directories | **PASS** |
| Manifest Completeness | All skills declared, valid JSON | `marketplace.json` declares name, version, entrypoint, all 5 skills | **PASS** |
| Designated Entrypoint | Exactly one entrypoint | `skills/audit-orchestrator/scripts/aggregate.py` | **PASS** |
| SKILL.md Files | YAML frontmatter, inputs, procedure, output | All 5 skills include compliant `SKILL.md` | **PASS** |
| Recommend-Only / Read-Only | No state mutation | Zero POST/PUT/DELETE; no form submissions | **PASS** |
| robots.txt Respect | Obey RFC 9309 | Full RFC 9309 parser; fail-closed on 5xx | **PASS** |
| Self-Contained & Portable | Standard deps, no proprietary lock-in | Python 3.10+, pinned `requirements.txt`, no proprietary APIs | **PASS** |
| Execution Budget | Under wall-clock ceiling | Monotonic `AuditDeadline` (default 240 s); typical runs 4–15 s | **PASS** |
| No Pretrained Weights | Zero model weight files | Deterministic rule-based analysis | **PASS** |
| Schema-Validated Report | Validated against JSON Schema | Emitted report validates against `report.schema.json` (Draft-07) | **PASS** |
| Evidence & Severity | Every finding has severity, evidence, action | 100% of findings include ID, severity, evidence, suggested_action | **PASS** |
| Proactive Suggestions | Forward-looking AI recommendations | Dedicated engine: PA-001..PA-006, PA-CANONICAL | **PASS** |
| Skill Composition | Genuine multi-skill orchestration | Entrypoint coordinates crawl frontier, parallel sub-skill runs, dedup | **PASS** |
| Unseen Generalization | Generalized rules, not fit-to-examples | Verified across 11 archetypes, 4 chaos scenarios, live URLs | **PASS** |
