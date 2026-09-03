# Brand AI-Readiness Audit Marketplace

> An autonomous, deterministic evaluation marketplace for benchmarking public brand websites against AI search, generative-answer, and citation engine ingest pipelines. Built for the **Adobe University Hackathon 2026 — Round 3**.

---

## 1. Executive Summary & Design Thesis

### 1.1 What Brand AI-Readiness Means

Over the past decade, web discovery was governed by keyword-centric Search Engine Optimization (SEO). In traditional search architectures, crawlers parse page markup to build inverted indices; PageRank and textual relevance algorithms determine which ten blue links appear on a search results page. A human user clicks a link, reads the rendered DOM in their browser, and reconciles ambiguities directly.

Modern generative AI systems—such as **ChatGPT (SearchGPT)**, **Claude**, **Perplexity**, **Google Gemini**, and **Microsoft Copilot**—operate under fundamentally different retrieval and synthesis constraints:

$$\text{Search Ranking} \neq \text{Machine-Readable Evidence Quality} \neq \text{Citation Readiness}$$

Generative engines do not merely present URLs for human appraisal; they ingest web content via automated fetchers, segment and embed text chunks, extract discrete factual assertions into knowledge graphs, verify claims across corroborating sources, and synthesize conversational answers while dynamically attaching citation anchors.

For a brand website to be discoverable and accurately represented in this paradigm, it must satisfy four structural requirements:

1. **Unencumbered Machine Access**: Headless AI user-agents (`GPTBot`, `Claude-Web`, `PerplexityBot`, etc.) must be permitted by robots.txt policies, navigate clean URL hierarchies without cyclic redirect chains, and receive server-rendered HTML rather than empty client-side render (CSR) application shells.
2. **Deterministic Fact Extraction**: Core product specifications, pricing, organizational identities, and leadership data must be serialized in machine-readable Schema.org JSON-LD rather than trapped inside pixel graphics, HTML5 `<canvas>` elements, or unstructured, orphaned PDF catalogs.
3. **Multi-Source Entity Corroboration**: Knowledge graph extractors must cross-corroborate organizational claims against external authority nodes (Wikidata, Wikipedia, LinkedIn) via unambiguous `sameAs` linkages and consistent Name/Address/Phone (NAP) data.
4. **Citation-Oriented Content Architecture**: Answering engines prioritize structured, inverted-pyramid passages with stable fragment identifiers (`#section-id`), semantic headings, and low layout-shift penalties, ensuring passages can be cleanly extracted and cited.

### 1.2 Design Thesis

The core design philosophy of this marketplace is grounded in formal deterministic verification:

$$\text{Deterministic Rules} + \text{Observable Evidence} + \text{Bounded Execution} + \text{Schema Validation} = \text{Repeatable AI-Readiness Auditing}$$

Many modern audit tools attempt to use large language models (LLMs) to grade websites. That approach introduces non-deterministic hallucinations, unbounded API latency, variable scoring between runs, high token costs, and proprietary model lock-in. 

In contrast, **`brand-ai-readiness-audit` operates as a zero-model-weight, rule-based expert engine**:

* **Deterministic Rule Execution**: 30 defect heuristics and 6 proactive recommendations evaluate concrete, observable HTML, HTTP, and JSON-LD primitives. Running the audit multiple times against identical static responses yields bit-identical findings.
* **Evidence-Backed Attribution**: Every finding is accompanied by the exact URI, violating code snippet or metric, and an actionable remediation summary.
* **Bounded Operational Footprint**: Crawling is capped at configurable page budgets (default 15 pages), rate-limited to 1 request per second per host, protected by exponential retry backoffs, and executed within a strict wall-clock timeout budget (default 240s).
* **Portability**: The entire suite runs on standard Python 3.10+ environments using lightweight dependencies (`requests`, `beautifulsoup4`, `lxml`, `jsonschema`). Browser-based headless DOM rendering (`playwright`) is dynamic and optional: if unavailable, the engine falls back gracefully to server-side HTML heuristics without crashing.

### 1.3 Causal Chain

An AI crawler encounters a target website in a strict chronological sequence. Each stage in the pipeline causally gates subsequent ingestion phases:

```text
HTTP Handshake & Transport (DNS, TLS, HTTP Status)
    ↓
Robots Policy & Crawler Accessibility (robots.txt, AI User-Agent permissions)
    ↓
Frontier Discovery & Sitemaps (Sitemap.xml, link extraction, depth traversal)
    ↓
DOM & Rendered Content Availability (Raw HTML vs Client-Side Rendering blanking)
    ↓
Structured Fact Extraction (Schema.org JSON-LD, Organization, Product, FAQPage)
    ↓
Entity Corroboration & Graph Linkage (sameAs authority nodes, NAP consistency)
    ↓
Passage & Citation Architecture (Heading hierarchy, fragment IDs, answer-first)
    ↓
On-Site Engagement & Retention (Viewport meta, absence of intrusive overlays)
```

If a site fails at an early stage (e.g., blanket-disallowing `GPTBot` via robots.txt or serving an empty `<div id="root"></div>` requiring JavaScript execution), all downstream investments in Schema.org markup or content depth become moot. The audit system models this causal sequence explicitly.

---

## 2. Marketplace Architecture & Decomposition

The project conforms to the **agentskills.io** modular marketplace standard. The system is decomposed into **one Entrypoint Orchestrator** and **four specialized Domain Sub-Skills**.

```text
                               Target URL
                                   │
                                   ▼
                         ┌───────────────────┐
                         │    HttpClient     │
                         │ (Rate Limiting,   │
                         │  Robots Cache)    │
                         └─────────┬─────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │     crawl-render-access     │
                    │   (CR-001 through CR-008)   │
                    └──────────────┬──────────────┘
                                   │
                    Crawl Frontier │ Page Results
                                   ▼
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│  structured-fact- │    │   trust-entity-   │    │    engagement-    │
│    extraction     │    │   corroboration   │    │     retention     │
│(SF-001 ... SF-008)│    │(TC-001 ... TC-006)│    │(ER-001 ... ER-008)│
└─────────┬─────────┘    └─────────┬─────────┘    └─────────┬─────────┘
          │                        │                        │
          └────────────────────────┼────────────────────────┘
                                   │ Domain Findings
                                   ▼
                    ┌─────────────────────────────┐
                    │      Audit Orchestrator     │
                    │   (aggregate.py Entrypoint) │
                    └──────────────┬──────────────┘
                                   │
                                   ├─► Deduplicate & Re-index (F-001..F-NNN)
                                   ├─► Cross-Reference (related_to resolution)
                                   ├─► Proactive Recommendations (PA-001..PA-006)
                                   ├─► Composite Scoring & Letter Grade Calculation
                                   ├─► Coverage Metrics Assembly
                                   ├─► JSON Schema Validation (report.schema.json)
                                   │
                                   ▼
                              Final Report
                             (stdout / JSON)
```

### 2.1 Skill Specifications

#### 1. `audit-orchestrator` (ENTRYPOINT)
* **Path**: `skills/audit-orchestrator`
* **Role**: Central coordinator and CLI entrypoint.
* **Key Responsibilities**:
  * Initializes the rate-limited `HttpClient` session.
  * Dispatches the initial crawl to `crawl-render-access` and captures the discovered URL frontier and pre-parsed `PageResult` DOM representations.
  * Detects critical site-wide crawler bans (`CR-001`) and gracefully short-circuits downstream audits to avoid futile network requests.
  * Fans out the crawled page results concurrently across `structured-fact-extraction`, `trust-entity-corroboration`, and `engagement-retention` without redundant network re-fetching.
  * Merges raw findings across all domains and executes deterministic, multi-attribute deduplication.
  * Sorts findings by severity precedence (`critical > high > medium > low > info`).
  * Assigns gap-free, sequential finding IDs (`F-001`, `F-002`, ..., `F-NNN`).
  * Resolves internal cross-domain relationships (`related_to`) to final stable report IDs.
  * Invokes the `proactive_engine` to inject strategic opportunities (`PA-001` through `PA-006`) with duplicate suppression against existing defect findings.
  * Computes bounded domain readiness scores, composite score (0–100), and letter grades (`A` through `F`) derived from `thresholds.json`.
  * Validates the complete output against `report.schema.json` before emitting pure JSON to stdout.

#### 2. `crawl-render-access`
* **Path**: `skills/crawl-render-access`
* **Role**: Transport, crawler access, and rendering verification.
* **Key Responsibilities**:
  * Inspects `robots.txt` for explicit or wildcard bans targeting 14 major AI user-agents (`CR-001`).
  * Audits HTTP response codes (flagging 4xx/5xx errors) and flags excessive redirect chains exceeding 3 hops (`CR-002`).
  * Measures SSR vs. CSR text-blanking ratios, flagging single-page apps that deliver empty HTML shells requiring full JavaScript evaluation (`CR-003`, `CR-004`).
  * Detects hard paywall or authentication gate overlays hiding body copy from non-credentialed crawlers (`CR-005`).
  * Validates XML sitemaps, verifying presence, robots.txt declaration, `<lastmod>` freshness, and absence of punitive `Crawl-delay` directives (`CR-006`, `CR-007`).
  * Detects public pages inappropriately tagged with `noindex` meta tags or `X-Robots-Tag` headers (`CR-008`).

#### 3. `structured-fact-extraction`
* **Path**: `skills/structured-fact-extraction`
* **Role**: Machine-readable entity and fact serialization audit.
* **Key Responsibilities**:
  * Scans HTML DOMs for Schema.org JSON-LD (`application/ld+json`) blocks (`SF-001`).
  * Validates JSON-LD syntactic parseability and ensures core required fields exist for `Organization`, `Product`, and `Article` types (`SF-002`).
  * Detects critical factual data trapped inside raster graphics (`<img>`) without descriptive `alt` tags (`SF-003`).
  * Identifies HTML5 `<canvas>` elements and video players lacking text alternatives or caption tracks (`SF-004`).
  * Scans for linked PDF catalogs or whitepapers lacking equivalent HTML text companion pages (`SF-005`).
  * Detects Q&A-style informational content that fails to provide `FAQPage` or `QAPage` structured markup (`SF-006`).
  * Evaluates content publication and modification timestamps to identify stale or unmaintained content (`SF-007`).
  * Identifies duplicate or generic `<title>` tags and meta descriptions across distinct URLs (`SF-008`).

#### 4. `trust-entity-corroboration`
* **Path**: `skills/trust-entity-corroboration`
* **Role**: Knowledge graph identity, authority linkage, and brand disambiguation.
* **Key Responsibilities**:
  * Validates `sameAs` link arrays in `Organization` schema, ensuring presence, URI validity, and external resolvability to authoritative nodes such as Wikidata, Wikipedia, and LinkedIn (`TC-001`).
  * Enforces multi-page Name, Address, and Phone (NAP) consistency across crawled headers, footers, and contact pages (`TC-002`).
  * Issues lightweight, rate-limited HEAD requests to corroborate claimed third-party affiliations and accreditations (`TC-003`, `TC-005`).
  * Evaluates brand name ambiguity: flags common dictionary words or homonyms used as brand names without entity disambiguators (`TC-004`).
  * Audits `Organization` schema completeness for corporate disambiguation attributes (`foundingDate`, `legalName`, `taxID`, `vatID`) (`TC-006`).

#### 5. `engagement-retention`
* **Path**: `skills/engagement-retention`
* **Role**: User experience, responsive layout stability, and passage navigation.
* **Key Responsibilities**:
  * Verifies above-the-fold orientation: checks for visible `<h1>` headings and primary `<nav>` structures (`ER-001`).
  * Audits structural breadcrumb navigation on deep URL hierarchies (`ER-002`).
  * Detects aggressive post-load interstitials, modal takeovers, and intrusive cookie banners covering >60% of the viewport (`ER-003`).
  * Crawls and validates internal hyperlink integrity, calculating broken link ratios (`ER-004`).
  * Verifies clear Call-to-Action (CTA) elements on commercial landing and product pages (`ER-005`).
  * Audits responsive `<meta name="viewport">` tags (`ER-006`) and flags accessibility-hostile zooming restrictions (`maximum-scale=1.0`, `user-scalable=no`) (`ER-007`).
  * Validates internal site-search capabilities on catalogs exceeding 10 pages (`ER-008`).

### 2.2 Architectural Decomposition Rationale

Monolithic website auditors suffer from tight coupling: crawler logic is intermingled with parsing rules, network timeouts halt all downstream analysis, and modifying a schema validation rule risks breaking crawl frontier expansion. 

The 5-skill decomposition resolves this through strict separation of concerns:

1. **Evidence-Source Isolation**: Each domain skill operates strictly within its designated evidence dimension (transport/rendering, structured data, entity graph, or UX ergonomics).
2. **Crawl Frontier & DOM Cache Reuse**: `crawl-render-access` executes network discovery and populates in-memory `PageResult` objects. Downstream skills receive pre-parsed DOMs (`BeautifulSoup`), entirely eliminating redundant network round-trips.
3. **Fault Isolation**: If a domain runner encounters a fatal parse exception on an unusual DOM construct, the orchestrator traps the error into that domain's coverage record (`coverage.<domain>.errors`) without aborting the broader audit.
4. **Contract Independence**: Domain sub-skills output standardized intermediate finding dictionaries. The orchestrator owns global report semantics: cross-domain deduplication, ID re-indexing, scoring, and schema validation.

---

## 3. Complete Heuristic & Detection Catalog

The audit engine executes **30 deterministic defect checks** across the four domain skills. Every rule maps directly to observable technical evidence and actionable remediation.

| Rule ID | Domain | Severity | Trigger Mechanism | Suggested Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **CR-001** | `crawl-render-access` | `critical` | robots.txt explicitly disallows one or more of 14 known AI crawlers (`GPTBot`, `Claude-Web`, `PerplexityBot`, etc.). | Update robots.txt to remove Disallow directives for reputable AI crawlers or add explicit Allow blocks. |
| **CR-002** | `crawl-render-access` | `high` / `low` | Internal URLs return 4xx/5xx HTTP status codes (high) or redirect chains exceed 3 consecutive hops (low). | Resolve dead URLs with appropriate 301 redirects to canonical destinations and flatten redirect chains. |
| **CR-003** | `crawl-render-access` | `critical` | Severe CSR text blanking: raw HTML contains < 15% of the text rendered in full browser DOM (or raw text < 100 chars while DOM > 800 chars). | Implement Server-Side Rendering (SSR) or Static Site Generation (SSG) so raw HTML delivers core readable content. |
| **CR-004** | `crawl-render-access` | `high` | Moderate CSR text blanking: raw HTML text ratio is between 15% and 30% of fully rendered browser DOM. | Pre-render critical editorial and factual passages into initial HTML payload before client-side hydration. |
| **CR-005** | `crawl-render-access` | `high` | Paywall, hard registration wall, or login gate blocks primary textual content on public content pages. | Implement Schema.org `isAccessibleForFree` metadata and ensure introductory content is crawler-accessible. |
| **CR-006** | `crawl-render-access` | `high` / `medium` | No XML sitemap discoverable at root or standard paths (high), or sitemap exists but is not declared in robots.txt (medium). | Publish an XML sitemap at `/sitemap.xml` and add a `Sitemap:` directive to robots.txt. |
| **CR-007** | `crawl-render-access` | `medium` / `low` | Sitemap URLs lack `<lastmod>` timestamps (medium), dates are stale (> 365 days) (low), or robots.txt imposes punitive `Crawl-delay` > 5s (low). | Add automated, accurate `<lastmod>` timestamps to sitemap entries and reduce or remove Crawl-delay. |
| **CR-008** | `crawl-render-access` | `high` | Public, linked content pages serve `<meta name="robots" content="noindex">` or `X-Robots-Tag: noindex`. | Remove `noindex` directives from canonical public pages intended for AI indexing and citation. |
| **SF-001** | `structured-fact-extraction` | `high` | Scanned pages contain zero Schema.org JSON-LD scripts, or the homepage lacks an `Organization` block. | Embed valid Schema.org JSON-LD markup on all key pages, beginning with an `Organization` block on homepage. |
| **SF-002** | `structured-fact-extraction` | `high` / `medium` | JSON-LD syntax contains invalid JSON (high) or core schemas lack essential attributes (e.g. `name`, `url`, `description`) (medium). | Validate JSON-LD syntax and provide all recommended properties specified in Schema.org documentation. |
| **SF-003** | `structured-fact-extraction` | `critical` | Key factual data (infographics, pricing tables, comparison charts) is embedded in images lacking descriptive `alt` text. | Provide descriptive, substantive `alt` attributes or reproduce image data in native HTML tables/text. |
| **SF-004** | `structured-fact-extraction` | `medium` | HTML5 `<canvas>` elements lack fallback DOM text, or video players lack `<track>` closed captioning. | Include semantic fallback text inside `<canvas>` tags and attach WebVTT caption tracks to video content. |
| **SF-005** | `structured-fact-extraction` | `high` | Crucial documentation or product brochures exist exclusively as linked PDFs without HTML companion pages. | Create crawlable HTML landing pages summarizing PDF content and transcribing core tabular specifications. |
| **SF-006** | `structured-fact-extraction` | `medium` | Page contains 3 or more question-and-answer formatted headings without `FAQPage` or `QAPage` schema. | Wrap question-and-answer pairs in Schema.org `FAQPage` structured data to enable direct AI answer extraction. |
| **SF-007** | `structured-fact-extraction` | `medium` / `low` | Article or documentation metadata indicates content has not been updated in > 180 days (medium) or lacks dates entirely (low). | Implement explicit `datePublished` and `dateModified` in Schema.org metadata and refresh stale technical facts. |
| **SF-008** | `structured-fact-extraction` | `medium` | Duplicate `<title>` tags or meta descriptions detected across multiple distinct crawled URLs. | Author unique, descriptive `<title>` tags and meta descriptions for every page in the site hierarchy. |
| **TC-001** | `trust-entity-corroboration` | `high` / `medium` | `Organization` schema lacks `sameAs` links (high), contains invalid URI syntax, or includes fewer than minimum external nodes (medium). | Populate `sameAs` arrays with verified URLs pointing to authoritative profiles (Wikidata, Wikipedia, LinkedIn). |
| **TC-002** | `trust-entity-corroboration` | `high` / `medium` | Brand name spelling varies across crawled pages (high), or phone numbers/addresses conflict between header/footer/contact pages (medium). | Standardize Name, Address, and Phone (NAP) details into a single canonical format across all site templates. |
| **TC-003** | `trust-entity-corroboration` | `high` | Claimed external partner, certification, or accreditation links return broken 4xx/5xx HTTP errors. | Audit and update outbound accreditation and trust verification links to ensure all targets resolve cleanly. |
| **TC-004** | `trust-entity-corroboration` | `critical` / `medium` | Brand name is an ambiguous common dictionary word lacking Wikidata entity disambiguation (critical), or shows excessive case variants (medium). | Connect brand identity to a disambiguated Wikidata entity and enforce consistent title-case brand capitalization. |
| **TC-005** | `trust-entity-corroboration` | `medium` | Site presents authority or partnership claims but provides zero verifiable external outbound links. | Add verifiable outbound links to authoritative registries, industry bodies, or official partner directories. |
| **TC-006** | `trust-entity-corroboration` | `medium` | `Organization` schema lacks legal disambiguation fields (`foundingDate`, `legalName`, `taxID`, `vatID`). | Enhance Organization schema with precise corporate identity attributes including `legalName` and `foundingDate`. |
| **ER-001** | `engagement-retention` | `high` / `medium` / `low` | Page lacks a visible `<h1>` heading (high), lacks primary `<nav>` with >= 3 links (medium), or has multiple `<h1>` elements (low). | Provide exactly one visible, descriptive `<h1>` heading above the fold and semantic `<nav>` navigation. |
| **ER-002** | `engagement-retention` | `medium` | Deep pages (path depth >= 2) lack breadcrumb navigation or `BreadcrumbList` Schema.org markup. | Implement semantic breadcrumb navigation with matching Schema.org `BreadcrumbList` structured markup. |
| **ER-003** | `engagement-retention` | `high` / `medium` / `low` | Post-load overlay/modal obscures > 60% of viewport (high), cookie banner covers content (medium), or popup lacks easy dismiss (low). | Ensure main content remains visible on page load; defer promotional popups and use non-blocking cookie notices. |
| **ER-004** | `engagement-retention` | `medium` | Internal links return 4xx client errors or broken on-page fragment targets (`href="#..."`). | Repair broken internal links and ensure all target fragment identifiers exist in the rendered DOM. |
| **ER-005** | `engagement-retention` | `medium` | Product or landing pages lack prominent Call-to-Action (CTA) elements. | Add clear, accessible Call-to-Action buttons or links (`Buy Now`, `Sign Up`, `Contact Sales`) above the fold. |
| **ER-006** | `engagement-retention` | `high` | HTML markup lacks `<meta name="viewport" content="width=device-width, initial-scale=1">`. | Insert a standard responsive viewport meta tag into the `<head>` of all HTML documents. |
| **ER-007** | `engagement-retention` | `medium` | Viewport meta tag disables user zooming (`user-scalable=no` or `maximum-scale=1.0`). | Remove user-scalable restrictions to comply with WCAG accessibility guidelines and mobile quality signals. |
| **ER-008** | `engagement-retention` | `low` | Site contains > 10 discovered pages but provides no search input or `<input type="search">` field. | Implement accessible site search or integrate search functionality with `SearchAction` Schema.org markup. |

---

## 4. Beyond-the-Defect Proactive Engine

A brand website may be completely free of technical defects yet still remain poorly optimized for modern AI citation engines. While defect heuristics flag what is **broken**, the **Proactive Recommendation Engine** (`proactive_engine.py`) detects what is **missing** to elevate a site into an authoritative AI knowledge source.

The engine evaluates six specialized signals:

* **PA-001 — LLM Site Manifest (`/llms.txt`)**:
  * *Signal*: Evaluates availability of `/llms.txt` or `/llms-full.txt` at the origin root.
  * *Rationale*: Emerging web standards (llmstxt.org) allow sites to provide a concise, markdown-formatted directory of brand offerings, APIs, and key pages specifically formatted for LLM context windows.
  * *Remediation*: Publish an `/llms.txt` file summarizing brand identity, core services, and documentation links.
* **PA-002 — Unified JSON-LD `@graph` Architecture**:
  * *Signal*: Analyzes whether JSON-LD scripts are fragmented into isolated blocks or unified into a single `@graph` structure with `@id` cross-references.
  * *Rationale*: AI knowledge extractors construct relationship triples more reliably when `WebSite`, `Organization`, and `WebPage` entities reference each other via stable URI identifiers (e.g. `{"@id": "https://example.com/#organization"}`).
  * *Remediation*: Consolidate isolated JSON-LD blocks into a unified `@graph` array using `#organization` and `#website` anchor IDs.
* **PA-003 — Deep Citation Heading Fragment IDs**:
  * *Signal*: Measures the ratio of `<h2>` and `<h3>` headings containing stable `id` attributes.
  * *Rationale*: When generative engines cite source passages, they link directly to anchored fragments (`https://example.com/page#pricing-details`). Headings without fragment IDs force citation engines to link to the page root, reducing attribution specificity.
  * *Remediation*: Attach descriptive, stable `id` attributes to all section headings across editorial templates.
* **PA-004 — Inverted-Pyramid & Answer-First Architecture**:
  * *Signal*: Heuristically analyzes the opening paragraphs of informational and editorial pages.
  * *Rationale*: Generative retrieval algorithms favor pages that lead with direct, declarative answers in the initial 50 words rather than narrative throat-clearing.
  * *Remediation*: Restructure article introductions using the inverted pyramid: place core conclusions in the first paragraph before elaboration.
* **PA-005 — Syndication Feeds for Freshness Tracking**:
  * *Signal*: Checks for `<link rel="alternate">` declarations with `application/rss+xml` or `application/atom+xml`.
  * *Rationale*: AI search aggregators continuously poll RSS/Atom feeds to discover newly published or updated content without incurring full-site crawl overhead.
  * *Remediation*: Publish and declare an RSS or Atom feed for blog, news, or changelog sections.
* **PA-006 — Explicit AI Crawler Welcome Directives**:
  * *Signal*: Inspects robots.txt for explicit `Allow:` directives targeting recognized AI crawlers (`GPTBot`, `Google-Extended`, `anthropic-ai`).
  * *Rationale*: While absence of a `Disallow` rule permits crawling by default, explicit `Allow` blocks provide unambiguous signal of welcoming intent.
  * *Remediation*: Add explicit `User-agent` blocks welcoming verified AI crawlers in robots.txt.

### 4.1 Proactive Suppression Logic

To maintain signal-to-noise ratio and prevent confusing site operators, the proactive engine enforces strict root-cause suppression:

```text
Existing Defect Finding Present?
             │
             ├──► Yes (e.g. CR-001 AI crawler blocked in robots.txt)
             │          │
             │          ▼
             │    Suppress PA-006 (Do not advise adding Allow directives
             │                     when site-wide blocks already flagged)
             │
             └──► No
                        │
                        ▼
                  Emit Proactive Finding
                  (severity="info", category="proactive")
```

All proactive findings are emitted with:
* `severity`: `"info"`
* `category`: `"proactive"`

Under the scoring formulation, proactive `info` findings carry a penalty of $0$, ensuring that forward-looking strategic advice never degrades the site's readiness score.

---

## 5. Scoring Methodology & Mathematical Formulation

The readiness scoring engine converts discrete technical findings into an objective, normalized **0–100 Brand AI-Readiness Score** and corresponding letter grade.

All scoring weights, severity deductions, and grade boundaries are loaded dynamically from `skills/audit-orchestrator/references/thresholds.json`.

### 5.1 Mathematical Formulation

Let $\mathcal{D}$ represent the set of four audited domain sub-skills:

$$\mathcal{D} = \{\text{crawl-render-access}, \text{structured-fact-extraction}, \text{trust-entity-corroboration}, \text{engagement-retention}\}$$

Each domain $d \in \mathcal{D}$ has a configured domain weight $w_d$ such that $\sum_{d \in \mathcal{D}} w_d = 1.0$:

| Domain ($d$) | Configured Weight ($w_d$) | Rationale |
| :--- | :---: | :--- |
| `structured_fact_extraction` | **0.30** (30%) | Highest weight: structured Schema.org facts are the primary input for generative knowledge extraction. |
| `crawl_render_access` | **0.25** (25%) | Gatekeeper weight: inaccessible or blanked pages prevent all downstream indexing. |
| `trust_entity_corroboration` | **0.25** (25%) | Authority weight: entity disambiguation and authority links dictate source trustworthiness. |
| `engagement_retention` | **0.20** (20%) | Ergonomic weight: user experience, navigation, and mobile stability ensure citation utility. |

Each finding $f$ carries an assigned severity level mapping to a fixed deduction penalty $P(\text{severity}(f))$:

| Severity Level | Penalty Deduction ($P$) | Impact Description |
| :--- | :---: | :--- |
| `critical` | **25** | Catastrophic failure (e.g. AI crawler ban, empty CSR shell, trapped facts). |
| `high` | **15** | Severe hindrance to discovery or extraction (e.g. missing Schema.org, noindex, broken links). |
| `medium` | **8** | Moderate optimization gap (e.g. sitemap omissions, NAP inconsistency, stale dates). |
| `low` | **3** | Minor heuristic imperfection (e.g. missing breadcrumb, sitemap date formatting). |
| `info` | **0** | Proactive guidance and forward-looking enhancements. Zero negative score impact. |

#### Step 1: Raw Domain Penalty Accumulation
For each domain $d \in \mathcal{D}$, the engine aggregates the penalties of all deduplicated defect findings belonging to that domain:

$$\text{RawPenalty}_d = \sum_{f \in \text{Findings}_d} P(\text{severity}(f))$$

#### Step 2: Domain-Level Penalty Capping
To ensure that a cluster of defects within a single domain does not disproportionately wipe out performance across unrelated domains, the accumulated penalty for any single domain is capped at $100.0$:

$$\text{CappedPenalty}_d = \min(\text{RawPenalty}_d, 100.0)$$

#### Step 3: Weighted Composite Penalty
The total composite penalty is calculated by taking the weighted sum across all four domains:

$$\text{TotalPenalty} = \sum_{d \in \mathcal{D}} w_d \cdot \text{CappedPenalty}_d$$

#### Step 4: Normalization & Clamping
The final composite readiness score $S$ is clamped to the range $[0.0, 100.0]$ and rounded to one decimal place:

$$S = \text{round}\Big(\max\big(0.0, \min(100.0, 100.0 - \text{TotalPenalty})\big), 1\Big)$$

#### Step 5: Letter Grade Derivation
The letter grade $G$ is derived from score $S$ using threshold boundaries defined in `thresholds.json`:

$$G = \begin{cases} 
\mathbf{A} & \text{if } S \ge 85.0 \\
\mathbf{B} & \text{if } 70.0 \le S < 85.0 \\
\mathbf{C} & \text{if } 55.0 \le S < 70.0 \\
\mathbf{D} & \text{if } 40.0 \le S < 55.0 \\
\mathbf{F} & \text{if } S < 40.0 
\end{cases}$$

### 5.2 Why the Score Is Causal

The scoring formulation is not an arbitrary point system. It reflects operational retrieval reality:

```text
Observable Technical Defect
             ↓
Specific Discovery / Extraction / Corroboration Risk
             ↓
Severity Level (Calibrated by retrieval impact)
             ↓
Bounded Domain Penalty
             ↓
Weighted Composite Readiness Score (0-100)
```

* **Zero Findings = Perfect Readiness**: If an audit discovers zero defects, $\text{TotalPenalty} = 0.0$, yielding an exact score of $100.0$ (`Grade A`).
* **Critical Finding Impact**: A single `critical` defect ($P = 25$) within `structured_fact_extraction` ($w = 0.30$) deducts $7.5$ points from the overall score. Four critical defects in that domain saturate its penalty ($100.0$), reducing the overall site score by the full $30.0$ points allocated to structured data.
* **Fault Isolation**: Even if a website fails completely in one domain (e.g. zero Schema.org data, losing 30 points), exceptional performance in crawlability, entity trust, and engagement allows the site to achieve a maximum possible score of $70.0$ (`Grade B`).

---

## 6. Installation, CLI Usage & Output Contract

### 6.1 Prerequisites

* **Operating System**: Windows, macOS, or Linux.
* **Python Runtime**: **Python 3.10+** (tested up to Python 3.13).
* **Dependencies**:
  * *Required*: `requests>=2.31.0`, `beautifulsoup4>=4.12.0`, `lxml>=5.0.0`
  * *Recommended*: `jsonschema>=4.21.0` (for strict JSON schema validation; a structural fallback validator runs if omitted)
  * *Optional*: `playwright>=1.43.0` (for headless DOM rendering; graceful SSR-fallback runs if omitted)

### 6.2 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/AkkiSensei/brand-ai-readiness-audit.git
cd brand-ai-readiness-audit

# Install required dependencies
pip install requests beautifulsoup4 lxml jsonschema

# Optional: Install Playwright for headless browser evaluation
pip install playwright
playwright install chromium
```

### 6.3 Command-Line Interface (CLI)

The audit orchestrator exposes a clean command-line interface via `aggregate.py`:

```bash
# Basic audit: emit pure JSON report to stdout
python skills/audit-orchestrator/scripts/aggregate.py https://example.com

# Limit crawl frontier scope (e.g. 5 pages max)
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --max-pages 5

# Export report directly to a file
python skills/audit-orchestrator/scripts/aggregate.py https://example.com --max-pages 10 --output audit_report.json
```

### 6.4 Stdout Purity Contract

The CLI is engineered to support seamless Unix pipeline integration:

$$\text{stdout} \longrightarrow \text{Pure, unpolluted JSON document}$$
$$\text{stderr} \longrightarrow \text{Diagnostic logging, error traces, status messages}$$

This strict separation guarantees that stdout can be directly piped into JSON parsers or automated downstream tooling:

```bash
python skills/audit-orchestrator/scripts/aggregate.py https://example.com | jq .summary
```

### 6.5 Output Contract & Schema

The output conforms strictly to `skills/audit-orchestrator/references/report.schema.json`. Below is a representative report payload:

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-09-03T16:44:23Z",
  "target_url": "https://example.com",
  "pages_audited": 4,
  "audit_duration_seconds": 5.02,
  "summary": {
    "total_findings": 9,
    "critical": 0,
    "high": 4,
    "medium": 3,
    "low": 0,
    "info": 2,
    "overall_score": 80.9,
    "grade": "B"
  },
  "coverage": {
    "crawl_render_access": {
      "pages_checked": 1,
      "checks_run": 1,
      "errors": 0
    },
    "structured_fact_extraction": {
      "pages_checked": 1,
      "checks_run": 1,
      "errors": 0
    },
    "trust_entity_corroboration": {
      "pages_checked": 1,
      "checks_run": 2,
      "errors": 0
    },
    "engagement_retention": {
      "pages_checked": 1,
      "checks_run": 3,
      "errors": 0
    }
  },
  "findings": [
    {
      "id": "F-001",
      "title": "No JSON-LD structured data found on any page",
      "severity": "high",
      "category": "discoverability",
      "evidence": "Scanned 1 pages; zero contained application/ld+json script blocks.",
      "suggested_action": {
        "summary": "Add Schema.org JSON-LD markup to at least the homepage (Organization), product pages (Product), and article pages (Article). This is critical for AI-engine fact extraction.",
        "priority": "high"
      },
      "related_to": []
    },
    {
      "id": "F-002",
      "title": "No sameAs links in Organization schema",
      "severity": "high",
      "category": "discoverability",
      "evidence": "No Organization JSON-LD block contains a sameAs property. AI engines cannot corroborate your brand identity against authoritative external profiles.",
      "suggested_action": {
        "summary": "Add a sameAs array to your Organization JSON-LD with links to your official Wikipedia page, Wikidata entry, LinkedIn company page, and verified social media profiles.",
        "priority": "high"
      },
      "related_to": [
        "F-001"
      ]
    },
    {
      "id": "F-008",
      "title": "No RSS or Atom feed detected",
      "severity": "info",
      "category": "proactive",
      "evidence": "No <link rel='alternate'> with type application/rss+xml or application/atom+xml was found across any crawled page.",
      "suggested_action": {
        "summary": "Publish an RSS or Atom feed for your blog, news, or product updates. Syndication feeds enable AI aggregators and citation engines to track your content freshness automatically.",
        "priority": "info"
      },
      "related_to": []
    }
  ],
  "proactive_recommendations": [
    "Add rel=canonical link elements: Canonical tags prevent duplicate content issues and consolidate link signals for AI citation engines.",
    "Create or link to a Wikidata entity: Wikidata is the primary knowledge base for many AI systems. A verified Wikidata entry with sameAs linking significantly improves entity recognition.",
    "Add contactPoint to Organization schema: ContactPoint structured data helps AI engines surface your customer service details in responses.",
    "Add skip-to-content navigation link: A 'Skip to main content' link improves accessibility and signals good UX practices to AI quality evaluators."
  ]
}
```

---

## 7. Generalization & Safety Guardrails

### 7.1 Generalization Mechanism

The audit engine does not rely on hard-coded selectors or brittle assumptions specific to individual websites. Instead, it evaluates fundamental web primitives that transcend site archetypes:

```text
Site Archetype (E-Commerce / B2B SaaS / Newsroom / Single-Page App / Portal)
                               │
                               ▼
                   Standard Web Primitives
 (HTTP Headers, Status Codes, robots.txt Directives, Sitemap XML,
  DOM Text Density, Schema.org Graph Triples, Viewport Meta, Anchor URIs)
                               │
                               ▼
                   Deterministic Rule Catalog
             (30 Defect Heuristics + 6 Proactive Checks)
                               │
                               ▼
              Normalized Finding Payload & Readiness Score
```

* **E-Commerce Platforms**: Evaluates `Product` JSON-LD availability, price metadata, image text-trapping (pricing in product graphics), and checkout CTA presence.
* **Single-Page Applications (SPAs)**: Detects severe CSR text-blanking ratios (`CR-003`), distinguishing server-rendered content from empty client-side DOM shells.
* **Publications & Blogs**: Evaluates `Article` schema, inverted-pyramid lead paragraphs (`PA-004`), RSS/Atom syndication feeds (`PA-005`), and content freshness timestamps (`SF-007`).
* **B2B SaaS Portals**: Audits `Organization` corporate identity, `sameAs` entity authority links, breadcrumb hierarchies on documentation pages (`ER-002`), and site search availability (`ER-008`).

### 7.2 Safety Guardrails & Operational Constraints

The audit engine is designed to operate safely as a read-only evaluation client against any public website:

* **Strict Read-Only Networking**: The `HttpClient` session issues only `GET` and `HEAD` HTTP requests. It never transmits `POST`, `PUT`, `PATCH`, or `DELETE` requests, eliminating any risk of state modification on target servers.
* **Per-Host Token-Bucket Rate Limiting**: The client enforces an unbypassable rate limit of **1 request per second per target host** (`RateLimiter(interval=1.0)`).
* **Robots.txt Adherence**: The crawler checks every URI against cached robots.txt rules prior to dispatching HTTP requests (`can_fetch()`). If the target origin disallows crawling, the crawler honors the restriction.
* **Response Size Capping**: HTTP response bodies are truncated at **5 MB** (`max_response_size_bytes: 5242880`), preventing memory-exhaustion attacks from accidental binary downloads.
* **Bounded Frontier Traversal**: Crawling is strictly capped at a default of 15 pages and a maximum link depth of 3 hops, preventing infinite loops on circular pagination paths or calendar traps.
* **Timeouts & Exponential Backoff**: Network calls enforce a 5-second connection timeout and an 8-second read timeout. Network retries use exponential backoff (`Retry(total=2, backoff_factor=0.5)`).
* **Stateless Sandboxing**: The engine requires zero persistent local databases, writes zero temporary scratch files during standard execution, and loads zero external neural model weights.

---

## 8. Verification & Test Suite

The repository includes an automated test suite confirming end-to-end operational integrity:

```bash
# Execute integration smoke test across all 4 domain runners
python tests/dry_run_test.py

# Execute complete end-to-end integration and schema contract test
python tests/test_end_to_end.py
```

### Verified Test Results

* **AST Syntax Verification**: All 10 Python source and test files pass Python AST syntax parsing with 0 errors.
* **Dry-Run Smoke Test**: All 4 domain runners execute cleanly against live targets without unhandled exceptions.
* **End-to-End Test**: The master orchestrator executes against `https://example.com`, parses stdout JSON, validates sequential `F-001..F-NNN` IDs, confirms severity ordering, verifies `related_to` cross-references, validates output against `report.schema.json`, and verifies that malformed test values are rejected.

---

## 9. License

This project is licensed under the **MIT License**. Created for the **Adobe University Hackathon 2026 — Round 3**.
