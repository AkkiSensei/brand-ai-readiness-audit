# Project Description: Brand AI-Readiness Audit

## Executive Pitch
When human buyers search the web today, they evaluate full visual web pages. But when AI agents, answer engines, and citation aggregators (ChatGPT/SearchGPT, Claude, Perplexity, Google Gemini, and Microsoft Copilot) browse on behalf of users, they ingest websites through headless HTTP fetchers, DOM parsers, and entity extraction pipelines. 

If a brand's web presence relies on unrendered client-side JavaScript, lacks Schema.org JSON-LD entity triples, hides behind intrusive location gates or aggressive bot mitigation, or presents conflicting corporate data, **that brand becomes invisible or hallucinated in AI answers**.

The **Brand AI-Readiness Audit** is a modular, zero-model-weight evaluation system developed for the **Adobe University Hackathon 2026 (Round 3)**. It benchmarks any public brand URL against machine-ingestion standards and outputs an evidence-backed, schema-validated JSON report.

---

## Key Features

* **Modular 5-Skill Marketplace Architecture**: Built strictly to the `agentskills.io` standard, separating transport/render analysis, structured data extraction, knowledge graph corroboration, engagement stability, and orchestration.
* **Deterministic Rule Engine (30 Defect Heuristics + 6 Proactive Signals)**: Evaluates observable web primitives (HTTP headers, robots.txt AI-bot policies, DOM text ratios, Schema.org graphs, viewport tags) without non-deterministic LLM grading or token costs.
* **Real-World Adversarial Hardening**: Proven against aggressive edge defense (Cloudflare/Akamai bot challenges, TLS connection tarpitting), location/pincode selection gates, DNS sinkholes, redirect loops, and socket blackholes.
* **Graceful Degradation & Bounded Execution**: Built-in per-host rate limiting (1 req/s), bounded wall-clock timeouts (8s read, 240s global budget), SSR fallback for environments without Playwright, and SSRF loopback protection.
* **Beyond-the-Defect Strategic Guidance**: Evaluates machine-readiness opportunities beyond errors—detecting `/llms.txt` presence, citation heading fragment IDs (`#section-id`), syndication feeds, and answer-first inverted pyramid text.
* **Strict JSON Schema Compliance**: Every emitted audit report strictly validates against `report.schema.json` with sequential, gap-free finding IDs (`F-001..F-NNN`) and resolved cross-references.

---

## Context & Distinctive Approach

Built as a submission for **Round 3 of the Adobe University Hackathon 2026**, this project rejects the common anti-pattern of using an ungrounded LLM prompt to "rate a website." Instead, it provides:

1. **Genuine Separation of Concerns**: Four domain sub-skills operate independently over shared pre-parsed DOM representations, eliminating duplicate network fetches.
2. **Empirical Grounding**: Developed and validated not merely on clean synthetic mockups, but across live commercial sites (including e-commerce, quick-commerce, and luxury retail) exhibiting real-world quirks like Akamai bot defense and pincode gates.
3. **Formal Governance**: Completely eliminates synthetic, hallucinated 0–100 scores from the core marketplace contract, returning pure objective findings, severity distributions, and crawler coverage metrics.
