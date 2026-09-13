# Project Description: Brand AI-Readiness Audit

## Problem

When human buyers search the web today, they evaluate full visual web pages. When AI agents, answer engines, and citation aggregators (ChatGPT/SearchGPT, Claude, Perplexity, Google Gemini, and Microsoft Copilot) browse on behalf of users, they ingest websites through headless HTTP fetchers, DOM parsers, and entity extraction pipelines.

A brand website that relies on unrendered client-side JavaScript, lacks Schema.org JSON-LD entity markup, hides behind aggressive bot mitigation or location gates, or presents conflicting corporate data across pages **becomes invisible or hallucinated in AI answers**. Existing tools either require costly LLM API calls (non-deterministic, opinionated), lack security hardening for autonomous network access, or audit only surface SEO signals rather than machine-ingestion quality.

## Solution

The **Brand AI-Readiness Audit** is a modular, zero-model-weight evaluation marketplace built for the **Adobe University Hackathon 2026 (Round 3)**. It benchmarks any public brand URL against machine-ingestion standards and outputs an evidence-backed, schema-validated JSON report.

The system is a **five-skill marketplace** adhering to the `agentskills.io` standard, with one designated orchestrator entrypoint (`skills/audit-orchestrator/scripts/aggregate.py`) that coordinates four domain sub-skills operating over a shared in-memory pre-parsed DOM representation — eliminating duplicate network fetches.

## Key Differentiators

**Deterministic rule engine** — 30 defect heuristics and 7 proactive signals evaluate observable web primitives (HTTP headers, `robots.txt` AI-bot policies, DOM text ratios, Schema.org graphs, viewport tags) without non-deterministic LLM grading. Running against identical server responses produces deterministic, repeatable finding sets, severities, evidence, and remediation plans (excluding run timestamps and duration metadata).

**Zero model weights** — No multi-gigabyte local model files. No third-party LLM API keys. The submission archive is self-contained and lightweight, relying on standard Python parsing libraries.

**SSRF-hardened transport** — `DestinationPinningManager` inside `SSRFSafeHTTPAdapter` resolves DNS once, validates the IP against private-network blocklists, and pins the socket to that pre-validated address — neutralizing TOCTOU DNS-rebinding attacks. Only `http://` and `https://` schemes are accepted.

**Causal pipeline with short-circuit semantics** — If the target host is completely inaccessible (WAF block, SSRF sinkhole, robots disallow), the orchestrator emits a valid `"blocked"` report rather than crashing or silently producing empty output.

**Bounded execution** — A monotonic `AuditDeadline` (default 240 s) constrains all crawl, render, and analysis steps. The system gracefully halts and emits a partial but schema-valid report if the budget is exhausted.

**Beyond-defect strategic guidance** — The proactive recommendation engine (`PA-001`..`PA-006`, `PA-CANONICAL`) flags opportunities specific to generative AI: `/llms.txt` manifests, unified Schema.org `@graph` architectures, citation heading fragment IDs, answer-first article structure, and syndication feeds.

## Scope & Coverage

- **30 defect heuristics** across crawlability, structured data, entity trust, and engagement/retention.
- **7 proactive AI-readiness recommendations**.
- **299 automated regression tests** covering archetypes, adversarial hardening, security, chaos, determinism, generalization, and schema compliance.
- **11 synthetic website archetypes** validated: SPA, e-commerce, legacy HTML, editorial blog, paywalled content, hydration-dependent DOM, cookie/privacy overlay, i18n, WAF-challenged, geo-gated, and malformed non-HTML.
- **4 chaos scenarios**: zero-byte HTML, garbage DOM/JSON-LD, infinite redirect loops, TCP socket blackhole.

## Adobe Round 3 Relationship

This project was built specifically for Round 3 of the Adobe University Hackathon 2026, which requires:
- An agent skill marketplace with a compliant `marketplace.json` manifest.
- A designated single entrypoint skill.
- Recommend-only / read-only operation (no state mutation).
- `robots.txt` compliance per RFC 9309.
- Schema-validated, evidence-backed output.
- Proactive forward-looking recommendations beyond defect detection.
- Genuine skill composition (not a monolith disguised as a marketplace).

The marketplace satisfies all requirements through its five-skill architecture, SSRF-hardened transport, deterministic rule engine, and JSON Schema Draft-07 validated report contract.
