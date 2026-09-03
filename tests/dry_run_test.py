"""
dry_run_test.py
===============
Integration smoke test for all 4 domain audit runners.

Initialises HttpClient, invokes run_audit("https://example.com", client) on
each script, and validates:
  1. All 4 run to completion without unhandled exceptions.
  2. The emitted payload keys match the contract.
  3. Findings and suggested_action are properly formatted.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add script paths
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))

from http_client import HttpClient

REQUIRED_KEYS = {"domain", "pages_analyzed", "pages_discovered", "errors", "findings", "proactive_candidates"}
FINDING_KEYS = {"local_id", "title", "severity", "category", "evidence", "suggested_action", "related_to"}
SUGGESTED_ACTION_KEYS = {"summary", "priority"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CATEGORIES = {"discoverability", "engagement"}
PROACTIVE_KEYS = {"title", "rationale", "priority"}

TARGET_URL = "https://example.com"


def validate_payload(name: str, payload: dict) -> list[str]:
    """Validate the payload structure and types against the contract."""
    issues: list[str] = []

    # Top-level keys
    missing_keys = REQUIRED_KEYS - set(payload.keys())
    if missing_keys:
        issues.append(f"Missing top-level keys: {missing_keys}")

    # Type checks
    if not isinstance(payload.get("domain"), str):
        issues.append("'domain' must be a string")
    if not isinstance(payload.get("pages_analyzed"), int):
        issues.append("'pages_analyzed' must be an int")
    if not isinstance(payload.get("pages_discovered"), int):
        issues.append("'pages_discovered' must be an int")
    if not isinstance(payload.get("errors"), list):
        issues.append("'errors' must be a list")
    if not isinstance(payload.get("findings"), list):
        issues.append("'findings' must be a list")
    if not isinstance(payload.get("proactive_candidates"), list):
        issues.append("'proactive_candidates' must be a list")

    # Validate each finding
    for i, finding in enumerate(payload.get("findings", [])):
        if not isinstance(finding, dict):
            issues.append(f"Finding [{i}] is not a dict")
            continue

        fmissing = FINDING_KEYS - set(finding.keys())
        if fmissing:
            issues.append(f"Finding [{i}] missing keys: {fmissing}")

        if finding.get("severity") not in VALID_SEVERITIES:
            issues.append(f"Finding [{i}] invalid severity: {finding.get('severity')}")

        if finding.get("category") not in VALID_CATEGORIES:
            issues.append(f"Finding [{i}] invalid category: {finding.get('category')}")

        if not isinstance(finding.get("evidence"), str):
            issues.append(f"Finding [{i}] 'evidence' must be a string")

        if not isinstance(finding.get("related_to"), list):
            issues.append(f"Finding [{i}] 'related_to' must be a list")

        sa = finding.get("suggested_action")
        if not isinstance(sa, dict):
            issues.append(f"Finding [{i}] 'suggested_action' must be a dict")
        else:
            sa_missing = SUGGESTED_ACTION_KEYS - set(sa.keys())
            if sa_missing:
                issues.append(f"Finding [{i}] suggested_action missing: {sa_missing}")
            if not isinstance(sa.get("summary"), str):
                issues.append(f"Finding [{i}] suggested_action.summary must be str")
            if sa.get("priority") not in VALID_SEVERITIES:
                issues.append(f"Finding [{i}] suggested_action.priority invalid: {sa.get('priority')}")

    # Validate proactive candidates
    for i, rec in enumerate(payload.get("proactive_candidates", [])):
        if not isinstance(rec, dict):
            issues.append(f"Proactive [{i}] is not a dict")
            continue
        pmissing = PROACTIVE_KEYS - set(rec.keys())
        if pmissing:
            issues.append(f"Proactive [{i}] missing keys: {pmissing}")
        if not isinstance(rec.get("title"), str):
            issues.append(f"Proactive [{i}] 'title' must be str")
        if not isinstance(rec.get("rationale"), str):
            issues.append(f"Proactive [{i}] 'rationale' must be str")

    return issues


def run_test():
    """Execute all 4 audit runners against example.com and validate."""
    print("=" * 70)
    print("DRY-RUN INTEGRATION TEST")
    print("=" * 70)
    print(f"Target: {TARGET_URL}\n")

    results: dict[str, dict] = {}
    overall_pass = True

    with HttpClient() as client:
        # Step 1: Run crawl audit (produces frontier)
        print("[1/4] crawl-render-access ...")
        t0 = time.monotonic()
        try:
            import crawl_audit
            crawl_result = crawl_audit.run_audit(TARGET_URL, client)
            elapsed = time.monotonic() - t0
            results["crawl-render-access"] = crawl_result
            print(f"      OK  ({elapsed:.1f}s)  "
                  f"findings={len(crawl_result['findings'])}  "
                  f"pages={crawl_result['pages_analyzed']}")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"      EXCEPTION ({elapsed:.1f}s): {exc}")
            overall_pass = False
            crawl_result = None

        # Extract frontier for downstream skills
        frontier = []
        page_results = {}
        if crawl_result:
            frontier = crawl_result.get("crawl_frontier", [TARGET_URL])
            page_results = crawl_result.get("page_results", {})

        kwargs = {"crawl_frontier": frontier, "page_results": page_results}

        # Step 2: Structured Fact Extraction
        print("[2/4] structured-fact-extraction ...")
        t0 = time.monotonic()
        try:
            import sfe_audit
            sfe_result = sfe_audit.run_audit(TARGET_URL, client, **kwargs)
            elapsed = time.monotonic() - t0
            results["structured-fact-extraction"] = sfe_result
            print(f"      OK  ({elapsed:.1f}s)  "
                  f"findings={len(sfe_result['findings'])}  "
                  f"pages={sfe_result['pages_analyzed']}")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"      EXCEPTION ({elapsed:.1f}s): {exc}")
            overall_pass = False

        # Step 3: Trust & Entity Corroboration
        print("[3/4] trust-entity-corroboration ...")
        t0 = time.monotonic()
        try:
            import tec_audit
            tec_result = tec_audit.run_audit(TARGET_URL, client, **kwargs)
            elapsed = time.monotonic() - t0
            results["trust-entity-corroboration"] = tec_result
            print(f"      OK  ({elapsed:.1f}s)  "
                  f"findings={len(tec_result['findings'])}  "
                  f"pages={tec_result['pages_analyzed']}")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"      EXCEPTION ({elapsed:.1f}s): {exc}")
            overall_pass = False

        # Step 4: Engagement & Retention
        print("[4/4] engagement-retention ...")
        t0 = time.monotonic()
        try:
            import er_audit
            er_result = er_audit.run_audit(TARGET_URL, client, **kwargs)
            elapsed = time.monotonic() - t0
            results["engagement-retention"] = er_result
            print(f"      OK  ({elapsed:.1f}s)  "
                  f"findings={len(er_result['findings'])}  "
                  f"pages={er_result['pages_analyzed']}")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"      EXCEPTION ({elapsed:.1f}s): {exc}")
            overall_pass = False

    # --- Contract Validation ---
    print("\n" + "=" * 70)
    print("CONTRACT VALIDATION")
    print("=" * 70)

    for domain, payload in results.items():
        issues = validate_payload(domain, payload)
        if issues:
            print(f"\nFAIL  {domain}:")
            for issue in issues:
                print(f"      - {issue}")
            overall_pass = False
        else:
            print(f"PASS  {domain}  (contract validated)")

    # --- Summary ---
    print("\n" + "=" * 70)
    total_findings = sum(len(r.get("findings", [])) for r in results.values())
    total_proactive = sum(len(r.get("proactive_candidates", [])) for r in results.values())
    total_errors = sum(len(r.get("errors", [])) for r in results.values())
    print(f"Total findings:    {total_findings}")
    print(f"Total proactive:   {total_proactive}")
    print(f"Total soft errors: {total_errors}")
    print("=" * 70)

    if overall_pass:
        print("\n*** ALL 4 DOMAIN AUDITS PASSED ***")
        return 0
    else:
        print("\n*** SOME CHECKS FAILED ***")
        return 1


if __name__ == "__main__":
    sys.exit(run_test())
