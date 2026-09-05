"""
aggregate.py
============
Audit Orchestrator — master integration entrypoint.

Coordinates crawl, downstream domain audits (SFE, TEC, ER), merges findings,
deduplicates, cross-references, scores, grades, injects proactive
recommendations, validates against the report JSON Schema, and emits the
final report.

Public API:
    run_audit(target_url, max_pages=15, timeout_s=240, **kwargs) -> dict

CLI:
    python aggregate.py <url> [--max-pages N] [--output path.json]
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ORCH_SCRIPTS = Path(__file__).resolve().parent
_ROOT = _ORCH_SCRIPTS.parent.parent  # skills/

_HTTP_SCRIPTS = _ROOT / "crawl-render-access" / "scripts"
_SFE_SCRIPTS = _ROOT / "structured-fact-extraction" / "scripts"
_TEC_SCRIPTS = _ROOT / "trust-entity-corroboration" / "scripts"
_ER_SCRIPTS = _ROOT / "engagement-retention" / "scripts"

for p in (_HTTP_SCRIPTS, _SFE_SCRIPTS, _TEC_SCRIPTS, _ER_SCRIPTS, _ORCH_SCRIPTS):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from http_client import HttpClient, PageResult  # type: ignore[import]
import crawl_audit  # type: ignore[import]
import sfe_audit  # type: ignore[import]
import tec_audit  # type: ignore[import]
import er_audit  # type: ignore[import]

from proactive_engine import inject_proactive_recommendations  # type: ignore[import]
from schema_validate import validate_report  # type: ignore[import]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_THRESH_PATH = _ORCH_SCRIPTS.parent / "references" / "thresholds.json"


def _load_thresholds() -> dict:
    try:
        return json.loads(_THRESH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_T = _load_thresholds()
_SCORING = _T.get("scoring", {})
_WEIGHTS: dict[str, float] = _SCORING.get("weights", {
    "crawl_render_access": 0.25,
    "structured_fact_extraction": 0.30,
    "trust_entity_corroboration": 0.25,
    "engagement_retention": 0.20,
})
_SEVERITY_PENALTY: dict[str, int] = _SCORING.get("severity_penalty", {
    "critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0,
})
_GRADE_THRESHOLDS: dict[str, int] = _SCORING.get("grade_thresholds", {
    "A": 85, "B": 70, "C": 55, "D": 40, "F": 0,
})

# Map from domain runner "domain" string -> schema category key
_DOMAIN_TO_CATEGORY: dict[str, str] = {
    "crawl-render-access": "crawl_render_access",
    "structured-fact-extraction": "structured_fact_extraction",
    "trust-entity-corroboration": "trust_entity_corroboration",
    "engagement-retention": "engagement_retention",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ===================================================================
# NORMALISATION: domain findings -> schema findings
# ===================================================================

def _normalise_finding(raw: dict, domain_name: str, target_url: str) -> dict:
    """Convert a Step-2 domain finding into the report-schema Finding shape."""
    # Category normalisation
    raw_cat = raw.get("category", "")
    valid_cats = {
        "discoverability", "engagement", "proactive",
        "crawl_render_access", "structured_fact_extraction",
        "trust_entity_corroboration", "engagement_retention",
    }
    if raw_cat in valid_cats:
        category = raw_cat
    else:
        category = _DOMAIN_TO_CATEGORY.get(domain_name, "discoverability")

    # Evidence: keep string or dict, ensure length >= 3
    raw_evidence = raw.get("evidence", "")
    if isinstance(raw_evidence, str):
        evidence = raw_evidence if len(raw_evidence) >= 3 else raw_evidence.ljust(3, ".")
    elif isinstance(raw_evidence, dict):
        if "url" not in raw_evidence:
            raw_evidence["url"] = target_url
        evidence = raw_evidence
    else:
        evidence = str(raw_evidence)
        if len(evidence) < 3:
            evidence = evidence.ljust(3, ".")

    # Title: clamp length
    title = str(raw.get("title", "Untitled finding"))[:120]
    if len(title) < 5:
        title = title.ljust(5, ".")

    severity = raw.get("severity", "info")
    if severity not in _SEVERITY_ORDER:
        severity = "info"

    # Suggested action: object with summary and priority
    raw_action = raw.get("suggested_action", {})
    if isinstance(raw_action, dict):
        summary_str = str(raw_action.get("summary", "")).strip()
        prio_str = str(raw_action.get("priority", severity)).strip()
        if len(summary_str) < 5:
            summary_str = summary_str.ljust(5, ".") if summary_str else "Review and address this finding."
        if prio_str not in _SEVERITY_ORDER:
            prio_str = severity if severity in _SEVERITY_ORDER else "info"
        suggested_action = {"summary": summary_str, "priority": prio_str}
    elif isinstance(raw_action, str):
        summary_str = raw_action.strip()
        if len(summary_str) < 5:
            summary_str = summary_str.ljust(5, ".") if summary_str else "Review and address this finding."
        suggested_action = {"summary": summary_str, "priority": severity}
    else:
        suggested_action = {"summary": "Review and address this finding.", "priority": severity}

    return {
        "_local_id": raw.get("local_id", ""),
        "local_id": raw.get("local_id", ""),
        "_domain": domain_name,
        "_related_to_local": list(raw.get("related_to", [])),
        "id": "",  # assigned after dedup + ordering
        "title": title,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "suggested_action": suggested_action,
        "related_to": [],
    }


# ===================================================================
# DEDUPLICATION
# ===================================================================

def _dedup_key(finding: dict) -> str:
    """Compute a normalised dedup key for a finding."""
    parts = [
        finding.get("category", ""),
        finding.get("severity", ""),
        finding.get("_local_id", ""),
        finding.get("title", "").lower().strip()[:80],
    ]
    return "|".join(parts)


def _deduplicate(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings, keeping the first occurrence."""
    seen: set[str] = set()
    result: list[dict] = []
    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


# ===================================================================
# ORDERING + ID ASSIGNMENT
# ===================================================================

def _sort_findings(findings: list[dict]) -> list[dict]:
    """Sort by severity (critical first), then category, then title."""
    def sort_key(f: dict) -> tuple:
        sev = f.get("severity", "info")
        sev_idx = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 99
        return (sev_idx, f.get("category", ""), f.get("title", ""))
    return sorted(findings, key=sort_key)


def _assign_ids(findings: list[dict]) -> list[dict]:
    """Assign sequential F-001..F-NNN IDs after dedup+sort."""
    for i, f in enumerate(findings, start=1):
        f["id"] = f"F-{i:03d}"
    return findings


# ===================================================================
# CROSS-REFERENCING
# ===================================================================

def _resolve_related_to(findings: list[dict]) -> list[dict]:
    """Resolve _related_to_local references to final F-XXX IDs."""
    # Build local_id -> final_id map
    local_to_final: dict[str, str] = {}
    for f in findings:
        lid = f.get("_local_id", "") or f.get("local_id", "")
        if lid:
            local_to_final[lid] = f["id"]

    final_ids = {f["id"] for f in findings}

    for f in findings:
        related_local = f.get("_related_to_local", [])
        resolved: list[str] = []
        for ref in related_local:
            if ref in final_ids and ref != f["id"]:
                resolved.append(ref)
            else:
                final = local_to_final.get(ref)
                if final and final != f["id"] and final in final_ids:
                    resolved.append(final)
        # Deduplicate while preserving order
        seen_refs: set[str] = set()
        deduped_resolved: list[str] = []
        for r in resolved:
            if r not in seen_refs:
                seen_refs.add(r)
                deduped_resolved.append(r)
        f["related_to"] = deduped_resolved

    return findings


def _clean_internal_fields(findings: list[dict]) -> list[dict]:
    """Remove internal _-prefixed fields before schema validation."""
    for f in findings:
        for key in list(f.keys()):
            if key.startswith("_"):
                del f[key]
    return findings


# ===================================================================
# SCORING + GRADING
# ===================================================================

def _compute_score(findings: list[dict]) -> float:
    """Compute composite 0-100 readiness score from findings.

    Algorithm:
      - Start at 100.
      - For each domain, accumulate weighted penalties.
      - Subtract penalties; clamp to [0, 100].
    """
    domain_penalties: dict[str, float] = {k: 0.0 for k in _WEIGHTS}

    domain_to_key = {
        "crawl-render-access": "crawl_render_access",
        "structured-fact-extraction": "structured_fact_extraction",
        "trust-entity-corroboration": "trust_entity_corroboration",
        "engagement-retention": "engagement_retention",
    }

    for f in findings:
        domain = f.get("_domain", "")
        key = domain_to_key.get(domain)
        if not key:
            cat = f.get("category", "")
            if cat in domain_penalties:
                key = cat
            elif cat == "engagement":
                key = "engagement_retention"
            elif cat == "discoverability":
                key = "crawl_render_access"
        severity = f.get("severity", "info")
        penalty = _SEVERITY_PENALTY.get(severity, 0)
        if key and key in domain_penalties:
            domain_penalties[key] += penalty

    total_penalty = 0.0
    for domain, weight in _WEIGHTS.items():
        # Cap per-domain penalty at 100 (before weighting)
        raw = min(domain_penalties.get(domain, 0.0), 100.0)
        total_penalty += raw * weight

    score = max(0.0, min(100.0, 100.0 - total_penalty))
    return round(score, 1)


def _compute_grade(score: float) -> str:
    """Derive letter grade from score using configured thresholds."""
    for grade in ("A", "B", "C", "D"):
        threshold = _GRADE_THRESHOLDS.get(grade, 0)
        if score >= threshold:
            return grade
    return "F"


# ===================================================================
# COVERAGE
# ===================================================================

def _build_coverage(
    domain_results: dict[str, dict | None],
    findings: list[dict],
    frontier: Optional[list] = None,
) -> dict:
    """Build per-domain SkillCoverage objects and surface render confidence."""
    coverage: dict[str, Any] = {}

    crawl_res = domain_results.get("crawl-render-access") or {}
    crawl_frontier = frontier if frontier is not None else crawl_res.get("crawl_frontier", [])
    page_results = crawl_res.get("page_results", {})

    low_conf_count = 0
    for u in crawl_frontier:
        conf = getattr(u, "render_confidence", None)
        if conf is None and isinstance(u, dict):
            conf = u.get("render_confidence")
        if conf is None and isinstance(u, str) and u in page_results:
            conf = getattr(page_results[u], "render_confidence", None)
        if conf == "low":
            low_conf_count += 1

    total_pages = len(crawl_frontier) if crawl_frontier else max(
        1, crawl_res.get("pages_discovered", 1)
    )

    for domain_key, schema_key in [
        ("crawl-render-access", "crawl_render_access"),
        ("structured-fact-extraction", "structured_fact_extraction"),
        ("trust-entity-corroboration", "trust_entity_corroboration"),
        ("engagement-retention", "engagement_retention"),
    ]:
        result = domain_results.get(domain_key)
        if result is None:
            coverage[schema_key] = {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Domain audit was skipped or failed.",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
            }
        else:
            pages_checked = result.get("pages_analyzed", 0)
            domain_low_conf = min(low_conf_count, pages_checked) if pages_checked > 0 else 0
            cov_entry: dict[str, Any] = {
                "pages_checked": pages_checked,
                "checks_run": len(result.get("findings", [])),
                "errors": len(result.get("errors", [])),
                "render_confidence": "low" if domain_low_conf > 0 else "high",
                "pages_with_low_render_confidence": domain_low_conf,
            }
            if domain_low_conf > 0:
                pct = round((domain_low_conf / total_pages) * 100)
                if schema_key == "crawl_render_access":
                    cov_entry["notes"] = (
                        f"{domain_low_conf} of {total_pages} page(s) ({pct}%) had low render confidence "
                        "(text blanking detected without successful JS render)."
                    )
                else:
                    domain_label = schema_key.replace("_", " ")
                    cov_entry["notes"] = (
                        f"{domain_low_conf} of {total_pages} page(s) ({pct}%) had low render confidence; "
                        f"{domain_label} checks ran on unrendered content rather than passing verified checks."
                    )
            coverage[schema_key] = cov_entry

    coverage["pages_with_low_render_confidence"] = low_conf_count
    coverage["render_confidence"] = "low" if low_conf_count > 0 else "high"

    return coverage


# ===================================================================
# PROACTIVE_RECOMMENDATIONS (string list for schema)
# ===================================================================

def _build_proactive_strings(
    domain_results: dict[str, dict | None],
) -> list[str]:
    """Collect proactive_candidates from domain runners as plain strings."""
    strings: list[str] = []
    seen: set[str] = set()
    for result in domain_results.values():
        if result is None:
            continue
        for rec in result.get("proactive_candidates", []):
            if isinstance(rec, dict):
                text = rec.get("title", "")
                rationale = rec.get("rationale", "")
                if text and rationale:
                    full = f"{text}: {rationale}"
                elif text:
                    full = text
                else:
                    full = rationale
            elif isinstance(rec, str):
                full = rec
            else:
                continue
            if full and full not in seen and len(full) >= 10:
                seen.add(full)
                strings.append(full)
    return strings


# ===================================================================
# SITE-WIDE BLOCK DETECTION
# ===================================================================

def _is_site_wide_block(crawl_result: dict) -> bool:
    """Check if CR-001 indicates a site-wide critical block."""
    for f in crawl_result.get("findings", []):
        lid = f.get("local_id", "")
        sev = f.get("severity", "")
        if lid == "CR-001" and sev == "critical":
            ev = f.get("evidence", "")
            if isinstance(ev, str):
                blocked_count_match = re.search(r"(\d+)\s+AI\s+crawler", ev)
                if blocked_count_match:
                    count = int(blocked_count_match.group(1))
                    # Site-wide if majority (>= 10 of 14) crawlers are blocked
                    if count >= 10:
                        return True
    return False


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================

def run_audit(
    target_url: str,
    max_pages: int = 15,
    timeout_s: int = 240,
    **kwargs: Any,
) -> dict:
    """Orchestrate the complete AI-readiness audit pipeline.

    Returns a fully validated JSON-Schema-compliant report dict.
    """
    t_start = time.monotonic()

    # --- Initialise HTTP client ---
    client = HttpClient()

    try:
        return _run_pipeline(target_url, max_pages, timeout_s, client, t_start)
    finally:
        client.close()


def _run_pipeline(
    target_url: str,
    max_pages: int,
    timeout_s: int,
    client: HttpClient,
    t_start: float,
) -> dict:
    """Internal pipeline — separated for testability."""
    domain_results: dict[str, dict | None] = {
        "crawl-render-access": None,
        "structured-fact-extraction": None,
        "trust-entity-corroboration": None,
        "engagement-retention": None,
    }
    all_errors: list[str] = []

    # ==============================================================
    # STEP 1: Crawl audit (produces frontier)
    # ==============================================================
    try:
        crawl_result = crawl_audit.run_audit(
            target_url, client, max_pages=max_pages,
        )
        domain_results["crawl-render-access"] = crawl_result
    except Exception as exc:
        all_errors.append(f"crawl-render-access crashed: {exc}")
        crawl_result = {
            "findings": [], "errors": [str(exc)],
            "crawl_frontier": [target_url], "page_results": {},
            "pages_analyzed": 0, "pages_discovered": 0,
            "proactive_candidates": [], "domain": "crawl-render-access",
        }
        domain_results["crawl-render-access"] = crawl_result

    frontier: list[str] = crawl_result.get("crawl_frontier", [target_url])
    page_results: dict[str, PageResult] = crawl_result.get("page_results", {})

    # ==============================================================
    # STEP 2: Site-wide block short-circuit
    # ==============================================================
    site_blocked = _is_site_wide_block(crawl_result)

    # ==============================================================
    # STEP 3: Downstream domain audits
    # ==============================================================
    downstream = [
        ("structured-fact-extraction", sfe_audit),
        ("trust-entity-corroboration", tec_audit),
        ("engagement-retention", er_audit),
    ]

    for domain_name, module in downstream:
        if site_blocked:
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": ["Skipped: site-wide AI-crawler block detected."],
                "findings": [],
                "proactive_candidates": [],
            }
            continue

        # Check timeout budget
        elapsed = time.monotonic() - t_start
        if elapsed >= timeout_s:
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": [f"Skipped: timeout budget exhausted ({elapsed:.0f}s >= {timeout_s}s)."],
                "findings": [],
                "proactive_candidates": [],
            }
            continue

        try:
            result = module.run_audit(
                target_url,
                client,
                crawl_frontier=frontier,
                page_results=page_results,
            )
            domain_results[domain_name] = result
        except Exception as exc:
            all_errors.append(f"{domain_name} crashed: {exc}")
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": [f"Domain runner exception: {exc}"],
                "findings": [],
                "proactive_candidates": [],
            }

    # ==============================================================
    # STEP 4: Merge findings from all domains
    # ==============================================================
    merged: list[dict] = []
    for domain_name, result in domain_results.items():
        if result is None:
            continue
        for raw_finding in result.get("findings", []):
            normalised = _normalise_finding(raw_finding, domain_name, target_url)
            merged.append(normalised)

    # ==============================================================
    # STEP 5: Deduplicate
    # ==============================================================
    deduped = _deduplicate(merged)

    # ==============================================================
    # STEP 6: Sort by severity
    # ==============================================================
    sorted_findings = _sort_findings(deduped)

    # ==============================================================
    # STEP 7: Assign sequential IDs
    # ==============================================================
    sorted_findings = _assign_ids(sorted_findings)

    # ==============================================================
    # STEP 8: Resolve related_to cross-references
    # ==============================================================
    sorted_findings = _resolve_related_to(sorted_findings)

    # ==============================================================
    # STEP 9: Build intermediate report for proactive engine
    # ==============================================================
    interim_report = {"findings": sorted_findings}

    # ==============================================================
    # STEP 10: Proactive recommendations (PA-001..PA-006)
    # ==============================================================
    proactive_findings = inject_proactive_recommendations(
        interim_report, page_results, client, target_url,
    )

    # Normalise proactive findings
    for pf in proactive_findings:
        norm = _normalise_finding(pf, "proactive", target_url)
        norm["severity"] = "info"
        norm["category"] = "proactive"
        sorted_findings.append(norm)

    # Re-deduplicate after proactive injection
    sorted_findings = _deduplicate(sorted_findings)

    # Re-sort: severity order maintained (info = proactive at end)
    sorted_findings = _sort_findings(sorted_findings)

    # Re-assign IDs sequentially (gap-free)
    sorted_findings = _assign_ids(sorted_findings)

    # Re-resolve references
    sorted_findings = _resolve_related_to(sorted_findings)

    # Clean internal fields
    sorted_findings = _clean_internal_fields(sorted_findings)

    # ==============================================================
    # STEP 11: Scoring + grading
    # ==============================================================
    score = _compute_score(sorted_findings)
    grade = _compute_grade(score)

    # ==============================================================
    # STEP 12: Summary
    # ==============================================================
    sev_counts: Counter[str] = Counter()
    for f in sorted_findings:
        sev_counts[f.get("severity", "info")] += 1

    summary = {
        "total_findings": len(sorted_findings),
        "critical": sev_counts.get("critical", 0),
        "high": sev_counts.get("high", 0),
        "medium": sev_counts.get("medium", 0),
        "low": sev_counts.get("low", 0),
        "info": sev_counts.get("info", 0),
        "overall_score": score,
        "grade": grade,
    }

    # ==============================================================
    # STEP 13: Coverage
    # ==============================================================
    coverage = _build_coverage(domain_results, sorted_findings, frontier=frontier)

    # ==============================================================
    # STEP 14: Proactive recommendation strings
    # ==============================================================
    proactive_strings = _build_proactive_strings(domain_results)

    # ==============================================================
    # STEP 15: Assemble report
    # ==============================================================
    elapsed = time.monotonic() - t_start
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_url": target_url,
        "pages_audited": (
            (domain_results.get("crawl-render-access") or {}).get("pages_analyzed")
            or len(frontier)
        ),
        "audit_duration_seconds": round(elapsed, 2),
        "summary": summary,
        "findings": sorted_findings,
        "proactive_recommendations": proactive_strings,
        "coverage": coverage,
    }

    # ==============================================================
    # STEP 16: Schema validation
    # ==============================================================
    valid, validation_errors = validate_report(report)
    if not valid:
        logger.warning("Report schema validation failed: %s", validation_errors)
        # Attempt repair: ensure all findings have required fields
        for f in report["findings"]:
            if "evidence" not in f or not f["evidence"]:
                f["evidence"] = f"Audited on {target_url}"
            if "suggested_action" not in f or not isinstance(f["suggested_action"], dict):
                f["suggested_action"] = {
                    "summary": "Review and address this finding.",
                    "priority": f.get("severity", "info"),
                }
            if "related_to" not in f or not isinstance(f["related_to"], list):
                f["related_to"] = []
        # Re-validate
        valid, validation_errors = validate_report(report)
        if not valid:
            logger.error("Report still invalid after repair: %s", validation_errors)

    return report


# ===================================================================
# CLI
# ===================================================================

def _cli() -> None:
    """Command-line interface for the audit orchestrator."""
    # Send logging to stderr so stdout is clean JSON
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Brand AI Readiness Audit — orchestrator",
    )
    parser.add_argument("url", help="Target URL to audit")
    parser.add_argument(
        "--max-pages", type=int, default=15,
        help="Maximum pages to crawl (default: 15)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Path to write JSON report (default: stdout)",
    )
    args = parser.parse_args()

    report = run_audit(
        target_url=args.url,
        max_pages=args.max_pages,
    )

    report_json = json.dumps(report, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report_json, encoding="utf-8")
        print(f"Report written to {out_path}", file=sys.stderr)
    else:
        print(report_json)


if __name__ == "__main__":
    _cli()
