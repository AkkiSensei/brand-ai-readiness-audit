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
import os
import re
import sys
import time
import urllib.parse
import warnings
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

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

from http_client import AuditDeadline, HttpClient, PageResult, PlaywrightRenderer, is_ssrf_disallowed  # type: ignore[import]
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

def _normalise_finding(raw: Any, domain_name: str, target_url: str) -> dict:
    """Convert a Step-2 domain finding into the report-schema Finding shape."""
    if not isinstance(raw, dict):
        raw = {"title": str(raw), "evidence": str(raw)}

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

    finding = {
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

    if "source" in raw and raw["source"] in ("static", "rendered"):
        finding["source"] = raw["source"]

    pages_affected = raw.get("pages_affected")
    pages_checked = raw.get("pages_checked")
    if (
        pages_affected is not None
        and pages_checked is not None
        and pages_checked > 0
    ):
        conf = round(pages_affected / pages_checked, 2)
        finding["confidence"] = max(0.0, min(1.0, conf))

    return finding


# ===================================================================
# DEDUPLICATION
# ===================================================================

def _dedup_key(finding: dict) -> str:
    """Compute a normalised dedup key for a finding."""
    parts = [
        finding.get("category", ""),
        finding.get("severity", ""),
        finding.get("_local_id", ""),
        finding.get("title", "").lower().strip()[:120],
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
    """Sort canonically by severity (critical first), category, local_id, title, and evidence.
    
    Establishes a complete total order so that no two findings ever have an
    ambiguous or arrival-dependent relative ordering.
    """
    def sort_key(f: dict) -> tuple:
        sev = f.get("severity", "info")
        sev_idx = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 99
        cat = str(f.get("category", ""))
        lid = str(f.get("_local_id", "") or f.get("local_id", ""))
        title = str(f.get("title", ""))
        ev = f.get("evidence", "")
        ev_str = json.dumps(ev, sort_keys=True) if isinstance(ev, (dict, list)) else str(ev)
        return (sev_idx, cat, lid, title, ev_str)
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
        # Deduplicate and sort canonically
        unique_resolved = sorted(set(resolved))
        f["related_to"] = unique_resolved

    return findings


def _clean_internal_fields(findings: list[dict]) -> list[dict]:
    """Remove internal _-prefixed fields before schema validation."""
    for f in findings:
        for key in list(f.keys()):
            if key.startswith("_"):
                del f[key]
    return findings


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
            errors_list = result.get("errors", [])
            domain_low_conf = min(low_conf_count, pages_checked) if pages_checked > 0 else 0
            cov_entry: dict[str, Any] = {
                "pages_checked": pages_checked,
                "checks_run": len(result.get("findings", [])),
                "errors": len(errors_list),
                "render_confidence": "low" if domain_low_conf > 0 else "high",
                "pages_with_low_render_confidence": domain_low_conf,
            }
            if errors_list:
                cov_entry["notes"] = "; ".join(str(e) for e in errors_list[:3])
            elif domain_low_conf > 0:
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
    """Collect proactive_candidates from domain runners in canonical order as plain strings."""
    strings: list[str] = []
    seen: set[str] = set()
    canonical_domain_order = [
        "crawl-render-access",
        "structured-fact-extraction",
        "trust-entity-corroboration",
        "engagement-retention",
    ]
    for domain_name in canonical_domain_order:
        result = domain_results.get(domain_name)
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
            full = full.strip()
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
# ABORTED REPORT BUILDER (SSRF, UNREACHABLE)
# ===================================================================

def _build_aborted_report(
    target_url: str,
    status: str,
    message: str,
    elapsed: float,
    reason: Optional[str] = None,
    findings: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """Build a compliant report for blocked or unreachable targets."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_findings = findings or []
    norm_findings = []
    for idx, f in enumerate(raw_findings, 1):
        nf = _normalise_finding(f, "crawl-render-access", target_url)
        nf["id"] = f"F-{idx:03d}"
        norm_findings.append(nf)
    norm_findings = _clean_internal_fields(norm_findings)

    sev_counts: Counter[str] = Counter()
    for f in norm_findings:
        sev_counts[f.get("severity", "info")] += 1

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": now_iso,
        "audited_at": now_iso,
        "target_url": target_url,
        "site": target_url,
        "audit_status": status,
        "audit_status_message": message,
        "pages_audited": 0,
        "audit_duration_seconds": max(0.0, round(elapsed, 2)),
        "summary": {
            "total_findings": len(norm_findings),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
            "coverage": {
                "pages_audited": 0,
                "pages_in_sitemap": None,
                "budget_limited": False,
            },
        },
        "findings": norm_findings,
        "proactive_recommendations": [],
        "coverage": {
            "crawl_render_access": {
                "pages_checked": 0,
                "checks_run": 1 if norm_findings else 0,
                "errors": 1,
                "notes": message,
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
            },
            "structured_fact_extraction": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
            },
            "trust_entity_corroboration": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
            },
            "engagement_retention": {
                "pages_checked": 0,
                "checks_run": 0,
                "errors": 0,
                "notes": "Skipped: audit aborted",
                "render_confidence": "high",
                "pages_with_low_render_confidence": 0,
            },
            "pages_with_low_render_confidence": 0,
            "render_confidence": "high",
        },
    }
    if reason:
        report["blocked_reason"] = reason

    # Ensure schema validity on aborted reports
    valid, validation_errors = validate_report(report)
    if not valid:
        logger.warning("Aborted report schema validation failed: %s", validation_errors)
        dur = report.get("audit_duration_seconds")
        if not isinstance(dur, (int, float)) or dur < 0:
            report["audit_duration_seconds"] = 0.0
        for f in report.get("findings", []):
            if "evidence" not in f or not f["evidence"]:
                f["evidence"] = f"Audited on {target_url}"
            if "suggested_action" not in f or not isinstance(f["suggested_action"], dict):
                f["suggested_action"] = {
                    "summary": "Review and address this finding.",
                    "priority": f.get("severity", "info"),
                }
            if "related_to" not in f or not isinstance(f["related_to"], list):
                f["related_to"] = []
        validate_report(report)

    return report


# ===================================================================
# MAIN ENTRY POINT
# ===================================================================

def run_audit(
    target_url: str,
    max_pages: int = 15,
    timeout_s: int = 240,
    render_js: bool = False,
    renderer: Optional[PlaywrightRenderer] = None,
    allow_private_ips: bool = False,
    **kwargs: Any,
) -> dict:
    """Orchestrate the complete AI-readiness audit pipeline.

    Returns a fully validated JSON-Schema-compliant report dict.
    """
    t_start = time.monotonic()
    deadline: Optional[AuditDeadline] = kwargs.get("deadline")
    if deadline is None:
        deadline = AuditDeadline.from_budget(timeout_s, started_at=t_start)
    else:
        # Honor deadline's start time, but never allow future start times
        t_start = min(deadline.started_at, t_start)

    if "render_js" in kwargs:
        render_js = bool(kwargs["render_js"])
    if "renderer" in kwargs and kwargs["renderer"] is not None:
        renderer = kwargs["renderer"]
    if "allow_private_ips" in kwargs:
        allow_private_ips = bool(kwargs["allow_private_ips"])

    # --- Initialise HTTP client ---
    target_host = urllib.parse.urlparse(target_url).hostname or ""
    # Only permit loopback/private target destinations when explicitly passed via allow_private_ips=True
    is_local_target = bool(allow_private_ips) and (target_host in ("127.0.0.1", "localhost", "::1"))

    # Fast SSRF abort for disallowed targets
    if not is_local_target:
        disallowed, reason = is_ssrf_disallowed(target_host)
        if disallowed:
            elapsed = max(0.0, time.monotonic() - t_start)
            return _build_aborted_report(
                target_url,
                "blocked",
                f"Audit could not complete: target URL is blocked by SSRF protection ({reason}). Content was not inspected.",
                elapsed,
                reason="ssrf_disallowed",
            )

    client = HttpClient(allow_private_ips=is_local_target, deadline=deadline)

    own_renderer = False
    if render_js and renderer is None:
        try:
            renderer = PlaywrightRenderer(
                rate_limiter=client._limiter,
                robots_cache=client.robots,
                allow_private_ips=client._allow_private_ips,
                deadline=deadline,
                session=client._session,
                pin_manager=client._pin_manager,
            )
            own_renderer = True
        except Exception as exc:
            logger.warning("Failed to initialize PlaywrightRenderer: %s", exc)
            renderer = None
    elif renderer is not None:
        renderer.set_deadline(deadline)

    try:
        return _run_pipeline(
            target_url, max_pages, timeout_s, client, t_start,
            renderer=renderer, deadline=deadline,
        )
    finally:
        client.close()
        if own_renderer and renderer is not None:
            try:
                renderer.close()
            except Exception:
                pass


def _validate_and_sanitize_skill_output(raw_result: Any, domain_name: str) -> dict:
    """Validate and sanitize output from a domain audit runner.
    
    Guarantees that the orchestrator receives a well-formed dict matching:
      - domain: str
      - pages_analyzed: int >= 0
      - pages_discovered: int >= 0
      - errors: list[str]
      - findings: list[dict]
      - proactive_candidates: list
    Tolerates None, non-dict payloads, missing keys, and malformed findings.
    """
    if not isinstance(raw_result, dict):
        err = f"Domain {domain_name} returned non-dict payload of type {type(raw_result).__name__}"
        logger.warning(err)
        return {
            "domain": domain_name,
            "pages_analyzed": 0,
            "pages_discovered": 0,
            "errors": [err],
            "findings": [],
            "proactive_candidates": [],
        }

    try:
        pages_analyzed = max(0, int(raw_result.get("pages_analyzed", 0) or 0))
    except (ValueError, TypeError):
        pages_analyzed = 0

    try:
        pages_discovered = max(0, int(raw_result.get("pages_discovered", 0) or 0))
    except (ValueError, TypeError):
        pages_discovered = 0

    proactive_raw = raw_result.get("proactive_candidates", [])
    if isinstance(proactive_raw, (list, tuple)):
        proactive = list(proactive_raw)
    else:
        proactive = []

    sanitized: dict[str, Any] = {
        "domain": str(raw_result.get("domain", domain_name)),
        "pages_analyzed": pages_analyzed,
        "pages_discovered": pages_discovered,
        "errors": [str(e) for e in raw_result.get("errors", []) if e is not None],
        "findings": [],
        "proactive_candidates": proactive,
    }

    # Pass through optional crawl-render-access fields if present
    for opt_key in (
        "crawl_frontier", "page_results", "coverage", "network_requests",
        "performance_metrics", "rendered_word_count", "static_word_count", "csr_blanking_ratio"
    ):
        if opt_key in raw_result:
            sanitized[opt_key] = raw_result[opt_key]

    raw_findings = raw_result.get("findings", [])
    if isinstance(raw_findings, list):
        for f in raw_findings:
            if isinstance(f, dict):
                sanitized["findings"].append(f)
            else:
                logger.warning("Ignoring non-dict finding in domain %s: %r", domain_name, f)

    return sanitized


def _run_pipeline(
    target_url: str,
    max_pages: int,
    timeout_s: int,
    client: HttpClient,
    t_start: float,
    renderer: Optional[PlaywrightRenderer] = None,
    deadline: Optional[AuditDeadline] = None,
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
        crawl_raw = crawl_audit.run_audit(
            target_url, client, max_pages=max_pages, timeout_s=timeout_s, t_start=t_start,
            renderer=renderer, deadline=deadline,
        )
        crawl_result = _validate_and_sanitize_skill_output(crawl_raw, "crawl-render-access")
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
    # STEP 2: Early abort on blocked/failed crawl
    # ==============================================================
    pages_analyzed = crawl_result.get("pages_analyzed", 0)
    if pages_analyzed == 0:
        elapsed = max(0.0, time.monotonic() - t_start)

        # 1. Total connection failure / host refused / DNS failure / timeout
        if not page_results or all(pr.status_code is None for pr in page_results.values()):
            errors_list = [pr.error for pr in page_results.values() if pr.error]
            if not errors_list:
                errors_list = crawl_result.get("errors", [])
            err_msg = "; ".join(errors_list[:3]) or "Target connection failed."
            return _build_aborted_report(
                target_url,
                status="blocked",
                message=f"Audit could not complete: connection to target failed ({err_msg}). No content could be inspected.",
                elapsed=elapsed,
                reason="connection_failed",
            )

        # 2. Site-wide robots disallow
        if any(pr.error and "robots.txt disallows" in pr.error for pr in page_results.values()):
            robots_findings = [f for f in crawl_result.get("findings", []) if f.get("local_id") == "CR-001"]
            return _build_aborted_report(
                target_url,
                status="blocked",
                message="Audit could not complete: robots.txt disallows crawler access to root. Content was not inspected.",
                elapsed=elapsed,
                reason="robots_disallowed",
                findings=robots_findings,
            )

        # 3. All attempted pages returned active WAF / anti-bot challenge
        waf_findings = [
            f for f in crawl_result.get("findings", [])
            if f.get("local_id") == "CR-002" and f.get("severity") == "critical"
        ]
        if waf_findings and all(pr.status_code in (403, 429, 503, 202) for pr in page_results.values()):
            return _build_aborted_report(
                target_url,
                status="blocked",
                message="Audit blocked: target site presented active WAF / anti-bot challenge on all attempted requests.",
                elapsed=elapsed,
                reason="waf_bot_challenge",
                findings=waf_findings,
            )

    # ==============================================================
    # STEP 3: Site-wide block short-circuit
    # ==============================================================
    site_blocked = _is_site_wide_block(crawl_result)

    # ==============================================================
    # STEP 4: Downstream domain audits
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
        elapsed = max(0.0, time.monotonic() - t_start)
        if (deadline and deadline.expired()) or elapsed >= timeout_s:
            domain_results[domain_name] = {
                "domain": domain_name,
                "pages_analyzed": 0,
                "pages_discovered": 0,
                "errors": ["Skipped: timeout budget exhausted."],
                "findings": [],
                "proactive_candidates": [],
            }
            continue

        try:
            raw_res = module.run_audit(
                target_url,
                client,
                crawl_frontier=frontier,
                page_results=page_results,
                timeout_s=timeout_s,
                t_start=t_start,
                deadline=deadline,
            )
            domain_results[domain_name] = _validate_and_sanitize_skill_output(raw_res, domain_name)
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
    # STEP 5: Canonical Sort then Deduplicate
    # ==============================================================
    # Canonical sort first so deduplication order is 100% deterministic
    merged_sorted = _sort_findings(merged)
    deduped = _deduplicate(merged_sorted)
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
        interim_report, page_results, client, target_url, deadline=deadline,
    )

    # Normalise proactive findings
    for pf in proactive_findings:
        norm = _normalise_finding(pf, "proactive", target_url)
        norm["severity"] = "info"
        norm["category"] = "proactive"
        sorted_findings.append(norm)

    # Re-deduplicate after proactive injection using canonical sorting
    sorted_findings = _sort_findings(sorted_findings)
    sorted_findings = _deduplicate(sorted_findings)
    sorted_findings = _sort_findings(sorted_findings)

    # Re-assign IDs sequentially (gap-free)
    sorted_findings = _assign_ids(sorted_findings)

    # Re-resolve references
    sorted_findings = _resolve_related_to(sorted_findings)

    # Clean internal fields
    sorted_findings = _clean_internal_fields(sorted_findings)

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
    }

    # Propagate crawl coverage into summary
    crawl_cov = (domain_results.get("crawl-render-access") or {}).get("coverage")
    if crawl_cov is not None:
        summary["coverage"] = crawl_cov
    else:
        summary["coverage"] = {
            "pages_audited": 0,
            "pages_in_sitemap": None,
            "budget_limited": False,
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
    elapsed = max(0.0, time.monotonic() - t_start)

    timeout_skipped = any(
        res and any("timeout budget" in str(e).lower() for e in res.get("errors", []))
        for res in domain_results.values()
    )
    subsystem_failures = [
        domain_name for domain_name, res in domain_results.items()
        if res and any("exception" in str(e).lower() or "crashed" in str(e).lower() for e in res.get("errors", []))
    ]
    if timeout_skipped:
        overall_status = "partial"
        blocked_reason = "timeout_budget_exhausted"
        status_msg = "Audit completed partially: timeout budget was reached before all domain checks finished."
    elif subsystem_failures or all_errors:
        overall_status = "partial"
        blocked_reason = "subsystem_failure"
        failed_list = ", ".join(subsystem_failures) if subsystem_failures else "subsystem error"
        status_msg = f"Audit completed partially: failures in subsystem(s) [{failed_list}]."
    else:
        overall_status = "completed"
        blocked_reason = None
        status_msg = "Audit completed successfully."

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_url": target_url,
        "site": target_url,
        "audit_status": overall_status,
        "audit_status_message": status_msg,
        "pages_audited": (
            (domain_results.get("crawl-render-access") or {}).get("pages_analyzed")
            or len(frontier)
        ),
        "audit_duration_seconds": max(0.0, round(elapsed, 2)),
        "summary": summary,
        "findings": sorted_findings,
        "proactive_recommendations": proactive_strings,
        "coverage": coverage,
    }
    if blocked_reason is not None:
        report["blocked_reason"] = blocked_reason

    # Add optional rendered metrics if available from crawl_result
    crawl_res = domain_results.get("crawl-render-access") or {}
    if crawl_res.get("network_requests") is not None:
        report["network_requests"] = crawl_res["network_requests"]
    if crawl_res.get("performance_metrics") is not None:
        report["performance_metrics"] = crawl_res["performance_metrics"]
    if crawl_res.get("rendered_word_count") is not None:
        report["rendered_word_count"] = crawl_res["rendered_word_count"]
    if crawl_res.get("static_word_count") is not None:
        report["static_word_count"] = crawl_res["static_word_count"]
    if crawl_res.get("csr_blanking_ratio") is not None:
        report["csr_blanking_ratio"] = crawl_res["csr_blanking_ratio"]

    # ==============================================================
    # STEP 16: Schema validation & Repair
    # ==============================================================
    valid, validation_errors = validate_report(report)
    if not valid:
        logger.warning("Report schema validation failed: %s", validation_errors)
        # Attempt repair: guarantee non-negative duration
        dur = report.get("audit_duration_seconds")
        if not isinstance(dur, (int, float)) or dur < 0:
            report["audit_duration_seconds"] = max(0.0, round(time.monotonic() - t_start, 2))
        # Ensure all findings have required fields
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
        "--render-js", action="store_true", default=False,
        help="Enable Playwright headless JS rendering (default: False)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Path to write JSON report (default: stdout)",
    )
    args = parser.parse_args()

    report = run_audit(
        target_url=args.url,
        max_pages=args.max_pages,
        render_js=args.render_js,
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
