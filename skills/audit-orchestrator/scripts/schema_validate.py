"""
schema_validate.py
==================
Report schema validation for brand-ai-readiness-audit.

Public API:
    validate_report(report_data: dict) -> tuple[bool, list[str]]
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "references" / "report.schema.json"
)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CATEGORIES = {
    "discoverability",
    "engagement",
    "proactive",
    "crawl_render_access",
    "structured_fact_extraction",
    "trust_entity_corroboration",
    "engagement_retention",
}
_DOMAIN_COVERAGE_KEYS = {
    "crawl_render_access",
    "structured_fact_extraction",
    "trust_entity_corroboration",
    "engagement_retention",
}
_COVERAGE_KEYS = _DOMAIN_COVERAGE_KEYS | {
    "pages_with_low_render_confidence",
    "render_confidence",
    "overall_state",
    "limitations",
}

_TOP_LEVEL_ALLOWED = {
    "schema_version",
    "generated_at",
    "audited_at",
    "target_url",
    "site",
    "audit_status",
    "blocked_reason",
    "audit_status_message",
    "pages_audited",
    "audit_duration_seconds",
    "summary",
    "findings",
    "proactive_recommendations",
    "remediation_themes",
    "coverage",
}
_SUMMARY_ALLOWED = {
    "total_findings",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "coverage",
}
_SUMMARY_COVERAGE_ALLOWED = {
    "pages_audited",
    "pages_in_sitemap",
    "budget_limited",
}
_FINDING_ALLOWED = {
    "id",
    "local_id",
    "title",
    "severity",
    "category",
    "evidence",
    "suggested_action",
    "related_to",
    "references",
    "duplicate_of",
    "confidence",
    "source",
    "location",
    "why_it_matters",
    "remediation_theme",
}


def _load_schema() -> dict | None:
    """Load report.schema.json from disk."""
    try:
        return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not load report schema: %s", exc)
        return None


def validate_report(report_data: dict) -> tuple[bool, list[str]]:
    """Validate *report_data* against the report schema.

    Returns:
        (True,  [])            if the report is valid.
        (False, [err1, ...])   if validation errors are found.
    """
    rel_errors: list[str] = []
    if isinstance(report_data, dict):
        findings = report_data.get("findings")
        if isinstance(findings, list):
            fids = {f.get("id") for f in findings if isinstance(f, dict) and "id" in f}
            for i, f in enumerate(findings):
                if isinstance(f, dict) and "related_to" in f:
                    rt = f["related_to"]
                    if isinstance(rt, list):
                        fid = f.get("id")
                        for ref in rt:
                            if isinstance(ref, str):
                                if ref == fid:
                                    rel_errors.append(
                                        f"findings[{i}].related_to contains self-reference to '{fid}'"
                                    )
                                elif ref not in fids:
                                    rel_errors.append(
                                        f"findings[{i}].related_to contains dangling reference to nonexistent ID '{ref}'"
                                    )

    # --- Try jsonschema first ---
    try:
        import jsonschema  # type: ignore[import]
        schema = _load_schema()
        if schema is not None:
            ok, js_errors = _validate_with_jsonschema(report_data, schema)
            all_errors = js_errors + rel_errors
            return (len(all_errors) == 0, all_errors)
    except ImportError:
        logger.info("jsonschema not installed; using built-in fallback validator.")
    except Exception as exc:
        logger.warning("jsonschema validation failed unexpectedly (%s); falling back.", exc)

    # --- Fallback ---
    ok, fb_errors = _validate_fallback(report_data)
    all_errors = fb_errors + [e for e in rel_errors if e not in fb_errors]
    return (len(all_errors) == 0, all_errors)


# ------------------------------------------------------------------
# jsonschema-based validation
# ------------------------------------------------------------------

def _validate_with_jsonschema(
    report_data: dict, schema: dict,
) -> tuple[bool, list[str]]:
    """Validate using the jsonschema library."""
    import jsonschema  # type: ignore[import]

    errors: list[str] = []
    validator_cls = jsonschema.Draft7Validator
    validator = validator_cls(schema)
    for err in sorted(validator.iter_errors(report_data), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{path}: {err.message}")
    return (len(errors) == 0, errors)


# ------------------------------------------------------------------
# Built-in fallback validator
# ------------------------------------------------------------------

def _validate_fallback(report_data: dict) -> tuple[bool, list[str]]:
    """Structural validation without jsonschema."""
    errors: list[str] = []

    if not isinstance(report_data, dict):
        return (False, ["Report root must be an object/dict."])

    # --- Unexpected top-level keys ---
    extra_top = set(report_data.keys()) - _TOP_LEVEL_ALLOWED
    if extra_top:
        errors.append(f"Report root has unexpected keys: {extra_top}")

    # --- Required top-level keys ---
    for key in ("schema_version", "generated_at", "audited_at", "target_url", "site", "summary", "findings"):
        if key not in report_data:
            errors.append(f"Missing required top-level key: '{key}'")

    # --- Type checks ---
    _check_type(report_data, "schema_version", str, errors)
    _check_type(report_data, "generated_at", str, errors)
    _check_type(report_data, "audited_at", str, errors)
    _check_type(report_data, "target_url", str, errors)
    _check_type(report_data, "site", str, errors)
    _check_type(report_data, "audit_status", str, errors, optional=True)
    if "audit_status" in report_data and report_data["audit_status"] is not None:
        if report_data["audit_status"] not in ("completed", "partial", "blocked"):
            errors.append(
                f"audit_status must be 'completed', 'partial', or 'blocked', got '{report_data['audit_status']}'"
            )
    _check_type(report_data, "blocked_reason", str, errors, optional=True)
    _check_type(report_data, "audit_status_message", str, errors, optional=True)
    _check_type(report_data, "pages_audited", int, errors, optional=True)
    if "audit_duration_seconds" in report_data and report_data["audit_duration_seconds"] is not None:
        dur = report_data["audit_duration_seconds"]
        if not isinstance(dur, (int, float)):
            errors.append(f"audit_duration_seconds must be a number, got {type(dur).__name__}")
        elif dur < 0:
            errors.append(f"audit_duration_seconds must be non-negative (>= 0), got {dur}")

    # --- Summary ---
    summary = report_data.get("summary")
    if isinstance(summary, dict):
        extra_sum = set(summary.keys()) - _SUMMARY_ALLOWED
        if extra_sum:
            errors.append(f"summary has unexpected keys: {extra_sum}")
        for skey in ("total_findings", "critical", "high", "medium", "low", "info"):
            if skey not in summary:
                errors.append(f"summary missing required key: '{skey}'")
            elif not isinstance(summary[skey], int):
                errors.append(f"summary.{skey} must be an integer, got {type(summary[skey]).__name__}")
        if "coverage" in summary:
            scov = summary["coverage"]
            if not isinstance(scov, dict):
                errors.append("summary.coverage must be an object/dict")
            else:
                extra_scov = set(scov.keys()) - _SUMMARY_COVERAGE_ALLOWED
                if extra_scov:
                    errors.append(f"summary.coverage has unexpected keys: {extra_scov}")
                for k in ("pages_audited", "pages_in_sitemap", "budget_limited"):
                    if k not in scov:
                        errors.append(f"summary.coverage missing required key '{k}'")
                if "pages_audited" in scov and not isinstance(scov["pages_audited"], int):
                    errors.append("summary.coverage.pages_audited must be an integer")
                if "pages_in_sitemap" in scov and scov["pages_in_sitemap"] is not None and not isinstance(scov["pages_in_sitemap"], int):
                    errors.append("summary.coverage.pages_in_sitemap must be an integer or null")
                if "budget_limited" in scov and not isinstance(scov["budget_limited"], bool):
                    errors.append("summary.coverage.budget_limited must be a boolean")
    elif summary is not None:
        errors.append("summary must be an object/dict")

    # --- Findings ---
    findings = report_data.get("findings")
    if isinstance(findings, list):
        fids = {f.get("id") for f in findings if isinstance(f, dict) and "id" in f}
        for i, finding in enumerate(findings):
            _validate_finding(finding, i, errors, fids)
    elif findings is not None:
        errors.append("findings must be an array/list")

    # --- Proactive recommendations ---
    proactive = report_data.get("proactive_recommendations")
    if proactive is not None:
        if not isinstance(proactive, list):
            errors.append("proactive_recommendations must be an array/list")
        else:
            for i, item in enumerate(proactive):
                if not isinstance(item, str):
                    errors.append(f"proactive_recommendations[{i}] must be a string")
                elif len(item) < 10:
                    errors.append(f"proactive_recommendations[{i}] too short (min 10 chars)")

    # --- Remediation themes ---
    themes = report_data.get("remediation_themes")
    if themes is not None:
        if not isinstance(themes, list):
            errors.append("remediation_themes must be an array/list")
        else:
            for i, th in enumerate(themes):
                if not isinstance(th, dict):
                    errors.append(f"remediation_themes[{i}] must be an object/dict")
                else:
                    for req_k in ("theme", "finding_ids", "primary_action", "priority"):
                        if req_k not in th:
                            errors.append(f"remediation_themes[{i}] missing required key '{req_k}'")
                    if "theme" in th and not isinstance(th["theme"], str):
                        errors.append(f"remediation_themes[{i}].theme must be a string")
                    if "finding_ids" in th:
                        if not isinstance(th["finding_ids"], list):
                            errors.append(f"remediation_themes[{i}].finding_ids must be a list of strings")
                        elif not all(isinstance(x, str) for x in th["finding_ids"]):
                            errors.append(f"remediation_themes[{i}].finding_ids items must be strings")
                    if "primary_action" in th and not isinstance(th["primary_action"], str):
                        errors.append(f"remediation_themes[{i}].primary_action must be a string")
                    if "target_asset" in th and not isinstance(th["target_asset"], str):
                        errors.append(f"remediation_themes[{i}].target_asset must be a string")
                    if "priority" in th and th["priority"] not in _VALID_SEVERITIES:
                        errors.append(f"remediation_themes[{i}].priority must be a valid severity")

    # --- Coverage ---
    coverage = report_data.get("coverage")
    if coverage is not None:
        if not isinstance(coverage, dict):
            errors.append("coverage must be an object/dict")
        else:
            for domain_key in _DOMAIN_COVERAGE_KEYS:
                if domain_key in coverage:
                    _validate_skill_coverage(coverage[domain_key], domain_key, errors)
            if "pages_with_low_render_confidence" in coverage and not isinstance(
                coverage["pages_with_low_render_confidence"], int
            ):
                errors.append("coverage.pages_with_low_render_confidence must be an integer")
            if "render_confidence" in coverage and coverage["render_confidence"] not in {
                "high", "medium", "low"
            }:
                errors.append("coverage.render_confidence must be one of high, medium, low")
            if "overall_state" in coverage and coverage["overall_state"] not in {
                "COMPLETE", "PARTIAL", "LIMITED", "UNAVAILABLE"
            }:
                errors.append("coverage.overall_state must be one of COMPLETE, PARTIAL, LIMITED, UNAVAILABLE")
            if "limitations" in coverage and not isinstance(coverage["limitations"], list):
                errors.append("coverage.limitations must be an array/list of strings")
            extra_keys = set(coverage.keys()) - _COVERAGE_KEYS
            if extra_keys:
                errors.append(f"coverage has unexpected keys: {extra_keys}")

    return (len(errors) == 0, errors)


def _validate_finding(
    finding: Any,
    index: int,
    errors: list[str],
    all_finding_ids: set[str] | None = None,
) -> None:
    """Validate a single Finding object."""
    prefix = f"findings[{index}]"
    if not isinstance(finding, dict):
        errors.append(f"{prefix} must be an object/dict")
        return

    extra_f = set(finding.keys()) - _FINDING_ALLOWED
    if extra_f:
        errors.append(f"{prefix} has unexpected keys: {extra_f}")

    for key in ("id", "title", "severity", "category", "evidence", "suggested_action"):
        if key not in finding:
            errors.append(f"{prefix} missing required key: '{key}'")

    # id pattern
    fid = finding.get("id")
    if isinstance(fid, str):
        import re
        if not re.match(r"^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$", fid):
            errors.append(f"{prefix}.id '{fid}' does not match pattern ^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$")
        if len(fid) < 3:
            errors.append(f"{prefix}.id too short (min 3)")
        if len(fid) > 80:
            errors.append(f"{prefix}.id too long (max 80)")

    # severity
    sev = finding.get("severity")
    if sev is not None and sev not in _VALID_SEVERITIES:
        errors.append(f"{prefix}.severity must be one of {_VALID_SEVERITIES}, got '{sev}'")

    # category
    cat = finding.get("category")
    if cat is not None and cat not in _VALID_CATEGORIES:
        errors.append(f"{prefix}.category must be one of {_VALID_CATEGORIES}, got '{cat}'")

    # title
    title = finding.get("title")
    if isinstance(title, str):
        if len(title) < 5:
            errors.append(f"{prefix}.title too short (min 5)")
        if len(title) > 120:
            errors.append(f"{prefix}.title too long (max 120)")

    # evidence (supports string or object with url)
    ev = finding.get("evidence")
    if ev is not None:
        if isinstance(ev, str):
            if len(ev) < 3:
                errors.append(f"{prefix}.evidence too short (min 3)")
        elif isinstance(ev, dict):
            if "url" not in ev:
                errors.append(f"{prefix}.evidence missing required key 'url'")
        else:
            errors.append(f"{prefix}.evidence must be a string or object/dict")

    # suggested_action (object with summary and priority)
    sa = finding.get("suggested_action")
    if sa is not None:
        if not isinstance(sa, dict):
            errors.append(f"{prefix}.suggested_action must be an object/dict")
        else:
            if "summary" not in sa:
                errors.append(f"{prefix}.suggested_action missing required key 'summary'")
            elif not isinstance(sa["summary"], str):
                errors.append(f"{prefix}.suggested_action.summary must be a string")
            elif len(sa["summary"]) < 5:
                errors.append(f"{prefix}.suggested_action.summary too short (min 5)")
            if "priority" not in sa:
                errors.append(f"{prefix}.suggested_action missing required key 'priority'")
            elif sa["priority"] not in _VALID_SEVERITIES:
                errors.append(f"{prefix}.suggested_action.priority invalid: {sa['priority']}")

    # related_to (optional list of strings)
    if "related_to" in finding:
        rt = finding["related_to"]
        if not isinstance(rt, list):
            errors.append(f"{prefix}.related_to must be an array/list")
        elif not all(isinstance(x, str) for x in rt):
            errors.append(f"{prefix}.related_to items must be strings")
        else:
            for ref in rt:
                if ref == fid:
                    errors.append(f"{prefix}.related_to contains self-reference to '{fid}'")
                elif all_finding_ids is not None and ref not in all_finding_ids:
                    errors.append(
                        f"{prefix}.related_to contains dangling reference to nonexistent ID '{ref}'"
                    )

    # confidence (optional number between 0.0 and 1.0)
    if "confidence" in finding:
        conf = finding["confidence"]
        if not isinstance(conf, (int, float)):
            errors.append(f"{prefix}.confidence must be a number")
        elif conf < 0.0 or conf > 1.0:
            errors.append(f"{prefix}.confidence must be between 0.0 and 1.0, got {conf}")

    # source (optional string: "static" or "rendered")
    if "source" in finding:
        src = finding["source"]
        if src not in ("static", "rendered"):
            errors.append(f"{prefix}.source must be 'static' or 'rendered', got '{src}'")

    for str_key in ("location", "why_it_matters", "remediation_theme"):
        if str_key in finding and not isinstance(finding[str_key], str):
            errors.append(f"{prefix}.{str_key} must be a string")


def _validate_skill_coverage(cov: Any, domain: str, errors: list[str]) -> None:
    """Validate a SkillCoverage object."""
    prefix = f"coverage.{domain}"
    if not isinstance(cov, dict):
        errors.append(f"{prefix} must be an object/dict")
        return
    for key in ("pages_checked", "checks_run", "errors"):
        if key not in cov:
            errors.append(f"{prefix} missing required key: '{key}'")
    for int_key in ("checks_available", "checks_attempted", "checks_skipped", "checks_blocked", "findings_produced"):
        if int_key in cov and not isinstance(cov[int_key], int):
            errors.append(f"{prefix}.{int_key} must be an integer")
    if "notes" in cov and not isinstance(cov["notes"], str):
        errors.append(f"{prefix}.notes must be a string")
    allowed = {
        "pages_checked",
        "checks_run",
        "checks_available",
        "checks_attempted",
        "checks_skipped",
        "checks_blocked",
        "findings_produced",
        "errors",
        "notes",
        "render_confidence",
        "pages_with_low_render_confidence",
        "network_requests",
        "performance_metrics",
        "rendered_word_count",
        "static_word_count",
        "csr_blanking_ratio",
        "coverage_state",
    }
    if "coverage_state" in cov and cov["coverage_state"] not in {
        "COMPLETE", "PARTIAL", "LIMITED", "UNAVAILABLE"
    }:
        errors.append(f"{prefix}.coverage_state must be one of COMPLETE, PARTIAL, LIMITED, UNAVAILABLE")
    extra = set(cov.keys()) - allowed
    if extra:
        errors.append(f"{prefix} has unexpected keys: {extra}")


def _check_type(
    data: dict,
    key: str,
    expected: type | tuple,
    errors: list[str],
    optional: bool = False,
) -> None:
    """Check that data[key] is the expected type."""
    if key not in data:
        if not optional:
            errors.append(f"Missing key: '{key}'")
        return
    if not isinstance(data[key], expected):
        errors.append(
            f"'{key}' must be {expected}, got {type(data[key]).__name__}"
        )


def _cli() -> None:
    import sys
    from pathlib import Path
    import json
    if len(sys.argv) < 2:
        print("Usage: python schema_validate.py <report.json>", file=sys.stderr)
        sys.exit(1)
    report_file = Path(sys.argv[1])
    if not report_file.exists():
        print(f"Error: file not found: {report_file}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(report_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error parsing JSON: {exc}", file=sys.stderr)
        sys.exit(1)
    valid, errors = validate_report(data)
    if valid:
        print(f"VALID: '{report_file.name}' matches report.schema.json successfully.")
        sys.exit(0)
    else:
        print(f"INVALID: '{report_file.name}' has {len(errors)} validation error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _cli()
