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
_VALID_GRADES = {"A", "B", "C", "D", "F"}
_COVERAGE_KEYS = {
    "crawl_render_access",
    "structured_fact_extraction",
    "trust_entity_corroboration",
    "engagement_retention",
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
    # --- Try jsonschema first ---
    try:
        import jsonschema  # type: ignore[import]
        schema = _load_schema()
        if schema is not None:
            return _validate_with_jsonschema(report_data, schema)
    except ImportError:
        logger.info("jsonschema not installed; using built-in fallback validator.")
    except Exception as exc:
        logger.warning("jsonschema validation failed unexpectedly (%s); falling back.", exc)

    # --- Fallback ---
    return _validate_fallback(report_data)


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

    # --- Required top-level keys ---
    for key in ("schema_version", "generated_at", "target_url", "summary", "findings"):
        if key not in report_data:
            errors.append(f"Missing required top-level key: '{key}'")

    # --- Type checks ---
    _check_type(report_data, "schema_version", str, errors)
    _check_type(report_data, "generated_at", str, errors)
    _check_type(report_data, "target_url", str, errors)
    _check_type(report_data, "pages_audited", int, errors, optional=True)
    _check_type(report_data, "audit_duration_seconds", (int, float), errors, optional=True)

    # --- Summary ---
    summary = report_data.get("summary")
    if isinstance(summary, dict):
        for skey in ("total_findings", "critical", "high", "medium", "low", "info"):
            if skey not in summary:
                errors.append(f"summary missing required key: '{skey}'")
            elif not isinstance(summary[skey], int):
                errors.append(f"summary.{skey} must be an integer, got {type(summary[skey]).__name__}")
        if "overall_score" in summary:
            score = summary["overall_score"]
            if not isinstance(score, (int, float)):
                errors.append("summary.overall_score must be a number")
            elif score < 0 or score > 100:
                errors.append(f"summary.overall_score must be 0-100, got {score}")
        if "grade" in summary:
            grade = summary["grade"]
            if grade not in _VALID_GRADES:
                errors.append(f"summary.grade must be one of {_VALID_GRADES}, got '{grade}'")
    elif summary is not None:
        errors.append("summary must be an object/dict")

    # --- Findings ---
    findings = report_data.get("findings")
    if isinstance(findings, list):
        for i, finding in enumerate(findings):
            _validate_finding(finding, i, errors)
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

    # --- Coverage ---
    coverage = report_data.get("coverage")
    if coverage is not None:
        if not isinstance(coverage, dict):
            errors.append("coverage must be an object/dict")
        else:
            for domain_key in _COVERAGE_KEYS:
                if domain_key in coverage:
                    _validate_skill_coverage(coverage[domain_key], domain_key, errors)
            extra_keys = set(coverage.keys()) - _COVERAGE_KEYS
            if extra_keys:
                errors.append(f"coverage has unexpected keys: {extra_keys}")

    return (len(errors) == 0, errors)


def _validate_finding(finding: Any, index: int, errors: list[str]) -> None:
    """Validate a single Finding object."""
    prefix = f"findings[{index}]"
    if not isinstance(finding, dict):
        errors.append(f"{prefix} must be an object/dict")
        return

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


def _validate_skill_coverage(cov: Any, domain: str, errors: list[str]) -> None:
    """Validate a SkillCoverage object."""
    prefix = f"coverage.{domain}"
    if not isinstance(cov, dict):
        errors.append(f"{prefix} must be an object/dict")
        return
    for key in ("pages_checked", "checks_run", "errors"):
        if key not in cov:
            errors.append(f"{prefix} missing required key: '{key}'")
        elif not isinstance(cov[key], int):
            errors.append(f"{prefix}.{key} must be an integer")
    if "notes" in cov and not isinstance(cov["notes"], str):
        errors.append(f"{prefix}.notes must be a string")
    allowed = {"pages_checked", "checks_run", "errors", "notes"}
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
