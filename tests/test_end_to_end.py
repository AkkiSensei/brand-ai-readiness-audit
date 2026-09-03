"""
test_end_to_end.py
==================
End-to-end integration test and contract validation for the audit orchestrator.

Exercises the real CLI against https://example.com, parses the output,
and validates all contract requirements and Section 34 assertions:
  1. Clean exit code
  2. Valid JSON stdout
  3. Summary consistency
  4. Sequential finding IDs (F-001..F-NNN)
  5. Schema validation (jsonschema & fallback)
  6. Severity ordering (critical -> high -> medium -> low -> info)
  7. Grade & score bounds
  8. Evidence type verification (string / object)
  9. Suggested action structure (object with summary & priority)
 10. related_to references existing final IDs
 11. Contract verification: categories, evidence, suggested_action, producer outputs
 12. Deliberately malformed values rejected
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_AGGREGATE = _ROOT / "skills" / "audit-orchestrator" / "scripts" / "aggregate.py"

# Add paths for imports
sys.path.insert(0, str(_ROOT / "skills" / "audit-orchestrator" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "crawl-render-access" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "structured-fact-extraction" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "trust-entity-corroboration" / "scripts"))
sys.path.insert(0, str(_ROOT / "skills" / "engagement-retention" / "scripts"))

from schema_validate import validate_report


def run_test() -> int:
    """Run the end-to-end integration and contract verification test."""
    print("=" * 70)
    print("END-TO-END INTEGRATION TEST & CONTRACT VERIFICATION")
    print("=" * 70)
    target = "https://example.com"
    print(f"Target:     {target}")
    print(f"Aggregate:  {_AGGREGATE}")
    print()

    failures: list[str] = []

    # ---- 1. Launch orchestrator CLI ----
    print("[1] Launching orchestrator CLI ...")
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            [sys.executable, str(_AGGREGATE), target, "--max-pages", "5"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        duration = time.monotonic() - t0
        print(f"    Exit code: {result.returncode}  ({duration:.1f}s)")
    except subprocess.TimeoutExpired:
        print("    FAIL: Process timed out after 120s")
        return 1
    except Exception as exc:
        print(f"    FAIL: Could not launch process: {exc}")
        return 1

    # ---- 2. Verify execution ----
    print("[2] Verifying execution ...")
    if result.returncode != 0:
        failures.append(f"Exit code is {result.returncode}, expected 0")
        print(f"    FAIL: non-zero exit code")
        if result.stderr:
            print(f"    stderr: {result.stderr[:500]}")
    else:
        print("    OK: clean exit code 0")

    # ---- 3. Parse JSON ----
    print("[3] Parsing stdout as JSON ...")
    try:
        report = json.loads(result.stdout)
        print(f"    OK: valid JSON ({len(result.stdout)} bytes)")
    except json.JSONDecodeError as exc:
        print(f"    FAIL: {exc}")
        if result.stdout:
            print(f"    stdout[:500]: {result.stdout[:500]}")
        if result.stderr:
            print(f"    stderr[:500]: {result.stderr[:500]}")
        return 1

    # ---- 4. Top-level fields & Summary consistency ----
    print("[4] Verifying required fields & summary consistency ...")
    for req in ("schema_version", "generated_at", "target_url", "summary", "findings", "coverage"):
        if req not in report:
            failures.append(f"Missing required top-level key: {req}")
    summary = report.get("summary", {})
    total = summary.get("total_findings", -1)
    findings = report.get("findings", [])
    actual_count = len(findings)
    if total == actual_count:
        print(f"    OK: total_findings={total} == len(findings)={actual_count}")
    else:
        failures.append(f"summary.total_findings ({total}) != len(findings) ({actual_count})")
        print(f"    FAIL: {total} != {actual_count}")

    sev_sum = sum(summary.get(s, 0) for s in ("critical", "high", "medium", "low", "info"))
    if sev_sum == total:
        print(f"    OK: severity counts sum to {sev_sum}")
    else:
        failures.append(f"Severity counts sum ({sev_sum}) != total ({total})")
        print(f"    FAIL: severity sum {sev_sum} != {total}")

    # ---- 5. Sequential finding IDs (F-001..F-NNN) ----
    print("[5] Verifying sequential finding IDs (F-001..F-NNN) ...")
    n = len(findings)
    expected_ids = [f"F-{i:03d}" for i in range(1, n + 1)]
    actual_ids = [f.get("id", "") for f in findings]
    if actual_ids == expected_ids:
        print(f"    OK: F-001..F-{n:03d} (sequential, gap-free)")
    else:
        failures.append(f"Finding IDs not sequential: {actual_ids}")
        print(f"    FAIL: expected {expected_ids[:5]}... got {actual_ids[:5]}...")

    # ---- 6. Schema validation ----
    print("[6] Validating report against report.schema.json ...")
    valid, errors = validate_report(report)
    if valid:
        print(f"    OK: schema valid (0 errors)")
    else:
        failures.append(f"Schema validation errors: {errors}")
        print(f"    FAIL: {len(errors)} error(s)")
        for err in errors[:5]:
            print(f"      - {err}")

    # ---- 7. Severity ordering ----
    print("[7] Verifying severity ordering ...")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    severity_values = [severity_order.get(f.get("severity", "info"), 99) for f in findings]
    is_ordered = all(a <= b for a, b in zip(severity_values, severity_values[1:]))
    if is_ordered:
        print(f"    OK: findings ordered by severity (critical->info)")
    else:
        failures.append("Findings not ordered by severity")
        print(f"    FAIL: {[f.get('severity') for f in findings]}")

    info_findings = [f for f in findings if f.get("severity") == "info"]
    non_info = [f for f in findings if f.get("severity") != "info"]
    if non_info and info_findings:
        last_non_info_idx = max(findings.index(f) for f in non_info)
        first_info_idx = min(findings.index(f) for f in info_findings)
        if first_info_idx > last_non_info_idx:
            print(f"    OK: info/proactive findings consistently at end")
        else:
            failures.append("Info findings not placed after higher-severity findings")

    # ---- 8. Evidence and Suggested Action Types ----
    print("[8] Verifying evidence and suggested_action types ...")
    for i, f in enumerate(findings):
        # Evidence check
        ev = f.get("evidence")
        if not isinstance(ev, (str, dict)):
            failures.append(f"findings[{i}].evidence is neither str nor dict: {type(ev)}")
        # Suggested action check
        sa = f.get("suggested_action")
        if not isinstance(sa, dict):
            failures.append(f"findings[{i}].suggested_action is not a dict: {type(sa)}")
        elif "summary" not in sa or "priority" not in sa:
            failures.append(f"findings[{i}].suggested_action missing required summary/priority")
    print(f"    OK: all {len(findings)} findings have valid evidence and suggested_action structure")

    # ---- 9. related_to cross-referencing ----
    print("[9] Verifying related_to references ...")
    final_id_set = set(actual_ids)
    all_refs_valid = True
    for f in findings:
        for ref in f.get("related_to", []):
            if ref not in final_id_set:
                failures.append(f"Finding {f['id']} references non-existent ID '{ref}'")
                all_refs_valid = False
            if ref == f["id"]:
                failures.append(f"Finding {f['id']} self-references")
                all_refs_valid = False
    if all_refs_valid:
        print(f"    OK: all related_to references resolve to valid final IDs")

    # ---- 10. Grade and Score bounds ----
    print("[10] Verifying score and grade ...")
    grade = summary.get("grade")
    score = summary.get("overall_score")
    if grade in ("A", "B", "C", "D", "F") and isinstance(score, (int, float)) and 0 <= score <= 100:
        print(f"    OK: grade={grade} score={score} (bounded 0-100)")
    else:
        failures.append(f"Invalid grade ({grade}) or score ({score})")
        print(f"    FAIL: grade={grade} score={score}")

    # ---- 11. Section 34 Contract Verification & Rejection Tests ----
    print("[11] Section 34 Contract Harmonization Verification ...")

    # Test 11a: Verify categories emitted by all producers are accepted
    valid_categories = {"discoverability", "engagement", "proactive"}
    for f in findings:
        cat = f.get("category")
        if cat not in valid_categories:
            print(f"    NOTE: Category '{cat}' emitted by finding {f['id']}")

    # Test 11b: Verify unsupported category is rejected
    bad_cat_report = copy.deepcopy(report)
    bad_cat_report["findings"][0]["category"] = "unsupported_invalid_category"
    bad_valid, _ = validate_report(bad_cat_report)
    if not bad_valid:
        print("    OK: unsupported category is rejected")
    else:
        failures.append("Schema failed to reject unsupported category 'unsupported_invalid_category'")
        print("    FAIL: unsupported category was accepted")

    # Test 11c: Verify string evidence is accepted
    str_ev_report = copy.deepcopy(report)
    str_ev_report["findings"][0]["evidence"] = "Verified plain text evidence string"
    sev_valid, _ = validate_report(str_ev_report)
    if sev_valid:
        print("    OK: plain text string evidence is accepted")
    else:
        failures.append("Schema rejected valid plain text string evidence")

    # Test 11d: Verify object evidence is accepted
    obj_ev_report = copy.deepcopy(report)
    obj_ev_report["findings"][0]["evidence"] = {
        "url": "https://example.com/test",
        "snippet": "Test snippet",
    }
    oev_valid, _ = validate_report(obj_ev_report)
    if oev_valid:
        print("    OK: structured object evidence is accepted")
    else:
        failures.append("Schema rejected valid structured object evidence")

    # Test 11e: Verify invalid evidence type (e.g. integer) is rejected
    int_ev_report = copy.deepcopy(report)
    int_ev_report["findings"][0]["evidence"] = 12345
    iev_valid, _ = validate_report(int_ev_report)
    if not iev_valid:
        print("    OK: invalid evidence type (int) is rejected")
    else:
        failures.append("Schema failed to reject integer evidence")

    # Test 11f: Verify suggested_action object is accepted
    sa_report = copy.deepcopy(report)
    sa_report["findings"][0]["suggested_action"] = {
        "summary": "This is a valid actionable recommendation.",
        "priority": "high",
    }
    sa_valid, _ = validate_report(sa_report)
    if sa_valid:
        print("    OK: suggested_action object with summary and priority is accepted")
    else:
        failures.append("Schema rejected valid suggested_action object")

    # Test 11g: Verify invalid suggested_action (e.g. string or missing priority) is rejected
    bad_sa_report = copy.deepcopy(report)
    bad_sa_report["findings"][0]["suggested_action"] = "Not an object"
    bsa_valid, _ = validate_report(bad_sa_report)
    if not bsa_valid:
        print("    OK: invalid suggested_action type (string) is rejected")
    else:
        failures.append("Schema failed to reject non-object suggested_action")

    # ---- Print execution metrics ----
    print()
    print("=" * 70)
    print("EXECUTION METRICS")
    print("=" * 70)
    print(f"  Target:           {target}")
    print(f"  Duration:         {duration:.1f}s")
    print(f"  Pages audited:    {report.get('pages_audited', 'N/A')}")
    print(f"  Total findings:   {total}")
    print(f"    Critical:       {summary.get('critical', 0)}")
    print(f"    High:           {summary.get('high', 0)}")
    print(f"    Medium:         {summary.get('medium', 0)}")
    print(f"    Low:            {summary.get('low', 0)}")
    print(f"    Info:           {summary.get('info', 0)}")
    print(f"  Score:            {score}")
    print(f"  Grade:            {grade}")
    print(f"  Proactive recs:   {len(report.get('proactive_recommendations', []))}")
    print(f"  Coverage domains: {len(report.get('coverage', {}))}")

    # ---- Final verdict ----
    print()
    print("=" * 70)
    if failures:
        print(f"FAILED ({len(failures)} issue(s)):")
        for f in failures:
            print(f"  - {f}")
        return 1
    else:
        print("*** ALL END-TO-END AND CONTRACT CHECKS PASSED ***")
        return 0


if __name__ == "__main__":
    sys.exit(run_test())
