"""
=============================================================================
INTERNAL TEAM TRIAGE TOOL ONLY — NOT PART OF OFFICIAL HACKATHON SUBMISSION
=============================================================================
NOTICE:
This script is an internal operational utility for team triage of batch audit
reports. It is intentionally placed in tools/ OUTSIDE the skills/ directory and
is strictly EXCLUDED from the hackathon submission package.

Scoring heuristic here is purely an internal operational triage metric based
on finding severity weights (critical=-25, high=-15, medium=-8, low=-3).
It does NOT represent an official grading signal or hackathon evaluation rubric.
The official project outputs schema-compliant JSON reports with severity counts
and findings without arbitrary scores.
=============================================================================
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import sys
from typing import Any

# Weight penalties for internal triage scoring
_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def compute_triage_score(report: dict[str, Any]) -> tuple[int, str]:
    """Compute transparent heuristic triage score [0..100] from real report findings."""
    status = report.get("audit_status", "unknown")
    if status == "blocked":
        # Target was blocked (SSRF, WAF challenge, connection failure, robots disallow)
        reason = report.get("blocked_reason", "unspecified")
        return 0, f"BLOCKED ({reason})"

    summary = report.get("summary", {})
    score = 100
    for sev, weight in _SEVERITY_WEIGHTS.items():
        count = summary.get(sev, 0)
        score -= count * weight

    score = max(0, min(100, score))
    if status == "partial":
        note = f"{score}/100 (PARTIAL: {report.get('blocked_reason', 'timeout')})"
    else:
        note = f"{score}/100"

    return score, note


def summarize_report(file_path: pathlib.Path) -> dict[str, Any] | None:
    """Load, validate, and summarize a single JSON report file."""
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[-] Error reading {file_path.name}: {exc}", file=sys.stderr)
        return None

    target = data.get("target_url") or data.get("site") or file_path.name
    status = data.get("audit_status", "unknown")
    reason = data.get("blocked_reason") or "-"
    pages = data.get("pages_audited", 0)
    summary = data.get("summary", {})
    score, note = compute_triage_score(data)

    return {
        "file": file_path.name,
        "target": target,
        "status": status,
        "reason": reason,
        "pages": pages,
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "info": summary.get("info", 0),
        "total": summary.get("total_findings", len(data.get("findings", []))),
        "score": score,
        "note": note,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Internal Batch Summary & Triage Tool (NOT FOR SUBMISSION)"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["scratch/*.json"],
        help="Report JSON file paths, directory, or glob pattern",
    )
    args = parser.parse_args()

    files: list[pathlib.Path] = []
    for pattern in args.paths:
        p = pathlib.Path(pattern)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(p.glob("*.json"))
        else:
            for matched in glob.glob(pattern):
                mp = pathlib.Path(matched)
                if mp.is_file() and mp.suffix.lower() == ".json":
                    files.append(mp)

    files = sorted(set(files))

    print("=" * 80)
    print("  INTERNAL BATCH SUMMARY & TRIAGE TOOL")
    print("  [INTERNAL TRIAGE ONLY - NOT AN OFFICIAL HACKATHON RUBRIC]")
    print("=" * 80)
    print(f"Found {len(files)} report file(s) for triage.\n")

    if not files:
        print("No report JSON files found to summarize.")
        return 1

    summaries = []
    for f in files:
        s = summarize_report(f)
        if s is not None:
            summaries.append(s)

    if not summaries:
        print("No valid reports could be summarized.")
        return 1

    # Print summary table
    header_fmt = "{:<24} {:<10} {:<12} {:>5} {:>4} {:>4} {:>4} {:>4} {:>4}  {:<16}"
    row_fmt    = "{:<24} {:<10} {:<12} {:>5} {:>4} {:>4} {:>4} {:>4} {:>4}  {:<16}"

    print(header_fmt.format("TARGET", "STATUS", "REASON", "PAGES", "CRIT", "HIGH", "MED", "LOW", "INFO", "TRIAGE SCORE"))
    print("-" * 88)

    for s in summaries:
        target_disp = s["target"]
        if len(target_disp) > 23:
            target_disp = target_disp[:20] + "..."
        print(row_fmt.format(
            target_disp,
            s["status"],
            s["reason"][:12],
            s["pages"],
            s["critical"],
            s["high"],
            s["medium"],
            s["low"],
            s["info"],
            s["note"],
        ))

    print("-" * 88)
    print(f"Total processed: {len(summaries)} | Completed: {sum(1 for s in summaries if s['status'] == 'completed')} | Partial: {sum(1 for s in summaries if s['status'] == 'partial')} | Blocked: {sum(1 for s in summaries if s['status'] == 'blocked')}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
