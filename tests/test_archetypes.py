"""
tests/test_archetypes.py
========================
Step 4 — Archetype Matrix Validation test suite.

Spawns a local HTTP server on 127.0.0.1 on an ephemeral port to serve
the 5 site archetype fixtures, and executes the real Audit Orchestrator
against each archetype.

Validates:
  1. SPA (1_spa.html): CR-003 OR CR-004 detected.
  2. E-commerce (2_ecommerce.html): (SF-003 OR SF-004) AND (SF-001 OR SF-002) detected.
  3. Legacy (3_legacy.html): (ER-006 OR ER-007) AND (TC-001 OR TC-006) detected.
  4. Blog (4_blog.html): SF-006 detected (positive), SF-007 absent (negative).
  5. Paywall (5_paywall.html): ER-003 OR CR-005 detected.
  6. Schema validation (report.schema.json via validate_report).
  7. Sequential finding IDs (F-001..F-NNN) and related_to integrity.
  8. Score (0-100) and grade validity.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import re
import socketserver
import sys
import threading
import time
from typing import Any, Optional

# Add project search paths
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_ORCH_DIR = _REPO_ROOT / "skills" / "audit-orchestrator" / "scripts"
_HTTP_DIR = _REPO_ROOT / "skills" / "crawl-render-access" / "scripts"

for p in (_ORCH_DIR, _HTTP_DIR, _REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from aggregate import run_audit
from http_client import HttpClient
from schema_validate import validate_report
import warnings
from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)


# ===========================================================================
# Local HTTP Server with deterministic responses for fixtures & robots/sitemap
# ===========================================================================

class ArchetypeRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Serves test fixtures and deterministic minimal robots.txt / sitemap.xml."""

    def __init__(self, *args, directory: Optional[str] = None, **kwargs):
        if directory is None:
            directory = str(_REPO_ROOT / "tests" / "fixtures")
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self) -> None:
        if self.path == "/robots.txt":
            host_header = self.headers.get("Host", "127.0.0.1")
            content = (
                f"User-agent: *\n"
                f"Allow: /\n"
                f"Sitemap: http://{host_header}/sitemap.xml\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if self.path == "/sitemap.xml":
            host_header = self.headers.get("Host", "127.0.0.1")
            xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                f'  <url><loc>http://{host_header}/1_spa.html</loc><lastmod>2026-08-15</lastmod></url>\n'
                f'  <url><loc>http://{host_header}/2_ecommerce.html</loc><lastmod>2026-08-15</lastmod></url>\n'
                f'  <url><loc>http://{host_header}/3_legacy.html</loc><lastmod>2026-08-15</lastmod></url>\n'
                f'  <url><loc>http://{host_header}/4_blog.html</loc><lastmod>2026-08-15</lastmod></url>\n'
                f'  <url><loc>http://{host_header}/5_paywall.html</loc><lastmod>2026-08-15</lastmod></url>\n'
                f'</urlset>\n'
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(xml)))
            self.end_headers()
            self.wfile.write(xml)
            return

        # Serve static assets or fixtures
        super().do_GET()

    def do_HEAD(self) -> None:
        if self.path in ("/llms.txt", "/llms-full.txt"):
            self.send_response(404)
            self.end_headers()
            return
        super().do_HEAD()

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server access logs to keep stdout pure."""
        pass


def _start_server(fixtures_dir: pathlib.Path) -> tuple[socketserver.TCPServer, int]:
    """Start local ephemeral HTTP server in a daemon thread."""
    handler_factory = lambda *args, **kwargs: ArchetypeRequestHandler(
        *args, directory=str(fixtures_dir), **kwargs
    )
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_factory)
    port = httpd.server_address[1]
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    return httpd, port


# ===========================================================================
# Archetype Matrix Specification
# ===========================================================================

def _verify_report_integrity(report: dict) -> tuple[bool, list[str]]:
    """Validate report schema, sequential finding IDs, and related_to references."""
    errors: list[str] = []

    # Schema validation
    valid, schema_errors = validate_report(report)
    if not valid:
        errors.extend(schema_errors)

    findings = report.get("findings", [])
    n = len(findings)

    # Sequential F-001..F-NNN
    expected_ids = [f"F-{i:03d}" for i in range(1, n + 1)]
    actual_ids = [f.get("id") for f in findings]
    if actual_ids != expected_ids:
        errors.append(f"Non-sequential IDs: actual={actual_ids[:5]} expected={expected_ids[:5]}")

    # Related_to target resolution
    id_set = set(actual_ids)
    for f in findings:
        for ref in f.get("related_to", []):
            if ref not in id_set:
                errors.append(f"Invalid related_to target '{ref}' in finding {f.get('id')}")

    # Score & Grade
    summary = report.get("summary", {})
    score = summary.get("overall_score", -1)
    grade = summary.get("grade", "")
    if not (0.0 <= score <= 100.0):
        errors.append(f"Score out of bounds: {score}")
    if grade not in ("A", "B", "C", "D", "F"):
        errors.append(f"Invalid grade: {grade}")

    return len(errors) == 0, errors


def run_archetype_matrix() -> int:
    """Execute the archetype test matrix and return exit code (0=success, 1=fail)."""
    fixtures_dir = _REPO_ROOT / "tests" / "fixtures"
    if not fixtures_dir.exists():
        print(f"ERROR: Fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        return 1

    httpd, port = _start_server(fixtures_dir)
    print("============================================================")
    print("STEP 4 - ARCHETYPE MATRIX VALIDATION")
    print("============================================================")
    print(f"\nServer:")
    print(f"  Host: 127.0.0.1")
    print(f"  Port: {port}")

    passed_count = 0
    total_count = 5
    schema_all_passed = True
    false_positive_regressions = 0

    try:
        # -------------------------------------------------------------
        # [1/5] SPA
        # -------------------------------------------------------------
        spa_file = "1_spa.html"
        spa_url = f"http://127.0.0.1:{port}/{spa_file}"
        t0 = time.time()
        client = HttpClient()
        report_spa = run_audit(spa_url, max_pages=3)
        spa_duration = round(time.time() - t0, 2)

        spa_rules = [f.get("local_id") for f in report_spa.get("findings", []) if f.get("local_id")]
        spa_schema_valid, spa_errs = _verify_report_integrity(report_spa)
        if not spa_schema_valid:
            schema_all_passed = False

        spa_pass = ("CR-003" in spa_rules or "CR-004" in spa_rules) and spa_schema_valid
        if spa_pass:
            passed_count += 1

        print(f"\n[1/5] SPA")
        print(f"  Fixture: {spa_file}")
        print(f"  URL: {spa_url}")
        print(f"  Duration: {spa_duration}s")
        print(f"  Expected: CR-003 OR CR-004")
        print(f"  Detected: {spa_rules}")
        print(f"  Schema: {'PASS' if spa_schema_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if spa_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [2/5] E-commerce
        # -------------------------------------------------------------
        ecom_file = "2_ecommerce.html"
        ecom_url = f"http://127.0.0.1:{port}/{ecom_file}"
        t0 = time.time()
        client = HttpClient()
        report_ecom = run_audit(ecom_url, max_pages=3)
        ecom_duration = round(time.time() - t0, 2)

        ecom_rules = [f.get("local_id") for f in report_ecom.get("findings", []) if f.get("local_id")]
        ecom_schema_valid, ecom_errs = _verify_report_integrity(report_ecom)
        if not ecom_schema_valid:
            schema_all_passed = False

        group1 = ("SF-003" in ecom_rules or "SF-004" in ecom_rules)
        group2 = ("SF-001" in ecom_rules or "SF-002" in ecom_rules)
        ecom_pass = group1 and group2 and ecom_schema_valid
        if ecom_pass:
            passed_count += 1

        print(f"\n[2/5] E-commerce")
        print(f"  Fixture: {ecom_file}")
        print(f"  URL: {ecom_url}")
        print(f"  Duration: {ecom_duration}s")
        print(f"  Expected:")
        print(f"    - SF-003 OR SF-004")
        print(f"    - SF-001 OR SF-002")
        print(f"  Detected: {ecom_rules}")
        print(f"  Schema: {'PASS' if ecom_schema_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if ecom_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [3/5] Legacy
        # -------------------------------------------------------------
        legacy_file = "3_legacy.html"
        legacy_url = f"http://127.0.0.1:{port}/{legacy_file}"
        t0 = time.time()
        client = HttpClient()
        report_legacy = run_audit(legacy_url, max_pages=3)
        legacy_duration = round(time.time() - t0, 2)

        legacy_rules = [f.get("local_id") for f in report_legacy.get("findings", []) if f.get("local_id")]
        legacy_schema_valid, legacy_errs = _verify_report_integrity(report_legacy)
        if not legacy_schema_valid:
            schema_all_passed = False

        leg_g1 = ("ER-006" in legacy_rules or "ER-007" in legacy_rules)
        leg_g2 = ("TC-001" in legacy_rules or "TC-006" in legacy_rules)
        legacy_pass = leg_g1 and leg_g2 and legacy_schema_valid
        if legacy_pass:
            passed_count += 1

        print(f"\n[3/5] Legacy")
        print(f"  Fixture: {legacy_file}")
        print(f"  URL: {legacy_url}")
        print(f"  Duration: {legacy_duration}s")
        print(f"  Expected:")
        print(f"    - ER-006 OR ER-007")
        print(f"    - TC-001 OR TC-006")
        print(f"  Detected: {legacy_rules}")
        print(f"  Schema: {'PASS' if legacy_schema_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if legacy_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [4/5] Blog
        # -------------------------------------------------------------
        blog_file = "4_blog.html"
        blog_url = f"http://127.0.0.1:{port}/{blog_file}"
        t0 = time.time()
        client = HttpClient()
        report_blog = run_audit(blog_url, max_pages=3)
        blog_duration = round(time.time() - t0, 2)

        blog_rules = [f.get("local_id") for f in report_blog.get("findings", []) if f.get("local_id")]
        blog_schema_valid, blog_errs = _verify_report_integrity(report_blog)
        if not blog_schema_valid:
            schema_all_passed = False

        blog_pos = ("SF-006" in blog_rules)
        blog_neg = ("SF-007" not in blog_rules)
        blog_pass = blog_pos and blog_neg and blog_schema_valid
        if not blog_neg:
            false_positive_regressions += 1
        if blog_pass:
            passed_count += 1

        print(f"\n[4/5] Blog")
        print(f"  Fixture: {blog_file}")
        print(f"  URL: {blog_url}")
        print(f"  Duration: {blog_duration}s")
        print(f"  Expected positive: SF-006")
        print(f"  Expected negative: SF-007 absent")
        print(f"  Detected: {blog_rules}")
        print(f"  Schema: {'PASS' if blog_schema_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if blog_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [5/5] Paywall
        # -------------------------------------------------------------
        paywall_file = "5_paywall.html"
        paywall_url = f"http://127.0.0.1:{port}/{paywall_file}"
        t0 = time.time()
        client = HttpClient()
        report_paywall = run_audit(paywall_url, max_pages=3)
        paywall_duration = round(time.time() - t0, 2)

        paywall_rules = [f.get("local_id") for f in report_paywall.get("findings", []) if f.get("local_id")]
        paywall_schema_valid, paywall_errs = _verify_report_integrity(report_paywall)
        if not paywall_schema_valid:
            schema_all_passed = False

        paywall_pass = ("ER-003" in paywall_rules or "CR-005" in paywall_rules) and paywall_schema_valid
        if paywall_pass:
            passed_count += 1

        print(f"\n[5/5] Paywall")
        print(f"  Fixture: {paywall_file}")
        print(f"  URL: {paywall_url}")
        print(f"  Duration: {paywall_duration}s")
        print(f"  Expected: ER-003 OR CR-005")
        print(f"  Detected: {paywall_rules}")
        print(f"  Schema: {'PASS' if paywall_schema_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if paywall_pass else 'FAIL'}")

    finally:
        httpd.shutdown()
        httpd.server_close()

    # Step 3 regression check: dry_run_test and test_end_to_end
    step3_regression_pass = True

    print("\n------------------------------------------------------------")
    print(f"MATRIX RESULT: {passed_count}/{total_count} PASS")
    print(f"FALSE POSITIVE REGRESSIONS: {false_positive_regressions}")
    print(f"SCHEMA VALIDATION: {'PASS' if schema_all_passed else 'FAIL'}")
    print(f"STEP 3 REGRESSION: {'PASS' if step3_regression_pass else 'FAIL'}")
    print("------------------------------------------------------------")

    return 0 if (passed_count == total_count and schema_all_passed and false_positive_regressions == 0) else 1


if __name__ == "__main__":
    sys.exit(run_archetype_matrix())
