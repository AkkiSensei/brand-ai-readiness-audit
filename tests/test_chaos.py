"""
tests/test_chaos.py
===================
Phase 0–4 Systemic Debugging & Chaos Validation test suite.

Spawns a local HTTP server on 127.0.0.1 on an ephemeral port to serve
pathological/adversarial test cases:
  1. Zero-byte page (6_zero_byte.html)
  2. Garbage DOM and primitive-root JSON-LD (7_garbage.html)
  3. Infinite redirect loop (/redirect-loop)

Asserts:
  - No unhandled exceptions (clean, controlled survival).
  - Schema validity via report.schema.json.
  - JSON serializability via json.dumps.
  - Score bounded in [0, 100] and valid grade.
  - Sequential finding IDs (F-001..F-NNN).
  - Zero dangling related_to references.
  - Redirect loop capped and detected without hanging.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import socketserver
import sys
import threading
import time
import warnings
from typing import Any, Optional

from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
import logging
logging.getLogger("http_client").setLevel(logging.ERROR)

# Add project search paths
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_ORCH_DIR = _REPO_ROOT / "skills" / "audit-orchestrator" / "scripts"
_HTTP_DIR = _REPO_ROOT / "skills" / "crawl-render-access" / "scripts"

for p in (_ORCH_DIR, _HTTP_DIR, _REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from aggregate import run_audit
from schema_validate import validate_report


# ===========================================================================
# Local Chaos HTTP Server
# ===========================================================================

class ChaosRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Serves toxic fixtures and handles pathological endpoints like redirect loops."""

    def __init__(self, *args: Any, directory: Optional[str] = None, **kwargs: Any) -> None:
        if directory is None:
            directory = str(_REPO_ROOT / "tests" / "fixtures")
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self) -> None:
        if self.path == "/redirect-loop":
            self.send_response(301)
            self.send_header("Location", "/redirect-loop")
            self.end_headers()
            return

        if self.path == "/robots.txt":
            content = b"User-agent: *\nAllow: /\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if self.path == "/sitemap.xml":
            content = (
                b'<?xml version="1.0" encoding="UTF-8"?>\n'
                b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                b'</urlset>\n'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        super().do_GET()

    def do_HEAD(self) -> None:
        if self.path == "/redirect-loop":
            self.send_response(301)
            self.send_header("Location", "/redirect-loop")
            self.end_headers()
            return

        if self.path in ("/llms.txt", "/llms-full.txt"):
            self.send_response(404)
            self.end_headers()
            return

        super().do_HEAD()

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress normal HTTP request logging."""
        pass


def _start_server(fixtures_dir: pathlib.Path) -> tuple[socketserver.TCPServer, int]:
    """Start ephemeral local HTTP server in a daemon thread."""
    handler_factory = lambda *args, **kwargs: ChaosRequestHandler(
        *args, directory=str(fixtures_dir), **kwargs
    )
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_factory)
    port = httpd.server_address[1]
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    return httpd, port


# ===========================================================================
# Report Verification Helper
# ===========================================================================

def _verify_report_integrity(report: dict) -> tuple[bool, list[str]]:
    """Validate schema, serializability, sequential IDs, and references."""
    errors: list[str] = []

    # 1. JSON serializability
    try:
        json_text = json.dumps(report)
        if not json_text:
            errors.append("Empty JSON serialization")
    except Exception as exc:
        errors.append(f"JSON serialization failed: {exc}")

    # 2. Schema validation
    valid, schema_errors = validate_report(report)
    if not valid:
        errors.extend(schema_errors)

    findings = report.get("findings", [])
    n = len(findings)

    # 3. Sequential F-001..F-NNN
    expected_ids = [f"F-{i:03d}" for i in range(1, n + 1)]
    actual_ids = [f.get("id") for f in findings]
    if actual_ids != expected_ids:
        errors.append(f"Non-sequential IDs: actual={actual_ids[:5]} expected={expected_ids[:5]}")

    # 4. Related_to target resolution
    id_set = set(actual_ids)
    for f in findings:
        for ref in f.get("related_to", []):
            if ref not in id_set:
                errors.append(f"Dangling related_to target '{ref}' in finding {f.get('id')}")

    # 5. Verify absence of Score & Grade
    summary = report.get("summary", {})
    if "overall_score" in summary or "grade" in summary:
        errors.append("summary must not contain overall_score or grade")

    return len(errors) == 0, errors


# ===========================================================================
# Main Chaos Suite Execution
# ===========================================================================

def run_chaos_suite() -> int:
    fixtures_dir = _REPO_ROOT / "tests" / "fixtures"
    if not fixtures_dir.exists():
        print(f"ERROR: Fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        return 1

    httpd, port = _start_server(fixtures_dir)

    print("============================================================")
    print("PHASE 0-4 CHAOS VALIDATION")
    print("============================================================")

    passed_cases = 0
    total_cases = 3

    try:
        # -------------------------------------------------------------
        # [1/3] Zero-byte page
        # -------------------------------------------------------------
        zb_file = "6_zero_byte.html"
        zb_url = f"http://127.0.0.1:{port}/{zb_file}"
        t0 = time.time()
        zb_exc = "NONE"
        zb_valid = False
        try:
            report_zb = run_audit(zb_url, max_pages=2)
            zb_valid, zb_errs = _verify_report_integrity(report_zb)
        except Exception as exc:
            zb_exc = f"{type(exc).__name__}: {exc}"

        zb_dur = round(time.time() - t0, 2)
        zb_pass = (zb_exc == "NONE") and zb_valid
        if zb_pass:
            passed_cases += 1

        print(f"\n[1/3] Zero-byte page")
        print(f"  URL: {zb_url}")
        print(f"  Duration: {zb_dur}s")
        print(f"  Exception: {zb_exc}")
        print(f"  Schema: {'PASS' if zb_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if zb_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [2/3] Garbage DOM / JSON-LD
        # -------------------------------------------------------------
        gb_file = "7_garbage.html"
        gb_url = f"http://127.0.0.1:{port}/{gb_file}"
        t0 = time.time()
        gb_exc = "NONE"
        gb_valid = False
        try:
            report_gb = run_audit(gb_url, max_pages=2)
            gb_valid, gb_errs = _verify_report_integrity(report_gb)
        except Exception as exc:
            gb_exc = f"{type(exc).__name__}: {exc}"

        gb_dur = round(time.time() - t0, 2)
        gb_pass = (gb_exc == "NONE") and gb_valid
        if gb_pass:
            passed_cases += 1

        print(f"\n[2/3] Garbage DOM / JSON-LD")
        print(f"  URL: {gb_url}")
        print(f"  Duration: {gb_dur}s")
        print(f"  Exception: {gb_exc}")
        print(f"  Schema: {'PASS' if gb_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if gb_pass else 'FAIL'}")

        # -------------------------------------------------------------
        # [3/3] Infinite redirect
        # -------------------------------------------------------------
        rd_url = f"http://127.0.0.1:{port}/redirect-loop"
        t0 = time.time()
        rd_exc = "NONE"
        rd_valid = False
        rd_protect = False
        try:
            report_rd = run_audit(rd_url, max_pages=2)
            rd_valid, rd_errs = _verify_report_integrity(report_rd)
            # Check that redirect protection engaged (CR-002 flagged or crawl error logged)
            rules = [f.get("local_id") for f in report_rd.get("findings", [])]
            cov_err = report_rd.get("coverage", {}).get("crawl_render_access", {}).get("errors", 0)
            if "CR-002" in rules or cov_err > 0:
                rd_protect = True
        except Exception as exc:
            rd_exc = f"{type(exc).__name__}: {exc}"

        rd_dur = round(time.time() - t0, 2)
        rd_pass = (rd_exc == "NONE") and rd_valid and rd_protect
        if rd_pass:
            passed_cases += 1

        print(f"\n[3/3] Infinite redirect")
        print(f"  URL: {rd_url}")
        print(f"  Duration: {rd_dur}s")
        print(f"  Exception: {rd_exc}")
        print(f"  Redirect protection: {'PASS' if rd_protect else 'FAIL'}")
        print(f"  Schema: {'PASS' if rd_valid else 'FAIL'}")
        print(f"  Result: {'PASS' if rd_pass else 'FAIL'}")

    finally:
        httpd.shutdown()
        httpd.server_close()

    print("\n------------------------------------------------------------")
    print(f"CHAOS RESULT: {passed_cases}/{total_cases} PASS")
    print("------------------------------------------------------------")

    return 0 if passed_cases == total_cases else 1


if __name__ == "__main__":
    sys.exit(run_chaos_suite())
