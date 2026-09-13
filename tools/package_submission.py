#!/usr/bin/env python3
"""
package_submission.py
=====================
Submission packaging and validation script for Adobe Hackathon Round 3.

Builds a clean, deterministic, production-ready submission ZIP archive:
- Whitelists only official submission files and directories
- Excludes git metadata, caches (__pycache__, .pytest_cache), bytecodes (*.pyc),
  internal tools, OS clutter, and local artifacts
- Normalizes file attributes, timestamps, and permissions (0o644 / 0o755)
- Verifies archive integrity by unpacking into a clean sandbox and running
  smoke validation
- Outputs exact file count, uncompressed and compressed sizes, and SHA-256 digest
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files in repo root to include
ROOT_FILES = [
    "README.md",
    "PROJECT_CONTEXT.md",
    "PROJECT_DESCRIPTION.md",
    "marketplace.json",
    "requirements.txt",
    "pytest.ini",
]

# Directories to include
INCLUDE_DIRS = [
    "skills",
    "tests",
]

# Patterns to strictly exclude anywhere
EXCLUDE_DIR_NAMES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "tools",
    "scratch",
}

EXCLUDE_FILE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".log",
    ".tmp",
    ".zip",
    ".tar",
    ".gz",
}

EXCLUDE_FILE_NAMES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".coverage",
}


def should_include_file(path: Path) -> bool:
    """Return True if path should be included in the submission."""
    # Check parts for excluded directories
    for part in path.parts:
        if part in EXCLUDE_DIR_NAMES:
            return False

    if path.name in EXCLUDE_FILE_NAMES:
        return False

    if path.suffix in EXCLUDE_FILE_EXTENSIONS:
        return False

    return True


def collect_submission_files(repo_root: Path) -> list[Path]:
    """Collect and sort all eligible submission files deterministically."""
    files: list[Path] = []

    # 1. Root files
    for fname in ROOT_FILES:
        fpath = repo_root / fname
        if fpath.is_file():
            files.append(fpath)
        else:
            print(f"WARNING: Expected root file not found: {fname}", file=sys.stderr)

    # 2. Directory trees
    for dname in INCLUDE_DIRS:
        dpath = repo_root / dname
        if not dpath.is_dir():
            print(f"WARNING: Expected directory not found: {dname}", file=sys.stderr)
            continue
        for root, dirs, filenames in os.walk(dpath):
            # Prune excluded directories in-place
            dirs[:] = [d for d in sorted(dirs) if d not in EXCLUDE_DIR_NAMES]
            for fname in sorted(filenames):
                fpath = Path(root) / fname
                if should_include_file(fpath):
                    files.append(fpath)

    # Return deterministically sorted list
    return sorted(files, key=lambda p: p.relative_to(repo_root).as_posix())


def create_submission_zip(output_zip: Path, repo_root: Path) -> tuple[int, int, str]:
    """Package submission files into a standard, clean ZIP file."""
    files = collect_submission_files(repo_root)
    total_uncompressed = sum(f.stat().st_size for f in files)

    # Fixed timestamp for reproducible archiving: 2026-03-01 12:00:00
    fixed_time = (2026, 3, 1, 12, 0, 0)

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    with zipfile.ZipFile(output_zip, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for fpath in files:
            rel_path = fpath.relative_to(repo_root).as_posix()
            data = fpath.read_bytes()

            zinfo = zipfile.ZipInfo(filename=rel_path, date_time=fixed_time)
            # Set POSIX file permissions
            if fpath.suffix in (".py", ".sh") or "scripts" in fpath.parts:
                zinfo.external_attr = 0o755 << 16  # rwxr-xr-x
            else:
                zinfo.external_attr = 0o644 << 16  # rw-r--r--
            zinfo.compress_type = zipfile.ZIP_DEFLATED

            zf.writestr(zinfo, data)

    compressed_size = output_zip.stat().st_size

    # Compute SHA-256
    hasher = hashlib.sha256()
    with open(output_zip, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    sha256_hex = hasher.hexdigest()

    return len(files), total_uncompressed, sha256_hex


def verify_zip_archive(zip_path: Path) -> bool:
    """Verify ZIP by unpacking into a temp directory and performing sanity checks."""
    print(f"\n--- Verifying Archive Integrity: {zip_path.name} ---")
    temp_dir = Path(tempfile.mkdtemp(prefix="submission_verify_"))
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            bad_file = zf.testzip()
            if bad_file:
                print(f"FAILED: Corrupt file in ZIP: {bad_file}", file=sys.stderr)
                return False
            zf.extractall(temp_dir)

        # Verify essential entrypoints
        entrypoint = temp_dir / "skills" / "audit-orchestrator" / "scripts" / "aggregate.py"
        if not entrypoint.is_file():
            print(f"FAILED: Entrypoint missing after extraction: {entrypoint}", file=sys.stderr)
            return False

        # Verify marketplace.json
        mp_path = temp_dir / "marketplace.json"
        if not mp_path.is_file():
            print(f"FAILED: marketplace.json missing after extraction", file=sys.stderr)
            return False

        # Verify all 5 skills exist
        expected_skills = [
            "audit-orchestrator",
            "crawl-render-access",
            "structured-fact-extraction",
            "trust-entity-corroboration",
            "engagement-retention",
        ]
        for skill in expected_skills:
            skill_md = temp_dir / "skills" / skill / "SKILL.md"
            if not skill_md.is_file():
                print(f"FAILED: {skill}/SKILL.md missing after extraction", file=sys.stderr)
                return False

        # Ensure no __pycache__ or .pyc leaked
        leaked = list(temp_dir.rglob("__pycache__")) + list(temp_dir.rglob("*.pyc"))
        if leaked:
            print(f"FAILED: Leaked caches or bytecodes found: {leaked}", file=sys.stderr)
            return False

        print("SUCCESS: Archive verified cleanly! All skills, entrypoints, and schemas intact.")
        return True
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    output_zip = REPO_ROOT / "brand-ai-readiness-audit-final.zip"
    print(f"Packaging submission archive from: {REPO_ROOT}")
    print(f"Destination: {output_zip}")

    count, uncompressed_bytes, sha256_hash = create_submission_zip(output_zip, REPO_ROOT)
    compressed_bytes = output_zip.stat().st_size
    ratio = (1.0 - (compressed_bytes / uncompressed_bytes)) * 100 if uncompressed_bytes else 0

    print(f"\n=======================================================")
    print(f"SUBMISSION PACKAGE SUMMARY")
    print(f"=======================================================")
    print(f"Archive File:         {output_zip.name}")
    print(f"Total Files Included: {count}")
    print(f"Uncompressed Size:    {uncompressed_bytes / 1024:.1f} KB ({uncompressed_bytes:,} bytes)")
    print(f"Compressed Size:      {compressed_bytes / 1024:.1f} KB ({compressed_bytes:,} bytes)")
    print(f"Compression Ratio:    {ratio:.1f}% reduction")
    print(f"SHA-256 Checksum:     {sha256_hash}")
    print(f"=======================================================")

    if not verify_zip_archive(output_zip):
        print("Packaging validation FAILED.", file=sys.stderr)
        return 1

    print("\nAll packaging checks PASSED successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
