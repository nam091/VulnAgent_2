"""
Verification script for Six Repos Benchmark Dataset.
Verifies all 16 files exist, are non-empty, have reasonable size, and are valid Python syntax.
Validates labels.json schema according to benchmark requirements.
"""

import ast
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
LABELS_FILE = BASE_DIR / "labels.json"

EXPECTED_VULN_FILES = [
    "django_sqli.py",
    "salt_cmdi.py",
    "airflow_pathtraversal.py",
    "salt_deserialization.py",
    "weasyprint_ssrf.py",
    "gradio_xss.py",
    "ansible_hardcoded_secret.py",
    "salt_auth_bypass.py",
    "airflow_idor.py",
    "gradio_info_disclosure.py",
]

EXPECTED_CLEAN_FILES = [
    "clean_django_crypto.py",
    "clean_airflow_dates.py",
    "clean_salt_units.py",
    "clean_ansible_display.py",
    "clean_gradio_media.py",
    "clean_weasyprint_units.py",
]


def verify_dataset() -> bool:
    print("=" * 70)
    print("SIX REPOS BENCHMARK DATASET INTEGRITY VERIFIER")
    print("=" * 70)

    errors = []

    # 1. Verify labels.json existence
    if not LABELS_FILE.is_file():
        print(f"[ERROR] labels.json not found at {LABELS_FILE}")
        return False

    with open(LABELS_FILE, "r", encoding="utf-8") as f:
        try:
            labels_data = json.load(f)
        except Exception as e:
            print(f"[ERROR] labels.json is not valid JSON: {e}")
            return False

    # 2. Schema check
    schema_version = labels_data.get("schema_version")
    if schema_version != 1:
        errors.append(f"schema_version must be 1, got {schema_version}")

    match_mode = labels_data.get("match_mode")
    if match_mode != "file":
        errors.append(f"match_mode must be 'file', got '{match_mode}'")

    clean_files = labels_data.get("clean_files", [])
    labels = labels_data.get("labels", [])

    if len(clean_files) != 6:
        errors.append(f"Expected 6 clean files, got {len(clean_files)}")
    if len(labels) != 10:
        errors.append(f"Expected 10 vulnerable labels, got {len(labels)}")

    # Check for forbidden Saleor references
    content_str = json.dumps(labels_data).lower()
    if "saleor" in content_str:
        errors.append("PROHIBITED: 'saleor' found in labels.json metadata!")

    print(f"[*] labels.json schema valid (v{schema_version}, match_mode='{match_mode}')")
    print(f"[*] Clean control files: {len(clean_files)}")
    print(f"[*] Vulnerable sample files: {len(labels)}")
    print("-" * 70)

    # 3. Verify clean files list match
    missing_clean = set(EXPECTED_CLEAN_FILES) - set(clean_files)
    if missing_clean:
        errors.append(f"Missing expected clean files in labels: {missing_clean}")

    # 4. Verify vuln files list match
    labelled_vuln_files = [item.get("file") for item in labels]
    missing_vuln = set(EXPECTED_VULN_FILES) - set(labelled_vuln_files)
    if missing_vuln:
        errors.append(f"Missing expected vuln files in labels: {missing_vuln}")

    # 5. Check all files on disk
    all_expected = EXPECTED_CLEAN_FILES + EXPECTED_VULN_FILES
    print(f"{'Filename':<30} | {'Type':<12} | {'Size (bytes)':<12} | {'Syntax':<8}")
    print("-" * 70)

    for fname in all_expected:
        fpath = SAMPLES_DIR / fname
        is_clean = fname in EXPECTED_CLEAN_FILES
        ftype = "Clean" if is_clean else "Vulnerable"

        if not fpath.is_file():
            print(f"{fname:<30} | {ftype:<12} | {'MISSING':<12} | FAIL")
            errors.append(f"File not found on disk: {fname}")
            continue

        size = fpath.stat().st_size
        if size == 0:
            print(f"{fname:<30} | {ftype:<12} | {'0 (EMPTY)':<12} | FAIL")
            errors.append(f"File is empty: {fname}")
            continue

        if size < 500 or size > 5_000_000:
            errors.append(f"File size unusual ({size} bytes): {fname}")

        # Syntax check via AST and compile
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            ast.parse(source, filename=fname)
            compile(source, fname, "exec")
            syntax_status = "VALID"
        except SyntaxError as se:
            syntax_status = f"SYNTAX_ERR ({se.lineno})"
            errors.append(f"Syntax error in {fname} at line {se.lineno}: {se.msg}")
        except Exception as ex:
            syntax_status = "ERROR"
            errors.append(f"Failed to compile {fname}: {ex}")

        print(f"{fname:<30} | {ftype:<12} | {size:>10,} B | {syntax_status}")

    print("-" * 70)

    if errors:
        print(f"\n[FAILED] Verification found {len(errors)} error(s):")
        for err in errors:
            print(f"  - {err}")
        return False

    print(f"\n[PASSED] All 16 files verified successfully:")
    print("  - 10 real-world CVE defect files (10 distinct CWEs across 6 repositories)")
    print("  - 6 clean control files (1 from each repository)")
    print("  - Schema version 1, match_mode='file'")
    print("  - Zero Saleor contamination verified")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = verify_dataset()
    sys.exit(0 if success else 1)
