import json
import os
import sys

def verify_dataset():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(base_dir, "samples")
    labels_file = os.path.join(base_dir, "labels.json")

    print(f"Checking dataset directory: {base_dir}")
    if not os.path.isfile(labels_file):
        print(f"ERROR: labels.json not found at {labels_file}")
        sys.exit(1)

    with open(labels_file, "r", encoding="utf-8") as f:
        labels_data = json.load(f)

    clean_files = labels_data.get("clean_files", [])
    vuln_files = [item["file"] for item in labels_data.get("labels", [])]

    expected_files = clean_files + vuln_files
    print(f"Total expected files in labels.json: {len(expected_files)} (5 clean, 10 vulnerable)")

    assert len(clean_files) == 5, f"Expected 5 clean files, got {len(clean_files)}"
    assert len(vuln_files) == 10, f"Expected 10 vuln files, got {len(vuln_files)}"

    missing_or_empty = []
    for fname in expected_files:
        fpath = os.path.join(samples_dir, fname)
        if not os.path.isfile(fpath):
            print(f"[-] MISSING: {fname}")
            missing_or_empty.append((fname, "missing"))
        else:
            size = os.path.getsize(fpath)
            if size == 0:
                print(f"[-] EMPTY: {fname}")
                missing_or_empty.append((fname, "empty"))
            else:
                print(f"[+] VALID: {fname:<25} ({size:>6} bytes)")

    if missing_or_empty:
        print(f"\nVerification FAILED: {len(missing_or_empty)} files invalid.")
        sys.exit(1)
    else:
        print(f"\nVerification PASSED: All {len(expected_files)} files exist and are non-empty.")

if __name__ == "__main__":
    verify_dataset()
