"""Build a stratified 50-file pilot evaluation dataset from OWASP Benchmark.

Selects 25 vulnerable files across representative CWE categories and 25 clean files,
enabling rapid, reproducible measurement of both Precision and Recall in ~2-3 minutes.
"""

import json
import shutil
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCHMARK_DIR = ROOT / "datasets" / "benchmark"
PILOT_DIR = ROOT / "datasets" / "pilot50"

def create_pilot(seed: int = 42, target_vuln: int = 25, target_clean: int = 25) -> None:
    random.seed(seed)
    labels_path = BENCHMARK_DIR / "labels.json"
    if not labels_path.is_file():
        raise FileNotFoundError(f"Source benchmark not found at {labels_path}")

    with open(labels_path, "r", encoding="utf-8") as f:
        bench_data = json.load(f)

    labels = bench_data.get("labels", [])
    clean_files = bench_data.get("clean_files", [])

    # Group labels by CWE
    by_cwe = defaultdict(list)
    for l in labels:
        by_cwe[l["cwe"]].append(l)

    # Key CWE targets: 22 (path), 78 (cmdi), 89 (sqli), 94 (codei), 79 (xss), 502 (deserial), 330 (rand), 328 (hash), 643 (xpath)
    priority_cwes = ["22", "78", "89", "94", "79", "502", "330", "328", "643"]
    selected_labels = []

    # Allocate roughly 2-3 per priority CWE
    for cwe in priority_cwes:
        items = by_cwe.get(cwe, [])
        sample_size = min(len(items), 3 if cwe in ("22", "78", "89", "79", "94", "330", "328") else 2)
        if sample_size > 0:
            selected_labels.extend(random.sample(items, sample_size))

    # Fill remaining from other CWEs if needed
    all_remaining = [l for l in labels if l not in selected_labels]
    needed = target_vuln - len(selected_labels)
    if needed > 0 and all_remaining:
        selected_labels.extend(random.sample(all_remaining, min(needed, len(all_remaining))))

    # Select clean files
    selected_clean = random.sample(clean_files, min(target_clean, len(clean_files)))

    # Prepare pilot directory
    samples_dir = PILOT_DIR / "samples"
    if samples_dir.exists():
        shutil.rmtree(samples_dir)
    samples_dir.mkdir(parents=True, exist_ok=True)

    # Copy files
    for l in selected_labels:
        src = BENCHMARK_DIR / "samples" / l["file"]
        if src.is_file():
            shutil.copy2(src, samples_dir / l["file"])

    for c in selected_clean:
        src = BENCHMARK_DIR / "samples" / c
        if src.is_file():
            shutil.copy2(src, samples_dir / c)

    pilot_data = {
        "schema_version": 1,
        "name": "OWASP BenchmarkPython Stratified Pilot 50",
        "source": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "licence": "OWASP Benchmark License",
        "match_mode": "file",
        "match_mode_note": "Stratified sample of 25 vulnerable cases and 25 clean control cases.",
        "partial_labels": False,
        "clean_files": sorted(selected_clean),
        "labels": sorted(selected_labels, key=lambda x: x["file"]),
    }

    with open(PILOT_DIR / "labels.json", "w", encoding="utf-8") as f:
        json.dump(pilot_data, f, indent=2, ensure_ascii=False)

    print(f"Created Pilot50 dataset at {PILOT_DIR}:")
    print(f"  Vulnerable cases: {len(selected_labels)}")
    print(f"  Clean cases:      {len(selected_clean)}")
    print(f"  Total test cases: {len(selected_labels) + len(selected_clean)}")

if __name__ == "__main__":
    create_pilot()
