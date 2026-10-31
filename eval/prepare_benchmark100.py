"""Build a stratified 100-file benchmark evaluation dataset from official OWASP Benchmark.

Selects exactly 50 vulnerable files across 11 representative CWE categories and
exactly 50 verified clean control files, ensuring a 50/50 balance with 100% original
BenchmarkTestXXXXX.py naming and rigorous international ground-truth.
"""

import json
import shutil
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BENCHMARK_DIR = ROOT / "datasets" / "benchmark"
BENCHMARK100_DIR = ROOT / "datasets" / "benchmark100"

def create_benchmark100(seed: int = 42, target_vuln: int = 50, target_clean: int = 50) -> None:
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

    # 11 Core CWE targets:
    # CWE-89 (SQLi): 5 files (take all 5 available)
    # CWE-78 (CMDi): 5 files
    # CWE-22 (Path Traversal): 5 files
    # CWE-502 (Insecure Deserialization): 5 files
    # CWE-79 (XSS): 5 files
    # CWE-94 (Code Injection): 5 files
    # CWE-643 (XPath Injection): 5 files
    # CWE-328 (Weak Hashing): 5 files
    # CWE-330 (Insecure Randomness): 5 files
    # CWE-611 (XXE): 3 files
    # CWE-601 (Open Redirect): 2 files
    # Total = 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 3 + 2 = 50 vulnerable files!

    allocation = {
        "89": 5,
        "78": 5,
        "22": 5,
        "502": 5,
        "79": 5,
        "94": 5,
        "643": 5,
        "328": 5,
        "330": 5,
        "611": 3,
        "601": 2,
    }

    selected_labels = []
    for cwe, count in allocation.items():
        items = by_cwe.get(cwe, [])
        sample_size = min(len(items), count)
        selected_labels.extend(random.sample(items, sample_size))

    # Fallback if any CWE had fewer than target
    if len(selected_labels) < target_vuln:
        remaining = [l for l in labels if l not in selected_labels]
        needed = target_vuln - len(selected_labels)
        selected_labels.extend(random.sample(remaining, needed))

    selected_labels = selected_labels[:target_vuln]

    # Select exactly 50 clean files
    selected_clean = random.sample(clean_files, target_clean)

    # Prepare directory
    samples_dir = BENCHMARK100_DIR / "samples"
    if samples_dir.exists():
        shutil.rmtree(samples_dir)
    samples_dir.mkdir(parents=True, exist_ok=True)

    # Copy files
    for l in selected_labels:
        src = BENCHMARK_DIR / "samples" / l["file"]
        if src.is_file():
            shutil.copy2(src, samples_dir / l["file"])
        else:
            raise FileNotFoundError(f"Missing sample file: {src}")

    for c in selected_clean:
        src = BENCHMARK_DIR / "samples" / c
        if src.is_file():
            shutil.copy2(src, samples_dir / c)
        else:
            raise FileNotFoundError(f"Missing clean file: {src}")

    benchmark100_data = {
        "schema_version": 1,
        "name": "OWASP BenchmarkPython 100 (50 Vuln + 50 Clean)",
        "source": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "licence": "OWASP Benchmark License",
        "match_mode": "file",
        "match_mode_note": "Rigorous stratified benchmark of exactly 50 vulnerable cases across 11 core CWE categories and 50 clean control cases from official OWASP BenchmarkPython.",
        "partial_labels": False,
        "clean_files": sorted(selected_clean),
        "labels": sorted(selected_labels, key=lambda x: x["file"]),
    }

    out_json = BENCHMARK100_DIR / "labels.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(benchmark100_data, f, indent=2)

    print(f"Successfully generated {BENCHMARK100_DIR}:")
    print(f"  Vulnerable files: {len(selected_labels)} across {len(allocation)} CWE groups")
    print(f"  Clean control files: {len(selected_clean)}")
    print(f"  Total files in samples: {len(list(samples_dir.glob('*.py')))}")

if __name__ == "__main__":
    create_benchmark100()
