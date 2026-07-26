"""Build an evaluation corpus from the OWASP Benchmark for Python.

https://github.com/OWASP-Benchmark/BenchmarkPython (v0.1)

This is the corpus the project should be judged on. 1,230 test cases, each
labelled in expectedresults-0.1.csv with its category, CWE, and — the part
that matters — whether the vulnerability is real.

778 of the 1,230 are deliberately NOT vulnerable: code that looks dangerous
and is not. No other Python corpus available has that. SecurityEval is all
positives and PyGoat is a real application with partial labels, so neither
can measure precision; this one can, because a finding on a false case is
unambiguously wrong rather than merely unlabelled.

Note the repository lives under the OWASP-Benchmark organisation, not OWASP.
Searching the OWASP organisation alone returns nothing and invites the wrong
conclusion that no Python benchmark exists.

    git clone https://github.com/OWASP-Benchmark/BenchmarkPython
    python eval/prepare_benchmark.py --source /path/to/BenchmarkPython
"""

import argparse
import csv
import json
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

EVAL_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = EVAL_DIR / "datasets" / "benchmark"

# The benchmark scores a tool per test case rather than per line: a case is
# one file with one seeded defect. Its own scorecards work the same way.
MATCH_MODE = "file"


def load_expected(source: Path) -> List[Dict[str, str]]:
    """
    Read the benchmark's ground-truth CSV.

    Args:
        source: A BenchmarkPython checkout

    Returns:
        List[Dict[str, str]]: One row per test case, keys stripped

    Raises:
        SystemExit: When the file is missing
    """

    matches = sorted(source.glob("expectedresults-*.csv"))
    if not matches:
        print(f"error: no expectedresults-*.csv in {source}", file=sys.stderr)
        print("Clone it: git clone https://github.com/OWASP-Benchmark/BenchmarkPython",
              file=sys.stderr)
        raise SystemExit(2)

    # Header fields carry leading spaces in the published file.
    with matches[-1].open(encoding="utf-8") as handle:
        return [
            {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            for row in csv.DictReader(handle)
        ]


def build(source: Path, out: Path, limit: int = 0) -> Dict:
    """
    Copy the test cases and write their labels.

    Args:
        source: A BenchmarkPython checkout
        out: Destination dataset directory
        limit: Keep only this many cases, newest-first by name; 0 keeps all

    Returns:
        Dict: Summary counts
    """

    rows = load_expected(source)
    testcode = source / "testcode"
    if not testcode.is_dir():
        print(f"error: {testcode} not found", file=sys.stderr)
        raise SystemExit(2)

    samples = out / "samples"
    if samples.exists():
        shutil.rmtree(samples)
    samples.mkdir(parents=True, exist_ok=True)

    labels: List[Dict] = []
    clean: List[str] = []
    skipped = Counter()
    categories: Counter = Counter()
    copied = 0

    for row in rows:
        name = row.get("# test name") or row.get("test name") or ""
        if not name:
            skipped["no test name"] += 1
            continue

        source_file = testcode / f"{name}.py"
        if not source_file.is_file():
            skipped["source file missing"] += 1
            continue

        if limit and copied >= limit:
            skipped["beyond --limit"] += 1
            continue

        filename = f"{name}.py"
        shutil.copy2(source_file, samples / filename)
        copied += 1

        category = row.get("category", "")
        categories[category] += 1

        if row.get("real vulnerability", "").lower() == "true":
            labels.append({
                "file": filename,
                "line": 0,
                "cwe": row.get("cwe", "").strip(),
                "type": category.upper(),
                "note": f"OWASP Benchmark {name} ({category})",
            })
        else:
            # A finding here is wrong, not merely unlabelled. This is what
            # makes the corpus able to measure precision at all.
            clean.append(filename)

    payload = {
        "schema_version": 1,
        "name": "OWASP Benchmark for Python v0.1",
        "source": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "licence": "See the upstream repository",
        "match_mode": MATCH_MODE,
        "match_mode_note": (
            "One test case is one file with one seeded defect, and the "
            "benchmark's own scorecards score per case, so a detection counts "
            "when it reports an equivalent CWE anywhere in the file. Files "
            "listed under clean_files are deliberately non-vulnerable: a "
            "finding in one is a false positive, which is why this corpus can "
            "measure precision where the others cannot."
        ),
        "partial_labels": False,
        "clean_files": clean,
        "labels": labels,
    }
    (out / "labels.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return {
        "copied": copied,
        "vulnerable": len(labels),
        "clean": len(clean),
        "categories": dict(categories.most_common()),
        "skipped": dict(skipped),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the OWASP BenchmarkPython corpus.")
    parser.add_argument("--source", required=True, help="Path to a BenchmarkPython checkout")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Destination directory")
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Keep only this many test cases. A full run is 1,230 files; "
             "start smaller when the LLM tier is enabled."
    )
    args = parser.parse_args()

    summary = build(Path(args.source), Path(args.out), limit=args.limit)
    print(f"wrote {summary['copied']} test case(s) to {args.out}/samples")
    print(f"  vulnerable : {summary['vulnerable']}")
    print(f"  clean      : {summary['clean']}  (findings here are false positives)")
    print(f"  categories : {summary['categories']}")
    for reason, count in summary["skipped"].items():
        print(f"  skipped {count}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
