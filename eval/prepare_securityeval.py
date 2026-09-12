"""Build an evaluation corpus from the SecurityEval dataset.

SecurityEval (Siddiq & Santos, MSR 2022 — https://github.com/s2e-lab/SecurityEval)
ships 121 Python samples whose CWE is encoded in the identifier. It is the
right corpus for this project for one reason above all: it was built to
evaluate LLM code generation, not to test any particular scanner, so it is
independent of Semgrep, Bandit and the LLM tier alike.

That independence is the point. Bandit's own `examples/` and Semgrep's rule
test files come with line-level annotations and are tempting, but scoring an
engine on the corpus its authors wrote to test that engine measures nothing —
and the rule tier here runs Semgrep's rules.

    python eval/prepare_securityeval.py --source /path/to/SecurityEval
"""

import argparse
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List

EVAL_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = EVAL_DIR / "datasets" / "securityeval"

# CWEs that describe a defect a static analyser can reasonably be asked to
# find in a single file. The rest of SecurityEval covers issues that need
# runtime context, configuration outside the snippet, or human judgement
# about business logic, where scoring a scanner would say more about the
# corpus than the tool.
IN_SCOPE_CWES = {
    "020", "022", "078", "079", "080", "089", "090", "094", "095",
    "113", "116", "117", "119", "120", "193", "200", "215", "252",
    "259", "269", "283", "285", "295", "306", "319", "321", "326",
    "327", "329", "330", "331", "339", "347", "352", "367", "377",
    "379", "385", "400", "409", "414", "425", "434", "441", "462",
    "477", "494", "502", "521", "522", "595", "601", "605", "611",
    "641", "643", "652", "703", "730", "759", "760", "776", "798",
    "827", "835", "841", "918", "941", "943", "1204", "1236", "1333",
}


def load_entries(source: Path) -> List[Dict]:
    """
    Read the SecurityEval dataset file.

    Args:
        source: Path to a SecurityEval checkout

    Returns:
        List[Dict]: Dataset entries
    """

    dataset = source / "dataset.jsonl"
    if not dataset.is_file():
        print(f"error: {dataset} not found", file=sys.stderr)
        print("Clone it: git clone https://github.com/s2e-lab/SecurityEval", file=sys.stderr)
        raise SystemExit(2)

    return [
        json.loads(line)
        for line in dataset.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build(source: Path, out: Path, include_prompt: bool = True) -> Dict:
    """
    Write the corpus and its label file.

    Args:
        source: SecurityEval checkout
        out: Destination dataset directory
        include_prompt: Prepend the prompt's imports and signature, so the
            sample is a complete module rather than a bare function body

    Returns:
        Dict: Summary counts
    """

    samples_dir = out / "samples"
    if samples_dir.exists():
        shutil.rmtree(samples_dir)
    samples_dir.mkdir(parents=True, exist_ok=True)

    labels = []
    skipped = Counter()
    written = 0

    for entry in load_entries(source):
        identifier = entry.get("ID", "")
        match = re.match(r"CWE-(\d+)_", identifier)
        if not match:
            skipped["unparseable id"] += 1
            continue

        cwe = match.group(1)
        if cwe.lstrip("0") and cwe not in IN_SCOPE_CWES:
            skipped[f"CWE-{cwe} out of scope"] += 1
            continue

        code = entry.get("Insecure_code") or ""
        if not code.strip():
            skipped["no insecure_code"] += 1
            continue

        # The insecure completion often omits the imports that appear in the
        # prompt; without them the file does not parse and every engine
        # scores zero for the wrong reason.
        if include_prompt:
            prompt = entry.get("Prompt") or ""
            imports = "\n".join(
                line for line in prompt.split("\n")
                if re.match(r"^\s*(import|from)\s", line)
            )
            if imports and imports not in code:
                code = imports + "\n\n" + code

        name = identifier if identifier.endswith(".py") else f"{identifier}.py"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        (samples_dir / name).write_text(code, encoding="utf-8")

        labels.append({
            "file": name,
            "line": 0,
            "cwe": cwe.lstrip("0") or "0",
            "type": "",
            "note": f"SecurityEval {identifier}",
        })
        written += 1

    payload = {
        "schema_version": 1,
        "name": "SecurityEval",
        "source": "https://github.com/s2e-lab/SecurityEval",
        "citation": (
            "Siddiq & Santos, SecurityEval Dataset: Mining Vulnerability "
            "Examples to Evaluate Machine Learning-Based Code Generation "
            "Techniques, MSR 2022."
        ),
        "match_mode": "file",
        "match_mode_note": (
            "Samples carry a CWE label but no annotated sink line, so a "
            "detection counts when it reports an equivalent CWE anywhere in "
            "the file. Every sample is known-vulnerable and there are no "
            "clean counterparts, so this corpus measures recall. Precision "
            "requires the hand-labelled dataset, which includes clean files."
        ),
        "clean_files": [],
        "partial_labels": True,
        "labels": labels,
    }

    (out / "labels.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    return {"written": written, "skipped": dict(skipped)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the SecurityEval corpus.")
    parser.add_argument(
        "--source", required=True,
        help="Path to a SecurityEval checkout"
    )
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Destination directory")
    args = parser.parse_args()

    summary = build(Path(args.source), Path(args.out))
    print(f"wrote {summary['written']} sample(s) to {args.out}/samples")
    for reason, count in sorted(summary["skipped"].items(), key=lambda kv: -kv[1])[:8]:
        print(f"  skipped {count}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
