"""Quantitative evaluation against a hand-labelled dataset.

Reports precision, recall and F1 for each engine configuration so the claim
that the hybrid beats either tier alone can be checked rather than asserted.

    python eval/run_eval.py                 # every configuration
    python eval/run_eval.py --only hybrid   # one configuration
    python eval/run_eval.py --json out.json # machine-readable results
"""

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from analyzer.scanner import ScanOptions, Scanner  # noqa: E402
from models.vulnerability import FindingSource, Vulnerability  # noqa: E402

DATASET_DIR = Path(__file__).resolve().parent / "dataset"
LABELS_FILE = DATASET_DIR / "labels.json"
SAMPLES_DIR = DATASET_DIR / "samples"

# A detection counts as a hit when it lands within this many lines of the
# labelled location. Static analysers anchor on the sink, humans sometimes
# label the tainted assignment a line or two above.
LINE_TOLERANCE = 3

# Different engines pick different, equally defensible CWEs for the same
# defect: Bandit calls a literal password CWE-259, VulnAgent calls it CWE-798;
# Semgrep files md5-for-passwords under CWE-327, this dataset under CWE-328.
# Requiring exact equality would score a correct detection as a false positive
# *and* a false negative at once, which quietly flatters whichever engine the
# labels were written against. Equivalence classes remove that bias.
CWE_EQUIVALENCE: Tuple[Set[str], ...] = (
    {"798", "259", "260", "321", "798"},           # hard-coded credentials
    {"326", "327", "328", "916"},                   # weak crypto / hashing
    {"330", "335", "338"},                          # insecure randomness
    {"16", "605", "668", "489", "1188"},            # misconfiguration / exposure
    {"22", "23", "35", "36", "73"},                 # path traversal
    {"79", "80", "116"},                            # cross-site scripting
    {"77", "78", "88"},                             # command injection
    {"94", "95", "96"},                             # code injection
    {"611", "776", "827"},                          # XML external entity
    {"502", "915"},                                 # deserialization
    {"89", "564", "943"},                           # SQL injection
    {"918", "441"},                                 # SSRF
    {"287", "306", "521", "307"},                   # broken authentication
)


def cwe_matches(detected: str, labelled: str) -> bool:
    """
    Decide whether two CWE identifiers denote the same defect.

    Args:
        detected: CWE number reported by an engine
        labelled: CWE number recorded in the dataset

    Returns:
        bool: True on an exact match, a known equivalence, or missing data
    """

    if not detected or not labelled:
        return True  # nothing to contradict; position and file still had to agree
    if detected == labelled:
        return True
    return any(
        detected in group and labelled in group
        for group in CWE_EQUIVALENCE
    )


@dataclass
class Label:
    """
    One hand-labelled vulnerability in the dataset.
    """

    file: str
    line: int
    cwe: str
    type: str
    note: str = ""

    def key(self) -> Tuple[str, int, str]:
        return (self.file, self.line, self.cwe)


@dataclass
class Detection:
    """
    One finding produced by an engine under evaluation.
    """

    file: str
    line: int
    cwe: str
    type: str
    source: str = ""


@dataclass
class Metrics:
    """
    Confusion-matrix counts and the scores derived from them.
    """

    name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    seconds: float = 0.0
    missed: List[str] = field(default_factory=list)
    spurious: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if not (self.precision + self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "seconds": round(self.seconds, 2),
            "missed": self.missed,
            "spurious": self.spurious,
        }


def load_labels() -> List[Label]:
    """
    Read the ground-truth labels.

    Returns:
        List[Label]: Every labelled vulnerability

    Raises:
        SystemExit: When the dataset is missing
    """

    if not LABELS_FILE.is_file():
        print(f"error: no labels at {LABELS_FILE}", file=sys.stderr)
        print("Create it following the schema in eval/README.md.", file=sys.stderr)
        raise SystemExit(2)

    payload = json.loads(LABELS_FILE.read_text(encoding="utf-8"))
    labels = []
    for entry in payload.get("labels", []):
        labels.append(Label(
            file=entry["file"],
            line=int(entry["line"]),
            cwe=str(entry["cwe"]).replace("CWE-", "").strip(),
            type=entry.get("type", ""),
            note=entry.get("note", "")
        ))
    return labels


def match(detections: Sequence[Detection], labels: Sequence[Label], name: str) -> Metrics:
    """
    Score detections against ground truth.

    Each label may be satisfied by at most one detection, and each detection
    may satisfy at most one label, so neither duplicate findings nor a single
    catch-all finding can inflate the score.

    Args:
        detections: Findings from one engine
        labels: Ground-truth labels
        name: Configuration name for the report

    Returns:
        Metrics: Scored result
    """

    metrics = Metrics(name=name)
    claimed_labels: Set[int] = set()
    matched_detections: Set[int] = set()

    for d_index, detection in enumerate(detections):
        for l_index, label in enumerate(labels):
            if l_index in claimed_labels:
                continue
            if detection.file != label.file:
                continue
            if abs(detection.line - label.line) > LINE_TOLERANCE:
                continue
            # CWE is the interoperable key; type names differ per engine.
            if not cwe_matches(detection.cwe, label.cwe):
                continue
            claimed_labels.add(l_index)
            matched_detections.add(d_index)
            break

    metrics.true_positives = len(claimed_labels)
    metrics.false_positives = len(detections) - len(matched_detections)
    metrics.false_negatives = len(labels) - len(claimed_labels)

    metrics.missed = [
        f"{l.file}:{l.line} {l.type or 'CWE-' + l.cwe}"
        for i, l in enumerate(labels) if i not in claimed_labels
    ]
    metrics.spurious = [
        f"{d.file}:{d.line} {d.type or 'CWE-' + d.cwe}"
        for i, d in enumerate(detections) if i not in matched_detections
    ]
    return metrics


def _to_detection(vuln: Vulnerability) -> Detection:
    """
    Convert a VulnAgent finding into a comparable detection.

    Args:
        vuln: The finding

    Returns:
        Detection: Normalised form
    """

    return Detection(
        file=Path(vuln.location.file_path).name,
        line=vuln.location.start_line,
        cwe=str(vuln.cwe_id).replace("CWE-", "").strip(),
        type=vuln.type.value,
        source=vuln.source.value,
    )


async def run_vulnagent(
    use_llm: bool,
    use_semgrep: bool,
    confirmed_only: bool = False
) -> Tuple[List[Detection], float]:
    """
    Run one VulnAgent configuration over the dataset.

    Args:
        use_llm: Enable the LLM tier
        use_semgrep: Enable the rule tier
        confirmed_only: Keep only findings both tiers agreed on

    Returns:
        Tuple[List[Detection], float]: Detections and elapsed seconds
    """

    options = ScanOptions(
        target=str(SAMPLES_DIR),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        concurrency=5,
        use_cache=True,
    )
    result = await Scanner(options).scan()

    findings = result.vulnerabilities
    if confirmed_only:
        findings = [v for v in findings if v.source == FindingSource.CONFIRMED]

    return [_to_detection(v) for v in findings], result.stats.get("total_seconds", 0.0)


def run_bandit() -> Tuple[List[Detection], float]:
    """
    Run Bandit as an external baseline.

    Returns:
        Tuple[List[Detection], float]: Detections and elapsed seconds
    """

    executable = shutil.which("bandit")
    if not executable:
        print("  bandit not installed; skipping (pip install bandit)")
        return [], 0.0

    import time
    started = time.perf_counter()
    proc = subprocess.run(
        [executable, "-r", str(SAMPLES_DIR), "-f", "json", "-q"],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    elapsed = time.perf_counter() - started

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        print("  bandit produced unparseable output; skipping")
        return [], elapsed

    detections = []
    for item in payload.get("results", []):
        cwe = item.get("issue_cwe", {}) or {}
        detections.append(Detection(
            file=Path(item.get("filename", "")).name,
            line=int(item.get("line_number", 0)),
            cwe=str(cwe.get("id", "")).strip(),
            type=item.get("test_name", ""),
            source="bandit",
        ))
    return detections, elapsed


def render_table(results: List[Metrics]) -> str:
    """
    Format the comparison table.

    Args:
        results: Scored configurations

    Returns:
        str: A fixed-width table
    """

    header = (
        f"{'configuration':<22} {'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'precision':>10} {'recall':>8} {'F1':>7} {'sec':>7}"
    )
    lines = [header, "-" * len(header)]
    for metrics in results:
        lines.append(
            f"{metrics.name:<22} {metrics.true_positives:>4} {metrics.false_positives:>4} "
            f"{metrics.false_negatives:>4} {metrics.precision:>10.3f} "
            f"{metrics.recall:>8.3f} {metrics.f1:>7.3f} {metrics.seconds:>7.1f}"
        )
    return "\n".join(lines)


CONFIGURATIONS = {
    "hybrid": ("VulnAgent (hybrid)", dict(use_llm=True, use_semgrep=True)),
    "confirmed": ("VulnAgent (confirmed)", dict(use_llm=True, use_semgrep=True, confirmed_only=True)),
    "semgrep": ("Semgrep only", dict(use_llm=False, use_semgrep=True)),
    "llm": ("LLM only", dict(use_llm=True, use_semgrep=False)),
}


async def main() -> int:
    """
    Run the evaluation.

    Returns:
        int: Process exit code
    """

    parser = argparse.ArgumentParser(description="Evaluate VulnAgent against labelled data.")
    parser.add_argument(
        "--only", choices=list(CONFIGURATIONS) + ["bandit"], action="append",
        help="Run only the named configuration (repeatable)"
    )
    parser.add_argument("--json", help="Write full results to a JSON file")
    parser.add_argument("--no-bandit", action="store_true", help="Skip the Bandit baseline")
    args = parser.parse_args()

    labels = load_labels()
    files = sorted({l.file for l in labels})
    print(f"Dataset: {len(labels)} labelled vulnerabilities across {len(files)} file(s)\n")

    selected = args.only or list(CONFIGURATIONS)
    results: List[Metrics] = []

    for key in CONFIGURATIONS:
        if key not in selected:
            continue
        name, kwargs = CONFIGURATIONS[key]
        print(f"running {name}...")
        detections, seconds = await run_vulnagent(**kwargs)
        metrics = match(detections, labels, name)
        metrics.seconds = seconds
        results.append(metrics)

    if not args.no_bandit and (not args.only or "bandit" in selected):
        print("running Bandit...")
        detections, seconds = run_bandit()
        if detections:
            metrics = match(detections, labels, "Bandit (baseline)")
            metrics.seconds = seconds
            results.append(metrics)

    print()
    print(render_table(results))
    print()

    for metrics in results:
        if metrics.missed:
            print(f"{metrics.name} missed:")
            for item in metrics.missed:
                print(f"    {item}")
        if metrics.spurious:
            print(f"{metrics.name} false positives:")
            for item in metrics.spurious:
                print(f"    {item}")
        if metrics.missed or metrics.spurious:
            print()

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "dataset": {"labels": len(labels), "files": len(files)},
                    "line_tolerance": LINE_TOLERANCE,
                    "results": [m.as_dict() for m in results],
                },
                indent=2, ensure_ascii=False
            ),
            encoding="utf-8"
        )
        print(f"wrote {args.json}")

    if len(labels) < 30:
        print(
            f"\nNOTE: {len(labels)} labels is too few for the numbers above to be "
            "meaningful. Treat this as a smoke test until the dataset reaches "
            "roughly 50-100 labelled vulnerabilities."
        )

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
