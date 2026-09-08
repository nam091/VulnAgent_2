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

DEFAULT_DATASET = Path(__file__).resolve().parent / "dataset"

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
    {"798", "259", "260", "321"},                   # hard-coded credentials
    {"326", "327", "328", "916"},                   # weak crypto / hashing
    {"330", "335", "338"},                          # insecure randomness
    {"16", "605", "668", "489", "1188"},            # misconfiguration / exposure
    {"22", "23", "35", "36", "73"},                 # path traversal
    {"79", "80", "116"},                            # cross-site scripting
    {"77", "78", "88"},                             # command injection
    {"94", "95", "96"},                             # code injection
    {"611", "827"},                                 # XML external entity (XXE)
    {"776", "400"},                                 # XML entity expansion / DoS
    {"502", "915"},                                 # deserialization
    {"89", "564", "943"},                           # SQL injection
    {"918", "441"},                                 # SSRF
    {"287", "306", "521", "307"},                   # broken authentication
)


def cwe_matches(detected: str, labelled: str, exact: bool = False) -> bool:
    """
    Decide whether two CWE identifiers denote the same defect.

    Args:
        detected: CWE number reported by an engine
        labelled: CWE number recorded in the dataset
        exact: Require exact numerical match without equivalence class

    Returns:
        bool: True on match, False on mismatch or missing CWE
    """

    det = (detected or "").strip().upper().replace("CWE-", "")
    lab = (labelled or "").strip().upper().replace("CWE-", "")

    if not det or not lab:
        return False  # missing CWE cannot claim a match
    if det == lab:
        return True
    if exact:
        return False
    return any(
        det in group and lab in group
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
    partial: bool = False
    unmatched: int = 0
    fp_on_clean: int = 0
    fp_wrong_type: int = 0
    missed: List[str] = field(default_factory=list)
    spurious: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        if self.partial:
            return float("nan")   # not measurable against partial ground truth
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.partial:
            return float("nan")   # follows precision
        if not (self.precision + self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "precision": None if self.partial else round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": None if self.partial else round(self.f1, 4),
            "unmatched": self.unmatched,
            "fp_on_clean_files": self.fp_on_clean,
            "fp_wrong_type_right_file": self.fp_wrong_type,
            "partial_ground_truth": self.partial,
            "seconds": round(self.seconds, 2),
            "missed": self.missed,
            "spurious": self.spurious,
        }


def load_dataset(dataset_dir: Path) -> Tuple[List[Label], Dict[str, Any]]:
    """
    Read a dataset's labels and configuration.

    Args:
        dataset_dir: Directory holding labels.json and samples/

    Returns:
        Tuple[List[Label], Dict[str, Any]]: Labels and dataset metadata

    Raises:
        SystemExit: When the dataset is missing
    """

    labels_file = dataset_dir / "labels.json"
    if not labels_file.is_file():
        print(f"error: no labels at {labels_file}", file=sys.stderr)
        print("Create it following the schema in eval/README.md.", file=sys.stderr)
        raise SystemExit(2)

    payload = json.loads(labels_file.read_text(encoding="utf-8"))
    labels = []
    for entry in payload.get("labels", []):
        labels.append(Label(
            file=entry["file"],
            line=int(entry.get("line", 0)),
            cwe=str(entry["cwe"]).replace("CWE-", "").strip(),
            type=entry.get("type", ""),
            note=entry.get("note", "")
        ))

    meta = {
        "name": payload.get("name", dataset_dir.name),
        "source": payload.get("source", ""),
        # "line" requires the detection to land near the annotated sink.
        # "file" only requires the right CWE somewhere in the file, for
        # corpora that label a sample without annotating a line.
        "match_mode": payload.get("match_mode", "line"),
        "clean_files": payload.get("clean_files", []),
        # A corpus that labels only some of its real defects cannot measure
        # precision: an unmatched detection may be a genuine finding that
        # nobody wrote a label for. Scoring those as false positives would
        # punish an engine for being more thorough than the ground truth.
        "partial_labels": bool(payload.get("partial_labels", False)),
    }
    return labels, meta


def match(
    detections: Sequence[Detection],
    labels: Sequence[Label],
    name: str,
    match_mode: str = "line",
    partial_labels: bool = False,
    exact_cwe: bool = False
) -> Metrics:
    """
    Score detections against ground truth.

    Each label may be satisfied by at most one detection, and each detection
    may satisfy at most one label, so neither duplicate findings nor a single
    catch-all finding can inflate the score.

    Args:
        detections: Findings from one engine
        labels: Ground-truth labels
        name: Configuration name for the report
        match_mode: "line" or "file"
        partial_labels: Whether ground truth is incomplete
        exact_cwe: Require exact CWE number without equivalence mapping

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
            # File-mode corpora label the sample, not the sink line.
            if match_mode == "line" and abs(detection.line - label.line) > LINE_TOLERANCE:
                continue
            # CWE is the interoperable key; type names differ per engine.
            if not cwe_matches(detection.cwe, label.cwe, exact=exact_cwe):
                continue
            claimed_labels.add(l_index)
            matched_detections.add(d_index)
            break

    metrics.true_positives = len(claimed_labels)
    metrics.false_negatives = len(labels) - len(claimed_labels)
    metrics.partial = partial_labels
    # With partial ground truth an unmatched detection is unclassifiable, not
    # wrong, so it is counted separately and kept out of precision.
    unmatched = len(detections) - len(matched_detections)
    if partial_labels:
        metrics.false_positives = 0
        metrics.unmatched = unmatched
    else:
        metrics.false_positives = unmatched

    metrics.missed = [
        f"{l.file}:{l.line} {l.type or 'CWE-' + l.cwe}"
        for i, l in enumerate(labels) if i not in claimed_labels
    ]
    # Two different failures hide in the false-positive column. A finding in
    # a file known to be clean is simply wrong. A finding in a vulnerable
    # file under the wrong CWE found the right place and mislabelled it,
    # which is a far milder error and worth separating.
    labelled_files = {l.file for l in labels}
    metrics.fp_on_clean = sum(
        1 for i, d in enumerate(detections)
        if i not in matched_detections and d.file not in labelled_files
    )
    metrics.fp_wrong_type = metrics.false_positives - metrics.fp_on_clean
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
    samples_dir: Path,
    use_llm: bool,
    use_semgrep: bool,
    confirmed_only: bool = False,
    verify: bool = False,
    verify_all: bool = False,
    concurrency: int = 5
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
        target=str(samples_dir),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        concurrency=concurrency,
        use_cache=True,
        verify=verify,
        verify_all=verify_all,
    )
    result = await Scanner(options).scan()

    findings = result.vulnerabilities
    if confirmed_only:
        findings = [v for v in findings if v.source == FindingSource.CONFIRMED]

    return [_to_detection(v) for v in findings], result.stats.get("total_seconds", 0.0)


def run_bandit(samples_dir: Path) -> Tuple[List[Detection], float]:
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
        [executable, "-r", str(samples_dir), "-f", "json", "-q"],
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
        fp = "  n/a" if metrics.partial else f"{metrics.false_positives:>4}"
        precision = "       n/a" if metrics.partial else f"{metrics.precision:>10.3f}"
        f1 = "    n/a" if metrics.partial else f"{metrics.f1:>7.3f}"
        lines.append(
            f"{metrics.name:<22} {metrics.true_positives:>4} {fp} "
            f"{metrics.false_negatives:>4} {precision} "
            f"{metrics.recall:>8.3f} {f1} {metrics.seconds:>7.1f}"
        )
    return "\n".join(lines)


CONFIGURATIONS = {
    "hybrid": ("VulnAgent (hybrid)", dict(use_llm=True, use_semgrep=True)),
    "confirmed": ("VulnAgent (confirmed)", dict(use_llm=True, use_semgrep=True, confirmed_only=True)),
    "semgrep": ("Semgrep only", dict(use_llm=False, use_semgrep=True)),
    "llm": ("LLM only", dict(use_llm=True, use_semgrep=False)),
    # The agentic configurations. "verified" is the question the thesis
    # actually asks: does letting the model investigate and try to refute its
    # own findings fix the precision problem that single-shot prompting has?
    "verified": ("VulnAgent (agent-verified)", dict(use_llm=True, use_semgrep=True, verify=True)),
    "llm-verified": ("LLM only + agent verify", dict(use_llm=True, use_semgrep=False, verify=True, verify_all=True)),
}


async def main() -> int:
    """
    Run the evaluation.

    Returns:
        int: Process exit code
    """

    parser = argparse.ArgumentParser(description="Evaluate VulnAgent against labelled data.")
    parser.add_argument(
        "--dataset", default=str(DEFAULT_DATASET),
        help="Dataset directory containing labels.json and samples/"
    )
    parser.add_argument(
        "--only", choices=list(CONFIGURATIONS) + ["bandit"], action="append",
        help="Run only the named configuration (repeatable)"
    )
    parser.add_argument("--json", help="Write full results to a JSON file")
    parser.add_argument("--no-bandit", action="store_true", help="Skip the Bandit baseline")
    parser.add_argument("--exact-cwe", action="store_true", help="Require exact CWE number match (no equivalence classes)")
    parser.add_argument("-j", "--concurrency", type=int, default=5, help="Concurrent LLM calls")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset)
    samples_dir = dataset_dir / "samples"
    labels, meta = load_dataset(dataset_dir)
    files = sorted({l.file for l in labels})

    print(f"Dataset : {meta['name']}")
    if meta.get("source"):
        print(f"Source  : {meta['source']}")
    clean = meta.get("clean_files") or []
    print(f"Labels  : {len(labels)} vulnerability(ies) across {len(files)} file(s)")
    if clean:
        print(f"          plus {len(clean)} file(s) known to be clean, where any")
        print(f"          finding is a false positive")
    print(f"Matching: {meta['match_mode']}-level"
          + (f" (+/-{LINE_TOLERANCE} lines)" if meta["match_mode"] == "line" else ""))
    if meta["partial_labels"]:
        print("          ground truth is PARTIAL, so precision and F1 are not")
        print("          measurable here - an unmatched detection may well be a")
        print("          real defect nobody labelled. This run measures RECALL.")
    # Precision is only meaningful when the corpus contains code that is
    # known to be safe. Saying otherwise on a corpus that has 778 such files
    # would throw away the one measurement it exists to provide.
    if meta["match_mode"] == "file" and not clean and not meta["partial_labels"]:
        print("          no file is known to be clean, so an unmatched detection")
        print("          cannot be judged: this run measures RECALL only.")
    print()

    selected = args.only or list(CONFIGURATIONS)
    results: List[Metrics] = []

    for key in CONFIGURATIONS:
        if key not in selected:
            continue
        name, kwargs = CONFIGURATIONS[key]
        print(f"running {name}...")
        detections, seconds = await run_vulnagent(
            samples_dir, concurrency=args.concurrency, **kwargs
        )
        metrics = match(detections, labels, name, meta["match_mode"], meta["partial_labels"], exact_cwe=args.exact_cwe)
        metrics.seconds = seconds
        results.append(metrics)

    if not args.no_bandit and (not args.only or "bandit" in selected):
        print("running Bandit...")
        detections, seconds = run_bandit(samples_dir)
        if detections:
            metrics = match(detections, labels, "Bandit (baseline)", meta["match_mode"], meta["partial_labels"], exact_cwe=args.exact_cwe)
            metrics.seconds = seconds
            results.append(metrics)

    print()
    print(render_table(results))
    print()

    if clean:
        print("False positives split:")
        for metrics in results:
            if metrics.partial:
                continue
            print(f"  {metrics.name:<22} {metrics.fp_on_clean:>4} in clean files"
                  f"   {metrics.fp_wrong_type:>4} right file, wrong CWE")
        print()

    # In file-mode the false-positive column is not interpretable, since a
    # sample can legitimately contain defects beyond the one it is labelled
    # for. Only the misses are worth listing.
    show_spurious = meta["match_mode"] == "line" and not meta["partial_labels"]
    for metrics in results:
        if metrics.missed:
            print(f"{metrics.name} missed {len(metrics.missed)}:")
            for item in metrics.missed[:20]:
                print(f"    {item}")
            if len(metrics.missed) > 20:
                print(f"    ... and {len(metrics.missed) - 20} more")
            print()
        if show_spurious and metrics.spurious:
            print(f"{metrics.name} false positives:")
            for item in metrics.spurious:
                print(f"    {item}")
            print()

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "dataset": {
                        "name": meta["name"],
                        "source": meta["source"],
                        "match_mode": meta["match_mode"],
                        "labels": len(labels),
                        "files": len(files),
                    },
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
            f"\nNOTE: {len(labels)} labels is too few for the numbers above to "
            "be meaningful. Treat this as a smoke test until the dataset "
            "reaches roughly 50-100 labelled vulnerabilities."
        )

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
