"""Quantitative evaluation against a hand-labelled dataset.

Reports precision, recall and F1 for each engine configuration so the claim
that the hybrid beats either tier alone can be checked rather than asserted.

    python eval/run_eval.py                 # every configuration
    python eval/run_eval.py --only hybrid   # one configuration
    python eval/run_eval.py --json out.json # machine-readable results
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
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
class RunRecord:
    """
    Direct execution result of an engine configuration, retaining status, coverage, and errors.
    """
    configuration: str
    status: str  # "completed", "failed", "degraded", "skipped"
    detections: List[Detection] = field(default_factory=list)
    elapsed: float = 0.0
    degraded: bool = False
    coverage: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Metrics:
    """
    Confusion-matrix counts and the scores derived from them.
    """

    name: str
    status: str = "completed"
    degraded: bool = False
    errors: List[str] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    seconds: float = 0.0
    partial: bool = False
    unmatched: int = 0
    fp_on_clean: int = 0
    fp_duplicate: int = 0
    fp_wrong_line: int = 0
    fp_wrong_type: int = 0
    missed: List[str] = field(default_factory=list)
    spurious: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        if self.partial or self.status not in ("completed", "degraded"):
            return float("nan")   # not measurable against partial ground truth or failed run
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        if self.status not in ("completed", "degraded"):
            return float("nan")
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.partial or self.status not in ("completed", "degraded"):
            return float("nan")   # follows precision
        if not (self.precision + self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    def as_dict(self) -> Dict[str, Any]:
        is_ok = self.status in ("completed", "degraded")
        return {
            "name": self.name,
            "status": self.status,
            "degraded": self.degraded,
            "errors": self.errors,
            "tp": self.true_positives if is_ok else None,
            "fp": self.false_positives if (is_ok and not self.partial) else None,
            "fn": self.false_negatives if is_ok else None,
            "precision": None if (self.partial or not is_ok) else round(self.precision, 4),
            "recall": round(self.recall, 4) if is_ok else None,
            "f1": None if (self.partial or not is_ok) else round(self.f1, 4),
            "unmatched": self.unmatched,
            "fp_on_clean_files": self.fp_on_clean,
            "fp_duplicate_sink": self.fp_duplicate,
            "fp_wrong_line_tolerance": self.fp_wrong_line,
            "fp_wrong_type_right_file": self.fp_wrong_type,
            "partial_ground_truth": self.partial,
            "seconds": round(self.seconds, 2),
            "coverage": self.coverage,
            "missed": self.missed,
            "spurious": self.spurious,
            "raw_findings": self.raw_findings,
        }


def _compute_sha256(p: Path) -> str:
    if not p.is_file():
        return ""
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _compute_dir_hash(p: Path) -> str:
    if not p.is_dir():
        return ""
    h = hashlib.sha256()
    for f in sorted(p.rglob("*")):
        if f.is_file():
            rel = f.relative_to(p).as_posix()
            h.update(rel.encode("utf-8"))
            h.update(f.read_bytes())
    return h.hexdigest()


def _resolve_rule_config(cfg: str) -> str:
    """
    Resolve rule config once according to CLI / CWD precedence.
    Returns resolved absolute path string if local file/directory exists, else raw config string.
    """
    p = Path(cfg)
    if p.is_absolute():
        return str(p.resolve())
    if p.exists():
        return str(p.resolve())
    if (ROOT / p).exists():
        return str((ROOT / p).resolve())
    return cfg


def _get_git_info(repo_path: Optional[Path] = None) -> Dict[str, Any]:
    target_repo = (repo_path or ROOT).resolve()
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True, cwd=str(target_repo)
        ).strip()
        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True, cwd=str(target_repo)
        ).strip()
        is_dirty = len(status_output) > 0
        return {"commit": commit, "dirty": is_dirty, "repo_root": str(target_repo)}
    except Exception:
        return {"commit": "unknown", "dirty": None, "repo_root": str(target_repo)}


def _get_tool_version(cmd: List[str]) -> Optional[str]:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
        return out.splitlines()[0] if out else None
    except Exception:
        return None


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
    samples_dir = dataset_dir / "samples"
    abs_samples = samples_dir.resolve() if samples_dir.exists() else None
    labels = []
    for entry in payload.get("labels", []):
        rel_file = Path(entry["file"]).as_posix()
        if abs_samples and abs_samples.is_dir():
            target_file = (abs_samples / rel_file).resolve()
            try:
                target_file.relative_to(abs_samples)
            except ValueError:
                print(f"error: label references sample outside dataset: {rel_file}", file=sys.stderr)
                raise SystemExit(2)
            if not target_file.is_file():
                print(f"warning: label references non-existent sample {rel_file}", file=sys.stderr)
        labels.append(Label(
            file=rel_file,
            line=int(entry.get("line", 0)),
            cwe=str(entry["cwe"]).replace("CWE-", "").strip(),
            type=entry.get("type", ""),
            note=entry.get("note", "")
        ))

    partial = bool(payload.get("partial_labels", False))
    if "partial_labels" not in payload and payload.get("match_mode") == "file" and not payload.get("clean_files"):
        partial = True

    meta = {
        "name": payload.get("name", dataset_dir.name),
        "source": payload.get("source", ""),
        "match_mode": payload.get("match_mode", "line"),
        "clean_files": [Path(f).as_posix() for f in payload.get("clean_files", [])],
        "partial_labels": partial,
    }
    return labels, meta


def _min_cost_max_bipartite_matching(
    detections: Sequence[Detection],
    labels: Sequence[Label],
    match_mode: str = "line",
    exact_cwe: bool = False,
    tolerance: int = LINE_TOLERANCE,
) -> List[Tuple[int, int]]:
    """
    Find maximum-cardinality one-to-one matching between detections and labels,
    minimizing total line distance as secondary objective with deterministic tie-breaking.
    Guarantees invariance to permutation of detections or labels.
    """
    n_d = len(detections)
    n_l = len(labels)
    if n_d == 0 or n_l == 0:
        return []

    adj: Dict[Any, List[List[Any]]] = {}

    def add_edge(u: Any, v: Any, cap: int, cost: int) -> None:
        if u not in adj:
            adj[u] = []
        if v not in adj:
            adj[v] = []
        forward = [v, cap, cost, len(adj[v])]
        backward = [u, 0, -cost, len(adj[u])]
        adj[u].append(forward)
        adj[v].append(backward)

    for i in range(n_d):
        add_edge("s", ("d", i), 1, 0)
    for j in range(n_l):
        add_edge(("l", j), "t", 1, 0)

    def _stable_tie_break(d: Detection, l: Label) -> int:
        d_sig = f"{d.file}:{d.line}:{d.cwe}:{d.type}:{d.source}"
        l_sig = f"{l.file}:{l.line}:{l.cwe}:{l.type}:{l.note}"
        h1 = int(hashlib.md5(d_sig.encode("utf-8")).hexdigest()[:8], 16) % 10000
        h2 = int(hashlib.md5(l_sig.encode("utf-8")).hexdigest()[:8], 16) % 10000
        return h1 * 10000 + h2

    has_candidate_edge = False
    for i, d in enumerate(detections):
        for j, l in enumerate(labels):
            if d.file != l.file:
                continue
            if not cwe_matches(d.cwe, l.cwe, exact=exact_cwe):
                continue
            dist = abs(d.line - l.line) if match_mode == "line" else 0
            if match_mode == "line" and dist > tolerance:
                continue
            cost = dist * 100000000 + _stable_tie_break(d, l)
            add_edge(("d", i), ("l", j), 1, cost)
            has_candidate_edge = True

    if not has_candidate_edge:
        return []

    while True:
        dist_map: Dict[Any, float] = {node: float("inf") for node in adj}
        parent: Dict[Any, Optional[Tuple[Any, int]]] = {node: None for node in adj}
        dist_map["s"] = 0.0
        in_queue = set(["s"])
        queue = ["s"]

        while queue:
            u = queue.pop(0)
            in_queue.remove(u)
            for edge_idx, (v, cap, cost, rev_idx) in enumerate(adj[u]):
                if cap > 0 and dist_map[u] + cost < dist_map[v]:
                    dist_map[v] = dist_map[u] + cost
                    parent[v] = (u, edge_idx)
                    if v not in in_queue:
                        queue.append(v)
                        in_queue.add(v)

        if dist_map.get("t", float("inf")) == float("inf"):
            break

        curr = "t"
        while curr != "s":
            assert parent[curr] is not None
            p, edge_idx = parent[curr]
            edge = adj[p][edge_idx]
            rev_idx = edge[3]
            edge[1] -= 1
            adj[curr][rev_idx][1] += 1
            curr = p

    matches = []
    for i in range(n_d):
        d_node = ("d", i)
        if d_node in adj:
            for v, cap, cost, rev_idx in adj[d_node]:
                if isinstance(v, tuple) and v[0] == "l" and cap == 0:
                    matches.append((i, v[1]))
    return matches


def match(
    detections: Sequence[Detection],
    labels: Sequence[Label],
    name: str,
    match_mode: str = "line",
    partial_labels: bool = False,
    exact_cwe: bool = False,
    clean_files: Optional[Sequence[str]] = None,
    run_status: str = "completed",
    degraded: bool = False,
    errors: Optional[List[str]] = None,
    coverage: Optional[Dict[str, Any]] = None,
    raw_findings: Optional[List[Dict[str, Any]]] = None,
) -> Metrics:
    """
    Score detections against ground truth using max bipartite matching.
    """
    metrics = Metrics(
        name=name,
        status=run_status,
        degraded=degraded,
        errors=list(errors or []),
        coverage=dict(coverage or {}),
        raw_findings=list(raw_findings or []),
    )

    if run_status not in ("completed", "degraded"):
        metrics.missed = [f"{l.file}:{l.line} {l.type or 'CWE-' + l.cwe}" for l in labels]
        return metrics

    clean_set = set(clean_files or [])
    matched_pairs = _min_cost_max_bipartite_matching(
        detections=detections,
        labels=labels,
        match_mode=match_mode,
        exact_cwe=exact_cwe,
        tolerance=LINE_TOLERANCE,
    )

    claimed_labels = {l_idx for _, l_idx in matched_pairs}
    matched_detections = {d_idx for d_idx, _ in matched_pairs}

    metrics.true_positives = len(claimed_labels)
    metrics.false_negatives = len(labels) - len(claimed_labels)
    metrics.partial = partial_labels

    unmatched_d_indices = [i for i in range(len(detections)) if i not in matched_detections]
    if partial_labels:
        metrics.false_positives = 0
        metrics.unmatched = len(unmatched_d_indices)
    else:
        metrics.false_positives = len(unmatched_d_indices)

    metrics.missed = [
        f"{l.file}:{l.line} {l.type or 'CWE-' + l.cwe}"
        for i, l in enumerate(labels) if i not in claimed_labels
    ]
    metrics.spurious = [
        f"{detections[i].file}:{detections[i].line} {detections[i].type or 'CWE-' + detections[i].cwe}"
        for i in unmatched_d_indices
    ]

    if not partial_labels:
        fp_clean = 0
        fp_dup = 0
        fp_line = 0
        fp_type = 0
        for i in unmatched_d_indices:
            d = detections[i]
            if d.file in clean_set:
                fp_clean += 1
            else:
                matching_cwe_labels = [l for l in labels if l.file == d.file and cwe_matches(d.cwe, l.cwe, exact=exact_cwe)]
                if matching_cwe_labels:
                    if any(abs(d.line - l.line) <= LINE_TOLERANCE for l in matching_cwe_labels):
                        fp_dup += 1
                    else:
                        fp_line += 1
                else:
                    fp_type += 1
        metrics.fp_on_clean = fp_clean
        metrics.fp_duplicate = fp_dup
        metrics.fp_wrong_line = fp_line
        metrics.fp_wrong_type = fp_type

    return metrics


def _to_detection(vuln: Vulnerability, samples_dir: Path) -> Detection:
    """
    Convert a VulnAgent finding into a comparable detection preserving relative path.
    """
    file_path = vuln.location.file_path
    p = Path(file_path)
    if not p.is_absolute():
        p = (samples_dir / p).resolve()
    else:
        p = p.resolve()
    try:
        rel_file = p.relative_to(samples_dir.resolve()).as_posix()
    except ValueError:
        rel_file = p.as_posix()

    return Detection(
        file=rel_file,
        line=vuln.location.start_line,
        cwe=str(vuln.cwe_id).replace("CWE-", "").strip(),
        type=vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type),
        source=vuln.source.value if hasattr(vuln.source, "value") else str(vuln.source),
    )


async def run_vulnagent(
    samples_dir: Path,
    use_llm: bool,
    use_semgrep: bool,
    confirmed_only: bool = False,
    verify: bool = False,
    verify_all: bool = False,
    concurrency: int = 5,
    configuration_name: str = "VulnAgent",
    use_cache: bool = True,
    semgrep_configs: Optional[Tuple[str, ...]] = None,
) -> RunRecord:
    """
    Run one VulnAgent configuration over the dataset, returning a structured RunRecord.
    """
    options = ScanOptions(
        target=str(samples_dir),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        semgrep_configs=semgrep_configs,
        concurrency=concurrency,
        use_cache=use_cache,
        verify=verify,
        verify_all=verify_all,
    )
    started = time.perf_counter()
    try:
        result = await Scanner(options).scan()
    except Exception as e:
        elapsed = time.perf_counter() - started
        return RunRecord(
            configuration=configuration_name,
            status="failed",
            elapsed=elapsed,
            errors=[f"Scanner exception: {e}"]
        )

    elapsed = time.perf_counter() - started
    status = getattr(result, "status", "completed")
    degraded = bool(getattr(result, "degraded", False))
    errors = []
    if result.stats.get("engine_failure"):
        errors.append("Engine failure reported in scan stats")
    if result.stats.get("rule_error"):
        errors.append(f"Rule error: {result.stats['rule_error']}")
    if result.stats.get("global_errors"):
        errors.extend(result.stats["global_errors"])

    if status in ("failed", "error") or (result.stats.get("engine_failure") and not result.vulnerabilities):
        status = "failed"
    elif degraded or status in ("partial", "incomplete"):
        status = "degraded"

    findings = result.vulnerabilities
    if confirmed_only:
        findings = [v for v in findings if v.source == FindingSource.CONFIRMED]

    detections = [_to_detection(v, samples_dir) for v in findings]
    raw_findings = [
        v.to_dict() if hasattr(v, "to_dict") else {
            "cwe": v.cwe_id,
            "file": v.location.file_path,
            "line": v.location.start_line
        }
        for v in findings
    ]
    hits = result.stats.get("cache_hits", 0)
    misses = result.stats.get("cache_misses", 0)
    coverage = {
        "files_scanned": result.stats.get("files_scanned", len(result.reports)),
        "files_requested": result.stats.get("files_requested", 0),
        "total_seconds": result.stats.get("total_seconds", elapsed),
        "cache_hits": hits,
        "cache_misses": misses,
        "cache_policy": "enabled" if use_cache else "disabled",
        "cache_state": "warmed" if (use_cache and hits > 0) else ("cold" if use_cache else "disabled"),
        "cache_mode": "warm" if (use_cache and hits > 0) else ("cold" if use_cache else "disabled"),
        "rule_tier_seconds": result.stats.get("rule_tier_seconds", 0.0),
        "llm_tier_seconds": result.stats.get("llm_tier_seconds", 0.0),
    }
    for k in ("verify_seconds", "verify_uncertain", "verify_refuted", "verify_supported"):
        if k in result.stats:
            coverage[k] = result.stats[k]

    return RunRecord(
        configuration=configuration_name,
        status=status,
        detections=detections,
        elapsed=elapsed,
        degraded=degraded,
        coverage=coverage,
        errors=errors,
        raw_findings=raw_findings,
    )


def run_bandit(samples_dir: Path) -> RunRecord:
    """
    Run Bandit as an external baseline, returning a structured RunRecord.
    """
    executable = shutil.which("bandit")
    if not executable:
        return RunRecord(
            configuration="Bandit (baseline)",
            status="skipped",
            errors=["bandit not installed (pip install bandit)"],
        )

    abs_samples_dir = samples_dir.resolve()
    all_py_files = list(abs_samples_dir.rglob("*.py"))
    total_files = len(all_py_files)

    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [executable, "-r", str(abs_samples_dir), "-f", "json", "-q"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except Exception as e:
        elapsed = time.perf_counter() - started
        return RunRecord(
            configuration="Bandit (baseline)",
            status="failed",
            elapsed=elapsed,
            errors=[f"Failed to execute Bandit subprocess: {e}"],
            coverage={"files_requested": total_files, "files_scanned": 0, "completion_rate": 0.0},
        )

    elapsed = time.perf_counter() - started

    if proc.returncode not in (0, 1):
        return RunRecord(
            configuration="Bandit (baseline)",
            status="failed",
            elapsed=elapsed,
            errors=[f"Bandit exited with error code {proc.returncode}: {proc.stderr.strip()}"],
            coverage={"files_requested": total_files, "files_scanned": 0, "completion_rate": 0.0},
        )

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        return RunRecord(
            configuration="Bandit (baseline)",
            status="failed",
            elapsed=elapsed,
            errors=[f"Bandit produced unparseable JSON: {e}"],
            coverage={"files_requested": total_files, "files_scanned": 0, "completion_rate": 0.0},
        )

    if not isinstance(payload, dict) or "results" not in payload:
        return RunRecord(
            configuration="Bandit (baseline)",
            status="failed",
            elapsed=elapsed,
            errors=["Bandit JSON output missing expected 'results' list schema"],
            coverage={"files_requested": total_files, "files_scanned": 0, "completion_rate": 0.0},
        )

    # Check for per-file errors (e.g. syntax errors or parser failures)
    raw_errors = payload.get("errors", [])
    error_messages = []
    error_files = set()
    for err in raw_errors:
        fn = err.get("filename", "unknown")
        reason = err.get("reason", "unknown error")
        error_messages.append(f"{fn}: {reason}")
        error_files.add(fn)

    successfully_scanned = max(0, total_files - len(error_files))
    completion_rate = (successfully_scanned / total_files) if total_files > 0 else 1.0

    # Determine execution status based on error presence and scanned files
    if error_messages:
        if successfully_scanned == 0 and total_files > 0:
            status = "failed"
            degraded = True
        else:
            status = "degraded"
            degraded = True
    else:
        status = "completed"
        degraded = False

    detections = []
    for item in payload.get("results", []):
        filename = item.get("filename", "")
        p = Path(filename)
        if not p.is_absolute():
            if (abs_samples_dir / p).exists():
                p = (abs_samples_dir / p).resolve()
            else:
                p = p.resolve()
        else:
            p = p.resolve()

        try:
            rel_file = p.relative_to(abs_samples_dir).as_posix()
        except ValueError:
            # Result is outside the evaluated samples directory
            continue

        cwe = item.get("issue_cwe", {}) or {}
        detections.append(Detection(
            file=rel_file,
            line=int(item.get("line_number", 0)),
            cwe=str(cwe.get("id", "")).strip(),
            type=item.get("test_name", ""),
            source="bandit",
        ))

    return RunRecord(
        configuration="Bandit (baseline)",
        status=status,
        detections=detections,
        elapsed=elapsed,
        degraded=degraded,
        coverage={
            "files_requested": total_files,
            "files_scanned": successfully_scanned,
            "files_failed": len(error_files),
            "completion_rate": completion_rate,
        },
        errors=error_messages,
        raw_findings=payload.get("results", []),
    )


def render_table(results: List[Metrics]) -> str:
    """
    Format the comparison table, distinguishing completed, degraded, and failed runs.
    """
    header = (
        f"{'configuration':<24} {'status':<10} {'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'precision':>10} {'recall':>8} {'F1':>7} {'sec':>7}"
    )
    lines = [header, "-" * len(header)]
    for metrics in results:
        status_str = metrics.status
        if metrics.degraded and metrics.status == "completed":
            status_str = "degraded"

        if metrics.status not in ("completed", "degraded"):
            lines.append(
                f"{metrics.name:<24} {status_str:<10} {'---':>4} {'---':>4} "
                f"{'---':>4} {'---':>10} {'---':>8} {'---':>7} {metrics.seconds:>7.1f}"
            )
            continue

        fp = "  n/a" if metrics.partial else f"{metrics.false_positives:>4}"
        precision = "       n/a" if metrics.partial else f"{metrics.precision:>10.3f}"
        f1 = "    n/a" if metrics.partial else f"{metrics.f1:>7.3f}"
        lines.append(
            f"{metrics.name:<24} {status_str:<10} {metrics.true_positives:>4} {fp} "
            f"{metrics.false_negatives:>4} {precision} "
            f"{metrics.recall:>8.3f} {f1} {metrics.seconds:>7.1f}"
        )
    return "\n".join(lines)


CONFIGURATIONS = {
    "hybrid": ("VulnAgent (hybrid)", dict(use_llm=True, use_semgrep=True)),
    "confirmed": ("VulnAgent (confirmed)", dict(use_llm=True, use_semgrep=True, confirmed_only=True)),
    "semgrep": ("Semgrep only", dict(use_llm=False, use_semgrep=True)),
    "llm": ("LLM only", dict(use_llm=True, use_semgrep=False)),
    "verified": ("VulnAgent (agent-verified)", dict(use_llm=True, use_semgrep=True, verify=True)),
    "llm-verified": ("LLM only + agent verify", dict(use_llm=True, use_semgrep=False, verify=True, verify_all=True)),
}


async def main() -> int:
    """
    Run the evaluation across all selected configurations.
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
    parser.add_argument("--rules", default=None, help="Semgrep rules configuration (file, dir, or pack, comma-separated)")
    parser.add_argument("--exact-cwe", action="store_true", help="Require exact CWE number match (no equivalence classes)")
    parser.add_argument("-j", "--concurrency", type=int, default=5, help="Concurrent LLM calls")
    parser.add_argument("--no-cache", action="store_true", help="Disable analyzer caching to measure cold latency and model variance")
    parser.add_argument("--cold", action="store_true", help="Alias for --no-cache")
    args = parser.parse_args()

    use_cache = not (args.no_cache or args.cold)

    # Resolve effective Semgrep rules before scan execution
    raw_configs: Tuple[str, ...]
    if args.rules:
        raw_configs = tuple(r.strip() for r in args.rules.split(",") if r.strip())
    elif os.environ.get("VULNAGENT_SEMGREP_RULES"):
        raw_configs = tuple(r.strip() for r in os.environ["VULNAGENT_SEMGREP_RULES"].split(",") if r.strip())
    elif (ROOT / "rules" / "pinned_security_rules.yaml").is_file():
        raw_configs = (str((ROOT / "rules" / "pinned_security_rules.yaml").resolve()),)
    else:
        raw_configs = ("p/python", "p/security-audit")

    effective_configs = tuple(_resolve_rule_config(c) for c in raw_configs)

    # Precompute rule snapshot hashes before scan execution to guarantee integrity
    initial_rule_hashes: Dict[str, str] = {}
    for cfg in effective_configs:
        p = Path(cfg)
        if p.is_file():
            initial_rule_hashes[str(p)] = _compute_sha256(p)

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
    print(f"Rules   : {', '.join(effective_configs)}")
    print(f"Cache   : {'enabled' if use_cache else 'disabled (--cold/--no-cache)'}")
    if meta["partial_labels"]:
        print("          ground truth is PARTIAL, so precision and F1 are not")
        print("          measurable here - an unmatched detection may well be a")
        print("          real defect nobody labelled. This run measures RECALL.")
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
        record = await run_vulnagent(
            samples_dir,
            concurrency=args.concurrency,
            configuration_name=name,
            use_cache=use_cache,
            semgrep_configs=effective_configs,
            **kwargs,
        )
        metrics = match(
            record.detections,
            labels,
            name,
            match_mode=meta["match_mode"],
            partial_labels=meta["partial_labels"],
            exact_cwe=args.exact_cwe,
            clean_files=clean,
            run_status=record.status,
            degraded=record.degraded,
            errors=record.errors,
            coverage=record.coverage,
            raw_findings=record.raw_findings,
        )
        metrics.seconds = record.elapsed
        results.append(metrics)

    if not args.no_bandit and (not args.only or "bandit" in selected):
        print("running Bandit...")
        record = run_bandit(samples_dir)
        metrics = match(
            record.detections,
            labels,
            "Bandit (baseline)",
            match_mode=meta["match_mode"],
            partial_labels=meta["partial_labels"],
            exact_cwe=args.exact_cwe,
            clean_files=clean,
            run_status=record.status,
            degraded=record.degraded,
            errors=record.errors,
            coverage=record.coverage,
            raw_findings=record.raw_findings,
        )
        metrics.seconds = record.elapsed
        results.append(metrics)

    print()
    print(render_table(results))
    print()

    # Report errors if any
    has_failures = False
    for metrics in results:
        if metrics.status != "completed" or metrics.degraded:
            has_failures = True
        if metrics.errors or metrics.degraded:
            print(f"[{metrics.name}] Status: {metrics.status} (degraded={metrics.degraded})")
            if metrics.coverage:
                scanned = metrics.coverage.get("files_scanned", 0)
                req = metrics.coverage.get("files_requested", 0)
                rate = metrics.coverage.get("completion_rate", 0.0) * 100
                print(f"  Coverage: {scanned}/{req} files scanned ({rate:.1f}% completion)")
            for err in metrics.errors:
                print(f"  - {err}")
            print()

    if clean:
        print("False positives breakdown:")
        for metrics in results:
            if metrics.partial or metrics.status not in ("completed", "degraded"):
                continue
            print(f"  {metrics.name:<24} "
                  f"clean_files: {metrics.fp_on_clean:>2} | "
                  f"duplicates: {metrics.fp_duplicate:>2} | "
                  f"wrong_line: {metrics.fp_wrong_line:>2} | "
                  f"wrong_type: {metrics.fp_wrong_type:>2}")
        print()

    show_spurious = meta["match_mode"] == "line" and not meta["partial_labels"]
    for metrics in results:
        if metrics.status not in ("completed", "degraded"):
            continue
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
        labels_path = dataset_dir / "labels.json"

        # Compute effective rules metadata directly from resolved configs
        rule_entries = []
        primary_path = None
        primary_sha256 = None
        for cfg in effective_configs:
            p = Path(cfg)
            if p.is_file():
                h = _compute_sha256(p)
                path_str = str(p.resolve())
                rule_entries.append({"type": "file", "path": path_str, "sha256": h})
                if primary_sha256 is None:
                    primary_sha256 = h
                    primary_path = path_str
            elif p.is_dir():
                h = _compute_dir_hash(p)
                path_str = str(p.resolve())
                rule_entries.append({"type": "directory", "path": path_str, "sha256": h})
                if primary_sha256 is None:
                    primary_sha256 = h
                    primary_path = path_str
            else:
                rule_entries.append({"type": "registry", "pack": cfg, "sha256": None})
                if primary_path is None:
                    primary_path = cfg

        aggregate_hits = sum(
            m.coverage.get("cache_hits", 0) for m in results
            if getattr(m, "coverage", None) and isinstance(m.coverage, dict)
        )
        aggregate_misses = sum(
            m.coverage.get("cache_misses", 0) for m in results
            if getattr(m, "coverage", None) and isinstance(m.coverage, dict)
        )
        cache_policy = "enabled" if use_cache else "disabled"
        cache_state = "warmed" if (use_cache and aggregate_hits > 0) else ("cold" if use_cache else "disabled")

        manifest_payload = {
            "version": "1.0",
            "environment": {
                "platform": platform.platform(),
                "python_version": sys.version.split()[0],
                "executable": sys.executable,
                "git": _get_git_info(ROOT),
                "engines": {
                    "semgrep": _get_tool_version(["semgrep", "--version"]),
                    "bandit": _get_tool_version(["bandit", "--version"]),
                },
            },
            "dataset": {
                "name": meta["name"],
                "source": meta["source"],
                "match_mode": meta["match_mode"],
                "labels": len(labels),
                "files": len(files),
                "partial_labels": meta["partial_labels"],
                "labels_sha256": _compute_sha256(labels_path),
                "samples_sha256": _compute_dir_hash(samples_dir),
                "git": _get_git_info(dataset_dir),
            },
            "rules": {
                "configs": list(effective_configs),
                "path": primary_path or ", ".join(effective_configs),
                "sha256": primary_sha256,
                "entries": rule_entries,
            },
            "protocol": {
                "line_tolerance": LINE_TOLERANCE,
                "exact_cwe": args.exact_cwe,
                "cache_policy": cache_policy,
                "cache_state": cache_state,
                "cache_mode": "warm" if (use_cache and aggregate_hits > 0) else ("cold" if use_cache else "disabled"),
                "cache_hits": aggregate_hits,
                "cache_misses": aggregate_misses,
                "concurrency": args.concurrency,
                "timestamp": time.time(),
                "iso_timestamp": datetime.now().isoformat(),
            },
            "results": [m.as_dict() for m in results],
        }
        Path(args.json).write_text(
            json.dumps(manifest_payload, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"wrote {args.json}")

    if len(labels) < 30:
        print(
            f"\nNOTE: {len(labels)} labels is too few for the numbers above to "
            "be meaningful. Treat this as a smoke test until the dataset "
            "reaches roughly 50-100 labelled vulnerabilities."
        )

    return 1 if has_failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
