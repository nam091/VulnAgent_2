"""Independent Benchmark Evaluation Script and CLI Tool.

Evaluates scan outputs (StandardScanOutput, dashboard job JSON, or raw findings)
against labelled benchmark datasets (benchmark100, pilot50, enterprise_multitier, etc.)
using bipartite matching, reports TP, FP, FN, Precision, Recall, F1, and per-CWE breakdowns.

Usage:
    python eval/evaluate_scan.py --scan scan_output.json --dataset eval/datasets/benchmark100
    python -m src.cli benchmark score --scan run1.json run2.json --detailed
"""

import argparse
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Set up paths so eval and src modules can be imported
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

try:
    from eval.run_eval import (
        CWE_EQUIVALENCE,
        LINE_TOLERANCE,
        Detection,
        Label,
        Metrics,
        _min_cost_max_bipartite_matching,
        cwe_matches,
        load_dataset,
        match,
    )
except ImportError:
    from run_eval import (
        CWE_EQUIVALENCE,
        LINE_TOLERANCE,
        Detection,
        Label,
        Metrics,
        _min_cost_max_bipartite_matching,
        cwe_matches,
        load_dataset,
        match,
    )

EXIT_CLEAN = 0
EXIT_ERROR = 2
DEFAULT_DATASET = "eval/datasets/benchmark100"


def resolve_dataset_dir(dataset_arg: Union[str, Path], root_dir: Optional[Path] = None) -> Path:
    """
    Resolve dataset directory from various possible formats and shorthand names.

    Supports:
        - Absolute or relative paths: "eval/datasets/benchmark100", "./my_dataset"
        - Shorthand dataset names: "benchmark100", "pilot50", "enterprise_multitier", "apigateway_micro"
    """
    root = (root_dir or ROOT).resolve()
    candidate = Path(dataset_arg)

    # Handle benchmark1000 / benchmark1230 aliases
    arg_str = str(dataset_arg).strip().lower()
    if arg_str in ("benchmark1000", "benchmark1230", "owasp1000", "owasp1230"):
        benchmark_dir = root / "eval" / "datasets" / "benchmark"
        if benchmark_dir.is_dir() and (benchmark_dir / "labels.json").is_file():
            return benchmark_dir.resolve()

    # 1. Exact path (absolute or relative to cwd)
    if candidate.is_dir() and (candidate / "labels.json").is_file():
        return candidate.resolve()

    # 2. Relative to ROOT
    if (root / candidate).is_dir() and ((root / candidate) / "labels.json").is_file():
        return (root / candidate).resolve()

    # 3. Inside eval/datasets/<name>
    in_datasets = root / "eval" / "datasets" / dataset_arg
    if in_datasets.is_dir() and (in_datasets / "labels.json").is_file():
        return in_datasets.resolve()

    # 4. Inside eval/<name>
    in_eval = root / "eval" / dataset_arg
    if in_eval.is_dir() and (in_eval / "labels.json").is_file():
        return in_eval.resolve()

    # Fallback to direct resolution
    return (root / candidate).resolve()


def extract_findings_from_payload(payload: Any) -> List[Dict[str, Any]]:
    """
    Extract finding dictionaries from multiple supported scan output schemas:
    - StandardScanOutput ({"findings": [...]})
    - Dashboard Job JSON ({"result": {"findings": [...]}} or {"result": [...]})
    - Raw list of findings ([{...}, ...])
    - VulnerabilityReport ({"vulnerabilities": [...]})
    - ScanResult ({"reports": [{"vulnerabilities": [...]}]})
    - Semgrep / Bandit JSON ({"results": [...]})
    - SARIF JSON ({"runs": [{"results": [...]}]})
    """
    if isinstance(payload, list):
        return [f for f in payload if isinstance(f, dict)]

    if not isinstance(payload, dict):
        return []

    # Case 1: Job wrapper with "result"
    if "result" in payload:
        res = payload["result"]
        if isinstance(res, dict):
            if "findings" in res and isinstance(res["findings"], list):
                return res["findings"]
            if "vulnerabilities" in res and isinstance(res["vulnerabilities"], list):
                return res["vulnerabilities"]
            if "results" in res and isinstance(res["results"], list):
                return res["results"]
        elif isinstance(res, list):
            return [f for f in res if isinstance(f, dict)]

    # Case 2: StandardScanOutput top-level "findings"
    if "findings" in payload and isinstance(payload["findings"], list):
        return payload["findings"]

    # Case 3: VulnerabilityReport top-level "vulnerabilities"
    if "vulnerabilities" in payload and isinstance(payload["vulnerabilities"], list):
        return payload["vulnerabilities"]

    # Case 4: ScanResult with "reports"
    if "reports" in payload and isinstance(payload["reports"], list):
        reports_findings = []
        for rep in payload["reports"]:
            if isinstance(rep, dict) and "vulnerabilities" in rep and isinstance(rep["vulnerabilities"], list):
                reports_findings.extend(rep["vulnerabilities"])
        if reports_findings:
            return reports_findings

    # Case 5: Bandit or Semgrep "results", or benchmark manifests with "raw_findings"
    if "results" in payload and isinstance(payload["results"], list):
        benchmark_findings: List[Dict[str, Any]] = []
        is_benchmark_manifest = False
        for item in payload["results"]:
            if isinstance(item, dict):
                if "raw_findings" in item and isinstance(item["raw_findings"], list):
                    benchmark_findings.extend(item["raw_findings"])
                    is_benchmark_manifest = True
                elif "findings" in item and isinstance(item["findings"], list):
                    benchmark_findings.extend(item["findings"])
                    is_benchmark_manifest = True
        if is_benchmark_manifest:
            return benchmark_findings
        return payload["results"]

    # Case 6: SARIF "runs"
    if "runs" in payload and isinstance(payload["runs"], list):
        sarif_findings = []
        for run in payload["runs"]:
            if isinstance(run, dict) and "results" in run and isinstance(run["results"], list):
                sarif_findings.extend(run["results"])
        if sarif_findings:
            return sarif_findings

    return []


def normalize_cwe_string(raw: Any) -> str:
    """
    Extract clean CWE numeric/symbolic identifier from varied finding representations.
    """
    if not raw:
        return ""
    if isinstance(raw, list):
        if not raw:
            return ""
        raw = raw[0]
    s = str(raw).strip()
    if ":" in s:
        s = s.split(":", 1)[0].strip()
    return s.upper().replace("CWE-", "").replace("CWE", "").strip()


def normalize_finding_file(raw_file: str, dataset_dir: Path, label_files: Optional[Set[str]] = None) -> str:
    """
    Normalize finding file path to POSIX relative path matching ground-truth dataset labels.
    """
    if not raw_file:
        return ""

    raw_posix = Path(raw_file).as_posix()

    # 1. Direct match with label files
    if label_files and raw_posix in label_files:
        return raw_posix

    # 2. Stripping "samples/" prefix
    if raw_posix.startswith("samples/"):
        stripped = raw_posix[len("samples/"):]
        if not label_files or stripped in label_files:
            return stripped

    # 3. Check relative to dataset_dir / "samples"
    samples_dir = (dataset_dir / "samples").resolve()
    try:
        p_res = Path(raw_file)
        if not p_res.is_absolute():
            p_res = (dataset_dir / raw_file).resolve()
        rel_samples = p_res.relative_to(samples_dir).as_posix()
        if not label_files or rel_samples in label_files:
            return rel_samples
    except Exception:
        pass

    # 4. Check relative to dataset_dir
    try:
        p_res = Path(raw_file)
        if not p_res.is_absolute():
            p_res = (dataset_dir / raw_file).resolve()
        rel_dir = p_res.relative_to(dataset_dir.resolve()).as_posix()
        if rel_dir.startswith("samples/"):
            rel_dir = rel_dir[len("samples/"):]
        if not label_files or rel_dir in label_files:
            return rel_dir
    except Exception:
        pass

    # 5. Suffix match against label files (for multi-tier repos or full paths)
    if label_files:
        filename = Path(raw_posix).name
        if filename in label_files:
            return filename
        parts = Path(raw_posix).parts
        for i in range(len(parts)):
            subpath = "/".join(parts[i:])
            if subpath in label_files:
                return subpath

    # Fallback: strip leading samples/ if present
    if raw_posix.startswith("samples/"):
        return raw_posix[len("samples/"):]
    return raw_posix


def finding_to_detection(
    item: Dict[str, Any],
    dataset_dir: Path,
    label_files: Optional[Set[str]] = None,
) -> Optional[Detection]:
    """
    Convert a raw finding dictionary into a comparable Detection dataclass.
    """
    if not isinstance(item, dict):
        return None

    # Extract file path
    raw_file = (
        item.get("file")
        or item.get("file_path")
        or item.get("path")
        or item.get("filename")
    )
    if not raw_file and isinstance(item.get("location"), dict):
        raw_file = item["location"].get("file_path")
    if not raw_file and "locations" in item and isinstance(item["locations"], list) and item["locations"]:
        first_loc = item["locations"][0]
        if isinstance(first_loc, dict):
            raw_file = (
                first_loc.get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri")
            )

    norm_file = normalize_finding_file(str(raw_file or ""), dataset_dir, label_files)

    # Extract line number
    line_val = (
        item.get("start_line")
        or item.get("line")
        or item.get("line_number")
    )
    if line_val is None and isinstance(item.get("location"), dict):
        line_val = item["location"].get("start_line")
    if line_val is None and isinstance(item.get("start"), dict):
        line_val = item["start"].get("line")
    if line_val is None and "locations" in item and isinstance(item["locations"], list) and item["locations"]:
        first_loc = item["locations"][0]
        if isinstance(first_loc, dict):
            line_val = (
                first_loc.get("physicalLocation", {})
                .get("region", {})
                .get("startLine")
            )

    try:
        line_int = int(line_val or 0)
    except (ValueError, TypeError):
        line_int = 0

    # Extract CWE
    raw_cwe = item.get("cwe") or item.get("cwe_id")
    if not raw_cwe and isinstance(item.get("issue_cwe"), dict):
        raw_cwe = item["issue_cwe"].get("id")
    if not raw_cwe and isinstance(item.get("extra"), dict):
        raw_cwe = item["extra"].get("metadata", {}).get("cwe")
    if not raw_cwe and isinstance(item.get("metadata"), dict):
        raw_cwe = item["metadata"].get("cwe")

    cwe_clean = normalize_cwe_string(raw_cwe)
    if not cwe_clean or cwe_clean in ("OTHER", "000", "UNKNOWN"):
        v_str = str(item.get("type") or item.get("vulnerability_type") or "").upper()
        type_to_cwe_map = {
            "CROSS_SITE_SCRIPTING": "79",
            "SQL_INJECTION": "89",
            "OS_COMMAND_INJECTION": "78",
            "CODE_INJECTION": "94",
            "PATH_TRAVERSAL": "22",
            "INSECURE_DESERIALIZATION": "502",
            "XML_EXTERNAL_ENTITY": "611",
            "XPATH_INJECTION": "643",
            "LDAP_INJECTION": "90",
            "SECURE_RANDOMNESS": "330",
            "USE_OF_WEAK_HASHING_ALGORITHM": "328",
            "UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS": "601",
            "SECURE_COOKIE": "614",
            "SERVER_SIDE_REQUEST_FORGERY": "918",
            "HARDCODED_CREDENTIALS": "798",
            "CSRF": "352",
        }
        for k, v in type_to_cwe_map.items():
            if k in v_str:
                cwe_clean = v
                break

    # Extract vulnerability type
    vuln_type = (
        item.get("type")
        or item.get("vulnerability_type")
        or item.get("test_name")
        or item.get("check_id")
        or item.get("rule_id")
        or ""
    )

    source = str(item.get("source") or "")

    return Detection(
        file=norm_file,
        line=line_int,
        cwe=cwe_clean,
        type=str(vuln_type),
        source=source,
    )


def compute_per_cwe_breakdown(
    labels: Sequence[Label],
    claimed_label_indices: Set[int],
) -> Dict[str, Dict[str, Any]]:
    """
    Calculate quantitative metrics broken down by CWE category:
    Total ground-truth cases, True Positives (TP), False Negatives (FN), and Recall.
    """
    breakdown: Dict[str, Dict[str, Any]] = {}
    for idx, label in enumerate(labels):
        cwe_clean = label.cwe.strip()
        cwe_name = f"CWE-{cwe_clean}" if not cwe_clean.upper().startswith("CWE-") else cwe_clean

        if cwe_name not in breakdown:
            breakdown[cwe_name] = {
                "cwe": cwe_name,
                "types": set(),
                "total": 0,
                "tp": 0,
                "fn": 0,
                "recall": 0.0,
            }

        breakdown[cwe_name]["total"] += 1
        if label.type:
            breakdown[cwe_name]["types"].add(label.type)

        if idx in claimed_label_indices:
            breakdown[cwe_name]["tp"] += 1
        else:
            breakdown[cwe_name]["fn"] += 1

    for cwe_name, row in breakdown.items():
        total = row["total"]
        row["recall"] = round(row["tp"] / total, 4) if total > 0 else 0.0
        row["types"] = sorted(list(row["types"]))

    return dict(sorted(breakdown.items(), key=lambda item: item[0]))


def evaluate_single_scan(
    scan_path: Union[str, Path],
    dataset_dir: Path,
    labels: Sequence[Label],
    dataset_meta: Dict[str, Any],
    exact_cwe: bool = False,
    cwe_scope: str = "core10",
) -> Dict[str, Any]:
    """
    Evaluate one scan output file against benchmark ground truth.
    """
    scan_file = Path(scan_path).resolve()
    if not scan_file.is_file():
        raise FileNotFoundError(f"Scan file not found: {scan_file}")

    content = scan_file.read_text(encoding="utf-8", errors="replace")
    payload = json.loads(content)

    findings_raw = extract_findings_from_payload(payload)
    label_files = {l.file for l in labels}

    detections: List[Detection] = []
    for f in findings_raw:
        det = finding_to_detection(f, dataset_dir, label_files=label_files)
        if det:
            detections.append(det)

    if cwe_scope == "core10":
        from eval.cwe_scope import filter_detections
        detections = filter_detections(detections)

    scan_name = scan_file.stem
    match_mode = dataset_meta.get("match_mode", "line")
    partial_labels = dataset_meta.get("partial_labels", False)
    clean_files = dataset_meta.get("clean_files", [])

    # Calculate confusion matrix via bipartite matching
    metrics: Metrics = match(
        detections=detections,
        labels=labels,
        name=scan_name,
        match_mode=match_mode,
        partial_labels=partial_labels,
        exact_cwe=exact_cwe,
        clean_files=clean_files,
        raw_findings=findings_raw,
    )

    # Get claimed labels for per-CWE breakdown
    matched_pairs = _min_cost_max_bipartite_matching(
        detections=detections,
        labels=labels,
        match_mode=match_mode,
        exact_cwe=exact_cwe,
        tolerance=LINE_TOLERANCE,
    )
    claimed_label_indices = {l_idx for _, l_idx in matched_pairs}
    per_cwe = compute_per_cwe_breakdown(labels, claimed_label_indices)

    metrics_dict = {
        "status": metrics.status,
        "tp": metrics.true_positives,
        "fp": None if partial_labels else metrics.false_positives,
        "fn": metrics.false_negatives,
        "precision": None if (partial_labels or math.isnan(metrics.precision)) else round(metrics.precision, 4),
        "recall": None if math.isnan(metrics.recall) else round(metrics.recall, 4),
        "f1": None if (partial_labels or math.isnan(metrics.f1)) else round(metrics.f1, 4),
        "unmatched": metrics.unmatched,
        "partial": partial_labels,
        "fp_on_clean_files": metrics.fp_on_clean,
        "fp_duplicate_sink": metrics.fp_duplicate,
        "fp_wrong_line_tolerance": metrics.fp_wrong_line,
        "fp_wrong_type_right_file": metrics.fp_wrong_type,
        "missed": metrics.missed,
        "spurious": metrics.spurious,
    }

    return {
        "name": scan_name,
        "scan_file": str(scan_file),
        "findings_count": len(findings_raw),
        "detections_count": len(detections),
        "metrics": metrics_dict,
        "per_cwe": per_cwe,
        "missed": metrics.missed,
        "spurious": metrics.spurious,
    }


def render_summary_table(results: List[Dict[str, Any]], dataset_name: str, total_labels: int, exact_cwe: bool) -> str:
    """
    Format a clean ASCII summary comparison table for console output.
    """
    col_name_w = max([len(r["name"]) for r in results] + [len("Scan / Configuration"), 20])
    cwe_mode_desc = "Exact Match" if exact_cwe else "Equivalence Classes"

    title = "BENCHMARK QUANTITATIVE EVALUATION SUMMARY"
    width = max(col_name_w + 64, 86)
    sep_double = "=" * width
    sep_single = "-" * width
    sep_border = "+" + "-" * (col_name_w + 2) + "+----------+----------+-----+-----+-----+-----------+--------+--------+"

    header = (
        f"| {'Scan / Configuration':<{col_name_w}} "
        f"| {'Status':<8} "
        f"| {'Findings':>8} "
        f"| {'TP':>3} "
        f"| {'FP':>3} "
        f"| {'FN':>3} "
        f"| {'Precision':>9} "
        f"| {'Recall':>6} "
        f"| {'F1':>6} |"
    )

    lines = [
        sep_double,
        f"{title:^{width}}",
        sep_double,
        f"Dataset : {dataset_name} ({total_labels} ground-truth defect labels)",
        f"CWE Mode: {cwe_mode_desc} | Matching: Sink line distance <= ±{LINE_TOLERANCE} lines",
        sep_border,
        header,
        sep_border,
    ]

    for r in results:
        m = r["metrics"]
        name = r["name"]
        status = str(m.get("status", "completed"))
        findings = str(r["findings_count"])
        tp = str(m["tp"] if m["tp"] is not None else "---")
        fp = str(m["fp"] if m["fp"] is not None else "n/a")
        fn = str(m["fn"] if m["fn"] is not None else "---")

        prec = f"{m['precision']:.4f}" if m["precision"] is not None else "n/a"
        rec = f"{m['recall']:.4f}" if m["recall"] is not None else "---"
        f1_val = f"{m['f1']:.4f}" if m["f1"] is not None else "n/a"

        row = (
            f"| {name:<{col_name_w}} "
            f"| {status:<8} "
            f"| {findings:>8} "
            f"| {tp:>3} "
            f"| {fp:>3} "
            f"| {fn:>3} "
            f"| {prec:>9} "
            f"| {rec:>6} "
            f"| {f1_val:>6} |"
        )
        lines.append(row)

    lines.append(sep_border)
    return "\n".join(lines)


def render_detailed_cwe_table(result: Dict[str, Any]) -> str:
    """
    Format detailed per-CWE breakdown table for a single scan.
    """
    scan_name = result["name"]
    per_cwe = result["per_cwe"]

    col_cat_w = 34
    for row in per_cwe.values():
        types_str = ", ".join(row["types"])
        if len(types_str) > col_cat_w:
            col_cat_w = min(len(types_str), 44)

    sep_border = f"+----------+-{'-' * col_cat_w}-+-------+-----+-----+--------+"
    header = f"| {'CWE':<8} | {'Vulnerability Category':<{col_cat_w}} | {'Total':>5} | {'TP':>3} | {'FN':>3} | {'Recall':>6} |"

    title = f"DETAILED PER-CWE BREAKDOWN: {scan_name}"
    width = len(sep_border)

    lines = [
        "",
        "=" * width,
        f"{title:^{width}}",
        "=" * width,
        sep_border,
        header,
        sep_border,
    ]

    total_gt = 0
    total_tp = 0
    total_fn = 0

    for cwe_id, data in per_cwe.items():
        types_str = ", ".join(data["types"]) or "General"
        if len(types_str) > col_cat_w:
            types_str = types_str[: col_cat_w - 3] + "..."
        tot = data["total"]
        tp = data["tp"]
        fn = data["fn"]
        rec = f"{data['recall'] * 100:>5.1f}%"

        total_gt += tot
        total_tp += tp
        total_fn += fn

        lines.append(
            f"| {cwe_id:<8} | {types_str:<{col_cat_w}} | {tot:>5} | {tp:>3} | {fn:>3} | {rec:>6} |"
        )

    lines.append(sep_border)
    overall_rec = f"{(total_tp / total_gt * 100):>5.1f}%" if total_gt else "  0.0%"
    lines.append(
        f"| {'TOTAL':<8} | {'ALL CATEGORIES':<{col_cat_w}} | {total_gt:>5} | {total_tp:>3} | {total_fn:>3} | {overall_rec:>6} |"
    )
    lines.append(sep_border)
    return "\n".join(lines)


def render_head_to_head_cwe_table(results: List[Dict[str, Any]]) -> str:
    """
    Format a head-to-head per-CWE recall comparison table across multiple scans.
    """
    scan_names = [r["name"] for r in results]
    all_cwes = sorted(list({cwe for r in results for cwe in r["per_cwe"]}))

    col_cat_w = 30
    scan_col_w = max([len(n) + 12 for n in scan_names] + [16])

    header_cols = [f"{n + ' Recall':^{scan_col_w}}" for n in scan_names]
    header = f"| {'CWE':<8} | {'Category':<{col_cat_w}} | {'Total':>5} | " + " | ".join(header_cols) + " |"
    sep_border = (
        f"+----------+-{'-' * col_cat_w}-+-------+-"
        + "-+-".join(["-" * scan_col_w for _ in scan_names])
        + "-+"
    )

    width = len(sep_border)
    title = "HEAD-TO-HEAD PER-CWE RECALL COMPARISON"

    lines = [
        "",
        "=" * width,
        f"{title:^{width}}",
        "=" * width,
        sep_border,
        header,
        sep_border,
    ]

    total_gt = 0
    scans_total_tp = [0] * len(results)

    for cwe_id in all_cwes:
        # Get category label and total from first scan that has it
        cat_str = "General"
        tot = 0
        for r in results:
            if cwe_id in r["per_cwe"]:
                cat_str = ", ".join(r["per_cwe"][cwe_id]["types"]) or "General"
                tot = r["per_cwe"][cwe_id]["total"]
                break

        if len(cat_str) > col_cat_w:
            cat_str = cat_str[: col_cat_w - 3] + "..."

        total_gt += tot

        cols = []
        for idx, r in enumerate(results):
            data = r["per_cwe"].get(cwe_id, {"tp": 0, "total": tot, "recall": 0.0})
            tp = data["tp"]
            scans_total_tp[idx] += tp
            pct = data["recall"] * 100
            cell = f"{pct:>5.1f}% ({tp}/{tot})"
            cols.append(f"{cell:^{scan_col_w}}")

        lines.append(f"| {cwe_id:<8} | {cat_str:<{col_cat_w}} | {tot:>5} | " + " | ".join(cols) + " |")

    lines.append(sep_border)
    # Overall summary row
    overall_cols = []
    for idx in range(len(results)):
        t_tp = scans_total_tp[idx]
        pct = (t_tp / total_gt * 100) if total_gt else 0.0
        cell = f"{pct:>5.1f}% ({t_tp}/{total_gt})"
        overall_cols.append(f"{cell:^{scan_col_w}}")

    lines.append(
        f"| {'OVERALL':<8} | {'ALL CATEGORIES':<{col_cat_w}} | {total_gt:>5} | "
        + " | ".join(overall_cols)
        + " |"
    )
    lines.append(sep_border)
    return "\n".join(lines)


def evaluate_scans(
    scan_paths: Sequence[Union[str, Path]],
    dataset: Union[str, Path] = DEFAULT_DATASET,
    exact_cwe: bool = False,
    json_out: Optional[Union[str, Path]] = None,
    detailed: bool = False,
    print_output: bool = True,
    cwe_scope: str = "core10",
) -> Dict[str, Any]:
    """
    Main evaluation routine: evaluates one or more scans against ground truth dataset.

    Args:
        scan_paths: List of paths to scan JSON files
        dataset: Dataset directory path or shorthand name
        exact_cwe: Require exact numeric CWE matching without equivalence classes
        json_out: Path to write result JSON
        detailed: Print detailed per-CWE breakdown table
        print_output: Whether to print ASCII tables to stdout

    Returns:
        Dict[str, Any]: Consolidated evaluation result
    """
    dataset_dir = resolve_dataset_dir(dataset)
    labels, dataset_meta = load_dataset(dataset_dir)
    labels_full = len(labels)
    coverage = None

    if cwe_scope == "core10":
        from eval.cwe_scope import filter_clean_files, filter_labels, scope_coverage
        labels = filter_labels(labels)
        dataset_meta = dict(dataset_meta)
        dataset_meta["clean_files"] = filter_clean_files(dataset_meta)
        coverage = scope_coverage(labels)

    results: List[Dict[str, Any]] = []
    for path in scan_paths:
        res = evaluate_single_scan(
            scan_path=path,
            dataset_dir=dataset_dir,
            labels=labels,
            dataset_meta=dataset_meta,
            exact_cwe=exact_cwe,
            cwe_scope=cwe_scope,
        )
        results.append(res)

    dataset_name = dataset_meta.get("name", dataset_dir.name)
    total_labels = len(labels)

    if print_output:
        summary_table = render_summary_table(
            results=results,
            dataset_name=dataset_name,
            total_labels=total_labels,
            exact_cwe=exact_cwe,
        )
        print(summary_table)

        if detailed:
            if len(results) == 1:
                print(render_detailed_cwe_table(results[0]))
            else:
                print(render_head_to_head_cwe_table(results))
                for r in results:
                    print(render_detailed_cwe_table(r))

    output_payload: Dict[str, Any] = {
        "dataset": dataset_name,
        "dataset_dir": str(dataset_dir),
        "total_ground_truth": total_labels,
        "total_ground_truth_full": labels_full,
        "cwe_scope": coverage,
        "exact_cwe": exact_cwe,
        "match_mode": dataset_meta.get("match_mode", "line"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scans": results,
    }

    if len(results) == 1:
        s0 = results[0]
        output_payload["name"] = s0["name"]
        output_payload["scan_file"] = s0["scan_file"]
        output_payload["findings_count"] = s0["findings_count"]
        output_payload["metrics"] = s0["metrics"]
        output_payload["per_cwe"] = s0["per_cwe"]
        output_payload["missed"] = s0["missed"]
        output_payload["spurious"] = s0["spurious"]

    if json_out:
        out_p = Path(json_out).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(output_payload, indent=2, ensure_ascii=False), encoding="utf-8")
        if print_output:
            print(f"\n[+] Quantitative benchmark evaluation exported to: {out_p}")

    return output_payload


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the command line argument parser for independent evaluation.
    """
    parser = argparse.ArgumentParser(
        prog="evaluate_scan",
        description="Independent quantitative benchmark evaluation and scoring tool.",
    )
    parser.add_argument(
        "--scan",
        nargs="+",
        action="extend",
        required=True,
        help="Path to 1 or more JSON scan output files",
    )
    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help=(
            f"Benchmark dataset directory or name (default: {DEFAULT_DATASET}). "
            "Supported shorthands: benchmark100, benchmark, pilot50, enterprise_multitier, apigateway_micro."
        ),
    )
    parser.add_argument(
        "--exact-cwe",
        action="store_true",
        help="Require exact CWE matching without equivalence classes",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        default=None,
        help="Path to export evaluation results as JSON",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Print detailed per-CWE breakdown table",
    )
    parser.add_argument(
        "--cwe-scope",
        choices=("core10", "full"),
        default="core10",
        help=(
            "Scoring scope (default: core10). 'core10' restricts ground truth, clean "
            "controls and detections to CWE 22/78/79/89/94/328/330/502/611/643; "
            "'full' scores every CWE in the dataset."
        ),
    )
    return parser


def run_evaluation_cli(args: argparse.Namespace) -> int:
    """
    Shared execution handler for CLI invocation.
    """
    scan_inputs = getattr(args, "scan", [])
    if not scan_inputs:
        print("error: --scan is required and must specify at least 1 file", file=sys.stderr)
        return EXIT_ERROR

    try:
        evaluate_scans(
            scan_paths=scan_inputs,
            dataset=getattr(args, "dataset", DEFAULT_DATASET),
            exact_cwe=getattr(args, "exact_cwe", False),
            json_out=getattr(args, "json_out", None),
            cwe_scope=getattr(args, "cwe_scope", "core10"),
            detailed=getattr(args, "detailed", False),
            print_output=True,
        )
        return EXIT_CLEAN
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:
        print(f"error during evaluation: {e}", file=sys.stderr)
        return EXIT_ERROR


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    CLI main entry point.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    return run_evaluation_cli(args)


if __name__ == "__main__":
    sys.exit(main())
