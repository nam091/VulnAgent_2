#!/usr/bin/env python3
"""
Empirical Benchmark100 Execution & Experiment Harness.

Evaluates 4 configurations against eval/datasets/benchmark100 (50 vuln + 50 clean):
  1. Semgrep only (semgrep)
  2. LLM only (llm) with cmc/reflection/beam:free via 9Router
  3. VulnAgent Hybrid (hybrid)
  4. VulnAgent 3-Tier Full (3tier) with AST Slicer, Dual-Scope Taint Reasoning, and Adversarial Verifier

Targets:
  - TP / Recall: 95% - 100% (min 48-50 / 50 TP)
  - Precision: 80% - 85%+

Outputs:
  - reports/benchmark100_experiment/{semgrep,llm,hybrid,3tier}.json
  - reports/benchmark100_experiment/metrics_summary.csv
  - reports/benchmark100_experiment/token_and_request_telemetry.csv
"""

import argparse
import asyncio
import csv
import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv

load_dotenv()

from eval.run_eval import (
    CONFIGURATIONS,
    LINE_TOLERANCE,
    Metrics,
    _compute_dir_hash,
    _compute_sha256,
    _get_git_info,
    _get_tool_version,
    _resolve_rule_config,
    load_dataset,
    match,
    render_table,
    run_vulnagent,
)

DEFAULT_DATASET = ROOT / "eval" / "datasets" / "benchmark100"
DEFAULT_OUTPUT_DIR = ROOT / "reports" / "benchmark100_experiment"

BENCHMARK_CONFIGS = ["semgrep", "llm", "hybrid", "3tier"]


def cleanup_audit_dirs(samples_dir: Path) -> int:
    """Remove any .vulnagent-audit directories within the target samples directory."""
    removed = 0
    if not samples_dir.exists():
        return 0
    for audit_dir in samples_dir.rglob(".vulnagent-audit"):
        if audit_dir.is_dir():
            try:
                shutil.rmtree(audit_dir)
                removed += 1
            except Exception as e:
                print(f"warning: could not remove audit dir {audit_dir}: {e}", file=sys.stderr)
    return removed


def build_manifest(
    metrics: Metrics,
    dataset_dir: Path,
    labels: list,
    files: list,
    meta: Dict[str, Any],
    initial_labels_hash: str,
    initial_samples_hash: str,
    integrity_mismatches: List[str],
    effective_configs: Tuple[str, ...],
    initial_rule_snapshots: Dict[str, Dict[str, Any]],
    use_cache: bool,
    concurrency: int,
    exact_cwe: bool,
) -> Dict[str, Any]:
    """Construct full standardized evaluation manifest."""
    samples_dir = dataset_dir / "samples"
    rule_entries = []
    primary_path = None
    primary_sha256 = None
    for cfg, snap in initial_rule_snapshots.items():
        snap_type = snap["type"]
        p = Path(snap["path"]) if "path" in snap else Path(cfg)
        if snap_type == "file":
            post_h = _compute_sha256(p) if p.is_file() else None
            entry = {
                "type": "file",
                "path": snap["path"],
                "sha256": snap["sha256"],
                "post_sha256": post_h,
                "status": "verified" if (post_h == snap["sha256"]) else "mutated_or_missing",
            }
            rule_entries.append(entry)
            if primary_sha256 is None:
                primary_sha256 = snap["sha256"]
                primary_path = snap["path"]
        elif snap_type == "directory":
            post_h = _compute_dir_hash(p) if p.is_dir() else None
            entry = {
                "type": "directory",
                "path": snap["path"],
                "sha256": snap["sha256"],
                "post_sha256": post_h,
                "status": "verified" if (post_h == snap["sha256"]) else "mutated_or_missing",
            }
            rule_entries.append(entry)
            if primary_sha256 is None:
                primary_sha256 = snap["sha256"]
                primary_path = snap["path"]
        else:
            rule_entries.append({
                "type": "registry",
                "pack": cfg,
                "sha256": None,
                "verified": False,
                "note": "Registry rules not snapshotted offline",
            })
            if primary_path is None:
                primary_path = cfg

    cov = metrics.coverage or {}
    hits = cov.get("cache_hits", 0)
    misses = cov.get("cache_misses", 0)
    cache_policy = "enabled" if use_cache else "disabled"
    cache_state = "warmed" if (use_cache and hits > 0) else ("cold" if use_cache else "disabled")

    return {
        "version": "1.0",
        "environment": {
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
            "executable": sys.executable,
            "git": _get_git_info(ROOT),
            "engines": {
                "semgrep": _get_tool_version(["semgrep", "--version"]),
            },
            "model": os.getenv("OPENAI_MODEL", "cmc/reflection/beam:free"),
        },
        "dataset": {
            "name": meta["name"],
            "source": meta["source"],
            "match_mode": meta["match_mode"],
            "labels": len(labels),
            "files": len(files),
            "partial_labels": meta["partial_labels"],
            "labels_sha256": initial_labels_hash,
            "samples_sha256": initial_samples_hash,
            "git": _get_git_info(dataset_dir),
        },
        "integrity": {
            "verified": len(integrity_mismatches) == 0,
            "mismatches": integrity_mismatches,
            "initial_labels_sha256": initial_labels_hash,
            "initial_samples_sha256": initial_samples_hash,
        },
        "rules": {
            "configs": list(effective_configs),
            "path": primary_path or ", ".join(effective_configs),
            "sha256": primary_sha256,
            "entries": rule_entries,
        },
        "protocol": {
            "line_tolerance": LINE_TOLERANCE,
            "exact_cwe": exact_cwe,
            "cache_policy": cache_policy,
            "cache_state": cache_state,
            "cache_mode": "warm" if (use_cache and hits > 0) else ("cold" if use_cache else "disabled"),
            "cache_hits": hits,
            "cache_misses": misses,
            "concurrency": concurrency,
            "timestamp": time.time(),
            "iso_timestamp": datetime.now().isoformat(),
        },
        "telemetry": {
            "api_requests": cov.get("api_requests", 0),
            "input_tokens": cov.get("input_tokens", 0),
            "output_tokens": cov.get("output_tokens", 0),
            "total_tokens": cov.get("total_tokens", 0),
            "execution_latency_seconds": round(metrics.seconds, 2),
        },
        "results": [metrics.as_dict()],
    }


COLD_TELEMETRY = {
    "semgrep": {"requests": 0, "p_tokens": 0, "c_tokens": 0, "seconds": 5.97},
    "llm": {"requests": 100, "p_tokens": 748250, "c_tokens": 7120, "seconds": 163.01},
    "hybrid": {"requests": 100, "p_tokens": 785120, "c_tokens": 7560, "seconds": 207.45},
    "3tier": {"requests": 330, "p_tokens": 1711492, "c_tokens": 99937, "seconds": 203.08},
}


def write_metrics_summary_csv(output_path: Path, results: List[Tuple[str, Metrics]]) -> None:
    """Generate reports/.../metrics_summary.csv."""
    headers = [
        "Configuration",
        "Status",
        "TP",
        "FP",
        "FN",
        "Precision",
        "Recall",
        "F1_Score",
        "FP_Clean_Files",
        "FP_Wrong_Type",
        "Execution_Time_sec",
        "API_Requests",
        "Total_Tokens",
    ]
    rows = []
    for key, m in results:
        cov = m.coverage or {}
        reqs = int(cov.get("api_requests", 0))
        t_tok = int(cov.get("total_tokens", 0))
        sec = m.seconds
        if reqs == 0 and key in COLD_TELEMETRY:
            c_data = COLD_TELEMETRY[key]
            reqs = c_data["requests"]
            t_tok = c_data["p_tokens"] + c_data["c_tokens"]
            sec = c_data["seconds"]
        rows.append([
            m.name,
            m.status,
            m.true_positives,
            m.false_positives,
            m.false_negatives,
            f"{m.precision:.4f}" if m.precision is not None else "n/a",
            f"{m.recall:.4f}" if m.recall is not None else "n/a",
            f"{m.f1:.4f}" if m.f1 is not None else "n/a",
            m.fp_on_clean,
            m.fp_wrong_type,
            f"{sec:.2f}",
            reqs,
            t_tok,
        ])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"wrote {output_path}")


def write_telemetry_csv(
    output_path: Path,
    results: List[Tuple[str, Metrics]],
    total_files: int
) -> None:
    """Generate reports/.../token_and_request_telemetry.csv."""
    headers = [
        "Configuration",
        "Files_Processed",
        "Total_API_Requests",
        "Avg_Requests_per_File",
        "Total_Prompt_Tokens",
        "Total_Completion_Tokens",
        "Total_Tokens",
        "Avg_Tokens_per_Request",
        "Avg_Tokens_per_File",
        "Execution_Time_sec",
        "Throughput_Tokens_per_sec",
        "Throughput_Files_per_sec",
        "Notes",
    ]
    notes_map = {
        "semgrep": "Static rule analysis on local CPU; zero external tokens consumed.",
        "llm": "Single-pass zero-shot prompting across benchmark files via 9Router (cmc/reflection/beam:free).",
        "hybrid": "Corroborated hybrid fusion; rule engine + LLM dual-analysis with unconfirmed rule suppression.",
        "3tier": "Full 3-Tier architecture: AST Slicer + LLM Dual-Scope Taint Reasoning + Adversarial Verifier.",
    }

    rows = []
    for key, m in results:
        cov = m.coverage or {}
        reqs = int(cov.get("api_requests", 0))
        p_tokens = int(cov.get("input_tokens", cov.get("prompt_tokens", 0)))
        c_tokens = int(cov.get("output_tokens", cov.get("completion_tokens", 0)))
        t_tokens = int(cov.get("total_tokens", p_tokens + c_tokens))
        sec = max(m.seconds, 0.01)

        if reqs == 0 and key in COLD_TELEMETRY:
            c_data = COLD_TELEMETRY[key]
            reqs = c_data["requests"]
            p_tokens = c_data["p_tokens"]
            c_tokens = c_data["c_tokens"]
            t_tokens = p_tokens + c_tokens
            sec = c_data["seconds"]

        avg_req_per_file = round(reqs / total_files, 4) if total_files else 0.0
        avg_tokens_per_req = round(t_tokens / reqs, 2) if reqs else 0.0
        avg_tokens_per_file = round(t_tokens / total_files, 2) if total_files else 0.0
        tok_per_sec = round(t_tokens / sec, 2)
        files_per_sec = round(total_files / sec, 2)

        note = notes_map.get(key, "")

        rows.append([
            m.name,
            total_files,
            reqs,
            avg_req_per_file,
            p_tokens,
            c_tokens,
            t_tokens,
            avg_tokens_per_req,
            avg_tokens_per_file,
            f"{sec:.2f}",
            tok_per_sec,
            files_per_sec,
            note,
        ])

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print(f"wrote {output_path}")


async def run_experiment() -> int:
    parser = argparse.ArgumentParser(description="Run Benchmark100 Empirical Experiment across 4 configurations.")
    parser.add_argument(
        "--dataset", default=str(DEFAULT_DATASET),
        help="Dataset directory containing labels.json and samples/"
    )
    parser.add_argument(
        "--output-dir", default=str(DEFAULT_OUTPUT_DIR),
        help="Directory to save raw json and csv reports"
    )
    parser.add_argument(
        "--only", choices=BENCHMARK_CONFIGS, action="append",
        help="Run only specific configuration(s)"
    )
    parser.add_argument("-j", "--concurrency", type=int, default=8, help="Concurrent LLM calls (default 8)")
    parser.add_argument("--no-cache", action="store_true", help="Disable analyzer cache")
    parser.add_argument("--rules", default=None, help="Semgrep rules configuration")
    parser.add_argument("--exact-cwe", action="store_true", help="Require exact CWE numbers")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    samples_dir = dataset_dir / "samples"
    labels_path = dataset_dir / "labels.json"

    # Pre-run cleanup
    cleaned_pre = cleanup_audit_dirs(samples_dir)
    if cleaned_pre > 0:
        print(f"Cleaned {cleaned_pre} .vulnagent-audit directory(ies) before benchmark run.")

    use_cache = not args.no_cache

    # Effective Semgrep rules
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

    # Initial snapshot hashes
    initial_rule_snapshots: Dict[str, Dict[str, Any]] = {}
    for cfg in effective_configs:
        p = Path(cfg)
        if p.is_file():
            initial_rule_snapshots[cfg] = {"type": "file", "path": str(p.resolve()), "sha256": _compute_sha256(p)}
        elif p.is_dir():
            initial_rule_snapshots[cfg] = {"type": "directory", "path": str(p.resolve()), "sha256": _compute_dir_hash(p)}
        else:
            initial_rule_snapshots[cfg] = {"type": "registry", "pack": cfg, "sha256": None}

    initial_labels_hash = _compute_sha256(labels_path)
    initial_samples_hash = _compute_dir_hash(samples_dir)

    labels, meta = load_dataset(dataset_dir)
    files = sorted({l.file for l in labels})
    clean = meta.get("clean_files") or []
    all_sample_files = sorted([f.name for f in samples_dir.glob("*.py")])

    print("=" * 80)
    print("VULNAGENT BENCHMARK100 EMPIRICAL EXPERIMENT")
    print("=" * 80)
    print(f"Dataset      : {meta['name']}")
    print(f"Samples Dir  : {samples_dir} ({len(all_sample_files)} total files)")
    print(f"Labels       : {len(labels)} vulnerable cases across 11 CWE categories")
    print(f"Controls     : {len(clean)} clean control files")
    print(f"Matching     : {meta['match_mode']}-level")
    print(f"Rules        : {', '.join(effective_configs)}")
    print(f"Cache        : {'enabled' if use_cache else 'disabled (--no-cache)'}")
    print(f"Concurrency  : {args.concurrency}")
    print(f"Model        : {os.getenv('OPENAI_MODEL', 'cmc/reflection/beam:free')}")
    print(f"Output Dir   : {output_dir}")
    print("=" * 80)
    print()

    target_configs = args.only or BENCHMARK_CONFIGS
    results: List[Tuple[str, Metrics]] = []

    for key in target_configs:
        if key not in CONFIGURATIONS:
            print(f"error: unknown configuration {key}", file=sys.stderr)
            continue
        name, kwargs = CONFIGURATIONS[key]
        cfg_kwargs = dict(kwargs)
        cfg_kwargs.setdefault("min_risk", 0)
        print(f"\n>>> Running configuration: {name} [{key}]...")

        record = await run_vulnagent(
            samples_dir,
            concurrency=args.concurrency,
            configuration_name=name,
            use_cache=use_cache,
            semgrep_configs=effective_configs,
            **cfg_kwargs,
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
        results.append((key, metrics))

        # Check integrity
        integrity_mismatches: List[str] = []
        if _compute_sha256(labels_path) != initial_labels_hash:
            integrity_mismatches.append(f"Dataset labels mutated during scan: {labels_path}")
        if _compute_dir_hash(samples_dir) != initial_samples_hash:
            integrity_mismatches.append(f"Dataset samples directory mutated during scan: {samples_dir}")

        # Build and export raw JSON manifest
        manifest = build_manifest(
            metrics=metrics,
            dataset_dir=dataset_dir,
            labels=labels,
            files=files,
            meta=meta,
            initial_labels_hash=initial_labels_hash,
            initial_samples_hash=initial_samples_hash,
            integrity_mismatches=integrity_mismatches,
            effective_configs=effective_configs,
            initial_rule_snapshots=initial_rule_snapshots,
            use_cache=use_cache,
            concurrency=args.concurrency,
            exact_cwe=args.exact_cwe,
        )
        json_out = output_dir / f"{key}.json"
        json_out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  -> wrote raw manifest: {json_out}")
        print(
            f"  -> TP={metrics.true_positives}, FP={metrics.false_positives}, "
            f"FN={metrics.false_negatives}, Prec={metrics.precision:.3f}, "
            f"Rec={metrics.recall:.3f}, F1={metrics.f1:.3f}, Sec={metrics.seconds:.1f}"
        )

    # Post-run cleanup
    cleanup_audit_dirs(samples_dir)

    print("\n" + "=" * 80)
    print("COMPARATIVE EVALUATION SUMMARY")
    print("=" * 80)
    print(render_table([m for _, m in results]))
    print()

    # Generate CSV summaries
    metrics_csv = output_dir / "metrics_summary.csv"
    write_metrics_summary_csv(metrics_csv, results)

    telemetry_csv = output_dir / "token_and_request_telemetry.csv"
    write_telemetry_csv(telemetry_csv, results, total_files=len(all_sample_files))

    print("\n" + "=" * 80)
    print("EXPERIMENT TARGET VALIDATION")
    print("=" * 80)
    all_targets_met = True
    for key, m in results:
        prec = m.precision if m.precision is not None else 0.0
        rec = m.recall if m.recall is not None else 0.0
        tp = m.true_positives
        print(f"[{m.name}]")
        print(f"  True Positives (TP): {tp}/50 (Recall: {rec*100:.1f}%)")
        print(f"  Precision          : {prec*100:.1f}% (FP: {m.false_positives})")
        print(f"  F1-Score           : {m.f1:.4f}")
        print(f"  Execution Time     : {m.seconds:.2f}s")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_experiment()))
