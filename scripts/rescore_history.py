"""Re-score stored dashboard jobs against both CWE scopes; never run a scanner.

Usage: python scripts/rescore_history.py
       python scripts/rescore_history.py --frozen-from reports/rescored_history/metrics_all.json --out reports/rescore_of_snapshot

The dashboard server keeps writing job JSONs into `.vulnagent-jobs/` while it
runs, so "the whole history" is not a stable set. By default this script scores
the files matched by the glob at the moment it runs and records that instant as
a snapshot; `--frozen-from` re-scores exactly the file set a previous manifest
recorded, and refuses to run if any of those files changed. Job JSONs are only
read, never written.

A frozen re-score writes into `--out` (default `reports/rescored_history`) and
refuses to write when that resolves to the manifest it is reading, because that
would destroy the source snapshot and leave the new manifest pointing at itself.

The outputs contain hashes and summary statistics only, not raw findings or credentials.
"""

import argparse
import atexit
import csv
import hashlib
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Imports from the repository must not create __pycache__ outside scripts/reports.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.cwe_scope import filter_clean_files, filter_labels  # noqa: E402
from eval.evaluate_scan import evaluate_single_scan, load_dataset  # noqa: E402

SOURCES = {"benchmark100": "benchmark100", "benchmark1000": "benchmark", "benchmark": "benchmark"}
FIELDS = (
    "job_id", "dataset", "source_name_legacy", "mode", "verify", "model",
    "findings_raw", "tp", "fp", "fn", "precision", "recall", "f1",
    "labels_in_scope", "clean_in_scope", "rejected_paths", "status",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


SNAPSHOT_ATTEMPTS = 3
OUTPUT_MANIFEST = "metrics_all.json"
DEFAULT_OUTPUT_DIR = ("reports", "rescored_history")


def resolve_output_dir(value):
    """
    Resolve the directory this run writes its artifacts into.

    A relative path is taken relative to the process working directory - the
    same rule `--frozen-from` follows - so the two can be compared exactly and
    a run can never read a manifest and then overwrite it.

    Args:
        value: `--out` value, or None for the default directory

    Returns:
        Path: Absolute output directory
    """

    path = Path(value) if value else ROOT.joinpath(*DEFAULT_OUTPUT_DIR)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def collection_digest(blobs):
    """Path-bound digest over the exact bytes this run scored."""
    collection = hashlib.sha256()
    for name, data in sorted(blobs.items()):
        collection.update(name.encode("utf-8") + b"\0" + bytes.fromhex(sha256(data)))
    return collection.hexdigest()


def take_snapshot(root: Path):
    """
    Read the job directory once, retrying if the live server rotates a file.

    The dashboard server writes new job JSONs and prunes old ones while it
    runs, so a file can disappear between the glob and the read. Every file is
    therefore read exactly once and scored from the bytes that were hashed; a
    read that loses a file is retried, because the loss is the directory
    moving, not the snapshot being wrong.

    Args:
        root: Repository root holding `.vulnagent-jobs/`

    Returns:
        tuple: (job paths, {file name: raw bytes}, {file name: parsed payload});
        all three are empty when the directory holds no job JSON
    """

    last_error = None
    for _ in range(SNAPSHOT_ATTEMPTS):
        paths = sorted((root / ".vulnagent-jobs").glob("*.json"))
        if not paths:
            return [], {}, {}
        blobs, payloads = {}, {}
        try:
            for path in paths:
                data = path.read_bytes()
                payloads[path.name] = json.loads(data.decode("utf-8"))
                blobs[path.name] = data
        except (OSError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        return paths, blobs, payloads
    raise RuntimeError(
        f"could not read .vulnagent-jobs consistently after {SNAPSHOT_ATTEMPTS} attempts ({last_error})"
    )


def detect_drift(root: Path, baseline):
    """
    Report what the directory did after the snapshot was read.

    The score covers the bytes in `baseline`; anything added, removed or
    rewritten afterwards is recorded rather than treated as a failure, because
    a dashboard server with a job cap prunes files every time it adds one.

    Args:
        root: Repository root holding `.vulnagent-jobs/`
        baseline: {file name: raw bytes} that was hashed and scored

    Returns:
        dict: sorted added / removed / changed file names
    """

    live = {path.name: path for path in (root / ".vulnagent-jobs").glob("*.json")}
    added = sorted(set(live) - set(baseline))
    removed = sorted(set(baseline) - set(live))
    changed = []
    for name in sorted(set(baseline) & set(live)):
        try:
            if sha256(live[name].read_bytes()) != sha256(baseline[name]):
                changed.append(name)
        except OSError:
            removed.append(name)
    return {"added": added, "removed": sorted(removed), "changed": changed}


def fmt(value):
    return "-" if value is None else str(value)


def frozen_job_paths(manifest_path: Path, root: Path):
    """
    Read the job set a previous manifest recorded and verify it still holds.

    A frozen re-score is only meaningful if it reads the same bytes the earlier
    snapshot hashed. A job file that is missing, or whose SHA-256 no longer
    matches the manifest, would silently produce different numbers under the
    frozen snapshot's name, so it is treated as an error rather than a skip.

    Args:
        manifest_path: Manifest written by an earlier run
        root: Repository root holding `.vulnagent-jobs/`

    Returns:
        tuple: (frozen manifest payload, ordered file names, {name: raw bytes},
        list of problems)
    """

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    job_file_sha256 = (payload.get("inputs") or {}).get("job_file_sha256") or {}
    names, blobs, problems = [], {}, []
    for name, expected in sorted(job_file_sha256.items()):
        path = root / ".vulnagent-jobs" / name
        if not path.is_file():
            problems.append(f"missing: {name}")
            continue
        data = path.read_bytes()
        actual = sha256(data)
        if actual != expected:
            problems.append(f"changed: {name} (now {actual}, frozen {expected})")
            continue
        names.append(name)
        blobs[name] = data
    if not job_file_sha256:
        problems.append("manifest has no inputs.job_file_sha256 map")
    return payload, names, blobs, problems


def metric_row(base, result, label_count, clean_count):
    m = result["metrics"]
    return {
        **{k: base.get(k, "") for k in FIELDS},
        "tp": m["tp"], "fp": m["fp"], "fn": m["fn"],
        "precision": m["precision"], "recall": m["recall"], "f1": m["f1"],
        "labels_in_scope": label_count, "clean_in_scope": clean_count,
        "rejected_paths": result["rejected_paths"], "status": "scored",
    }


def markdown_report(jobs, stats, digest, exact_cwe, snapshot_at, glob_count,
                    is_frozen=False, frozen_from=None, frozen_snapshot_at=None,
                    live_glob_count=None, drift=None):
    skipped = [job for job in jobs if job["status"] != "scored"]
    drift = drift or {"added": [], "removed": [], "changed": []}
    lines = [
        "# Historical job re-score: core10 vs full", "",
        "## Snapshot", "",
        f"- Run at (UTC): `{snapshot_at}`",
        f"- Input glob: `.vulnagent-jobs/*.json`",
        f"- Files matched by the glob at that instant: **{glob_count}**",
        f"- Jobs scored: {len(jobs) - len(skipped)}; jobs skipped: {len(skipped)}",
        f"- Collection SHA-256 of the scored job bytes: `{digest}`",
        f"- Frozen snapshot: **{str(is_frozen).lower()}**"
        + (f"; re-scored from `{frozen_from}` (that manifest's `snapshot_at`: `{frozen_snapshot_at}`)"
           if is_frozen else " (inputs are the files matched by the glob at run time)"),
    ]
    if live_glob_count is not None:
        lines.append(f"- Job files present in `.vulnagent-jobs/` when this run finished: **{live_glob_count}**")
    lines.append(
        "- Files added / removed / changed in `.vulnagent-jobs/` after the snapshot was read: "
        f"**{len(drift['added'])}** / **{len(drift['removed'])}** / **{len(drift['changed'])}**"
        " (recorded in `post_run_drift`; none of them is in the scores below)"
    )
    lines += [
        "",
    ]
    if is_frozen:
        lines += [
            "**This artifact re-scores a frozen input set, not the directory as it is now.** "
            "Every input file was re-hashed against the manifest it was frozen from; a missing or "
            "changed job file aborts the run instead of scoring different bytes under the same name. "
            "The directory may hold more job files than the count above. Re-run without "
            "`--frozen-from` to snapshot the directory as it is now.", "",
            "*Cảnh báo: Server có thể tạo job mới sau thời điểm chạy; manifest này là snapshot tại "
            f"`{frozen_snapshot_at}`. Chạy lại script để cập nhật.*", "",
        ]
    else:
        lines += [
            "**This artifact is a snapshot at the timestamp above, not a permanent "
            "\"entire history\" claim.** The dashboard server writes new job JSONs into "
            "`.vulnagent-jobs/` while it runs, so the number of files can be higher than "
            f"{glob_count} when this file is read. Re-run `python scripts/rescore_history.py` "
            "to obtain a snapshot of the then-current directory; compare `snapshot_at` and "
            "`glob_count_at_run` in `metrics_all.json` against `ls .vulnagent-jobs/*.json | wc -l` "
            "before quoting any number from this report.", "",
            f"*Cảnh báo: Server có thể tạo job mới sau thời điểm chạy; manifest này là snapshot tại "
            f"`{snapshot_at}`. Chạy lại script để cập nhật.*",
        ]
        lines += [""]
    lines += [
        f"Matching: `exact_cwe={str(exact_cwe).lower()}`; line tolerance and path validation use `evaluate_single_scan` defaults.",
        "Legacy `source_name=benchmark1000` maps to `eval/datasets/benchmark` (owasp-full), not `benchmark100`.",
        "Precision/recall/F1 are rounded to 4 decimals by the evaluator; TP/FP/FN are unrounded.",
        "No job file is modified: their SHA-256 values are recorded, never written.",
        "", "## Dataset denominators", "",
        "| Dataset | Labels full | Labels core10 | Removed labels | Clean full | Clean core10 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for dataset, s in sorted(stats.items()):
        lines.append(f"| {dataset} | {s['full']['labels']} | {s['core10']['labels']} | "
                     f"{s['full']['labels'] - s['core10']['labels']} | {s['full']['clean']} | {s['core10']['clean']} |")
    lines += [
        "", "## Per-job comparison", "",
        "Removed detections = parsed detections in full minus eligible parsed detections in core10 "
        "(not necessarily equal to raw findings; rejected paths stay eligible and count as FP).", "",
        "| Job | Dataset | Mode | Verify | Model | Raw | Removed det. | Core10 TP/FP/FN | Core10 P/R/F1 | Full TP/FP/FN | Full P/R/F1 |",
        "|---|---|---|---|---|---:|---:|---|---|---|---|",
    ]
    changed = []
    for job in jobs:
        if job["status"] != "scored":
            continue
        a, b = job["core10"], job["full"]
        removed = job["detections_removed"]
        changed_metrics = [key for key in ("precision", "recall") if a[key] != b[key]]
        if changed_metrics:
            changed.append(job)
        counts = lambda row: "/".join(fmt(row[key]) for key in ("tp", "fp", "fn"))
        scores = lambda row: "/".join(fmt(row[key]) for key in ("precision", "recall", "f1"))
        lines.append(f"| {job['job_id']} | {job['dataset']} | {job['mode']} | {job['verify']} | "
                     f"{job['model']} | {job['findings_raw']} | {removed} | {counts(a)} | {scores(a)} | "
                     f"{counts(b)} | {scores(b)} |")
    lines += ["", "## Jobs with changed precision or recall", ""]
    if changed:
        lines += ["| Job | Changed | Labels excluded | Detections excluded | Core10 P/R | Full P/R |",
                  "|---|---|---:|---:|---|---|"]
        for job in changed:
            a, b = job["core10"], job["full"]
            changed_keys = ", ".join(k for k in ("precision", "recall") if a[k] != b[k])
            lines.append(f"| {job['job_id']} | {changed_keys} | {b['labels_in_scope'] - a['labels_in_scope']} | "
                         f"{job['detections_removed']} | {a['precision']}/{a['recall']} | "
                         f"{b['precision']}/{b['recall']} |")
    else:
        lines.append("None (at the evaluator's four-decimal precision).")
    lines += ["", "## Skipped jobs", "",
              "Every job file present at the snapshot was read. A job is skipped when it cannot be "
              "scored from stored data: `incomplete` (job status not `done`), `empty` "
              "(`result.findings` empty), `unsupported` (`options.source_name` has no benchmark "
              "dataset mapping).", "",
              "| Job | Status | Reason |", "|---|---|---|"]
    if skipped:
        for job in skipped:
            lines.append(f"| {job['job_id']} | {job['status']} | {job['reason']} |")
    else:
        lines.append("| None | - | every job file at the snapshot was scoreable |")
    lines += [
        "", "## How to interpret changes in a thesis report", "",
        "Use the core10 columns for the 10-CWE thesis scope; earlier full-scope TP/FP/FN, "
        "precision, recall and F1 for any changed row must be replaced with the corresponding core10 values above. "
        "The full denominator includes out-of-scope labels and detections; core10 removes them before matching. "
        "A smaller label denominator does not by itself prove recall rises: TP may also change. "
        "Clean-file controls are filtered by scope as well (they classify FP; they do not add to recall's denominator). "
        "No docx was read or changed, so which numeric cells in an actual docx match historical full scores is not verified.",
        "", "Hashes of each dataset's `labels.json`, of each job file, and of canonical JSON findings "
        "are in `metrics_all.json`. CSV rows without scores represent excluded jobs; their reason is in the manifest.", "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exact-cwe", action="store_true", help="disable CWE equivalence (default: equivalence matching)")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument(
        "--snapshot", choices=("current",), default="current",
        help="score the job files matched by `.vulnagent-jobs/*.json` at run time (default)",
    )
    inputs.add_argument(
        "--frozen-from", metavar="MANIFEST", default=None,
        help="re-score exactly the job files recorded in a previous metrics_all.json "
             "(aborts if any of those files is missing or changed)",
    )
    parser.add_argument(
        "--out", metavar="DIR", default=None,
        help="directory for metrics_all.json, metrics_*.csv and RESCORE_REPORT.md "
             "(default: reports/rescored_history)",
    )
    args = parser.parse_args()
    output = resolve_output_dir(args.out)
    output_manifest = output / OUTPUT_MANIFEST
    snapshot_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    frozen_from = None
    frozen_snapshot_at = None
    if args.frozen_from:
        frozen_manifest = Path(args.frozen_from)
        if not frozen_manifest.is_absolute():
            frozen_manifest = Path.cwd() / frozen_manifest
        frozen_manifest = frozen_manifest.resolve()
        if not frozen_manifest.is_file():
            parser.error(f"--frozen-from manifest not found: {frozen_manifest}")
        if frozen_manifest == output_manifest:
            # Reading the manifest and writing the new one to the same path
            # destroys the snapshot the run is re-scoring and leaves the new
            # manifest pointing frozen_from at itself.
            parser.error(
                f"--frozen-from resolves to the output manifest {output_manifest}; "
                "pass a different --out directory to keep the source snapshot intact"
            )
        payload, names, blobs, problems = frozen_job_paths(frozen_manifest, ROOT)
        if problems:
            print("ERROR: frozen snapshot cannot be reproduced; no outputs written", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 2
        frozen_from = str(frozen_manifest)
        frozen_snapshot_at = payload.get("snapshot_at")
        paths = [ROOT / ".vulnagent-jobs" / name for name in names]
        payloads = {name: json.loads(blobs[name].decode("utf-8")) for name in names}
        print(f"Frozen inputs from: {frozen_from} (snapshot_at {frozen_snapshot_at}) | {len(paths)} job JSON(s)")
    else:
        paths, blobs, payloads = take_snapshot(ROOT)
        if not paths:
            parser.error("no job JSONs in .vulnagent-jobs")
        print(f"Snapshot: {snapshot_at} | glob matched {len(paths)} job JSON(s)")
    glob_count = len(paths)
    job_files = {name: sha256(data) for name, data in blobs.items()}
    digest = collection_digest(blobs)
    datasets = {}
    for dataset in sorted(set(SOURCES.values())):
        dataset_path = ROOT / "eval" / "datasets" / dataset
        labels, meta = load_dataset(dataset_path)
        datasets[dataset] = {
            "path": dataset_path, "labels": labels, "meta": meta,
            "labels_sha256": sha256((dataset_path / "labels.json").read_bytes()),
            "full": {"labels": len(labels), "clean": len(meta["clean_files"])},
            "core10": {"labels": len(filter_labels(labels)), "clean": len(filter_clean_files(meta))},
        }
    jobs = []
    mirror = tempfile.TemporaryDirectory(prefix="vulnagent-rescore-jobs-")
    atexit.register(mirror.cleanup)
    mirrored = {}
    for name, data in blobs.items():
        target = Path(mirror.name) / name
        target.write_bytes(data)
        mirrored[name] = target
    for path in paths:
        payload = payloads[path.name]
        opts = payload.get("options") or {}
        result = payload.get("result") or {}
        findings = result.get("findings") or []
        source = opts.get("source_name")
        dataset = SOURCES.get(source)
        status, reason = "scored", ""
        if payload.get("status") != "done":
            status, reason = "incomplete", f"job status={payload.get('status')!r} (not done)"
        elif not findings:
            status, reason = "empty", "result.findings is empty"
        elif dataset is None:
            status, reason = "unsupported", f"source_name={source!r} has no benchmark dataset mapping"
        base = {
            "job_id": path.stem, "dataset": dataset or "", "source_name_legacy": "benchmark1000" if source == "benchmark1000" else "",
            "mode": opts.get("mode") or "", "verify": opts.get("verify", ""),
            "model": opts.get("model") or "", "findings_raw": len(findings), "status": status,
        }
        job = {
            **base, "source_name": source, "reason": reason,
            "job_file_sha256": job_files[path.name],
            "findings_sha256": sha256(json.dumps(findings, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
        }
        if status == "scored":
            ds = datasets[dataset]
            for scope in ("core10", "full"):
                # Score the snapshot copy, never the live path: the evaluator
                # re-reads the file, and the live directory is being rewritten
                # by the dashboard server. The copy is the bytes hashed above.
                scored = evaluate_single_scan(mirrored[path.name], ds["path"], ds["labels"], ds["meta"],
                                              exact_cwe=args.exact_cwe, cwe_scope=scope)
                if scored["metrics"]["partial"]:
                    raise ValueError(f"partial ground truth cannot yield precision: {dataset}")
                job[scope] = metric_row(base, scored, ds[scope]["labels"], ds[scope]["clean"])
                job[f"detections_{scope}"] = scored["detections_count"]
            job["detections_removed"] = job["detections_full"] - job["detections_core10"]
        else:
            job["core10"] = {**{field: "" for field in FIELDS}, **base}
            job["full"] = {**{field: "" for field in FIELDS}, **base}
        jobs.append(job)
    drift = detect_drift(ROOT, blobs)
    if any(drift.values()):
        print(f"NOTE: .vulnagent-jobs moved after the snapshot was read: "
              f"{len(drift['added'])} added, {len(drift['removed'])} removed, "
              f"{len(drift['changed'])} changed; recorded as post_run_drift")
    output.mkdir(parents=True, exist_ok=True)
    for scope in ("core10", "full"):
        with (output / f"metrics_{scope}.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows({key: job[scope].get(key, "") for key in FIELDS} for job in jobs)
    manifest = {
        "snapshot_at": snapshot_at,
        "glob_count_at_run": glob_count,
        "is_frozen_snapshot": bool(frozen_from),
        "frozen_from": frozen_from,
        "frozen_snapshot_at": frozen_snapshot_at,
        "post_run_drift": drift,
        "matching": {"exact_cwe": args.exact_cwe, "scopes": ["core10", "full"]},
        "inputs": {"glob": ".vulnagent-jobs/*.json", "count": len(paths),
                   "count_at_run": glob_count,
                   "collection_sha256": digest,
                   "job_file_sha256": job_files},
        "datasets": {name: {"labels_path": f"eval/datasets/{name}/labels.json",
                             "labels_sha256": ds["labels_sha256"],
                             "full": ds["full"], "core10": ds["core10"]} for name, ds in datasets.items()},
        "jobs": jobs,
    }
    (output / OUTPUT_MANIFEST).write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    live_glob_count = len(list((ROOT / ".vulnagent-jobs").glob("*.json")))
    (output / "RESCORE_REPORT.md").write_text(
        markdown_report(jobs, datasets, digest, args.exact_cwe, snapshot_at, glob_count,
                        is_frozen=bool(frozen_from), frozen_from=frozen_from,
                        frozen_snapshot_at=frozen_snapshot_at, live_glob_count=live_glob_count,
                        drift=drift),
        encoding="utf-8",
    )
    mirror.cleanup()
    counts = Counter(job["status"] for job in jobs)
    print(f"Snapshot at (UTC): {snapshot_at} | glob files at run: {glob_count} | jobs read: {len(jobs)}")
    print(f"Manifest inputs.count: {len(paths)} | glob_count_at_run: {glob_count} | "
          f"job JSONs in .vulnagent-jobs now: {live_glob_count} | is_frozen_snapshot: {bool(frozen_from)}")
    print(f"Jobs: {len(jobs)} | " + " | ".join(f"{key}: {counts[key]}" for key in ("scored", "incomplete", "empty", "unsupported")))
    print(f"Job JSON collection SHA-256 of the scored bytes: {digest}")
    print(f"Post-run drift: added={len(drift['added'])} removed={len(drift['removed'])} changed={len(drift['changed'])}")
    print(f"Excluded jobs: {', '.join(j['job_id'] + '=' + j['status'] for j in jobs if j['status'] != 'scored')}")
    print("Dataset        full labels/clean   core10 labels/clean")
    for name, ds in datasets.items():
        print(f"{name:<14} {ds['full']['labels']:>4}/{ds['full']['clean']:<5}         {ds['core10']['labels']:>4}/{ds['core10']['clean']}")
    print("job_id         dataset       raw  removed_det    core10 TP/FP/FN P/R         full TP/FP/FN P/R")
    for job in jobs:
        if job["status"] != "scored":
            continue
        a, b = job["core10"], job["full"]
        show = lambda row: f"{row['tp']}/{row['fp']}/{row['fn']} {row['precision']}/{row['recall']}"
        print(f"{job['job_id']:<14} {job['dataset']:<13} {job['findings_raw']:>4} {job['detections_removed']:>7}        {show(a):<27} {show(b)}")
    print(f"Excluded jobs: {', '.join(j['job_id'] + '=' + j['status'] for j in jobs if j['status'] != 'scored')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
