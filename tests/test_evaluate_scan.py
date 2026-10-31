"""Unit tests for independent evaluation script and benchmark score CLI.

Tests cover:
1. Finding payload extraction across supported schemas (StandardScanOutput, Job JSON, raw list, reports, SARIF)
2. Path, line, and CWE normalization into Detection models
3. CWE matching modes (equivalence classes vs exact CWE)
4. Per-CWE breakdown calculation (Total, TP, FN, Recall)
5. Single scan evaluation metrics (TP, FP, FN, Precision, Recall, F1, missed, spurious)
6. Multiple scan head-to-head comparison
7. JSON result export and schema conformance
8. CLI command dispatch via eval.evaluate_scan and src.cli benchmark score
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from cli import build_parser as build_cli_parser, main as cli_main
from eval.evaluate_scan import (
    EXIT_CLEAN,
    EXIT_ERROR,
    compute_per_cwe_breakdown,
    evaluate_scans,
    evaluate_single_scan,
    extract_findings_from_payload,
    finding_to_detection,
    normalize_cwe_string,
    normalize_finding_file,
    render_detailed_cwe_table,
    render_head_to_head_cwe_table,
    render_summary_table,
    resolve_dataset_dir,
    run_evaluation_cli,
)
from eval.run_eval import Detection, Label


@pytest.fixture
def temp_benchmark_dataset(tmp_path: Path) -> Path:
    """Create a temporary mock benchmark dataset with ground-truth labels."""
    dataset_dir = tmp_path / "mock_dataset"
    samples_dir = dataset_dir / "samples"
    samples_dir.mkdir(parents=True)

    # Sample files
    (samples_dir / "vuln_sql.py").write_text("cursor.execute(user_input)\n", encoding="utf-8")
    (samples_dir / "vuln_traversal.py").write_text("open(user_path).read()\n", encoding="utf-8")
    (samples_dir / "vuln_auth.py").write_text("hardcoded_pass = 'secret'\n", encoding="utf-8")
    (samples_dir / "clean_sample.py").write_text("print('clean code')\n", encoding="utf-8")

    labels_data = {
        "name": "Mock Benchmark Dataset",
        "match_mode": "line",
        "partial_labels": False,
        "clean_files": ["clean_sample.py"],
        "labels": [
            {
                "file": "vuln_sql.py",
                "line": 1,
                "cwe": "CWE-89",
                "type": "SQL_INJECTION",
                "note": "Sink at line 1",
            },
            {
                "file": "vuln_traversal.py",
                "line": 1,
                "cwe": "CWE-22",
                "type": "PATH_TRAVERSAL",
                "note": "Sink at line 1",
            },
            {
                "file": "vuln_auth.py",
                "line": 1,
                "cwe": "CWE-798",
                "type": "HARDCODED_CREDENTIALS",
                "note": "Sink at line 1",
            },
        ],
    }

    (dataset_dir / "labels.json").write_text(json.dumps(labels_data), encoding="utf-8")
    return dataset_dir


def test_extract_findings_from_payload():
    """Verify finding extraction across various scan output structures."""
    # 1. Raw list
    raw_list = [{"file": "test.py", "line": 10, "cwe": "CWE-89"}]
    assert extract_findings_from_payload(raw_list) == raw_list

    # 2. StandardScanOutput schema
    standard_scan = {"schema_version": "1.0.0", "findings": raw_list}
    assert extract_findings_from_payload(standard_scan) == raw_list

    # 3. Dashboard Job JSON schema
    job_scan = {"id": "job123", "result": {"findings": raw_list}}
    assert extract_findings_from_payload(job_scan) == raw_list

    # 4. Job with list result
    job_list_scan = {"id": "job123", "result": raw_list}
    assert extract_findings_from_payload(job_list_scan) == raw_list

    # 5. VulnerabilityReport
    vuln_report = {"status": "completed", "vulnerabilities": raw_list}
    assert extract_findings_from_payload(vuln_report) == raw_list

    # 6. ScanResult with multiple reports
    scan_result = {"reports": [{"vulnerabilities": raw_list}]}
    assert extract_findings_from_payload(scan_result) == raw_list

    # 7. Semgrep / Bandit style results
    semgrep_out = {"results": raw_list}
    assert extract_findings_from_payload(semgrep_out) == raw_list

    # 8. SARIF format
    sarif_out = {"runs": [{"results": raw_list}]}
    assert extract_findings_from_payload(sarif_out) == raw_list

    # 9. Benchmark manifest format with raw_findings
    bench_manifest = {
        "version": "1.0",
        "results": [{"name": "TestRun", "raw_findings": raw_list}],
    }
    assert extract_findings_from_payload(bench_manifest) == raw_list

    # 10. Empty or non-dict payloads
    assert extract_findings_from_payload(None) == []
    assert extract_findings_from_payload({}) == []
    assert extract_findings_from_payload("not a json") == []


def test_normalize_finding_file(temp_benchmark_dataset: Path):
    """Verify file path normalization for relative, absolute, and Windows slashes."""
    labels = {"vuln_sql.py", "vuln_traversal.py", "vuln_auth.py"}

    # Exact filename
    assert normalize_finding_file("vuln_sql.py", temp_benchmark_dataset, labels) == "vuln_sql.py"

    # Leading samples/
    assert normalize_finding_file("samples/vuln_sql.py", temp_benchmark_dataset, labels) == "vuln_sql.py"

    # Windows backslashes
    assert normalize_finding_file("samples\\vuln_sql.py", temp_benchmark_dataset, labels) == "vuln_sql.py"

    # Full path inside samples
    full_path = (temp_benchmark_dataset / "samples" / "vuln_sql.py").resolve().as_posix()
    assert normalize_finding_file(full_path, temp_benchmark_dataset, labels) == "vuln_sql.py"

    # Arbitrary prefix ending in valid label
    assert normalize_finding_file("build/sources/vuln_traversal.py", temp_benchmark_dataset, labels) == "vuln_traversal.py"


def test_normalize_cwe_string():
    """Verify CWE string normalization from different representations."""
    assert normalize_cwe_string("CWE-89") == "89"
    assert normalize_cwe_string("89") == "89"
    assert normalize_cwe_string("cwe-22") == "22"
    assert normalize_cwe_string(["CWE-89: SQL Injection"]) == "89"
    assert normalize_cwe_string(89) == "89"
    assert normalize_cwe_string("") == ""
    assert normalize_cwe_string(None) == ""


def test_finding_to_detection(temp_benchmark_dataset: Path):
    """Verify finding dictionary conversion into Detection model."""
    label_files = {"vuln_sql.py"}

    # Standard finding
    f1 = {
        "file": "samples/vuln_sql.py",
        "start_line": 1,
        "cwe": "CWE-89",
        "type": "SQL_INJECTION",
        "source": "confirmed",
    }
    det1 = finding_to_detection(f1, temp_benchmark_dataset, label_files)
    assert det1 is not None
    assert det1.file == "vuln_sql.py"
    assert det1.line == 1
    assert det1.cwe == "89"
    assert det1.type == "SQL_INJECTION"
    assert det1.source == "confirmed"

    # Nested location dict
    f2 = {
        "location": {"file_path": "vuln_sql.py", "start_line": 5},
        "cwe_id": "89",
        "type": "SQL_INJECTION",
    }
    det2 = finding_to_detection(f2, temp_benchmark_dataset, label_files)
    assert det2 is not None
    assert det2.file == "vuln_sql.py"
    assert det2.line == 5
    assert det2.cwe == "89"

    # Semgrep / Bandit style finding
    f3 = {
        "path": "vuln_sql.py",
        "start": {"line": 1},
        "extra": {"metadata": {"cwe": ["CWE-89: SQL Injection"]}},
        "check_id": "python.sql.injection",
    }
    det3 = finding_to_detection(f3, temp_benchmark_dataset, label_files)
    assert det3 is not None
    assert det3.file == "vuln_sql.py"
    assert det3.line == 1
    assert det3.cwe == "89"
    assert det3.type == "python.sql.injection"


def test_compute_per_cwe_breakdown():
    """Verify per-CWE breakdown counts and recall calculations."""
    labels = [
        Label(file="a.py", line=1, cwe="89", type="SQL_INJECTION"),
        Label(file="b.py", line=1, cwe="89", type="SQL_INJECTION"),
        Label(file="c.py", line=1, cwe="22", type="PATH_TRAVERSAL"),
        Label(file="d.py", line=1, cwe="79", type="XSS"),
    ]

    # Suppose label 0 (SQL) and label 2 (Traversal) are claimed
    claimed = {0, 2}
    breakdown = compute_per_cwe_breakdown(labels, claimed)

    # Check CWE-89: total=2, tp=1, fn=1, recall=0.5
    assert "CWE-89" in breakdown
    assert breakdown["CWE-89"]["total"] == 2
    assert breakdown["CWE-89"]["tp"] == 1
    assert breakdown["CWE-89"]["fn"] == 1
    assert breakdown["CWE-89"]["recall"] == 0.5

    # Check CWE-22: total=1, tp=1, fn=0, recall=1.0
    assert "CWE-22" in breakdown
    assert breakdown["CWE-22"]["total"] == 1
    assert breakdown["CWE-22"]["tp"] == 1
    assert breakdown["CWE-22"]["fn"] == 0
    assert breakdown["CWE-22"]["recall"] == 1.0

    # Check CWE-79: total=1, tp=0, fn=1, recall=0.0
    assert "CWE-79" in breakdown
    assert breakdown["CWE-79"]["total"] == 1
    assert breakdown["CWE-79"]["tp"] == 0
    assert breakdown["CWE-79"]["fn"] == 1
    assert breakdown["CWE-79"]["recall"] == 0.0


def test_evaluate_single_scan_exact_vs_equivalent(temp_benchmark_dataset: Path, tmp_path: Path):
    """Verify CWE equivalence matching vs exact_cwe flag."""
    # Dataset label has CWE-798 (Hardcoded credential)
    # Finding reports CWE-259 (Hardcoded password), which is in CWE_EQUIVALENCE group with 798
    finding_equivalent = [
        {"file": "vuln_auth.py", "start_line": 1, "cwe": "CWE-259", "type": "HARDCODED_PASSWORD"}
    ]
    scan_file = tmp_path / "scan_cwe_test.json"
    scan_file.write_text(json.dumps({"findings": finding_equivalent}), encoding="utf-8")

    labels_data = json.loads((temp_benchmark_dataset / "labels.json").read_text(encoding="utf-8"))
    labels = [
        Label(file=l["file"], line=l["line"], cwe=l["cwe"], type=l["type"])
        for l in labels_data["labels"]
    ]

    # 1. With exact_cwe=False (default): CWE-259 matches CWE-798
    res_default = evaluate_single_scan(
        scan_path=scan_file,
        dataset_dir=temp_benchmark_dataset,
        labels=labels,
        dataset_meta=labels_data,
        exact_cwe=False,
    )
    assert res_default["metrics"]["tp"] == 1
    assert res_default["per_cwe"]["CWE-798"]["tp"] == 1

    # 2. With exact_cwe=True: CWE-259 does not match CWE-798
    res_exact = evaluate_single_scan(
        scan_path=scan_file,
        dataset_dir=temp_benchmark_dataset,
        labels=labels,
        dataset_meta=labels_data,
        exact_cwe=True,
    )
    assert res_exact["metrics"]["tp"] == 0
    assert res_exact["per_cwe"]["CWE-798"]["tp"] == 0


def test_evaluate_scans_end_to_end(temp_benchmark_dataset: Path, tmp_path: Path):
    """Verify full end-to-end evaluation with JSON export and reporting."""
    # Scan 1: Catches SQL and Traversal (2 TP), 1 Spurious on clean_sample.py (1 FP), Misses Auth (1 FN)
    scan1_data = {
        "findings": [
            {"file": "vuln_sql.py", "start_line": 1, "cwe": "CWE-89", "type": "SQL_INJECTION"},
            {"file": "vuln_traversal.py", "start_line": 1, "cwe": "CWE-22", "type": "PATH_TRAVERSAL"},
            {"file": "clean_sample.py", "start_line": 1, "cwe": "CWE-79", "type": "XSS"},
        ]
    }
    scan1_path = tmp_path / "scan1.json"
    scan1_path.write_text(json.dumps(scan1_data), encoding="utf-8")

    # Scan 2: Catches only SQL (1 TP, 2 FN)
    scan2_data = {
        "result": {
            "findings": [
                {"file": "vuln_sql.py", "start_line": 1, "cwe": "CWE-89", "type": "SQL_INJECTION"}
            ]
        }
    }
    scan2_path = tmp_path / "scan2.json"
    scan2_path.write_text(json.dumps(scan2_data), encoding="utf-8")

    json_export = tmp_path / "evaluation_report.json"

    result = evaluate_scans(
        scan_paths=[scan1_path, scan2_path],
        dataset=temp_benchmark_dataset,
        exact_cwe=False,
        json_out=json_export,
        detailed=True,
        print_output=True,
    )

    assert result["dataset"] == "Mock Benchmark Dataset"
    assert result["total_ground_truth"] == 3
    assert len(result["scans"]) == 2

    # Verify Scan 1
    s1 = result["scans"][0]
    assert s1["metrics"]["tp"] == 2
    assert s1["metrics"]["fp"] == 1
    assert s1["metrics"]["fn"] == 1
    assert round(s1["metrics"]["precision"], 4) == round(2 / 3, 4)
    assert round(s1["metrics"]["recall"], 4) == round(2 / 3, 4)

    # Verify Scan 2
    s2 = result["scans"][1]
    assert s2["metrics"]["tp"] == 1
    assert s2["metrics"]["fp"] == 0
    assert s2["metrics"]["fn"] == 2
    assert s2["metrics"]["precision"] == 1.0
    assert round(s2["metrics"]["recall"], 4) == round(1 / 3, 4)

    # Verify JSON export
    assert json_export.is_file()
    exported = json.loads(json_export.read_text(encoding="utf-8"))
    assert exported["dataset"] == "Mock Benchmark Dataset"
    assert len(exported["scans"]) == 2


def test_resolve_dataset_dir(temp_benchmark_dataset: Path):
    """Verify dataset directory resolution logic."""
    # Direct path
    assert resolve_dataset_dir(temp_benchmark_dataset) == temp_benchmark_dataset.resolve()

    # Built-in benchmark100 resolution
    b100 = resolve_dataset_dir("benchmark100")
    assert b100.is_dir()
    assert (b100 / "labels.json").is_file()


def test_render_tables(temp_benchmark_dataset: Path, tmp_path: Path):
    """Verify ASCII table rendering functions produce expected headers and content."""
    scan_data = {
        "findings": [
            {"file": "vuln_sql.py", "start_line": 1, "cwe": "CWE-89", "type": "SQL_INJECTION"}
        ]
    }
    scan_file = tmp_path / "table_test.json"
    scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

    res = evaluate_scans(
        scan_paths=[scan_file],
        dataset=temp_benchmark_dataset,
        print_output=False,
    )

    summary_str = render_summary_table(res["scans"], "Mock Dataset", 3, False)
    assert "BENCHMARK QUANTITATIVE EVALUATION SUMMARY" in summary_str
    assert "table_test" in summary_str

    detailed_str = render_detailed_cwe_table(res["scans"][0])
    assert "DETAILED PER-CWE BREAKDOWN" in detailed_str
    assert "CWE-89" in detailed_str
    assert "TOTAL" in detailed_str

    h2h_str = render_head_to_head_cwe_table(res["scans"])
    assert "HEAD-TO-HEAD PER-CWE RECALL COMPARISON" in h2h_str


def test_cli_integration_via_evaluate_scan(temp_benchmark_dataset: Path, tmp_path: Path):
    """Verify CLI interface of eval/evaluate_scan.py."""
    scan_data = {"findings": [{"file": "vuln_sql.py", "start_line": 1, "cwe": "CWE-89"}]}
    scan_file = tmp_path / "cli_test.json"
    scan_file.write_text(json.dumps(scan_data), encoding="utf-8")

    args = argparse.Namespace(
        scan=[str(scan_file)],
        dataset=str(temp_benchmark_dataset),
        exact_cwe=False,
        json_out=None,
        detailed=True,
    )

    exit_code = run_evaluation_cli(args)
    assert exit_code == EXIT_CLEAN


def test_cli_integration_via_src_cli(temp_benchmark_dataset: Path, tmp_path: Path):
    """Verify integration with main CLI: python -m src.cli benchmark score."""
    scan_data = {"findings": [{"file": "vuln_sql.py", "start_line": 1, "cwe": "CWE-89"}]}
    scan_file = tmp_path / "score_test.json"
    scan_file.write_text(json.dumps(scan_data), encoding="utf-8")
    json_out = tmp_path / "cli_out.json"

    argv = [
        "benchmark",
        "score",
        "--scan",
        str(scan_file),
        "--dataset",
        str(temp_benchmark_dataset),
        "--detailed",
        "--json",
        str(json_out),
    ]

    exit_code = cli_main(argv)
    assert exit_code == EXIT_CLEAN
    assert json_out.is_file()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["metrics"]["tp"] == 1


def test_error_handling_non_existent_scan():
    """Verify error handling on non-existent scan file."""
    args = argparse.Namespace(
        scan=["non_existent_scan_123.json"],
        dataset="benchmark100",
        exact_cwe=False,
        json_out=None,
        detailed=False,
    )
    exit_code = run_evaluation_cli(args)
    assert exit_code == EXIT_ERROR
