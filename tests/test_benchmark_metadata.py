"""Unit tests for Benchmark metadata standardization and enrichment."""

import json
from pathlib import Path
import pytest

from eval.run_eval import load_dataset
from eval.run_model_comparison import load_dataset_labels
from eval.enrich_benchmark_metadata import (
    BENCHMARK_CATEGORIES,
    classify_clean_control,
    detect_vulnerable_sink_and_dataflow,
    enrich_dataset,
    extract_category_from_code,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = ROOT / "eval" / "datasets" / "benchmark"
BENCHMARK100_DIR = ROOT / "eval" / "datasets" / "benchmark100"


@pytest.mark.parametrize("dataset_dir", [BENCHMARK_DIR, BENCHMARK100_DIR])
def test_labels_json_structure(dataset_dir: Path):
    """Verify labels.json meets all required schema and content specifications."""
    labels_path = dataset_dir / "labels.json"
    assert labels_path.is_file(), f"labels.json not found in {dataset_dir}"

    data = json.loads(labels_path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert "labels" in data
    assert "clean_files" in data
    assert len(data["labels"]) > 0
    assert len(data["clean_files"]) > 0

    samples_dir = dataset_dir / "samples"

    # 1. Check all vulnerable labels
    for entry in data["labels"]:
        assert "file" in entry and entry["file"].endswith(".py")
        assert (samples_dir / entry["file"]).is_file(), f"Sample {entry['file']} does not exist"
        assert isinstance(entry["line"], int) and entry["line"] > 0, f"Line must be > 0 for {entry['file']}"
        assert entry["cwe"].startswith("CWE-"), f"CWE must be standard format for {entry['file']}"
        assert entry["type"] != "", f"Type must not be empty for {entry['file']}"
        assert "sink_call" in entry and entry["sink_call"] != ""
        assert "note" in entry and entry["note"] != ""
        assert "explanation" in entry and entry["explanation"] != ""
        assert "without sanitization" in entry["explanation"] or "flows into" in entry["explanation"]

    # 2. Check all clean files
    for clean in data["clean_files"]:
        assert isinstance(clean, dict), f"Clean file entry must be a dictionary: {clean}"
        assert "file" in clean and clean["file"].endswith(".py")
        assert (samples_dir / clean["file"]).is_file(), f"Sample {clean['file']} does not exist"
        assert clean["cwe"].startswith("CWE-")
        assert clean["type"] != ""
        assert "defense_type" in clean and clean["defense_type"] != ""
        assert "safe_reason" in clean and clean["safe_reason"] != ""


@pytest.mark.parametrize("dataset_dir", [BENCHMARK_DIR, BENCHMARK100_DIR])
def test_load_dataset_compatibility(dataset_dir: Path):
    """Verify eval/run_eval.py load_dataset() runs without error and returns clean string paths."""
    labels, meta = load_dataset(dataset_dir)
    assert len(labels) > 0
    assert len(meta["clean_files"]) > 0

    for l in labels:
        assert l.line > 0
        assert l.cwe != ""
        assert not l.cwe.startswith("CWE-")  # stripped to integer CWE in run_eval.py
        assert l.file.endswith(".py")

    for f in meta["clean_files"]:
        assert isinstance(f, str), f"clean_files in meta must be strings, got {type(f)}"
        assert f.endswith(".py")

    assert "clean_file_controls" in meta
    assert len(meta["clean_file_controls"]) == len(meta["clean_files"])


@pytest.mark.parametrize("dataset_name", ["benchmark", "benchmark100"])
def test_load_model_comparison_compatibility(dataset_name: str):
    """Verify eval/run_model_comparison.py load_dataset_labels() handles enriched metadata."""
    labels, clean_files = load_dataset_labels(dataset_name)
    assert len(labels) > 0
    assert len(clean_files) > 0

    for cf in clean_files:
        assert isinstance(cf, str)
        assert cf.endswith(".py")


def test_sink_detection_and_classification_functions():
    """Verify individual detection and classification functions on sample files."""
    sample_vuln = BENCHMARK_DIR / "samples" / "BenchmarkTest00001.py"
    sample_clean = BENCHMARK_DIR / "samples" / "BenchmarkTest00004.py"
    if not sample_vuln.is_file() or not sample_clean.is_file():
        pytest.skip("Benchmark sample files not present on disk")

    vuln_info = detect_vulnerable_sink_and_dataflow(sample_vuln, "pathtraver")
    assert vuln_info["line"] == 47
    assert vuln_info["cwe"] == "CWE-22"
    assert vuln_info["type"] == "PATH_TRAVERSAL"
    assert vuln_info["sink_call"] == "codecs.open"
    assert "codecs.open" in vuln_info["explanation"]

    sample_clean = BENCHMARK_DIR / "samples" / "BenchmarkTest00004.py"
    clean_info = classify_clean_control(sample_clean, "pathtraver")
    assert clean_info["cwe"] == "CWE-22"
    assert clean_info["type"] == "PATH_TRAVERSAL"
    assert clean_info["defense_type"] == "dead_branch_constant_bypass"
    assert "safe_reason" in clean_info
