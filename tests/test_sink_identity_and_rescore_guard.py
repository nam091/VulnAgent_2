"""Regression tests for sink identity across both stages, and for one unsafe CLI.

The three defects covered here are design defects, not syntax bugs:

A. The intra-tier collapse inside fusion dropped one of two real sinks that sat
   within the old +/-LINE_WINDOW tolerance, before the post-verification merge
   ever saw it. Sink identity has to be the same predicate in both stages.

B. The post-verification merge only compared reported start lines when one side
   of a pair carried no trace, so a traced sink at line 17 never absorbed the
   same sink reported at line 17 by a tier that traced nothing.

C. ``scripts/rescore_history.py --frozen-from`` read a manifest and then wrote
   the new one to the same path, destroying the snapshot it was re-scoring and
   leaving the fresh manifest pointing ``frozen_from`` at itself.

Every test is offline and hermetic: no network, no model call, no scan.
"""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from analyzer import fusion
from analyzer.scanner import merge_duplicate_sinks
from models.vulnerability import VulnerabilityType
from tests.conftest import make_vuln

ROOT = Path(__file__).resolve().parents[1]
RESCORE_SCRIPT = ROOT / "scripts" / "rescore_history.py"


def _sink_flow(source_line: int, sink_line: int) -> list:
    return [
        {"step": 1, "kind": "source", "file": "app.py", "line": source_line},
        {"step": 2, "kind": "sink", "file": "app.py", "line": sink_line},
    ]


def _supported(vuln):
    vuln.assessment_status = "supported"
    return vuln


# --------------------------------------------------------------------------
# A - the intra-tier collapse must not merge two real sinks
# --------------------------------------------------------------------------


def test_fusion_keeps_two_real_sinks_in_one_tier():
    """
    A: two sinks seven lines apart survive fusion with their evidence.

    Each finding traced its own flow to its own sink step. The old rule merged
    any same-file, same-type pair inside the line window, so the second sink
    and its evidence id were deleted before the post-verification merge ran.
    """
    first = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 10)))
    first.evidence_ids = ["evidence-a"]

    second = _supported(make_vuln(file_path="app.py", start_line=17, taint_path=_sink_flow(5, 17)))
    second.evidence_ids = ["evidence-b"]

    merged = fusion.fuse([], [first, second]).vulnerabilities

    assert len(merged) == 2
    assert sorted(v.location.start_line for v in merged) == [10, 17]
    assert sorted(eid for v in merged for eid in v.evidence_ids) == ["evidence-a", "evidence-b"]


def test_fusion_keeps_two_real_sinks_at_the_same_reported_line():
    """
    A: a shared reported line is not identity when both sides traced a flow.

    Both reports opened at line 10, but the flows terminate at line 10 and line
    14 respectively: two sinks, two findings.
    """
    first = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 10)))
    second = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 14)))

    merged = fusion.fuse([], [first, second]).vulnerabilities

    assert len(merged) == 2
    assert sorted(fusion.sink_point(v)[1] for v in merged) == [10, 14]


def test_fusion_still_collapses_one_sink_reported_twice():
    """
    A: relaxing the collapse must not stop it from doing its job.

    One sink, one flow, two names for the same defect and two reported lines.
    This is the PATH_TRAVERSAL / INSECURE_FILE_READ case the collapse exists
    for, and it must still yield a single finding.
    """
    aliased = make_vuln(
        vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22",
        file_path="app.py", start_line=31, taint_path=_sink_flow(1, 31),
    )
    same = make_vuln(
        vuln_type=VulnerabilityType.INSECURE_FILE_READ, cwe_id="CWE-22",
        file_path="app.py", start_line=33, taint_path=_sink_flow(1, 31),
    )

    merged = fusion.fuse([], [aliased, same]).vulnerabilities

    assert len(merged) == 1


def test_fusion_collapses_traced_sink_and_untraced_report_of_it():
    """
    A: one side traced sink@31, the other reported line 31 without a trace.

    The traced sink step is the only exact location available, so it decides:
    one sink, one finding.
    """
    traced = make_vuln(file_path="app.py", start_line=20, taint_path=_sink_flow(1, 31))
    untraced = make_vuln(file_path="app.py", start_line=31)

    merged = fusion.fuse([], [traced, untraced]).vulnerabilities

    assert len(merged) == 1


def test_fusion_keeps_untraced_report_at_a_different_line_from_the_traced_sink():
    """
    A: the one-sided rule compares the traced sink step, not "any nearby line".

    The traced flow terminates at line 17 while the other report points at line
    10, so these are two different program points.
    """
    traced = make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 17))
    untraced = make_vuln(file_path="app.py", start_line=10)

    merged = fusion.fuse([], [traced, untraced]).vulnerabilities

    assert len(merged) == 2


# --------------------------------------------------------------------------
# B - a traced sink must absorb an untraced report of the same point
# --------------------------------------------------------------------------


def test_merge_matches_traced_sink_against_untraced_reported_line():
    """
    B: traced sink@17 plus an untraced report at line 17 is one finding.

    The old fallback compared the two reported start lines (10 vs 17), found
    them different, and kept two findings for one sink - one true positive and
    one false positive in the report.
    """
    traced = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 17)))
    traced.evidence_ids = ["evidence-traced"]

    untraced = _supported(make_vuln(file_path="app.py", start_line=17))
    untraced.evidence_ids = ["evidence-plain"]

    merged = merge_duplicate_sinks([traced, untraced])

    assert len(merged) == 1
    assert sorted(merged[0].evidence_ids) == ["evidence-plain", "evidence-traced"]
    assert merged[0].taint_path, "the surviving finding must keep the traced flow"


def test_merge_matches_untraced_report_first_regardless_of_input_order():
    """
    B: identity must not depend on which side of the pair is scanned first.
    """
    traced = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 17)))
    untraced = _supported(make_vuln(file_path="app.py", start_line=17))

    merged = merge_duplicate_sinks([untraced, traced])

    assert len(merged) == 1


def test_merge_keeps_untraced_report_at_a_line_the_traced_sink_does_not_name():
    """
    B: the new one-sided rule is still an identity proof, not a window.

    The trace terminates at line 17; the untraced report points at line 10.
    Keeping both is the safe direction - losing a real sink is not.
    """
    traced = _supported(make_vuln(file_path="app.py", start_line=10, taint_path=_sink_flow(1, 17)))
    untraced = _supported(make_vuln(file_path="app.py", start_line=10))

    merged = merge_duplicate_sinks([traced, untraced])

    assert len(merged) == 2


def test_merge_keeps_untraced_report_for_a_sink_in_another_file():
    """
    B: a cross-file flow's sink step does not name a point in this file.

    The trace runs in app.py and terminates in db.py:17. An untraced app.py:17
    finding is a different program point, whatever the line number says.
    """
    traced = _supported(make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 1},
            {"step": 2, "kind": "sink", "file": "db.py", "line": 17},
        ],
    ))
    untraced = _supported(make_vuln(file_path="app.py", start_line=17))

    merged = merge_duplicate_sinks([traced, untraced])

    assert len(merged) == 2


# --------------------------------------------------------------------------
# C - --frozen-from must never overwrite the manifest it reads
# --------------------------------------------------------------------------


def _write_frozen_manifest(directory: Path) -> Path:
    target = directory / "reports" / "rescored_history"
    target.mkdir(parents=True, exist_ok=True)
    manifest = target / "metrics_all.json"
    manifest.write_text(
        '{\n  "snapshot_at": "2026-01-01T00:00:00Z",\n'
        '  "inputs": {"job_file_sha256": {}}\n}\n',
        encoding="utf-8",
    )
    return manifest


def _run_rescore(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RESCORE_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        timeout=180,
    )


def test_frozen_from_that_resolves_to_the_output_manifest_is_refused(tmp_path: Path):
    """
    C: the source snapshot survives a run that would have overwritten it.

    ``--out`` is passed explicitly so the test never depends on the default
    directory of the checkout it runs in; it resolves to the same directory as
    ``--frozen-from``, which is the defect.
    """
    manifest = _write_frozen_manifest(tmp_path)
    before = hashlib.sha256(manifest.read_bytes()).hexdigest()

    result = _run_rescore(
        tmp_path,
        "--frozen-from", "reports/rescored_history/metrics_all.json",
        "--out", "reports/rescored_history",
    )

    after = hashlib.sha256(manifest.read_bytes()).hexdigest()

    assert result.returncode != 0, "a run that overwrites its own input must fail"
    assert "pass a different --out directory" in result.stderr
    assert "Traceback" not in result.stderr, "this must be a clean refusal, not a crash"
    assert before == after, "the frozen source manifest must be byte-identical"
    assert sorted(p.name for p in manifest.parent.iterdir()) == ["metrics_all.json"]


def test_frozen_from_with_a_distinct_out_directory_is_not_refused(tmp_path: Path):
    """
    C: the new guard must not block the intended use.

    The run proceeds past the guard and fails later for an unrelated reason
    (this fixture manifest records no job hashes), so the refusal message must
    be absent and the source manifest must still be untouched.
    """
    manifest = _write_frozen_manifest(tmp_path)
    before = hashlib.sha256(manifest.read_bytes()).hexdigest()

    result = _run_rescore(
        tmp_path,
        "--frozen-from", "reports/rescored_history/metrics_all.json",
        "--out", "reports/rescore_of_snapshot",
    )

    assert "pass a different --out directory" not in result.stderr
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == before
    assert not (tmp_path / "reports" / "rescore_of_snapshot").exists()


def test_out_directory_defaults_are_reported_in_usage(tmp_path: Path):
    """
    C: ``--out`` is a documented option, not a hidden one.
    """
    result = _run_rescore(tmp_path, "--help")

    assert result.returncode == 0
    assert "--out DIR" in result.stdout
    assert "default: reports/rescored_history" in result.stdout


@pytest.mark.parametrize("flag", ["--out", "--frozen-from"])
def test_rescore_cli_accepts_both_path_options_without_argument(flag: str, tmp_path: Path):
    """
    C: both path options require a value, so neither can silently fall back.
    """
    result = _run_rescore(tmp_path, flag)

    assert result.returncode != 0
    assert "expected one argument" in result.stderr
