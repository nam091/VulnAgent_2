"""Regression tests for four report-integrity defects in the merge and output stages.

A. The standard finding schema had no field for `alternate_taint_paths`, so
   every flow the fusion stage had deliberately preserved was dropped when the
   finding was serialised for the CLI and the API. The data survived inside
   `Vulnerability` and then stopped at the output boundary.

B. `_combine` overwrote `alternate_taint_paths` with the rule tier's flows
   instead of unioning them, so the LLM tier's own alternate flows disappeared
   from a cross-tier merge.

C. The post-verification merge in the scanner had no contradicting-verdict
   guard, so a finding the verifier refuted was folded into one it confirmed
   and its evidence ids were attached to the opposite conclusion.
   fusion._absorb_into already refuses that pair; this pass runs later.

D. With two contradicting findings kept side by side, the fusion sort key was
   equal on every component, so the output order followed the input order and
   the same scan serialised differently from run to run.

All tests are offline and hermetic: no network, no real model call.
"""

import logging
from types import SimpleNamespace
from typing import Any, Dict, List

from analyzer import fusion
from analyzer.scanner import merge_duplicate_sinks
from models.vulnerability import (
    FindingSource,
    StandardFindingOutput,
    StandardScanOutput,
)
from tests.conftest import make_vuln


def _flow(source_line: int, sink_line: int) -> List[Dict[str, Any]]:
    """
    Build a two-step flow from a source line to a sink line.

    Args:
        source_line: Line the data enters at
        sink_line: Line the data lands at

    Returns:
        List[Dict[str, Any]]: The steps
    """

    return [
        {"step": 1, "kind": "source", "file": "app.py", "line": source_line},
        {"step": 2, "kind": "sink", "file": "app.py", "line": sink_line},
    ]


def _traced_lines(finding) -> List[tuple]:
    """
    Collect every (kind, line) pair a finding still reports, primary or alternate.

    Args:
        finding: A Vulnerability

    Returns:
        List[tuple]: Reachable steps, with duplicates removed
    """

    paths = [finding.taint_path, *(finding.alternate_taint_paths or [])]
    return sorted(
        {
            (step.get("kind"), step.get("line"))
            for path in paths
            for step in path
            if isinstance(step, dict)
        }
    )


# --------------------------------------------------------------------------
# A - the standard output schema must carry the alternate flows
# --------------------------------------------------------------------------


def test_standard_output_serialises_alternate_taint_paths():
    """
    A: a finding's alternate flows must reach the serialised output.

    The fusion stage keeps a second flow reaching the same sink as evidence.
    The standard finding schema copied only `taint_path`, so the JSON the CLI
    and the API emit lost that flow while the internal model still held it.
    """
    vuln = make_vuln(
        file_path="app.py", start_line=10, taint_path=_flow(5, 10),
    )
    vuln.alternate_taint_paths = [_flow(1, 10)]

    serialised = StandardFindingOutput.from_vulnerability(vuln).model_dump()

    assert serialised["alternate_taint_paths"] is not None
    assert len(serialised["alternate_taint_paths"]) == 1
    steps = serialised["alternate_taint_paths"][0]
    assert [(step["kind"], step["line"]) for step in steps] == [
        ("source", 1), ("sink", 10),
    ]
    # Normalised the same way the primary flow is: same file handling, same
    # numeric step numbering, so a consumer can read both fields identically.
    assert [(step["step"], step["file"]) for step in steps] == [(1, "app.py"), (2, "app.py")]
    assert [step["step"] for step in serialised["taint_path"]] == [1, 2]


def test_standard_scan_output_keeps_alternate_taint_paths():
    """
    A: the whole-scan output inherits the field, per finding.

    `from_scan_result` builds each entry through `from_vulnerability`, so the
    flows must survive that second hop into the report body as well.
    """
    vuln = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    vuln.alternate_taint_paths = [_flow(1, 10)]

    result = SimpleNamespace(
        root=None,
        stats={},
        reports=[],
        vulnerabilities=[vuln],
        refuted_vulnerabilities=[],
        status="completed",
        degraded=False,
        coverage=None,
    )

    payload = StandardScanOutput.from_scan_result(result).model_dump()

    assert payload["findings"][0]["alternate_taint_paths"] is not None
    assert [
        (step["kind"], step["line"])
        for step in payload["findings"][0]["alternate_taint_paths"][0]
    ] == [("source", 1), ("sink", 10)]


def test_standard_output_omits_the_field_when_no_alternate_flow_exists():
    """
    A: "no second flow" is None, not a silently empty list.

    A consumer must be able to tell a finding with one flow from a payload whose
    field was never populated - the two mean different things to a reader of the
    report.
    """
    vuln = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))

    assert StandardFindingOutput.from_vulnerability(vuln).model_dump()[
        "alternate_taint_paths"
    ] is None


# --------------------------------------------------------------------------
# B - a cross-tier merge unions flows instead of overwriting them
# --------------------------------------------------------------------------


def test_combine_unions_alternate_taint_paths():
    """
    B: the rule tier's flow must not delete the LLM tier's alternate flow.

    The LLM traced 7 -> 10 and, separately, recorded 5 -> 10 as an alternate.
    The rule tier traced 1 and stopped. _combine copied the LLM finding for its
    text and then replaced `alternate_taint_paths` with the rule tier's path, so
    the LLM's own alternate flow left the report. Every flow reaching the sink
    is evidence; the merge unions them.
    """
    llm = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(5, 10),
    )
    llm.alternate_taint_paths = [_flow(7, 10)]

    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
        taint_path=[{"step": 1, "kind": "source", "file": "app.py", "line": 1}],
    )

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    finding = merged[0]
    assert finding.source == FindingSource.CONFIRMED

    # The LLM's richer flow stays primary.
    assert [(step.get("kind"), step.get("line")) for step in finding.taint_path] == [
        ("source", 5), ("sink", 10),
    ]

    reachable = [tuple(step) for step in _traced_lines(finding)]
    assert ("source", 1) in reachable, "the rule tier's origin was dropped"
    assert ("source", 7) in reachable, "the LLM tier's alternate flow was overwritten"
    assert ("source", 5) in reachable
    assert ("sink", 10) in reachable


def test_combine_does_not_duplicate_a_flow_both_tiers_traced():
    """
    B: the union is by flow signature, so agreement adds no duplicate entry.

    Both tiers traced the same flow. Keeping the LLM's alternate set untouched
    while appending the rule tier's identical path would list one flow twice.
    """
    llm = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(5, 10),
    )
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
        taint_path=_flow(5, 10),
    )

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].alternate_taint_paths == []


# --------------------------------------------------------------------------
# C - the post-verification merge must not fold contradicting verdicts
# --------------------------------------------------------------------------


def test_post_verification_merge_keeps_conflicting_verdicts():
    """
    C: 'confirmed' and 'refuted' on one sink stay two findings.

    merge_duplicate_sinks runs after verification. Without a verdict guard it
    picked the 'supported' survivor by sort order and folded the refuted
    finding's evidence ids into it, so a refutation became evidence for the
    opposite conclusion.
    """
    confirmed = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    confirmed.assessment_status = "supported"
    confirmed.verification = {"verdict": "confirmed"}
    confirmed.confidence = 0.9
    confirmed.evidence_ids = ["confirmed-evidence"]

    refuted = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    refuted.assessment_status = "refuted"
    refuted.verification = {"verdict": "refuted"}
    refuted.confidence = 0.4
    refuted.evidence_ids = ["refuted-evidence"]

    merged = merge_duplicate_sinks([confirmed, refuted])

    assert len(merged) == 2
    assert {v.id for v in merged} == {confirmed.id, refuted.id}

    by_verdict = {v.verification["verdict"]: v for v in merged}
    assert by_verdict["confirmed"].evidence_ids == ["confirmed-evidence"], (
        "the refuted finding's evidence was attached to the confirmed one"
    )
    assert by_verdict["refuted"].evidence_ids == ["refuted-evidence"]
    assert by_verdict["confirmed"].assessment_status == "supported"
    assert by_verdict["refuted"].assessment_status == "refuted"


def test_post_verification_merge_logs_the_refusal(caplog):
    """
    C: the refusal is visible in the log, not silent.

    Two findings left in one report for the same sink is a state a reviewer has
    to know about; a silent keep looks identical to two unrelated findings.
    """
    confirmed = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    confirmed.assessment_status = "supported"
    confirmed.verification = {"verdict": "confirmed"}

    refuted = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    refuted.assessment_status = "refuted"
    refuted.verification = {"verdict": "refuted"}

    with caplog.at_level(logging.WARNING, logger="analyzer.scanner"):
        merged = merge_duplicate_sinks([confirmed, refuted])

    assert len(merged) == 2
    assert any(
        "contradicting verification verdicts" in record.message.lower()
        for record in caplog.records
    )


def test_post_verification_merge_still_folds_agreeing_verdicts():
    """
    C (no regression): the guard is narrow - agreeing verdicts still merge.
    """
    first = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    first.assessment_status = "supported"
    first.verification = {"verdict": "confirmed"}
    first.confidence = 0.9
    first.evidence_ids = ["first-evidence"]

    second = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    second.assessment_status = "supported"
    second.verification = {"verdict": "confirmed"}
    second.confidence = 0.5
    second.evidence_ids = ["second-evidence"]

    merged = merge_duplicate_sinks([first, second])

    assert len(merged) == 1
    assert sorted(merged[0].evidence_ids) == ["first-evidence", "second-evidence"]


def test_post_verification_merge_unions_taint_paths():
    """
    B (second call site): the scanner's fold unions flows as fusion's does.

    A survivor that traced its own flow used to keep only that flow, and a
    survivor that already held alternates lost them to the duplicate's paths.
    """
    survivor = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    survivor.assessment_status = "supported"
    survivor.verification = {"verdict": "confirmed"}
    survivor.confidence = 0.9
    survivor.alternate_taint_paths = [_flow(7, 10)]

    # Same primary flow (so the pair is provably one sink and one flow), with an
    # alternate flow only the duplicate carried.
    duplicate = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    duplicate.assessment_status = "supported"
    duplicate.verification = {"verdict": "confirmed"}
    duplicate.confidence = 0.5
    duplicate.alternate_taint_paths = [_flow(1, 10)]

    merged = merge_duplicate_sinks([survivor, duplicate])

    assert len(merged) == 1
    reachable = {tuple(step) for step in _traced_lines(merged[0])}
    assert ("source", 5) in reachable
    assert ("source", 7) in reachable
    assert ("source", 1) in reachable


# --------------------------------------------------------------------------
# D - output order must not depend on input order
# --------------------------------------------------------------------------


def _verdict_pair() -> List[Any]:
    """
    Build two contradicting findings that tie on the pre-existing sort keys.

    Same severity, confidence, file and line, but different code snippets, so
    the two ids differ while the leading sort components are equal.

    Returns:
        List[Any]: (supported, refuted)
    """

    supported = make_vuln(
        file_path="app.py", start_line=10, taint_path=_flow(5, 10),
        context="cursor.execute(query_a)",
    )
    supported.assessment_status = "supported"
    supported.verification = {"verdict": "confirmed"}

    refuted = make_vuln(
        file_path="app.py", start_line=10, taint_path=_flow(5, 10),
        context="cursor.execute(query_b)",
    )
    refuted.assessment_status = "refuted"
    refuted.verification = {"verdict": "refuted"}

    return [supported, refuted]


def test_fuse_output_order_is_deterministic():
    """
    D: reversing the input must not reverse the output.

    Two findings kept side by side because their verdicts contradict each other
    tie on severity, confidence, file and line. A sort that stops there leaves
    their order to the order the input arrived in, so two runs over the same
    findings serialise differently.
    """
    supported, refuted = _verdict_pair()

    forward = fusion.fuse([], [supported, refuted]).vulnerabilities
    backward = fusion.fuse([], [refuted, supported]).vulnerabilities

    assert len(forward) == 2
    assert len(backward) == 2
    assert [v.id for v in forward] == [v.id for v in backward]

    # Determinism must not come from picking one verdict: both are still there.
    assert sorted(v.assessment_status for v in forward) == ["refuted", "supported"]


def test_merge_taint_paths_sorts_alternates_by_signature():
    """
    D: the alternate list itself is ordered by flow, not by arrival.

    The alternate flows are part of the serialised output, so their order has to
    be a function of the flows rather than of which finding was absorbed first.
    """
    first = _flow(7, 10)
    second = _flow(1, 10)

    forward = fusion.merge_taint_paths(_flow(5, 10), [], [first, second])
    backward = fusion.merge_taint_paths(_flow(5, 10), [], [second, first])

    assert forward == backward
    assert [
        [(step["kind"], step["line"]) for step in path] for path in forward[1]
    ] == [[("source", 1), ("sink", 10)], [("source", 7), ("sink", 10)]]


# --------------------------------------------------------------------------
# E - the guard must read assessment_status, not only verification.verdict
#
# The verdict guard in section C read only `verification["verdict"]`. A finding
# the verifier concluded on without writing that record - a rule-tier finding
# assessed straight to 'refuted' - read as holding no opinion, so
# {'confirmed', ''} missed CONTRADICTORY_VERDICTS and the refutation was folded
# into its 'confirmed' opposite, evidence ids and all. The guard now reads the
# assessment status too, in three steps: the verdict pair, the status pair, and
# the mixed case where one side's verdict contradicts the other side's status.
# --------------------------------------------------------------------------


def test_merge_blocks_conflict_when_one_verification_is_none():
    """
    E: a refuted finding without a verification record is still a refutation.

    `verification` is optional and the survivor is chosen by _sink_rank, which
    ranks 'supported' first. With the verdict-only guard the refuted side read
    as verdict "" , the pair was not a conflict, and its evidence id was folded
    into the confirmed finding.
    """
    confirmed = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    confirmed.assessment_status = "supported"
    confirmed.verification = {"verdict": "confirmed"}
    confirmed.confidence = 0.9
    confirmed.evidence_ids = ["conf-ev"]

    refuted = make_vuln(file_path="app.py", start_line=30, taint_path=_flow(5, 10))
    refuted.assessment_status = "refuted"
    refuted.verification = None
    refuted.confidence = 0.4
    refuted.evidence_ids = ["ref-ev"]

    merged = merge_duplicate_sinks([confirmed, refuted])

    assert len(merged) == 2
    assert {v.id for v in merged} == {confirmed.id, refuted.id}

    by_status = {v.assessment_status: v for v in merged}
    assert by_status["supported"].evidence_ids == ["conf-ev"], (
        "the refuted finding's evidence was attached to the supported one"
    )
    assert by_status["refuted"].evidence_ids == ["ref-ev"]
    assert by_status["refuted"].verification is None


def test_merge_still_folds_when_both_supported():
    """
    E (no regression): two 'supported' findings are one sink, not a conflict.

    Both axes agree, so the new status step must not fire and the fold must
    still union the evidence ids.
    """
    first = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    first.assessment_status = "supported"
    first.verification = {"verdict": "confirmed"}
    first.confidence = 0.9
    first.evidence_ids = ["first-evidence"]

    second = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    second.assessment_status = "supported"
    second.verification = {"verdict": "confirmed"}
    second.confidence = 0.5
    second.evidence_ids = ["second-evidence"]

    merged = merge_duplicate_sinks([first, second])

    assert len(merged) == 1
    assert merged[0].assessment_status == "supported"
    assert sorted(merged[0].evidence_ids) == ["first-evidence", "second-evidence"]


def test_merge_still_folds_when_both_unreviewed():
    """
    E (no regression): two unreviewed findings carry no conclusion to oppose.

    Neither side has an assessment to contradict, so the pair folds: refusing
    here would report one sink twice for no reason.
    """
    first = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    first.assessment_status = "unreviewed"
    first.verification = None
    first.confidence = 0.9
    first.evidence_ids = ["first-evidence"]

    second = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    second.assessment_status = "unreviewed"
    second.verification = None
    second.confidence = 0.5
    second.evidence_ids = ["second-evidence"]

    merged = merge_duplicate_sinks([first, second])

    assert len(merged) == 1
    assert merged[0].assessment_status == "unreviewed"
    assert sorted(merged[0].evidence_ids) == ["first-evidence", "second-evidence"]


def test_merge_blocks_confirmed_vs_refuted_status_mix():
    """
    E: the two axes are read against each other, not only side by side.

    One finding's verdict says 'confirmed' while the other's assessment says
    'refuted'. Neither pair is internally contradictory (the first status is
    'unreviewed' and the second has no verdict), yet the two conclusions are
    opposite, so folding them would file one under the other.
    """
    confirmed = make_vuln(file_path="app.py", start_line=10, taint_path=_flow(5, 10))
    confirmed.assessment_status = "unreviewed"
    confirmed.verification = {"verdict": "confirmed"}
    confirmed.confidence = 0.9
    confirmed.evidence_ids = ["conf-ev"]

    refuted = make_vuln(file_path="app.py", start_line=30, taint_path=_flow(5, 10))
    refuted.assessment_status = "refuted"
    refuted.verification = None
    refuted.confidence = 0.4
    refuted.evidence_ids = ["ref-ev"]

    merged = merge_duplicate_sinks([confirmed, refuted])

    assert len(merged) == 2
    assert {v.id for v in merged} == {confirmed.id, refuted.id}
    assert sorted(word for v in merged for word in v.evidence_ids) == ["conf-ev", "ref-ev"]
