"""Regression tests for three ways evidence was deleted after a disagreement.

A. Rule-tier suppression read "no match" as "the LLM did not confirm".

   _find_match returns None for two different situations: the LLM tier never
   described the sink, and the LLM tier described it while concluding the
   opposite. The suppression branch treated both as absence of confirmation and
   dropped the rule finding, so a finding that already carried confirming
   evidence was deleted because the other tier said otherwise - and the refusal
   to pair the two, which exists to keep both, was turned into a silent
   deletion. A contradicted rule finding is now kept beside its counterpart
   (fail closed); a rule finding with no counterpart at all is still suppressed.

B. The verifier's traced flow overwrote the AST tier's proven flow.

   `vuln.taint_path = verdict.taint_path` replaced a dataflow the static tier had
   verified with the verifier's own trace. Both are evidence about one sink and
   they routinely start from different origins, so the AST flow disappeared from
   the report with nothing recording it, while its evidence ids stayed behind
   naming an artifact no longer reachable from the finding.

C. Two refutations of one sink were counted as two refuted defects.

   The refuted list is deduplicated by identity of the sink and agreement of both
   conclusions, and the duplicate's evidence is folded into the survivor before
   it is dropped. Removal from `vulnerabilities` stays keyed on object identity,
   so a refuted finding never takes a fingerprint twin with it; `verify_dropped`
   counts findings actually removed, not distinct refuted defects.

All tests are offline and hermetic: no network, no real model call.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from agent.verifier import Verdict
from analyzer import fusion
from analyzer.scanner import ScanOptions, Scanner
from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilityReport,
    VulnerabilityType,
)
from tests.conftest import make_vuln

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _flow(source_line: int, sink_line: int = 10) -> List[Dict[str, Any]]:
    """
    Build a two-step trace reaching one sink.

    Args:
        source_line: Line the tainted value enters the program on
        sink_line: Line the data lands on

    Returns:
        List[Dict[str, Any]]: Source step followed by the sink step
    """

    return [
        {"step": 1, "kind": "source", "file": "app.py", "line": source_line},
        {"step": 2, "kind": "sink", "file": "app.py", "line": sink_line},
    ]


def _evidenced(finding: Vulnerability, evidence_ids: List[str]) -> Vulnerability:
    """
    Attach stored evidence ids so a deletion is visible in the output.

    Args:
        finding: The finding to label
        evidence_ids: Ids naming stored artifacts

    Returns:
        Vulnerability: The same object, labelled
    """

    finding.evidence_ids = list(evidence_ids)
    return finding


def _options(tmp_path: Path) -> ScanOptions:
    """
    Build scan options for a verification-only pass.

    Args:
        tmp_path: Scan root

    Returns:
        ScanOptions: Options that route every finding through verification
    """

    return ScanOptions(
        target=str(tmp_path),
        use_llm=False,
        use_semgrep=False,
        verify=True,
        verify_all=True,
    )


async def _run_verification_with(
    scanner: Scanner,
    report: VulnerabilityReport,
    verdicts: Dict[int, Verdict],
    root: Path,
) -> Dict[str, Any]:
    """
    Drive the verification pass with every model call replaced by a fixed verdict.

    Args:
        scanner: Scanner under test
        report: The single report to verify
        verdicts: Verdicts keyed by id(finding)
        root: Scan root

    Returns:
        Dict[str, Any]: The statistics the pass returned
    """

    async def mock_verify(vuln: Vulnerability) -> Verdict:
        return verdicts[id(vuln)]

    with patch.object(
        type(scanner.analyzer.ai_client),
        "openai_client",
        new_callable=PropertyMock,
        return_value=MagicMock(),
    ), patch("agent.verifier.VerificationAgent.__init__", return_value=None), patch(
        "agent.verifier.VerificationAgent.verify", side_effect=mock_verify
    ), patch.object(
        scanner, "_judge_chains", new_callable=AsyncMock
    ) as mock_judge:
        mock_judge.return_value = {}
        return await scanner._run_verification([report], root)


def _refuted_pair(sink_lines: tuple) -> List[Vulnerability]:
    """
    Build one refuted finding per given sink line.

    Each finding traces its own two-step flow to its own sink and carries a
    named mitigating control, which is what the refutation path requires before
    it will move a traced finding into the refuted bucket.

    Args:
        sink_lines: Sink lines, one finding per entry

    Returns:
        List[Vulnerability]: Refuted findings, one per sink line
    """

    return [
        make_vuln(
            file_path="app.py",
            start_line=sink_line,
            context="",
            source=FindingSource.LLM,
            # One source line throughout, so two findings built for the same
            # sink line are identical in fingerprint and in flow - the only
            # thing that separates them is their object identity.
            taint_path=_flow(1, sink_line),
        )
        for sink_line in sink_lines
    ]


# --------------------------------------------------------------------------
# A - suppression must not delete a finding the other tier contradicted
# --------------------------------------------------------------------------


def test_suppression_keeps_confirmed_finding_when_counterpart_refuted():
    """
    A: the reported pair, with suppression switched on.

    The rule finding carries a 'confirmed' verification record; the LLM finding
    on the same sink reports 'refuted'. _find_match refuses the pair, and the
    suppression branch used to read that refusal as "the LLM tier did not confirm
    this" and delete the rule finding together with its evidence id. Both must
    survive, unpaired.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=_flow(1),
        ),
        ["conf-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    llm = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=_flow(2),
        ),
        ["ref-ev"],
    )
    llm.assessment_status = "refuted"
    llm.verification = None

    result = fusion.fuse(
        [rule], [llm],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    assert len(result) == 2, (
        "suppression deleted a finding the LLM tier contradicted instead of "
        "publishing both sides of the disagreement"
    )

    # The premise of the defect: the rule finding is exactly the kind the
    # suppression branch drops when nothing contradicts it.
    assert fusion._is_reliable_rule_finding(rule) is False
    assert fusion._has_conflicting_counterpart(rule, [llm]) is True

    evidence = sorted(sorted(v.evidence_ids) for v in result)
    assert evidence == [["conf-ev"], ["ref-ev"]], (
        f"evidence carrying the confirming verdict was deleted: {evidence}"
    )

    # Kept, but still not paired: pairing would publish the rule tier's proof
    # under the LLM tier's opposite conclusion.
    assert all(v.source != FindingSource.CONFIRMED for v in result)
    kept = next(v for v in result if "conf-ev" in v.evidence_ids)
    assert kept.source == FindingSource.SEMGREP
    assert kept.verification == {"verdict": "confirmed"}


def test_suppression_still_drops_rule_when_no_counterpart_describes_the_sink():
    """
    A: the guard must not disable suppression itself.

    A rule finding the LLM tier never described has no counterpart, conflicting
    or otherwise, so the false-positive control still applies. Without this the
    fix for the pair above would have switched suppression off entirely.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=_flow(1),
        ),
        ["conf-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    unrelated = make_vuln(
        file_path="app.py",
        start_line=80,
        vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS,
        cwe_id="CWE-798",
        source=FindingSource.LLM,
    )

    assert fusion._has_conflicting_counterpart(rule, [unrelated]) is False

    result = fusion.fuse(
        [rule], [unrelated],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    assert [v.source for v in result] == [FindingSource.LLM], (
        "an unconfirmed rule finding with no counterpart survived suppression"
    )
    assert all("conf-ev" not in v.evidence_ids for v in result)


# --------------------------------------------------------------------------
# A - the exemption is about one sink, not about the file
# --------------------------------------------------------------------------


def test_suppression_not_exempted_by_counterpart_at_different_sink():
    """
    A: the LLM tier's opposite conclusion is on a different sink in the same
    file.

    The exemption asked only for the same file, a compatible type and a
    contradicting conclusion. It never asked whether the counterpart described
    *this* sink, so a refutation of an unrelated call eighty lines down exempted
    the rule finding from suppression: the rule tier's unconfirmed finding at
    line 10 survived on the strength of evidence about line 80. Same file is not
    same sink, and that gap is the false-positive inflation suppression exists
    to remove.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=_flow(1, 10),
        ),
        ["rule-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    elsewhere = _evidenced(
        make_vuln(
            file_path="app.py", start_line=80, context="",
            source=FindingSource.LLM,
        ),
        ["far-ev"],
    )
    elsewhere.assessment_status = "refuted"
    elsewhere.verification = {"verdict": "refuted"}

    # Premise of the defect: the pair conflicts on every axis the predicate
    # checked and fails only on sink identity.
    assert fusion.verdicts_conflict(rule, elsewhere) is True
    assert fusion._same_sink_point(rule, elsewhere) is False
    assert fusion._has_conflicting_counterpart(rule, [elsewhere]) is False

    result = fusion.fuse(
        [rule], [elsewhere],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    lines = [v.location.start_line for v in result]
    assert lines == [80], (
        f"a conclusion reached at another sink exempted the rule finding from "
        f"suppression: kept {lines}"
    )
    assert all("rule-ev" not in v.evidence_ids for v in result)


def test_suppression_exempted_by_counterpart_at_same_sink():
    """
    A: the guard added against that false positive must not re-open the round-11
    deletion.

    Both findings report line 10 and disagree, so the exemption applies on its
    original terms: two findings survive, unpaired, each keeping its own
    evidence.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=_flow(1, 10),
        ),
        ["conf-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    llm = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=_flow(2, 10),
        ),
        ["ref-ev"],
    )
    llm.assessment_status = "refuted"
    llm.verification = None

    assert fusion._same_sink_point(rule, llm) is True
    assert fusion.is_same_sink(rule, llm) is False, (
        "the fixture's two traces differ, which is what separates sink identity "
        "from finding identity"
    )
    assert fusion._has_conflicting_counterpart(rule, [llm]) is True

    result = fusion.fuse(
        [rule], [llm],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    assert len(result) == 2, (
        "a counterpart on the same sink no longer exempts the rule finding"
    )
    evidence = sorted(sorted(v.evidence_ids) for v in result)
    assert evidence == [["conf-ev"], ["ref-ev"]], (
        f"evidence was deleted or mixed: {evidence}"
    )


def test_suppression_still_suppresses_without_any_counterpart():
    """
    A: the base case, unchanged by the sink condition.

    The LLM tier holds no finding of this type anywhere in the file, so nothing
    contradicts the rule finding and nothing confirms it either. Suppression
    applies: the rule tier's unconfirmed finding goes, the LLM tier's stays.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=_flow(1, 10),
        ),
        ["rule-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    other_type = make_vuln(
        file_path="app.py", start_line=30,
        vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS, cwe_id="CWE-798",
        source=FindingSource.LLM,
    )
    other_type.assessment_status = "supported"
    other_type.verification = {"verdict": "confirmed"}

    assert fusion._has_conflicting_counterpart(rule, [other_type]) is False

    result = fusion.fuse(
        [rule], [other_type],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    lines = [v.location.start_line for v in result]
    assert lines == [30], (
        f"an unconfirmed rule finding with no counterpart survived: kept {lines}"
    )
    assert all("rule-ev" not in v.evidence_ids for v in result)


def test_suppression_exempted_when_both_untraced_at_same_line():
    """
    A: neither finding traced a flow and both report the same line.

    With no sink step on either side the reported start line is the only
    identity available (see is_same_sink), and equal lines with opposite
    conclusions is exactly the disagreement the exemption reports. Requiring a
    trace here would suppress a rule finding whose contradiction sits on its own
    line.
    """
    rule = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=[],
        ),
        ["conf-ev"],
    )
    rule.assessment_status = "unreviewed"
    rule.verification = {"verdict": "confirmed"}

    llm = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=[],
        ),
        ["ref-ev"],
    )
    llm.assessment_status = "refuted"
    llm.verification = None

    assert fusion.sink_point(rule) is None
    assert fusion.sink_point(llm) is None
    assert fusion._same_sink_point(rule, llm) is True
    assert fusion._has_conflicting_counterpart(rule, [llm]) is True

    result = fusion.fuse(
        [rule], [llm],
        suppress_unconfirmed_rules=True,
        file_analyzed_by_llm=True,
    ).vulnerabilities

    assert len(result) == 2, (
        "two untraced findings on one line with opposite conclusions lost the "
        "rule tier's confirming evidence"
    )
    evidence = sorted(sorted(v.evidence_ids) for v in result)
    assert evidence == [["conf-ev"], ["ref-ev"]], (
        f"evidence was deleted or mixed: {evidence}"
    )


# --------------------------------------------------------------------------
# B - a confirmed verdict must preserve the AST trace as an alternate flow
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verifier_confirmed_preserves_ast_taint_path_as_alternate(
    tmp_path: Path,
):
    """
    B: the AST tier proved source@1 -> sink@10, the verifier traced source@2 ->
    sink@10.

    The verdict's flow replaces the primary (it is the conclusion just reached),
    and the AST flow must survive as an alternate instead of vanishing while its
    evidence id still names a stored artifact. The two traces describe one sink
    reached by different data, so neither may be dropped.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    scanner = Scanner(options=_options(tmp_path))

    ast_flow = _flow(1, 10)
    verdict_flow = _flow(2, 10)

    finding = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.SEMGREP, taint_path=ast_flow,
        ),
        ["ast-proof"],
    )
    finding.corroborated = True

    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[finding],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    await _run_verification_with(
        scanner, report, {id(finding): Verdict(verdict="confirmed", taint_path=verdict_flow)}, tmp_path
    )

    assert finding.assessment_status == "supported"

    primary_lines = [(step["kind"], step["line"]) for step in finding.taint_path]
    assert primary_lines == [("source", 2), ("sink", 10)], (
        f"the verifier's flow must stay primary, got {primary_lines}"
    )

    alternate_lines = [
        [(step["kind"], step["line"]) for step in path]
        for path in (finding.alternate_taint_paths or [])
    ]
    assert alternate_lines == [[("source", 1), ("sink", 10)]], (
        f"the AST tier's proven flow was overwritten: {alternate_lines}"
    )
    assert "ast-proof" in finding.evidence_ids


@pytest.mark.asyncio
async def test_verifier_confirmed_without_flow_keeps_ast_flavour_of_the_trace(
    tmp_path: Path,
):
    """
    B: a confirmed verdict that traced nothing must leave the AST flow alone.

    The earlier guard for this case is kept: an empty verdict path is not a
    trace, so it may not erase the slice the static tier produced, and no
    alternate appears out of nothing.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    scanner = Scanner(options=_options(tmp_path))

    finding = make_vuln(
        file_path="app.py", start_line=10, context="",
        source=FindingSource.SEMGREP, taint_path=_flow(1, 10),
    )
    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[finding],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    await _run_verification_with(
        scanner, report, {id(finding): Verdict(verdict="confirmed")}, tmp_path
    )

    assert [(step["kind"], step["line"]) for step in finding.taint_path] == [
        ("source", 1), ("sink", 10),
    ]
    assert not finding.alternate_taint_paths


# --------------------------------------------------------------------------
# C - one refuted sink is one refuted defect
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_identical_refutations_are_deduplicated(tmp_path: Path):
    """
    C: two findings with the same fingerprint and the same trace, both refuted.

    They are one sink refuted twice, so the refuted list must hold one entry and
    calculate_summary must count one refuted defect. Removal from
    `vulnerabilities` stays keyed on identity, so both objects are still removed
    and verify_dropped reports the two findings the report actually lost.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    scanner = Scanner(options=_options(tmp_path))

    first, second = _refuted_pair((10, 10))
    assert first.id == second.id, "fixture must reproduce the fingerprint collision"
    assert first is not second
    assert fusion.is_same_sink(first, second) is True

    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[first, second],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    mitigating = "value validated against a regex whitelist before use"
    stats = await _run_verification_with(
        scanner,
        report,
        {
            id(first): Verdict(verdict="refuted", mitigating_control=mitigating),
            id(second): Verdict(verdict="refuted", mitigating_control=mitigating),
        },
        tmp_path,
    )

    assert len(report.refuted_vulnerabilities) == 1, (
        f"one refuted sink was counted as "
        f"{len(report.refuted_vulnerabilities)} refuted defects"
    )
    assert report.summary["refuted"] == 1
    assert report.summary["total"] == 0
    assert stats["verify_refuted"] == 2, "both findings were refuted"
    assert stats["verify_dropped"] == 2, (
        "verify_dropped counts findings removed from the report, so both "
        "fingerprint twins must be counted even though one refuted entry stands"
    )


@pytest.mark.asyncio
async def test_refutations_of_different_sinks_are_kept_separate(tmp_path: Path):
    """
    C: two refuted findings at two different sinks are two refuted defects.

    Deduplication is keyed on identity of the sink, not on the file or the
    fingerprint, so collapsing these would under-report the refuted tally.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    scanner = Scanner(options=_options(tmp_path))

    first, second = _refuted_pair((10, 20))
    assert fusion.is_same_sink(first, second) is False

    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[first, second],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    mitigating = "value validated against a regex whitelist before use"
    stats = await _run_verification_with(
        scanner,
        report,
        {
            id(first): Verdict(verdict="refuted", mitigating_control=mitigating),
            id(second): Verdict(verdict="refuted", mitigating_control=mitigating),
        },
        tmp_path,
    )

    assert len(report.refuted_vulnerabilities) == 2
    assert report.summary["refuted"] == 2
    assert stats["verify_dropped"] == 2
    assert report.vulnerabilities == []
