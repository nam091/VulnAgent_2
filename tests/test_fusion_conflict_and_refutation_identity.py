"""Regression tests for two ways a conclusion was lost during merging.

A. A conflict is a conflict on either axis, and on either tier path.

   A finding's conclusion is recorded twice: in the verification record's
   'verdict' and in assessment_status, and only one of the two is usually
   populated. The guards used to read one axis each, so a pair holding
   'confirmed' + 'unreviewed' against 'refuted' + no verification record looked
   like "one verdict and no opinion" and was folded: one finding claiming
   'refuted' with both tiers' evidence ids attached, the CONFIRMED tier's proof
   published under the opposite conclusion. fusion.verdicts_conflict is the one
   predicate now applied before the intra-tier collapse picks an anchor, before
   the cross-tier match hands a candidate to _combine, and before _absorb_into
   folds anything.

   The guard must not overreach: 'supported' next to 'uncertain', two
   'unreviewed', and two 'supported' findings all still describe the same sink
   once and still fold, or the report fills with duplicates of every agreement.

B. Refutation removes the finding it judged, not every finding with its
   fingerprint.

   vuln.id hashes file, type and the reported line, so two findings on one line
   with different traces - a proven flow and a mitigated one - share an id. The
   filter keyed on that id, so refuting the mitigated finding also deleted the
   CONFIRMED one from the report: a true positive lost to a fingerprint
   collision, with nothing in the report recording that it had existed.

All tests are offline: no network, no model call.
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
    Attach stored evidence ids so a merge that unions them is visible.

    Args:
        finding: The finding to label
        evidence_ids: Ids naming stored artifacts

    Returns:
        Vulnerability: The same object, labelled
    """

    finding.evidence_ids = list(evidence_ids)
    return finding


# --------------------------------------------------------------------------
# A - cross-tier pairing must refuse contradicting conclusions
# --------------------------------------------------------------------------


def test_fuse_blocks_conflict_when_verification_missing():
    """
    A: the CONFIRMED tier holds a verdict but no status; the LLM tier the
    opposite.

    `verification` is optional, so the rule tier's 'confirmed' met the LLM
    tier's 'refuted' as if only one side had an opinion of any kind and the pair
    was paired: _combine copied the LLM finding and unioned the rule tier's
    evidence into it. The report then carried one finding asserting 'refuted'
    while holding the proof of the opposite conclusion, and the rule tier's
    finding was gone.

    Two findings must survive, each with its own evidence.
    """
    confirmed = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.CONFIRMED, taint_path=_flow(1),
        ),
        ["conf-ev"],
    )
    confirmed.assessment_status = "unreviewed"
    confirmed.verification = {"verdict": "confirmed"}

    refuted = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=_flow(2),
        ),
        ["ref-ev"],
    )
    refuted.assessment_status = "refuted"
    refuted.verification = None

    result = fusion.fuse([confirmed], [refuted]).vulnerabilities

    assert len(result) == 2, "the contradicting pair was folded into one finding"

    evidence = sorted(sorted(v.evidence_ids) for v in result)
    assert evidence == [["conf-ev"], ["ref-ev"]], (
        f"evidence was mixed across opposite conclusions: {evidence}"
    )

    conclusions = sorted(
        (v.assessment_status, (v.verification or {}).get("verdict") or "none")
        for v in result
    )
    assert conclusions == [("refuted", "none"), ("unreviewed", "confirmed")]


# --------------------------------------------------------------------------
# A - the intra-tier collapse must refuse the same pair
# --------------------------------------------------------------------------


def test_deduplicate_tier_blocks_conflict():
    """
    A: the same pair, both findings from one tier.

    _deduplicate_tier picks an anchor by severity and description length before
    _absorb_into ever runs, and the anchor decided the pair was a duplicate. The
    conflict has to be tested before a candidate is chosen, not only inside the
    fold: picking one side is the decision under dispute.
    """
    refuted = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=_flow(1),
        ),
        ["ref-ev"],
    )
    refuted.assessment_status = "refuted"
    refuted.verification = None

    confirmed = _evidenced(
        make_vuln(
            file_path="app.py", start_line=10, context="",
            source=FindingSource.LLM, taint_path=_flow(1),
        ),
        ["conf-ev"],
    )
    confirmed.assessment_status = "unreviewed"
    confirmed.verification = {"verdict": "confirmed"}

    result = fusion.fuse([], [refuted, confirmed]).vulnerabilities

    assert len(result) == 2, "the intra-tier collapse folded a contradicting pair"

    evidence = sorted(sorted(v.evidence_ids) for v in result)
    assert evidence == [["conf-ev"], ["ref-ev"]], (
        f"evidence was mixed across opposite conclusions: {evidence}"
    )


# --------------------------------------------------------------------------
# A - the guard must not turn every agreement into two findings
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_a, status_b",
    [
        ("supported", "uncertain"),
        ("unreviewed", "unreviewed"),
        ("supported", "supported"),
        ("uncertain", "uncertain"),
    ],
)
def test_non_conflicting_pairs_still_merge(status_a: str, status_b: str):
    """
    A: pairs that hold no opposite conclusion still collapse.

    The guard fires only on exactly the two opposite values, so a weaker or
    equal pair on the same sink is one defect reported twice and must stay one
    finding. A guard that kept every pair apart would report each agreement
    twice and score the duplicate as a false positive.
    """
    first = make_vuln(
        file_path="app.py", start_line=10, context="",
        source=FindingSource.LLM, taint_path=_flow(1),
    )
    first.assessment_status = status_a
    first.verification = None

    second = make_vuln(
        file_path="app.py", start_line=10, context="",
        source=FindingSource.LLM, taint_path=_flow(1),
    )
    second.assessment_status = status_b
    second.verification = None

    result = fusion.fuse([], [first, second]).vulnerabilities

    assert len(result) == 1, (
        f"{status_a} + {status_b} on one sink was kept as two findings"
    )


@pytest.mark.parametrize(
    "status_a, status_b, verdict_a, verdict_b",
    [
        ("supported", "uncertain", None, None),
        ("unreviewed", "unreviewed", None, None),
        ("supported", "supported", {"verdict": "confirmed"}, {"verdict": "confirmed"}),
        ("unreviewed", "supported", None, {"verdict": "confirmed"}),
        ("uncertain", "unreviewed", {"verdict": "uncertain"}, None),
    ],
)
def test_verdicts_conflict_needs_exactly_opposite_values(
    status_a: str,
    status_b: str,
    verdict_a,
    verdict_b,
):
    """
    A: the predicate itself, on pairs that carry an opinion without contradicting.

    'confirmed' next to 'confirmed', a status with no verdict against one with a
    verdict, and two absent conclusions are all non-conflicting. Only the exact
    opposite pairs are, so the guard cannot be widened by a neighbouring status.
    """
    first = make_vuln(file_path="app.py", start_line=10, context="")
    first.assessment_status = status_a
    first.verification = verdict_a

    second = make_vuln(file_path="app.py", start_line=10, context="")
    second.assessment_status = status_b
    second.verification = verdict_b

    assert fusion.verdicts_conflict(first, second) is False
    assert fusion.verdicts_conflict(second, first) is False


def test_scanner_verdict_guard_delegates_to_fusion():
    """
    A: one definition, not two.

    analyzer.scanner runs its own post-verification merge and needs the same
    answer on the same pair. It kept a second copy of the logic, and the copy is
    what still folded a 'refuted' finding whose counterpart recorded only a
    verdict. The module-level function must now be the only implementation.
    """
    from analyzer import scanner as scanner_module

    pairs = [
        ("supported", {"verdict": "confirmed"}, "refuted", None),
        ("unreviewed", {"verdict": "confirmed"}, "refuted", None),
        ("supported", None, "refuted", {"verdict": "refuted"}),
        ("supported", None, "uncertain", None),
        ("unreviewed", None, "unreviewed", None),
        ("uncertain", {"verdict": "uncertain"}, "supported", None),
    ]

    for status_a, verification_a, status_b, verification_b in pairs:
        a = make_vuln(file_path="app.py", start_line=10, context="")
        a.assessment_status = status_a
        a.verification = verification_a
        b = make_vuln(file_path="app.py", start_line=10, context="")
        b.assessment_status = status_b
        b.verification = verification_b

        expected = fusion.verdicts_conflict(a, b)
        assert scanner_module._verdicts_conflict(a, b) is expected, (
            f"scanner disagreed with fusion on ({status_a}, {verification_a}) "
            f"vs ({status_b}, {verification_b})"
        )


# --------------------------------------------------------------------------
# B - refutation removes the finding it judged, not its fingerprint twins
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verification_does_not_drop_confirmed_with_same_fingerprint(tmp_path: Path):
    """
    B: two findings on one line, one proven and one mitigated, share an id.

    vuln.id hashes file, type and the reported line, so the proven flow and the
    mitigated one collide even though they are different dataflows reaching
    different sinks. Refutation tracked that id, so when the mitigated finding
    was refuted the filter deleted the CONFIRMED finding too: the report kept
    one refuted entry and lost the true positive it had already proven, with
    nothing left to show it had ever been found.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    options = ScanOptions(
        target=str(tmp_path),
        use_llm=False,
        use_semgrep=False,
        verify=True,
        verify_all=True,
    )
    scanner = Scanner(options=options)

    proven = make_vuln(
        file_path="app.py", start_line=10, context="",
        source=FindingSource.CONFIRMED, taint_path=_flow(1),
    )
    mitigated = make_vuln(
        file_path="app.py", start_line=10, context="",
        source=FindingSource.LLM, taint_path=_flow(2),
    )

    # The collision is the premise of this test, not an incidental detail: if
    # the two ids ever stop matching, this test verifies nothing.
    assert proven.id == mitigated.id, "fixture must reproduce the fingerprint collision"
    assert proven is not mitigated

    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[proven, mitigated],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    verdicts = {
        id(proven): Verdict(verdict="confirmed"),
        id(mitigated): Verdict(
            verdict="refuted",
            mitigating_control="value validated against a regex whitelist before use",
        ),
    }

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
        stats = await scanner._run_verification([report], tmp_path)

    assert any(v is proven for v in report.vulnerabilities), (
        "the confirmed finding was dropped because a different finding on the "
        "same line was refuted"
    )
    assert proven in report.vulnerabilities
    assert not any(v is proven for v in report.refuted_vulnerabilities)
    assert proven.assessment_status == "supported"

    assert any(v is mitigated for v in report.refuted_vulnerabilities)
    assert mitigated in report.refuted_vulnerabilities
    assert not any(v is mitigated for v in report.vulnerabilities)
    assert mitigated.assessment_status == "refuted"

    # Counting is unchanged: one candidate was refuted and one was dropped.
    assert stats["verify_confirmed"] == 1
    assert stats["verify_refuted"] == 1
    assert stats["verify_dropped"] == 1
