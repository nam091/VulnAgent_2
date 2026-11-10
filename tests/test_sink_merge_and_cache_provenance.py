"""Regression tests for design defects, not syntax bugs.

A. Cross-tier matching must not weld two different sinks together. A rule sink
   at line 10 and an LLM sink at line 17 were paired on line distance alone,
   producing one CONFIRMED finding and deleting the rule tier's evidence with
   it. Identity is the traced sink point, the same predicate both merge stages
   already use.

B. Post-verification sink deduplication must run for every report, not only for
   reports that lost a finding to refutation. It also must compare findings
   that already carry a verdict: skipping them let one sink be reported twice
   (one true positive plus one false positive), which is a precision defect in
   the report for a defect that is not in the code.

C. A trace that names no sink names no sink point. 'source@app.py:17' is where
   the path starts, not where the data lands; read as a sink it welded a
   finding reported at line 10 onto a different finding reported at line 17.

D. The scan cache must not hand a fallback backend's analysis back as the
   configured model's analysis.

All tests are offline and hermetic: no network, no real model call.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from agent.verifier import Verdict, VerificationAgent
from analyzer import fusion
from analyzer.scanner import ScanOptions, Scanner, merge_duplicate_sinks
from evidence.store import EvidenceStore
from models.vulnerability import FindingSource, VulnerabilityReport, VulnerabilityType
from tests.conftest import make_vuln
from utils.ai_client import ANTHROPIC_MODEL, AIClient

# --------------------------------------------------------------------------
# Minimal OpenAI-shaped mocks for the verifier tool loop
# --------------------------------------------------------------------------


class _MockFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _MockToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = _MockFunction(name, arguments)


class _MockMessage:
    def __init__(self, content: str = None, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _MockChoice:
    def __init__(self, message: _MockMessage) -> None:
        self.message = message


class _MockResponse:
    def __init__(self, message: _MockMessage) -> None:
        self.choices = [_MockChoice(message)]
        self.usage = None


# --------------------------------------------------------------------------
# E - imported sanitizer must not promote "uncertain" to "refuted"
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_imported_unrelated_sanitizer_does_not_refute_uncertain(tmp_path: Path):
    """
    E: an unrelated sanitizer in an imported module must leave "uncertain" alone.

    ``app/views.py`` renders user input without escaping. The verifier reads
    ``utils/unrelated.py``, which does contain ``html.escape`` - but inside a
    helper that no call path reaches. That read is not evidence of a mitigating
    control for this sink, so the model's "uncertain" must survive: promoting it
    to "refuted" would delete a possible true CWE-79 on evidence nobody checked.
    """
    (tmp_path / "app").mkdir(parents=True)
    (tmp_path / "app" / "views.py").write_text(
        "from utils.unrelated import unrelated_helper\n"
        "\n"
        "\n"
        "def render_comment(req):\n"
        "    user_c = req.args.get('comment')\n"
        "    label = unrelated_helper('static')\n"
        "    return '<div>' + user_c + '</div>'\n",
        encoding="utf-8",
    )

    (tmp_path / "utils").mkdir(parents=True)
    (tmp_path / "utils" / "unrelated.py").write_text(
        "import html\n"
        "\n"
        "\n"
        "def unrelated_helper(value):\n"
        "    return html.escape(value)\n",
        encoding="utf-8",
    )

    store = EvidenceStore(tmp_path)
    snapshot = store.create_snapshot()

    verifier = VerificationAgent(
        client=MagicMock(),
        model="test-verifier-model",
        root=tmp_path,
        evidence_store=store,
        snapshot_id=snapshot.snapshot_id,
    )

    vuln = make_vuln(
        vuln_type=VulnerabilityType.CROSS_SITE_SCRIPTING,
        cwe_id="CWE-79",
        file_path="app/views.py",
        start_line=5,
        end_line=7,
    )

    turn_read_sink = _MockMessage(
        tool_calls=[
            _MockToolCall(
                call_id="call_read_views",
                name="read_lines",
                arguments=json.dumps({"path": "app/views.py", "start_line": 1, "end_line": 7}),
            )
        ]
    )
    turn_read_unrelated = _MockMessage(
        tool_calls=[
            _MockToolCall(
                call_id="call_read_unrelated",
                name="read_imported_symbol",
                arguments=json.dumps({"symbol_name": "unrelated_helper", "from_file": "app/views.py"}),
            )
        ]
    )
    turn_final = _MockMessage(
        content=json.dumps(
            {
                "verdict": "uncertain",
                "reason": "Cannot tell whether the template escapes the value.",
                "evidence_file": "",
                "evidence_line": 0,
            }
        )
    )

    verifier.client.chat.completions.create.side_effect = [
        _MockResponse(turn_read_sink),
        _MockResponse(turn_read_unrelated),
        _MockResponse(turn_final),
    ]

    verdict = await verifier.verify(vuln)

    # The sanitizer was found in the imported file, yet the verdict is untouched.
    symbol_reads = [r for r in verdict.successful_reads if r.get("tool") == "read_imported_symbol"]
    assert symbol_reads, "precondition: the imported module must have been read"

    assert verdict.verdict == "uncertain"
    assert verdict.refuted is False
    assert verdict.mitigating_control == ""
    assert verdict.evidence_file == ""


# --------------------------------------------------------------------------
# B - post-verification sink deduplication merges instead of skipping
# --------------------------------------------------------------------------


def _report_for(findings: List[Any], file_name: str = "app.py") -> VulnerabilityReport:
    report = VulnerabilityReport(
        file_name=file_name,
        vulnerabilities=list(findings),
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )
    report.calculate_summary()
    report.calculate_risk_score()
    return report


def test_merge_two_supported_findings_at_one_sink_yields_one():
    """
    B: two verifier-supported findings on the same sink are one finding.

    Both findings are upheld, same file, same type, and both traced the same
    flow, so their sink step names the same (file, line) even though the two
    reports opened their spans three lines apart. Leaving both in the report
    scores one sink as a true positive plus a false positive.
    """
    flow = [
        {"step": 1, "kind": "source", "file": "app.py", "line": 1},
        {"step": 2, "kind": "sink", "file": "app.py", "line": 10},
    ]
    strong = make_vuln(file_path="app.py", start_line=10, taint_path=[dict(s) for s in flow])
    strong.assessment_status = "supported"
    strong.confidence = 0.9

    weak = make_vuln(file_path="app.py", start_line=12, taint_path=[dict(s) for s in flow])
    weak.assessment_status = "supported"
    weak.confidence = 0.6

    merged = merge_duplicate_sinks([weak, strong])

    assert len(merged) == 1
    assert merged[0].id == strong.id
    assert merged[0].assessment_status == "supported"


def test_merge_two_uncertain_findings_at_one_sink_yields_one():
    """
    B: two deliberately-unsettled findings on the same sink are one finding.
    """
    flow = [
        {"step": 1, "kind": "source", "file": "app.py", "line": 5},
        {"step": 2, "kind": "sink", "file": "app.py", "line": 30},
    ]
    first = make_vuln(file_path="app.py", start_line=30, taint_path=[dict(s) for s in flow])
    first.assessment_status = "uncertain"

    second = make_vuln(file_path="app.py", start_line=34, taint_path=[dict(s) for s in flow])
    second.assessment_status = "uncertain"

    merged = merge_duplicate_sinks([first, second])

    assert len(merged) == 1
    assert merged[0].assessment_status == "uncertain"


def test_merge_keeps_two_distinct_sinks_seven_lines_apart_with_their_own_flows():
    """
    G: two real sinks seven lines apart are two findings, not one.

    Each finding traced its own flow to its own sink step. Proximity is not
    identity: merging them would delete a true positive together with the
    loser's taint path and evidence id.
    """
    first = make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 1},
            {"step": 2, "kind": "sink", "file": "app.py", "line": 10},
        ],
    )
    first.assessment_status = "supported"
    first.evidence_ids = ["evidence-a"]

    second = make_vuln(
        file_path="app.py", start_line=17,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 5},
            {"step": 2, "kind": "sink", "file": "app.py", "line": 17},
        ],
    )
    second.assessment_status = "supported"
    second.evidence_ids = ["evidence-b"]

    merged = merge_duplicate_sinks([first, second])

    assert len(merged) == 2
    assert {v.id for v in merged} == {first.id, second.id}
    kept_evidence = sorted(eid for v in merged for eid in v.evidence_ids)
    assert kept_evidence == ["evidence-a", "evidence-b"]
    kept_lines = sorted(v.location.start_line for v in merged)
    assert kept_lines == [10, 17]
    for kept in merged:
        assert len(kept.taint_path) == 2


def test_merge_one_proven_sink_keeps_same_line_findings_and_unions_evidence():
    """
    G: the same sink reported twice is still one finding, with every evidence id.

    Neither report traced a flow, so the only proof of identity available is an
    identical reported line. The survivor must carry both evidence ids: the
    artifacts behind the dropped id still exist and must stay reachable.
    """
    survivor = make_vuln(file_path="app.py", start_line=10)
    survivor.assessment_status = "supported"
    survivor.confidence = 0.9
    survivor.evidence_ids = ["evidence-keep"]

    duplicate = make_vuln(file_path="app.py", start_line=10)
    duplicate.assessment_status = "supported"
    duplicate.confidence = 0.6
    duplicate.evidence_ids = ["evidence-fold"]

    merged = merge_duplicate_sinks([duplicate, survivor])

    assert len(merged) == 1
    assert merged[0].id == survivor.id
    assert sorted(merged[0].evidence_ids) == ["evidence-fold", "evidence-keep"]


def test_merge_keeps_two_flows_that_reach_the_same_sink_step():
    """
    G: one sink point reached by two different traced flows is two findings.

    The sink step matches, but the source and the path to it do not, so these
    are two distinct data flows. Folding them would delete a flow no other
    field of the report records.
    """
    direct = make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 1},
            {"step": 2, "kind": "sink", "file": "app.py", "line": 10},
        ],
    )
    direct.assessment_status = "supported"

    forwarded = make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 5},
            {"step": 2, "kind": "propagation", "file": "app.py", "line": 7},
            {"step": 3, "kind": "sink", "file": "app.py", "line": 10},
        ],
    )
    forwarded.assessment_status = "supported"

    merged = merge_duplicate_sinks([direct, forwarded])

    assert len(merged) == 2
    assert {v.id for v in merged} == {direct.id, forwarded.id}


def test_merge_keeps_two_real_sinks_beyond_the_line_window():
    """
    B: findings at genuinely different sinks are both kept.
    """
    left = make_vuln(file_path="app.py", start_line=10)
    left.assessment_status = "supported"

    right = make_vuln(file_path="app.py", start_line=40)
    right.assessment_status = "supported"

    merged = merge_duplicate_sinks([left, right])

    assert len(merged) == 2
    assert {v.id for v in merged} == {left.id, right.id}


def test_merge_folds_evidence_of_the_dropped_finding_into_the_survivor():
    """
    B: merging must not lose enrichment only the duplicate carried.

    Both reports point at the same line, so the sink is proven the same; only
    the duplicate traced a flow and only it stored an evidence id.
    """
    survivor = make_vuln(file_path="app.py", start_line=10)
    survivor.assessment_status = "supported"
    survivor.confidence = 0.9

    duplicate = make_vuln(file_path="app.py", start_line=10)
    duplicate.confidence = 0.4
    # The fixture must name the sink the report points at: identity is the sink
    # step, so a trace that stops at the source (line 1) proves nothing about
    # line 10 and is not the same defect.
    duplicate.taint_path = [
        {"step": "source", "file": "app.py", "line": 1, "kind": "source"},
        {"step": "sink", "file": "app.py", "line": 10, "kind": "sink"},
    ]
    duplicate.corroborated = True
    duplicate.evidence_ids = ["evd-123"]

    merged = merge_duplicate_sinks([duplicate, survivor])

    assert len(merged) == 1
    kept = merged[0]
    assert kept.id == survivor.id
    assert kept.taint_path == duplicate.taint_path
    assert kept.corroborated is True
    assert kept.evidence_ids == ["evd-123"]


@pytest.mark.asyncio
async def test_run_verification_collapses_duplicate_supported_sink(tmp_path: Path):
    """
    B: end-to-end through Scanner._run_verification.

    Two findings are upheld by the verifier, which traced the same flow to the
    same sink for both, and an unrelated finding elsewhere in the file is
    refuted (which is what the verification pass routinely does). The report
    must end up with a single finding for that sink, not two.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    opts = ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=False, verify=True, verify_all=True)
    scanner = Scanner(options=opts)

    first = make_vuln(file_path="app.py", start_line=10)
    second = make_vuln(file_path="app.py", start_line=14)
    refuted = make_vuln(file_path="app.py", start_line=200)

    report = _report_for([first, second, refuted])

    traced = [
        {"step": 1, "kind": "source", "file": "app.py", "line": 2},
        {"step": 2, "kind": "sink", "file": "app.py", "line": 10},
    ]
    verdicts = {
        first.id: Verdict(verdict="confirmed", taint_path=[dict(step) for step in traced]),
        second.id: Verdict(verdict="confirmed", taint_path=[dict(step) for step in traced]),
        refuted.id: Verdict(verdict="refuted", mitigating_control="parameterised query used"),
    }

    async def mock_verify(vuln):
        return verdicts[vuln.id]

    with patch.object(type(scanner.analyzer.ai_client), "openai_client", new_callable=PropertyMock, return_value=MagicMock()), \
         patch("agent.verifier.VerificationAgent.__init__", return_value=None), \
         patch("agent.verifier.VerificationAgent.verify", side_effect=mock_verify), \
         patch.object(scanner, "_judge_chains", new_callable=AsyncMock) as mock_judge:
        mock_judge.return_value = {}
        await scanner._run_verification([report], tmp_path)

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].assessment_status == "supported"
    assert report.summary["total"] == 1
    assert refuted in report.refuted_vulnerabilities


# --------------------------------------------------------------------------
# D - cache provenance for fallback backends
# --------------------------------------------------------------------------


def _scanner(tmp_path: Path) -> Scanner:
    opts = ScanOptions(
        target=str(tmp_path),
        use_llm=True,
        use_cache=True,
        cache_dir=str(tmp_path / "cache"),
        model="gpt-4o",
    )
    return Scanner(options=opts)


def test_cache_key_separates_fallback_backend_from_configured_model(tmp_path: Path, monkeypatch):
    """
    D: the same file, analysed once by the configured model and once by the
    fallback backend, must not share a cache key.
    """
    monkeypatch.setenv("AI_PROVIDER", "openai")
    scanner = _scanner(tmp_path)
    content = "print('hello')\n"

    primary_key = scanner._cache_key(content)
    same_as_legacy_call = scanner._cache_key(content, served_by={"provider": "openai", "model": "gpt-4o"})
    fallback_key = scanner._cache_key(
        content, served_by={"provider": "anthropic", "model": ANTHROPIC_MODEL}
    )

    # A primary-backed response keys exactly as before the provenance stamp
    # existed, so upgrading does not invalidate an existing cache.
    assert primary_key == same_as_legacy_call
    assert fallback_key != primary_key


def test_fallback_result_is_not_served_as_the_configured_model(tmp_path: Path, monkeypatch):
    """
    D: a cached fallback analysis is never returned for the primary key.
    """
    monkeypatch.setenv("AI_PROVIDER", "openai")
    scanner = _scanner(tmp_path)
    content = "print('hello')\n"

    fallback_analysis = {
        "vulnerabilities": [],
        "_served_by": {"provider": "anthropic", "model": ANTHROPIC_MODEL},
    }
    scanner._cache_put(content, fallback_analysis)

    # The entry is retained under its own key (auditable), but the primary
    # lookup misses so the next run retries the configured backend.
    assert scanner._cache_get(content) is None

    fallback_path = scanner._cache_dir / (
        scanner._cache_key(content, served_by=fallback_analysis["_served_by"]) + ".json"
    )
    assert fallback_path.is_file()
    assert json.loads(fallback_path.read_text(encoding="utf-8"))["_served_by"]["provider"] == "anthropic"


def test_primary_result_still_round_trips_through_the_cache(tmp_path: Path, monkeypatch):
    """
    D: the provenance stamp must not break caching of primary-backend results.
    """
    monkeypatch.setenv("AI_PROVIDER", "openai")
    scanner = _scanner(tmp_path)
    content = "print('hello')\n"

    analysis = {"vulnerabilities": [], "_served_by": {"provider": "openai", "model": "gpt-4o"}}
    scanner._cache_put(content, analysis)

    assert scanner._cache_get(content) == analysis


@pytest.mark.asyncio
async def test_analyze_security_stamps_the_backend_that_served_it(monkeypatch):
    """
    D: analyze_security reports which backend produced the analysis.
    """
    monkeypatch.setenv("AI_PROVIDER", "openai")
    client = AIClient()
    valid = {"vulnerabilities": []}

    with patch.object(AIClient, "anthropic_client", new_callable=PropertyMock, return_value=MagicMock()), \
         patch.object(client, "_analyze_with_openai", new_callable=AsyncMock) as primary, \
         patch.object(client, "_analyze_with_anthropic", new_callable=AsyncMock) as fallback:
        primary.return_value = dict(valid)
        served = await client.analyze_security("prompt", model="gpt-4o")

        fallback.return_value = dict(valid)
        primary.side_effect = RuntimeError("upstream 500")
        forced = await client.analyze_security("prompt", model="gpt-4o")

    assert served["_served_by"] == {"provider": "openai", "model": "gpt-4o"}
    assert forced["_served_by"] == {"provider": "anthropic", "model": ANTHROPIC_MODEL}
    assert forced["_served_by"] != served["_served_by"]


# --------------------------------------------------------------------------
# A - cross-tier matching may not weld two different sinks together
# --------------------------------------------------------------------------


def _flow(source_line: int, sink_line: int, kind: str = "sink") -> List[dict]:
    return [
        {"step": 1, "kind": "source", "file": "app.py", "line": source_line},
        {"step": 2, "kind": kind, "file": "app.py", "line": sink_line},
    ]


def test_cross_tier_distinct_sinks_stay_two_findings_with_their_evidence():
    """
    A: a rule sink at line 10 and an LLM sink at line 17 are two defects.

    Distance alone matched them, produced one CONFIRMED finding, and dropped
    the rule tier's evidence id with the finding it belonged to. Identity is
    the traced sink point, so neither finding may absorb the other.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
        taint_path=_flow(2, 10),
    )
    rule.evidence_ids = ["rule-evidence"]

    llm = make_vuln(
        file_path="app.py", start_line=17, source=FindingSource.LLM,
        taint_path=_flow(5, 17),
    )
    llm.evidence_ids = ["llm-evidence"]

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 2
    assert sorted(eid for v in merged for eid in v.evidence_ids) == [
        "llm-evidence", "rule-evidence",
    ]
    assert sorted(v.location.start_line for v in merged) == [10, 17]
    assert {v.source for v in merged} == {FindingSource.SEMGREP, FindingSource.LLM}


def test_cross_tier_same_sink_step_is_one_finding_with_unioned_evidence():
    """
    A (no regression): the same traced sink reached by the same flow is one
    sink reported twice, so tier agreement still produces one CONFIRMED
    finding carrying both tiers' evidence ids.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
        taint_path=_flow(2, 10),
    )
    rule.evidence_ids = ["rule-evidence"]

    llm = make_vuln(
        file_path="app.py", start_line=12, source=FindingSource.LLM,
        taint_path=_flow(2, 10),
    )
    llm.evidence_ids = ["llm-evidence"]

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].source == FindingSource.CONFIRMED
    assert merged[0].location.start_line == 10
    assert sorted(merged[0].evidence_ids) == ["llm-evidence", "rule-evidence"]


# --------------------------------------------------------------------------
# B - deduplication runs even when nothing was refuted
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_verification_dedups_with_zero_refutations(tmp_path: Path):
    """
    B: end-to-end, with no finding refuted at all.

    Both findings are upheld and traced to the same sink. With nothing
    refuted, the dedup and the summary refresh used to be skipped entirely, so
    the report kept two findings for one sink and a summary that said two.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    opts = ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=False, verify=True, verify_all=True)
    scanner = Scanner(options=opts)

    first = make_vuln(file_path="app.py", start_line=10)
    second = make_vuln(file_path="app.py", start_line=14)

    report = _report_for([first, second])

    traced = _flow(2, 10)
    verdicts = {
        first.id: Verdict(verdict="confirmed", taint_path=[dict(step) for step in traced]),
        second.id: Verdict(verdict="confirmed", taint_path=[dict(step) for step in traced]),
    }

    async def mock_verify(vuln):
        return verdicts[vuln.id]

    with patch.object(type(scanner.analyzer.ai_client), "openai_client", new_callable=PropertyMock, return_value=MagicMock()), \
         patch("agent.verifier.VerificationAgent.__init__", return_value=None), \
         patch("agent.verifier.VerificationAgent.verify", side_effect=mock_verify), \
         patch.object(scanner, "_judge_chains", new_callable=AsyncMock) as mock_judge:
        mock_judge.return_value = {}
        await scanner._run_verification([report], tmp_path)

    assert report.refuted_vulnerabilities == []
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].assessment_status == "supported"
    assert report.summary["total"] == 1
    assert report.risk_score is not None


# --------------------------------------------------------------------------
# C - a trace that names no sink names no sink point
# --------------------------------------------------------------------------


def test_source_only_trace_is_not_a_sink_point():
    """
    C: 'source@app.py:17' is where the path starts, not where the data lands.

    Read as a sink point it named ('app.py', 17), which welded the finding that
    reported line 10 onto a different finding that merely reported line 17.
    With no sink step the finding is untraced, and untraced findings are the
    same sink only when they report the same line.
    """
    traced = make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[{"step": 1, "kind": "source", "file": "app.py", "line": 17}],
    )
    untraced = make_vuln(file_path="app.py", start_line=17)

    assert fusion.sink_point(traced) is None
    assert fusion.is_same_sink(traced, untraced) is False
    assert len(merge_duplicate_sinks([traced, untraced])) == 2


def test_imported_sink_step_names_the_sink():
    """
    C: the kinds that do declare a sink are honoured, cross-file included.
    """
    traced = make_vuln(
        file_path="app.py", start_line=10,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 2},
            {"step": 2, "kind": "imported_sink", "file": "db.py", "line": 17},
        ],
    )

    assert fusion.sink_point(traced) == ("db.py", 17)


@pytest.mark.parametrize(
    "taint_path",
    [
        None,
        [],
        "not-a-path-at-all",
        [None, "junk", 42],
        [{}],
        [{"kind": "source", "file": "app.py", "line": 17}],
        [{"kind": "sink"}],
        [{"kind": "sink", "file": "app.py"}],
        [{"kind": "sink", "line": 10}],
        [{"kind": "sink", "file": "app.py", "line": "10"}],
        [{"kind": "sink", "file": "app.py", "line": True}],
        [{"kind": "sink", "file": "app.py", "line": 0}],
        [{"kind": "sink", "file": "   ", "line": 10}],
        [{"kind": None, "file": "app.py", "line": 10}],
        [{"kind": "sink", "file": "app.py", "line": 10}, {"kind": "source", "file": "app.py", "line": 99}],
    ],
)
def test_sink_point_and_identity_survive_dirty_taint_paths(taint_path):
    """
    C: malformed taint data yields "sink not established", never an exception.

    Identity falling back to the reported line is the safe direction; raising
    in the merge stage would abort a whole report over one bad step.
    """
    dirty = make_vuln(file_path="app.py", start_line=10)
    dirty.taint_path = taint_path
    other = make_vuln(file_path="app.py", start_line=10)

    point = fusion.sink_point(dirty)

    if taint_path == [{"kind": "sink", "file": "app.py", "line": 10}, {"kind": "source", "file": "app.py", "line": 99}]:
        # The sink step is present and usable; a later non-sink step must not
        # displace it.
        assert point == ("app.py", 10)
    else:
        assert point is None

    assert isinstance(fusion.is_same_sink(dirty, other), bool)
    assert isinstance(len(merge_duplicate_sinks([dirty, other])), int)


# --------------------------------------------------------------------------
# A/C - matching must distinguish "no trace" from "a trace without a sink"
# --------------------------------------------------------------------------


def test_fuse_keeps_two_findings_when_one_trace_has_only_source():
    """
    A: a trace that stops at 'source@app.py:17' is not the absence of a trace.

    sink_point() reads no sink step there, so the finding was classified as
    untraced and the cross-tier window welded it onto a different finding
    reported at line 17. Two findings, two lines, two evidence ids.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.CONFIRMED,
        taint_path=[{"step": 1, "kind": "source", "file": "app.py", "line": 17}],
    )
    rule.evidence_ids = ["rule-evidence"]

    llm = make_vuln(file_path="app.py", start_line=17, source=FindingSource.LLM)
    llm.evidence_ids = ["llm-evidence"]

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 2
    assert sorted(v.location.start_line for v in merged) == [10, 17]
    assert sorted(eid for v in merged for eid in v.evidence_ids) == [
        "llm-evidence", "rule-evidence",
    ]
    assert {v.source for v in merged} == {FindingSource.SEMGREP, FindingSource.LLM}


# --------------------------------------------------------------------------
# B - intra-tier collapse folds evidence instead of dropping it
# --------------------------------------------------------------------------


def test_fuse_unions_evidence_for_identical_sink():
    """
    B: two reports of one sink are one finding, but both evidence ids survive.

    Collapsing the duplicate with a bare `continue` left the survivor holding
    only its own evidence id, orphaning the other stored artifact from the
    report.
    """
    first = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    first.evidence_ids = ["first-evidence"]

    second = make_vuln(
        file_path="app.py", start_line=30, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    second.evidence_ids = ["second-evidence"]

    merged = fusion.fuse([], [first, second]).vulnerabilities

    assert len(merged) == 1
    assert sorted(merged[0].evidence_ids) == ["first-evidence", "second-evidence"]


def test_fuse_still_matches_two_untraced_findings_by_window():
    """
    C (no regression): with no trace on either side the window still applies.

    tests/test_core.py pins this: refusing to match two untraced reports of one
    file and one type would turn every tier agreement into two findings on
    position noise alone.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
    )
    rule.evidence_ids = ["rule-evidence"]

    llm = make_vuln(file_path="app.py", start_line=12, source=FindingSource.LLM)
    llm.evidence_ids = ["llm-evidence"]

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].source == FindingSource.CONFIRMED
    assert merged[0].location.start_line == 10
    assert sorted(merged[0].evidence_ids) == ["llm-evidence", "rule-evidence"]


# --------------------------------------------------------------------------
# E - a cross-tier merge must not drop the tier's dataflow evidence
# --------------------------------------------------------------------------


def test_combine_preserves_rule_taint_path_when_llm_has_none():
    """
    E: the combination copied the LLM finding wholesale for its text.

    Text is prose and the LLM tier is the only one that writes it, so copying
    it is right. A trace is not prose: when the LLM traced nothing, the rule
    tier's path is the only record that data reaches this sink, and taking the
    LLM's empty path deleted it. One finding, both steps, both evidence ids.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.SEMGREP,
        taint_path=_flow(1, 10),
    )
    rule.evidence_ids = ["rule-proof"]

    llm = make_vuln(file_path="app.py", start_line=10, source=FindingSource.LLM)

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].source == FindingSource.CONFIRMED
    assert len(merged[0].taint_path) == 2
    assert [step["kind"] for step in merged[0].taint_path] == ["source", "sink"]
    assert merged[0].taint_path[-1]["line"] == 10
    assert "rule-proof" in merged[0].evidence_ids


def test_dedup_absorbs_higher_assessment_status():
    """
    E: folding moved 'verification' but not 'assessment_status'.

    The survivor kept 'unreviewed' next to the duplicate's 'confirmed'
    verification - a self-contradictory finding, and the post-verification
    deduplication keys on assessment_status. The stronger state wins.
    """
    unreviewed = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    unreviewed.assessment_status = "unreviewed"
    unreviewed.verification = {"verdict": "confirmed"}

    supported = make_vuln(
        file_path="app.py", start_line=30, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    supported.assessment_status = "supported"
    supported.verification = {"verdict": "confirmed"}

    merged = fusion.fuse([], [unreviewed, supported]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].assessment_status == "supported"
    assert merged[0].verification == {"verdict": "confirmed"}


def test_dedup_keeps_conflicting_verdicts_separate():
    """
    E: 'supported' and 'refuted' cannot both describe one sink.

    Collapsing them picked a survivor by sort order, which carries no evidence
    for either verdict. Both are kept so a reviewer sees the disagreement
    instead of a coin flip recorded as a finding.
    """
    supported = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    supported.assessment_status = "supported"

    refuted = make_vuln(
        file_path="app.py", start_line=30, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    refuted.assessment_status = "refuted"

    merged = fusion.fuse([], [supported, refuted]).vulnerabilities

    assert len(merged) == 2
    assert sorted(v.assessment_status for v in merged) == ["refuted", "supported"]
    assert sorted(v.location.start_line for v in merged) == [10, 30]


# --------------------------------------------------------------------------
# E - a cross-tier merge must not flatten two flows into one
# --------------------------------------------------------------------------


def test_combine_keeps_rule_trace_when_llm_trace_differs():
    """
    E: two tiers agreed on the sink while naming different sources.

    The LLM traced 'source@app.py:5 -> sink@app.py:10'; the rule tier traced
    'source@app.py:1' and stopped there. _combine copies the LLM finding for its
    text, so its path became the survivor's only path and the rule tier's origin
    left the report with no field recording it. Both origins are evidence: the
    sink is corroborated, and the two flows must both stay reachable.
    """
    rule = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.CONFIRMED,
        taint_path=[{"step": 1, "kind": "source", "file": "app.py", "line": 1}],
    )
    rule.evidence_ids = ["rule-proof"]

    llm = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=[
            {"step": 1, "kind": "source", "file": "app.py", "line": 5},
            {"step": 2, "kind": "sink", "file": "app.py", "line": 10},
        ],
    )

    merged = fusion.fuse([rule], [llm]).vulnerabilities

    assert len(merged) == 1
    assert merged[0].source == FindingSource.CONFIRMED
    assert "rule-proof" in merged[0].evidence_ids

    traced = [(step.get("kind"), step.get("line")) for step in merged[0].taint_path]
    traced.extend(
        (step.get("kind"), step.get("line"))
        for path in merged[0].alternate_taint_paths
        for step in path
    )

    # The rule tier's origin is still reachable from the merged finding.
    assert ("source", 1) in traced
    # ...and the LLM's flow reaching the sink was not displaced to make room.
    assert ("source", 5) in traced
    assert ("sink", 10) in traced


# --------------------------------------------------------------------------
# E - status and its verification record are one conclusion
# --------------------------------------------------------------------------


def test_absorb_moves_status_and_verification_together():
    """
    E: the fold raised 'unreviewed' to 'supported' but kept 'refuted'.

    The duplicate ranked higher, so its status won; the survivor's verification
    record stayed, producing a finding that claims verification upheld it while
    its own verdict says the opposite. Status and metadata are one conclusion
    and must reach the survivor together.
    """
    anchor = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    anchor.assessment_status = "unreviewed"
    anchor.verification = {"verdict": "refuted"}

    duplicate = make_vuln(
        file_path="app.py", start_line=30, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    duplicate.assessment_status = "supported"
    duplicate.verification = {"verdict": "confirmed"}

    merged = fusion.fuse([], [anchor, duplicate]).vulnerabilities

    for finding in merged:
        verdict = (finding.verification or {}).get("verdict")
        assert not (
            finding.assessment_status == "supported" and verdict == "refuted"
        ), "status and verification came from different sides of the fold"
        assert not (
            finding.assessment_status == "refuted" and verdict == "confirmed"
        ), "status and verification came from different sides of the fold"

    # Two exclusive verdicts are not folded at all (fail closed), and every
    # surviving finding remains internally consistent.
    assert len(merged) == 2
    assert sorted(
        (v.assessment_status, v.verification["verdict"]) for v in merged
    ) == [("supported", "confirmed"), ("unreviewed", "refuted")]


def test_absorb_keeps_two_when_verdicts_conflict():
    """
    E: verification said 'confirmed' on one report and 'refuted' on the other.

    assessment_status does not catch this pair - the fold would attach one
    tier's verdict to the other tier's evidence. Two exclusive statements about
    one sink stay two findings for review.
    """
    supported = make_vuln(
        file_path="app.py", start_line=10, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    supported.assessment_status = "supported"
    supported.verification = {"verdict": "confirmed"}

    refuted = make_vuln(
        file_path="app.py", start_line=30, source=FindingSource.LLM,
        taint_path=_flow(1, 10),
    )
    refuted.assessment_status = "refuted"
    refuted.verification = {"verdict": "refuted"}

    merged = fusion.fuse([], [supported, refuted]).vulnerabilities

    assert len(merged) == 2
    assert sorted(v.location.start_line for v in merged) == [10, 30]
    assert sorted(v.verification["verdict"] for v in merged) == [
        "confirmed", "refuted",
    ]
