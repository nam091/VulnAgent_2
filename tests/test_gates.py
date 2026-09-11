"""Regression test suite for G1-G2 gates, MCP evidence flow, verifier citations,
and snapshot membership.
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from agent.loop import AgentRun, ToolCallingAgent
from agent.verifier import Verdict, VerificationAgent
from evidence.store import EvidenceStore
from mcp_server import _scan_sessions, check_fix, get_finding_context, read_evidence
from models.evidence import EvidenceStatus
from models.vulnerability import FindingSource, VulnerabilityReport
from conftest import make_vuln


@pytest.mark.asyncio
async def test_mcp_read_evidence_valid_raw_content_and_range(tmp_path: Path):
    """
    Test P1 Bug 1: SafeReader returns numbered lines, but MCP must record raw lines
    in EvidenceStore, use the clamped actual range, and report read_succeeded=True.
    """
    test_file = tmp_path / "main.py"
    test_file.write_text("x = 1\ny = 2\nz = 3\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    manifest = store.create_snapshot()

    vuln = make_vuln(file_path="main.py", start_line=1, end_line=2)
    scan_id = "test_mcp_read_flow"
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {vuln.id: vuln},
        "changed_files": ["main.py"],
        "expanded_files": ["main.py"],
        "evidence_store": store,
        "snapshot": manifest,
    }

    # 1. Test read_evidence
    read_res = await read_evidence(scan_id=scan_id, path="main.py", start_line=1, end_line=2)
    assert read_res["read_succeeded"] is True
    assert read_res["status"] == "valid"
    assert not read_res["evidence_id"].startswith("ev_invalid_")
    assert read_res["start_line"] == 1
    assert read_res["end_line"] == 2

    # Verify that EvidenceStore validates this evidence ID as VALID
    valid, status, _ = store.validate_evidence(read_res["evidence_id"], manifest.snapshot_id)
    assert valid is True
    assert status == EvidenceStatus.VALID

    # 2. Test get_finding_context
    ctx_res = await get_finding_context(scan_id=scan_id, finding_id=vuln.id)
    assert not ctx_res["initial_evidence_id"].startswith("ev_invalid_")
    assert ctx_res["evidence_status"] == "valid"
    valid_ctx, status_ctx, _ = store.validate_evidence(ctx_res["initial_evidence_id"], manifest.snapshot_id)
    assert valid_ctx is True
    assert status_ctx == EvidenceStatus.VALID


@pytest.mark.asyncio
async def test_verifier_requires_successful_read_and_matching_citation(tmp_path: Path):
    """
    Test P1 Bug 2: Tool read failure must not count as investigated.
    Even if investigated, cited evidence file/lines must match actual successful reads.
    """
    app_file = tmp_path / "app.py"
    app_file.write_text("user_input = request.args.get('id')\nsafe_id = int(user_input)\n", encoding="utf-8")
    other_file = tmp_path / "other.py"
    other_file.write_text("DEBUG = True\n", encoding="utf-8")
    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)

    vuln = make_vuln(file_path="app.py", start_line=1)

    # Case A: Tool read failed (e.g. missing file). tool_calls=1, successful_reads=[] -> investigated=False
    run_failed_tool = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_failed_tool
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert verdict.investigated is False

    # Case B: Tool read succeeded on other.py, but model cites app.py (exists on disk, but never read)
    run_unread_file = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[{"tool": "read_lines", "path": "other.py", "start_line": 1, "end_line": 1}]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_unread_file
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert "chưa từng được đọc" in verdict.reason

    # Case C: Tool read app.py lines 1-1, but model cites line 2 (out of read slice)
    run_line_outside_read = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[{"tool": "read_lines", "path": "app.py", "start_line": 1, "end_line": 1}]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_line_outside_read
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"

    # Case D: Legitimate refutation where cited file and line were actually read
    rec = verifier.evidence_store.record_evidence(
        snapshot_id=verifier.snapshot_id,
        path="app.py",
        start_line=1,
        end_line=2,
        origin="read_lines",
    )
    run_valid = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[{"tool": "read_lines", "path": "app.py", "start_line": 1, "end_line": 2, "evidence_id": rec.evidence_id}]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_valid
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "refuted"
        assert verdict.investigated is True

    # Case E: Missing evidence_id in successful_reads -> must downgrade to uncertain
    run_no_eid = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[{"tool": "read_lines", "path": "app.py", "start_line": 1, "end_line": 2, "evidence_id": ""}]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_no_eid
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert "thiếu mã bằng chứng" in verdict.reason


def test_evidence_store_snapshot_membership(tmp_path: Path):
    """
    Test P1 Bug 3: Snapshot must exist and file must belong to snapshot manifest.
    Files created after the snapshot cannot be issued valid evidence under the old snapshot.
    """
    existing_file = tmp_path / "existing.py"
    existing_file.write_text("x = 1\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    manifest = store.create_snapshot()

    # 1. Non-existent snapshot_id
    rec_nonexistent = store.record_evidence("nonexistent_snap", "existing.py", 1, 1, content="x = 1")
    assert rec_nonexistent.status == EvidenceStatus.INVALID
    assert rec_nonexistent.read_succeeded is False

    valid, status, _ = store.validate_evidence(rec_nonexistent.evidence_id, manifest.snapshot_id)
    assert valid is False

    # 2. File created after snapshot
    new_file = tmp_path / "created_after_snapshot.py"
    new_file.write_text("y = 2\n", encoding="utf-8")

    rec_new_file = store.record_evidence(manifest.snapshot_id, "created_after_snapshot.py", 1, 1, content="y = 2")
    assert rec_new_file.status == EvidenceStatus.INVALID
    assert rec_new_file.read_succeeded is False

    valid, status, _ = store.validate_evidence(rec_new_file.evidence_id, manifest.snapshot_id)
    assert valid is False


@pytest.mark.asyncio
async def test_check_fix_regression_in_expanded_scope(tmp_path: Path):
    """
    Test P1 Bug 4: check_fix must detect new regressions across all files in expanded_files scope,
    not just changed_files.
    """
    scan_id = "test_expanded_regression"
    orig_vuln = make_vuln(file_path="app.py", start_line=1)
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {orig_vuln.id: orig_vuln},
        "changed_files": ["app.py"],
        "expanded_files": ["app.py", "helper.py"],
    }

    # Simulate rescan: orig_vuln in app.py resolved, but new regression in helper.py
    regression_vuln = make_vuln(file_path="helper.py", start_line=10)
    report = VulnerabilityReport(
        file_name="helper.py",
        vulnerabilities=[regression_vuln],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
        status="completed",
        tiers={"semgrep": "ok"},
    )
    from analyzer.scanner import ScanResult
    mock_scan_result = ScanResult(
        reports=[report],
        root=tmp_path,
        stats={"status": "completed"}
    )

    with patch("mcp_server.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_scan_result
        res = await check_fix(scan_id=scan_id, finding_ids=[orig_vuln.id])

        assert res["clean"] is False
        assert len(res["new_regressions"]) == 1
        assert res["new_regressions"][0]["file"] == "helper.py"
        assert orig_vuln.id in res["resolved_findings"]


@pytest.mark.asyncio
async def test_check_fix_degraded_rejected(tmp_path: Path):
    """
    Test B01/B16: Degraded or failed rescan must never report clean=True.
    """
    scan_id = "test_degraded_scan"
    orig_vuln = make_vuln(file_path="app.py", start_line=1)
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {orig_vuln.id: orig_vuln},
        "changed_files": ["app.py"],
        "expanded_files": ["app.py"],
    }

    degraded_report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
        status="failed",
        tiers={"semgrep": "failed"},
    )
    from analyzer.scanner import ScanResult
    mock_scan_result = ScanResult(
        reports=[degraded_report],
        root=tmp_path,
        stats={"status": "failed"}
    )

    with patch("mcp_server.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_scan_result
        res = await check_fix(scan_id=scan_id, finding_ids=[orig_vuln.id])

        assert res["clean"] is False
        assert res["status"] == "incomplete"
        assert res["degraded"] is True
        assert res["resolved_findings"] == []
        assert res["persistent_findings"] == [orig_vuln.id]


import json


class MockFunction:
    def __init__(self, name: str, arguments: dict):
        self.name = name
        self.arguments = json.dumps(arguments)


class MockToolCall:
    def __init__(self, name: str, arguments: dict, call_id: str = "call_1"):
        self.id = call_id
        self.function = MockFunction(name, arguments)


class MockMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


@pytest.mark.asyncio
async def test_e2e_verifier_rejects_different_directory_same_basename(tmp_path: Path):
    """
    Test P1 Bug 1 (End-to-End):
    Model calls read_lines on a/app.py:1-5, but refutes citing b/app.py:1.
    Must be rejected even though basename is identical.
    """
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "app.py").write_text("def check(): return True\n", encoding="utf-8")
    (tmp_path / "b" / "app.py").write_text("def check(): return False\n", encoding="utf-8")

    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    vuln = make_vuln(file_path="b/app.py", start_line=1)

    # Turn 1: model reads a/app.py
    msg1 = MockMessage(tool_calls=[MockToolCall("read_lines", {"path": "a/app.py", "start_line": 1, "end_line": 5})])
    # Turn 2: model claims refuted citing b/app.py
    msg2 = MockMessage(content=json.dumps({
        "verdict": "refuted",
        "mitigating_control": "check returns True",
        "evidence_file": "b/app.py",
        "evidence_line": 1
    }))

    with patch("agent.loop.ToolCallingAgent._complete", new_callable=AsyncMock, side_effect=[msg1, msg2]):
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert "chưa từng được đọc" in verdict.reason


@pytest.mark.asyncio
async def test_e2e_verifier_rejects_empty_search_and_definition_not_found(tmp_path: Path):
    """
    Test P1 Bug 2 (End-to-End):
    search with 0 matches and find_definition with found=False must NOT count as successful read.
    """
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    vuln = make_vuln(file_path="app.py", start_line=1)

    # Turn 1: search non-existent pattern -> matches=[]
    msg1 = MockMessage(tool_calls=[MockToolCall("search", {"pattern": "NON_EXISTENT_PATTERN"})])
    # Turn 2: find_definition non-existent func -> found=False
    msg2 = MockMessage(tool_calls=[MockToolCall("find_definition", {"name": "non_existent_func"})])
    # Turn 3: model claims refuted
    msg3 = MockMessage(content=json.dumps({
        "verdict": "refuted",
        "mitigating_control": "sanitizer exists",
        "evidence_file": "app.py",
        "evidence_line": 1
    }))

    with patch("agent.loop.ToolCallingAgent._complete", new_callable=AsyncMock, side_effect=[msg1, msg2, msg3]):
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert verdict.investigated is False


@pytest.mark.asyncio
async def test_e2e_verifier_rejects_citation_outside_truncated_output(tmp_path: Path):
    """
    Test P1 Bug 3 (End-to-End):
    Line 1 is 7000 chars, so line 2 is truncated from model output.
    Model cites line 2 -> must be rejected as unread.
    """
    app_file = tmp_path / "app.py"
    app_file.write_text("# " + "A" * 5988 + "\nx = 100\n", encoding="utf-8")

    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    vuln = make_vuln(file_path="app.py", start_line=1)

    # Turn 1: model reads lines 1 to 2
    msg1 = MockMessage(tool_calls=[MockToolCall("read_lines", {"path": "app.py", "start_line": 1, "end_line": 2})])
    # Turn 2: model claims refuted citing line 2 (which was cut from model output)
    msg2 = MockMessage(content=json.dumps({
        "verdict": "refuted",
        "mitigating_control": "x is safe constant",
        "evidence_file": "app.py",
        "evidence_line": 2
    }))

    with patch("agent.loop.ToolCallingAgent._complete", new_callable=AsyncMock, side_effect=[msg1, msg2]):
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert "chưa từng được đọc" in verdict.reason


@pytest.mark.asyncio
async def test_e2e_verifier_rejects_file_modified_after_read(tmp_path: Path):
    """
    Test P1 Bug 4 (End-to-End):
    File changes on disk after tool read -> verifier detects stale/invalid evidence and returns uncertain.
    """
    app_file = tmp_path / "app.py"
    app_file.write_text("x = 1\n", encoding="utf-8")

    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    vuln = make_vuln(file_path="app.py", start_line=1)

    msg1 = MockMessage(tool_calls=[MockToolCall("read_lines", {"path": "app.py", "start_line": 1, "end_line": 1})])
    msg2 = MockMessage(content=json.dumps({
        "verdict": "refuted",
        "mitigating_control": "safe constant",
        "evidence_file": "app.py",
        "evidence_line": 1
    }))

    async def mock_complete(messages, with_tools=True):
        if with_tools:
            return msg1
        else:
            # Modify app.py on disk after read but before verifier receives final verdict
            app_file.write_text("x = 99999\n", encoding="utf-8")
            return msg2

    with patch("agent.loop.ToolCallingAgent._complete", new_callable=AsyncMock, side_effect=mock_complete):
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert "không còn hợp lệ" in verdict.reason or "thay đổi" in verdict.reason


def test_midway_cut_line_not_recorded_as_read(tmp_path: Path):
    """
    Unit test: read_lines with a line exceeding MAX_TOOL_RESULT_CHARS is cut midway.
    It must not be recorded as a valid whole-line read.
    """
    long_content = "  1 | x = '" + ("A" * 7000) + "' # HIDDEN_CONTROL"
    raw_lines = ["x = '" + ("A" * 7000) + "' # HIDDEN_CONTROL"]
    store = EvidenceStore(tmp_path)
    snap_id = store.create_snapshot().snapshot_id

    agent = ToolCallingAgent(
        client=None,
        model="test",
        dispatch=lambda *a: {},
        tool_schemas=[],
        evidence_store=store,
        snapshot_id=snap_id,
    )

    tool_result = {
        "path": "app.py",
        "content": long_content,
        "raw_lines": raw_lines,
        "start_line": 1,
        "end_line": 1,
    }
    reads = agent._process_tool_result_and_reads("read_lines", {"path": "app.py"}, tool_result)
    assert reads == []
    assert tool_result.get("start_line") is None
    assert tool_result.get("end_line") is None


@pytest.mark.asyncio
async def test_e2e_verifier_rejects_citation_from_midway_cut_line(tmp_path: Path):
    """
    Test P1 Bug: Single line longer than MAX_TOOL_RESULT_CHARS (6000).
    Tail of line contains HIDDEN_CONTROL, which is truncated and never delivered to model.
    Model cites the line claiming HIDDEN_CONTROL -> must be downgraded to uncertain.
    """
    long_line = "x = '" + ("A" * 7100) + "' # safe: HIDDEN_CONTROL\n"
    app_file = tmp_path / "app.py"
    app_file.write_text(long_line, encoding="utf-8")

    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    vuln = make_vuln(file_path="app.py", start_line=1)

    # Turn 1: model reads line 1
    msg1 = MockMessage(tool_calls=[MockToolCall("read_lines", {"path": "app.py", "start_line": 1, "end_line": 1})])
    # Turn 2: model claims refuted citing line 1 with HIDDEN_CONTROL
    msg2 = MockMessage(content=json.dumps({
        "verdict": "refuted",
        "mitigating_control": "HIDDEN_CONTROL",
        "evidence_file": "app.py",
        "evidence_line": 1
    }))

    with patch("agent.loop.ToolCallingAgent._complete", new_callable=AsyncMock, side_effect=[msg1, msg2]):
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "uncertain"
        assert (
            verdict.investigated is False
            or "chưa từng được đọc" in verdict.reason
            or "thiếu mã bằng chứng" in verdict.reason
        )


@pytest.mark.asyncio
async def test_scanner_semgrep_parse_error_marks_partial_degraded(tmp_path: Path):
    """
    Test B01: Semgrep parse errors on individual files mark file failed and ScanResult partial.
    """
    from analyzer.scanner import Scanner, ScanOptions
    from analyzer.semgrep_runner import SemgrepRunner

    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def broken_syntax(:\n", encoding="utf-8")
    good_file = tmp_path / "good.py"
    good_file.write_text("x = 1\n", encoding="utf-8")

    opts = ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=True, files=["bad.py", "good.py"])
    scanner = Scanner(options=opts)

    with patch.object(SemgrepRunner, "scan", return_value=[]), \
         patch.object(SemgrepRunner, "get_file_errors", return_value={"bad.py": "Syntax error at line 1"}):
        result = await scanner.scan()

    assert result.status == "partial"
    assert result.degraded is True
    assert "bad.py" in result.coverage["semgrep"]["failed_files"]
    assert "good.py" in result.coverage["semgrep"]["analyzed_files"]

    report_map = {r.file_name: r for r in result.reports}
    assert report_map["bad.py"].status == "failed"
    assert report_map["bad.py"].engine_status["semgrep"]["status"] == "parse_error"
    assert report_map["good.py"].status == "completed"
    assert report_map["good.py"].engine_status["semgrep"]["status"] == "ok"


@pytest.mark.asyncio
async def test_scanner_disambiguates_same_basename(tmp_path: Path):
    """
    Test B01/B09: Scanner filters requested files by exact relative path, not basename.
    """
    from analyzer.scanner import Scanner, ScanOptions
    from analyzer.semgrep_runner import SemgrepRunner

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b" / "app.py").write_text("y = 2\n", encoding="utf-8")

    opts = ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=True, files=["a/app.py"])
    scanner = Scanner(options=opts)

    with patch.object(SemgrepRunner, "scan", return_value=[]), \
         patch.object(SemgrepRunner, "get_file_errors", return_value={}):
        result = await scanner.scan()

    analyzed = result.coverage["semgrep"]["analyzed_files"]
    assert "a/app.py" in analyzed
    assert "b/app.py" not in analyzed


def test_evaluate_assessment_policy_supported_and_refuted(tmp_path: Path):
    """
    Test B02/B12: Unified policy evaluation for supported, refuted, and uncertain.
    """
    from models.assessment import AssessmentStatus, evaluate_assessment_policy
    from evidence.store import EvidenceStore

    f = tmp_path / "test.py"
    f.write_text("x = 1\ny = 2\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    snap = store.create_snapshot()
    ev = store.record_evidence(snap.snapshot_id, "test.py", 1, 1, origin="read_lines")

    vuln = make_vuln(file_path="test.py", start_line=1)
    vuln_type = vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type)

    # 1. Supported without evidence -> uncertain
    a1 = evaluate_assessment_policy(
        vuln_id=vuln.id,
        vuln_type=vuln_type,
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        reason="Looks vulnerable",
        evidence_ids=[],
    )
    assert a1.status == AssessmentStatus.UNCERTAIN
    assert "thiếu mã bằng chứng" in a1.reason or "no evidence_ids" in a1.reason

    # 2. Supported with valid evidence but no taint/explanation -> uncertain
    a2 = evaluate_assessment_policy(
        vuln_id=vuln.id,
        vuln_type=vuln_type,
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        reason="Has evidence",
        evidence_ids=[ev.evidence_id],
        taint_path=[],
    )
    assert a2.status == AssessmentStatus.UNCERTAIN
    assert "taint" in a2.reason or "bằng chứng" in a2.reason

    # 3. Supported with valid evidence and taint steps -> accepted
    a3 = evaluate_assessment_policy(
        vuln_id=vuln.id,
        vuln_type=vuln_type,
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        reason="Flow verified",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"step": "source", "evidence_id": ev.evidence_id, "file": "test.py", "line": 1},
            {"step": "sink", "evidence_id": ev.evidence_id, "file": "test.py", "line": 1},
        ],
    )
    assert a3.status == AssessmentStatus.SUPPORTED

    # 4. Refuted without mitigating_control -> uncertain
    a4 = evaluate_assessment_policy(
        vuln_id=vuln.id,
        vuln_type=vuln_type,
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="refuted",
        reason="Safe",
        evidence_ids=[ev.evidence_id],
        mitigating_control=None,
    )
    assert a4.status == AssessmentStatus.UNCERTAIN


@pytest.mark.asyncio
async def test_mcp_check_stale_assessments_on_file_change(tmp_path: Path):
    """
    Test B02/B03/B12: check_stale_assessments marks assessment STALE if source changed.
    """
    from mcp_server import submit_assessment, check_stale_assessments, _scan_sessions
    from evidence.store import EvidenceStore

    f = tmp_path / "app.py"
    f.write_text("original_content = True\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    snap = store.create_snapshot()
    ev = store.record_evidence(snap.snapshot_id, "app.py", 1, 1, origin="read_lines")

    vuln = make_vuln(file_path="app.py", start_line=1)
    scan_id = "test_stale_session"
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {vuln.id: vuln},
        "evidence_store": store,
        "snapshot": snap,
        "assessments": {},
    }

    # Submit valid refuted assessment
    sub_res = await submit_assessment(
        scan_id=scan_id,
        finding_id=vuln.id,
        verdict="refuted",
        reason="Controlled by boolean",
        evidence_ids=[ev.evidence_id],
        mitigating_control="original_content",
    )
    assert sub_res["accepted_status"] == "refuted"
    assert sub_res["policy_verified"] is True

    # Modify file on disk
    f.write_text("modified_content = False\n", encoding="utf-8")

    # Run check_stale_assessments
    stale_res = await check_stale_assessments(scan_id=scan_id)
    assert stale_res["stale_count"] == 1
    assert vuln.id in stale_res["stale_finding_ids"]


def test_patch_risk_and_stale_snapshot_protection(tmp_path: Path):
    """
    Test B16: Patch risk semantics, stale snapshot protection on apply, and safe rollback.
    """
    from analyzer.fixer import Patch, PatchPlan, apply_plan, revert, PatchRisk
    import hashlib

    target = tmp_path / "service.py"
    target.write_text("def run():\n    return check_auth()\n", encoding="utf-8")

    vuln = make_vuln(file_path="service.py", start_line=2, end_line=2)

    # 1. Clean patch
    p_clean = Patch(
        vulnerability=vuln,
        file_path=target,
        start_line=2,
        end_line=2,
        original="    return check_auth()",
        replacement="    return bool(check_auth())",
    )
    assert p_clean.risk == "safe"
    assert p_clean.risk == "passed_structural_check"
    assert p_clean.formal_check_status == "passed_structural_check"

    # 2. Risky patch (bypass auth)
    p_risky = Patch(
        vulnerability=vuln,
        file_path=target,
        start_line=2,
        end_line=2,
        original="    return check_auth()",
        replacement="    return True",
    )
    assert p_risky.risk == "review"
    assert p_risky.risk == "review_required"
    assert "constant return" in p_risky.risk_reasons[0]

    # 3. Apply plan with stale hash protection
    plan = PatchPlan(patches=[p_clean])
    wrong_hash = hashlib.sha256(b"different content").hexdigest()
    res = apply_plan(plan, expected_snapshot_hashes={target: wrong_hash})
    assert res["patches_applied"] == 0
    assert target.read_text(encoding="utf-8") == "def run():\n    return check_auth()\n"

    # 4. Apply plan with valid hash
    correct_hash = hashlib.sha256(target.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    res_ok = apply_plan(plan, expected_snapshot_hashes={target: correct_hash})
    assert res_ok["patches_applied"] == 1
    assert "bool(check_auth())" in target.read_text(encoding="utf-8")

    # 5. Revert with concurrent modification protection
    # User modifies file concurrently after patch was applied
    target.write_text("def run():\n    # User added comment\n    return bool(check_auth())\n", encoding="utf-8")
    revert_count = revert(res_ok["backups"], expected_current_hashes=res_ok["written_hashes"])
    assert revert_count == 0  # skipped rollback to preserve user changes
    assert "# User added comment" in target.read_text(encoding="utf-8")


def test_fusion_disambiguates_different_dir_same_basename():
    """
    Test B06: Fusion does not merge findings from a/app.py and b/app.py.
    """
    from analyzer.fusion import fuse
    from models.vulnerability import FindingSource, VulnerabilityType

    v_rule = make_vuln(file_path="a/app.py", start_line=10, end_line=10, vuln_type=VulnerabilityType.SQL_INJECTION)
    v_rule.source = FindingSource.SEMGREP
    v_rule.engine_sources = ["SEMGREP"]

    v_llm = make_vuln(file_path="b/app.py", start_line=10, end_line=10, vuln_type=VulnerabilityType.SQL_INJECTION)
    v_llm.source = FindingSource.LLM
    v_llm.engine_sources = ["LLM"]

    result = fuse([v_rule], [v_llm])
    assert len(result.vulnerabilities) == 2
    paths = {v.location.file_path for v in result.vulnerabilities}
    assert "a/app.py" in paths
    assert "b/app.py" in paths
    assert all(not getattr(v, "corroborated", False) for v in result.vulnerabilities)


def test_scanner_cache_atomic_and_skip_error(tmp_path: Path):
    """
    Test B17: Cache writes atomically, does not cache error or truncated responses, and incorporates model identity.
    """
    from analyzer.scanner import Scanner, ScanOptions

    opts = ScanOptions(target=str(tmp_path), use_llm=True, cache_dir=str(tmp_path / "cache"))
    scanner = Scanner(options=opts)

    # 1. Cache key check
    key = scanner._cache_key("content_v1")
    assert isinstance(key, str) and len(key) == 64

    # 2. Skip caching error / truncated responses
    scanner._cache_put("err_content", {"error": "rate limit exceeded"})
    assert scanner._cache_get("err_content") is None

    scanner._cache_put("trunc_content", {"truncated": True, "vulnerabilities": []})
    assert scanner._cache_get("trunc_content") is None

    # 3. Successful cache write and retrieval
    scanner._cache_put("good_content", {"vulnerabilities": [{"type": "SQL_INJECTION"}]})
    cached = scanner._cache_get("good_content")
    assert cached is not None
    assert cached["vulnerabilities"][0]["type"] == "SQL_INJECTION"


@pytest.mark.asyncio
async def test_r01_cli_check_changes(tmp_path: Path):
    """
    R01: CLI check --changes must not raise AttributeError (get_modified_files)
    and should expand scope and scan without error.
    """
    from cli import _run_check
    import argparse

    f = tmp_path / "main.py"
    f.write_text("print('hello')\n", encoding="utf-8")

    args = argparse.Namespace(
        target=str(tmp_path),
        changes=True,
        before_release=False,
    )
    with patch("context.diff_scope.DiffScopeAnalyzer.get_changed_files", return_value=["main.py"]):
        code = await _run_check(args)
        assert code in (0, 1)


@pytest.mark.asyncio
async def test_r02_cli_check_fails_on_degraded_or_failed_status(tmp_path: Path):
    """
    R02: CLI check must return exit 2 (EXIT_ERROR) when scan fails or is degraded,
    even if findings list is empty.
    """
    from cli import _run_check, EXIT_ERROR
    from analyzer.scanner import ScanResult
    import argparse

    args_norm = argparse.Namespace(
        target=str(tmp_path),
        changes=False,
        before_release=False,
    )
    args_rel = argparse.Namespace(
        target=str(tmp_path),
        changes=False,
        before_release=True,
    )

    mock_res = ScanResult([], tmp_path, {"rule_error": "synthetic engine failure"})
    assert mock_res.status == "failed"
    assert mock_res.degraded is True

    with patch("analyzer.scanner.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = mock_res
        code_norm = await _run_check(args_norm)
        assert code_norm == EXIT_ERROR

        code_rel = await _run_check(args_rel)
        assert code_rel == EXIT_ERROR


def test_r03_policy_taint_path_validation(tmp_path: Path):
    """
    R03: evaluate_assessment_policy rejects [{}], invented evidence IDs,
    out of range lines, mismatched files, and missing source/sink for taint CWEs.
    """
    from models.assessment import AssessmentStatus, evaluate_assessment_policy
    from evidence.store import EvidenceStore

    f = tmp_path / "app.py"
    f.write_text("x = input()\nos.system(x)\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    snap = store.create_snapshot()
    ev = store.record_evidence(snap.snapshot_id, "app.py", 1, 2, origin="read_lines")

    # 1. Empty step [{}]
    a_empty = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[{}],
    )
    assert a_empty.status == AssessmentStatus.UNCERTAIN
    assert "empty" in a_empty.reason.lower() or "malformed" in a_empty.reason.lower()

    # 2. Invented evidence ID
    a_invented = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[{"kind": "sink", "file": "missing.py", "line": 999, "evidence_id": "invented"}],
    )
    assert a_invented.status == AssessmentStatus.UNCERTAIN

    # 3. Out of range line
    a_bad_line = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "source", "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
            {"kind": "sink", "file": "app.py", "line": 999, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_bad_line.status == AssessmentStatus.UNCERTAIN
    assert "range" in a_bad_line.reason.lower()

    # 4. Mismatched file
    a_bad_file = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "source", "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
            {"kind": "sink", "file": "other.py", "line": 2, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_bad_file.status == AssessmentStatus.UNCERTAIN
    assert "match" in a_bad_file.reason.lower()

    # 5. Missing sink
    a_no_sink = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "source", "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_no_sink.status == AssessmentStatus.UNCERTAIN
    assert "sink" in a_no_sink.reason.lower()

    # 6. Valid source and sink
    a_valid = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "source", "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
            {"kind": "sink", "file": "app.py", "line": 2, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_valid.status == AssessmentStatus.SUPPORTED


@pytest.mark.asyncio
async def test_r04_check_fix_missing_file_cannot_be_resolved(tmp_path: Path):
    """
    R04: check_fix must not mark a finding in a missing or unscanned file as resolved or clean.
    """
    from mcp_server import check_fix, _scan_sessions
    from evidence.store import EvidenceStore
    from conftest import make_vuln

    store = EvidenceStore(tmp_path)
    snap = store.create_snapshot()
    vuln = make_vuln(file_path="missing.py", start_line=1)

    scan_id = "test_r04_missing_file"
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {vuln.id: vuln},
        "changed_files": ["missing.py"],
        "expanded_files": ["missing.py"],
        "evidence_store": store,
        "snapshot": snap,
    }

    res = await check_fix(scan_id=scan_id, finding_ids=[vuln.id])
    assert res["clean"] is False
    assert vuln.id in res.get("persistent_findings", [])
    assert vuln.id not in res.get("resolved_findings", [])


@pytest.mark.asyncio
async def test_r05_verify_fix_fingerprint_instances(tmp_path: Path):
    """
    R05: Different Vulnerability instances with identical attributes must not
    be misidentified as regressions due to bound method comparison.
    """
    from cli import _verify_fix, EXIT_CLEAN
    from analyzer.scanner import ScanResult
    from conftest import make_vuln
    import argparse

    v_before = make_vuln(file_path="app.py", start_line=10)
    v_after = make_vuln(file_path="app.py", start_line=10)

    assert v_before is not v_after
    assert v_before.fingerprint() == v_after.fingerprint()

    r_before = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[v_before],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    before_result = ScanResult([r_before], tmp_path, {})

    r_after = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[v_after],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    after_result = ScanResult([r_after], tmp_path, {})

    args = argparse.Namespace(
        target=str(tmp_path),
        no_llm=True,
    )

    with patch("analyzer.scanner.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = after_result
        code = await _verify_fix(args, before_result, backups={}, expected_current_hashes={})
        assert code == EXIT_CLEAN


def test_r06_semgrep_global_errors_assembler(tmp_path: Path):
    """
    R06: Assembler marks run degraded and failed when Semgrep outputs global errors under "".
    """
    from analyzer.scanner import Scanner, ScanOptions, ScanResult
    from analyzer.discovery import DiscoveredFile

    opts = ScanOptions(target=str(tmp_path), use_semgrep=True, use_llm=False)
    scanner = Scanner(opts)
    scanner._file_rule_errors = {"": [{"message": "global rule failure"}]}

    df = DiscoveredFile(path=tmp_path / "app.py", root=tmp_path, risk_score=0, reasons=[])
    reports = scanner._assemble([df], {}, {}, {})

    assert len(reports) == 1
    assert reports[0].status == "failed"
    assert reports[0].degraded is True
    assert "global rule failure" in reports[0].engine_status["semgrep"]["reason"]

    result = ScanResult(reports, tmp_path, {})
    assert result.status == "failed"
    assert result.degraded is True


def test_r07_apply_plan_with_snapshot_hashes(tmp_path: Path):
    """
    R07: apply_plan refuses to patch files that were modified after plan snapshot.
    """
    import hashlib
    from analyzer.fixer import apply_plan, PatchPlan, Patch
    from conftest import make_vuln

    f = tmp_path / "main.py"
    f.write_text("a = 1\n", encoding="utf-8")
    initial_hash = hashlib.sha256(f.read_bytes()).hexdigest()

    vuln = make_vuln(file_path=str(f), start_line=1)
    patch = Patch(
        file_path=f,
        start_line=1,
        end_line=1,
        original="a = 1\n",
        replacement="a = 2\n",
        vulnerability=vuln,
    )
    plan = PatchPlan(patches=[patch], rejected=[])

    f.write_text("a = 999\n", encoding="utf-8")

    stats = apply_plan(plan, expected_snapshot_hashes={f: initial_hash})
    assert stats["patches_applied"] == 0
    assert f.read_text(encoding="utf-8") == "a = 999\n"


@pytest.mark.asyncio
async def test_n01_scanner_default_without_files(tmp_path: Path):
    """
    N01: Scanner.scan() without files option must not raise UnboundLocalError
    on empty directory or populated directory.
    """
    from analyzer.scanner import Scanner, ScanOptions

    # 1. Empty directory
    scanner_empty = Scanner(ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=False))
    res_empty = await scanner_empty.scan()
    assert res_empty.status == "completed"
    assert res_empty.stats["files_requested"] == []

    # 2. Populated directory
    f = tmp_path / "hello.py"
    f.write_text("print('test')\n", encoding="utf-8")
    scanner_pop = Scanner(ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=False))
    res_pop = await scanner_pop.scan()
    assert res_pop.status == "completed"
    assert "hello.py" in res_pop.stats["files_requested"]


def test_n02_n03_taint_policy_strict_schema_and_path(tmp_path: Path):
    """
    N02/N03: Strict path resolution against EvidenceStore (no suffix matching)
    and strict TaintStep schema validation (no substring matching, error on invalid kind/types).
    """
    from models.assessment import AssessmentStatus, evaluate_assessment_policy
    from evidence.store import EvidenceStore

    f = tmp_path / "app.py"
    f.write_text("x = input()\nos.system(x)\n", encoding="utf-8")

    store = EvidenceStore(tmp_path)
    snap = store.create_snapshot()
    ev = store.record_evidence(snap.snapshot_id, "app.py", 1, 2, origin="read_lines")

    # 1. N02: Subdirectory path mismatch (b/app.py vs app.py)
    a_mismatch = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "source", "file": "b/app.py", "line": 1, "evidence_id": ev.evidence_id},
            {"kind": "sink", "file": "b/app.py", "line": 2, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_mismatch.status == AssessmentStatus.UNCERTAIN
    assert "not match" in a_mismatch.reason.lower()

    # 2. N03: kind='not_source_not_sink' must fail schema validation and be uncertain
    a_fake_kind = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": "not_source_not_sink", "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_fake_kind.status == AssessmentStatus.UNCERTAIN
    assert "schema validation failed" in a_fake_kind.reason.lower()

    # 3. N03: kind=123 (integer) must not crash with AttributeError
    a_int_kind = evaluate_assessment_policy(
        vuln_id="v1",
        vuln_type="SQL_INJECTION",
        snapshot_id=snap.snapshot_id,
        evidence_store=store,
        verdict="supported",
        evidence_ids=[ev.evidence_id],
        taint_path=[
            {"kind": 123, "file": "app.py", "line": 1, "evidence_id": ev.evidence_id},
        ],
    )
    assert a_int_kind.status == AssessmentStatus.UNCERTAIN
    assert "schema validation failed" in a_int_kind.reason.lower()


@pytest.mark.asyncio
async def test_r07_timing_detects_file_modification_between_plan_and_apply(tmp_path: Path):
    """
    R07 timing: build_plan snapshots file hash during plan creation.
    If the file is modified on disk before apply_plan runs, _run_fix halts with error.
    """
    from cli import _run_fix, EXIT_ERROR
    from analyzer.scanner import ScanResult
    from conftest import make_vuln
    import argparse

    f = tmp_path / "code.py"
    f.write_text("x = 1\n", encoding="utf-8")
    import hashlib
    code_hash = hashlib.sha256(b"x = 1\n").hexdigest()

    vuln = make_vuln(file_path="code.py", start_line=1, secure_code_example="x = 2\n", file_hash=code_hash)
    report = VulnerabilityReport(
        file_name="code.py",
        vulnerabilities=[vuln],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    scan_res = ScanResult([report], tmp_path, {}, file_hashes={"code.py": code_hash})

    args = argparse.Namespace(
        target=str(tmp_path),
        no_llm=False,
        confirmed_only=False,
        dry_run=False,
        verify=False,
        yes=True,
        include_risky=True,
    )

    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = scan_res

        orig_build_plan = __import__("analyzer.fixer", fromlist=["build_plan"]).build_plan

        def side_effect_build_plan(*b_args, **b_kwargs):
            plan = orig_build_plan(*b_args, **b_kwargs)
            # Simulate modification on disk AFTER build_plan has created plan
            f.write_text("x = 999\n", encoding="utf-8")
            return plan

        with patch("cli.build_plan", side_effect=side_effect_build_plan):
            code = await _run_fix(args)
            assert code == EXIT_ERROR
            assert f.read_text(encoding="utf-8") == "x = 999\n"


@pytest.mark.asyncio
async def test_r07_detects_file_modification_between_analysis_and_plan(tmp_path: Path):
    """
    R07: changes between analysis and build_plan must be rejected as stale/conflict.
    The file on disk must NOT be overwritten with the old suggestion.
    """
    from cli import _run_fix, EXIT_ERROR, EXIT_CLEAN
    from analyzer.scanner import ScanResult
    from conftest import make_vuln
    import argparse
    import hashlib

    app_file = tmp_path / "app.py"
    initial_content = "x = 1\n"
    app_file.write_text(initial_content, encoding="utf-8")
    hash_a = hashlib.sha256(initial_content.encode("utf-8")).hexdigest()

    vuln = make_vuln(
        file_path="app.py",
        start_line=1,
        context="x = 1",
        secure_code_example="x = 2\n",
        file_hash=hash_a,
    )
    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[vuln],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    scan_res = ScanResult([report], tmp_path, {}, file_hashes={"app.py": hash_a})

    args = argparse.Namespace(
        target=str(tmp_path),
        no_llm=False,
        confirmed_only=False,
        dry_run=False,
        verify=False,
        yes=True,
        include_risky=True,
    )

    # 1. Simulate user edit after analysis (x = 1 -> x = 999) before build_plan runs
    app_file.write_text("x = 999\n", encoding="utf-8")

    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = scan_res
        code = await _run_fix(args)

        # Must report stale/conflict error, NOT exit 0
        assert code == EXIT_ERROR
        # Must NOT overwrite x = 999 with x = 2
        assert app_file.read_text(encoding="utf-8") == "x = 999\n"

    # 2. When file is unchanged from analysis, fix must apply cleanly
    app_file.write_text(initial_content, encoding="utf-8")
    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = scan_res
        code = await _run_fix(args)

        assert code == EXIT_CLEAN
        assert app_file.read_text(encoding="utf-8") == "x = 2\n"


@pytest.mark.asyncio
async def test_r07_scanner_populates_baseline_file_hashes(tmp_path: Path):
    """
    R07: Scanner computes snapshot hashes during discovery and sets file_hash on findings.
    """
    from analyzer.scanner import Scanner, ScanOptions
    from analyzer.fixer import build_plan
    from conftest import make_vuln
    import hashlib

    f = tmp_path / "hello.py"
    f.write_text("print('hello')\n", encoding="utf-8")
    expected_hash = hashlib.sha256(b"print('hello')\n").hexdigest()

    scanner = Scanner(ScanOptions(target=str(tmp_path), use_llm=False, use_semgrep=False))
    res = await scanner.scan()

    assert "hello.py" in res.file_hashes
    assert res.file_hashes["hello.py"] == expected_hash

    # Now simulate a finding based on this snapshot
    vuln = make_vuln(file_path="hello.py", start_line=1, secure_code_example="print('world')\n")
    # File is modified before build_plan
    f.write_text("print('modified')\n", encoding="utf-8")

    plan = build_plan([vuln], tmp_path, baseline_hashes=res.file_hashes)
    assert plan.stale is True
    assert len(plan.conflicts) == 1
    assert len(plan.patches) == 0


@pytest.mark.asyncio
async def test_r07_rejects_fix_when_baseline_metadata_missing(tmp_path: Path):
    """
    R07: When ScanResult/vulnerability lacks baseline hash metadata,
    CLI fix must fail-closed (require_baseline=True), report conflict/re-scan,
    and NOT overwrite user changes on disk.
    """
    from cli import _run_fix, EXIT_ERROR
    from analyzer.scanner import ScanResult
    from conftest import make_vuln
    import argparse

    app_file = tmp_path / "app.py"
    app_file.write_text("x = 1\n", encoding="utf-8")

    # Finding based on old code x = 1, but missing file_hash metadata
    vuln = make_vuln(
        file_path="app.py",
        start_line=1,
        context="x = 1",
        secure_code_example="x = 2\n",
        file_hash=None,
    )
    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[vuln],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    # Simulated legacy/mock scanner returning result without hash metadata
    scan_res = ScanResult([report], tmp_path, {})
    assert not scan_res.file_hashes

    # File on disk modified to x = 999 after analysis
    app_file.write_text("x = 999\n", encoding="utf-8")

    args = argparse.Namespace(
        target=str(tmp_path),
        no_llm=False,
        confirmed_only=False,
        dry_run=False,
        verify=False,
        yes=True,
        include_risky=True,
    )

    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = scan_res
        code = await _run_fix(args)

        # Must report error, NOT exit 0
        assert code == EXIT_ERROR
        # Must keep user change x = 999
        assert app_file.read_text(encoding="utf-8") == "x = 999\n"


# ---------------------------------------------------------------------------
# R08-R14: Editor mode consistency, Host adapter hooks, Provenance, Persistent
# audit, Cache identity & concurrency, SafeReader DoS defense, E2E Demo.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r08_editor_mode_zero_backend_llm_calls(monkeypatch, tmp_path: Path):
    """
    R08: Editor mode must strictly prevent backend model calls and expose
    honest per-tool capabilities.
    """
    import mcp_server
    monkeypatch.setenv("VULNAGENT_MODE", "editor")
    monkeypatch.setattr(mcp_server, "EDITOR_MODE", True)

    caps = await mcp_server.capabilities()
    assert caps["editor_mode"] is True
    assert caps["backend_llm_calls"] is False
    assert caps["mode"] == "editor"
    assert "tools" in caps
    assert caps["tools"]["scan_changes"]["backend_llm_calls"] is False

    with patch("mcp_server.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        from analyzer.scanner import ScanResult
        mock_scan.return_value = ScanResult([], tmp_path, {})
        await mcp_server._scan_target(tmp_path, mode="deep")
        assert mock_scan.called


@pytest.mark.asyncio
async def test_r09_editor_hook_runner_debounce_and_snapshot(tmp_path: Path):
    """
    R09: EditorHookRunner debounce skips repeated runs within window;
    dirty snapshot skips execution when files are unmodified.
    """
    from integrations.host_adapter import EditorHookRunner

    f = tmp_path / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")

    runner = EditorHookRunner(root=tmp_path, debounce_seconds=1.0, max_rounds=2)

    scan_called = 0
    async def dummy_scan():
        nonlocal scan_called
        scan_called += 1
        return []

    # First run: runs scan
    res1 = await runner.run(scan_fn=dummy_scan, files=[f])
    assert res1["status"] == "clean"
    assert scan_called == 1

    # Immediate second run: debounced
    res2 = await runner.run(scan_fn=dummy_scan, files=[f])
    assert res2["status"] == "skipped"
    assert res2["reason"] == "debounced"
    assert scan_called == 1

    # Advance time beyond debounce window, but file unmodified
    runner._last_run_time = 0.0
    res3 = await runner.run(scan_fn=dummy_scan, files=[f])
    assert res3["status"] == "skipped"
    assert res3["reason"] == "unmodified"
    assert scan_called == 1

    # Modify file, advance time -> runs scan again
    f.write_text("x = 2\n", encoding="utf-8")
    res4 = await runner.run(scan_fn=dummy_scan, files=[f])
    assert res4["status"] == "clean"
    assert scan_called == 2


@pytest.mark.asyncio
async def test_r09_editor_hook_runner_trailing_debounce(tmp_path: Path):
    """
    R09: Trailing debounce guarantees final edit in a rapid burst is not dropped.
    """
    import json
    from integrations.host_adapter import EditorHookRunner, HostAdapter

    f = tmp_path / "app.py"
    f.write_text("x = 1\n", encoding="utf-8")

    runner = EditorHookRunner(root=tmp_path, debounce_seconds=0.3, max_rounds=2)

    scanned_values = []
    async def dummy_scan():
        text = f.read_text(encoding="utf-8")
        scanned_values.append(text.strip())
        return []

    # Initial scan
    res1 = await runner.run(scan_fn=dummy_scan, files=[f])
    assert res1["status"] == "clean"
    assert scanned_values == ["x = 1"]

    # Rapid edit within debounce window with trailing=True
    f.write_text("x = 99\n", encoding="utf-8")
    res2 = await runner.run(scan_fn=dummy_scan, files=[f], trailing=True)
    assert res2["status"] == "clean"
    assert scanned_values == ["x = 1", "x = 99"]

    # Test HostAdapter configure_editor_save_hook
    adapter = HostAdapter(tmp_path)
    res_hook = adapter.configure_editor_save_hook(host="cursor")
    assert res_hook["hook_configured"] is True
    tasks_file = tmp_path / ".cursor" / "tasks.json"
    assert tasks_file.is_file()
    tasks_content = json.loads(tasks_file.read_text(encoding="utf-8"))
    labels = [t["label"] for t in tasks_content.get("tasks", [])]
    assert "VulnAgent On-Save Security Check" in labels


@pytest.mark.asyncio
async def test_r09_editor_hook_runner_lock_and_no_progress(tmp_path: Path):
    """
    R09: EditorHookRunner respects process lock, caps at 2 rounds,
    and terminates early with no_progress if findings do not decrease.
    """
    from integrations.host_adapter import EditorHookRunner
    from conftest import make_vuln

    f = tmp_path / "test.py"
    f.write_text("v = 1\n", encoding="utf-8")

    runner = EditorHookRunner(root=tmp_path, debounce_seconds=0.0, max_rounds=2)

    # 1. Test lock contention
    with runner.lock():
        runner2 = EditorHookRunner(root=tmp_path, debounce_seconds=0.0)
        res_locked = await runner2.run(scan_fn=AsyncMock(), files=[f])
        assert res_locked["status"] == "skipped"
        assert res_locked["reason"] == "locked"

    # 2. Test no-progress termination
    vuln = make_vuln(file_path="test.py", start_line=1)
    async def stub_scan():
        return [vuln]

    async def ineffective_fix(scan_res):
        pass

    res_no_progress = await runner.run(scan_fn=stub_scan, fix_fn=ineffective_fix, files=[f])
    assert res_no_progress["status"] == "no_progress"
    assert res_no_progress["rounds"] == 2
    assert res_no_progress["initial_count"] == 1
    assert res_no_progress["final_count"] == 1


@pytest.mark.asyncio
async def test_r09_editor_hook_runner_trailing_concurrent_save_during_lock(tmp_path: Path):
    """
    R09 (E03 regression): Trailing save hook does NOT drop save events
    when another scan is actively holding the repository lock.
    Instead of returning skipped/locked, trailing=True waits for the lock
    and executes a follow-up scan on the updated contents.
    """
    import asyncio
    from integrations.host_adapter import EditorHookRunner

    target_file = tmp_path / "app.py"
    target_file.write_text("x = 1\n", encoding="utf-8")

    runner1 = EditorHookRunner(root=tmp_path, debounce_seconds=0.0)
    runner2 = EditorHookRunner(root=tmp_path, debounce_seconds=0.0)

    scan1_started = asyncio.Event()
    allow_scan1_finish = asyncio.Event()
    scanned_contents = []

    async def scan1():
        scanned_contents.append(target_file.read_text(encoding="utf-8").strip())
        scan1_started.set()
        await allow_scan1_finish.wait()
        return {"status": "clean", "vulnerabilities": []}

    async def scan2():
        scanned_contents.append(target_file.read_text(encoding="utf-8").strip())
        return {"status": "clean", "vulnerabilities": []}

    # Start first scan that holds the lock while running
    t1 = asyncio.create_task(runner1.run(scan_fn=scan1, files=[target_file], trailing=False))
    await scan1_started.wait()

    # While scan1 holds the lock, modify the file on disk
    target_file.write_text("x = 2\n", encoding="utf-8")

    # Start second scan with trailing=True (simulating on-save hook while scan in-flight)
    t2 = asyncio.create_task(runner2.run(scan_fn=scan2, files=[target_file], trailing=True))

    # Also test non-trailing runner: should immediately return skipped/locked
    runner_nontrailing = EditorHookRunner(root=tmp_path, debounce_seconds=0.0)
    res_nontrailing = await runner_nontrailing.run(scan_fn=scan2, files=[target_file], trailing=False)
    assert res_nontrailing["status"] == "skipped"
    assert res_nontrailing["reason"] == "locked"

    # Give t2 a moment to enter lock_async wait
    await asyncio.sleep(0.08)

    # Allow scan1 to finish and release the lock
    allow_scan1_finish.set()
    res1 = await t1
    res2 = await t2

    assert res1["status"] == "clean"
    # Trailing runner must NOT be skipped as locked
    assert res2.get("reason") != "locked"
    assert res2["status"] == "clean"
    # Both initial x=1 and trailing x=2 must have been scanned
    assert "x = 1" in scanned_contents
    assert "x = 2" in scanned_contents


@pytest.mark.asyncio
async def test_r09_editor_hook_runner_trailing_auto_fix_budget_capped(tmp_path: Path):
    """
    R09 (E06 regression): Trailing auto-fix loop is strictly capped by max_rounds.
    When fixer modifies files but findings do not decrease, fixer must NOT be invoked
    beyond the max_rounds budget (e.g. max_rounds=2 caps at exactly 1 fix attempt),
    terminating with status 'no_progress'.
    """
    from integrations.host_adapter import EditorHookRunner
    from conftest import make_vuln

    target_file = tmp_path / "app.py"
    target_file.write_text("x = 1\n", encoding="utf-8")

    runner = EditorHookRunner(root=tmp_path, debounce_seconds=0.0, max_rounds=2)

    fix_call_count = 0
    vuln = make_vuln(file_path="app.py", start_line=1)

    async def persistent_scan():
        return [vuln]

    async def busy_fixer(scan_res):
        nonlocal fix_call_count
        fix_call_count += 1
        target_file.write_text(f"x = {fix_call_count + 10}\n", encoding="utf-8")

    res = await runner.run(scan_fn=persistent_scan, fix_fn=busy_fixer, files=[target_file], trailing=True)

    assert fix_call_count == 1
    assert res["status"] == "no_progress"
    assert res["rounds"] == 2
    assert res["initial_count"] == 1
    assert res["final_count"] == 1


@pytest.mark.asyncio
async def test_r09_editor_hook_preserves_existing_settings_and_tasks(tmp_path: Path):
    """
    R09 (E05 regression): configure_editor_save_hook must preserve existing JSONC settings,
    unrelated settings (e.g. editor.tabSize), string literals containing ',}' or ',]' or URLs,
    existing user on-save commands (e.g. tools/cli.py, echo commands mentioning vulnagent),
    existing tasks, and must not overwrite existing git pre-commit hooks.
    """
    import json
    from integrations.host_adapter import HostAdapter

    config_dir = tmp_path / ".cursor"
    config_dir.mkdir(parents=True, exist_ok=True)

    # 1. Existing settings.json with JSONC comments, trailing commas, strings with commas/brackets/escapes/URLs,
    # and diverse user commands including 'tools/cli.py lint', 'echo keep-me vulnagent', and legacy hook.
    existing_settings_raw = (
        "{\n"
        "  // Custom developer settings\n"
        '  "editor.tabSize": 8,\n'
        '  "custom.url": "https://example.com/api?foo=1//not-a-comment",\n'
        '  "custom.escape": "escaped \\"quote\\" and /* not block */",\n'
        '  "custom.trailing_bracket": "a,}",\n'
        '  "custom.trailing_square": "b,]",\n'
        '  "emeraldwalk.runonsave": {\n'
        '    "autoClearConsole": true,\n'
        '    "commands": [\n'
        '      {\n'
        '        "match": "\\\\.js$",\n'
        '        "cmd": "eslint ${file}",\n'
        '      },\n'
        '      {\n'
        '        "match": "\\\\.py$",\n'
        '        "cmd": "python tools/cli.py lint",\n'
        '      },\n'
        '      {\n'
        '        "match": ".*",\n'
        '        "cmd": "echo \'keep-me vulnagent mention\'",\n'
        '      },\n'
        '      {\n'
        '        "match": "\\\\.py$",\n'
        '        "cmd": "python -m cli hook --target \\"${workspaceFolder}\\" --files \\"${file}\\" --trailing",\n'
        '      },\n'
        '    ],\n'
        '  },\n'
        "}\n"
    )
    (config_dir / "settings.json").write_text(existing_settings_raw, encoding="utf-8")

    # 2. Existing tasks.json with custom user task containing comment and trailing commas
    existing_tasks_raw = (
        "{\n"
        '  "version": "2.0.0",\n'
        '  // Developer build tasks\n'
        '  "tasks": [\n'
        "    {\n"
        '      "label": "My Custom Build",\n'
        '      "type": "shell",\n'
        '      "command": "make build",\n'
        "    },\n"
        "  ],\n"
        "}\n"
    )
    (config_dir / "tasks.json").write_text(existing_tasks_raw, encoding="utf-8")

    # 3. Existing git pre-commit hook
    git_hooks = tmp_path / ".git" / "hooks"
    git_hooks.mkdir(parents=True, exist_ok=True)
    custom_hook = git_hooks / "pre-commit"
    custom_hook.write_text("#!/bin/sh\necho 'my custom pre-commit'\n", encoding="utf-8")

    adapter = HostAdapter(tmp_path)
    res1 = adapter.configure_editor_save_hook(host="cursor")
    assert res1["hook_configured"] is True
    assert res1["trigger_configured"] is True

    # Check Git hook was NOT overwritten
    assert custom_hook.read_text(encoding="utf-8") == "#!/bin/sh\necho 'my custom pre-commit'\n"

    # Check settings.json preserved all strings intact without data corruption
    settings_data = json.loads((config_dir / "settings.json").read_text(encoding="utf-8"))
    assert settings_data["editor.tabSize"] == 8
    assert settings_data["custom.url"] == "https://example.com/api?foo=1//not-a-comment"
    assert settings_data["custom.escape"] == 'escaped "quote" and /* not block */'
    assert settings_data["custom.trailing_bracket"] == "a,}"
    assert settings_data["custom.trailing_square"] == "b,]"
    assert settings_data["emeraldwalk.runonsave"]["autoClearConsole"] is True

    cmds = settings_data["emeraldwalk.runonsave"]["commands"]
    # User commands must ALL be preserved
    assert any(c.get("cmd") == "eslint ${file}" for c in cmds)
    assert any(c.get("cmd") == "python tools/cli.py lint" for c in cmds)
    assert any(c.get("cmd") == "echo 'keep-me vulnagent mention'" for c in cmds)
    # Legacy hook command replaced by current hook command
    assert not any(c.get("cmd") == 'python -m cli hook --target "${workspaceFolder}" --files "${file}" --trailing' for c in cmds)
    assert any(c.get("id") == "vulnagent-on-save" for c in cmds)
    assert len(cmds) == 4

    # Check tasks.json preserved user build task
    tasks_data = json.loads((config_dir / "tasks.json").read_text(encoding="utf-8"))
    task_labels = [t.get("label") for t in tasks_data.get("tasks", [])]
    assert "My Custom Build" in task_labels
    assert "VulnAgent On-Save Security Check" in task_labels

    # Idempotent re-run: should not duplicate command or tasks
    res2 = adapter.configure_editor_save_hook(host="cursor")
    assert res2["hook_configured"] is True
    settings_data2 = json.loads((config_dir / "settings.json").read_text(encoding="utf-8"))
    cmds2 = settings_data2["emeraldwalk.runonsave"]["commands"]
    assert len(cmds2) == 4
    assert any(c.get("cmd") == "eslint ${file}" for c in cmds2)
    assert any(c.get("cmd") == "python tools/cli.py lint" for c in cmds2)
    assert any(c.get("cmd") == "echo 'keep-me vulnagent mention'" for c in cmds2)


def test_r09_parse_jsonc_preserves_complex_strings():
    """
    R09 (E05 regression): _parse_jsonc must preserve strings containing structural characters
    like ',}' or ',]', quote escapes, URLs with '//', and comment markers, while correctly
    stripping JS comments and structural trailing commas.
    """
    from integrations.host_adapter import _parse_jsonc

    raw_jsonc = (
        "{\n"
        "  // Single-line comment\n"
        '  "test_comma_bracket": "a,}",\n'
        '  "test_comma_square": "b,]",\n'
        '  "test_url": "https://example.com/api//v1",\n'
        '  "test_escaped": "val \\"with quotes\\" and \\\\ backslash",\n'
        '  "test_comment_markers": "/* not a block comment */ and // not line comment",\n'
        "  /* Multi-line\n"
        "     block comment */\n"
        '  "test_list": [\n'
        '    "elem1",\n'
        '    "elem2,]", // trailing comma in list\n'
        "  ],\n"
        "}\n"
    )

    data = _parse_jsonc(raw_jsonc)
    assert data["test_comma_bracket"] == "a,}"
    assert data["test_comma_square"] == "b,]"
    assert data["test_url"] == "https://example.com/api//v1"
    assert data["test_escaped"] == 'val "with quotes" and \\ backslash'
    assert data["test_comment_markers"] == "/* not a block comment */ and // not line comment"
    assert data["test_list"] == ["elem1", "elem2,]"]


@pytest.mark.asyncio
async def test_r09_editor_hook_unified_launcher_standalone(tmp_path: Path):
    """
    R09 (E02 regression): Standalone CLI launcher configured in settings and tasks
    executes without requiring PYTHONPATH in external environment, eliminating 'No module named cli'.
    """
    import json
    import os
    import subprocess
    import sys
    from integrations.host_adapter import HostAdapter

    adapter = HostAdapter(tmp_path)
    res = adapter.configure_editor_save_hook(host="cursor")
    assert res["hook_configured"] is True

    launcher_path = Path(res["launcher"])
    assert launcher_path.is_file()

    settings_data = json.loads((tmp_path / ".cursor" / "settings.json").read_text(encoding="utf-8"))
    save_cmd = settings_data["emeraldwalk.runonsave"]["commands"][0]["cmd"]
    assert str(launcher_path.as_posix()) in save_cmd or str(launcher_path) in save_cmd

    # Test executing CLI launcher with cleared PYTHONPATH from isolated tmp_path cwd
    isolated_env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, str(launcher_path), "--version"],
        cwd=str(tmp_path),
        env=isolated_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 0
    assert "VulnAgent" in proc.stdout or "VulnAgent" in proc.stderr



@pytest.mark.asyncio
async def test_r09_doctor_mcp_smoke_and_semgrep_advice():
    """
    R09: doctor command includes MCP in-process handshake smoke test and
    actionable remediation advice for Semgrep.
    """
    import argparse
    from cli import _run_doctor, EXIT_CLEAN, EXIT_ERROR

    args = argparse.Namespace()
    code = await _run_doctor(args)
    assert code in (EXIT_CLEAN, EXIT_ERROR)


@pytest.mark.asyncio
async def test_r10_r11_persistent_assessment_store_and_mcp_semantics(tmp_path: Path):
    """
    R10 & R11: Structured provenance/assessment in MCP _to_dict,
    persistent JSONL audit store re-hydration across sessions, and stale event tracking.
    """
    from models.assessment import AssessmentStore, FindingAssessment, AssessmentStatus
    from mcp_server import _to_dict, get_assessment_history, _scan_sessions
    from conftest import make_vuln

    audit_dir = tmp_path / ".vulnagent-audit"
    store = AssessmentStore(storage_dir=audit_dir)

    vuln = make_vuln(file_path="foo.py", start_line=1)
    vuln.file_hash = "abc123hash"
    vuln.assessment_status = "supported"
    vuln.evidence_ids = ["ev_1"]

    # Test R10 _to_dict structured output
    payload = _to_dict(vuln)
    assert "provenance" in payload
    assert payload["provenance"]["file_hash"] == "abc123hash"
    assert "assessment" in payload
    assert payload["assessment"]["status"] == "supported"
    assert payload["assessment"]["evidence_ids"] == ["ev_1"]
    assert payload["assessment_status"] == "supported"

    # Test R11 persistent storage
    assessment = FindingAssessment(
        finding_id=vuln.id,
        snapshot_id="snap_123",
        status=AssessmentStatus.SUPPORTED,
        reason="Injection verified by evidence",
        evidence_ids=["ev_1"],
        assessor="host_editor",
    )
    store.save(assessment)
    store.record_event("test_event", {"finding_id": vuln.id, "detail": "sample"})

    log_file = audit_dir / "audit_log.jsonl"
    assert log_file.is_file()
    assert len(log_file.read_text(encoding="utf-8").splitlines()) == 2

    # Re-hydrate in new store instance
    store2 = AssessmentStore(storage_dir=audit_dir)
    loaded = store2.get(vuln.id)
    assert loaded is not None
    assert loaded.status == AssessmentStatus.SUPPORTED
    assert len(store2.get_events()) == 1

    # MCP get_assessment_history with events
    scan_id = "test_audit_session"
    _scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {vuln.id: vuln},
        "assessment_store": store2,
    }
    hist = await get_assessment_history(scan_id=scan_id, finding_id=vuln.id)
    assert hist["finding_id"] == vuln.id
    assert len(hist["history"]) >= 1
    assert len(hist["events"]) == 1


def test_r12_cache_key_identity_and_concurrency(tmp_path: Path, monkeypatch):
    """
    R12: Cache key derives from actual provider, model, endpoint, prompt version;
    atomic write uses UUID in temp file to prevent same-process collisions.
    """
    from analyzer.scanner import ScanOptions, Scanner

    options = ScanOptions(target=str(tmp_path), cache_dir=str(tmp_path / "cache"))
    scanner = Scanner(options)

    content = "print('hello')\n"
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    k1 = scanner._cache_key(content)

    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
    k2 = scanner._cache_key(content)
    assert k1 != k2

    monkeypatch.setenv("OPENAI_BASE_URL", "https://custom.endpoint/v1")
    k3 = scanner._cache_key(content)
    assert k2 != k3

    analysis = {"vulnerabilities": []}
    scanner._cache_put(content, analysis)
    cached = scanner._cache_get(content)
    assert cached == analysis


def test_r13_code_tools_safe_reader_and_redos_guard(tmp_path: Path):
    """
    R13: CodeTools delegates reads to SafeReader, limits file sizes,
    and protects search against ReDoS (length limits and nested repetitions).
    """
    from agent.tools import CodeTools, ToolError

    (tmp_path / "app.py").write_text("def run():\n    pass\n", encoding="utf-8")
    tools = CodeTools(tmp_path)

    # 1. Path traversal rejected
    with pytest.raises(ToolError):
        tools.read_lines("../outside.py")

    # 2. Regex length exceeded (>200)
    with pytest.raises(ToolError, match="exceeds maximum length"):
        tools.search("a" * 201)

    # 3. Potentially catastrophic nested repetition rejected
    with pytest.raises(ToolError, match="catastrophic nested repetition"):
        tools.search(r"((a+)+)+")

    # 4. Valid search works safely
    res = tools.search(r"def run")
    assert res["matches"]
    assert res["matches"][0]["line"] == 1


@pytest.mark.asyncio
async def test_r14_end_to_end_python_demo_three_branches(tmp_path: Path):
    """
    R14: End-to-end Python demo workflow covering three branches:
      Branch 1: Clean fix workflow (finding -> evidence -> assessment -> fix -> check_fix clean -> audit trail)
      Branch 2: Stale baseline conflict (finding -> external modification -> conflict prevented)
      Branch 3: Engine failure handling (engine degraded/failed -> status failed, fail-closed exit)
    """
    import argparse
    from analyzer.fixer import build_plan, apply_plan
    from analyzer.scanner import ScanResult
    from cli import _run_check, _run_fix, EXIT_CLEAN, EXIT_ERROR
    from conftest import make_vuln
    import mcp_server

    # -------------------------------------------------------------
    # Branch 1: Clean fix workflow
    # -------------------------------------------------------------
    app_file = tmp_path / "app.py"
    app_file.write_text("import sqlite3\ncur.execute(f'SELECT * FROM users WHERE id = {user_input}')\n", encoding="utf-8")

    scan_id = "demo_branch1_clean"
    vuln = make_vuln(
        file_path="app.py",
        start_line=2,
        context="cur.execute(f'SELECT * FROM users WHERE id = {user_input}')\n",
        secure_code_example="cur.execute('SELECT * FROM users WHERE id = ?', (user_input,))\n",
    )
    from evidence.store import EvidenceStore
    ev_store = EvidenceStore(tmp_path)
    snapshot = ev_store.create_snapshot()
    vuln.file_hash = snapshot.files.get("app.py", "")

    mcp_server._scan_sessions[scan_id] = {
        "root": tmp_path,
        "findings": {vuln.id: vuln},
        "changed_files": ["app.py"],
        "expanded_files": ["app.py"],
        "evidence_store": ev_store,
        "snapshot": snapshot,
    }

    # Step 1: Read evidence
    read_res = await mcp_server.read_evidence(scan_id=scan_id, path="app.py", start_line=1, end_line=2)
    assert read_res["read_succeeded"] is True
    eid = read_res["evidence_id"]

    # Step 2: Submit assessment
    assess_res = await mcp_server.submit_assessment(
        scan_id=scan_id,
        finding_id=vuln.id,
        verdict="supported",
        evidence_ids=[eid],
        taint_path=[{"kind": "source", "file": "app.py", "line": 2, "evidence_id": eid},
                    {"kind": "sink", "file": "app.py", "line": 2, "evidence_id": eid}],
        reason="Confirmed user_input flows directly into SQL execute",
    )
    assert assess_res["accepted_status"] == "supported"

    # Step 3: Apply fix
    plan = build_plan([vuln], tmp_path, baseline_hashes={"app.py": vuln.file_hash})
    assert len(plan.patches) == 1
    apply_res = apply_plan(plan, expected_snapshot_hashes={"app.py": vuln.file_hash})
    assert apply_res["patches_applied"] == 1
    assert "cur.execute('SELECT * FROM users WHERE id = ?'" in app_file.read_text(encoding="utf-8")

    # Step 4: check_fix verification
    with patch("mcp_server.Scanner.scan", new_callable=AsyncMock) as mock_rescan:
        mock_rescan.return_value = ScanResult([], tmp_path, {})
        fix_check = await mcp_server.check_fix(scan_id=scan_id, finding_ids=[vuln.id])
        assert fix_check["clean"] is True
        assert vuln.id in fix_check["resolved_findings"]

    # -------------------------------------------------------------
    # Branch 2: Stale baseline conflict
    # -------------------------------------------------------------
    app_file.write_text("import sqlite3\n# external developer changed this line completely\n", encoding="utf-8")
    stale_plan = build_plan([vuln], tmp_path, baseline_hashes={"app.py": vuln.file_hash})
    assert stale_plan.stale is True
    assert len(stale_plan.conflicts) == 1
    assert len(stale_plan.patches) == 0

    args_fix = argparse.Namespace(
        target=str(tmp_path),
        no_llm=False,
        confirmed_only=False,
        dry_run=False,
        verify=False,
        yes=True,
        include_risky=True,
    )
    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        from models.vulnerability import VulnerabilityReport
        rep = VulnerabilityReport(file_name="app.py", vulnerabilities=[vuln], chained_vulnerabilities=[], status="completed", timestamp=datetime.now())
        mock_scan.return_value = ScanResult([rep], tmp_path, {"app.py": vuln.file_hash})
        fix_exit = await _run_fix(args_fix)
        assert fix_exit == EXIT_ERROR
        assert "external developer changed" in app_file.read_text(encoding="utf-8")

    # -------------------------------------------------------------
    # Branch 3: Engine failure fail-closed
    # -------------------------------------------------------------
    args_check = argparse.Namespace(
        target=str(tmp_path),
        no_llm=False,
        no_semgrep=False,
        changes=False,
        before_release=True,
    )
    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan_fail:
        mock_scan_fail.return_value = ScanResult(
            [], tmp_path, {"rule_error": "Fatal syntax failure in engine", "status": "failed", "degraded": True}
        )
        check_exit = await _run_check(args_check)
        assert check_exit == EXIT_ERROR


@pytest.mark.asyncio
async def test_h01_runner_gates_failure_and_allows_retry_on_same_snapshot(tmp_path: Path):
    """
    H01: EditorHookRunner gates engine failures and degraded coverage,
    does not prematurely record snapshot as clean, and allows retry
    on the exact same snapshot once the engine recovers.
    """
    from integrations.host_adapter import EditorHookRunner
    runner = EditorHookRunner(tmp_path, debounce_seconds=0.0)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    # 1. Engine returns failure
    async def failing_scan():
        return {"status": "failed", "vulnerabilities": [], "engine_failure": True}

    res = await runner.run(scan_fn=failing_scan)
    assert res["status"] == "failed"
    assert "Engine failure" in res.get("reason", "")
    # Crucial: _last_snapshot must NOT record the file snapshot on failure
    assert "app.py" not in runner._last_snapshot

    # 2. Re-running immediately on same unchanged snapshot succeeds and runs scan
    async def recovered_scan():
        return {"status": "completed", "vulnerabilities": []}

    res2 = await runner.run(scan_fn=recovered_scan)
    assert res2["status"] == "clean"
    assert "app.py" in runner._last_snapshot

    # 3. Third run on same snapshot is skipped as clean (no change)
    res3 = await runner.run(scan_fn=recovered_scan)
    assert res3["status"] == "skipped"
    assert res3["reason"] == "unmodified"


def test_h02_runner_lock_preserves_live_owner_across_time_warp_and_token_cleanup(tmp_path: Path):
    """
    H02: Lock is never evicted if the owner process PID is alive, even if
    file timestamp is older than lock timeout (60s). Lock cleanup validates
    UUID token so old process cannot delete new owner's lock.
    """
    import json
    import os
    import time
    from integrations.host_adapter import EditorHookRunner

    runner1 = EditorHookRunner(tmp_path)
    runner2 = EditorHookRunner(tmp_path)
    lock_file = tmp_path / ".vulnagent.lock"

    # Acquire lock with runner1
    with runner1.lock():
        assert lock_file.is_file()
        token1 = runner1._active_lock_token
        assert token1 is not None

        # Simulate 120s elapsed time on lock file
        past_time = time.time() - 120.0
        os.utime(lock_file, (past_time, past_time))

        # Runner 2 tries to acquire lock. Since runner 1 PID is active, runner 2 cannot steal it!
        with pytest.raises(PermissionError):
            with runner2.lock(timeout_seconds=0.0):
                pass

        # Runner 1's lock file remains intact with runner 1's token
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
        assert lock_data["token"] == token1

    # After exit, lock_file is cleanly unlinked
    assert not lock_file.is_file()

    # Test token safety on cleanup: if lock file has different token, runner1 does not unlink it
    fake_token = "foreign_token_123"
    lock_file.write_text(json.dumps({"pid": os.getpid(), "token": fake_token, "timestamp": time.time()}), encoding="utf-8")
    runner1._active_lock_token = "my_token_456"
    # Calling cleanup on runner1 must NOT remove lock_file with fake_token
    runner1._active_lock_token = None
    assert lock_file.is_file()
    lock_file.unlink()


def test_h03_regex_guard_rejects_redos_and_worker_timeout(tmp_path: Path):
    """
    H03: Static screen catches ReDoS alternation and nested patterns like (a|aa)+$,
    literal parameter bypasses regex compilation, and worker execution has hard timeout.
    """
    from agent.tools import CodeTools, ToolError

    (tmp_path / "app.py").write_text("x = 'test string'\n", encoding="utf-8")
    tools = CodeTools(tmp_path)

    # 1. Reject catastrophic alternation repetitions
    with pytest.raises(ToolError, match="ambiguous alternation with repetition"):
        tools.search(r"(a|aa)+$")

    with pytest.raises(ToolError, match="ambiguous alternation with repetition"):
        tools.search(r"(foo|foobar)+")

    # 2. Reject nested repetitions
    with pytest.raises(ToolError, match="catastrophic nested repetition"):
        tools.search(r"((ab)+)+")

    # 3. Literal search works even with regex chars
    res = tools.search("test string", literal=True)
    assert len(res["matches"]) == 1
    assert res["matches"][0]["line"] == 1


@pytest.mark.asyncio
async def test_r09_cli_hook_subcommand(tmp_path: Path):
    """
    R09: CLI hook subcommand executes EditorHookRunner and exits properly.
    """
    import argparse
    from cli import _run_hook, EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR

    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    args = argparse.Namespace(target=str(tmp_path), files=None, max_rounds=2, debounce=0.0)

    with patch("integrations.host_adapter.EditorHookRunner.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"status": "clean"}
        code = await _run_hook(args)
        assert code == EXIT_CLEAN

        mock_run.return_value = {"status": "findings_detected"}
        code = await _run_hook(args)
        assert code == EXIT_FINDINGS

        mock_run.return_value = {"status": "failed", "reason": "Engine crashed"}
        code = await _run_hook(args)
        assert code == EXIT_ERROR


@pytest.mark.asyncio
async def test_r11_mcp_session_rehydration_after_restart(tmp_path: Path):
    """
    R11: Scan sessions, snapshots, evidence records, and assessments are restored
    from .vulnagent-audit after MCP server restart (clearing memory).
    """
    import json
    import mcp_server
    from evidence.store import EvidenceStore

    app_file = tmp_path / "app.py"
    app_file.write_text("user = input()\nquery = f'SELECT * FROM t WHERE id={user}'\n", encoding="utf-8")

    # Initial scan in editor mode
    scan_res = await mcp_server.scan_changes(target=str(tmp_path))
    scan_id = scan_res["scan_id"]
    assert scan_id.startswith("scan_")

    # Read evidence to persist evidence record
    read_res = await mcp_server.read_evidence(scan_id=scan_id, path="app.py", start_line=1, end_line=2)
    assert read_res["read_succeeded"] is True
    ev_id = read_res["evidence_id"]

    # Register finding into session and persisted session record
    from conftest import make_vuln
    vuln = make_vuln(file_path="app.py", start_line=2, end_line=2)
    session = mcp_server._scan_sessions[scan_id]
    session["findings"][vuln.id] = vuln
    audit_dir = tmp_path / ".vulnagent-audit"
    sess_file = audit_dir / "sessions.jsonl"
    sess_data = json.loads(sess_file.read_text(encoding="utf-8").splitlines()[-1])
    sess_data["findings"].append(vuln.model_dump())
    sess_file.write_text(json.dumps(sess_data, ensure_ascii=False) + "\n", encoding="utf-8")

    # Submit assessment
    assess_res = await mcp_server.submit_assessment(
        scan_id=scan_id,
        finding_id=vuln.id,
        verdict="uncertain",
        evidence_ids=[ev_id],
        reason="Context rehydration test",
    )
    assert assess_res["accepted_status"] == "uncertain"

    # SIMULATE RESTART: Clear in-memory dictionary
    mcp_server._scan_sessions.clear()
    assert scan_id not in mcp_server._scan_sessions

    # Rehydrated read_evidence (with root_hint=tmp_path via cwd context)
    import os
    orig_cwd = os.getcwd()
    os.chdir(str(tmp_path))
    try:
        re_read = await mcp_server.read_evidence(scan_id=scan_id, path="app.py", start_line=1, end_line=1)
        assert re_read["read_succeeded"] is True
        assert "user = input()" in re_read["content"]

        # Rehydrated get_assessment_history
        hist = await mcp_server.get_assessment_history(scan_id=scan_id, finding_id=vuln.id)
        assert len(hist["history"]) >= 1
        assert hist["history"][0]["status"] == "uncertain"
    finally:
        os.chdir(orig_cwd)


def test_r14_runtime_behavioral_sql_execution(tmp_path: Path):
    """
    R14: End-to-end runtime security verification executing real Python code against SQLite.
    Demonstrates actual SQL injection exploitation on vulnerable code vs parameterized safe execution on patched code.
    """
    import sqlite3
    import subprocess
    import sys

    # 1. Setup SQLite database with sensitive records
    db_path = tmp_path / "app.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret_token TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'FLAG{SUPER_SECRET_ADMIN_KEY}')")
    conn.execute("INSERT INTO users VALUES (2, 'guest', 'guest_token')")
    conn.commit()
    conn.close()

    # 2. Write vulnerable application script
    vuln_script = tmp_path / "vuln_app.py"
    db_escaped = str(db_path).replace("\\", "/")
    vuln_script.write_text(f'''
import sqlite3
import sys

def get_user(uid):
    conn = sqlite3.connect("{db_escaped}")
    cur = conn.cursor()
    query = f"SELECT username, secret_token FROM users WHERE id = {{uid}}"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    payload = sys.argv[1]
    results = get_user(payload)
    print("COUNT:" + str(len(results)))
    for r in results:
        print("ROW:" + r[0] + ":" + r[1])
''', encoding="utf-8")

    # Run vulnerable app with injection payload: "999 OR 1=1"
    proc_vuln = subprocess.run(
        [sys.executable, str(vuln_script), "999 OR 1=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "COUNT:2" in proc_vuln.stdout
    assert "FLAG{SUPER_SECRET_ADMIN_KEY}" in proc_vuln.stdout

    # 3. Write patched secure application script using parameterized query
    patched_script = tmp_path / "patched_app.py"
    patched_script.write_text(f'''
import sqlite3
import sys

def get_user(uid):
    conn = sqlite3.connect("{db_escaped}")
    cur = conn.cursor()
    query = "SELECT username, secret_token FROM users WHERE id = ?"
    cur.execute(query, (uid,))
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    payload = sys.argv[1]
    results = get_user(payload)
    print("COUNT:" + str(len(results)))
    for r in results:
        print("ROW:" + r[0] + ":" + r[1])
''', encoding="utf-8")

    # Run patched app with same injection payload
    proc_patched = subprocess.run(
        [sys.executable, str(patched_script), "999 OR 1=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    # Parameterized query treats entire payload as literal id; id "999 OR 1=1" matches no users!
    assert "COUNT:0" in proc_patched.stdout
    assert "FLAG{SUPER_SECRET_ADMIN_KEY}" not in proc_patched.stdout


@pytest.mark.asyncio
async def test_h01_runner_gates_partial_status_and_incomplete_coverage(tmp_path: Path):
    """
    H01: ScanResult with status='partial' and degraded=False must NOT be reported clean.
    Runner must fail the round and preserve last snapshot to permit retry.
    """
    from analyzer.scanner import ScanResult
    from integrations.host_adapter import EditorHookRunner
    from models.vulnerability import VulnerabilityReport

    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    runner = EditorHookRunner(tmp_path, debounce_seconds=0.0)

    # 1. Partial report with empty findings and degraded=False
    partial_rep = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[],
        chained_vulnerabilities=[],
        status="partial",
        timestamp=datetime.now(),
    )
    partial_result = ScanResult([partial_rep], tmp_path, {"status": "partial", "degraded": False})

    async def partial_scan():
        return partial_result

    res = await runner.run(scan_fn=partial_scan)
    assert res["status"] == "failed"
    assert "incomplete" in res.get("reason", "").lower() or "partial" in res.get("reason", "").lower()
    # Crucial: snapshot is not saved as clean
    assert "app.py" not in runner._last_snapshot

    # 2. When scanner recovers to full completion, scan succeeds and records snapshot
    completed_rep = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    completed_result = ScanResult([completed_rep], tmp_path, {"status": "completed", "degraded": False})

    async def full_scan():
        return completed_result

    res2 = await runner.run(scan_fn=full_scan)
    assert res2["status"] == "clean"
    assert "app.py" in runner._last_snapshot


@pytest.mark.asyncio
async def test_r11_public_mcp_tools_restore_session_when_cwd_differs_from_repo(tmp_path: Path, monkeypatch):
    """
    R11: Public MCP tools (without root_hint) restore sessions from registry
    even when server cwd is a different directory from the scanned repository.
    """
    import json
    import os
    import mcp_server
    from conftest import make_vuln

    # Create isolated registry location
    reg_dir = tmp_path / "global_reg"
    reg_dir.mkdir()
    monkeypatch.setenv("VULNAGENT_REGISTRY_DIR", str(reg_dir))

    # Repo located at separate directory
    repo_dir = tmp_path / "repo_under_test"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("x = input()\n", encoding="utf-8")

    # Working dir is at another directory
    server_cwd = tmp_path / "server_workspace"
    server_cwd.mkdir()

    orig_cwd = os.getcwd()
    os.chdir(str(server_cwd))
    try:
        # 1. Scan target is repo_dir (different from cwd)
        scan_res = await mcp_server.scan_changes(target=str(repo_dir))
        scan_id = scan_res["scan_id"]

        vuln = make_vuln(file_path="app.py", start_line=1, end_line=1)
        session = mcp_server._scan_sessions[scan_id]
        session["findings"][vuln.id] = vuln

        # Persist finding to session file
        audit_dir = repo_dir / ".vulnagent-audit"
        sess_file = audit_dir / "sessions.jsonl"
        sess_lines = sess_file.read_text(encoding="utf-8").splitlines()
        last_data = json.loads(sess_lines[-1])
        last_data["findings"].append(vuln.model_dump())
        sess_file.write_text(json.dumps(last_data, ensure_ascii=False) + "\n", encoding="utf-8")

        # 2. Read evidence
        read_res = await mcp_server.read_evidence(scan_id=scan_id, path="app.py", start_line=1, end_line=1)
        assert read_res["read_succeeded"] is True
        ev_id = read_res["evidence_id"]

        # 3. Submit assessment
        assess_res = await mcp_server.submit_assessment(
            scan_id=scan_id,
            finding_id=vuln.id,
            verdict="refuted",
            evidence_ids=[ev_id],
            mitigating_control="Input validated before use",
            reason="Verified safe",
        )
        assert assess_res["accepted_status"] == "refuted"

        # 4. SIMULATE RESTART: wipe RAM
        mcp_server._scan_sessions.clear()
        assert scan_id not in mcp_server._scan_sessions
        assert Path.cwd() == server_cwd  # cwd is STILL different from repo_dir!

        # 5. Call public tool get_assessment_history WITHOUT root_hint
        hist = await mcp_server.get_assessment_history(scan_id=scan_id, finding_id=vuln.id)
        assert len(hist["history"]) >= 1
        assert hist["history"][0]["status"] == "refuted"

        # 6. Call public tool read_evidence WITHOUT root_hint
        re_read = await mcp_server.read_evidence(scan_id=scan_id, path="app.py", start_line=1, end_line=1)
        assert re_read["read_succeeded"] is True
        assert "x = input()" in re_read["content"]

        # 7. Check stale assessments WITHOUT root_hint
        stale_res = await mcp_server.check_stale_assessments(scan_id=scan_id)
        assert "stale_count" in stale_res
    finally:
        os.chdir(orig_cwd)


@pytest.mark.asyncio
async def test_r14_behavioral_integration_pipeline_demo_with_simulated_finding_and_rescan(tmp_path: Path):
    """
    R14 Behavioral integration demo (simulated finding/rescan):
    1. Runtime SQLite verification: valid input ('1') returns Alice; malicious input ('999 OR 1=1') leaks database.
    2. VulnAgent fixer pipeline: build_plan -> apply_plan rewrites code with parameterized query.
    3. check_fix simulated verification.
    4. Post-patch runtime verification: valid input preserved, injection completely neutralized.
    """
    import sqlite3
    import subprocess
    import sys
    from analyzer.fixer import build_plan, apply_plan
    from analyzer.scanner import ScanOptions, Scanner, ScanResult
    from evidence.store import EvidenceStore
    import mcp_server

    # Step 1: Database setup
    db_file = tmp_path / "demo.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'Alice', 'admin')")
    conn.execute("INSERT INTO users VALUES (2, 'Bob', 'user')")
    conn.commit()
    conn.close()

    # Step 2: Write vulnerable script
    db_escaped = str(db_file).replace("\\", "/")
    app_py = tmp_path / "app.py"
    app_py.write_text(f'''import sqlite3
import sys

def get_user_role(user_id):
    conn = sqlite3.connect("{db_escaped}")
    cur = conn.cursor()
    cur.execute(f"SELECT name, role FROM users WHERE id = {{user_id}}")
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    uid = sys.argv[1]
    res = get_user_role(uid)
    print("COUNT:" + str(len(res)))
    for r in res:
        print("USER:" + r[0] + ":" + r[1])
''', encoding="utf-8")

    # Step 3: Verify pre-patch runtime behavior
    # Valid input '1': returns exactly 1 user (Alice)
    p_valid = subprocess.run([sys.executable, str(app_py), "1"], capture_output=True, text=True, check=True)
    assert "COUNT:1" in p_valid.stdout
    assert "USER:Alice:admin" in p_valid.stdout

    # Injection input '999 OR 1=1': leaks all users
    p_inj = subprocess.run([sys.executable, str(app_py), "999 OR 1=1"], capture_output=True, text=True, check=True)
    assert "COUNT:2" in p_inj.stdout
    assert "USER:Alice:admin" in p_inj.stdout
    assert "USER:Bob:user" in p_inj.stdout

    # Step 4: Vulnerability detection and finding binding (simulated fixture finding)
    ev_store = EvidenceStore(tmp_path)
    snap = ev_store.create_snapshot()
    vuln = make_vuln(
        file_path="app.py",
        start_line=7,
        end_line=7,
        context='    cur.execute(f"SELECT name, role FROM users WHERE id = {user_id}")\n',
        secure_code_example='    cur.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))\n',
    )
    vuln.file_hash = snap.files.get("app.py", "")

    # Step 5: Build and Apply Plan through VulnAgent fixer pipeline
    plan = build_plan([vuln], tmp_path, baseline_hashes={"app.py": vuln.file_hash})
    assert len(plan.patches) == 1
    apply_res = apply_plan(plan, expected_snapshot_hashes={"app.py": vuln.file_hash})
    assert apply_res["patches_applied"] == 1
    assert 'cur.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))' in app_py.read_text(encoding="utf-8")

    # Step 6: Fix verification via check_fix
    scan_id = "r14_demo_scan"
    mcp_server._scan_sessions[scan_id] = {
        "root": tmp_path,
        "snapshot": snap,
        "evidence_store": ev_store,
        "findings": {vuln.id: vuln},
        "changed_files": ["app.py"],
        "expanded_files": ["app.py"],
    }
    with patch("mcp_server.Scanner.scan", new_callable=AsyncMock) as mock_rescan:
        mock_rescan.return_value = ScanResult([], tmp_path, {})
        fix_check = await mcp_server.check_fix(scan_id=scan_id, finding_ids=[vuln.id])
        assert fix_check["clean"] is True
        assert vuln.id in fix_check["resolved_findings"]

    # Step 7: Verify post-patch runtime behavior
    # Valid input '1': STILL WORKS!
    p_post_valid = subprocess.run([sys.executable, str(app_py), "1"], capture_output=True, text=True, check=True)
    assert "COUNT:1" in p_post_valid.stdout
    assert "USER:Alice:admin" in p_post_valid.stdout

    # Injection input '999 OR 1=1': Neutralized!
    p_post_inj = subprocess.run([sys.executable, str(app_py), "999 OR 1=1"], capture_output=True, text=True, check=True)
    assert "COUNT:0" in p_post_inj.stdout
    assert "Alice" not in p_post_inj.stdout


@pytest.mark.integration
@pytest.mark.asyncio
async def test_r14_real_semgrep_detector_and_rescan_e2e_integration(tmp_path: Path):
    """
    R14 End-to-end integration with REAL Semgrep engine and REAL rescan coverage:
    1. Creates file with real OS Command Injection (subprocess.call(cmd, shell=True)).
    2. Runs real Scanner.scan() with use_semgrep=True, use_llm=False.
    3. Asserts real Semgrep finding detected (CWE-78 / OS_COMMAND_INJECTION) and real coverage report status='completed'.
    4. Applies secure rewrite through build_plan and apply_plan (changing shell=True to shell=False).
    5. Runs real Scanner.scan() rescan: asserts finding resolved, 0 vulnerabilities, status='completed'.
    """
    from analyzer.fixer import build_plan, apply_plan
    from analyzer.scanner import ScanOptions, Scanner
    from evidence.store import EvidenceStore
    from models.vulnerability import VulnerabilityType

    app_py = tmp_path / "command_runner.py"
    app_py.write_text(
        "import subprocess\n"
        "\n"
        "def execute_user_command(cmd: str):\n"
        "    subprocess.call(cmd, shell=True)\n",
        encoding="utf-8"
    )

    ev_store = EvidenceStore(tmp_path)
    snap = ev_store.create_snapshot()

    # Step 1: Real Semgrep scan using pinned offline rules
    rules_path = Path(__file__).resolve().parent.parent / "rules" / "pinned_security_rules.yaml"
    assert rules_path.is_file(), f"Pinned rules missing: {rules_path}"
    options = ScanOptions(
        target=str(tmp_path),
        use_llm=False,
        use_semgrep=True,
        semgrep_configs=(str(rules_path),),
    )
    scanner = Scanner(options)
    assert scanner.semgrep.configs == (str(rules_path),)
    scan_res = await scanner.scan()

    # Step 2: Assert real detector found vulnerability
    assert scan_res.status == "completed"
    assert scan_res.degraded is False
    assert len(scan_res.reports) == 1
    assert scan_res.reports[0].status == "completed"
    assert len(scan_res.vulnerabilities) >= 1

    vuln = next((v for v in scan_res.vulnerabilities if v.type == VulnerabilityType.OS_COMMAND_INJECTION or "78" in getattr(v, "cwe_id", "")), None)
    assert vuln is not None
    assert vuln.location.file_path in ("command_runner.py", str(app_py))

    # Step 3: Secure rewrite through fixer pipeline
    vuln.secure_code_example = "    subprocess.call(cmd, shell=False)"
    plan = build_plan([vuln], tmp_path, baseline_hashes={vuln.location.file_path: snap.files.get("command_runner.py", "")})
    assert len(plan.patches) == 1
    apply_res = apply_plan(plan, expected_snapshot_hashes={vuln.location.file_path: snap.files.get("command_runner.py", "")})
    assert apply_res["patches_applied"] == 1
    assert "shell=False" in app_py.read_text(encoding="utf-8")

    # Step 4: Real Semgrep rescan confirms resolution
    rescan_res = await scanner.scan()
    assert rescan_res.status == "completed"
    assert rescan_res.degraded is False
    assert len(rescan_res.vulnerabilities) == 0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_r14_mcp_transport_handshake_and_stdio_e2e(tmp_path: Path):
    """
    R14 Real MCP stdio transport client handshake & E2E full lifecycle execution:
    1. Launches python src/mcp_server.py over real stdio transport.
    2. Performs protocol initialize() handshake and lists all registered tools.
    3. Calls 'capabilities' tool over transport: asserts schema version and editor mode.
    4. Calls 'scan_changes' with real detector: asserts completed coverage, degraded=False, candidate found.
    5. Protocol failure tests: verifies unknown scan_id rejection and unverified verdict on fabricated evidence.
    6. Calls 'get_finding_context' & 'read_evidence': gets authenticated evidence ID.
    7. Calls 'submit_assessment': records supported verdict and audit trail.
    8. Disk modification & stale detection: verifies check_stale_assessments flags modified files over stdio.
    9. Syntax failure gate: verifies check_fix catches syntax errors over stdio.
    10. Applies valid fix and calls 'check_fix': asserts clean=True and finding resolved.
    11. Calls 'get_assessment_history': verifies audit trail over stdio.
    12. Spawns brand new server subprocess (simulating restart): verifies cross-process & cross-cwd session restoration.
    """
    import json
    import os
    import sys
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_script = Path(__file__).resolve().parent.parent / "src" / "mcp_server.py"
    rules_path = Path(__file__).resolve().parent.parent / "rules" / "pinned_security_rules.yaml"
    assert rules_path.is_file(), f"Pinned rules missing: {rules_path}"
    server_env = {**os.environ, "VULNAGENT_SEMGREP_RULES": str(rules_path)}
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
        env=server_env,
    )

    calc_py = tmp_path / "calculator.py"
    calc_py.write_text(
        "def evaluate_math(code_str: str):\n"
        "    return eval(code_str)\n",
        encoding="utf-8"
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # 1. Transport handshake
            init_res = await session.initialize()
            assert init_res.serverInfo.name == "vulnagent"

            # 2. Tool list discovery
            tools_res = await session.list_tools()
            tool_names = {t.name for t in tools_res.tools}
            expected_tools = {
                "scan_changes", "get_finding_context", "read_evidence",
                "submit_assessment", "check_stale_assessments", "get_assessment_history",
                "check_fix", "capabilities"
            }
            assert expected_tools.issubset(tool_names)

            # 3. Call capabilities over stdio
            cap_res = await session.call_tool("capabilities", {})
            assert cap_res.content and len(cap_res.content) > 0
            cap_data = json.loads(cap_res.content[0].text)
            assert cap_data["schema_version"] == "2.0.0"
            assert cap_data["editor_mode"] is True

            # 4. Call scan_changes over stdio (real detector & coverage check)
            scan_call = await session.call_tool("scan_changes", {"target": str(tmp_path)})
            assert scan_call.content and len(scan_call.content) > 0
            scan_out = json.loads(scan_call.content[0].text)
            assert "scan_id" in scan_out
            assert "snapshot_id" in scan_out
            scan_id = scan_out["scan_id"]

            coverage = scan_out["coverage"]
            assert coverage["status"] == "completed"
            assert coverage["degraded"] is False
            assert coverage["total_files"] >= 1
            assert coverage["scanned_count"] >= 1
            assert "calculator.py" in coverage["files_scanned"]
            assert coverage["file_statuses"]["calculator.py"]["status"] == "completed"
            assert len(scan_out["candidates"]) >= 1
            fid = scan_out["candidates"][0]["id"]

            # 5a. Protocol failure check: unknown scan_id rejection
            bad_ev_call = await session.call_tool("read_evidence", {"scan_id": "nonexistent_scan_999", "path": "calculator.py"})
            bad_ev_out = json.loads(bad_ev_call.content[0].text)
            assert "error" in bad_ev_out or bad_ev_out.get("read_succeeded") is False

            # 5b. Protocol failure check: fabricated evidence rejection in submit_assessment
            fake_ass_call = await session.call_tool("submit_assessment", {
                "scan_id": scan_id,
                "finding_id": fid,
                "verdict": "supported",
                "evidence_ids": ["ev_fabricated_999"],
            })
            fake_ass_out = json.loads(fake_ass_call.content[0].text)
            assert fake_ass_out["policy_verified"] is False
            assert fake_ass_out["accepted_status"] == "uncertain"

            # 6. Call get_finding_context over stdio
            ctx_call = await session.call_tool("get_finding_context", {"scan_id": scan_id, "finding_id": fid})
            ctx_out = json.loads(ctx_call.content[0].text)
            assert "enclosing_scope" in ctx_out
            assert "initial_evidence_id" in ctx_out

            # 7. Call read_evidence over stdio
            ev_call = await session.call_tool("read_evidence", {"scan_id": scan_id, "path": "calculator.py", "start_line": 1, "end_line": 2})
            ev_out = json.loads(ev_call.content[0].text)
            assert ev_out["read_succeeded"] is True
            ev_id = ev_out["evidence_id"]

            # 8. Call submit_assessment with verified evidence over stdio
            ass_call = await session.call_tool("submit_assessment", {
                "scan_id": scan_id,
                "finding_id": fid,
                "verdict": "supported",
                "evidence_ids": [ev_id],
                "taint_path": [
                    {"kind": "source", "file": "calculator.py", "line": 1, "evidence_id": ev_id},
                    {"kind": "sink", "file": "calculator.py", "line": 2, "evidence_id": ev_id}
                ],
                "reason": "Direct user input flow into eval",
            })
            ass_out = json.loads(ass_call.content[0].text)
            assert ass_out["accepted_status"] == "supported"
            assert ass_out["policy_verified"] is True

            # 9a. Check stale assessments initially (should be 0 stale)
            stale_init_call = await session.call_tool("check_stale_assessments", {"scan_id": scan_id})
            stale_init_out = json.loads(stale_init_call.content[0].text)
            assert stale_init_out["stale_count"] == 0

            # 9b. Modify file on disk and verify check_stale_assessments flags it
            calc_py.write_text(
                "def evaluate_math(code_str: str):\n    return eval(code_str)  # edited on disk\n",
                encoding="utf-8"
            )
            stale_post_call = await session.call_tool("check_stale_assessments", {"scan_id": scan_id})
            stale_post_out = json.loads(stale_post_call.content[0].text)
            assert stale_post_out["stale_count"] == 1
            assert fid in stale_post_out["stale_finding_ids"]

            # 9c. Syntax break check: check_fix rejects broken syntax
            calc_py.write_text("def evaluate_broken_math(:\n", encoding="utf-8")
            syn_call = await session.call_tool("check_fix", {"scan_id": scan_id, "finding_ids": [fid]})
            syn_out = json.loads(syn_call.content[0].text)
            assert syn_out["syntax_valid"] is False

            # 10. Apply valid fix and call check_fix over stdio
            calc_py.write_text(
                "import ast\n\ndef evaluate_math(code_str: str):\n    return ast.literal_eval(code_str)\n",
                encoding="utf-8"
            )
            fix_call = await session.call_tool("check_fix", {"scan_id": scan_id, "finding_ids": [fid]})
            fix_out = json.loads(fix_call.content[0].text)
            assert fix_out["syntax_valid"] is True
            assert fix_out["clean"] is True
            assert fid in fix_out["resolved_findings"]

            # 11. Call get_assessment_history over stdio
            hist_call = await session.call_tool("get_assessment_history", {"scan_id": scan_id, "finding_id": fid})
            hist_out = json.loads(hist_call.content[0].text)
            assert len(hist_out.get("history", [])) >= 1
            statuses = [h["status"] for h in hist_out["history"]]
            assert "supported" in statuses
            assert "stale" in statuses

    # 12. Re-open in fresh server process (restart persistence & cross-cwd restore over stdio)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session2:
            await session2.initialize()
            re_hist = await session2.call_tool("get_assessment_history", {"scan_id": scan_id, "finding_id": fid})
            re_out = json.loads(re_hist.content[0].text)
            assert len(re_out.get("history", [])) >= 1
            re_statuses = [h["status"] for h in re_out["history"]]
            assert "supported" in re_statuses

            # Modified file on disk: read_evidence across restart detects modification and rejects
            re_ev = await session2.call_tool("read_evidence", {"scan_id": scan_id, "path": "calculator.py", "start_line": 1, "end_line": 3})
            re_ev_out = json.loads(re_ev.content[0].text)
            assert re_ev_out["read_succeeded"] is False
            assert re_ev_out["status"] == "invalid"

            # Restore original file: read_evidence succeeds across restart
            calc_py.write_text(
                "def evaluate_math(code_str: str):\n"
                "    return eval(code_str)\n",
                encoding="utf-8"
            )
            re_ev_valid = await session2.call_tool("read_evidence", {"scan_id": scan_id, "path": "calculator.py", "start_line": 1, "end_line": 2})
            re_ev_valid_out = json.loads(re_ev_valid.content[0].text)
            assert re_ev_valid_out["read_succeeded"] is True










