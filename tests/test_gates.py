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
