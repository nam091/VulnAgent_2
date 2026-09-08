"""Regression test suite for G1-G2 gates, MCP evidence flow, verifier citations,
and snapshot membership.
"""

from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from agent.loop import AgentRun
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
    verifier = VerificationAgent(client=None, model="test-model", root=tmp_path)
    app_file = tmp_path / "app.py"
    app_file.write_text("user_input = request.args.get('id')\nsafe_id = int(user_input)\n", encoding="utf-8")
    other_file = tmp_path / "other.py"
    other_file.write_text("DEBUG = True\n", encoding="utf-8")

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
    run_valid = AgentRun(
        text='{"verdict": "refuted", "mitigating_control": "uses int() cast", "evidence_file": "app.py", "evidence_line": 2}',
        tool_calls=1,
        successful_reads=[{"tool": "read_lines", "path": "app.py", "start_line": 1, "end_line": 2}]
    )
    with patch("agent.loop.ToolCallingAgent.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = run_valid
        verdict = await verifier.verify(vuln)
        assert verdict.verdict == "refuted"
        assert verdict.investigated is True


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
