"""Baselines, suppressions, patch safety, discovery and taint chaining.

These are the mechanisms that decide what a developer is shown and what gets
written to their files, so a defect here is either noise they will not
tolerate or a silent edit they did not ask for.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

import httpx
import openai

from conftest import make_vuln

from analyzer.baseline import Baseline, SuppressionIndex, gate
from analyzer.code_analyzer import CodeAnalyzer
from analyzer.discovery import discover, route_to_llm, score_risk
from analyzer.fixer import build_plan
from models.vulnerability import (
    FindingSource,
    VulnerabilitySeverity,
    VulnerabilityType,
)

SEVERITY_RANK = {
    VulnerabilitySeverity.CRITICAL: 0,
    VulnerabilitySeverity.HIGH: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 3,
    VulnerabilitySeverity.INFO: 4,
}


class TestBaseline:
    def test_round_trip(self, tmp_path: Path):
        path = str(tmp_path / "baseline.json")
        findings = [make_vuln(context="a"), make_vuln(context="b", start_line=20)]

        Baseline().save(path, findings)
        loaded = Baseline.load(path)

        new_findings, known = loaded.partition(findings)
        assert new_findings == []
        assert len(known) == 2

    def test_new_finding_is_new(self, tmp_path: Path):
        path = str(tmp_path / "baseline.json")
        Baseline().save(path, [make_vuln(context="original")])

        loaded = Baseline.load(path)
        new_findings, known = loaded.partition([
            make_vuln(context="original"),
            make_vuln(context="freshly introduced", start_line=99),
        ])
        assert len(new_findings) == 1
        assert len(known) == 1

    def test_missing_file_treats_everything_as_new(self, tmp_path: Path):
        loaded = Baseline.load(str(tmp_path / "absent.json"))
        new_findings, known = loaded.partition([make_vuln(context="a")])
        assert len(new_findings) == 1
        assert known == []

    def test_resolved_findings_are_reported(self, tmp_path: Path):
        path = str(tmp_path / "baseline.json")
        Baseline().save(path, [make_vuln(context="fixed"), make_vuln(context="still here")])

        loaded = Baseline.load(path)
        assert len(loaded.resolved([make_vuln(context="still here")])) == 1


class TestSuppression:
    def test_typed_directive_on_same_line(self):
        index = SuppressionIndex()
        index.load_file("app.py", "\n".join([
            "x = 1",
            "cursor.execute(q)  # vulnagent: ignore[SQL_INJECTION] constant query",
        ]))
        assert index.is_suppressed(make_vuln(start_line=2))

    def test_directive_on_line_above(self):
        index = SuppressionIndex()
        index.load_file("app.py", "\n".join([
            "# vulnagent: ignore[SQL_INJECTION]",
            "cursor.execute(q)",
        ]))
        assert index.is_suppressed(make_vuln(start_line=2))

    def test_typed_directive_does_not_waive_other_types(self):
        index = SuppressionIndex()
        index.load_file("app.py", "cursor.execute(q)  # vulnagent: ignore[PATH_TRAVERSAL]")
        assert not index.is_suppressed(
            make_vuln(start_line=1, vuln_type=VulnerabilityType.SQL_INJECTION)
        )

    def test_bare_directive_waives_everything_on_the_line(self):
        index = SuppressionIndex()
        index.load_file("app.py", "cursor.execute(q)  # vulnagent: ignore")
        assert index.is_suppressed(make_vuln(start_line=1))

    def test_file_level_directive(self):
        index = SuppressionIndex()
        index.load_file("app.py", "# vulnagent: ignore-file\nimport os\ncursor.execute(q)\n")
        assert index.is_suppressed(make_vuln(start_line=3))

    def test_foreign_markers_are_honoured(self):
        index = SuppressionIndex()
        index.load_file("app.py", "os.system(cmd)  # nosec")
        assert index.is_suppressed(make_vuln(start_line=1))

    def test_unmarked_code_is_not_suppressed(self):
        index = SuppressionIndex()
        index.load_file("app.py", "cursor.execute(q)\n")
        assert not index.is_suppressed(make_vuln(start_line=1))


class TestGate:
    def test_threshold_filters_by_severity(self):
        findings = [
            make_vuln(severity=VulnerabilitySeverity.CRITICAL, context="a"),
            make_vuln(severity=VulnerabilitySeverity.LOW, context="b"),
        ]
        breaching = gate(findings, SEVERITY_RANK[VulnerabilitySeverity.HIGH], SEVERITY_RANK)
        assert len(breaching) == 1

    def test_confirmed_only_excludes_llm_findings(self):
        """LLM-only findings fluctuate between runs, so letting them block a
        merge makes pipelines flap."""
        findings = [
            make_vuln(severity=VulnerabilitySeverity.CRITICAL, source=FindingSource.LLM, context="a"),
            make_vuln(severity=VulnerabilitySeverity.CRITICAL, source=FindingSource.CONFIRMED, context="b"),
        ]
        breaching = gate(
            findings, SEVERITY_RANK[VulnerabilitySeverity.HIGH], SEVERITY_RANK,
            confirmed_only=True
        )
        assert len(breaching) == 1
        assert breaching[0].source == FindingSource.CONFIRMED

    def test_disabled_gate_blocks_nothing(self):
        findings = [make_vuln(severity=VulnerabilitySeverity.CRITICAL, context="a")]
        assert gate(findings, None, SEVERITY_RANK) == []


class TestPatchSafety:
    def test_clean_substitution_is_safe(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            'def q(u):\n    cursor.execute("SELECT * FROM t WHERE u = \'%s\'" % u)\n',
            encoding="utf-8",
        )
        vuln = make_vuln(
            start_line=2,
            secure_code_example='cursor.execute("SELECT * FROM t WHERE u = ?", (u,))',
        )
        plan = build_plan([vuln], tmp_path)

        assert len(plan.patches) == 1
        assert plan.patches[0].risk == "safe"

    def test_placeholder_is_flagged_for_review(self, tmp_path: Path):
        """A rewrite that invents a path is not applicable code."""
        (tmp_path / "app.py").write_text("def r(f):\n    return open(f).read()\n", encoding="utf-8")
        vuln = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22", start_line=2,
            secure_code_example="ALLOWED = '/safe/dir'\nreturn open(ALLOWED).read()",
        )
        plan = build_plan([vuln], tmp_path)

        assert plan.patches[0].risk == "review"
        assert any("placeholder" in r for r in plan.patches[0].risk_reasons)

    def test_introduced_return_is_flagged(self, tmp_path: Path):
        """A replacement carrying its own return duplicates the one below."""
        (tmp_path / "app.py").write_text("def r(c):\n    x = run(c)\n    return x\n", encoding="utf-8")
        vuln = make_vuln(
            start_line=2,
            secure_code_example="return run_safely(c)",
        )
        plan = build_plan([vuln], tmp_path)
        assert any("return" in r for r in plan.patches[0].risk_reasons)

    def test_syntax_breaking_patch_is_rejected(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("def q(u):\n    execute(u)\n", encoding="utf-8")
        vuln = make_vuln(start_line=2, secure_code_example="def (((broken")
        plan = build_plan([vuln], tmp_path)

        assert plan.patches == []
        assert any("parse" in reason for _, reason in plan.rejected)

    def test_missing_suggestion_is_rejected(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        plan = build_plan([make_vuln(start_line=1, secure_code_example="")], tmp_path)
        assert plan.patches == []

    def test_overlapping_patches_do_not_both_apply(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
        first = make_vuln(start_line=1, end_line=3, context="one", secure_code_example="a = 0")
        second = make_vuln(start_line=2, context="two", secure_code_example="b = 0")
        plan = build_plan([first, second], tmp_path)

        assert len(plan.patches) == 1
        assert any("overlap" in reason for _, reason in plan.rejected)


class TestDiscovery:
    def test_vendored_directories_are_skipped(self, tmp_project: Path):
        found = {f.relative for f in discover(str(tmp_project))}
        assert "app.py" in found
        assert not any("venv" in name for name in found)

    def test_test_and_doc_directories_are_skipped(self, tmp_project: Path):
        for dirname in ("tests", "test", "testing", "fixtures", "docs", "site", "example", "examples"):
            subdir = tmp_project / dirname
            subdir.mkdir(parents=True, exist_ok=True)
            (subdir / "sample.py").write_text("import os\nos.system('echo')\n", encoding="utf-8")

        found = {f.relative for f in discover(str(tmp_project))}
        assert "app.py" in found
        for dirname in ("tests", "test", "testing", "fixtures", "docs", "site", "example", "examples"):
            assert not any(dirname in name for name in found)

    def test_direct_scan_into_test_directory_discovers_files(self, tmp_project: Path):
        tests_dir = tmp_project / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_sample.py").write_text("import os\nos.system('echo')\n", encoding="utf-8")

        found = {f.relative for f in discover(str(tests_dir))}
        assert "test_sample.py" in found

    def test_risk_scoring_separates_dangerous_from_dull(self, tmp_project: Path):
        risky, _ = score_risk((tmp_project / "app.py").read_text(encoding="utf-8"))
        dull, _ = score_risk((tmp_project / "quiet.py").read_text(encoding="utf-8"))
        assert risky > dull

    def test_routing_selects_risky_files(self, tmp_project: Path):
        files = discover(str(tmp_project))
        routed = {f.relative for f in route_to_llm(files, min_risk=3)}
        assert "app.py" in routed
        assert "quiet.py" not in routed

    def test_rule_hits_force_routing_of_a_dull_file(self):
        """A file the rule tier flagged must reach the LLM even if its own
        signals look boring, or the explanation never gets written."""
        from analyzer.discovery import DiscoveredFile

        dull = DiscoveredFile(Path("quiet.py"), Path("."), risk_score=0, reasons=[])
        assert route_to_llm([dull], rule_hits={"quiet.py": 1}, min_risk=3) == [dull]

    def test_new_risk_signals_detection(self):
        # 1. html component output
        s, r = score_risk("div_out = render_output('<div class=\"user\">' + name + '</div>')")
        assert "html component output" in r
        assert s >= 3

        # 2. custom deserialization
        s, r = score_risk("obj = pcrypt.loads(raw_data)")
        assert "custom deserialization" in r
        assert s >= 4

        # 3. ldap/xpath query
        s, r = score_risk("entries = conn.search_s(base, ldap.SCOPE_SUBTREE, filter_str)")
        assert "ldap/xpath query" in r
        assert s >= 3

        # 4. cookie security
        s, r = score_risk("resp.set_cookie('session_id', val, secure=False)")
        assert "cookie security" in r
        assert s >= 3

    def test_ast_sink_files_forces_routing_of_dull_file(self):
        from analyzer.discovery import DiscoveredFile

        dull = DiscoveredFile(Path("sink_file.py"), Path("."), risk_score=0, reasons=[])
        res = route_to_llm([dull], rule_hits={}, min_risk=3, ast_sink_files={"sink_file.py"})
        assert res == [dull]

    def test_scanner_ast_sink_detection_and_routing(self, tmp_path: Path):
        from analyzer.scanner import ScanOptions, Scanner
        from analyzer.discovery import discover

        target_file = tmp_path / "sink_demo.py"
        target_file.write_text("import sqlite3\ndef query(x):\n    c.execute(x)\n", encoding="utf-8")
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("X = 1\n", encoding="utf-8")

        files = discover(str(tmp_path))
        scanner = Scanner(ScanOptions(target=str(tmp_path), min_risk=10, use_ast_slicer=True))
        sink_files = scanner._find_ast_sink_files(files)
        assert "sink_demo.py" in sink_files
        assert "safe.py" not in sink_files

        # When use_ast_slicer=True, sink_demo.py is routed despite min_risk=10
        routed_slicer = route_to_llm(files, min_risk=10, ast_sink_files=sink_files)
        routed_names = {f.relative for f in routed_slicer}
        assert "sink_demo.py" in routed_names
        assert "safe.py" not in routed_names

        # When use_ast_slicer=False, sink_demo.py is not routed
        routed_no_slicer = route_to_llm(files, min_risk=10, ast_sink_files=set())
        assert not any(f.relative == "sink_demo.py" for f in routed_no_slicer)

    def test_scanner_deep_verify_routes_all_files(self, tmp_path: Path):
        from analyzer.scanner import ScanOptions, Scanner
        from analyzer.discovery import discover

        f1 = tmp_path / "a.py"
        f1.write_text("A = 1\n", encoding="utf-8")
        f2 = tmp_path / "b.py"
        f2.write_text("B = 2\n", encoding="utf-8")

        files = discover(str(tmp_path))
        scanner = Scanner(ScanOptions(target=str(tmp_path), min_risk=10, verify=True))
        effective_min_risk = 0 if getattr(scanner.options, "verify", False) else scanner.options.min_risk
        routed = route_to_llm(files, min_risk=effective_min_risk)
        assert len(routed) == 2

    @pytest.mark.asyncio
    async def test_scanner_scan_routes_ast_sinks_to_llm(self, tmp_path: Path):
        from analyzer.scanner import ScanOptions, Scanner

        sink_file = tmp_path / "sink.py"
        sink_file.write_text("def do_cmd(c):\n    subprocess.Popen(c, shell=True)\n", encoding="utf-8")
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("x = 1\n", encoding="utf-8")

        opts = ScanOptions(target=str(tmp_path), min_risk=10, use_semgrep=False, use_llm=True, use_ast_slicer=True)
        scanner = Scanner(opts)
        routed_files = []

        async def fake_llm_tier(routed):
            routed_files.extend([f.relative for f in routed])
            return {}, {}

        scanner._run_llm_tier = fake_llm_tier
        await scanner.scan()

        assert "sink.py" in routed_files
        assert "safe.py" not in routed_files


class TestTaintChaining:
    def setup_method(self):
        self.analyzer = CodeAnalyzer(use_semgrep=False)

    def test_shared_source_links_two_findings(self):
        first = make_vuln(start_line=17, taint_path=[
            {"file": "app.py", "line": 10, "kind": "source"},
            {"file": "app.py", "line": 17, "kind": "sink"},
        ])
        second = make_vuln(
            vuln_type=VulnerabilityType.CROSS_SITE_SCRIPTING, cwe_id="CWE-79", start_line=25,
            taint_path=[
                {"file": "app.py", "line": 10, "kind": "source"},
                {"file": "app.py", "line": 25, "kind": "sink"},
            ],
        )
        assert self.analyzer._check_data_flow_relationship(first, second)

    def test_disjoint_paths_are_unrelated(self):
        first = make_vuln(taint_path=[{"file": "app.py", "line": 10, "kind": "sink"}])
        second = make_vuln(
            file_path="other.py", taint_path=[{"file": "other.py", "line": 90, "kind": "sink"}]
        )
        assert not self.analyzer._check_data_flow_relationship(first, second)

    def test_sink_feeding_another_path_links_them(self):
        first = make_vuln(taint_path=[{"file": "app.py", "line": 30, "kind": "sink"}])
        second = make_vuln(
            vuln_type=VulnerabilityType.CSRF, cwe_id="CWE-352",
            taint_path=[
                {"file": "app.py", "line": 30, "kind": "source"},
                {"file": "app.py", "line": 44, "kind": "sink"},
            ],
        )
        assert self.analyzer._check_data_flow_relationship(first, second)


class TestScannerIsolation:
    def test_cache_counters_are_per_scan(self):
        """These were class attributes, so in the web server - one process,
        many scans - every result carried the running total of every scan
        before it."""
        from analyzer.scanner import ScanOptions, Scanner

        first = Scanner(ScanOptions(target="examples"))
        second = Scanner(ScanOptions(target="examples"))
        first._cache_hits += 3
        first._cache_misses += 2

        assert second._cache_hits == 0
        assert second._cache_misses == 0

    def test_rule_error_starts_clear(self):
        from analyzer.scanner import ScanOptions, Scanner

        assert Scanner(ScanOptions(target="examples"))._rule_error == ""


class TestJobStore:
    def test_nonsense_limit_never_slices_from_the_wrong_end(self, tmp_path):
        """A negative limit reached list()[:limit] and returned everything
        *except* the newest few, which read as 'no scans' while scans
        existed. The guarantee is that whatever comes back is a prefix of
        newest-first order, never a slice off the far end."""
        from jobs import JobStore

        store = JobStore(directory=tmp_path / "jobs")
        for i in range(3):
            store.create(kind="snippet", label=f"job {i}", options={})

        newest = store.list(limit=3)[0].label
        for bad in (-5, 0):
            result = store.list(limit=bad)
            assert result, f"limit={bad} returned nothing"
            assert result[0].label == newest, f"limit={bad} skipped the newest job"

        assert len(store.list(limit=2)) == 2

    def test_interrupted_jobs_are_marked_failed_on_reload(self, tmp_path):
        """A job left running when the process died did not survive it, and
        must not reappear as perpetually in-progress."""
        from jobs import JobStore

        directory = tmp_path / "jobs"
        store = JobStore(directory=directory)
        job = store.create(kind="snippet", label="interrupted", options={})
        store.update(job, status="running")

        reloaded = JobStore(directory=directory).get(job.id)
        assert reloaded.status == "failed"
        assert "restart" in reloaded.error.lower()


class TestStreamParameterCompat:
    """Verifies that 9router / OpenAI-compatible endpoints receive stream=False explicitly."""

    @pytest.mark.asyncio
    async def test_ai_client_analyze_with_openai_passes_stream_false(self):
        from utils.ai_client import AIClient

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message = MagicMock(content='{"vulnerabilities": []}')
        mock_choice.finish_reason = "stop"
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        client_wrapper = AIClient(disabled=True)
        res = await client_wrapper._analyze_with_openai(
            client=mock_client,
            prompt="def test(): pass",
            model="test-model",
        )

        mock_client.chat.completions.create.assert_called_once()
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert "stream" in kwargs
        assert kwargs["stream"] is False
        # OpenAI-compatible responses now carry diagnostic metadata alongside findings.
        assert set(res) == {"vulnerabilities", "_trace"}
        assert res["vulnerabilities"] == []
        assert res["_trace"]["raw_content"] == '{"vulnerabilities": []}'
        assert set(res["_trace"]["usage"]) == {"prompt_tokens", "completion_tokens", "thinking_tokens", "total_tokens"}

    @pytest.mark.asyncio
    async def test_ai_client_analyze_with_openai_retry_preserves_stream_false(self):
        from utils.ai_client import AIClient

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message = MagicMock(content='{"vulnerabilities": []}')
        mock_choice.finish_reason = "stop"
        mock_response.choices = [mock_choice]

        req = httpx.Request("POST", "http://test")
        resp = httpx.Response(400, request=req)
        mock_client.chat.completions.create.side_effect = [
            openai.BadRequestError("temperature not supported", response=resp, body=None),
            mock_response,
        ]

        client_wrapper = AIClient(disabled=True)
        res = await client_wrapper._analyze_with_openai(
            client=mock_client,
            prompt="def test(): pass",
            model="custom-reasoner",
        )

        assert mock_client.chat.completions.create.call_count == 2
        for call in mock_client.chat.completions.create.call_args_list:
            assert call.kwargs.get("stream") is False
        # Retry also retains the successful response's diagnostic trace.
        assert set(res) == {"vulnerabilities", "_trace"}
        assert res["vulnerabilities"] == []
        assert res["_trace"]["raw_content"] == '{"vulnerabilities": []}'
        assert set(res["_trace"]["usage"]) == {"prompt_tokens", "completion_tokens", "thinking_tokens", "total_tokens"}

    @pytest.mark.asyncio
    async def test_tool_calling_agent_complete_passes_stream_false(self):
        from agent.loop import ToolCallingAgent

        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message = MagicMock(content="Analysis complete.")
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        agent = ToolCallingAgent(
            client=mock_client,
            model="test-model",
            dispatch=lambda *a: {},
            tool_schemas=[],
        )

        msg = await agent._complete(
            messages=[{"role": "user", "content": "analyze code"}],
            with_tools=False,
        )

        mock_client.chat.completions.create.assert_called_once()
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert "stream" in kwargs
        assert kwargs["stream"] is False
        assert msg.content == "Analysis complete."

    @pytest.mark.asyncio
    async def test_tool_calling_agent_complete_retry_preserves_stream_false(self):
        from agent.loop import ToolCallingAgent

        mock_client = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message = MagicMock(content="Retry succeeded.")
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        mock_client.chat.completions.create.side_effect = [
            Exception("temperature parameter is not supported by this model"),
            mock_response,
        ]

        agent = ToolCallingAgent(
            client=mock_client,
            model="test-model",
            dispatch=lambda *a: {},
            tool_schemas=[],
            temperature=0.2,
        )

        msg = await agent._complete(
            messages=[{"role": "user", "content": "analyze code"}],
            with_tools=False,
        )

        assert mock_client.chat.completions.create.call_count == 2
        for call in mock_client.chat.completions.create.call_args_list:
            assert call.kwargs.get("stream") is False
        assert msg.content == "Retry succeeded."

