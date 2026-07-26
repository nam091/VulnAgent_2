"""Baselines, suppressions, patch safety, discovery and taint chaining.

These are the mechanisms that decide what a developer is shown and what gets
written to their files, so a defect here is either noise they will not
tolerate or a silent edit they did not ask for.
"""

from pathlib import Path

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
