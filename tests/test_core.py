"""Fingerprints, fusion and the rule-tier mapping.

These cover the invariants everything downstream depends on: that a finding
keeps the same identity across runs, that agreement between tiers is
recognised, and that a correct detection is not mislabelled because an
engine reported an unhelpful CWE.
"""

from conftest import make_vuln

from analyzer import fusion
from analyzer.semgrep_runner import SemgrepRunner
from models.vulnerability import (
    FindingSource,
    VulnerabilitySeverity,
    VulnerabilityType,
)


class TestFingerprint:
    def test_is_stable_across_instances(self):
        a = make_vuln(context="cursor.execute(sql)")
        b = make_vuln(context="cursor.execute(sql)")
        assert a.id == b.id

    def test_survives_line_shift(self):
        """An edit above a defect must not change its identity, or every
        baseline and suppression breaks on an unrelated change."""
        a = make_vuln(start_line=10, context="cursor.execute(sql)")
        b = make_vuln(start_line=42, context="cursor.execute(sql)")
        assert a.id == b.id

    def test_ignores_whitespace_reformatting(self):
        a = make_vuln(context="cursor.execute( sql )")
        b = make_vuln(context="cursor.execute(   sql   )")
        assert a.id == b.id

    def test_differs_by_type(self):
        a = make_vuln(vuln_type=VulnerabilityType.SQL_INJECTION, context="x")
        b = make_vuln(vuln_type=VulnerabilityType.PATH_TRAVERSAL, context="x")
        assert a.id != b.id

    def test_differs_by_file(self):
        a = make_vuln(file_path="a.py", context="x")
        b = make_vuln(file_path="b.py", context="x")
        assert a.id != b.id

    def test_falls_back_to_line_without_snippet(self):
        a = make_vuln(start_line=10, context="")
        b = make_vuln(start_line=11, context="")
        assert a.id != b.id


class TestFusion:
    def test_agreement_produces_confirmed(self):
        rule = make_vuln(source=FindingSource.SEMGREP, start_line=17, context="rule snippet")
        llm = make_vuln(source=FindingSource.LLM, start_line=17)
        result = fusion.fuse([rule], [llm])

        assert len(result.vulnerabilities) == 1
        merged = result.vulnerabilities[0]
        assert merged.source == FindingSource.CONFIRMED
        assert merged.confidence > 0.9

    def test_confirmed_takes_rule_position_and_llm_prose(self):
        """The rule engine has the exact line; only the LLM writes usable
        remediation. A merged finding must take each from the right side."""
        rule = make_vuln(source=FindingSource.SEMGREP, start_line=17, context="exact")
        llm = make_vuln(source=FindingSource.LLM, start_line=13, description="why it matters")
        merged = fusion.fuse([rule], [llm]).vulnerabilities[0]

        assert merged.location.start_line == 17
        assert merged.description == "why it matters"

    def test_llm_only_survives(self):
        """The rule tier missing a defect must not delete it - this is the
        hardcoded-credentials case the architecture exists for."""
        llm = make_vuln(vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS, cwe_id="CWE-798")
        result = fusion.fuse([], [llm])

        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].source == FindingSource.LLM

    def test_distant_findings_do_not_merge(self):
        rule = make_vuln(source=FindingSource.SEMGREP, start_line=10, context="a")
        llm = make_vuln(source=FindingSource.LLM, start_line=90)
        assert len(fusion.fuse([rule], [llm]).vulnerabilities) == 2

    def test_different_types_do_not_merge(self):
        rule = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.SEMGREP, context="a"
        )
        llm = make_vuln(vuln_type=VulnerabilityType.WEAK_CRYPTOGRAPHY, cwe_id="CWE-327")
        assert len(fusion.fuse([rule], [llm]).vulnerabilities) == 2

    def test_aliased_types_do_merge(self):
        rule = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22",
            source=FindingSource.SEMGREP, context="a"
        )
        llm = make_vuln(vuln_type=VulnerabilityType.INSECURE_FILE_READ, cwe_id="CWE-22")
        assert len(fusion.fuse([rule], [llm]).vulnerabilities) == 1

    def test_intra_tier_duplicates_collapse(self):
        """One defect reported twice under two names must not become two
        findings - observed with PATH_TRAVERSAL and INSECURE_FILE_READ."""
        a = make_vuln(vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22", start_line=31)
        b = make_vuln(vuln_type=VulnerabilityType.INSECURE_FILE_READ, cwe_id="CWE-22", start_line=31)
        assert len(fusion.fuse([], [a, b]).vulnerabilities) == 1

    def test_more_severe_wins_on_merge(self):
        rule = make_vuln(
            severity=VulnerabilitySeverity.CRITICAL,
            source=FindingSource.SEMGREP, context="a"
        )
        llm = make_vuln(severity=VulnerabilitySeverity.LOW)
        merged = fusion.fuse([rule], [llm]).vulnerabilities[0]
        assert merged.severity == VulnerabilitySeverity.CRITICAL

    def test_stats_count_each_provenance(self):
        result = fusion.fuse(
            [make_vuln(source=FindingSource.SEMGREP, file_path="x.py", context="a")],
            [make_vuln(file_path="y.py", vuln_type=VulnerabilityType.CSRF, cwe_id="CWE-352")],
        )
        assert result.stats["TOTAL"] == 2
        assert result.stats["SEMGREP"] == 1
        assert result.stats["LLM"] == 1

    def test_empty_input(self):
        assert fusion.fuse([], []).vulnerabilities == []

    def test_suppress_unconfirmed_rules_when_file_analyzed_by_llm(self):
        """When suppress_unconfirmed_rules=True and file_analyzed_by_llm=True,
        unconfirmed rule findings are discarded."""
        rule_unconfirmed = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.SEMGREP, start_line=10, context="rule"
        )
        rule_confirmed = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22",
            source=FindingSource.SEMGREP, start_line=20, context="rule2"
        )
        llm_match = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22",
            source=FindingSource.LLM, start_line=20
        )
        llm_only = make_vuln(
            vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS, cwe_id="CWE-798",
            source=FindingSource.LLM, start_line=50
        )

        result = fusion.fuse(
            [rule_unconfirmed, rule_confirmed],
            [llm_match, llm_only],
            suppress_unconfirmed_rules=True,
            file_analyzed_by_llm=True,
        )

        assert len(result.vulnerabilities) == 2
        sources = {v.source for v in result.vulnerabilities}
        assert sources == {FindingSource.CONFIRMED, FindingSource.LLM}
        types = {v.type for v in result.vulnerabilities}
        assert VulnerabilityType.SQL_INJECTION not in types

    def test_keep_unconfirmed_rules_when_file_not_analyzed_by_llm(self):
        """When suppress_unconfirmed_rules=True but file_analyzed_by_llm=False,
        rule findings are preserved because LLM never inspected the file."""
        rule = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.SEMGREP, start_line=10, context="rule"
        )
        result = fusion.fuse(
            [rule],
            [],
            suppress_unconfirmed_rules=True,
            file_analyzed_by_llm=False,
        )
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].source == FindingSource.SEMGREP

    def test_default_suppress_unconfirmed_rules_false_preserves_semgrep(self):
        """Default suppress_unconfirmed_rules=False preserves backwards compatibility."""
        rule = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.SEMGREP, start_line=10, context="rule"
        )
        result = fusion.fuse(
            [rule],
            [],
            suppress_unconfirmed_rules=False,
            file_analyzed_by_llm=True,
        )
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].source == FindingSource.SEMGREP

    def test_agreement_produces_confirmed_with_confidence_098(self):
        """Tier agreement creates a CONFIRMED finding with confidence 0.98,
        Semgrep exact position, and LLM explanation prose."""
        rule = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.SEMGREP, start_line=42, context="cursor.execute(sql)"
        )
        rule.rule_id = "rules.python-sql-injection"
        llm = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION, cwe_id="CWE-89",
            source=FindingSource.LLM, start_line=40,
            description="User-controlled string directly formatted into SQL query",
            secure_code_example="cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"
        )
        result = fusion.fuse([rule], [llm])
        assert len(result.vulnerabilities) == 1
        merged = result.vulnerabilities[0]
        assert merged.source == FindingSource.CONFIRMED
        assert merged.confidence == 0.98
        assert merged.location.start_line == 42
        assert merged.description == "User-controlled string directly formatted into SQL query"
        assert merged.secure_code_example == "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))"

    def test_suppress_generic_path_traversal_on_os_path_join(self):
        """Generic path traversal warnings (e.g. CWE-22, os.path.join) are suppressed
        to prevent false positive inflation when unconfirmed by LLM."""
        generic_path_rule = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL, cwe_id="CWE-22",
            severity=VulnerabilitySeverity.MEDIUM, source=FindingSource.SEMGREP,
            start_line=25, context="os.path.join(base_dir, user_file)"
        )
        generic_path_rule.rule_id = "rules.python-path-traversal-open"

        # LLM analyzed the file and found an unrelated issue, not path traversal
        llm_other = make_vuln(
            vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS, cwe_id="CWE-798",
            source=FindingSource.LLM, start_line=80
        )

        result = fusion.fuse(
            [generic_path_rule],
            [llm_other],
            suppress_unconfirmed_rules=True,
            file_analyzed_by_llm=True,
        )
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].source == FindingSource.LLM
        assert result.vulnerabilities[0].type == VulnerabilityType.HARDCODED_CREDENTIALS

    def test_preserve_reliable_high_risk_semgrep_rule_when_unconfirmed(self):
        """Specific reliable high-risk rules (CRITICAL/HIGH specific rule_id)
        are kept as SEMGREP even if unconfirmed by LLM to protect recall."""
        reliable_rule = make_vuln(
            vuln_type=VulnerabilityType.OS_COMMAND_INJECTION, cwe_id="CWE-78",
            severity=VulnerabilitySeverity.CRITICAL, source=FindingSource.SEMGREP,
            start_line=50, context="subprocess.run(cmd, shell=True)"
        )
        reliable_rule.rule_id = "rules.python-insecure-subprocess-shell"

        result = fusion.fuse(
            [reliable_rule],
            [],
            suppress_unconfirmed_rules=True,
            file_analyzed_by_llm=True,
        )
        assert len(result.vulnerabilities) == 1
        kept = result.vulnerabilities[0]
        assert kept.source == FindingSource.SEMGREP
        assert kept.confidence == 0.90
        assert kept.rule_id == "rules.python-insecure-subprocess-shell"

    def test_preserve_llm_only_findings_full_recall(self):
        """All LLM findings without Semgrep rules are preserved to guarantee
        100% Recall for logic flaws, auth issues, and exposed secrets."""
        llm1 = make_vuln(
            vuln_type=VulnerabilityType.HARDCODED_CREDENTIALS, cwe_id="CWE-798",
            source=FindingSource.LLM, start_line=15
        )
        llm2 = make_vuln(
            vuln_type=VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY, cwe_id="CWE-918",
            source=FindingSource.LLM, start_line=30
        )
        llm3 = make_vuln(
            vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION, cwe_id="CWE-502",
            source=FindingSource.LLM, start_line=45
        )

        result = fusion.fuse(
            [],
            [llm1, llm2, llm3],
            suppress_unconfirmed_rules=True,
            file_analyzed_by_llm=True,
        )
        assert len(result.vulnerabilities) == 3
        assert all(v.source == FindingSource.LLM for v in result.vulnerabilities)
        assert {v.cwe_id for v in result.vulnerabilities} == {"CWE-798", "CWE-918", "CWE-502"}


class TestRuleTierMapping:
    def test_wrong_cwe_metadata_is_corrected(self):
        """Semgrep reports tainted-sql-string as CWE-704. Resolving the type
        from the rule id must also fix the CWE, or fusion matches on a wrong
        key and reports mislead."""
        resolved = SemgrepRunner._resolve_type("704", "python.flask.security.tainted-sql-string")
        assert resolved == VulnerabilityType.SQL_INJECTION

    def test_known_cwe_wins(self):
        resolved = SemgrepRunner._resolve_type("89", "some.unhelpful.rule.name")
        assert resolved == VulnerabilityType.SQL_INJECTION

    def test_unmappable_rule_returns_none(self):
        assert SemgrepRunner._resolve_type("", "totally.unrelated.style.check") is None

    def test_cwe_number_extraction(self):
        assert SemgrepRunner._first_cwe_number(
            ["CWE-89: Improper Neutralization of Special Elements"]
        ) == "89"
        assert SemgrepRunner._first_cwe_number([]) == ""

    def test_overlapping_findings_deduplicate(self):
        """Three rules fire on one subprocess call; that is one defect."""
        findings = [
            make_vuln(
                vuln_type=VulnerabilityType.OS_COMMAND_INJECTION, cwe_id="CWE-78",
                start_line=38, context=f"rule {i}", source=FindingSource.SEMGREP
            )
            for i in range(3)
        ]
        for index, finding in enumerate(findings):
            finding.rule_id = f"rule-{index}"

        kept = SemgrepRunner._deduplicate(findings)
        assert len(kept) == 1
        assert len(kept[0].merged_rule_ids) == 3

    def test_distinct_lines_are_kept(self):
        findings = [
            make_vuln(
                vuln_type=VulnerabilityType.OS_COMMAND_INJECTION, cwe_id="CWE-78",
                start_line=line, context=f"line {line}", source=FindingSource.SEMGREP
            )
            for line in (10, 50)
        ]
        assert len(SemgrepRunner._deduplicate(findings)) == 2
