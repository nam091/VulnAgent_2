"""Unit and integration tests for Semgrep runner rule engine and pack configurations.

Validates:
1. Flexible rule pack resolution:
   - Standard Semgrep registry packs: p/python, p/security-audit, p/owasp-top-ten
   - Preset aliases: 'standard', 'registry', 'owasp', 'owasp-top-ten', 'security-audit', 'python'
   - Comma-separated configs and string normalization
   - Offline mode resolving to rules/pinned_security_rules.yaml
   - Environment variables VULNAGENT_SEMGREP_RULES and VULNAGENT_OFFLINE
2. Vulnerability type resolution across all 14 focal CWE categories:
   - CWE-89 (SQL Injection)
   - CWE-78 (OS Command Injection)
   - CWE-79 (Cross-Site Scripting)
   - CWE-22 (Path Traversal)
   - CWE-94 (Code Injection)
   - CWE-502 (Insecure Deserialization)
   - CWE-90 (LDAP Injection)
   - CWE-643 (XPath Injection)
   - CWE-611 (XML External Entity - XXE)
   - CWE-330 (Insecure Randomness)
   - CWE-328 (Use of Weak Hashing Algorithm)
   - CWE-601 (Open Redirect)
   - CWE-614 (Insecure Cookie)
   - CWE-918 (Server-Side Request Forgery - SSRF)
3. End-to-end Semgrep execution using offline pinned rules on code samples.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from analyzer.semgrep_runner import (
    DEFAULT_CONFIGS,
    PINNED_RULES_PATH,
    STANDARD_REGISTRY_PACKS,
    SemgrepRunner,
    resolve_rule_configs,
)
from models.vulnerability import FindingSource, VulnerabilityType


class TestSemgrepConfigResolution:
    def test_default_configs_and_standard_packs(self):
        assert DEFAULT_CONFIGS == ("p/python", "p/security-audit")
        assert STANDARD_REGISTRY_PACKS == (
            "p/python",
            "p/security-audit",
            "p/owasp-top-ten",
        )
        assert SemgrepRunner.get_standard_packs() == STANDARD_REGISTRY_PACKS
        assert SemgrepRunner.get_pinned_rules_path() == PINNED_RULES_PATH
        assert PINNED_RULES_PATH.is_file()

    def test_resolve_standard_preset(self):
        resolved = resolve_rule_configs("standard")
        assert resolved == STANDARD_REGISTRY_PACKS

        resolved_reg = resolve_rule_configs("registry")
        assert resolved_reg == STANDARD_REGISTRY_PACKS

    def test_resolve_owasp_pack(self):
        assert resolve_rule_configs("owasp") == ("p/owasp-top-ten",)
        assert resolve_rule_configs("owasp-top-ten") == ("p/owasp-top-ten",)
        assert resolve_rule_configs("p/owasp-top-ten") == ("p/owasp-top-ten",)

    def test_resolve_comma_separated_packs(self):
        resolved = resolve_rule_configs("p/python, p/security-audit, p/owasp-top-ten")
        assert resolved == ("p/python", "p/security-audit", "p/owasp-top-ten")

    def test_resolve_offline_mode(self):
        resolved = resolve_rule_configs(offline=True)
        assert len(resolved) == 1
        assert resolved[0] == str(PINNED_RULES_PATH.resolve())

        resolved_pinned = resolve_rule_configs("pinned")
        assert resolved_pinned == (str(PINNED_RULES_PATH.resolve()),)

        resolved_offline = resolve_rule_configs("offline")
        assert resolved_offline == (str(PINNED_RULES_PATH.resolve()),)

    def test_env_rules_override(self):
        with patch.dict("os.environ", {"VULNAGENT_SEMGREP_RULES": "p/python,p/owasp-top-ten"}):
            runner = SemgrepRunner()
            assert runner.configs == ("p/python", "p/owasp-top-ten")

    def test_env_offline_override(self):
        with patch.dict("os.environ", {"VULNAGENT_OFFLINE": "1"}):
            runner = SemgrepRunner()
            assert runner.configs == (str(PINNED_RULES_PATH.resolve()),)


class TestSemgrepFourteenCWEMapping:
    FOCAL_CWES = [
        ("89", "python-sql-injection", VulnerabilityType.SQL_INJECTION),
        ("78", "python-insecure-subprocess-shell", VulnerabilityType.OS_COMMAND_INJECTION),
        ("79", "python-flask-render-template-string", VulnerabilityType.CROSS_SITE_SCRIPTING),
        ("22", "python-path-traversal-open", VulnerabilityType.PATH_TRAVERSAL),
        ("94", "python-insecure-eval", VulnerabilityType.CODE_INJECTION),
        ("502", "python-insecure-deserialization", VulnerabilityType.INSECURE_DESERIALIZATION),
        ("90", "python-ldap-injection", VulnerabilityType.LDAP_INJECTION),
        ("643", "python-xpath-injection", VulnerabilityType.XPATH_INJECTION),
        ("611", "python-xml-external-entity", VulnerabilityType.XML_EXTERNAL_ENTITY),
        ("330", "python-insecure-randomness", VulnerabilityType.SECURE_RANDOMNESS),
        ("328", "python-weak-hashing", VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM),
        ("601", "python-open-redirect", VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS),
        ("614", "python-insecure-cookie", VulnerabilityType.SECURE_COOKIE),
        ("918", "python-ssrf-requests", VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY),
    ]

    @pytest.mark.parametrize("cwe,rule_id,expected_type", FOCAL_CWES)
    def test_cwe_metadata_resolution(self, cwe: str, rule_id: str, expected_type: VulnerabilityType):
        """Authoritative CWE resolution."""
        res = SemgrepRunner._resolve_type(cwe, "generic.unrelated.check")
        assert res == expected_type, f"CWE-{cwe} did not resolve to {expected_type}"

    @pytest.mark.parametrize("cwe,rule_id,expected_type", FOCAL_CWES)
    def test_rule_id_exact_and_prefixed_resolution(self, cwe: str, rule_id: str, expected_type: VulnerabilityType):
        """Resolution via rule ID without CWE metadata (both bare and with namespace prefix)."""
        # Bare rule ID
        res_bare = SemgrepRunner._resolve_type("", rule_id)
        assert res_bare == expected_type, f"Bare rule {rule_id} did not resolve to {expected_type}"

        # Prefixed rule ID as emitted by Semgrep file scanner
        res_prefixed = SemgrepRunner._resolve_type("", f"rules.pinned_security_rules.{rule_id}")
        assert res_prefixed == expected_type, f"Prefixed rule {rule_id} did not resolve to {expected_type}"

    def test_xpath_injection_canonical_cwe(self):
        from analyzer.semgrep_runner import TYPE_TO_CANONICAL_CWE
        assert TYPE_TO_CANONICAL_CWE[VulnerabilityType.XPATH_INJECTION] == "643"

    def test_keyword_fallback_resolution(self):
        assert SemgrepRunner._resolve_type("", "rules.audit.user-xpath-query") == VulnerabilityType.XPATH_INJECTION
        assert SemgrepRunner._resolve_type("", "rules.audit.user-xxe-parse") == VulnerabilityType.XML_EXTERNAL_ENTITY
        assert SemgrepRunner._resolve_type("", "rules.crypto.md5-hash") == VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM
        assert SemgrepRunner._resolve_type("", "rules.web.open-redirect-handler") == VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS


class TestSemgrepOfflineRunnerE2E:
    def test_all_14_cwes_detected_by_pinned_rules(self, tmp_path: Path):
        """
        Integration test verifying that the pinned rules file triggers detections
        for all 14 focal CWEs against vulnerable code snippets.
        """
        code = (
            "import subprocess, os, pickle, ldap, requests, hashlib, random\n"
            "from flask import render_template_string, redirect, Response\n"
            "import xml.etree.ElementTree as ET\n"
            "\n"
            "def handle_request(user_input):\n"
            "    # 1. CWE-94 Code Injection\n"
            "    eval(user_input)\n"
            "\n"
            "    # 2. CWE-78 OS Command Injection\n"
            "    subprocess.call('ls ' + user_input, shell=True)\n"
            "\n"
            "    # 3. CWE-89 SQL Injection\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id = {user_input}')\n"
            "\n"
            "    # 4. CWE-79 XSS\n"
            "    render_template_string('Hello ' + user_input)\n"
            "\n"
            "    # 5. CWE-22 Path Traversal\n"
            "    open('/tmp/' + user_input)\n"
            "\n"
            "    # 6. CWE-502 Deserialization\n"
            "    pickle.loads(user_input)\n"
            "\n"
            "    # 7. CWE-90 LDAP Injection\n"
            "    ldap.search('dc=example,dc=com', user_input)\n"
            "\n"
            "    # 8. CWE-643 XPath Injection\n"
            "    tree = ET.parse('test.xml')\n"
            "    tree.xpath('//user[@id=' + user_input + ']')\n"
            "\n"
            "    # 9. CWE-611 XXE\n"
            "    ET.fromstring(user_input)\n"
            "\n"
            "    # 10. CWE-330 Insecure Randomness\n"
            "    token = random.randint(1000, 9999)\n"
            "\n"
            "    # 11. CWE-328 Weak Hashing\n"
            "    h = hashlib.md5(user_input.encode()).hexdigest()\n"
            "\n"
            "    # 12. CWE-601 Open Redirect\n"
            "    redirect(user_input)\n"
            "\n"
            "    # 13. CWE-614 Insecure Cookie\n"
            "    resp = Response('ok')\n"
            "    resp.set_cookie('session_id', '123', secure=False)\n"
            "\n"
            "    # 14. CWE-918 SSRF\n"
            "    requests.get('https://' + user_input)\n"
        )

        test_file = tmp_path / "vulnerable_app.py"
        test_file.write_text(code, encoding="utf-8")

        runner = SemgrepRunner(offline=True)
        findings = runner.scan(str(test_file))

        detected_types = {f.type for f in findings}
        detected_cwes = {f.cwe_id for f in findings}

        expected_types = {
            VulnerabilityType.CODE_INJECTION,
            VulnerabilityType.OS_COMMAND_INJECTION,
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.CROSS_SITE_SCRIPTING,
            VulnerabilityType.PATH_TRAVERSAL,
            VulnerabilityType.INSECURE_DESERIALIZATION,
            VulnerabilityType.LDAP_INJECTION,
            VulnerabilityType.XPATH_INJECTION,
            VulnerabilityType.XML_EXTERNAL_ENTITY,
            VulnerabilityType.SECURE_RANDOMNESS,
            VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
            VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
            VulnerabilityType.SECURE_COOKIE,
            VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
        }

        for expected in expected_types:
            assert expected in detected_types, f"Expected {expected.value} in findings, got {detected_types}"

        # Ensure findings carry SEMGREP source and real line context
        assert all(f.source == FindingSource.SEMGREP for f in findings)
        assert all(f.location.context for f in findings)
        assert all(f.location.start_line > 0 for f in findings)
