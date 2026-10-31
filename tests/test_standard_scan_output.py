import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from models.vulnerability import (
    CodeLocation,
    FindingSource,
    StandardFinding,
    StandardFindingOutput,
    StandardScanOutput,
    StandardTaintStep,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
    normalize_cwe,
    normalize_posix_path,
    normalize_source_label,
)
from cli import serialize_scan_output, _render
from main import _package, _enrich_taint_path


def _make_dummy_vuln(
    file_path: str = "src\\models\\vulnerability.py",
    v_type: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    cwe_id: str = "89",
    source: FindingSource = FindingSource.CONFIRMED,
) -> Vulnerability:
    return Vulnerability(
        type=v_type,
        severity=severity,
        location=CodeLocation(
            file_path=file_path,
            start_line=10,
            end_line=12,
            context="db.execute(query)",
        ),
        description="SQL injection in execute statement",
        impact="Data exfiltration",
        remediation="Use parameterized queries",
        cwe_id=cwe_id,
        owasp_category="A03:2021-Injection",
        cvss_score=8.5,
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        proof_of_concept="' OR 1=1 --",
        secure_code_example="db.execute('SELECT * FROM users WHERE id = %s', (uid,))",
        source=source,
        confidence=0.92,
        taint_path=[
            {
                "step": 1,
                "kind": "source",
                "file": file_path,
                "line": 5,
                "description": "User input read from query param",
                "code": "query = request.GET.get('id')",
            },
            {
                "step": "propagated through variable",
                "file": file_path,
                "line": 8,
                "kind": "propagation",
            },
        ],
    )


class DummyReport:
    def __init__(self, file_name: str, vulns, refuted=None):
        self.file_name = file_name
        self.vulnerabilities = vulns
        self.refuted_vulnerabilities = refuted or []
        self.chained_vulnerabilities = []
        self.status = "completed"
        self.tiers = {"rule": "ok", "llm": "ok"}
        self.engine_status = {}
        self.risk_score = 8.5
        self.degraded = False

    def model_dump(self, mode="json"):
        return {
            "file_name": self.file_name,
            "vulnerabilities": [v.model_dump() for v in self.vulnerabilities],
            "status": self.status,
            "risk_score": self.risk_score,
        }


class DummyScanResult:
    def __init__(self, reports, root=Path(".")):
        self.reports = reports
        self.root = root
        self.stats = {"scanned_files": len(reports), "duration_ms": 120}
        self.status = "completed"
        self.coverage = {"total": len(reports), "analyzed": len(reports)}

    @property
    def vulnerabilities(self):
        return [v for r in self.reports for v in r.vulnerabilities]

    @property
    def refuted_vulnerabilities(self):
        return [v for r in self.reports for v in r.refuted_vulnerabilities]

    @property
    def degraded(self):
        return any(r.degraded for r in self.reports)


def test_path_and_cwe_and_source_normalization():
    # POSIX path
    assert normalize_posix_path("foo\\bar\\baz.py") == "foo/bar/baz.py"
    assert normalize_posix_path("foo/bar/baz.py") == "foo/bar/baz.py"
    assert normalize_posix_path("") == ""

    # CWE
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe("CWE-89") == "CWE-89"
    assert normalize_cwe("cwe-79") == "CWE-cwe-79" or normalize_cwe("cwe-79") == "cwe-79"
    assert normalize_cwe("") == "CWE-Unknown"
    assert normalize_cwe(None) == "CWE-Unknown"

    # Source
    assert normalize_source_label(FindingSource.CONFIRMED) == "confirmed"
    assert normalize_source_label(FindingSource.SEMGREP) == "rule-only"
    assert normalize_source_label(FindingSource.LLM) == "llm-only"
    assert normalize_source_label("SEMGREP") == "rule-only"
    assert normalize_source_label("corroborated") == "confirmed"


def test_standard_taint_step_schema():
    step = StandardTaintStep(
        step=1,
        kind="source",
        file="backend\\api.py",
        line=14,
        description="User param",
        code="id = req.param('id')",
    )
    d = step.model_dump()
    assert d["step"] == 1
    assert d["kind"] == "source"
    assert d["file"] == "backend/api.py"
    assert d["line"] == 14
    assert d["description"] == "User param"
    assert d["code"] == "id = req.param('id')"

    # Step normalization when step is string or line is string
    step2 = StandardTaintStep.model_validate({
        "step": "sink executed",
        "file": "backend/api.py",
        "line": "42",
        "kind": "sink",
    })
    assert step2.step == 1
    assert step2.description == "sink executed"
    assert step2.line == 42


def test_standard_finding_output_from_vulnerability():
    vuln = _make_dummy_vuln()
    output = StandardFindingOutput.from_vulnerability(vuln)
    d = output.model_dump()

    assert d["id"] == vuln.id
    assert d["type"] == "SQL_INJECTION"
    assert d["cwe"] == "CWE-89"
    assert d["severity"] == "HIGH"
    assert d["file"] == "src/models/vulnerability.py"
    assert d["start_line"] == 10
    assert d["end_line"] == 12
    assert d["confidence"] == 0.92
    assert d["source"] == "confirmed"
    assert "SQL injection" in d["description"]
    assert d["snippet"] == "db.execute(query)"
    assert len(d["taint_path"]) == 2

    step1 = d["taint_path"][0]
    assert step1["step"] == 1
    assert step1["kind"] == "source"
    assert step1["file"] == "src/models/vulnerability.py"
    assert step1["line"] == 5
    assert step1["description"] == "User input read from query param"
    assert step1["code"] == "query = request.GET.get('id')"

    step2 = d["taint_path"][1]
    assert step2["step"] == 2
    assert step2["kind"] == "propagation"
    assert step2["line"] == 8
    assert step2["description"] == "propagated through variable"


def test_standard_scan_output_schema_validation():
    vuln = _make_dummy_vuln()
    finding_dict = StandardFindingOutput.from_vulnerability(vuln).model_dump()

    output = StandardScanOutput(
        schema_version="1.0.0",
        scanner="VulnAgent",
        timestamp=datetime.now().isoformat(),
        target="src/",
        options={"concurrency": 5},
        stats={"files": 1},
        files=[{"file": "src/models/vulnerability.py", "findings": 1}],
        findings=[finding_dict],
        refuted_findings=[],
        chains=[],
    )

    dumped = output.model_dump(mode="json")
    for key in (
        "schema_version",
        "scanner",
        "timestamp",
        "target",
        "options",
        "stats",
        "files",
        "findings",
        "refuted_findings",
        "chains",
    ):
        assert key in dumped

    # Verify findings item format
    f0 = dumped["findings"][0]
    for req_field in (
        "id", "type", "cwe", "severity", "file", "start_line", "end_line",
        "confidence", "source", "description", "snippet", "verification", "taint_path"
    ):
        assert req_field in f0, f"Missing required field {req_field} in finding"

    for step in f0["taint_path"]:
        for step_field in ("step", "kind", "file", "line", "description", "code"):
            assert step_field in step, f"Missing {step_field} in taint step"


def test_cli_serialize_scan_output():
    vuln = _make_dummy_vuln()
    rep = DummyReport("src/models/vulnerability.py", [vuln])
    result = DummyScanResult([rep], root=Path("."))

    import argparse
    args = argparse.Namespace(
        format="json",
        target="src/",
        verbose=False,
    )

    std_out = serialize_scan_output(result, args=args)
    assert isinstance(std_out, StandardScanOutput)
    assert std_out.schema_version == "1.0.0"
    assert std_out.scanner == "VulnAgent"
    assert len(std_out.findings) == 1
    assert std_out.findings[0]["cwe"] == "CWE-89"
    assert std_out.findings[0]["source"] == "confirmed"

    # Test _render with format == "json"
    json_rendered = _render(args, result)
    parsed = json.loads(json_rendered)

    assert parsed["schema_version"] == "1.0.0"
    assert parsed["scanner"] == "VulnAgent"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["type"] == "SQL_INJECTION"


def test_main_package_standard_scan_output():
    vuln = _make_dummy_vuln()
    rep = DummyReport("src/models/vulnerability.py", [vuln])
    result = DummyScanResult([rep], root=Path("."))

    pkg = _package(result)
    assert isinstance(pkg, dict)

    # Validate against StandardScanOutput
    validated = StandardScanOutput.model_validate(pkg)
    assert validated.schema_version == "1.0.0"
    assert validated.scanner == "VulnAgent"
    assert len(validated.findings) == 1
    assert validated.findings[0]["cwe"] == "CWE-89"
    assert validated.findings[0]["file"] == "src/models/vulnerability.py"

    # Verify compatibility fields for UI
    assert "status" in pkg
    assert "counts" in pkg
    assert "sources" in pkg
    assert "chains" in pkg
    assert "files" in pkg
    assert "risk_score" in pkg
    assert "stats" in pkg
    assert "degraded" in pkg


def test_enrich_taint_path():
    raw_path = [
        {"step": "user entry", "file": "src/models/vulnerability.py", "line": 10, "kind": "source"},
        {"step": 2, "file": "src\\models\\vulnerability.py", "line": 20, "description": "sink"},
    ]
    enriched = _enrich_taint_path(raw_path, "src/models/vulnerability.py")
    assert len(enriched) == 2
    assert enriched[0]["step"] == 1
    assert enriched[0]["kind"] == "source"
    assert enriched[0]["description"] == "user entry"
    assert enriched[0]["file"] == "src/models/vulnerability.py"

    assert enriched[1]["step"] == 2
    assert enriched[1]["kind"] == "step"
    assert enriched[1]["description"] == "sink"
    assert enriched[1]["file"] == "src/models/vulnerability.py"
