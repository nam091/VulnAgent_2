"""Shared fixtures.

Every test here runs offline. Nothing in this suite may reach the network or
an LLM provider: a test that needs an API key is a test nobody runs.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from models.vulnerability import (  # noqa: E402
    CodeLocation,
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)


def make_vuln(
    vuln_type: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    file_path: str = "app.py",
    start_line: int = 10,
    end_line: Optional[int] = None,
    cwe_id: str = "CWE-89",
    context: str = "",
    source: FindingSource = FindingSource.LLM,
    description: str = "a finding",
    secure_code_example: str = "",
    taint_path: Optional[List[Dict[str, Any]]] = None,
    file_hash: Optional[str] = None,
) -> Vulnerability:
    """
    Build a Vulnerability with sensible defaults for tests.

    Args:
        vuln_type: Vulnerability type
        severity: Severity level
        file_path: Reported file
        start_line: First line
        end_line: Last line, defaults to start_line
        cwe_id: CWE identifier
        context: Code snippet
        source: Provenance
        description: Description text
        secure_code_example: Suggested rewrite
        taint_path: Traced dataflow path
        file_hash: Snapshot hash of analyzed file content

    Returns:
        Vulnerability: A populated finding
    """

    return Vulnerability(
        type=vuln_type,
        severity=severity,
        location=CodeLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line if end_line is not None else start_line,
            context=context,
        ),
        description=description,
        impact="impact",
        remediation="remediation",
        cwe_id=cwe_id,
        owasp_category="A03:2021 - Injection",
        cvss_score=7.5,
        references=[],
        proof_of_concept="",
        secure_code_example=secure_code_example,
        source=source,
        taint_path=taint_path or [],
        file_hash=file_hash,
    )


@pytest.fixture
def vuln_factory():
    """
    Expose make_vuln as a fixture.
    """

    return make_vuln


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """
    A small project tree with a vendored directory that must be skipped.

    Args:
        tmp_path: pytest temporary directory

    Returns:
        Path: The project root
    """

    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "from flask import request\n"
        "\n"
        "def run():\n"
        "    host = request.args.get('host')\n"
        "    return subprocess.check_output(f'ping {host}', shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "quiet.py").write_text("VALUE = 1\n", encoding="utf-8")

    vendored = tmp_path / "venv" / "lib"
    vendored.mkdir(parents=True)
    (vendored / "thirdparty.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")

    return tmp_path
