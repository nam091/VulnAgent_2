"""Unit tests for taint path enrichment with code snippets and metadata."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.verifier import Verdict, VerificationAgent
from analyzer.code_analyzer import CodeAnalyzer
from analyzer.scanner import Scanner, ScanOptions, ScanResult
from evidence.safe_reader import SafeReader, enrich_taint_path, read_code_snippet
from models.vulnerability import (
    CodeLocation,
    FindingSource,
    Vulnerability,
    VulnerabilityReport,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from reporters import console
from tests.conftest import make_vuln


class MockFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class MockToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = MockFunction(name, arguments)


class MockMessage:
    def __init__(self, content: str = None, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class MockChoice:
    def __init__(self, message: MockMessage) -> None:
        self.message = message


class MockResponse:
    def __init__(self, message: MockMessage) -> None:
        self.choices = [MockChoice(message)]


def test_read_code_snippet_from_disk(tmp_path: Path):
    """Ensure read_code_snippet accurately reads lines with numbering and '>' indicator."""
    code_file = tmp_path / "app.py"
    code_file.write_text(
        "import os\n"
        "from flask import request\n"
        "\n"
        "def run_command():\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )

    # Read line 5 (cmd = ...) with 2 context lines (lines 3-7)
    snippet = read_code_snippet(code_file, 5, root_dir=tmp_path, context_lines=2)
    assert snippet
    lines = snippet.splitlines()
    assert len(lines) == 5
    # Line 5 must be marked with '>'
    assert any(">    5 |     cmd = request.args.get('cmd')" in l for l in lines)
    # Surrounding lines must have blank marker
    assert any("     4 | def run_command():" in l for l in lines)
    assert any("     6 |     os.system(cmd)" in l for l in lines)

    # Test edge line 1
    snippet_start = read_code_snippet(code_file, 1, root_dir=tmp_path, context_lines=1)
    assert snippet_start.splitlines()[0].startswith(">    1 | import os")

    # SafeReader instance method test
    reader = SafeReader(tmp_path)
    sr_snippet = reader.read_code_snippet("app.py", 5, context_lines=2)
    assert sr_snippet == snippet

    # Invalid line numbers return empty string
    assert read_code_snippet(code_file, None) == ""
    assert read_code_snippet(code_file, 0) == ""
    assert read_code_snippet(code_file, -5) == ""
    assert read_code_snippet(tmp_path / "missing.py", 5) == ""


def test_read_code_snippet_fallback_content():
    """Ensure in-memory fallback_content is extracted when file is not on disk."""
    content = "a = 1\nb = 2\nc = a + b\nprint(c)\n"
    snippet = read_code_snippet("nonexistent.py", 3, fallback_content=content, context_lines=1)
    assert snippet
    lines = snippet.splitlines()
    assert len(lines) == 3
    assert ">    3 | c = a + b" in lines[1]
    assert "     2 | b = 2" in lines[0]
    assert "     4 | print(c)" in lines[2]


def test_enrich_taint_path_normalization_and_code(tmp_path: Path):
    """Verify enrich_taint_path standardizes metadata and attaches code from disk."""
    target_file = tmp_path / "handler.py"
    target_file.write_text(
        "def handle(req):\n"
        "    raw = req.get('input')\n"
        "    validated = check(raw)\n"
        "    execute(validated)\n",
        encoding="utf-8",
    )

    raw_taint = [
        {"step": "source input", "file": str(target_file), "line": 2},
        {"step": "propagation step", "kind": "propagator", "file": "handler.py", "line": 3},
        {"step": 3, "description": "sink execution", "kind": "sink", "file": "handler.py", "line": 4},
    ]

    enriched = enrich_taint_path(raw_taint, default_file="handler.py", root_dir=tmp_path, infer_kind=True)
    assert len(enriched) == 3

    # Step 1: inferred kind "source", int step 1, description preserved
    assert enriched[0]["step"] == 1
    assert enriched[0]["kind"] == "source"
    assert enriched[0]["description"] == "source input"
    assert enriched[0]["line"] == 2
    assert ">    2 |     raw = req.get('input')" in enriched[0]["code"]

    # Step 2: kind normalized from "propagator" to "propagation"
    assert enriched[1]["step"] == 2
    assert enriched[1]["kind"] == "propagation"
    assert enriched[1]["description"] == "propagation step"
    assert enriched[1]["line"] == 3
    assert ">    3 |     validated = check(raw)" in enriched[1]["code"]

    # Step 3: kind "sink"
    assert enriched[2]["step"] == 3
    assert enriched[2]["kind"] == "sink"
    assert enriched[2]["description"] == "sink execution"
    assert enriched[2]["line"] == 4
    assert ">    4 |     execute(validated)" in enriched[2]["code"]


def test_enrich_taint_path_from_successful_reads():
    """Verify code and evidence_id extraction from successful_reads."""
    successful_reads = [
        {
            "path": "service/executor.py",
            "start_line": 10,
            "end_line": 15,
            "evidence_id": "ev-xyz-123",
            "raw_lines": [
                "def execute(data):",
                "    clean = sanitize(data)",
                "    os.system(clean)",
                "    return True",
            ],
        }
    ]

    raw_path = [
        {
            "step": "cross-file sink",
            "file": "service/executor.py",
            "line": 12,
            "kind": "imported_sink",
        }
    ]

    enriched = enrich_taint_path(raw_path, successful_reads=successful_reads)
    assert len(enriched) == 1
    step = enriched[0]
    assert step["evidence_id"] == "ev-xyz-123"
    assert step["kind"] == "imported_sink"
    assert step["line"] == 12
    assert ">   12 |     os.system(clean)" in step["code"]


def test_code_analyzer_process_ai_response_enriches_taint_path(tmp_path: Path):
    """Verify CodeAnalyzer._process_ai_response enriches taint_path with code."""
    analyzer = CodeAnalyzer(use_semgrep=False, use_llm=False)

    source_code = (
        "import sqlite3\n"
        "def query_user(req):\n"
        "    uid = req.args['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
    )
    src_file = tmp_path / "app.py"
    src_file.write_text(source_code, encoding="utf-8")

    ai_response = {
        "vulnerabilities": [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "cwe_id": "CWE-89",
                "location": {"start_line": 4, "end_line": 4},
                "description": "SQL Injection in query_user",
                "impact": "Data breach",
                "remediation": "Use parameterized query",
                "taint_path": [
                    {"step": "user id argument", "file": "app.py", "line": 3, "kind": "source"},
                    {"step": "raw concatenation in cursor.execute", "file": "app.py", "line": 4, "kind": "sink"},
                ],
            }
        ]
    }

    # Pass in code_content and file
    vulns = analyzer._process_ai_response(ai_response, filename=str(src_file), code_content=source_code)
    assert len(vulns) == 1
    v = vulns[0]
    assert len(v.taint_path) == 2

    step1 = v.taint_path[0]
    assert step1["step"] == 1
    assert step1["kind"] == "source"
    assert step1["line"] == 3
    assert step1["description"] == "user id argument"
    assert "uid = req.args['id']" in step1["code"]

    step2 = v.taint_path[1]
    assert step2["step"] == 2
    assert step2["kind"] == "sink"
    assert step2["line"] == 4
    assert "cursor.execute" in step2["code"]


@pytest.mark.asyncio
async def test_verifier_agent_attaches_code_to_taint_path(tmp_path: Path):
    """Verify that VerificationAgent.verify ensures verdict.taint_path has code attached."""
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "from services.db import run_query\n"
        "def handler(req):\n"
        "    q = req.args.get('q')\n"
        "    run_query(q)\n",
        encoding="utf-8",
    )
    db_py = tmp_path / "services" / "db.py"
    db_py.parent.mkdir(parents=True, exist_ok=True)
    db_py.write_text(
        "import sqlite3\n"
        "def run_query(sql_str):\n"
        "    cursor.execute(sql_str)\n",
        encoding="utf-8",
    )

    verifier = VerificationAgent(
        client=MagicMock(),
        model="mock-model",
        root=tmp_path,
        max_turns=3,
    )

    vuln = make_vuln(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        file_path="app.py",
        start_line=3,
        description="SQL injection in handler",
    )

    mock_msg_turn1 = MockMessage(
        tool_calls=[
            MockToolCall(
                call_id="call_read_app",
                name="read_lines",
                arguments=json.dumps({"path": "app.py", "start_line": 1, "end_line": 4}),
            )
        ]
    )
    mock_msg_turn2 = MockMessage(
        tool_calls=[
            MockToolCall(
                call_id="call_read_db",
                name="read_imported_symbol",
                arguments=json.dumps({"symbol_name": "run_query", "from_file": "app.py"}),
            )
        ]
    )

    final_verdict_json = json.dumps({
        "verdict": "confirmed",
        "reason": "Unsanitized user argument flows into sqlite3 cursor.execute across files",
        "evidence_file": "services/db.py",
        "evidence_line": 3,
        "taint_path": [
            {"kind": "source", "file": "app.py", "line": 3, "step": "Source: query argument q"},
            {"kind": "imported_call", "file": "services/db.py", "line": 2, "step": "Imported call into run_query"},
            {"kind": "imported_sink", "file": "services/db.py", "line": 3, "step": "Sink cursor.execute"},
        ],
    })

    verifier.client.chat.completions.create.side_effect = [
        MockResponse(mock_msg_turn1),
        MockResponse(mock_msg_turn2),
        MockResponse(MockMessage(content=final_verdict_json)),
    ]

    verdict = await verifier.verify(vuln)
    assert verdict.verdict == "confirmed"
    assert len(verdict.taint_path) == 3

    # Check that each step has actual code snippet attached
    s1 = verdict.taint_path[0]
    assert s1["kind"] == "source"
    assert s1["line"] == 3
    assert ">    3 |     q = req.args.get('q')" in s1["code"]

    s2 = verdict.taint_path[1]
    assert s2["kind"] == "imported_call"
    assert s2["line"] == 2
    assert ">    2 | def run_query(sql_str):" in s2["code"]

    s3 = verdict.taint_path[2]
    assert s3["kind"] == "imported_sink"
    assert s3["line"] == 3
    assert ">    3 |     cursor.execute(sql_str)" in s3["code"]


def test_scanner_enrich_all_taint_paths(tmp_path: Path):
    """Verify that Scanner._enrich_all_taint_paths enriches all report vulnerabilities."""
    code_file = tmp_path / "test_file.py"
    code_file.write_text(
        "def test():\n"
        "    x = input()\n"
        "    eval(x)\n",
        encoding="utf-8",
    )

    vuln = make_vuln(
        vuln_type=VulnerabilityType.CODE_INJECTION,
        file_path="test_file.py",
        start_line=3,
        taint_path=[
            {"step": "input entry", "line": 2, "kind": "source"},
            {"step": "eval call", "line": 3, "kind": "sink"},
        ],
    )

    report = VulnerabilityReport(
        file_name="test_file.py",
        vulnerabilities=[vuln],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )

    options = ScanOptions(target=str(tmp_path), use_semgrep=False, use_llm=False)
    scanner = Scanner(options)

    scanner._enrich_all_taint_paths([report], root=tmp_path)

    v = report.vulnerabilities[0]
    assert len(v.taint_path) == 2
    assert v.taint_path[0]["step"] == 1
    assert v.taint_path[0]["kind"] == "source"
    assert v.taint_path[0]["description"] == "input entry"
    assert ">    2 |     x = input()" in v.taint_path[0]["code"]

    assert v.taint_path[1]["step"] == 2
    assert v.taint_path[1]["kind"] == "sink"
    assert v.taint_path[1]["description"] == "eval call"
    assert ">    3 |     eval(x)" in v.taint_path[1]["code"]


def test_console_reporter_format_taint_path_and_verbose_render():
    """Verify console format_taint_path and render(verbose=True) show visual taint flow."""
    taint_path = [
        {
            "step": 1,
            "kind": "source",
            "file": "app.py",
            "line": 10,
            "description": "User input read from query",
            "code": "     9 | def handler():\n>   10 |     val = req.args['val']\n    11 |     process(val)",
        },
        {
            "step": 2,
            "kind": "sink",
            "file": "db.py",
            "line": 25,
            "description": "Raw string execution",
            "code": "    24 | def process(q):\n>   25 |     execute(q)",
        },
    ]

    # Test format_taint_path directly
    lines = console.format_taint_path(taint_path, paint=lambda text, code: text)
    full_output = "\n".join(lines)
    assert "Taint Flow:" in full_output
    assert "[1] SOURCE at app.py:10 - User input read from query" in full_output
    assert ">   10 |     val = req.args['val']" in full_output
    assert "[2] SINK at db.py:25 - Raw string execution" in full_output
    assert ">   25 |     execute(q)" in full_output

    # Test render(result, verbose=True)
    vuln = make_vuln(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        file_path="app.py",
        start_line=10,
        taint_path=taint_path,
        description="SQL Injection found",
    )
    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[vuln],
        chained_vulnerabilities=[],
        timestamp=datetime.now(),
    )
    scan_res = ScanResult([report], Path("."), stats={"total_seconds": 0.5})

    verbose_output = console.render(scan_res, verbose=True)
    assert "Taint Flow:" in verbose_output
    assert "[1] SOURCE at app.py:10" in verbose_output
    assert ">   10 |     val = req.args['val']" in verbose_output
    assert "[2] SINK at db.py:25" in verbose_output

    # When verbose=False, taint flow is not shown
    non_verbose_output = console.render(scan_res, verbose=False)
    assert "Taint Flow:" not in non_verbose_output
