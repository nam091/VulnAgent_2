"""Integration tests for cross-file taint path tracing and verification.

Verifies the end-to-end chain:
1. Module A imports a symbol (function, class, sanitizer) from Module B (or across re-exports).
2. Module B contains either a dangerous sink or a mitigating sanitizer.
3. The verification agent invokes `read_imported_symbol` to resolve Module B's code and inspect it.
4. ToolCallingAgent records the code slice into EvidenceStore with a validated snapshot evidence ID.
5. VerificationAgent traces cross-file taint paths or verifies sanitizers with evaluate_assessment_policy.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent.loop import AgentRun, ToolCallingAgent
from agent.tools import CodeTools, clear_symbol_index_cache, tools_schema
from agent.verifier import SYSTEM_PROMPT, Verdict, VerificationAgent
from context.project_index import ProjectSymbolIndex
from evidence.store import EvidenceStatus, EvidenceStore
from models.assessment import AssessmentStatus, evaluate_assessment_policy
from models.vulnerability import (
    CodeLocation,
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)
from tests.conftest import make_vuln


class MockFunction:
    """Mock for OpenAI tool call function attribute."""

    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class MockToolCall:
    """Mock for OpenAI tool call object."""

    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.function = MockFunction(name, arguments)


class MockMessage:
    """Mock assistant message."""

    def __init__(self, content: str = None, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class MockChoice:
    def __init__(self, message: MockMessage) -> None:
        self.message = message


class MockResponse:
    def __init__(self, message: MockMessage) -> None:
        self.choices = [MockChoice(message)]
        self.usage = None


@pytest.fixture(autouse=True)
def clean_cache():
    """Ensure symbol index cache is cleared before and after each test."""
    clear_symbol_index_cache()
    yield
    clear_symbol_index_cache()





class TestCrossFileVerification:
    """End-to-end integration test suite for cross-file verification."""

    @pytest.mark.asyncio
    async def test_cross_file_taint_trace_to_dangerous_sink(self, tmp_path: Path):
        """
        Scenario 1: Module A imports a function from Module B.
        Module B contains a dangerous SQL injection sink.
        Agent uses read_imported_symbol to resolve Module B and traces taint path:
        Source in Module A -> Propagation in Module A -> Sink in Module B.
        """
        # Module A: Web handler receiving user input
        app_code = (
            "from database.query_builder import execute_user_query\n"  # line 1
            "\n"                                                       # line 2
            "def handle_search(request):\n"                            # line 3
            "    user_input = request.args.get('q')\n"                 # line 4 (Source)
            "    result = execute_user_query(user_input)\n"            # line 5 (Propagation)
            "    return result\n"                                      # line 6
        )

        # Module B: Database layer executing dynamic SQL
        db_code = (
            "import sqlite3\n"                                         # line 1
            "\n"                                                       # line 2
            "def execute_user_query(raw_query: str):\n"                # line 3
            "    conn = sqlite3.connect('test.db')\n"                  # line 4
            "    cursor = conn.cursor()\n"                             # line 5
            "    sql = f'SELECT * FROM users WHERE name = {raw_query}'\n" # line 6
            "    cursor.execute(sql)\n"                                # line 7 (Sink)
            "    return cursor.fetchall()\n"                           # line 8
        )

        app_dir = tmp_path / "app"
        app_dir.mkdir(parents=True)
        (app_dir / "views.py").write_text(app_code, encoding="utf-8")

        db_dir = tmp_path / "database"
        db_dir.mkdir(parents=True)
        (db_dir / "query_builder.py").write_text(db_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            cwe_id="CWE-89",
            file_path="app/views.py",
            start_line=4,
            end_line=5,
            description="Untrusted user input flows into execute_user_query and raw SQL query",
        )

        # Build mock LLM conversation:
        # Turn 1: Model reads app/views.py
        # Turn 2: Model sees imported execute_user_query, calls read_imported_symbol
        # Turn 3: Model inspects database/query_builder.py, confirms SQL injection sink, emits JSON verdict
        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_app",
                    name="read_lines",
                    arguments=json.dumps({"path": "app/views.py", "start_line": 1, "end_line": 6}),
                )
            ]
        )

        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_resolve_symbol",
                    name="read_imported_symbol",
                    arguments=json.dumps({
                        "symbol_name": "execute_user_query",
                        "from_file": "app/views.py",
                    }),
                )
            ]
        )

        final_verdict_json = json.dumps({
            "verdict": "confirmed",
            "reason": "User input from request.args.get('q') reaches cursor.execute(sql) in database/query_builder.py without sanitization.",
            "evidence_file": "database/query_builder.py",
            "evidence_line": 7,
            "taint_path": [
                {
                    "kind": "source",
                    "file": "app/views.py",
                    "line": 4,
                    "description": "Source: untrusted parameter q from request.args",
                },
                {
                    "kind": "propagation",
                    "file": "app/views.py",
                    "line": 5,
                    "description": "Propagation: passed to execute_user_query",
                },
                {
                    "kind": "sink",
                    "file": "database/query_builder.py",
                    "line": 7,
                    "description": "Sink: formatted string passed to cursor.execute",
                },
            ],
        })
        mock_msg_final = MockMessage(content=final_verdict_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        # Assertions
        assert verdict.verdict == "confirmed"
        assert verdict.confirmed is True
        assert verdict.investigated is True
        assert verdict.tool_calls == 2
        assert len(verdict.successful_reads) >= 2

        # Verify read_imported_symbol successfully registered evidence in database/query_builder.py
        symbol_reads = [
            r for r in verdict.successful_reads if r.get("tool") == "read_imported_symbol"
        ]
        assert len(symbol_reads) == 1
        assert symbol_reads[0]["path"] == "database/query_builder.py"
        assert symbol_reads[0]["start_line"] <= 7 <= symbol_reads[0]["end_line"]
        assert symbol_reads[0]["evidence_id"]

        # Validate cross-file taint path integrity
        assert len(verdict.taint_path) == 3
        source_step = verdict.taint_path[0]
        prop_step = verdict.taint_path[1]
        sink_step = verdict.taint_path[2]

        assert source_step["kind"] == "source"
        assert source_step["file"] == "app/views.py"
        assert source_step["line"] == 4
        assert source_step.get("evidence_id")

        assert prop_step["kind"] == "propagation"
        assert prop_step["file"] == "app/views.py"
        assert prop_step["line"] == 5

        assert sink_step["kind"] == "sink"
        assert sink_step["file"] == "database/query_builder.py"
        assert sink_step["line"] == 7
        assert sink_step.get("evidence_id") == symbol_reads[0]["evidence_id"]

        # Verify with evaluate_assessment_policy
        c_eids = [r["evidence_id"] for r in verdict.successful_reads]
        assessment = evaluate_assessment_policy(
            vuln_id=vuln.id,
            vuln_type="SQL_INJECTION",
            snapshot_id=snapshot.snapshot_id,
            evidence_store=store,
            verdict="supported",
            evidence_ids=c_eids,
            reason=verdict.reason,
            taint_path=verdict.taint_path,
        )
        assert assessment.status == AssessmentStatus.SUPPORTED

    @pytest.mark.asyncio
    async def test_cross_file_sanitizer_refutation(self, tmp_path: Path):
        """
        Scenario 2: Module A imports a sanitizer from Module B.
        Module B contains a genuine path traversal sanitizer (is_relative_to / resolve).
        Agent uses read_imported_symbol to resolve Module B, verifies mitigating control,
        and returns a refuted verdict referencing Module B.
        """
        # Module A: File delivery endpoint
        routes_code = (
            "from utils.sanitizers import safe_resolve_doc\n"         # line 1
            "\n"                                                       # line 2
            "def download_file(request):\n"                            # line 3
            "    user_filename = request.args.get('file')\n"           # line 4
            "    safe_target = safe_resolve_doc(user_filename)\n"      # line 5
            "    with open(safe_target, 'rb') as f:\n"                 # line 6
            "        return f.read()\n"                                # line 7
        )

        # Module B: Sanitizer module
        sanitizer_code = (
            "from pathlib import Path\n"                               # line 1
            "\n"                                                       # line 2
            "DOCS_ROOT = Path('/var/app/docs').resolve()\n"            # line 3
            "\n"                                                       # line 4
            "def safe_resolve_doc(untrusted_filename: str) -> Path:\n" # line 5
            "    target = (DOCS_ROOT / untrusted_filename).resolve()\n"# line 6
            "    if not target.is_relative_to(DOCS_ROOT):\n"           # line 7 (Sanitizer check)
            "        raise PermissionError('Path traversal blocked')\n"# line 8
            "    return target\n"                                      # line 9
        )

        (tmp_path / "routes").mkdir(parents=True)
        (tmp_path / "routes" / "download.py").write_text(routes_code, encoding="utf-8")

        (tmp_path / "utils").mkdir(parents=True)
        (tmp_path / "utils" / "sanitizers.py").write_text(sanitizer_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
            cwe_id="CWE-22",
            file_path="routes/download.py",
            start_line=4,
            end_line=6,
            description="Potential path traversal when opening user_filename",
        )

        # Conversation turns:
        # Turn 1: Model reads routes/download.py
        # Turn 2: Model resolves safe_resolve_doc via read_imported_symbol
        # Turn 3: Model recognizes mitigating control in utils/sanitizers.py line 7, returns refuted
        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_routes",
                    name="read_lines",
                    arguments=json.dumps({"path": "routes/download.py", "start_line": 1, "end_line": 7}),
                )
            ]
        )

        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_sanitizer",
                    name="read_imported_symbol",
                    arguments=json.dumps({
                        "symbol_name": "safe_resolve_doc",
                        "from_file": "routes/download.py",
                    }),
                )
            ]
        )

        refute_json = json.dumps({
            "verdict": "refuted",
            "reason": "Path traversal is prevented because safe_resolve_doc enforces is_relative_to boundary check against DOCS_ROOT.",
            "mitigating_control": "Path resolution base-check via is_relative_to",
            "evidence_file": "utils/sanitizers.py",
            "evidence_line": 7,
        })
        mock_msg_final = MockMessage(content=refute_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        assert verdict.verdict == "refuted"
        assert verdict.refuted is True
        assert verdict.investigated is True
        assert verdict.evidence_file == "utils/sanitizers.py"
        assert verdict.evidence_line == 7
        assert "is_relative_to" in verdict.mitigating_control

        # Verify that utils/sanitizers.py was actually read and recorded
        matching_read = next(
            (r for r in verdict.successful_reads if r["path"] == "utils/sanitizers.py"), None
        )
        assert matching_read is not None
        assert matching_read["start_line"] <= 7 <= matching_read["end_line"]

        # Validate that EvidenceStore holds this evidence as valid
        valid, status, _ = store.validate_evidence(matching_read["evidence_id"], snapshot.snapshot_id)
        assert valid is True
        assert status == EvidenceStatus.VALID

    @pytest.mark.asyncio
    async def test_cross_file_two_hop_reexport_taint_resolution(self, tmp_path: Path):
        """
        Scenario 3: Multi-hop re-export chain.
        Module A (cli.py) imports helper from Module B (api/__init__.py).
        Module B re-exports helper from Module C (backend/executor.py).
        read_imported_symbol must traverse the re-export chain (depth <= 2 hops)
        and correctly identify the sink in Module C.
        """
        # Module A
        cli_code = (
            "from api import execute_system_task\n"
            "\n"
            "def run_cli(cmd):\n"
            "    execute_system_task(cmd)\n"
        )

        # Module B (re-export)
        init_code = (
            "from backend.executor import execute_system_task\n"
            "__all__ = ['execute_system_task']\n"
        )

        # Module C (leaf implementation with sink)
        backend_code = (
            "import os\n"
            "\n"
            "def execute_system_task(command_line: str):\n"
            "    os.system(command_line)\n"
        )

        (tmp_path / "cli.py").write_text(cli_code, encoding="utf-8")
        (tmp_path / "api").mkdir(parents=True)
        (tmp_path / "api" / "__init__.py").write_text(init_code, encoding="utf-8")
        (tmp_path / "backend").mkdir(parents=True)
        (tmp_path / "backend" / "executor.py").write_text(backend_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        tools = CodeTools(tmp_path, evidence_store=store, snapshot_id=snapshot.snapshot_id)

        # Test read_imported_symbol resolves through the re-export to backend/executor.py
        result = tools.read_imported_symbol("execute_system_task", from_file="cli.py")
        assert result["found"] is True
        assert result["file"] == "backend/executor.py"
        assert result["line"] == 3
        assert "os.system(command_line)" in result["source"]

        # Now test through ToolCallingAgent turn simulation
        agent = ToolCallingAgent(
            client=MagicMock(),
            model="test-verifier-model",
            dispatch=tools.dispatch,
            tool_schemas=tools_schema(),
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        reads = agent._process_tool_result_and_reads(
            "read_imported_symbol",
            {"symbol_name": "execute_system_task", "from_file": "cli.py"},
            result,
        )

        assert len(reads) == 1
        assert reads[0]["tool"] == "read_imported_symbol"
        assert reads[0]["path"] == "backend/executor.py"
        assert reads[0]["start_line"] == 3
        assert reads[0]["end_line"] == 4

        # Validate stored evidence
        eid = reads[0]["evidence_id"]
        valid, status, _ = store.validate_evidence(eid, snapshot.snapshot_id)
        assert valid is True
        assert status == EvidenceStatus.VALID

    @pytest.mark.asyncio
    async def test_cross_file_command_injection_two_hop_end_to_end(self, tmp_path: Path):
        """
        Scenario 4: Two-hop re-export chain verified end-to-end with VerificationAgent.
        cli.py -> api/__init__.py -> backend/executor.py (dangerous sink os.system).
        """
        cli_code = (
            "from api import execute_system_task\n"
            "\n"
            "def handle_cli_input(raw_arg):\n"
            "    cmd = 'echo ' + raw_arg\n"
            "    execute_system_task(cmd)\n"
        )
        init_code = (
            "from backend.executor import execute_system_task\n"
        )
        backend_code = (
            "import os\n"
            "\n"
            "def execute_system_task(command_line: str):\n"
            "    os.system(command_line)\n"
        )

        (tmp_path / "cli.py").write_text(cli_code, encoding="utf-8")
        (tmp_path / "api").mkdir(parents=True)
        (tmp_path / "api" / "__init__.py").write_text(init_code, encoding="utf-8")
        (tmp_path / "backend").mkdir(parents=True)
        (tmp_path / "backend" / "executor.py").write_text(backend_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.OS_COMMAND_INJECTION,
            cwe_id="CWE-78",
            file_path="cli.py",
            start_line=3,
            end_line=5,
            description="Untrusted command string passed across modules to os.system",
        )

        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_cli",
                    name="read_lines",
                    arguments=json.dumps({"path": "cli.py", "start_line": 1, "end_line": 5}),
                )
            ]
        )

        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_reexport_symbol",
                    name="read_imported_symbol",
                    arguments=json.dumps({
                        "symbol_name": "execute_system_task",
                        "from_file": "cli.py",
                    }),
                )
            ]
        )

        final_verdict_json = json.dumps({
            "verdict": "confirmed",
            "reason": "Command string is forwarded through re-export into os.system in backend/executor.py",
            "evidence_file": "backend/executor.py",
            "evidence_line": 4,
            "taint_path": [
                {
                    "kind": "source",
                    "file": "cli.py",
                    "line": 4,
                    "description": "Source: untrusted argument concatenated into command string",
                },
                {
                    "kind": "propagation",
                    "file": "cli.py",
                    "line": 5,
                    "description": "Propagation: passed to execute_system_task",
                },
                {
                    "kind": "sink",
                    "file": "backend/executor.py",
                    "line": 4,
                    "description": "Sink: executed directly with shell in os.system",
                },
            ],
        })
        mock_msg_final = MockMessage(content=final_verdict_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        assert verdict.verdict == "confirmed"
        assert verdict.confirmed is True
        assert verdict.investigated is True
        assert len(verdict.successful_reads) >= 2

        # Verify sink resolved to backend/executor.py across 2 hops
        sink_step = [s for s in verdict.taint_path if s["kind"] == "sink"][0]
        assert sink_step["file"] == "backend/executor.py"
        assert sink_step["line"] == 4
        assert sink_step["evidence_id"]


    @pytest.mark.asyncio
    async def test_cross_file_symbol_resolution_fails_on_missing_or_bad_import(self, tmp_path: Path):
        """
        Scenario 4: If symbol cannot be resolved across files, read_imported_symbol returns
        found=False, and hallucinated refutation is rejected as uncertain.
        """
        main_code = (
            "from missing_mod import ghost_cleaner\n"
            "def handler(data):\n"
            "    cleaned = ghost_cleaner(data)\n"
            "    return cleaned\n"
        )
        (tmp_path / "main.py").write_text(main_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()
        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.CODE_INJECTION,
            cwe_id="CWE-94",
            file_path="main.py",
            start_line=3,
        )

        # Model attempts to read non-existent symbol, then tries to refute without valid read
        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_fail",
                    name="read_imported_symbol",
                    arguments=json.dumps({"symbol_name": "ghost_cleaner", "from_file": "main.py"}),
                )
            ]
        )
        mock_msg_final = MockMessage(
            content=json.dumps({
                "verdict": "refuted",
                "reason": "Assumed sanitized by ghost_cleaner",
                "mitigating_control": "ast.literal_eval safe evaluation",
                "evidence_file": "missing_mod.py",
                "evidence_line": 1,
            })
        )

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)
        # Should be downgraded to uncertain because evidence file was never read
        assert verdict.verdict == "uncertain"
        assert not verdict.refuted

    @pytest.mark.asyncio
    async def test_cross_file_taint_path_with_imported_call_and_imported_sink(self, tmp_path: Path):
        """
        Scenario 5: Cross-file taint path using imported_call and imported_sink steps.
        Source in app/handler.py -> imported_call in services/processor.py -> imported_sink in services/processor.py.
        Ensures evaluate_assessment_policy recognizes imported_call and imported_sink.
        """
        app_code = (
            "from services.processor import execute_payload\n"  # line 1
            "def handle_req(request):\n"                        # line 2
            "    user_cmd = request.args.get('cmd')\n"          # line 3 (source)
            "    execute_payload(user_cmd)\n"                   # line 4
        )
        proc_code = (
            "import os\n"                                       # line 1
            "def execute_payload(command: str):\n"              # line 2 (imported_call)
            "    os.system(command)\n"                          # line 3 (imported_sink)
        )

        (tmp_path / "app").mkdir(parents=True)
        (tmp_path / "app" / "handler.py").write_text(app_code, encoding="utf-8")
        (tmp_path / "services").mkdir(parents=True)
        (tmp_path / "services" / "processor.py").write_text(proc_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.OS_COMMAND_INJECTION,
            cwe_id="CWE-78",
            file_path="app/handler.py",
            start_line=3,
            end_line=4,
            description="Command injection flowing across modules into os.system",
        )

        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_app",
                    name="read_lines",
                    arguments=json.dumps({"path": "app/handler.py", "start_line": 1, "end_line": 4}),
                )
            ]
        )
        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_proc",
                    name="read_imported_symbol",
                    arguments=json.dumps({"symbol_name": "execute_payload", "from_file": "app/handler.py"}),
                )
            ]
        )
        final_verdict_json = json.dumps({
            "verdict": "confirmed",
            "reason": "Unsanitized user_cmd flows across modules into os.system in services/processor.py",
            "evidence_file": "services/processor.py",
            "evidence_line": 3,
            "taint_path": [
                {
                    "kind": "source",
                    "file": "app/handler.py",
                    "line": 3,
                    "step": "Source: untrusted query argument cmd",
                },
                {
                    "kind": "imported_call",
                    "file": "services/processor.py",
                    "line": 2,
                    "step": "Cross-file call: enters execute_payload in services/processor.py",
                },
                {
                    "kind": "imported_sink",
                    "file": "services/processor.py",
                    "line": 3,
                    "step": "Imported sink: executes os.system with untrusted command",
                },
            ],
        })
        mock_msg_final = MockMessage(content=final_verdict_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        assert verdict.verdict == "confirmed"
        assert verdict.confirmed is True
        assert len(verdict.taint_path) == 3
        kinds = [s["kind"] for s in verdict.taint_path]
        assert kinds == ["source", "imported_call", "imported_sink"]

        # Ensure evidence_ids are mapped for all steps including cross-file ones
        for step in verdict.taint_path:
            assert step.get("evidence_id")
            assert step.get("description")
            assert step.get("step")

        # Verify evaluate_assessment_policy accepts imported_sink as satisfying sink requirement
        c_eids = [r["evidence_id"] for r in verdict.successful_reads]
        assessment = evaluate_assessment_policy(
            vuln_id=vuln.id,
            vuln_type="OS_COMMAND_INJECTION",
            snapshot_id=snapshot.snapshot_id,
            evidence_store=store,
            verdict="supported",
            evidence_ids=c_eids,
            reason=verdict.reason,
            taint_path=verdict.taint_path,
        )
        assert assessment.status == AssessmentStatus.SUPPORTED

    @pytest.mark.asyncio
    async def test_cross_file_sanitizer_refutation_int_casting(self, tmp_path: Path):
        """
        Scenario 6: SQL Injection finding refuted by imported int() type-casting.
        Module A calls clean_id(request_id) -> Module B returns int(raw_val).
        Verifier detects mitigating control from imported symbol and refutes the finding.
        """
        app_code = (
            "from utils.type_casters import clean_id\n"
            "def get_user(request, db):\n"
            "    user_id = clean_id(request.args.get('id'))\n"
            "    return db.query(f'SELECT * FROM users WHERE id = {user_id}')\n"
        )
        caster_code = (
            "def clean_id(raw_val: str) -> int:\n"
            "    return int(raw_val)\n"
        )

        (tmp_path / "app").mkdir(parents=True)
        (tmp_path / "app" / "views.py").write_text(app_code, encoding="utf-8")
        (tmp_path / "utils").mkdir(parents=True)
        (tmp_path / "utils" / "type_casters.py").write_text(caster_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            cwe_id="CWE-89",
            file_path="app/views.py",
            start_line=3,
            end_line=4,
            description="Potential SQL injection in f-string query",
        )

        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_views",
                    name="read_lines",
                    arguments=json.dumps({"path": "app/views.py", "start_line": 1, "end_line": 4}),
                )
            ]
        )
        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_caster",
                    name="read_imported_symbol",
                    arguments=json.dumps({"symbol_name": "clean_id", "from_file": "app/views.py"}),
                )
            ]
        )
        refute_json = json.dumps({
            "verdict": "refuted",
            "reason": "clean_id casts input to int(), neutralizing SQL injection",
            "mitigating_control": "SQL Injection sanitized via int()",
            "evidence_file": "utils/type_casters.py",
            "evidence_line": 2,
            "taint_path": [
                {
                    "kind": "source",
                    "file": "app/views.py",
                    "line": 3,
                    "step": "Input received",
                },
                {
                    "kind": "sanitizer",
                    "file": "utils/type_casters.py",
                    "line": 2,
                    "step": "int() cast sanitization",
                },
            ],
        })
        mock_msg_final = MockMessage(content=refute_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        assert verdict.verdict == "refuted"
        assert verdict.refuted is True
        assert "int" in verdict.mitigating_control.lower()
        assert verdict.evidence_file == "utils/type_casters.py"

    @pytest.mark.asyncio
    async def test_cross_file_sanitizer_auto_detection_when_model_is_uncertain(self, tmp_path: Path):
        """
        Scenario 7: Post-processing detects mitigating control from imported symbol
        even if model returned uncertain or omitted mitigating_control.
        Module A calls escape_text() -> Module B uses escape_for_html().
        Verifier recognizes CWE-79 sanitizer and respects refuted status with mitigating_control.
        """
        app_code = (
            "from security.escaper import escape_text\n"
            "def render_comment(req):\n"
            "    user_c = req.args.get('comment')\n"
            "    safe_c = escape_text(user_c)\n"
            "    return f'<div>{safe_c}</div>'\n"
        )
        escaper_code = (
            "import html\n"
            "def escape_text(val: str) -> str:\n"
            "    return html.escape(val)\n"
        )

        (tmp_path / "app").mkdir(parents=True)
        (tmp_path / "app" / "views.py").write_text(app_code, encoding="utf-8")
        (tmp_path / "security").mkdir(parents=True)
        (tmp_path / "security" / "escaper.py").write_text(escaper_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.CROSS_SITE_SCRIPTING,
            cwe_id="CWE-79",
            file_path="app/views.py",
            start_line=3,
            end_line=5,
            description="Reflected XSS in comment rendering",
        )

        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_app",
                    name="read_lines",
                    arguments=json.dumps({"path": "app/views.py", "start_line": 1, "end_line": 5}),
                )
            ]
        )
        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_escaper",
                    name="read_imported_symbol",
                    arguments=json.dumps({"symbol_name": "escape_text", "from_file": "app/views.py"}),
                )
            ]
        )
        # Model returns uncertain because it's not sure
        uncertain_json = json.dumps({
            "verdict": "uncertain",
            "reason": "Unsure if html.escape completely stops XSS in this context",
            "evidence_file": "",
            "evidence_line": 0,
        })
        mock_msg_final = MockMessage(content=uncertain_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        # Verifier post-processing detects html.escape in imported symbol and respects refutation
        assert verdict.verdict == "refuted"
        assert verdict.refuted is True
        assert "html.escape" in verdict.mitigating_control or "escape" in verdict.mitigating_control
        assert verdict.evidence_file == "security/escaper.py"

    @pytest.mark.asyncio
    async def test_cross_file_sanitizer_refutation_whitelist_check(self, tmp_path: Path):
        """
        Scenario 8: Path traversal finding refuted by imported whitelist validation.
        Module B validates filename against ALLOWED_DOCS.
        Verifier respects refuted verdict and records mitigating_control.
        """
        app_code = (
            "from utils.validator import get_safe_path\n"
            "def fetch_doc(req):\n"
            "    name = req.args.get('doc')\n"
            "    path = get_safe_path(name)\n"
            "    with open(path) as f:\n"
            "        return f.read()\n"
        )
        validator_code = (
            "ALLOWED_DOCS = {'report.pdf', 'summary.txt'}\n"
            "def get_safe_path(doc_name: str) -> str:\n"
            "    if doc_name in ALLOWED_DOCS:\n"
            "        return f'/var/docs/{doc_name}'\n"
            "    raise ValueError('Forbidden document')\n"
        )

        (tmp_path / "app").mkdir(parents=True)
        (tmp_path / "app" / "views.py").write_text(app_code, encoding="utf-8")
        (tmp_path / "utils").mkdir(parents=True)
        (tmp_path / "utils" / "validator.py").write_text(validator_code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()

        verifier = VerificationAgent(
            client=MagicMock(),
            model="test-verifier-model",
            root=tmp_path,
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        vuln = make_vuln(
            vuln_type=VulnerabilityType.PATH_TRAVERSAL,
            cwe_id="CWE-22",
            file_path="app/views.py",
            start_line=3,
            end_line=5,
            description="Potential path traversal when opening doc",
        )

        mock_msg_turn1 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_app",
                    name="read_lines",
                    arguments=json.dumps({"path": "app/views.py", "start_line": 1, "end_line": 6}),
                )
            ]
        )
        mock_msg_turn2 = MockMessage(
            tool_calls=[
                MockToolCall(
                    call_id="call_read_validator",
                    name="read_imported_symbol",
                    arguments=json.dumps({"symbol_name": "get_safe_path", "from_file": "app/views.py"}),
                )
            ]
        )
        refute_json = json.dumps({
            "verdict": "refuted",
            "reason": "get_safe_path validates doc_name against ALLOWED_DOCS whitelist",
            "mitigating_control": "Whitelist condition check: if doc_name in ALLOWED_DOCS",
            "evidence_file": "utils/validator.py",
            "evidence_line": 3,
        })
        mock_msg_final = MockMessage(content=refute_json)

        verifier.client.chat.completions.create.side_effect = [
            MockResponse(mock_msg_turn1),
            MockResponse(mock_msg_turn2),
            MockResponse(mock_msg_final),
        ]

        verdict = await verifier.verify(vuln)

        assert verdict.verdict == "refuted"
        assert verdict.refuted is True
        assert "whitelist" in verdict.mitigating_control.lower() or "allowed" in verdict.mitigating_control.lower()
        assert verdict.evidence_file == "utils/validator.py"
