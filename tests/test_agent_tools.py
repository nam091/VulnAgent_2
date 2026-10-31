import pytest
from pathlib import Path
from unittest.mock import MagicMock

from agent.tools import (
    CodeTools,
    ToolError,
    TOOL_SCHEMAS,
    clear_symbol_index_cache,
    get_project_symbol_index,
    tools_schema,
    tools_schemas,
)
from context.project_index import ProjectSymbolIndex
from evidence.store import EvidenceStore


@pytest.fixture(autouse=True)
def cleanup_cache():
    """Ensure symbol index cache is clean between tests."""
    clear_symbol_index_cache()
    yield
    clear_symbol_index_cache()


class TestAgentToolsReadImportedSymbol:
    def test_schema_registration(self):
        """Verify read_imported_symbol is present in tool schemas."""
        schemas = tools_schema()
        assert schemas is TOOL_SCHEMAS
        assert tools_schemas() is TOOL_SCHEMAS

        tool_names = [s["function"]["name"] for s in schemas]
        assert "read_imported_symbol" in tool_names
        assert "read_lines" in tool_names
        assert "find_definition" in tool_names
        assert "search" in tool_names
        assert "list_files" in tool_names

        symbol_schema = next(s for s in schemas if s["function"]["name"] == "read_imported_symbol")
        func_spec = symbol_schema["function"]
        assert "symbol_name" in func_spec["parameters"]["properties"]
        assert "from_file" in func_spec["parameters"]["properties"]
        assert "symbol_name" in func_spec["parameters"]["required"]

    def test_read_imported_symbol_direct_definition(self, tmp_path: Path):
        """Verify read_imported_symbol can resolve a function defined directly in a file."""
        code = (
            "def sanitize_path(input_path: str) -> str:\n"
            "    '''Sanitize path against traversal.'''\n"
            "    return input_path.replace('..', '')\n"
        )
        (tmp_path / "sanitizers.py").write_text(code, encoding="utf-8")

        tools = CodeTools(tmp_path)
        res = tools.read_imported_symbol("sanitize_path", from_file="sanitizers.py")

        assert res["found"] is True
        assert res["symbol"] == "sanitize_path"
        assert res["file"] == "sanitizers.py"
        assert res["start_line"] == 1
        assert res["line"] == 1
        assert res["end_line"] == 3
        assert res["kind"] == "function"
        assert "Sanitize path against traversal" in res["source"]
        assert "1 | def sanitize_path" in res["source"]

    def test_read_imported_symbol_across_files(self, tmp_path: Path):
        """Verify read_imported_symbol resolves an import from one file to another."""
        utils_code = (
            "class SafeValidator:\n"
            "    def is_valid(self, value):\n"
            "        return bool(value)\n"
        )
        app_code = (
            "from utils import SafeValidator\n"
            "\n"
            "def handle_request(req):\n"
            "    v = SafeValidator()\n"
            "    return v.is_valid(req)\n"
        )
        (tmp_path / "utils.py").write_text(utils_code, encoding="utf-8")
        (tmp_path / "app.py").write_text(app_code, encoding="utf-8")

        tools = CodeTools(tmp_path)
        res = tools.read_imported_symbol("SafeValidator", from_file="app.py")

        assert res["found"] is True
        assert res["symbol"] == "SafeValidator"
        assert res["file"] == "utils.py"
        assert res["kind"] == "class"
        assert "class SafeValidator:" in res["source"]
        assert "from_file" in res and res["from_file"] == "app.py"

    def test_read_imported_symbol_aliased_import(self, tmp_path: Path):
        """Verify read_imported_symbol handles aliased imports (from mod import func as alias)."""
        core_code = (
            "def compute_hash(data: str) -> str:\n"
            "    return 'hashed_' + data\n"
        )
        service_code = (
            "from core import compute_hash as hasher\n"
            "\n"
            "res = hasher('admin')\n"
        )
        (tmp_path / "core.py").write_text(core_code, encoding="utf-8")
        (tmp_path / "service.py").write_text(service_code, encoding="utf-8")

        tools = CodeTools(tmp_path)
        res = tools.read_imported_symbol("hasher", from_file="service.py")

        assert res["found"] is True
        assert res["file"] == "core.py"
        assert res["name"] == "hasher"
        assert "compute_hash" in res["source_code"]

    def test_read_imported_symbol_global_fallback_when_no_from_file(self, tmp_path: Path):
        """Verify global fallback when from_file is None."""
        config_code = (
            "SECRET_TOKEN = 'super_secret_key'\n"
            "DATABASE_PORT = 5432\n"
        )
        (tmp_path / "config.py").write_text(config_code, encoding="utf-8")

        tools = CodeTools(tmp_path)
        res = tools.read_imported_symbol("SECRET_TOKEN")

        assert res["found"] is True
        assert res["symbol"] == "SECRET_TOKEN"
        assert res["file"] == "config.py"
        assert res["kind"] == "variable"
        assert "super_secret_key" in res["source"]

    def test_read_imported_symbol_not_found(self, tmp_path: Path):
        """Verify non-existent symbol returns found=False with clear note."""
        (tmp_path / "empty.py").write_text("x = 1\n", encoding="utf-8")
        tools = CodeTools(tmp_path)

        res = tools.read_imported_symbol("non_existent_symbol", from_file="empty.py")
        assert res["found"] is False
        assert "non_existent_symbol" in res["note"]

    def test_read_imported_symbol_input_validation(self, tmp_path: Path):
        """Verify validation of symbol_name and path escapes."""
        (tmp_path / "main.py").write_text("pass\n", encoding="utf-8")
        tools = CodeTools(tmp_path)

        # Empty or non-string symbol_name
        with pytest.raises(ToolError, match="symbol_name must be a non-empty string"):
            tools.read_imported_symbol("")

        with pytest.raises(ToolError, match="symbol_name must be a non-empty string"):
            tools.read_imported_symbol("   ")

        # Non-existent from_file
        with pytest.raises(ToolError, match="no such file"):
            tools.read_imported_symbol("foo", from_file="missing.py")

        # Path traversal from_file
        with pytest.raises(ToolError, match="path escapes the scan root"):
            tools.read_imported_symbol("foo", from_file="../outside.py")

    def test_hop_depth_limit_within_two_hops(self, tmp_path: Path):
        """
        Verify hop depth behavior:
        Hop 1: mod_a -> mod_b (allowed)
        Hop 2: mod_a -> mod_b -> mod_c (allowed)
        Hop 3: mod_a -> mod_b -> mod_c -> mod_d (stopped, returns found=False)
        """
        mod_d = "def leaf_func():\n    return 'leaf'\n"
        mod_c = "from mod_d import leaf_func\n"
        mod_b = "from mod_c import leaf_func\n"
        mod_a = "from mod_b import leaf_func\n"

        (tmp_path / "mod_d.py").write_text(mod_d, encoding="utf-8")
        (tmp_path / "mod_c.py").write_text(mod_c, encoding="utf-8")
        (tmp_path / "mod_b.py").write_text(mod_b, encoding="utf-8")
        (tmp_path / "mod_a.py").write_text(mod_a, encoding="utf-8")

        tools = CodeTools(tmp_path)

        # 1 hop: mod_b -> mod_c (leaf_func in mod_c is imported from mod_d: 1 re-export hop)
        res_1hop = tools.read_imported_symbol("leaf_func", from_file="mod_c.py")
        assert res_1hop["found"] is True
        assert res_1hop["file"] == "mod_d.py"

        # 2 hops: mod_b -> mod_c -> mod_d (2 hops total)
        res_2hop = tools.read_imported_symbol("leaf_func", from_file="mod_b.py")
        assert res_2hop["found"] is True
        assert res_2hop["file"] == "mod_d.py"

        # 3 hops: mod_a -> mod_b -> mod_c -> mod_d (3 hops: exceeds hop limit of 2)
        res_3hop = tools.read_imported_symbol("leaf_func", from_file="mod_a.py")
        assert res_3hop["found"] is False

    def test_circular_imports_handled_safely(self, tmp_path: Path):
        """Verify circular import does not hang or infinite loop."""
        file_a = (
            "from file_b import helper_b\n"
            "def helper_a():\n"
            "    return helper_b()\n"
        )
        file_b = (
            "from file_a import helper_a\n"
            "def helper_b():\n"
            "    return 42\n"
        )
        (tmp_path / "file_a.py").write_text(file_a, encoding="utf-8")
        (tmp_path / "file_b.py").write_text(file_b, encoding="utf-8")

        tools = CodeTools(tmp_path)
        # Should resolve cleanly without RecursionError or hang
        res = tools.read_imported_symbol("helper_b", from_file="file_a.py")
        assert res["found"] is True
        assert res["file"] == "file_b.py"

    def test_execute_tool_and_dispatch(self, tmp_path: Path):
        """Verify execute_tool and dispatch properly invoke read_imported_symbol."""
        code = "def process():\n    return True\n"
        (tmp_path / "worker.py").write_text(code, encoding="utf-8")

        tools = CodeTools(tmp_path)

        # 1. dispatch by dict
        res_dispatch = tools.dispatch("read_imported_symbol", {
            "symbol_name": "process",
            "from_file": "worker.py",
        })
        assert res_dispatch["found"] is True
        assert res_dispatch["file"] == "worker.py"

        # 2. execute_tool with dict arguments
        res_exec_dict = tools.execute_tool("read_imported_symbol", {
            "symbol_name": "process",
            "from_file": "worker.py",
        })
        assert res_exec_dict["found"] is True

        # 3. execute_tool with kwargs
        res_exec_kwargs = tools.execute_tool("read_imported_symbol", symbol_name="process", from_file="worker.py")
        assert res_exec_kwargs["found"] is True

        # 4. Unknown tool returns error dict
        err = tools.execute_tool("unknown_tool")
        assert "error" in err

    def test_workspace_index_caching(self, tmp_path: Path):
        """Verify ProjectSymbolIndex is cached per root workspace."""
        (tmp_path / "module.py").write_text("VAL = 10\n", encoding="utf-8")

        idx1 = get_project_symbol_index(tmp_path)
        idx2 = get_project_symbol_index(tmp_path)
        assert idx1 is idx2

        tools1 = CodeTools(tmp_path)
        tools2 = CodeTools(tmp_path)
        assert tools1.symbol_index is idx1
        assert tools2.symbol_index is idx1

        clear_symbol_index_cache(tmp_path)
        idx3 = get_project_symbol_index(tmp_path)
        assert idx3 is not idx1

    def test_evidence_recording_in_loop(self, tmp_path: Path):
        """Verify read_imported_symbol produces valid successful_reads in ToolCallingAgent."""
        from agent.loop import ToolCallingAgent

        code = "def authenticate():\n    return True\n"
        (tmp_path / "auth.py").write_text(code, encoding="utf-8")

        store = EvidenceStore(tmp_path)
        snapshot = store.create_snapshot()
        tools = CodeTools(tmp_path, evidence_store=store, snapshot_id=snapshot.snapshot_id)

        agent = ToolCallingAgent(
            client=MagicMock(),
            model="test-model",
            dispatch=tools.dispatch,
            tool_schemas=tools_schema(),
            evidence_store=store,
            snapshot_id=snapshot.snapshot_id,
        )

        # Call _process_tool_result_and_reads directly to simulate tool dispatch recording
        result = tools.dispatch("read_imported_symbol", {"symbol_name": "authenticate", "from_file": "auth.py"})
        reads = agent._process_tool_result_and_reads("read_imported_symbol", {"symbol_name": "authenticate"}, result)

        assert len(reads) == 1
        assert reads[0]["tool"] == "read_imported_symbol"
        assert reads[0]["path"] == "auth.py"
        assert reads[0]["start_line"] == 1
        assert reads[0]["end_line"] == 2
        assert reads[0]["evidence_id"]
