import pytest
from pathlib import Path

from context import ProjectSymbolIndex
from context.project_index import ProjectSymbolIndex as DirectProjectSymbolIndex


def test_reexport():
    assert ProjectSymbolIndex is DirectProjectSymbolIndex


class TestProjectSymbolIndex:
    def test_extract_definitions_function_class_variable(self):
        index = ProjectSymbolIndex()
        code = (
            "GLOBAL_CONST = 100\n"
            "a, b = 1, 2\n"
            "typed_var: str = 'hello'\n"
            "\n"
            "def simple_func(x, y):\n"
            "    z = 10\n"  # local variable z should NOT be indexed
            "    return x + y + z\n"
            "\n"
            "async def async_worker():\n"
            "    pass\n"
            "\n"
            "class SampleClass:\n"
            "    CLASS_ATTR = 'val'\n"
            "    def method_one(self):\n"
            "        return True\n"
        )
        index.add_file("module_a.py", content=code)

        # 1. Variables
        assert "GLOBAL_CONST" in index.definitions
        assert index.definitions["GLOBAL_CONST"][0]["kind"] == "variable"
        assert index.definitions["GLOBAL_CONST"][0]["line"] == 1

        assert "a" in index.definitions
        assert index.definitions["a"][0]["kind"] == "variable"
        assert "b" in index.definitions
        assert "typed_var" in index.definitions

        # Local variable 'z' should not be indexed as module symbol
        assert "z" not in index.definitions

        # 2. Functions
        assert "simple_func" in index.definitions
        assert index.definitions["simple_func"][0]["kind"] == "function"
        assert index.definitions["simple_func"][0]["line"] == 5

        assert "async_worker" in index.definitions
        assert index.definitions["async_worker"][0]["kind"] == "function"

        # 3. Classes and Methods
        assert "SampleClass" in index.definitions
        assert index.definitions["SampleClass"][0]["kind"] == "class"

        assert "SampleClass.method_one" in index.definitions
        assert index.definitions["SampleClass.method_one"][0]["kind"] == "function"

        assert "method_one" in index.definitions
        assert index.definitions["method_one"][0]["kind"] == "function"

        assert "SampleClass.CLASS_ATTR" in index.definitions
        assert index.definitions["SampleClass.CLASS_ATTR"][0]["kind"] == "variable"

    def test_extract_imports(self):
        index = ProjectSymbolIndex()
        code = (
            "import os\n"
            "import sys as system\n"
            "from math import sqrt, ceil as ceiling\n"
            "from .relative_mod import local_func\n"
            "from ..parent_mod import parent_func as pf\n"
            "from wildcard import *\n"
        )
        index.add_file("src/foo.py", content=code)

        imports = index.get_imports("src/foo.py")
        assert len(imports) >= 5

        # Check import os
        imp_os = [i for i in imports if i["module"] == "os"][0]
        assert "os" in imp_os["names"]
        assert imp_os["level"] == 0

        # Check import sys as system
        imp_sys = [i for i in imports if i["module"] == "sys"][0]
        assert "sys" in imp_sys["names"]
        assert "system" in imp_sys["names"]
        assert imp_sys["alias_map"].get("system") == "sys"

        # Check from math import sqrt, ceil as ceiling
        imp_math = [i for i in imports if i["module"] == "math"][0]
        assert "sqrt" in imp_math["names"]
        assert "ceil" in imp_math["names"]
        assert "ceiling" in imp_math["names"]
        assert imp_math["alias_map"].get("ceiling") == "ceil"

        # Check relative imports
        imp_rel = [i for i in imports if i["module"] == "relative_mod"][0]
        assert imp_rel["level"] == 1
        assert "local_func" in imp_rel["names"]

        imp_parent = [i for i in imports if i["module"] == "parent_mod"][0]
        assert imp_parent["level"] == 2
        assert "pf" in imp_parent["names"]
        assert imp_parent["alias_map"].get("pf") == "parent_func"

        # Check wildcard
        imp_star = [i for i in imports if i["module"] == "wildcard"][0]
        assert "*" in imp_star["names"]

    def test_resolve_symbol_local(self):
        index = ProjectSymbolIndex()
        code = (
            "def calculate(a, b):\n"
            "    return a * b\n"
        )
        index.add_file("calc.py", content=code)

        res = index.resolve_symbol("calculate", "calc.py")
        assert res is not None
        assert res["name"] == "calculate"
        assert res["file"] == "calc.py"
        assert res["line"] == 1
        assert res["end_line"] == 2
        assert res["kind"] == "function"
        assert "return a * b" in res["source"]

    def test_resolve_symbol_via_direct_import(self):
        index = ProjectSymbolIndex()
        models_code = (
            "class UserModel:\n"
            "    def __init__(self, name):\n"
            "        self.name = name\n"
        )
        service_code = (
            "from models import UserModel\n"
            "\n"
            "def get_user():\n"
            "    return UserModel('Alice')\n"
        )
        index.add_file("models.py", content=models_code)
        index.add_file("service.py", content=service_code)

        res = index.resolve_symbol("UserModel", "service.py")
        assert res is not None
        assert res["name"] == "UserModel"
        assert res["file"] == "models.py"
        assert res["kind"] == "class"
        assert "class UserModel:" in res["source"]

    def test_resolve_symbol_via_aliased_import(self):
        index = ProjectSymbolIndex()
        lib_code = (
            "def heavy_computation():\n"
            "    return 42\n"
        )
        main_code = (
            "from lib import heavy_computation as compute\n"
            "\n"
            "compute()\n"
        )
        index.add_file("lib.py", content=lib_code)
        index.add_file("main.py", content=main_code)

        res = index.resolve_symbol("compute", "main.py")
        assert res is not None
        assert res["name"] == "heavy_computation"
        assert res["file"] == "lib.py"
        assert res["kind"] == "function"
        assert "return 42" in res["source"]

    def test_resolve_symbol_reexport_chain(self):
        index = ProjectSymbolIndex()
        backend_code = (
            "class DatabaseConnection:\n"
            "    pass\n"
        )
        db_init_code = (
            "from .backend import DatabaseConnection\n"
        )
        app_code = (
            "from db import DatabaseConnection\n"
        )
        index.add_file("db/backend.py", content=backend_code)
        index.add_file("db/__init__.py", content=db_init_code)
        index.add_file("app.py", content=app_code)

        res = index.resolve_symbol("DatabaseConnection", "app.py")
        assert res is not None
        assert res["name"] == "DatabaseConnection"
        assert res["file"] == "db/backend.py"
        assert res["kind"] == "class"

    def test_resolve_symbol_wildcard_import(self):
        index = ProjectSymbolIndex()
        consts_code = (
            "API_KEY = 'secret'\n"
            "TIMEOUT = 60\n"
        )
        client_code = (
            "from consts import *\n"
        )
        index.add_file("consts.py", content=consts_code)
        index.add_file("client.py", content=client_code)

        res = index.resolve_symbol("API_KEY", "client.py")
        assert res is not None
        assert res["name"] == "API_KEY"
        assert res["file"] == "consts.py"
        assert res["kind"] == "variable"
        assert "secret" in res["source"]

    def test_resolve_symbol_global_fallback(self):
        index = ProjectSymbolIndex()
        util_code = (
            "def format_response(data):\n"
            "    return str(data)\n"
        )
        view_code = (
            "# No import here\n"
            "def show():\n"
            "    pass\n"
        )
        index.add_file("utils/formatter.py", content=util_code)
        index.add_file("views/main.py", content=view_code)

        res = index.resolve_symbol("format_response", "views/main.py")
        assert res is not None
        assert res["name"] == "format_response"
        assert res["file"] == "utils/formatter.py"
        assert res["kind"] == "function"

    def test_resolve_symbol_dotted_lookup(self):
        index = ProjectSymbolIndex()
        helpers_code = (
            "class ToolKit:\n"
            "    def execute(self):\n"
            "        return 'done'\n"
        )
        runner_code = (
            "from helpers import ToolKit\n"
            "tk = ToolKit()\n"
        )
        index.add_file("helpers.py", content=helpers_code)
        index.add_file("runner.py", content=runner_code)

        res = index.resolve_symbol("ToolKit.execute", "runner.py")
        assert res is not None
        assert res["kind"] == "function"
        assert res["file"] == "helpers.py"
        assert "def execute(self):" in res["source"]

    def test_resolve_symbol_not_found(self):
        index = ProjectSymbolIndex()
        index.add_file("empty.py", content="x = 1\n")
        assert index.resolve_symbol("non_existent_symbol", "empty.py") is None

    def test_reindexing_cleans_old_entries(self):
        index = ProjectSymbolIndex()
        index.add_file("sample.py", content="def old_func(): pass\n")
        assert "old_func" in index.definitions

        # Re-index with new content
        index.add_file("sample.py", content="def new_func(): pass\n")
        assert "old_func" not in index.definitions
        assert "new_func" in index.definitions

    def test_build_index_and_index_project_on_directory(self, tmp_path: Path):
        # Create a mock directory structure with ignored folders
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "core.py").write_text("class Core:\n    val = 1\n", encoding="utf-8")
        
        # Ignored dirs
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "ignored.py").write_text("def venv_func(): pass\n", encoding="utf-8")

        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "git_ignore.py").write_text("def git_func(): pass\n", encoding="utf-8")

        index = ProjectSymbolIndex(root_path=tmp_path)
        index.index_project()

        assert "Core" in index.definitions
        assert "venv_func" not in index.definitions
        assert "git_func" not in index.definitions
        assert len(index) == 1
        assert "src/core.py" in index.files

    def test_read_source_lines_from_disk(self, tmp_path: Path):
        file_path = tmp_path / "test_file.py"
        file_path.write_text(
            "# Line 1\n"
            "def targeted_function():\n"
            "    x = 1\n"
            "    y = 2\n"
            "    return x + y\n"
            "# Line 6\n",
            encoding="utf-8"
        )
        index = ProjectSymbolIndex(root_path=tmp_path)
        index.build_index([file_path])

        res = index.resolve_symbol("targeted_function", str(file_path))
        assert res is not None
        assert res["line"] == 2
        assert res["end_line"] == 5
        assert "def targeted_function():" in res["source"]
        assert "return x + y" in res["source"]
        assert "# Line 1" not in res["source"]
        assert "# Line 6" not in res["source"]
