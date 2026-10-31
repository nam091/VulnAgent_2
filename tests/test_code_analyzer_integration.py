"""Unit tests for ASTSlicer and PromptManager integration into CodeAnalyzer.

Validates:
1. CodeAnalyzer.__init__ initializes self.ast_slicer, self.prompt_manager, and use_ast_slicer flag.
2. CodeAnalyzer._generate_security_prompt uses AST backward slicing when enabled and sinks are found.
3. Fallback to general security prompt when no sinks found or AST slicing fails/disabled.
4. ScanOptions and Scanner propagation of use_ast_slicer.
5. Compatibility re-exports from analyzer.ast_slicer and analyzer package.
"""

import pytest

from analyzer.code_analyzer import CodeAnalyzer
from analyzer.prompt_manager import PromptManager
from analyzer.scanner import ScanOptions, Scanner
from analyzer.ast_slicer import (
    ASTSlicer,
    SliceNode,
    SliceResult,
    SINK_CALL_SIGNATURES,
)


class TestCodeAnalyzerInitialization:
    def test_default_initialization(self):
        analyzer = CodeAnalyzer(use_semgrep=False, use_llm=False)
        assert isinstance(analyzer.ast_slicer, ASTSlicer)
        assert isinstance(analyzer.prompt_manager, PromptManager)
        assert analyzer.use_ast_slicer is True

    def test_explicit_use_ast_slicer_flag(self):
        analyzer = CodeAnalyzer(use_semgrep=False, use_llm=False, use_ast_slicer=False)
        assert analyzer.use_ast_slicer is False
        assert isinstance(analyzer.ast_slicer, ASTSlicer)
        assert isinstance(analyzer.prompt_manager, PromptManager)

    def test_initialization_with_scan_options_object(self):
        options = ScanOptions(target=".", use_llm=False, use_semgrep=False, use_ast_slicer=False)
        analyzer = CodeAnalyzer(options=options)
        assert analyzer.use_ast_slicer is False

    def test_initialization_with_positional_scan_options(self):
        options = ScanOptions(target=".", use_llm=False, use_semgrep=False, use_ast_slicer=False)
        analyzer = CodeAnalyzer(options)
        assert analyzer.use_ast_slicer is False


class TestCodeAnalyzerPromptGeneration:
    @pytest.fixture
    def analyzer(self):
        return CodeAnalyzer(use_semgrep=False, use_llm=False, use_ast_slicer=True)

    def test_sliced_prompt_generated_for_sql_injection_sink(self, analyzer):
        code = (
            "import sqlite3\n"
            "def query(user_id):\n"
            "    dead_var = 12345\n"
            "    sql = f'SELECT * FROM users WHERE id = {user_id}'\n"
            "    cursor.execute(sql)\n"
        )
        parsed = {
            "content": code,
            "language": "Python",
            "imports": ["sqlite3"],
            "functions": [{"name": "query"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="db.py")

        assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
        assert "[LLM SEMANTIC TAINT REASONING]" in prompt
        assert "cursor.execute" in prompt
        assert "db.py" in prompt
        facts_slice_section = prompt.split("--- BEGIN FULL SOURCE")[0]
        assert "dead_var" not in facts_slice_section
        assert "cursor.execute" in facts_slice_section

    def test_sliced_prompt_generated_for_command_injection_sinks(self, analyzer):
        for sink_call in ["os.system(cmd)", "subprocess.Popen(cmd)"]:
            code = (
                "def run_cmd(user_arg):\n"
                f"    cmd = 'echo ' + user_arg\n"
                f"    {sink_call}\n"
            )
            parsed = {
                "content": code,
                "language": "Python",
                "imports": [],
                "functions": [{"name": "run_cmd"}],
                "classes": [],
                "file_type": "source",
            }
            prompt = analyzer._generate_security_prompt(parsed, filename="cmd.py")
            assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
            assert "[LLM SEMANTIC TAINT REASONING]" in prompt
            assert "cmd.py" in prompt

    def test_sliced_prompt_generated_for_eval_and_open_sinks(self, analyzer):
        for sink_call in ["eval(code_str)", "open(file_path)"]:
            code = (
                "def dangerous(param):\n"
                f"    target = param\n"
                f"    {sink_call.replace('code_str', 'target').replace('file_path', 'target')}\n"
            )
            parsed = {
                "content": code,
                "language": "Python",
                "imports": [],
                "functions": [{"name": "dangerous"}],
                "classes": [],
                "file_type": "source",
            }
            prompt = analyzer._generate_security_prompt(parsed, filename="flaw.py")
            assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
            assert "[LLM SEMANTIC TAINT REASONING]" in prompt

    def test_fallback_to_general_prompt_when_no_sinks_present(self, analyzer):
        code = (
            "def calculate(a, b):\n"
            "    total = a + b\n"
            "    return total * 2\n"
        )
        parsed = {
            "content": code,
            "language": "Python",
            "imports": [],
            "functions": [{"name": "calculate"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="math_util.py")

        assert "[AST-VERIFIED STRUCTURAL FACTS]" not in prompt
        assert "Perform a comprehensive security analysis of this Python code" in prompt
        assert "--- BEGIN SOURCE ---" in prompt

    def test_fallback_to_general_prompt_when_use_ast_slicer_disabled(self):
        analyzer = CodeAnalyzer(use_semgrep=False, use_llm=False, use_ast_slicer=False)
        code = (
            "def run(user_input):\n"
            "    os.system(user_input)\n"
        )
        parsed = {
            "content": code,
            "language": "Python",
            "imports": ["os"],
            "functions": [{"name": "run"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="exec.py")

        assert "[AST-VERIFIED STRUCTURAL FACTS]" not in prompt
        assert "Perform a comprehensive security analysis of this Python code" in prompt
        assert "os.system(user_input)" in prompt

    def test_fallback_on_syntax_error_or_non_python(self, analyzer):
        parsed = {
            "content": "function test() { var x = 1; eval(x); }",
            "language": "JavaScript",
            "imports": [],
            "functions": ["test"],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="script.js")

        assert "[AST-VERIFIED STRUCTURAL FACTS]" not in prompt
        assert "Perform a comprehensive security analysis of this JavaScript code" in prompt

    def test_dual_scope_preserves_module_constants_in_reference_code(self, analyzer):
        """Dual-Scope: files with slices must preserve all module constants in reference code."""
        code = (
            "SECRET_KEY = 'hardcoded-insecure-django-secret'\n"
            "DEBUG = True\n"
            "ALLOWED_HOSTS = ['*']\n"
            "def handle_query(user_id):\n"
            "    query = f'SELECT * FROM accounts WHERE id = {user_id}'\n"
            "    cursor.execute(query)\n"
        )
        parsed = {
            "content": code,
            "language": "Python",
            "imports": [],
            "functions": [{"name": "handle_query"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="app_views.py")

        # 1. Facts block contains slice
        assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
        assert "cursor.execute" in prompt
        # 2. Module constants identified in facts block
        assert "Module Constants / Configuration: ['SECRET_KEY', 'DEBUG', 'ALLOWED_HOSTS']" in prompt
        # 3. Reference source code completely intact
        assert "--- BEGIN FULL SOURCE (REFERENCE) ---" in prompt
        assert "SECRET_KEY = 'hardcoded-insecure-django-secret'" in prompt
        assert "DEBUG = True" in prompt
        assert "ALLOWED_HOSTS = ['*']" in prompt
        # 4. Dual-Scope reasoning directives present
        assert "DUAL-SCOPE SECURITY ANALYSIS" in prompt
        assert "Scope A" in prompt
        assert "Scope B" in prompt
        assert "DO NOT limit your vulnerability reporting to only statements present in the AST slices" in prompt

    def test_sliced_prompt_uses_adaptive_context_slicing_on_large_file(self, analyzer):
        """CodeAnalyzer._generate_security_prompt should apply adaptive context slicing for files > 500 LOC."""
        lines = [
            "SECRET_KEY = 'hardcoded-insecure-key'",
            "DEBUG = False",
            "CONFIG = {'max': 100}",
        ]
        for i in range(1, 4):
            lines.append(f"def unrelated_task_{i}():")
            for j in range(100):
                lines.append(f"    var_{i}_{j} = {j}")
            lines.append("    return None")

        lines.append("def db_query(user_id):")
        lines.append("    import sqlite3")
        lines.append("    conn = sqlite3.connect(':memory:')")
        lines.append("    cursor = conn.cursor()")
        lines.append("    sql = f'SELECT * FROM users WHERE id = {user_id}'")
        lines.append("    cursor.execute(sql)")
        lines.append("    return cursor.fetchall()")

        for i in range(4, 7):
            lines.append(f"def unrelated_task_{i}():")
            for j in range(100):
                lines.append(f"    var_{i}_{j} = {j}")
            lines.append("    return None")

        code = "\n".join(lines)
        assert len(code.split("\n")) > 600

        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": [{"name": "db_query"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = analyzer._generate_security_prompt(parsed, filename="large_db.py")

        assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
        assert "[LLM SEMANTIC TAINT REASONING]" in prompt
        assert "--- BEGIN FULL SOURCE (REFERENCE) ---" in prompt
        # Module constants preserved
        assert "SECRET_KEY = 'hardcoded-insecure-key'" in prompt
        assert "DEBUG = False" in prompt
        assert "CONFIG = {'max': 100}" in prompt
        # Sliced function preserved
        assert "cursor.execute" in prompt
        assert "def db_query" in prompt
        # Unrelated functions collapsed & outline present
        assert "FILE OUTLINE: REMAINING CLASSES & FUNCTIONS" in prompt
        assert "var_1_50 = 50" not in prompt


class TestScannerAndScanOptionsIntegration:
    def test_scan_options_default_ast_slicer(self):
        opts = ScanOptions(target=".")
        assert opts.use_ast_slicer is True

    def test_scan_options_disable_ast_slicer(self):
        opts = ScanOptions(target=".", use_ast_slicer=False)
        assert opts.use_ast_slicer is False

    def test_scanner_passes_use_ast_slicer_to_analyzer(self):
        opts_true = ScanOptions(target=".", use_llm=False, use_semgrep=False, use_ast_slicer=True)
        scanner_true = Scanner(opts_true)
        assert scanner_true.analyzer.use_ast_slicer is True

        opts_false = ScanOptions(target=".", use_llm=False, use_semgrep=False, use_ast_slicer=False)
        scanner_false = Scanner(opts_false)
        assert scanner_false.analyzer.use_ast_slicer is False

    def test_scan_options_suppress_unconfirmed_rules(self):
        opts_default = ScanOptions(target=".")
        assert opts_default.suppress_unconfirmed_rules is False

        opts_suppress = ScanOptions(target=".", suppress_unconfirmed_rules=True)
        assert opts_suppress.suppress_unconfirmed_rules is True

    def test_scanner_assemble_suppress_unconfirmed_rules(self):
        from analyzer.discovery import DiscoveredFile
        from models.vulnerability import FindingSource, VulnerabilityType
        from tests.conftest import make_vuln
        from pathlib import Path

        root = Path(".")
        file_item = DiscoveredFile(path=root / "dummy.py", root=root, risk_score=10, reasons=["test"])
        semgrep_finding = make_vuln(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            cwe_id="CWE-89",
            file_path="dummy.py",
            start_line=10,
            source=FindingSource.SEMGREP,
            context="code snippet",
        )

        # 1. When suppress_unconfirmed_rules=True and LLM status is ok -> finding is suppressed
        scanner_suppress = Scanner(ScanOptions(target=".", use_llm=True, use_semgrep=True, suppress_unconfirmed_rules=True))
        reports = scanner_suppress._assemble(
            files=[file_item],
            rule_by_file={"dummy.py": [semgrep_finding]},
            llm_by_file={"dummy.py": []},
            tier_status={"dummy.py": "ok"},
        )
        assert len(reports[0].vulnerabilities) == 0

        # 2. When suppress_unconfirmed_rules=True but file was not routed to LLM -> finding is preserved
        reports_not_routed = scanner_suppress._assemble(
            files=[file_item],
            rule_by_file={"dummy.py": [semgrep_finding]},
            llm_by_file={"dummy.py": []},
            tier_status={"dummy.py": "not routed"},
        )
        assert len(reports_not_routed[0].vulnerabilities) == 1

        # 3. When suppress_unconfirmed_rules=False and LLM status is ok -> finding is preserved
        scanner_default = Scanner(ScanOptions(target=".", use_llm=True, use_semgrep=True, suppress_unconfirmed_rules=False))
        reports_default = scanner_default._assemble(
            files=[file_item],
            rule_by_file={"dummy.py": [semgrep_finding]},
            llm_by_file={"dummy.py": []},
            tier_status={"dummy.py": "ok"},
        )
        assert len(reports_default[0].vulnerabilities) == 1


class TestReExports:
    def test_analyzer_ast_slicer_reexports(self):
        from analyzer.ast_slicer import (
            ASTSlicer as Slicer1,
            SliceResult as Result1,
            SliceNode as Node1,
            ABSTRACT_SINK_CATEGORIES as Categories1,
            SINK_CALL_SIGNATURES as Sinks1,
            get_sink_category as get_sink_cat1,
        )
        from context.ast_slicer import (
            ASTSlicer as Slicer2,
            SliceResult as Result2,
            SliceNode as Node2,
            ABSTRACT_SINK_CATEGORIES as Categories2,
            SINK_CALL_SIGNATURES as Sinks2,
            get_sink_category as get_sink_cat2,
        )
        assert Slicer1 is Slicer2
        assert Result1 is Result2
        assert Node1 is Node2
        assert Categories1 == Categories2
        assert Sinks1 == Sinks2
        assert get_sink_cat1 is get_sink_cat2

    def test_analyzer_package_exports(self):
        import analyzer
        assert hasattr(analyzer, "ASTSlicer")
        assert hasattr(analyzer, "PromptManager")
        assert hasattr(analyzer, "CWE_TAINT_RULES")
        assert hasattr(analyzer, "ABSTRACT_SINK_CATEGORIES")
        assert hasattr(analyzer, "get_sink_category")


class TestMultiSinkExtraction:
    @pytest.fixture
    def analyzer(self):
        return CodeAnalyzer(use_semgrep=False, use_llm=False, use_ast_slicer=True)

    def test_multi_sink_extraction_up_to_10_slices(self, analyzer):
        """Verify _extract_ast_slices extracts multiple sinks in logical line order."""
        code = (
            "SECRET_KEY = 'hardcoded-insecure-secret-key'\n"
            "def task1(user_input):\n"
            "    cursor.execute(user_input)\n"
            "def task2(cmd):\n"
            "    os.system(cmd)\n"
            "def task3(filepath):\n"
            "    open(filepath, 'r')\n"
            "def task4(url):\n"
            "    requests.get(url)\n"
        )
        slices = analyzer._extract_ast_slices(code)
        assert len(slices) >= 4
        # Verify slices are in strictly ascending line order
        line_numbers = [s.target_sink_line for s in slices]
        assert line_numbers == sorted(line_numbers)
        # Verify distinct sinks captured
        sink_names = [s.sink_name for s in slices]
        assert "cursor.execute" in sink_names
        assert "os.system" in sink_names
        assert "open" in sink_names
        assert "requests.get" in sink_names

    def test_multi_sink_extraction_capped_at_10(self, analyzer):
        """Verify _extract_ast_slices caps maximum slices at 10 and maintains order."""
        lines = []
        for i in range(1, 15):
            lines.append(f"def func_{i}(arg_{i}):")
            lines.append(f"    os.system(arg_{i})")
        code = "\n".join(lines)

        slices = analyzer._extract_ast_slices(code)
        assert len(slices) == 10
        line_numbers = [s.target_sink_line for s in slices]
        assert line_numbers == sorted(line_numbers)

    def test_multi_sink_slices_passed_to_prompt(self, analyzer):
        """Verify _generate_security_prompt passes all extracted slices into the prompt."""
        code = (
            "SECRET_KEY = 'hardcoded-insecure-secret-key'\n"
            "def task1(cmd):\n"
            "    os.system(cmd)\n"
            "def task2(path):\n"
            "    open(path, 'r')\n"
        )
        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": ["task1", "task2"],
            "classes": [],
            "file_type": "source",
        }
        prompt = analyzer._generate_security_prompt(parsed, "multi_sinks.py")
        assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
        assert "Total Dangerous Slices Extracted:" in prompt
        assert "os.system" in prompt
        assert "open" in prompt
        assert "SECRET_KEY = 'hardcoded-insecure-secret-key'" in prompt

    def test_interprocedural_call_site_slice_in_security_prompt(self, analyzer):
        """Verify _extract_ast_slices captures inter-procedural call-site sink anchors."""
        code = (
            "def run_sql(query):\n"
            "    cursor.execute(query)\n"
            "def handler(user_req):\n"
            "    sql = 'SELECT ' + user_req\n"
            "    run_sql(sql)\n"
        )
        slices = analyzer._extract_ast_slices(code)
        # Should extract slice for line 2 (primitive) and line 5 (inter-procedural call-site)
        assert len(slices) >= 2
        sink_names = [s.sink_name for s in slices]
        assert "cursor.execute" in sink_names
        assert "run_sql" in sink_names

        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": ["run_sql", "handler"],
            "classes": [],
            "file_type": "source",
        }
        prompt = analyzer._generate_security_prompt(parsed, "interproc.py")
        assert "[AST-VERIFIED STRUCTURAL FACTS]" in prompt
        assert "run_sql" in prompt
        assert "cursor.execute" in prompt


