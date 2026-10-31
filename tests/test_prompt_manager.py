"""Unit tests for analyzer.prompt_manager."""

import unittest
from analyzer.prompt_manager import PromptManager, CWE_TAINT_RULES, UNIVERSAL_SOURCES
from context.ast_slicer import ASTSlicer


class TestPromptManager(unittest.TestCase):
    def setUp(self):
        self.pm = PromptManager()

    def test_cwe_taint_rules_presence(self):
        """Ensure all required CWEs (89, 78, 22, 79) are defined with necessary keys."""
        for cwe_id in ["CWE-89", "CWE-78", "CWE-22", "CWE-79"]:
            self.assertIn(cwe_id, CWE_TAINT_RULES)
            rule = CWE_TAINT_RULES[cwe_id]
            self.assertIn("dangerous_sinks", rule)
            self.assertIn("valid_mitigations", rule)
            self.assertIn("invalid_controls", rule)
            self.assertIn("semantic_notes", rule)

    def test_expanded_cwe_taint_rules_presence(self):
        """Ensure all 21 core CWE groups are defined with complete taxonomy specifications."""
        expected_cwes = [
            "CWE-89",    # SQLi
            "CWE-78",    # Command Injection
            "CWE-22",    # Path Traversal
            "CWE-79",    # XSS
            "CWE-798",   # Hardcoded Secrets (SECRET_KEY)
            "CWE-918",   # SSRF
            "CWE-502",   # Insecure Deserialization
            "CWE-209",   # Information Disclosure / Exception traceback
            "CWE-352",   # CSRF
            "CWE-20",    # Improper Input Validation
            "CWE-1188",  # Insecure Default Configuration
            "CWE-639",   # Authorization Bypass / IDOR
            "CWE-287",   # Improper Authentication
            "CWE-284",   # Improper Access Control
            "CWE-328",   # Weak Hashing
            "CWE-330",   # Insecure Randomness
            "CWE-643",   # XPath Injection
            "CWE-614",   # Insecure Cookie Flag
            "CWE-90",    # LDAP Injection
            "CWE-601",   # Open Redirect
            "CWE-611",   # XML External Entity (XXE)
        ]
        self.assertEqual(len(expected_cwes), 21, "Expected exactly 21 CWEs in test list")
        self.assertEqual(len(CWE_TAINT_RULES), 21, "Expected exactly 21 CWEs in CWE_TAINT_RULES matrix")
        for cwe_id in expected_cwes:
            self.assertIn(cwe_id, CWE_TAINT_RULES, f"Missing required CWE taxonomy: {cwe_id}")
            rule = CWE_TAINT_RULES[cwe_id]
            self.assertIn("name", rule, f"Missing name in {cwe_id}")
            self.assertIn("dangerous_sinks", rule, f"Missing dangerous_sinks in {cwe_id}")
            self.assertIn("valid_mitigations", rule, f"Missing valid_mitigations in {cwe_id}")
            self.assertIn("invalid_controls", rule, f"Missing invalid_controls in {cwe_id}")
            self.assertIn("semantic_notes", rule, f"Missing semantic_notes in {cwe_id}")
            self.assertTrue(len(rule["dangerous_sinks"]) > 0)
            self.assertTrue(len(rule["valid_mitigations"]) > 0)
            self.assertTrue(len(rule["invalid_controls"]) > 0)
            self.assertTrue(len(rule["semantic_notes"]) > 0)

    def test_new_seven_cwe_taint_rules_detailed(self):
        """Verify detailed taxonomy for 7 newly added CWE groups (328, 330, 643, 614, 90, 601, 611)."""
        new_cwes = {
            "CWE-328": {
                "name_substr": "Weak Hash",
                "sink_sample": "hashlib.md5",
                "mitigation_sample": "bcrypt",
                "invalid_sample": "hashlib.md5()",
            },
            "CWE-330": {
                "name_substr": "Random",
                "sink_sample": "random.random",
                "mitigation_sample": "secrets",
                "invalid_sample": "Mersenne Twister",
            },
            "CWE-643": {
                "name_substr": "XPath",
                "sink_sample": "xpath",
                "mitigation_sample": "tree.xpath",
                "invalid_sample": "XPath",
            },
            "CWE-614": {
                "name_substr": "Cookie",
                "sink_sample": "response.set_cookie",
                "mitigation_sample": "secure=True",
                "invalid_sample": "secure=False",
            },
            "CWE-90": {
                "name_substr": "LDAP",
                "sink_sample": "ldap.search",
                "mitigation_sample": "escape_filter_chars",
                "invalid_sample": "LDAP",
            },
            "CWE-601": {
                "name_substr": "Redirect",
                "sink_sample": "redirect",
                "mitigation_sample": "allowlist",
                "invalid_sample": "redirect(request.args.get",
            },
            "CWE-611": {
                "name_substr": "XML",
                "sink_sample": "xml.etree.ElementTree.parse",
                "mitigation_sample": "defusedxml",
                "invalid_sample": "resolve_entities=True",
            },
        }

        for cwe_id, spec in new_cwes.items():
            self.assertIn(cwe_id, CWE_TAINT_RULES)
            rule = CWE_TAINT_RULES[cwe_id]
            self.assertIn("name", rule)
            self.assertIn("dangerous_sinks", rule)
            self.assertIn("valid_mitigations", rule)
            self.assertIn("invalid_controls", rule)
            self.assertIn("semantic_notes", rule)

            self.assertIn(spec["name_substr"].lower(), rule["name"].lower())
            self.assertTrue(any(spec["sink_sample"] in s for s in rule["dangerous_sinks"]))
            self.assertTrue(any(spec["mitigation_sample"] in m for m in rule["valid_mitigations"]))
            self.assertTrue(any(spec["invalid_sample"] in inv for inv in rule["invalid_controls"]))

    def test_semantic_disambiguation_guidelines_in_prompts(self):
        """Verify prompt instructions contain precise semantic disambiguation guidelines:
        - secrets vs random thông thường
        - bcrypt/argon2/sha256 vs md5/sha1
        - defusedxml vs lxml/ElementTree entity resolution
        - URL allowlist vs unvalidated redirect
        """
        code = "def sample(): pass\n"
        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": [{"name": "sample"}],
            "classes": [],
            "file_type": "source",
        }

        # 1. Check sliced prompt
        sliced_prompt = self.pm.generate_sliced_security_prompt(parsed, [], "sample.py")
        self.assertIn("secrets vs random", sliced_prompt)
        self.assertIn("bcrypt/argon2/sha256 vs md5/sha1", sliced_prompt)
        self.assertIn("defusedxml vs lxml/ElementTree entity resolution", sliced_prompt)
        self.assertIn("URL allowlist vs unvalidated redirect", sliced_prompt)

        # 2. Check general security prompt
        general_prompt = self.pm.generate_general_security_prompt(parsed, "sample.py")
        self.assertIn("secrets vs random", general_prompt)
        self.assertIn("bcrypt/argon2/sha256 vs md5/sha1", general_prompt)
        self.assertIn("defusedxml vs lxml/ElementTree entity resolution", general_prompt)
        self.assertIn("URL allowlist vs unvalidated redirect", general_prompt)

    def test_dual_scope_prompt_structure_and_instructions(self):
        """Verify Dual-Scope Prompting provides both Scope A and Scope B guidance."""
        code = (
            "SECRET_KEY = 'hardcoded-insecure-key'\n"
            "DEBUG = True\n"
            "def run_query(param):\n"
            "    cursor.execute(f'SELECT * FROM items WHERE id = {param}')\n"
        )
        slicer = ASTSlicer()
        slices = slicer.slice_from_sink(code, 4, "param")
        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": [{"name": "run_query"}],
            "classes": [],
            "file_type": "source",
        }
        prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "app.py")

        # Scope A & Scope B instructions
        self.assertIn("DUAL-SCOPE SECURITY ANALYSIS", prompt)
        self.assertIn("Scope A", prompt)
        self.assertIn("Scope B", prompt)
        self.assertIn("DO NOT limit your vulnerability reporting to only statements present in the AST slices", prompt)
        self.assertIn("SECRET_KEY", prompt)
        self.assertIn("DEBUG", prompt)
        self.assertIn("Module Constants / Configuration: ['SECRET_KEY', 'DEBUG']", prompt)
        self.assertIn("--- BEGIN FULL SOURCE (REFERENCE) ---", prompt)
        self.assertIn("SECRET_KEY = 'hardcoded-insecure-key'", prompt)

    def test_generate_general_security_prompt(self):
        """Test generating general prompt matching CodeAnalyzer format."""
        parsed = {
            "content": "def test():\n    pass\n",
            "language": "python",
            "imports": ["os"],
            "functions": [{"name": "test"}],
            "classes": [],
            "file_type": "source",
        }
        prompt = self.pm.generate_general_security_prompt(parsed, "test.py")
        self.assertIn("Perform a comprehensive security analysis of this python code", prompt)
        self.assertIn("--- BEGIN SOURCE ---", prompt)
        self.assertIn("--- END SOURCE ---", prompt)
        self.assertIn("   1 | def test():", prompt)
        self.assertIn("Imports: ['os']", prompt)
        self.assertIn("Functions: ['test']", prompt)

    def test_generate_sliced_security_prompt_with_ast_slicer(self):
        """Test generating prompt from ASTSlicer SliceResult."""
        code = (
            "import sqlite3\n"
            "def query(user_id):\n"
            "    sql = f'SELECT * FROM users WHERE id = {user_id}'\n"
            "    conn = sqlite3.connect('test.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(sql)\n"
        )
        slicer = ASTSlicer()
        slices = slicer.slice_from_sink(code, 6, "sql")

        parsed = {
            "content": code,
            "language": "python",
            "imports": ["sqlite3"],
            "functions": [{"name": "query"}],
            "classes": [],
            "file_type": "source",
        }

        prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "app.py")

        self.assertIn("[AST-VERIFIED STRUCTURAL FACTS]", prompt)
        self.assertIn("[LLM SEMANTIC TAINT REASONING]", prompt)
        self.assertIn("CANONICAL CWE TAINT & SANITIZATION MATRIX", prompt)
        self.assertIn("CWE-89", prompt)
        self.assertIn("CWE-78", prompt)
        self.assertIn("CWE-22", prompt)
        self.assertIn("CWE-79", prompt)
        self.assertIn("cursor.execute", prompt)
        self.assertIn("REQUIRED JSON OUTPUT SCHEMA", prompt)

    def test_universal_source_detection_guidelines(self):
        """Verify prompt includes Universal Source Detection across web frameworks and CLI."""
        code = (
            "from flask import request\n"
            "def handle_post():\n"
            "    user_data = request.form.get('input_val')\n"
            "    cursor.execute(f'SELECT * FROM users WHERE name = {user_data}')\n"
        )
        slicer = ASTSlicer()
        slices = slicer.slice_from_sink(code, 4, "user_data")
        parsed = {
            "content": code,
            "language": "python",
            "imports": ["flask"],
            "functions": [{"name": "handle_post"}],
            "classes": [],
            "file_type": "source",
        }
        prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "views.py")

        # Verify Universal Source Detection instructions
        self.assertIn("Universal Source Detection", prompt)
        self.assertIn("request.args", prompt)
        self.assertIn("request.form", prompt)
        self.assertIn("request.json", prompt)
        self.assertIn("request.cookies", prompt)
        self.assertIn("request.headers", prompt)
        self.assertIn("sys.argv", prompt)
        self.assertIn("input()", prompt)
        self.assertIn("os.environ", prompt)
        self.assertIn("Django", prompt)
        self.assertIn("Flask", prompt)
        self.assertIn("FastAPI", prompt)
        self.assertIn("CLI", prompt)

        # Verify Anti-bias independent taint analysis guidelines
        self.assertIn("Anti-Bias Directive", prompt)
        self.assertIn("objective data-flow taint propagation", prompt)

    def test_universal_sources_catalog_structure(self):
        """Verify UNIVERSAL_SOURCES dictionary contains expected categories and entry points."""
        self.assertIn("WEB_FRAMEWORKS", UNIVERSAL_SOURCES)
        self.assertIn("HEADERS_AND_COOKIES", UNIVERSAL_SOURCES)
        self.assertIn("CLI_AND_ENV", UNIVERSAL_SOURCES)
        self.assertIn("PAYLOADS_AND_STREAMS", UNIVERSAL_SOURCES)

        # Spot-check critical entries
        self.assertIn("request.args", UNIVERSAL_SOURCES["WEB_FRAMEWORKS"])
        self.assertIn("request.form", UNIVERSAL_SOURCES["WEB_FRAMEWORKS"])
        self.assertIn("request.cookies", UNIVERSAL_SOURCES["HEADERS_AND_COOKIES"])
        self.assertIn("request.headers", UNIVERSAL_SOURCES["HEADERS_AND_COOKIES"])
        self.assertIn("sys.argv", UNIVERSAL_SOURCES["CLI_AND_ENV"])
        self.assertIn("os.environ", UNIVERSAL_SOURCES["CLI_AND_ENV"])
        self.assertIn("input()", UNIVERSAL_SOURCES["CLI_AND_ENV"])

    def test_adaptive_context_slicing_small_file_preserves_100_percent_content(self):
        """A small file (<= 500 lines, e.g. 100 lines) must retain 100% full numbered source."""
        lines = [
            "import os",
            "import sys",
            "",
            "SECRET_KEY = 'test-secret-key'",
            "DEBUG = True",
            "CONFIG = {'cache': False}",
            "",
            "def small_helper(val):",
            "    return val * 2",
            "",
            "def handle_request(user_input):",
            "    cmd = 'cat ' + user_input",
            "    os.system(cmd)",
            "    return True",
            "",
        ]
        # Pad to exactly 100 lines
        while len(lines) < 100:
            lines.append(f"# line padding {len(lines) + 1}")
        small_code = "\n".join(lines)
        self.assertEqual(len(small_code.split("\n")), 100)

        # Slice target at os.system (line 13)
        slices = [{"target_sink_line": 13, "sliced_lines": [11, 12, 13]}]

        result = self.pm._generate_adaptive_reference_content(
            full_content=small_code,
            slices=slices,
            max_full_lines=500,
        )

        # Must match 100% full numbered source exactly
        expected_numbered = self.pm.number_lines(small_code)
        self.assertEqual(result, expected_numbered)
        self.assertNotIn("collapsed", result)
        self.assertNotIn("FILE OUTLINE", result)
        self.assertIn("   1 | import os", result)
        self.assertIn(" 100 | # line padding 100", result)

    def test_adaptive_context_slicing_large_file_preserves_constants_and_slice_while_collapsing_unrelated(self):
        """A large file (>600 lines) must preserve module constants & target function (+-20 lines) and collapse unrelated functions."""
        lines = [
            '"""Main web service module."""',
            "import os",
            "import sys",
            "from flask import Flask, request",
            "",
            "SECRET_KEY = 'super-secret-production-django-key'",
            "DEBUG = False",
            "CONFIG = {'max_connections': 100, 'timeout': 60}",
            "ALLOWED_HOSTS = ['api.internal.corp', 'localhost']",
            "",
        ]
        # Unrelated function 1 (120 lines)
        lines.append("def unrelated_worker_one(task_id):")
        lines.append('    """Unrelated worker that handles async metrics."""')
        for i in range(118):
            lines.append(f"    worker_one_step_{i} = {i} * 3")
        lines.append("    return None")
        lines.append("")

        # Unrelated function 2 (120 lines)
        lines.append("def unrelated_worker_two(batch_data):")
        lines.append('    """Unrelated worker that processes batch jobs."""')
        for i in range(118):
            lines.append(f"    worker_two_step_{i} = {i} * 5")
        lines.append("    return None")
        lines.append("")

        # Target vulnerable function with SQL injection sink
        lines.append("def vulnerable_user_lookup(user_id):")
        lines.append('    """Vulnerable endpoint querying DB without parameterization."""')
        lines.append("    import sqlite3")
        lines.append("    conn = sqlite3.connect('app.db')")
        lines.append("    cursor = conn.cursor()")
        lines.append("    sql = f'SELECT * FROM users WHERE id = {user_id}'")
        lines.append("    cursor.execute(sql)")
        lines.append("    return cursor.fetchall()")
        lines.append("")

        # Unrelated class with methods (120 lines)
        lines.append("class UnrelatedAnalyticsService:")
        lines.append('    """Unrelated service for gathering analytics."""')
        lines.append("    service_name = 'analytics'")
        lines.append("")
        lines.append("    def aggregate_metrics(self, payload):")
        for i in range(115):
            lines.append(f"        metric_calc_{i} = {i}")
        lines.append("        return metric_calc_0")
        lines.append("")

        # Pad to > 600 lines (e.g. 650 lines)
        while len(lines) < 650:
            lines.append(f"# end of file padding {len(lines) + 1}")

        large_code = "\n".join(lines)
        total_loc = len(large_code.split("\n"))
        self.assertGreater(total_loc, 600)

        # Identify line of cursor.execute
        raw_lines = large_code.split("\n")
        sink_line = [i for i, l in enumerate(raw_lines, 1) if "cursor.execute(sql)" in l][0]

        slices = [{
            "target_sink_line": sink_line,
            "sliced_lines": [sink_line - 1, sink_line],
            "sink_name": "cursor.execute",
        }]

        result = self.pm._generate_adaptive_reference_content(
            full_content=large_code,
            slices=slices,
            max_full_lines=500,
        )

        # (a) Header / Imports & Module-Level Constants preserved
        self.assertIn("SECRET_KEY = 'super-secret-production-django-key'", result)
        self.assertIn("DEBUG = False", result)
        self.assertIn("CONFIG = {'max_connections': 100, 'timeout': 60}", result)
        self.assertIn("ALLOWED_HOSTS = ['api.internal.corp', 'localhost']", result)
        self.assertIn("import os", result)
        self.assertIn("from flask import Flask, request", result)

        # (b) Complete function containing slice/sink and surrounding context (+-20 lines) preserved
        self.assertIn("def vulnerable_user_lookup(user_id):", result)
        self.assertIn("cursor.execute(sql)", result)
        self.assertIn(f"{sink_line:>4} |     cursor.execute(sql)", result)

        # (c) Unrelated functions/classes collapsed and outlined
        self.assertIn("FILE OUTLINE: REMAINING CLASSES & FUNCTIONS", result)
        self.assertIn("def unrelated_worker_one", result)
        self.assertIn("def unrelated_worker_two", result)
        self.assertIn("class UnrelatedAnalyticsService", result)

        # Bodies of distant unrelated functions/classes should NOT be present
        self.assertNotIn("worker_one_step_50 = 150", result)
        self.assertNotIn("worker_two_step_50 = 250", result)
        self.assertNotIn("metric_calc_50 = 50", result)

        # Collapsed gap markers present
        self.assertIn("collapsed", result)

        # Output line count significantly reduced (compact context window)
        result_lines = result.split("\n")
        self.assertLess(len(result_lines), 200, f"Expected < 200 lines, got {len(result_lines)}")

    def test_generate_sliced_security_prompt_with_large_file_adaptive_slicing(self):
        """Verify generate_sliced_security_prompt integrates adaptive slicing into AST structural facts."""
        lines = [
            "SECRET_KEY = 'insecure-prod-key'",
            "DEBUG = True",
        ]
        for i in range(1, 4):
            lines.append(f"def filler_fn_{i}():")
            for j in range(100):
                lines.append(f"    v_{i}_{j} = {j}")
            lines.append("    return None")

        lines.append("def sql_entry(user_id):")
        lines.append("    sql = f'SELECT * FROM accounts WHERE id = {user_id}'")
        lines.append("    cursor.execute(sql)")

        for i in range(4, 7):
            lines.append(f"def filler_fn_{i}():")
            for j in range(100):
                lines.append(f"    v_{i}_{j} = {j}")
            lines.append("    return None")

        large_code = "\n".join(lines)
        raw_lines = large_code.split("\n")
        sink_line = [i for i, l in enumerate(raw_lines, 1) if "cursor.execute(sql)" in l][0]

        parsed = {
            "content": large_code,
            "language": "python",
            "imports": [],
            "functions": [{"name": "sql_entry"}],
            "classes": [],
            "file_type": "source",
        }
        slices = [{"target_sink_line": sink_line, "sliced_lines": [sink_line - 1, sink_line], "sink_name": "cursor.execute"}]

        prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "large_app.py", max_full_lines=500)

        # Dual-Scope structure intact
        self.assertIn("[AST-VERIFIED STRUCTURAL FACTS]", prompt)
        self.assertIn("[LLM SEMANTIC TAINT REASONING]", prompt)
        self.assertIn("--- BEGIN FULL SOURCE (REFERENCE) ---", prompt)

        # Adaptive reference content present inside reference source block
        self.assertIn("SECRET_KEY = 'insecure-prod-key'", prompt)
        self.assertIn("cursor.execute(sql)", prompt)
        self.assertIn("FILE OUTLINE: REMAINING CLASSES & FUNCTIONS", prompt)
        self.assertNotIn("v_1_50 = 50", prompt)

    def test_generate_adaptive_reference_content_module_alias(self):
        """Ensure _generate_adaptive_reference_content is exported at module level."""
        from analyzer.prompt_manager import _generate_adaptive_reference_content
        code = "SECRET_KEY = '123'\nDEBUG = True\n"
        out = _generate_adaptive_reference_content(code, [], max_full_lines=500)
        self.assertEqual(out, self.pm.number_lines(code))

    def test_dual_scope_prompt_with_multiple_slices(self):
        """Verify prompt dual-scope displays full list of AST slices and adaptive reference context."""
        code = (
            "SECRET_KEY = 'hardcoded-top-secret-token'\n"
            "def handle_upload(path):\n"
            "    target = open(path, 'r')\n"
            "    return target.read()\n"
            "def handle_command(cmd):\n"
            "    os.system(cmd)\n"
            "def handle_db(uid):\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        )
        slicer = ASTSlicer()
        slice1 = slicer.slice_from_sink(code, 3, "path")
        slice2 = slicer.slice_from_sink(code, 6, "cmd")
        slice3 = slicer.slice_from_sink(code, 8, "uid")
        slices = [slice1, slice2, slice3]

        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": ["handle_upload", "handle_command", "handle_db"],
            "classes": [],
            "file_type": "source",
        }
        prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "multitask.py")

        self.assertIn("Total Dangerous Slices Extracted: 3", prompt)
        self.assertIn("Slice #1 of 3:", prompt)
        self.assertIn("Slice #2 of 3:", prompt)
        self.assertIn("Slice #3 of 3:", prompt)
        self.assertIn("open", prompt)
        self.assertIn("os.system", prompt)
        self.assertIn("cursor.execute", prompt)
        self.assertIn("SECRET_KEY = 'hardcoded-top-secret-token'", prompt)
        self.assertIn("--- BEGIN FULL SOURCE (REFERENCE) ---", prompt)
        self.assertIn("--- END FULL SOURCE (REFERENCE) ---", prompt)

    def test_refined_taint_matrix_sinks_and_notes(self):
        """Verify task ref-taint-prompt updates to CWE_TAINT_RULES for CWE-22, 643, 328, 330."""
        # 1. CWE-22 Path Traversal & Zip Slip
        cwe22 = CWE_TAINT_RULES["CWE-22"]
        for sink in ["tarfile.extractall", "zipfile.extractall", "extractall", "shutil.unpack_archive"]:
            self.assertIn(sink, cwe22["dangerous_sinks"], f"Missing dangerous sink {sink} in CWE-22")
        # Check notes on Zip Slip / Tar Slip and containment check for each member
        has_zip_slip_note = any("Zip Slip" in note or "Tar Slip" in note for note in cwe22["semantic_notes"])
        has_containment_check = any("containment" in m.lower() for m in cwe22["valid_mitigations"])
        self.assertTrue(has_zip_slip_note, "CWE-22 semantic_notes must explicitly describe Zip Slip / Tar Slip")
        self.assertTrue(has_containment_check, "CWE-22 valid_mitigations must include member containment check")

        # 2. CWE-643 XPath Injection
        cwe643 = CWE_TAINT_RULES["CWE-643"]
        for sink in ["findtext", "iterfind", "getiterator", "xpath_eval"]:
            self.assertIn(sink, cwe643["dangerous_sinks"], f"Missing dangerous sink {sink} in CWE-643")

        # 3. CWE-328 Weak Hash
        cwe328 = CWE_TAINT_RULES["CWE-328"]
        for sink in ["hashlib.new", "sha224", "ripemd160"]:
            self.assertIn(sink, cwe328["dangerous_sinks"], f"Missing dangerous sink {sink} in CWE-328")

        # 4. CWE-330 Insecure Randomness
        cwe330 = CWE_TAINT_RULES["CWE-330"]
        for sink in ["random.triangular", "random.betavariate", "random.uniform"]:
            self.assertIn(sink, cwe330["dangerous_sinks"], f"Missing dangerous sink {sink} in CWE-330")

    def test_dual_scope_interprocedural_and_zip_slip_guidance(self):
        """Verify Dual-Scope prompts contain guidance on inter-procedural taint forwarding and Zip Slip."""
        code = "def sample(): pass\n"
        parsed = {
            "content": code,
            "language": "python",
            "imports": [],
            "functions": [{"name": "sample"}],
            "classes": [],
            "file_type": "source",
        }

        # 1. Sliced Dual-Scope prompt
        sliced_prompt = self.pm.generate_sliced_security_prompt(parsed, [], "sample.py")
        self.assertIn("Inter-procedural taint forwarding", sliced_prompt)
        self.assertIn("helper/wrapper", sliced_prompt)
        self.assertIn("extractall", sliced_prompt)
        self.assertIn("Zip Slip", sliced_prompt)

        # 2. General security prompt
        general_prompt = self.pm.generate_general_security_prompt(parsed, "sample.py")
        self.assertIn("Inter-procedural taint forwarding", general_prompt)
        self.assertIn("Zip Slip", general_prompt)

    def test_cmc_reflection_beam_taint_reasoning_and_clean_control_guidelines(self):
        """Verify Taint Reasoning instructions optimized for cmc/reflection/beam:free:
        1. Clean control code / safe implementations (html.escape, os.path.basename,
           parameterized SQL, hardcoded constants) must return {"vulnerabilities": []}
           without speculative guessing.
        2. Tainted flows directly reaching dangerous sinks without sanitizers must be
           immediately confirmed matching the 11 benchmark CWE groups.
        """
        code = (
            "import os, html, sqlite3\n"
            "def safe_handler(val, path):\n"
            "    cleaned_html = html.escape(val)\n"
            "    base_name = os.path.basename(path)\n"
            "    cursor.execute('SELECT * FROM users WHERE id = %s', (val,))\n"
            "    return open(base_name, 'r').read()\n"
        )
        parsed = {
            "content": code,
            "language": "python",
            "imports": ["os", "html", "sqlite3"],
            "functions": [{"name": "safe_handler"}],
            "classes": [],
            "file_type": "source",
        }

        # 1. Sliced Dual-Scope prompt verification
        slices = [{"target_sink_line": 6, "sliced_lines": [4, 6], "sink_name": "open"}]
        sliced_prompt = self.pm.generate_sliced_security_prompt(parsed, slices, "safe_views.py")

        # Optimization for cmc/reflection/beam:free
        self.assertIn("cmc/reflection/beam:free", sliced_prompt)
        self.assertIn("clean control code", sliced_prompt)
        self.assertIn("html.escape", sliced_prompt)
        self.assertIn("os.path.basename", sliced_prompt)
        self.assertIn("parameterized SQL", sliced_prompt)
        self.assertIn("hằng số cố định", sliced_prompt)
        self.assertIn('{"vulnerabilities": []}', sliced_prompt)
        self.assertIn("phỏng đoán suy diễn", sliced_prompt)
        self.assertIn("Anti-Speculation Directive", sliced_prompt)

        # 11 Benchmark CWE Groups confirmation
        self.assertIn("11 nhóm CWE của benchmark", sliced_prompt)
        for cwe in ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-328", "CWE-330", "CWE-643", "CWE-614", "CWE-90", "CWE-601"]:
            self.assertIn(cwe, sliced_prompt, f"Missing benchmark CWE {cwe} in sliced prompt")

        # 2. General security prompt verification
        general_prompt = self.pm.generate_general_security_prompt(parsed, "safe_views.py")
        self.assertIn("cmc/reflection/beam:free", general_prompt)
        self.assertIn("clean control code", general_prompt)
        self.assertIn("html.escape", general_prompt)
        self.assertIn("os.path.basename", general_prompt)
        self.assertIn("parameterized SQL", general_prompt)
        self.assertIn("hằng số cố định", general_prompt)
        self.assertIn('{"vulnerabilities": []}', general_prompt)
        self.assertIn("phỏng đoán suy diễn", general_prompt)
        self.assertIn("11 nhóm CWE của benchmark", general_prompt)



if __name__ == "__main__":
    unittest.main()
