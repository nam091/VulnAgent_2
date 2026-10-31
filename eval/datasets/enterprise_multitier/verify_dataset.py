#!/usr/bin/env python3
"""Dataset Verification Script for Enterprise Multi-tier Benchmark.

Validates:
1. Dataset structure: labels.json and samples/ directory.
2. labels.json schema compliance (schema_version, labels, clean_files, match_mode).
3. 100% valid Python syntax for all sample files via AST parsing.
4. Accurate sink line locations for all labeled vulnerabilities.
5. Multi-tier cross-file architectural dependencies and import linkages.
6. Clean control implementations (sanitizers, auth helpers, configs).
"""

import ast
import json
import sys
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parent
LABELS_PATH = ROOT / "labels.json"
SAMPLES_DIR = ROOT / "samples"

EXPECTED_FILES: Set[str] = {
    "config.py",
    "controllers.py",
    "user_service.py",
    "data_access.py",
    "file_service.py",
    "storage_driver.py",
    "network_client.py",
    "task_executor.py",
    "sanitizers.py",
    "auth_helper.py",
}

EXPECTED_SINKS: Dict[str, Dict[str, any]] = {
    "data_access.py": {
        "line": 30,
        "token": "cursor.execute",
        "cwe": "89",
    },
    "storage_driver.py": {
        "line": 22,
        "token": "open(",
        "cwe": "22",
    },
    "network_client.py": {
        "line": 20,
        "token": "requests.get",
        "cwe": "918",
    },
    "task_executor.py": {
        "line": 24,
        "token": "subprocess.call",
        "cwe": "78",
    },
}


def verify_labels_schema() -> Dict:
    """Validate labels.json schema and completeness."""
    assert LABELS_PATH.is_file(), f"Missing labels.json at {LABELS_PATH}"
    
    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("schema_version") == 1, "Expected schema_version == 1"
    assert "name" in data, "Missing 'name' field"
    assert "clean_files" in data and isinstance(data["clean_files"], list), "Missing clean_files list"
    assert "labels" in data and isinstance(data["labels"], list), "Missing labels list"

    # Verify clean files
    clean_files = set(data["clean_files"])
    expected_clean = {"config.py", "sanitizers.py", "auth_helper.py"}
    assert expected_clean.issubset(clean_files), (
        f"clean_files missing required controls: {expected_clean - clean_files}"
    )

    # Verify labeled entries
    for entry in data["labels"]:
        for key in ("file", "line", "cwe", "type", "note"):
            assert key in entry, f"Label entry missing required key '{key}': {entry}"
        sample_path = SAMPLES_DIR / entry["file"]
        assert sample_path.is_file(), f"Label references non-existent file: {entry['file']}"

    return data


def verify_python_syntax_and_sinks(labels_data: Dict):
    """Parse all sample files with AST and check sink line annotations."""
    assert SAMPLES_DIR.is_dir(), f"Missing samples directory at {SAMPLES_DIR}"

    actual_files = {p.name for p in SAMPLES_DIR.glob("*.py")}
    missing_files = EXPECTED_FILES - actual_files
    assert not missing_files, f"Missing expected files in samples/: {missing_files}"

    parsed_asts = {}
    file_lines_map = {}

    for file_name in sorted(EXPECTED_FILES):
        file_path = SAMPLES_DIR / file_name
        code_text = file_path.read_text(encoding="utf-8")
        assert len(code_text.strip()) > 50, f"File {file_name} is unexpectedly empty"

        # AST parsing guarantees 100% valid Python syntax
        try:
            tree = ast.parse(code_text, filename=file_name)
            parsed_asts[file_name] = tree
        except SyntaxError as e:
            raise AssertionError(f"Syntax error in {file_name}:{e.lineno}: {e.msg}") from e

        file_lines_map[file_name] = code_text.splitlines()

    print(f"[OK] 10/10 Python files parsed successfully with valid AST syntax.")

    # Validate sinks against line numbers
    labels_by_file = {entry["file"]: entry for entry in labels_data["labels"]}
    for vuln_file, sink_spec in EXPECTED_SINKS.items():
        assert vuln_file in labels_by_file, f"Missing label for vulnerable file: {vuln_file}"
        label = labels_by_file[vuln_file]
        assert str(label["cwe"]) == sink_spec["cwe"], (
            f"CWE mismatch for {vuln_file}: expected {sink_spec['cwe']}, got {label['cwe']}"
        )
        assert label["line"] == sink_spec["line"], (
            f"Line mismatch for {vuln_file}: expected {sink_spec['line']}, got {label['line']}"
        )
        
        # Verify the actual code line contains the sink token
        actual_line = file_lines_map[vuln_file][label["line"] - 1]
        assert sink_spec["token"] in actual_line, (
            f"Sink token '{sink_spec['token']}' not found at {vuln_file}:{label['line']}\n"
            f"Actual line: {actual_line}"
        )
        print(f"  [OK] Verified sink for {vuln_file}:{label['line']} (CWE-{sink_spec['cwe']}) -> {sink_spec['token']}")

    return parsed_asts


def verify_architecture_linkages(parsed_asts: Dict[str, ast.AST]):
    """Verify multi-tier cross-file import connections."""
    def extract_imported_modules(tree: ast.AST) -> Set[str]:
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
        return imports

    imports_by_file = {fname: extract_imported_modules(tree) for fname, tree in parsed_asts.items()}

    # controllers -> user_service, file_service, network_client
    controllers_imports = imports_by_file["controllers.py"]
    for expected in ("user_service", "file_service", "network_client"):
        assert expected in controllers_imports, (
            f"controllers.py missing required import '{expected}'"
        )

    # user_service -> data_access, task_executor
    user_service_imports = imports_by_file["user_service.py"]
    for expected in ("data_access", "task_executor"):
        assert expected in user_service_imports, (
            f"user_service.py missing required import '{expected}'"
        )

    # file_service -> storage_driver
    file_service_imports = imports_by_file["file_service.py"]
    assert "storage_driver" in file_service_imports, (
        "file_service.py missing required import 'storage_driver'"
    )

    print("[OK] Multi-tier inter-file dependencies verified (Controller -> Services -> Sinks).")


def verify_clean_controls(parsed_asts: Dict[str, ast.AST]):
    """Verify that clean control files contain required defense functions."""
    def get_function_names(tree: ast.AST) -> Set[str]:
        return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    # sanitizers.py
    sanitizer_funcs = get_function_names(parsed_asts["sanitizers.py"])
    for fn in ("safe_int_cast", "validate_whitelist_path", "escape_markup"):
        assert fn in sanitizer_funcs, f"sanitizers.py missing function '{fn}'"

    # auth_helper.py
    auth_funcs = get_function_names(parsed_asts["auth_helper.py"])
    for fn in ("hash_token", "verify_permission", "generate_session_token"):
        assert fn in auth_funcs, f"auth_helper.py missing function '{fn}'"

    print("[OK] Clean control modules verified (sanitizers, auth_helper).")


def main():
    print("=" * 65)
    print(" Enterprise Multi-tier Benchmark Verification ")
    print("=" * 65)
    
    labels_data = verify_labels_schema()
    parsed_asts = verify_python_syntax_and_sinks(labels_data)
    verify_architecture_linkages(parsed_asts)
    verify_clean_controls(parsed_asts)

    print("=" * 65)
    print(" ALL VERIFICATIONS PASSED (100% Syntax & Schema Compliant) ")
    print("=" * 65)


if __name__ == "__main__":
    main()
