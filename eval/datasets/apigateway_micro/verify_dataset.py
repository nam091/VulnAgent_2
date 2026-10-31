#!/usr/bin/env python3
"""Dataset Verification Script for Microservice / API Gateway Benchmark.

Validates:
1. Dataset structure: labels.json and samples/ directory.
2. labels.json schema compliance (schema_version, labels, clean_files, match_mode).
3. 100% valid Python syntax for all sample files via AST parsing.
4. Accurate sink line locations and tokens for all labeled vulnerabilities.
5. Microservice cross-file architectural dependencies and import linkages.
6. Clean control implementations (auth middleware, rate limiter, crypto utils, validators).
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
    "gateway_router.py",
    "auth_middleware.py",
    "proxy_handler.py",
    "template_renderer.py",
    "eval_engine.py",
    "deserializer.py",
    "rate_limiter.py",
    "crypto_utils.py",
    "validators.py",
}

EXPECTED_SINKS: Dict[str, Dict[str, any]] = {
    "proxy_handler.py": {
        "line": 22,
        "token": "requests.get(upstream_url",
        "cwe": "918",
    },
    "template_renderer.py": {
        "line": 28,
        "token": "render_template_string(template",
        "cwe": "79",
    },
    "eval_engine.py": {
        "line": 19,
        "token": "eval(query_expr",
        "cwe": "94",
    },
    "deserializer.py": {
        "line": 21,
        "token": "pickle.loads(payload",
        "cwe": "502",
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
    expected_clean = {"auth_middleware.py", "rate_limiter.py", "crypto_utils.py", "validators.py"}
    assert clean_files == expected_clean, (
        f"clean_files mismatch: expected {expected_clean}, got {clean_files}"
    )

    # Verify labeled entries
    for entry in data["labels"]:
        for key in ("file", "line", "cwe", "type", "note"):
            assert key in entry, f"Label entry missing required key '{key}': {entry}"
        sample_path = SAMPLES_DIR / entry["file"]
        assert sample_path.is_file(), f"Label references non-existent file: {entry['file']}"

    return data


def verify_python_syntax_and_sinks(labels_data: Dict) -> Dict[str, ast.AST]:
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

    print(f"[OK] {len(EXPECTED_FILES)}/{len(EXPECTED_FILES)} Python files parsed successfully with valid AST syntax.")

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
    """Verify microservice cross-file import connections."""
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

    # gateway_router -> auth_middleware, rate_limiter, proxy_handler, template_renderer, eval_engine, deserializer, validators
    gateway_imports = imports_by_file["gateway_router.py"]
    for expected in (
        "auth_middleware",
        "rate_limiter",
        "proxy_handler",
        "template_renderer",
        "eval_engine",
        "deserializer",
        "validators",
    ):
        assert expected in gateway_imports, (
            f"gateway_router.py missing required import '{expected}'"
        )

    # auth_middleware -> crypto_utils
    auth_imports = imports_by_file["auth_middleware.py"]
    assert "crypto_utils" in auth_imports, (
        "auth_middleware.py missing required import 'crypto_utils'"
    )

    # proxy_handler -> validators
    proxy_imports = imports_by_file["proxy_handler.py"]
    assert "validators" in proxy_imports, (
        "proxy_handler.py missing required import 'validators'"
    )

    # template_renderer -> validators
    template_imports = imports_by_file["template_renderer.py"]
    assert "validators" in template_imports, (
        "template_renderer.py missing required import 'validators'"
    )

    print("[OK] Microservice inter-file dependencies verified (Gateway -> Handlers -> Utilities).")


def verify_clean_controls(parsed_asts: Dict[str, ast.AST]):
    """Verify that clean control files contain required defense functions."""
    def get_function_names(tree: ast.AST) -> Set[str]:
        return {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    def get_class_names(tree: ast.AST) -> Set[str]:
        return {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}

    # rate_limiter.py
    rate_classes = get_class_names(parsed_asts["rate_limiter.py"])
    assert "TokenBucketRateLimiter" in rate_classes, "rate_limiter.py missing TokenBucketRateLimiter class"
    rate_code = (SAMPLES_DIR / "rate_limiter.py").read_text(encoding="utf-8")
    assert "time.monotonic()" in rate_code, "rate_limiter.py must use time.monotonic() for safe timing"

    # crypto_utils.py
    crypto_funcs = get_function_names(parsed_asts["crypto_utils.py"])
    for fn in ("generate_hmac_signature", "verify_hmac_signature", "generate_secure_token"):
        assert fn in crypto_funcs, f"crypto_utils.py missing function '{fn}'"

    # validators.py
    validator_funcs = get_function_names(parsed_asts["validators.py"])
    for fn in ("is_valid_url_scheme", "is_whitelisted_domain", "validate_upstream_url"):
        assert fn in validator_funcs, f"validators.py missing function '{fn}'"

    # auth_middleware.py
    auth_funcs = get_function_names(parsed_asts["auth_middleware.py"])
    for fn in ("extract_bearer_token", "verify_auth_token", "authenticate_gateway_request"):
        assert fn in auth_funcs, f"auth_middleware.py missing function '{fn}'"

    print("[OK] Clean control modules verified (rate_limiter, crypto_utils, validators, auth_middleware).")


def main():
    print("=" * 65)
    print(" Microservice / API Gateway Benchmark Verification ")
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
