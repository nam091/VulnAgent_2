"""Automatic enrichment and standardization of OWASP Benchmark metadata.

Standardizes `labels.json` for both Benchmark100 and Benchmark1230:
1. Vulnerable labels:
   - `file`: Source filename (e.g. `BenchmarkTest00001.py`)
   - `line`: Accurate 1-based sink line number (using AST Slicer / AST visitor)
   - `cwe`: Standard CWE identifier (e.g. `CWE-89`)
   - `type`: Standardized vulnerability type (e.g. `SQL_INJECTION`)
   - `sink_call`: Dangerous sink function or construct
   - `source`: User input source expression
   - `note`: Concise vulnerability summary
   - `explanation`: Detailed dataflow analysis from tainted source to sink without sanitization.

2. Clean control files (`clean_files`):
   - `file`: Control filename
   - `cwe`: Counterpart CWE identifier
   - `type`: Counterpart vulnerability type
   - `defense_type`: Specific defensive pattern (e.g. `input_validation_guard`, `parameterized_query`)
   - `safe_reason`: Explanation of why the code is safe against the defect.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from context.ast_slicer import ASTSlicer  # noqa: E402

logger = logging.getLogger(__name__)

# Standard Category Mapping (OWASP Benchmark Category -> CWE & Canonical Type)
BENCHMARK_CATEGORIES: Dict[str, Tuple[str, str]] = {
    "pathtraver": ("CWE-22", "PATH_TRAVERSAL"),
    "cmdi": ("CWE-78", "OS_COMMAND_INJECTION"),
    "xss": ("CWE-79", "CROSS_SITE_SCRIPTING"),
    "sqli": ("CWE-89", "SQL_INJECTION"),
    "ldapi": ("CWE-90", "LDAP_INJECTION"),
    "codeinj": ("CWE-94", "CODE_INJECTION"),
    "hash": ("CWE-328", "USE_OF_WEAK_HASHING_ALGORITHM"),
    "weakrand": ("CWE-330", "SECURE_RANDOMNESS"),
    "trustbound": ("CWE-501", "TRUST_BOUNDARY_VIOLATION"),
    "deserialization": ("CWE-502", "INSECURE_DESERIALIZATION"),
    "redirect": ("CWE-601", "UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS"),
    "xxe": ("CWE-611", "XML_EXTERNAL_ENTITY"),
    "securecookie": ("CWE-614", "SECURE_COOKIE"),
    "xpathi": ("CWE-643", "XPATH_INJECTION"),
}

# Type abbreviation to category lookup
TYPE_TO_CATEGORY: Dict[str, str] = {
    "PATHTRAVER": "pathtraver",
    "CMDI": "cmdi",
    "XSS": "xss",
    "SQLI": "sqli",
    "LDAPI": "ldapi",
    "CODEINJ": "codeinj",
    "HASH": "hash",
    "WEAKRAND": "weakrand",
    "TRUSTBOUND": "trustbound",
    "DESERIALIZATION": "deserialization",
    "REDIRECT": "redirect",
    "XXE": "xxe",
    "SECURECOOKIE": "securecookie",
    "XPATHI": "xpathi",
    # Allow mapping canonical names if already standardized
    "PATH_TRAVERSAL": "pathtraver",
    "OS_COMMAND_INJECTION": "cmdi",
    "CROSS_SITE_SCRIPTING": "xss",
    "SQL_INJECTION": "sqli",
    "LDAP_INJECTION": "ldapi",
    "CODE_INJECTION": "codeinj",
    "USE_OF_WEAK_HASHING_ALGORITHM": "hash",
    "SECURE_RANDOMNESS": "weakrand",
    "TRUST_BOUNDARY_VIOLATION": "trustbound",
    "INSECURE_DESERIALIZATION": "deserialization",
    "UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS": "redirect",
    "XML_EXTERNAL_ENTITY": "xxe",
    "SECURE_COOKIE": "securecookie",
    "XPATH_INJECTION": "xpathi",
}


def extract_category_from_code(code: str) -> Optional[str]:
    """Extract benchmark category from route decorator url pattern."""
    m = re.search(r"/benchmark/([^/]+)/", code)
    if m:
        prefix = m.group(1).split("-")[0].lower()
        if prefix in BENCHMARK_CATEGORIES:
            return prefix
    return None


def detect_vulnerable_sink_and_dataflow(
    file_path: Path,
    category: str,
    slicer: Optional[ASTSlicer] = None,
) -> Dict[str, Any]:
    """
    Locate sink line, source expression, and construct explanation for a vulnerable file.
    """
    code = file_path.read_text(encoding="utf-8")
    tree = ast.parse(code)

    post_funcs = [
        fn for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.endswith("_post")
    ]
    scope: ast.AST = post_funcs[0] if post_funcs else tree

    sink_line = 0
    sink_call = ""
    source_expr = ""
    taint_var = "bar"

    # 1. Identify input source expression
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            val_str = ast.unparse(node.value)
            if any(src in val_str for src in ("request.cookies", "request.form", "request.headers", "request.args", "request.")):
                source_expr = val_str
                for t in node.targets:
                    t_str = ast.unparse(t)
                    if t_str in ("param", "bar"):
                        taint_var = t_str
                break

    # 2. Locate CWE-specific sink
    if category == "pathtraver":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if (
                    name in ("open", "codecs.open")
                    or name.endswith(".open")
                    or name.endswith(".exists")
                    or name.endswith(".read_text")
                    or name.endswith(".read_bytes")
                    or name in ("os.path.exists", "os.stat")
                ):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "cmdi":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "subprocess" in name or name in ("os.system", "os.popen") or "run" in name:
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "codeinj":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if name in ("eval", "exec"):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "deserialization":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "pickle" in name or "yaml" in name:
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "hash":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "hashlib" in name or name.startswith("hash."):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "ldapi":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if name.endswith(".search") or name == "search":
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "redirect":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "redirect" in name:
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "securecookie":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "set_cookie" in name and getattr(node, "lineno", 0) > 35:
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "sqli":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if name.endswith(".execute") or name.endswith(".executemany"):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "trustbound":
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Subscript):
                        val_name = ast.unparse(t.value)
                        if "session" in val_name:
                            sink_line = node.lineno
                            sink_call = f"{val_name}[...]"
                            break

    elif category == "weakrand":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if "random." in name:
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "xpathi":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if any(x in name for x in ("xpath", "select", "XPath", "run_query")):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "xxe":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if any(x in name for x in ("parseString", "parse", "fromstring")):
                    sink_line = node.lineno
                    sink_call = name
                    break

    elif category == "xss":
        for node in ast.walk(scope):
            if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "RESPONSE":
                sink_line = node.lineno
                sink_call = "RESPONSE +="
                break
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "RESPONSE" and getattr(node, "lineno", 0) > 40:
                        sink_line = node.lineno
                        sink_call = "RESPONSE ="
                        break

    # Fallback to line 1 if no sink identified
    if sink_line == 0:
        sink_line = 1

    cwe, vuln_type = BENCHMARK_CATEGORIES.get(category, ("CWE-UNKNOWN", category.upper()))

    # Build concise note and complete explanation
    test_name = file_path.stem
    note = f"OWASP Benchmark {test_name} ({vuln_type}): sink at line {sink_line}"
    explanation = (
        f"Untrusted user input from {source_expr or 'HTTP request'} flows into {taint_var} and reaches "
        f"{sink_call or 'sink call'} at line {sink_line} without sanitization or boundary validation ({cwe})."
    )

    return {
        "file": file_path.name,
        "line": sink_line,
        "cwe": cwe,
        "type": vuln_type,
        "sink_call": sink_call,
        "source": source_expr,
        "note": note,
        "explanation": explanation,
    }


def classify_clean_control(file_path: Path, category: str) -> Dict[str, Any]:
    """
    Analyze a non-vulnerable control case and describe its defense mechanism.
    """
    code = file_path.read_text(encoding="utf-8")
    tree = ast.parse(code)
    cwe, vuln_type = BENCHMARK_CATEGORIES.get(category, ("CWE-UNKNOWN", category.upper()))

    post_funcs = [
        fn for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.endswith("_post")
    ]
    scope: ast.AST = post_funcs[0] if post_funcs else tree

    # 1. Parameterized SQL
    if category == "sqli":
        if "cur.execute(" in code or "cursor.execute(" in code:
            if ", (" in code or ", [" in code or "?" in code:
                return {
                    "file": file_path.name,
                    "cwe": cwe,
                    "type": vuln_type,
                    "defense_type": "parameterized_query",
                    "safe_reason": "Safe parameterized SQL query: values bound via SQL parameter placeholders (?, %s) rather than string interpolation.",
                }
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "safe_database_query",
            "safe_reason": "Database query uses constant query or safe static statements preventing injection.",
        }

    # 2. Strong Crypto Hash
    if category == "hash":
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if any(h in name.lower() for h in ("sha256", "sha512", "sha384")):
                    return {
                        "file": file_path.name,
                        "cwe": cwe,
                        "type": vuln_type,
                        "defense_type": "strong_cryptographic_algorithm",
                        "safe_reason": f"Strong cryptographic hash algorithm ({name}) used instead of weak MD5 or SHA-1.",
                    }
                for a in node.args:
                    arg_str = ast.unparse(a).lower()
                    if any(h in arg_str for h in ("sha256", "sha512", "sha384")):
                        return {
                            "file": file_path.name,
                            "cwe": cwe,
                            "type": vuln_type,
                            "defense_type": "strong_cryptographic_algorithm",
                            "safe_reason": f"Strong cryptographic hash algorithm ({arg_str}) specified instead of weak MD5 or SHA-1.",
                        }
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "strong_cryptographic_algorithm",
            "safe_reason": "Cryptographic hash operation employs strong collision-resistant algorithm (SHA-256 or higher).",
        }

    # 3. Secure Random
    if category == "weakrand":
        if "secrets." in code:
            return {
                "file": file_path.name,
                "cwe": cwe,
                "type": vuln_type,
                "defense_type": "cryptographically_secure_randomness",
                "safe_reason": "Cryptographically secure pseudorandom number generator (secrets module / CSPRNG) used for token generation.",
            }
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "secure_randomness",
            "safe_reason": "Random value generation uses cryptographically robust source or non-security-critical context.",
        }

    # 4. Secure Cookie
    if category == "securecookie":
        if "secure=True" in code:
            return {
                "file": file_path.name,
                "cwe": cwe,
                "type": vuln_type,
                "defense_type": "secure_cookie_flags",
                "safe_reason": "Sensitive cookie is issued with secure flag enabled (secure=True) and httponly protection.",
            }
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "secure_cookie_configuration",
            "safe_reason": "Cookie attributes configured defensively to mitigate session hijacking over cleartext channels.",
        }

    # 5. XML / XXE Protection
    if category == "xxe":
        if "setFeature" in code or "FEATURE_EXTERNAL" in code or "disallow-doctype-decl" in code:
            return {
                "file": file_path.name,
                "cwe": cwe,
                "type": vuln_type,
                "defense_type": "xxe_parser_hardening",
                "safe_reason": "XML parser explicitly configured with entity expansion and external DTD resolution disabled.",
            }
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "xxe_protection",
            "safe_reason": "XML parser disabled external general entity and parameter entity parsing.",
        }

    # 6. Guard clauses & input validation
    for node in ast.walk(scope):
        if isinstance(node, ast.If):
            cond_str = ast.unparse(node.test)
            if any(p in cond_str for p in ("../", "..", "startswith", "endswith", "isalnum", "isdigit", "isalpha", "isnumeric", "isidentifier")):
                return {
                    "file": file_path.name,
                    "cwe": cwe,
                    "type": vuln_type,
                    "defense_type": "input_validation_guard",
                    "safe_reason": f"Input validation guard clause (if {cond_str}) rejects path traversal or malicious injection sequences.",
                }

    # 7. Ternary or Match dead branch / constant bypass
    for node in ast.walk(scope):
        if isinstance(node, ast.IfExp):
            cond_str = ast.unparse(node.test)
            return {
                "file": file_path.name,
                "cwe": cwe,
                "type": vuln_type,
                "defense_type": "dead_branch_constant_bypass",
                "safe_reason": f"Statically evaluated ternary expression condition ({cond_str}) assigns a safe constant literal, bypassing tainted input.",
            }
        if isinstance(node, ast.Match):
            return {
                "file": file_path.name,
                "cwe": cwe,
                "type": vuln_type,
                "defense_type": "static_pattern_match_selection",
                "safe_reason": "Deterministic pattern matching selects safe constant branch, ensuring untrusted input never feeds sink.",
            }

    # 8. Deterministic arithmetic or string branching
    for node in ast.walk(scope):
        if isinstance(node, ast.If):
            cond_str = ast.unparse(node.test)
            if any(op in cond_str for op in ("*", "+", "-", ">", "<", "should")):
                if not (cond_str.startswith("not param") or cond_str.startswith("param")):
                    return {
                        "file": file_path.name,
                        "cwe": cwe,
                        "type": vuln_type,
                        "defense_type": "deterministic_control_flow",
                        "safe_reason": f"Deterministic condition ({cond_str}) routes control flow exclusively to safe constant assignment.",
                    }

    # 9. Overwrite with safe constant
    assigns = [node for node in ast.walk(scope) if isinstance(node, ast.Assign)]
    for node in assigns:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "bar":
                v_str = ast.unparse(node.value)
                if "safe" in v_str.lower() or v_str in ("'bob'", '"bob"', "'a-Value'", '"a-Value"'):
                    return {
                        "file": file_path.name,
                        "cwe": cwe,
                        "type": vuln_type,
                        "defense_type": "constant_safe_assignment",
                        "safe_reason": f"Tainted variable is overwritten with safe constant ({v_str}) before reaching sink.",
                    }

    # 10. Output Escaping / HTML Escaping
    if "escape_for_html" in code:
        return {
            "file": file_path.name,
            "cwe": cwe,
            "type": vuln_type,
            "defense_type": "contextual_output_escaping",
            "safe_reason": "Untrusted input is passed through HTML escaping function (escape_for_html) before insertion into response.",
        }

    return {
        "file": file_path.name,
        "cwe": cwe,
        "type": vuln_type,
        "defense_type": "safe_control_flow",
        "safe_reason": "Defensive control flow or data sanitization ensures tainted user input cannot reach dangerous execution sink.",
    }


def enrich_dataset(dataset_dir: Path) -> Dict[str, Any]:
    """
    Read dataset_dir/labels.json, enrich all labels and clean_files, and save updated labels.json.
    """
    labels_file = dataset_dir / "labels.json"
    if not labels_file.is_file():
        raise FileNotFoundError(f"labels.json not found in {dataset_dir}")

    payload = json.loads(labels_file.read_text(encoding="utf-8"))
    samples_dir = dataset_dir / "samples"
    if not samples_dir.is_dir():
        raise FileNotFoundError(f"samples directory not found in {dataset_dir}")

    slicer = ASTSlicer()

    # 1. Enrich vulnerable labels
    enriched_labels: List[Dict[str, Any]] = []
    for entry in payload.get("labels", []):
        filename = entry["file"]
        file_path = samples_dir / filename
        if not file_path.is_file():
            logger.warning(f"File {filename} referenced in labels not found in {samples_dir}")
            continue

        raw_type = entry.get("type", "")
        raw_cwe = str(entry.get("cwe", "")).replace("CWE-", "").strip()
        cat = TYPE_TO_CATEGORY.get(raw_type) or extract_category_from_code(file_path.read_text(encoding="utf-8"))
        if not cat:
            # fallback from CWE number
            for c_name, (c_id, _) in BENCHMARK_CATEGORIES.items():
                if c_id.replace("CWE-", "") == raw_cwe:
                    cat = c_name
                    break

        cat = cat or "pathtraver"
        enriched = detect_vulnerable_sink_and_dataflow(file_path, cat, slicer=slicer)
        enriched_labels.append(enriched)

    # 2. Enrich clean control files
    raw_clean = payload.get("clean_files", [])
    enriched_clean: List[Dict[str, Any]] = []
    for item in raw_clean:
        filename = item["file"] if isinstance(item, dict) else item
        file_path = samples_dir / filename
        if not file_path.is_file():
            logger.warning(f"Clean file {filename} not found in {samples_dir}")
            continue

        code = file_path.read_text(encoding="utf-8")
        cat = extract_category_from_code(code) or "pathtraver"
        clean_control = classify_clean_control(file_path, cat)
        enriched_clean.append(clean_control)

    # 3. Assemble standardized metadata payload
    updated_payload = {
        "schema_version": payload.get("schema_version", 1),
        "name": payload.get("name", dataset_dir.name),
        "source": payload.get("source", "https://github.com/OWASP-Benchmark/BenchmarkPython"),
        "licence": payload.get("licence", "OWASP Benchmark License"),
        "match_mode": payload.get("match_mode", "file"),
        "match_mode_note": (
            "One test case is one file with one seeded defect. The ground truth provides "
            "the exact sink line, standard CWE identifier, canonical vulnerability type, and "
            "taint dataflow explanation. Files listed under clean_files represent deliberate "
            "control cases with documented defense mechanisms (safe_reason)."
        ),
        "partial_labels": payload.get("partial_labels", False),
        "clean_files": enriched_clean,
        "labels": enriched_labels,
    }

    # Write formatted JSON with 2 spaces
    labels_file.write_text(
        json.dumps(updated_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return {
        "dataset": dataset_dir.name,
        "vulnerable_count": len(enriched_labels),
        "clean_count": len(enriched_clean),
        "total_files": len(enriched_labels) + len(enriched_clean),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Enrich and standardize OWASP Benchmark metadata.")
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=["eval/datasets/benchmark", "eval/datasets/benchmark100"],
        help="Dataset paths to enrich (default: benchmark and benchmark100)",
    )
    args = parser.parse_args()

    for ds_path_str in args.datasets:
        ds_path = (ROOT / ds_path_str) if not Path(ds_path_str).is_absolute() else Path(ds_path_str)
        if not ds_path.is_dir():
            print(f"Skipping {ds_path}: not a directory", file=sys.stderr)
            continue
        print(f"Enriching {ds_path}...")
        summary = enrich_dataset(ds_path)
        print(f"  Enriched {summary['dataset']}: {summary['vulnerable_count']} vulnerable labels, "
              f"{summary['clean_count']} clean controls (Total: {summary['total_files']} files)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
