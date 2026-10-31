"""Verification script for ollama/gemma4 compatibility via AIClient and CodeAnalyzer."""
import asyncio
import json
import os
import sys
from pathlib import Path

# Ensure src is on sys.path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from dotenv import load_dotenv

load_dotenv()

from utils.ai_client import AIClient, AIAnalysisError  # noqa: E402
from analyzer.code_analyzer import CodeAnalyzer  # noqa: E402
from models.vulnerability import VulnerabilityType  # noqa: E402

SAMPLE_1_COMMAND_INJECTION = '''import os

def ping_host(host_ip: str):
    # Dangerous sink: user-supplied input directly executed in shell
    cmd = "ping -c 1 " + host_ip
    return os.system(cmd)
'''

SAMPLE_2_SAFE_CODE = '''import math

def calculate_square_root(val: float) -> float:
    if val < 0:
        raise ValueError("Cannot calculate square root of negative number")
    return math.sqrt(val)
'''

REQUIRED_VULN_FIELDS = [
    "type",
    "severity",
    "location",
    "description",
    "impact",
    "remediation",
    "cwe_id",
    "owasp_category",
    "cvss_score",
    "references",
    "proof_of_concept",
    "secure_code_example",
]


async def run_verification():
    print("=" * 60)
    print("VulnAgent - ollama/gemma4 Compatibility Verification")
    print("=" * 60)
    print(f"[*] OPENAI_BASE_URL: {os.getenv('OPENAI_BASE_URL')}")
    print(f"[*] OPENAI_MODEL:    {os.getenv('OPENAI_MODEL')}")

    client = AIClient()
    print(f"[*] AIClient configured model: {client.openai_default_model}")
    assert client.openai_default_model == "ollama/gemma4", (
        f"Expected model 'ollama/gemma4', got '{client.openai_default_model}'"
    )

    # ---------------------------------------------------------
    # TEST 1: Sample 1 - Command Injection (os.system(cmd))
    # ---------------------------------------------------------
    print("\n" + "-" * 50)
    print("[1/2] Testing Sample 1: Command Injection (os.system(cmd))")
    print("-" * 50)
    prompt_1 = f"""Please analyze this Python code for vulnerabilities:
File: app/network.py
```python
{SAMPLE_1_COMMAND_INJECTION}
```
"""
    res_1 = await client.analyze_security(prompt_1)
    print("[+] AIClient returned without parser crash.")
    assert isinstance(res_1, dict), "Result must be a dict"
    assert "vulnerabilities" in res_1, "Result must contain 'vulnerabilities' key"
    assert isinstance(res_1["vulnerabilities"], list), "'vulnerabilities' must be a list"
    assert len(res_1["vulnerabilities"]) >= 1, "Expected at least 1 vulnerability detected"

    vuln_item = res_1["vulnerabilities"][0]
    print(f"[+] Detected {len(res_1['vulnerabilities'])} vulnerability/vulnerabilities.")
    print(f"    - Type:     {vuln_item.get('type')}")
    print(f"    - Severity: {vuln_item.get('severity')}")
    print(f"    - CWE ID:   {vuln_item.get('cwe_id')}")
    print(f"    - OWASP:    {vuln_item.get('owasp_category')}")
    print(f"    - Line:     {vuln_item.get('location', {}).get('start_line')}")

    # Validate schema fields
    missing_fields = [f for f in REQUIRED_VULN_FIELDS if f not in vuln_item]
    assert not missing_fields, f"Missing required fields in vulnerability: {missing_fields}"
    assert client._validate_response(res_1), "AIClient._validate_response failed on Sample 1"
    print("[+] Schema validation passed: all 12 required fields present.")

    # ---------------------------------------------------------
    # TEST 2: Sample 2 - Safe Code (math.sqrt(4))
    # ---------------------------------------------------------
    print("\n" + "-" * 50)
    print("[2/2] Testing Sample 2: Safe Code (math.sqrt)")
    print("-" * 50)
    prompt_2 = f"""Please analyze this Python code for vulnerabilities:
File: app/calc.py
```python
{SAMPLE_2_SAFE_CODE}
```
"""
    res_2 = await client.analyze_security(prompt_2)
    print("[+] AIClient returned without parser crash.")
    assert isinstance(res_2, dict), "Result must be a dict"
    assert "vulnerabilities" in res_2, "Result must contain 'vulnerabilities' key"
    assert isinstance(res_2["vulnerabilities"], list), "'vulnerabilities' must be a list"
    print(f"[+] Vulnerabilities found on safe code: {len(res_2['vulnerabilities'])}")
    assert len(res_2["vulnerabilities"]) == 0, (
        f"Expected 0 vulnerabilities for safe code, found: {res_2['vulnerabilities']}"
    )
    assert client._validate_response(res_2), "AIClient._validate_response failed on Sample 2"
    print("[+] Zero false positives verified on safe code.")

    # ---------------------------------------------------------
    # TEST 3: End-to-end integration via CodeAnalyzer
    # ---------------------------------------------------------
    print("\n" + "-" * 50)
    print("[3/3] End-to-end CodeAnalyzer verification")
    print("-" * 50)
    analyzer = CodeAnalyzer()
    report_vuln = await analyzer.analyze_code(SAMPLE_1_COMMAND_INJECTION, "network.py")
    assert len(report_vuln.vulnerabilities) >= 1, "CodeAnalyzer should report at least 1 vulnerability"
    top_v = report_vuln.vulnerabilities[0]
    print(f"[+] CodeAnalyzer detected: {top_v.type} ({top_v.cwe_id}) at line {top_v.location.start_line}")
    assert "INJECTION" in str(top_v.type) or top_v.cwe_id == "CWE-78", (
        f"Unexpected vuln type: {top_v.type}, cwe: {top_v.cwe_id}"
    )

    report_safe = await analyzer.analyze_code(SAMPLE_2_SAFE_CODE, "calc.py")
    print(f"[+] CodeAnalyzer safe code findings count: {len(report_safe.vulnerabilities)}")
    assert len(report_safe.vulnerabilities) == 0, "CodeAnalyzer reported false positives on safe code"

    print("\n" + "=" * 60)
    print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_verification())
