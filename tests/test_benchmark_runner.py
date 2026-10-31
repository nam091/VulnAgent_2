"""Unit tests for eval/run_model_comparison.py."""

import json
from pathlib import Path

import pytest

from eval.run_model_comparison import (
    clean_markdown_and_thinking,
    compile_directory_summaries,
    extract_cwe_from_dict,
    extract_line_number,
    get_model_filename,
    parse_findings_from_text,
    parse_response_payload,
    write_summary_csv,
)


def test_extract_cwe_from_dict():
    assert extract_cwe_from_dict({"cwe_id": "CWE-89"}) == "89"
    assert extract_cwe_from_dict({"cwe": "798"}) == "798"
    assert extract_cwe_from_dict({"vulnerability_type": {"cwe": "CWE-20: Improper Input Validation"}}) == "20"
    assert extract_cwe_from_dict({"vulnerability_type": "CWE-918"}) == "918"
    assert extract_cwe_from_dict({"type": "CWE-78_COMMAND_INJECTION"}) == "78"
    assert extract_cwe_from_dict({"title": "Finding with CWE-208 Timing Attack"}) == "208"
    assert extract_cwe_from_dict({"description": "Generic issue without CWE"}) == ""


def test_extract_line_number():
    assert extract_line_number({"location": {"start_line": 42}}) == 42
    assert extract_line_number({"location": {"line": 100}}) == 100
    assert extract_line_number({"start_line": 15}) == 15
    assert extract_line_number({"line_number": 88}) == 88
    assert extract_line_number({}) == 1


def test_clean_markdown_and_thinking():
    raw_with_think = "<think>Analyzing logic flow</think>\n```json\n[{\"cwe\": \"798\"}]\n```"
    cleaned = clean_markdown_and_thinking(raw_with_think)
    assert "<think>" not in cleaned
    assert "```" not in cleaned
    assert '[{"cwe": "798"}]' in cleaned


def test_parse_findings_from_text_valid_json():
    json_text = json.dumps({
        "vulnerabilities": [
            {
                "cwe_id": "CWE-798",
                "severity": "CRITICAL",
                "location": {"start_line": 12},
                "description": "Hardcoded secret key",
            }
        ]
    })
    is_valid, findings = parse_findings_from_text(json_text)
    assert is_valid is True
    assert len(findings) == 1
    assert findings[0]["cwe_id"] == "CWE-798"


def test_parse_findings_from_text_repair_trailing_commas():
    malformed = '{"vulnerabilities": [{"cwe_id": "CWE-89", "severity": "HIGH",},],}'
    is_valid, findings = parse_findings_from_text(malformed)
    assert len(findings) == 1
    assert findings[0]["cwe_id"] == "CWE-89"


def test_compile_directory_summaries_and_csv(tmp_path: Path):
    dummy_report_1 = {
        "model": "cx/gpt-5.6-luna",
        "summary": {
            "model": "cx/gpt-5.6-luna",
            "role": "competitor",
            "total_files": 13,
            "success_count": 13,
            "blocked_count": 0,
            "timeout_count": 0,
            "http_error_count": 0,
            "avg_latency_sec": 12.5,
            "total_latency_sec": 162.5,
            "total_prompt_tokens": 1000,
            "total_completion_tokens": 200,
            "total_reasoning_tokens": 0,
            "total_tokens": 1200,
            "total_findings": 10,
            "valid_json_rate": 100.0,
            "true_positives": 5,
            "false_positives": 5,
            "false_negatives": 4,
            "fp_on_clean": 1,
            "precision": 0.5,
            "recall": 0.5556,
            "f1_score": 0.5263,
        },
    }
    (tmp_path / "gpt_56_luna.json").write_text(json.dumps(dummy_report_1), encoding="utf-8")

    summaries = compile_directory_summaries(tmp_path)
    assert len(summaries) == 1
    assert summaries[0]["model"] == "cx/gpt-5.6-luna"

    csv_out = tmp_path / "summary.csv"
    write_summary_csv(summaries, csv_out)
    assert csv_out.exists()
    content = csv_out.read_text(encoding="utf-8")
    assert "cx/gpt-5.6-luna" in content
    assert "0.5263" in content


def test_get_model_filename():
    assert get_model_filename("mistral/codestral-latest") == "codestral_latest.json"
    assert get_model_filename("ollama/gpt-oss:120b") == "gpt_oss_120b.json"
    assert get_model_filename("cx/gpt-5.6-luna") == "gpt_56_luna.json"
    assert get_model_filename("ollama/gemma4") == "ollama_gemma4.json"
    assert get_model_filename("custom/my-model:v1.0") == "custom_my_model_v1_0.json"


def test_parse_response_payload():
    # 1. Normal JSON
    normal_json = '{"choices": [{"message": {"content": "ok"}}]}'
    res = parse_response_payload(normal_json)
    assert res["choices"][0]["message"]["content"] == "ok"

    # 2. JSON with trailing SSE [DONE]
    trailing_garbage = '{"choices": [{"message": {"content": "with_done"}}]}data: [DONE]\n\n'
    res = parse_response_payload(trailing_garbage)
    assert res["choices"][0]["message"]["content"] == "with_done"

    # 3. SSE chunks reconstruction
    sse_text = (
        'data: {"choices": [{"delta": {"content": "Hello "}}]}\n\n'
        'data: {"choices": [{"delta": {"content": "world!"}}]}\n\n'
        'data: {"usage": {"total_tokens": 42}}\n\n'
        'data: [DONE]\n\n'
    )
    res = parse_response_payload(sse_text)
    assert res["choices"][0]["message"]["content"] == "Hello world!"
    assert res["usage"]["total_tokens"] == 42

