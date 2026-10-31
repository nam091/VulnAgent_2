#!/usr/bin/env python3
"""
Multi-Model Benchmark Runner for VulnAgent Security Analysis.

Head-to-head evaluation across LLM backends:
1. cx/gpt-5.6-luna
2. ag/gemini-3.8-flash-low
3. ag/gemini-3.8-flash-medium
4. ag/gemini-3.8-flash-high
(with baseline comparison against ollama/gemma4)

Evaluates on representative test files from Apache Superset 2.0.1 and Saleor 3.10.0,
covering diverse CWE vulnerability classes, safety filter trigger candidates, and clean controls.
Logs per-request latency, token consumption, safety blockages, JSON schema validity,
and computes TP, FP, FN, Precision, Recall, and F1 against ground-truth dataset labels.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from dotenv import load_dotenv

# Ensure repository root and src/ are in sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

load_dotenv()

from analyzer.code_analyzer import CodeAnalyzer
from eval.run_eval import LINE_TOLERANCE, Detection, Label, cwe_matches, match

# Default 9Router Configuration
DEFAULT_BASE_URL = os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:20128/v1")
DEFAULT_API_KEY = os.getenv("OPENAI_API_KEY", "")
DEFAULT_TIMEOUT_SEC = 45.0
DEFAULT_REPORTS_DIR = ROOT / "reports" / "model_comparison"

# Target models to benchmark
DEFAULT_MODELS = [
    {
        "id": "cx/gpt-5.6-luna",
        "output_filename": "gpt_56_luna.json",
        "role": "competitor",
    },
    {
        "id": "ag/gemini-3.8-flash-low",
        "output_filename": "gemini_flash_low.json",
        "role": "competitor",
    },
    {
        "id": "ag/gemini-3.8-flash-medium",
        "output_filename": "gemini_flash_medium.json",
        "role": "competitor",
    },
    {
        "id": "ag/gemini-3.8-flash-high",
        "output_filename": "gemini_flash_high.json",
        "role": "competitor",
    },
    {
        "id": "ollama/gemma4",
        "output_filename": "ollama_gemma4.json",
        "role": "baseline",
    },
    {
        "id": "mistral/codestral-latest",
        "output_filename": "codestral_latest.json",
        "role": "competitor",
    },
    {
        "id": "ollama/gpt-oss:120b",
        "output_filename": "gpt_oss_120b.json",
        "role": "competitor",
    },
]

# Explicit mapping of model IDs to benchmark output JSON filenames
MODEL_SLUG_MAP: Dict[str, str] = {
    "cx/gpt-5.6-luna": "gpt_56_luna.json",
    "ag/gemini-3.8-flash-low": "gemini_flash_low.json",
    "ag/gemini-3.8-flash-medium": "gemini_flash_medium.json",
    "ag/gemini-3.8-flash-high": "gemini_flash_high.json",
    "ollama/gemma4": "ollama_gemma4.json",
    "mistral/codestral-latest": "codestral_latest.json",
    "ollama/gpt-oss:120b": "gpt_oss_120b.json",
}


def get_model_filename(model_id: str) -> str:
    """Return mapped or sanitized output JSON filename for a model ID."""
    if model_id in MODEL_SLUG_MAP:
        return MODEL_SLUG_MAP[model_id]
    safe_name = re.sub(r"[/\\:\-\.]+", "_", model_id).strip("_") + ".json"
    return safe_name

# Representative Benchmark Dataset Samples
# Selected from Apache Superset 2.0.1 and Saleor 3.10.0 benchmarks
REPRESENTATIVE_SAMPLES = [
    # --- Apache Superset 2.0.1 ---
    {
        "dataset": "superset",
        "file": "superset_config.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "798",
        "category": "HARDCODED_CREDENTIALS / Safety Trigger",
    },
    {
        "dataset": "superset",
        "file": "views_core.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "918",
        "category": "SSRF / Complex View",
    },
    {
        "dataset": "superset",
        "file": "database_views.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "209",
        "category": "INFORMATION_DISCLOSURE",
    },
    {
        "dataset": "superset",
        "file": "query_context_factory.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "20",
        "category": "INPUT_VALIDATION / Safety Trigger",
    },
    {
        "dataset": "superset",
        "file": "sql_lab_models.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "89",
        "category": "SQL_INJECTION",
    },
    {
        "dataset": "superset",
        "file": "slack_util.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": False,
        "primary_cwe": "78",
        "category": "COMMAND_INJECTION",
    },
    {
        "dataset": "superset",
        "file": "clean_date_parser.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": True,
        "primary_cwe": "",
        "category": "CLEAN_CONTROL",
    },
    {
        "dataset": "superset",
        "file": "clean_hashing.py",
        "rel_dir": "eval/datasets/superset/samples",
        "is_clean": True,
        "primary_cwe": "",
        "category": "CLEAN_CONTROL",
    },
    # --- Saleor 3.10.0 ---
    {
        "dataset": "saleor310",
        "file": "adyen_plugin.py",
        "rel_dir": "eval/datasets/saleor310/samples",
        "is_clean": False,
        "primary_cwe": "208",
        "category": "TIMING_ATTACK / Sensitive Payment",
    },
    {
        "dataset": "saleor310",
        "file": "refresh_token.py",
        "rel_dir": "eval/datasets/saleor310/samples",
        "is_clean": False,
        "primary_cwe": "352",
        "category": "CSRF_BYPASS / Sensitive Auth",
    },
    {
        "dataset": "saleor310",
        "file": "account_mutations.py",
        "rel_dir": "eval/datasets/saleor310/samples",
        "is_clean": False,
        "primary_cwe": "284",
        "category": "AUTHORIZATION_BYPASS",
    },
    {
        "dataset": "saleor310",
        "file": "clean_core_utils.py",
        "rel_dir": "eval/datasets/saleor310/samples",
        "is_clean": True,
        "primary_cwe": "",
        "category": "CLEAN_CONTROL",
    },
    {
        "dataset": "saleor310",
        "file": "clean_taxes.py",
        "rel_dir": "eval/datasets/saleor310/samples",
        "is_clean": True,
        "primary_cwe": "",
        "category": "CLEAN_CONTROL",
    },
]


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0


@dataclass
class RequestResult:
    model: str
    file: str
    dataset: str
    category: str
    is_clean: bool
    status: str  # SUCCESS | BLOCKED_BY_SAFETY_FILTER | TIMEOUT | HTTP_ERROR
    status_code: Optional[int]
    latency_sec: float
    tokens: TokenUsage
    is_valid_json: bool
    findings_count: int
    extracted_findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_response_snippet: str = ""
    error_message: str = ""
    block_reason: str = ""
    # Metrics against ground truth
    ground_truth_labels: List[Dict[str, Any]] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    fp_on_clean: int = 0
    missed: List[str] = field(default_factory=list)
    spurious: List[str] = field(default_factory=list)


def load_dataset_labels(dataset_name: str) -> Tuple[List[Label], List[str]]:
    """Load labels and clean files list for a dataset."""
    label_path = ROOT / "eval" / "datasets" / dataset_name / "labels.json"
    if not label_path.exists():
        logging.warning(f"Label path not found: {label_path}")
        return [], []
    data = json.loads(label_path.read_text(encoding="utf-8"))
    labels = [
        Label(
            file=item["file"],
            line=item.get("line", 1),
            cwe=str(item.get("cwe", "")),
            type=item.get("type", ""),
            note=item.get("note", ""),
        )
        for item in data.get("labels", [])
    ]
    clean_files_raw = data.get("clean_files", [])
    clean_files = [
        Path(item["file"] if isinstance(item, dict) else item).as_posix()
        for item in clean_files_raw
    ]
    return labels, clean_files


def extract_cwe_from_dict(item: Dict[str, Any]) -> str:
    """Robustly extract CWE number from various LLM JSON schemas."""
    # 1. Direct fields
    for k in ("cwe_id", "cwe", "cwe_number"):
        val = item.get(k)
        if val:
            m = re.search(r"(\d+)", str(val))
            if m:
                return m.group(1)

    # 2. Nested vulnerability_type dict or string
    vt = item.get("vulnerability_type")
    if isinstance(vt, dict):
        for v in vt.values():
            m = re.search(r"CWE-(\d+)", str(v), re.IGNORECASE)
            if m:
                return m.group(1)
    elif isinstance(vt, str):
        m = re.search(r"CWE-(\d+)", vt, re.IGNORECASE)
        if m:
            return m.group(1)

    # 3. Type field
    t = item.get("type")
    if isinstance(t, str):
        m = re.search(r"CWE-(\d+)", t, re.IGNORECASE)
        if m:
            return m.group(1)

    # 4. Search entire item string
    m = re.search(r"CWE[-_ ]?(\d+)", str(item), re.IGNORECASE)
    if m:
        return m.group(1)

    return ""


def extract_line_number(item: Dict[str, Any]) -> int:
    """Extract line number from location or direct properties."""
    loc = item.get("location")
    if isinstance(loc, dict):
        for k in ("start_line", "line", "line_number"):
            if k in loc and loc[k] is not None:
                try:
                    return int(loc[k])
                except (ValueError, TypeError):
                    pass
    for k in ("start_line", "line", "line_number"):
        if k in item and item[k] is not None:
            try:
                return int(item[k])
            except (ValueError, TypeError):
                pass
    return 1


def clean_markdown_and_thinking(raw_text: str) -> str:
    """Strip reasoning/thought tags and markdown code blocks."""
    if not raw_text:
        return ""
    # Strip <think> or <thought>
    cleaned = re.sub(r"<(?:think|thought)>[\s\S]*?</(?:think|thought)>", "", raw_text, flags=re.IGNORECASE).strip()
    # Strip markdown fences
    fence = re.search(r"```(?:json|python)?\s*([\s\S]*?)\s*```", cleaned)
    if fence:
        return fence.group(1).strip()
    if "```" in cleaned:
        return re.sub(r"^[\s\S]*?```(?:json|python)?\s*", "", cleaned).strip()
    return cleaned


def parse_findings_from_text(raw_text: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """Parse vulnerability findings from raw model completion text."""
    if not raw_text or not raw_text.strip():
        return False, []

    cleaned = clean_markdown_and_thinking(raw_text)

    # Candidates list
    candidates = [cleaned]

    # Outermost JSON object / array
    pos_brace = cleaned.find("{")
    pos_bracket = cleaned.find("[")
    if pos_brace != -1 or pos_bracket != -1:
        if pos_brace != -1 and (pos_bracket == -1 or pos_brace < pos_bracket):
            open_c, close_c, start = "{", "}", pos_brace
        else:
            open_c, close_c, start = "[", "]", pos_bracket
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(cleaned)):
            c = cleaned[i]
            if esc:
                esc = False
                continue
            if c == "\\":
                esc = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0:
                    candidates.append(cleaned[start : i + 1])
                    break

    # Add trailing comma & boolean repairs
    for base in list(candidates):
        rep = re.sub(r"\bTrue\b", "true", base)
        rep = re.sub(r"\bFalse\b", "false", rep)
        rep = re.sub(r"\bNone\b", "null", rep)
        rep = re.sub(r",\s*([}\]])", r"\1", rep)
        if rep != base:
            candidates.append(rep)

    parsed_obj = None
    is_valid_json = False

    for cand in candidates:
        try:
            parsed_obj = json.loads(cand, strict=False)
            is_valid_json = True
            break
        except Exception:
            continue

    if parsed_obj is None:
        # Fallback to regex salvage of finding dicts
        finding_chunks = re.findall(r"\{[^{}]*?(?:cwe|vulnerability|severity)[^{}]*?\}", cleaned, re.IGNORECASE)
        salvaged = []
        for ch in finding_chunks:
            try:
                obj = json.loads(ch, strict=False)
                if isinstance(obj, dict):
                    salvaged.append(obj)
            except Exception:
                pass
        if salvaged:
            parsed_obj = salvaged
            is_valid_json = False
        else:
            return False, []

    # Extract finding list
    findings: List[Dict[str, Any]] = []
    if isinstance(parsed_obj, dict):
        for k in ("vulnerabilities", "findings", "issues", "results"):
            if k in parsed_obj and isinstance(parsed_obj[k], list):
                findings = parsed_obj[k]
                break
        if not findings and ("cwe" in parsed_obj or "cwe_id" in parsed_obj or "vulnerability_type" in parsed_obj):
            findings = [parsed_obj]
    elif isinstance(parsed_obj, list):
        findings = [f for f in parsed_obj if isinstance(f, dict)]

    return is_valid_json, findings


def parse_response_payload(raw_text: str) -> Dict[str, Any]:
    """Parse HTTP response payload from OpenAI-compatible endpoints.

    Gracefully handles:
    1. Standard JSON responses.
    2. JSON objects with trailing SSE stream endings (e.g. 'data: [DONE]').
    3. Server-Sent Events (SSE) streaming chunks reconstructed into a completion object.
    """
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return {}

    # 1. Standard JSON parse
    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 2. JSON object with trailing text/garbage (e.g., 'data: [DONE]')
    if raw_text.startswith("{"):
        last_brace = raw_text.rfind("}")
        if last_brace != -1:
            try:
                candidate = raw_text[: last_brace + 1]
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass

    # 3. Server-Sent Events (SSE) stream reconstruction
    if "data:" in raw_text:
        content_parts: List[str] = []
        reasoning_parts: List[str] = []
        finish_reason = ""
        model_id = ""
        usage_dict: Dict[str, Any] = {}

        for line in raw_text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk_str = line[5:].strip()
            if not chunk_str or chunk_str == "[DONE]":
                continue
            try:
                chunk = json.loads(chunk_str)
                if not isinstance(chunk, dict):
                    continue
                if not model_id and "model" in chunk:
                    model_id = chunk["model"]
                if "usage" in chunk and isinstance(chunk["usage"], dict):
                    usage_dict.update(chunk["usage"])
                choices = chunk.get("choices", [])
                if choices and isinstance(choices, list):
                    c0 = choices[0]
                    if isinstance(c0, dict):
                        if c0.get("finish_reason"):
                            finish_reason = c0["finish_reason"]
                        delta = c0.get("delta", {})
                        if isinstance(delta, dict):
                            if delta.get("content"):
                                content_parts.append(delta["content"])
                            if delta.get("reasoning_content"):
                                reasoning_parts.append(delta["reasoning_content"])
            except Exception:
                continue

        if content_parts or reasoning_parts or finish_reason or usage_dict:
            full_content = "".join(content_parts)
            return {
                "id": "reconstructed-sse",
                "object": "chat.completion",
                "model": model_id,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": finish_reason or "stop",
                        "message": {
                            "role": "assistant",
                            "content": full_content,
                        },
                    }
                ],
                "usage": usage_dict,
                "reasoning_content": "".join(reasoning_parts),
            }

    return {"raw_text": raw_text}


class ModelBenchmarkRunner:
    """Executes multi-model benchmark evaluation."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str = DEFAULT_API_KEY,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        output_dir: Path = DEFAULT_REPORTS_DIR,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_sec = timeout_sec
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.analyzer = CodeAnalyzer()

        # Cache dataset labels
        self.dataset_labels: Dict[str, List[Label]] = {}
        self.dataset_clean_files: Dict[str, List[str]] = {}
        for ds in ("superset", "saleor310"):
            lbls, cleans = load_dataset_labels(ds)
            self.dataset_labels[ds] = lbls
            self.dataset_clean_files[ds] = cleans

    async def run_single_request(
        self,
        client: httpx.AsyncClient,
        model_id: str,
        sample: Dict[str, Any],
    ) -> RequestResult:
        """Execute a single security audit request with latency and token telemetry."""
        fn = sample["file"]
        ds = sample["dataset"]
        rel_dir = sample["rel_dir"]
        is_clean = sample["is_clean"]
        category = sample["category"]

        file_path = ROOT / rel_dir / fn
        file_labels = [l for l in self.dataset_labels[ds] if l.file == fn]
        gt_serialized = [asdict(l) for l in file_labels]
        missed_default = [f"{l.file}:{l.line} {l.type or 'CWE-' + l.cwe}" for l in file_labels]

        if not file_path.exists():
            return RequestResult(
                model=model_id,
                file=fn,
                dataset=ds,
                category=category,
                is_clean=is_clean,
                status="HTTP_ERROR",
                status_code=None,
                latency_sec=0.0,
                tokens=TokenUsage(),
                is_valid_json=False,
                findings_count=0,
                ground_truth_labels=gt_serialized,
                fn=len(file_labels),
                missed=missed_default,
                error_message=f"File not found: {file_path}",
            )

        code_content = file_path.read_text(encoding="utf-8")
        # Build prompt using VulnAgent's AST/general prompt manager
        prompt = self.analyzer._generate_security_prompt(code_content, filename=fn)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        body = {
            "model": model_id,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.0,
            "stream": False,
        }

        url = f"{self.base_url}/chat/completions"

        t_start = time.perf_counter()
        try:
            resp = await client.post(url, json=body, headers=headers, timeout=self.timeout_sec)
            latency = time.perf_counter() - t_start
            status_code = resp.status_code

            try:
                res_data = resp.json()
            except Exception:
                res_data = parse_response_payload(resp.text)

            if not res_data or not res_data.get("choices"):
                fallback_parsed = parse_response_payload(resp.text)
                if fallback_parsed.get("choices"):
                    res_data = fallback_parsed

        except httpx.TimeoutException:
            latency = time.perf_counter() - t_start
            return RequestResult(
                model=model_id,
                file=fn,
                dataset=ds,
                category=category,
                is_clean=is_clean,
                status="TIMEOUT",
                status_code=None,
                latency_sec=round(latency, 3),
                tokens=TokenUsage(),
                is_valid_json=False,
                findings_count=0,
                ground_truth_labels=gt_serialized,
                fn=len(file_labels),
                missed=missed_default,
                error_message=f"Request timed out after {self.timeout_sec}s",
            )
        except Exception as e:
            latency = time.perf_counter() - t_start
            return RequestResult(
                model=model_id,
                file=fn,
                dataset=ds,
                category=category,
                is_clean=is_clean,
                status="HTTP_ERROR",
                status_code=None,
                latency_sec=round(latency, 3),
                tokens=TokenUsage(),
                is_valid_json=False,
                findings_count=0,
                ground_truth_labels=gt_serialized,
                fn=len(file_labels),
                missed=missed_default,
                error_message=str(e),
            )

        # Telemetry & Status Extraction
        tokens = TokenUsage()
        usage = res_data.get("usage")
        if not usage and "response" in res_data and "usageMetadata" in res_data["response"]:
            usage = res_data["response"]["usageMetadata"]

        if isinstance(usage, dict):
            tokens.prompt_tokens = usage.get("prompt_tokens") or usage.get("promptTokenCount") or 0
            tokens.completion_tokens = usage.get("completion_tokens") or usage.get("candidatesTokenCount") or 0
            tokens.total_tokens = usage.get("total_tokens") or usage.get("totalTokenCount") or 0
            # Reasoning tokens if provided
            details = usage.get("completion_tokens_details")
            if isinstance(details, dict):
                tokens.reasoning_tokens = details.get("reasoning_tokens", 0)
            else:
                tokens.reasoning_tokens = usage.get("reasoning_tokens", 0)
            if not tokens.total_tokens:
                tokens.total_tokens = tokens.prompt_tokens + tokens.completion_tokens

        # Check for safety filter block
        prompt_feedback = res_data.get("promptFeedback")
        if not prompt_feedback and "response" in res_data and isinstance(res_data["response"], dict):
            prompt_feedback = res_data["response"].get("promptFeedback")

        block_reason = ""
        if isinstance(prompt_feedback, dict):
            block_reason = prompt_feedback.get("blockReason") or ""

        # Check finish_reason
        choices = res_data.get("choices", [])
        finish_reason = ""
        raw_completion = ""
        if choices and isinstance(choices, list) and len(choices) > 0:
            first_choice = choices[0]
            finish_reason = first_choice.get("finish_reason", "")
            msg = first_choice.get("message", {})
            if isinstance(msg, dict):
                raw_completion = msg.get("content", "") or ""

        is_blocked = (
            block_reason != ""
            or finish_reason in ("SAFETY", "content_filter")
            or "blocked by Gemini's filters" in str(res_data)
            or (not choices and "promptFeedback" in str(res_data))
        )

        if is_blocked:
            return RequestResult(
                model=model_id,
                file=fn,
                dataset=ds,
                category=category,
                is_clean=is_clean,
                status="BLOCKED_BY_SAFETY_FILTER",
                status_code=status_code,
                latency_sec=round(latency, 3),
                tokens=tokens,
                is_valid_json=False,
                findings_count=0,
                ground_truth_labels=gt_serialized,
                fn=len(file_labels),
                missed=missed_default,
                raw_response_snippet=str(prompt_feedback or res_data)[:500],
                block_reason=block_reason or "SAFETY_FILTER",
            )

        if status_code != 200 or not choices:
            return RequestResult(
                model=model_id,
                file=fn,
                dataset=ds,
                category=category,
                is_clean=is_clean,
                status="HTTP_ERROR",
                status_code=status_code,
                latency_sec=round(latency, 3),
                tokens=tokens,
                is_valid_json=False,
                findings_count=0,
                ground_truth_labels=gt_serialized,
                fn=len(file_labels),
                missed=missed_default,
                raw_response_snippet=str(res_data)[:500],
                error_message=f"HTTP {status_code}: {res_data.get('error', 'No choices returned')}",
            )

        # Parse findings from completion text
        is_valid_json, parsed_findings = parse_findings_from_text(raw_completion)

        # Convert to standardized detections
        detections: List[Detection] = []
        normalized_findings: List[Dict[str, Any]] = []

        for f in parsed_findings:
            cwe = extract_cwe_from_dict(f)
            line = extract_line_number(f)
            v_type = f.get("type") or f.get("vulnerability_type") or f.get("title") or "UNKNOWN"
            if isinstance(v_type, dict):
                v_type = v_type.get("cwe") or v_type.get("name") or "UNKNOWN"
            det = Detection(
                file=fn,
                line=line,
                cwe=cwe,
                type=str(v_type),
                source="llm",
            )
            detections.append(det)
            normalized_findings.append({
                "cwe": cwe,
                "line": line,
                "type": str(v_type),
                "severity": f.get("severity") or f.get("severity_level") or "MEDIUM",
                "description": (f.get("description") or f.get("impact") or "")[:200],
            })

        # Score against dataset ground-truth
        file_labels = [l for l in self.dataset_labels[ds] if l.file == fn]
        clean_files = self.dataset_clean_files[ds]

        metrics = match(
            detections=detections,
            labels=file_labels,
            name=f"{model_id}:{fn}",
            match_mode="file",
            clean_files=clean_files,
            run_status="completed",
        )

        return RequestResult(
            model=model_id,
            file=fn,
            dataset=ds,
            category=category,
            is_clean=is_clean,
            status="SUCCESS",
            status_code=status_code,
            latency_sec=round(latency, 3),
            tokens=tokens,
            is_valid_json=is_valid_json,
            findings_count=len(detections),
            extracted_findings=normalized_findings,
            raw_response_snippet=raw_completion[:300],
            ground_truth_labels=[asdict(l) for l in file_labels],
            tp=metrics.true_positives,
            fp=metrics.false_positives,
            fn=metrics.false_negatives,
            fp_on_clean=metrics.fp_on_clean,
            missed=metrics.missed,
            spurious=metrics.spurious,
        )

    async def benchmark_model(
        self,
        model_info: Dict[str, str],
        samples: List[Dict[str, Any]],
        concurrency: int = 2,
    ) -> Dict[str, Any]:
        """Execute benchmark for one model across all samples."""
        model_id = model_info["id"]
        role = model_info.get("role", "competitor")
        output_fn = model_info["output_filename"]

        logging.info(f"\n========================================================")
        logging.info(f"BENCHMARKING MODEL: {model_id} (Role: {role})")
        logging.info(f"Target Samples: {len(samples)} files, Concurrency: {concurrency}")
        logging.info(f"========================================================")

        sem = asyncio.Semaphore(concurrency)
        results: List[RequestResult] = []

        async with httpx.AsyncClient() as client:
            async def run_with_sem(sample: Dict[str, Any]) -> RequestResult:
                async with sem:
                    fn = sample["file"]
                    logging.info(f"[{model_id}] -> Testing {fn} ({sample['category']})...")
                    res = await self.run_single_request(client, model_id, sample)
                    logging.info(
                        f"[{model_id}] <- {fn}: Status={res.status}, "
                        f"Latency={res.latency_sec:.2f}s, Findings={res.findings_count}, "
                        f"TP={res.tp}, FP={res.fp}, FN={res.fn}"
                    )
                    return res

            tasks = [run_with_sem(s) for s in samples]
            results = await asyncio.gather(*tasks)

        # Summary calculations
        total_files = len(results)
        success_count = sum(1 for r in results if r.status == "SUCCESS")
        blocked_count = sum(1 for r in results if r.status == "BLOCKED_BY_SAFETY_FILTER")
        timeout_count = sum(1 for r in results if r.status == "TIMEOUT")
        http_error_count = sum(1 for r in results if r.status == "HTTP_ERROR")

        latencies = [r.latency_sec for r in results]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        total_latency = sum(latencies)

        total_prompt_tokens = sum(r.tokens.prompt_tokens for r in results)
        total_completion_tokens = sum(r.tokens.completion_tokens for r in results)
        total_reasoning_tokens = sum(r.tokens.reasoning_tokens for r in results)
        total_tokens = sum(r.tokens.total_tokens for r in results)

        total_findings = sum(r.findings_count for r in results)
        valid_json_count = sum(1 for r in results if r.status == "SUCCESS" and r.is_valid_json)
        valid_json_rate = (valid_json_count / success_count * 100.0) if success_count else 0.0

        total_tp = sum(r.tp for r in results)
        total_fp = sum(r.fp for r in results)
        total_fn = sum(r.fn for r in results)
        total_fp_clean = sum(r.fp_on_clean for r in results)

        denom_prec = total_tp + total_fp
        precision = (total_tp / denom_prec) if denom_prec else 0.0

        denom_rec = total_tp + total_fn
        recall = (total_tp / denom_rec) if denom_rec else 0.0

        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        summary = {
            "model": model_id,
            "role": role,
            "total_files": total_files,
            "success_count": success_count,
            "blocked_count": blocked_count,
            "timeout_count": timeout_count,
            "http_error_count": http_error_count,
            "avg_latency_sec": round(avg_latency, 3),
            "total_latency_sec": round(total_latency, 3),
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_reasoning_tokens": total_reasoning_tokens,
            "total_tokens": total_tokens,
            "total_findings": total_findings,
            "valid_json_rate": round(valid_json_rate, 2),
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "fp_on_clean": total_fp_clean,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

        full_record = {
            "model": model_id,
            "role": role,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "base_url": self.base_url,
            "timeout_sec": self.timeout_sec,
            "summary": summary,
            "file_results": [asdict(r) for r in results],
        }

        # Write raw JSON report
        out_json_path = self.output_dir / output_fn
        out_json_path.write_text(json.dumps(full_record, indent=2), encoding="utf-8")
        logging.info(f"Saved raw JSON report: {out_json_path}")

        return summary


def compile_directory_summaries(output_dir: Path) -> List[Dict[str, Any]]:
    """Scan output directory for model JSON reports and compile full summary list."""
    canonical_order = [
        "cx/gpt-5.6-luna",
        "ag/gemini-3.8-flash-low",
        "ag/gemini-3.8-flash-medium",
        "ag/gemini-3.8-flash-high",
        "ollama/gemma4",
        "mistral/codestral-latest",
        "ollama/gpt-oss:120b",
    ]
    summaries: Dict[str, Dict[str, Any]] = {}
    for json_file in output_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if "summary" in data and isinstance(data["summary"], dict):
                mid = data["summary"].get("model")
                if mid:
                    summaries[mid] = data["summary"]
        except Exception:
            continue

    compiled = []
    for mid in canonical_order:
        if mid in summaries:
            compiled.append(summaries.pop(mid))
    # Any remaining custom models
    for s in summaries.values():
        compiled.append(s)
    return compiled


def write_summary_csv(
    summaries: List[Dict[str, Any]],
    output_path: Path,
) -> None:
    """Export benchmark technical summary CSV."""
    fieldnames = [
        "Model",
        "Role",
        "Total_Files",
        "Success_Count",
        "Blocked_Count",
        "Timeout_Count",
        "Http_Error_Count",
        "Avg_Latency_sec",
        "Total_Latency_sec",
        "Total_Prompt_Tokens",
        "Total_Completion_Tokens",
        "Total_Reasoning_Tokens",
        "Total_Tokens",
        "Total_Findings",
        "Valid_JSON_Rate_pct",
        "TP",
        "FP",
        "FN",
        "FP_On_Clean",
        "Precision",
        "Recall",
        "F1_Score",
    ]

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in summaries:
            writer.writerow({
                "Model": s["model"],
                "Role": s["role"],
                "Total_Files": s["total_files"],
                "Success_Count": s["success_count"],
                "Blocked_Count": s["blocked_count"],
                "Timeout_Count": s["timeout_count"],
                "Http_Error_Count": s["http_error_count"],
                "Avg_Latency_sec": s["avg_latency_sec"],
                "Total_Latency_sec": s["total_latency_sec"],
                "Total_Prompt_Tokens": s["total_prompt_tokens"],
                "Total_Completion_Tokens": s["total_completion_tokens"],
                "Total_Reasoning_Tokens": s["total_reasoning_tokens"],
                "Total_Tokens": s["total_tokens"],
                "Total_Findings": s["total_findings"],
                "Valid_JSON_Rate_pct": s["valid_json_rate"],
                "TP": s["true_positives"],
                "FP": s["false_positives"],
                "FN": s["false_negatives"],
                "FP_On_Clean": s["fp_on_clean"],
                "Precision": f"{s['precision']:.4f}",
                "Recall": f"{s['recall']:.4f}",
                "F1_Score": f"{s['f1_score']:.4f}",
            })
    logging.info(f"Saved summary CSV report: {output_path}")


def print_formatted_summary(summaries: List[Dict[str, Any]]) -> None:
    """Print ASCII comparison table to stdout."""
    header = (
        f"{'Model':<28} | {'Status (S/B/T/E)':<16} | {'Avg Lat':<8} | "
        f"{'Tokens (P/C/R)':<18} | {'Findings':<8} | {'TP':<4} | {'FP':<4} | "
        f"{'FN':<4} | {'Prec':<7} | {'Recall':<7} | {'F1':<7}"
    )
    divider = "-" * len(header)
    print("\n" + divider)
    print("MULTI-MODEL BENCHMARK RUNNER - HEAD-TO-HEAD SUMMARY")
    print(divider)
    print(header)
    print(divider)

    for s in summaries:
        status_str = f"{s['success_count']}/{s['blocked_count']}/{s['timeout_count']}/{s['http_error_count']}"
        tokens_str = f"{s['total_prompt_tokens']}/{s['total_completion_tokens']}/{s['total_reasoning_tokens']}"
        print(
            f"{s['model']:<28} | {status_str:<16} | {s['avg_latency_sec']:<7.2f}s | "
            f"{tokens_str:<18} | {s['total_findings']:<8} | {s['true_positives']:<4} | "
            f"{s['false_positives']:<4} | {s['false_negatives']:<4} | "
            f"{s['precision']:<7.4f} | {s['recall']:<7.4f} | {s['f1_score']:<7.4f}"
        )
    print(divider + "\n")


async def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-Model Benchmark Runner for VulnAgent")
    parser.add_argument(
        "--models",
        nargs="*",
        default=[],
        help="Model IDs to benchmark (space or comma-separated, default: all defined models)",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=DEFAULT_BASE_URL,
        help=f"9Router base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SEC,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="Concurrent requests per model (default: 2)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(DEFAULT_REPORTS_DIR),
        help=f"Output directory for JSON and CSV reports (default: {DEFAULT_REPORTS_DIR})",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Skip API requests and compile summary CSV/table directly from existing JSON reports in output directory",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    models_to_run = list(DEFAULT_MODELS)
    if args.models:
        selected_ids: List[str] = []
        if isinstance(args.models, list):
            for item in args.models:
                selected_ids.extend([m.strip() for m in re.split(r"[\s,]+", item) if m.strip()])
        elif isinstance(args.models, str):
            selected_ids = [m.strip() for m in re.split(r"[\s,]+", args.models) if m.strip()]

        default_map = {m["id"]: m for m in DEFAULT_MODELS}
        models_to_run = []
        for mid in selected_ids:
            if mid in default_map:
                models_to_run.append(default_map[mid])
            else:
                safe_name = get_model_filename(mid)
                models_to_run.append({
                    "id": mid,
                    "output_filename": safe_name,
                    "role": "competitor" if mid in MODEL_SLUG_MAP else "custom",
                })

    runner = ModelBenchmarkRunner(
        base_url=args.base_url,
        api_key=DEFAULT_API_KEY,
        timeout_sec=args.timeout,
        output_dir=Path(args.output_dir),
    )

    if args.summary_only:
        logging.info("Running in --summary-only mode...")
        compiled_summaries = compile_directory_summaries(runner.output_dir)
        summary_csv_path = runner.output_dir / "models_metrics_summary.csv"
        write_summary_csv(compiled_summaries, summary_csv_path)
        print_formatted_summary(compiled_summaries)
        return 0

    logging.info(f"Initialized Benchmark Runner.")
    logging.info(f"Base URL: {runner.base_url}")
    logging.info(f"Timeout: {runner.timeout_sec}s per request")
    logging.info(f"Output Directory: {runner.output_dir}")
    logging.info(f"Target Models: {[m['id'] for m in models_to_run]}")
    logging.info(f"Test Suite Samples: {len(REPRESENTATIVE_SAMPLES)} files")

    all_summaries: List[Dict[str, Any]] = []

    for model_info in models_to_run:
        summary = await runner.benchmark_model(
            model_info=model_info,
            samples=REPRESENTATIVE_SAMPLES,
            concurrency=args.concurrency,
        )
        all_summaries.append(summary)

    # Compile complete summary across all existing model reports in output directory
    compiled_summaries = compile_directory_summaries(runner.output_dir)
    if not compiled_summaries:
        compiled_summaries = all_summaries

    # Write summary CSV
    summary_csv_path = runner.output_dir / "models_metrics_summary.csv"
    write_summary_csv(compiled_summaries, summary_csv_path)

    # Print comparative table
    print_formatted_summary(compiled_summaries)

    logging.info("Multi-Model Benchmark Runner execution completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
