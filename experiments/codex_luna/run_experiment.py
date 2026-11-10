"""Experiment runner: run VulnAgent's real pipeline over the Codex transport.

The core pipeline is untouched. This script monkeypatches ``openai.Client``
inside its own process only, so Tier 2 (scan) and Tier 3 (verifier) both talk to
the Codex Responses backend and expose reasoning summaries.

Usage:
    python -m experiments.codex_luna.run_experiment --probe
    python -m experiments.codex_luna.run_experiment --scan <path> [--no-verify]
    python -m experiments.codex_luna.run_experiment --token-status
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from .auth import CodexAuthError, seconds_remaining  # noqa: E402
from .client import ALLOWED_MODEL, CodexClient  # noqa: E402
from .openai_shim import ShimClient  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent / "runs"


def probe(effort: str) -> int:
    client = CodexClient()
    result = client.create(
        model=ALLOWED_MODEL,
        input_items=[{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "What is 17*19?"}],
        }],
        instructions="You are a helpful assistant.",
        reasoning_effort=effort,
    )
    usage = result.usage or {}
    details = usage.get("output_tokens_details") or {}
    print(f"model            : {ALLOWED_MODEL}")
    print(f"reasoning echo   : {json.dumps(result.reasoning_meta, ensure_ascii=False)}")
    print(f"reasoning summary: {result.reasoning_summary or '(EMPTY)'}")
    print(f"answer           : {result.text.strip() or '(EMPTY)'}")
    print(f"encrypted chars  : {len(result.encrypted_reasoning)}")
    print(f"tokens           : in={usage.get('input_tokens')} out={usage.get('output_tokens')} "
          f"reasoning={details.get('reasoning_tokens')} total={usage.get('total_tokens')}")
    return 0


def token_status() -> int:
    remaining = seconds_remaining()
    print(f"auth store : {Path(__file__).resolve().parent.parent.parent / ''}")
    print(f"remaining  : {remaining/3600:.1f} h ({remaining/86400:.2f} days)")
    return 0


async def run_scan(target: str, verify: bool, effort: str) -> int:
    import openai

    from analyzer.scanner import ScanOptions, Scanner

    # Replace the OpenAI SDK constructor for this process only, so both the
    # scan tier and the verifier agent use the Codex transport.
    openai.Client = lambda **kwargs: ShimClient(reasoning_effort=effort)  # type: ignore[assignment]

    options = ScanOptions(
        target=target,
        use_llm=True,
        use_semgrep=True,
        concurrency=1,
        verify=verify,
        verify_turns=4,
        use_cache=False,
        model=f"cx/{ALLOWED_MODEL}",
        verify_model=f"cx/{ALLOWED_MODEL}",
        cwe_scope="core10",
    )

    result = await Scanner(options).scan()
    usage = result.stats.get("telemetry") or {}
    findings = []
    for report in result.reports:
        for vuln in report.vulnerabilities:
            findings.append({
                "file": vuln.location.file_path,
                "line": vuln.location.start_line,
                "type": vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type),
                "cwe": vuln.cwe_id,
                "severity": vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity),
                "source": vuln.source.value if hasattr(vuln.source, "value") else str(vuln.source),
                "verification": (vuln.verification or {}).get("verdict") if isinstance(vuln.verification, dict) else None,
                "thinking_chars": len((vuln.verification or {}).get("thinking") or "") if isinstance(vuln.verification, dict) else 0,
            })

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUT_DIR / f"scan_{Path(target).name}_{ALLOWED_MODEL.replace('/', '_')}.json"
    output.write_text(json.dumps({
        "target": target,
        "model": ALLOWED_MODEL,
        "verify": verify,
        "reasoning_effort": effort,
        "stats": {k: v for k, v in result.stats.items() if k not in ("file_hashes", "snapshot_hashes", "debug_traces")},
        "telemetry": usage,
        "findings": findings,
        "debug_traces": result.stats.get("debug_traces", []),
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"findings      : {len(findings)}")
    for item in findings:
        print(f"  {item['severity']:<9} {item['cwe']:<9} {item['type']:<32} {item['file']}:{item['line']} "
              f"[{item['source']}] verdict={item['verification']} thinking={item['thinking_chars']}c")
    print(f"thinking tok  : {usage.get('thinking_tokens', 0)}")
    print(f"tokens        : in={usage.get('input_tokens', 0)} out={usage.get('output_tokens', 0)}")
    print(f"saved         : {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex/Luna experiment harness (isolated)")
    parser.add_argument("--probe", action="store_true", help="Single reasoning round-trip")
    parser.add_argument("--scan", default=None, help="Run the real pipeline on a path")
    parser.add_argument("--no-verify", action="store_true", help="Skip Tier 3")
    parser.add_argument("--effort", default="high", choices=("low", "medium", "high"))
    parser.add_argument("--token-status", action="store_true")
    args = parser.parse_args()

    try:
        if args.token_status:
            return token_status()
        if args.probe:
            return probe(args.effort)
        if args.scan:
            return asyncio.run(run_scan(args.scan, not args.no_verify, args.effort))
    except CodexAuthError as exc:
        print(f"AUTH ERROR: {exc}", file=sys.stderr)
        return 2
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
