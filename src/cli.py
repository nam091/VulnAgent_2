"""VulnAgent command line interface.

Every other surface - the HTTP API, the MCP server, the GitHub Action - is a
thin wrapper over the same scan pipeline this exposes.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from analyzer.baseline import BASELINE_FILENAME, Baseline, SuppressionIndex, gate
from analyzer.fixer import apply_plan, build_plan
from analyzer.scanner import ScanOptions, Scanner, ScanResult
from analyzer.semgrep_runner import SemgrepRunner
from context.diff_scope import DiffScopeAnalyzer
from integrations.host_adapter import HostAdapter
from models.vulnerability import FindingSource, Vulnerability, VulnerabilitySeverity
from reporters import console, sarif

__version__ = "1.0.0"

SEVERITY_RANK = {
    VulnerabilitySeverity.CRITICAL: 0,
    VulnerabilitySeverity.HIGH: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 3,
    VulnerabilitySeverity.INFO: 4,
}

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    """
    Attach the options shared by `scan` and `fix`.

    Args:
        parser: The subparser to extend
    """

    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--no-llm", action="store_true", help="Rule tier only")
    parser.add_argument("--no-semgrep", action="store_true", help="LLM tier only")
    parser.add_argument("--no-cache", action="store_true", help="Ignore the content-hash cache")
    parser.add_argument(
        "-j", "--concurrency", type=int, default=5,
        help="Concurrent LLM calls (default: 5)"
    )
    parser.add_argument(
        "--min-risk", type=int, default=3,
        help="Minimum risk score for a file to reach the LLM tier (default: 3)"
    )
    parser.add_argument(
        "--max-llm-files", type=int, default=None,
        help="Cap how many files reach the LLM tier, highest risk first"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="Additional path pattern to skip (repeatable)"
    )
    parser.add_argument(
        "--verify-findings", action="store_true", dest="verify_findings",
        help=(
            "Send findings through an adversarial verification agent that reads "
            "the surrounding code and tries to refute them. Drops false positives "
            "and attaches a traced taint path to those it upholds."
        )
    )
    parser.add_argument(
        "--verify-all", action="store_true",
        help="Verify every finding, not just the LLM-only ones"
    )
    parser.add_argument(
        "--verify-turns", type=int, default=6,
        help="Investigation budget per finding, in model turns (default: 6)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the argument parser.

    Returns:
        argparse.ArgumentParser: The configured parser
    """

    parser = argparse.ArgumentParser(
        prog="vulnagent",
        description="Hybrid vulnerability scanner: rule-based static analysis + LLM."
    )
    parser.add_argument("--version", action="version", version=f"VulnAgent {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a file or directory")
    _add_scan_options(scan)
    scan.add_argument(
        "-f", "--format", choices=("text", "json", "sarif"), default="text",
        help="Output format (default: text)"
    )
    scan.add_argument("-o", "--output", help="Write output to a file instead of stdout")
    scan.add_argument(
        "--fail-on", choices=("critical", "high", "medium", "low", "info", "never"),
        default="high",
        help="Exit non-zero when a finding at or above this severity exists (default: high)"
    )
    scan.add_argument(
        "--confirmed-only", action="store_true",
        help="Only let findings corroborated by both tiers fail the build"
    )
    scan.add_argument(
        "--baseline", nargs="?", const=BASELINE_FILENAME, default=None, metavar="FILE",
        help=f"Compare against a baseline file (default: {BASELINE_FILENAME})"
    )
    scan.add_argument(
        "--fail-on-new", action="store_true",
        help="Only findings absent from the baseline can fail the build"
    )
    scan.add_argument(
        "--no-suppressions", action="store_true",
        help="Ignore inline '# vulnagent: ignore' directives"
    )
    scan.add_argument("-v", "--verbose", action="store_true", help="Show impact and remediation")

    fix = subparsers.add_parser("fix", help="Apply suggested secure rewrites")
    _add_scan_options(fix)
    fix.add_argument(
        "--yes", action="store_true",
        help="Apply patches without prompting (safe-classified ones only unless --all)"
    )
    fix.add_argument(
        "--all", action="store_true", dest="include_risky",
        help="With --yes, also apply patches flagged for review"
    )
    fix.add_argument(
        "--dry-run", action="store_true",
        help="Show the patches without writing anything"
    )
    fix.add_argument(
        "--confirmed-only", action="store_true",
        help="Only patch findings corroborated by both tiers"
    )
    fix.add_argument(
        "--verify", action="store_true",
        help="Re-scan after patching and revert if the findings did not improve"
    )

    base = subparsers.add_parser("baseline", help="Record current findings as accepted debt")
    _add_scan_options(base)
    base.add_argument(
        "-o", "--output", default=BASELINE_FILENAME,
        help=f"Baseline file to write (default: {BASELINE_FILENAME})"
    )

    subparsers.add_parser("serve", help="Run the HTTP API and web UI")
    subparsers.add_parser("mcp", help="Run the MCP server on stdio")

    init_cmd = subparsers.add_parser("init", help="Initialize VulnAgent in current workspace")
    init_cmd.add_argument("--host", choices=("cursor", "claude", "auto"), default="auto", help="Target editor host (default: auto)")

    subparsers.add_parser("doctor", help="Check local environment, dependencies and tools")

    check_cmd = subparsers.add_parser("check", help="Run quick check on changes or security gate")
    check_cmd.add_argument("target", nargs="?", default=".", help="Target directory (default: .)")
    check_cmd.add_argument("--changes", action="store_true", help="Scan only git-modified files")
    check_cmd.add_argument("--before-release", action="store_true", help="Comprehensive pre-release scan")
    check_cmd.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    hook_cmd = subparsers.add_parser("hook", help="Run editor hook lifecycle with debounce and lock")
    hook_cmd.add_argument("target", nargs="?", default=None, help="Target directory (default: .)")
    hook_cmd.add_argument("--target", dest="target_opt", default=None, help="Target directory option")
    hook_cmd.add_argument("--files", nargs="*", default=None, help="Specific files changed")
    hook_cmd.add_argument("--max-rounds", type=int, default=2, help="Max hook rounds (default: 2)")
    hook_cmd.add_argument("--debounce", type=float, default=3.0, help="Debounce in seconds (default: 3.0)")
    hook_cmd.add_argument("--trailing", action="store_true", help="Wait out debounce window to guarantee final edit is analyzed")

    return parser


def _threshold(name: str) -> Optional[int]:
    """
    Convert a --fail-on value into a severity rank.

    Args:
        name: The option value

    Returns:
        Optional[int]: The rank, or None when the gate is disabled
    """

    if name == "never":
        return None
    return SEVERITY_RANK[VulnerabilitySeverity(name.upper())]


def _options_from(args: argparse.Namespace) -> ScanOptions:
    """
    Build ScanOptions from parsed arguments.

    Args:
        args: Parsed arguments

    Returns:
        ScanOptions: The scan configuration
    """

    return ScanOptions(
        target=str(Path(args.target)),
        use_llm=not getattr(args, "no_llm", False),
        use_semgrep=not getattr(args, "no_semgrep", False),
        concurrency=getattr(args, "concurrency", 5),
        min_risk=getattr(args, "min_risk", 0),
        max_llm_files=getattr(args, "max_llm_files", None),
        excludes=getattr(args, "exclude", None),
        use_cache=not getattr(args, "no_cache", False),
        verify=getattr(args, "verify_findings", False),
        verify_all=getattr(args, "verify_all", False),
        verify_turns=getattr(args, "verify_turns", 6),
    )


def _validate_target(args: argparse.Namespace) -> Optional[str]:
    """
    Check the target and tier flags before running.

    Args:
        args: Parsed arguments

    Returns:
        Optional[str]: An error message, or None when valid
    """

    if not Path(args.target).exists():
        return f"no such file or directory: {args.target}"
    if args.no_llm and args.no_semgrep:
        return "--no-llm and --no-semgrep cannot both be given"
    return None


def _apply_suppressions(result: ScanResult) -> int:
    """
    Drop findings waived by inline directives in the source.

    Args:
        result: The scan result, mutated in place

    Returns:
        int: How many findings were suppressed
    """

    index = SuppressionIndex()
    total = 0

    for report in result.reports:
        file_path = result.root / (report.file_name or "")
        try:
            index.load_file(report.file_name, file_path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue

        kept, dropped = index.apply(report.vulnerabilities)
        if dropped:
            report.vulnerabilities = kept
            report.calculate_summary()
            report.calculate_risk_score()
            total += dropped

    if total:
        logging.info(f"{total} finding(s) suppressed by inline directives")
    return total


async def _run_scan(args: argparse.Namespace) -> int:
    """
    Execute the scan subcommand.

    Args:
        args: Parsed arguments

    Returns:
        int: Process exit code
    """

    error = _validate_target(args)
    if error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = await Scanner(_options_from(args)).scan()
    except Exception as e:
        logging.exception("Scan failed")
        print(f"error: scan failed: {e}", file=sys.stderr)
        return EXIT_ERROR

    suppressed = 0 if args.no_suppressions else _apply_suppressions(result)

    gating_pool: Sequence[Vulnerability] = result.vulnerabilities
    baseline_note = ""
    if args.baseline:
        baseline = Baseline.load(args.baseline)
        new_findings, known = baseline.partition(result.vulnerabilities)
        resolved = baseline.resolved(result.vulnerabilities)
        baseline_note = (
            f"{len(new_findings)} new, {len(known)} known, {len(resolved)} resolved "
            f"(baseline: {args.baseline})"
        )
        if args.fail_on_new:
            gating_pool = new_findings

    payload = _render(args, result)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(payload, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
        if args.format != "text":
            print(console.render(result, verbose=args.verbose), file=sys.stderr)
    else:
        print(payload)

    stream = sys.stderr if args.output else sys.stdout
    if suppressed:
        print(f"  {suppressed} finding(s) suppressed by inline directives", file=stream)
    if baseline_note:
        print(f"  {baseline_note}", file=stream)

    breaching = gate(
        gating_pool,
        _threshold(args.fail_on),
        SEVERITY_RANK,
        confirmed_only=args.confirmed_only
    )
    if breaching:
        print(
            f"  gate: {len(breaching)} finding(s) at or above "
            f"{args.fail_on.upper()}{' (confirmed only)' if args.confirmed_only else ''}",
            file=stream
        )
        return EXIT_FINDINGS

    if result.degraded:
        print("  gate: failed because one or more analysis tiers degraded/failed", file=stream)
        return EXIT_ERROR

    return EXIT_CLEAN


def _render(args: argparse.Namespace, result: ScanResult) -> str:
    """
    Produce output in the requested format.

    Args:
        args: Parsed arguments
        result: The scan outcome

    Returns:
        str: The rendered payload
    """

    if args.format == "text":
        return console.render(result, verbose=args.verbose)
    if args.format == "json":
        return json.dumps(
            {
                "status": result.status,
                "degraded": result.degraded,
                "coverage": result.coverage,
                "stats": result.stats,
                "reports": [r.model_dump(mode="json") for r in result.reports],
            },
            indent=2, ensure_ascii=False, default=str
        )
    return json.dumps(
        sarif.to_sarif(result.reports, tool_version=__version__, base_path=str(result.root)),
        indent=2, ensure_ascii=False, default=str
    )


async def _run_fix(args: argparse.Namespace) -> int:
    """
    Execute the fix subcommand.

    Args:
        args: Parsed arguments

    Returns:
        int: Process exit code
    """

    error = _validate_target(args)
    if error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.no_llm:
        print(
            "error: fix needs the LLM tier - the rule engine does not produce rewrites",
            file=sys.stderr
        )
        return EXIT_ERROR

    try:
        result = await Scanner(_options_from(args)).scan()
    except Exception as e:
        logging.exception("Scan failed")
        print(f"error: scan failed: {e}", file=sys.stderr)
        return EXIT_ERROR

    _apply_suppressions(result)
    baseline_hashes = getattr(result, "file_hashes", None) or result.stats.get("file_hashes") or result.stats.get("snapshot_hashes")
    plan = build_plan(
        result.vulnerabilities,
        result.root,
        confirmed_only=args.confirmed_only,
        baseline_hashes=baseline_hashes,
        require_baseline=True,
    )

    if plan.conflicts or plan.stale:
        print("\nerror: file(s) modified since analysis or baseline stale/conflict; please re-scan before patching.", file=sys.stderr)
        for vuln, why in plan.rejected:
            if any(k in why.lower() for k in ("stale", "baseline", "modified", "conflict")):
                print(f"  conflict at {vuln.location.file_path}:L{vuln.location.start_line}: {why}", file=sys.stderr)
        return EXIT_ERROR

    if not plan.patches:
        print("\nNo applicable patches.")
        for vuln, why in plan.rejected[:10]:
            print(f"  skipped {vuln.type.value} at L{vuln.location.start_line}: {why}")
        return EXIT_CLEAN

    safe = [p for p in plan.patches if p.risk == "safe"]
    print(f"\n{len(plan.patches)} patch(es) proposed "
          f"({len(safe)} safe, {len(plan.patches) - len(safe)} need review), "
          f"{len(plan.rejected)} rejected.\n")

    selected = []
    for patch in plan.patches:
        vuln = patch.vulnerability
        marker = "safe" if patch.risk == "safe" else "REVIEW"
        print(f"  [{marker}] {vuln.severity.value}  "
              f"{vuln.location.file_path}:{patch.start_line}  {vuln.type.value}"
              f"  [{vuln.source.value.lower()}]")
        if patch.reason:
            print(f"    {patch.reason[:110]}")
        for why in patch.risk_reasons:
            print(f"    ! {why}")
        print()
        print("\n".join(f"    {line}" for line in patch.diff.rstrip().split("\n")))
        print()

        if args.dry_run:
            selected.append(patch)
            continue

        if args.yes:
            # Unattended runs apply only clean substitutions. A patch that
            # rewrites control flow or invents a path needs a human, and
            # applying it silently is how an auto-fixer earns distrust.
            if patch.risk == "safe" or args.include_risky:
                selected.append(patch)
            else:
                print("    skipped (needs review; pass --all to include)\n")
            continue

        try:
            answer = input("    apply this patch? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\naborted")
            return EXIT_ERROR
        if answer in ("y", "yes"):
            selected.append(patch)
        print()

    if not selected:
        print("Nothing applied.")
        return EXIT_CLEAN

    plan.patches = selected
    stats = apply_plan(plan, dry_run=args.dry_run, expected_snapshot_hashes=plan.snapshot_hashes)
    if stats.get("patches_applied", 0) == 0 and selected and not args.dry_run:
        print("error: files modified on disk since plan creation or missing baseline guard; patches skipped to avoid corruption.", file=sys.stderr)
        return EXIT_ERROR

    verb = "would change" if args.dry_run else "changed"
    print(f"\n{stats['patches_applied']} patch(es) applied, "
          f"{stats['files_changed']} file(s) {verb}.")

    if args.dry_run:
        return EXIT_CLEAN

    if args.verify:
        return await _verify_fix(args, result, stats["backups"], expected_current_hashes=stats.get("written_hashes"))

    print("Re-run `vulnagent scan` to confirm the findings are resolved.")
    return EXIT_CLEAN


async def _verify_fix(
    args: argparse.Namespace,
    before: ScanResult,
    backups: dict,
    expected_current_hashes: Optional[dict] = None,
) -> int:
    """
    Re-scan after patching and undo the changes if they did not help.

    Args:
        args: Parsed arguments
        before: The scan taken before patching
        backups: Original file contents, for reverting
        expected_current_hashes: Hashes written by fixer to protect concurrent edits

    Returns:
        int: Process exit code
    """

    from analyzer.fixer import revert

    print("\nVerifying by re-scanning...")
    options = _options_from(args)
    options.use_cache = False  # the files just changed

    try:
        after = await Scanner(options).scan()
    except Exception as e:
        print(f"  verification scan failed: {e}", file=sys.stderr)
        print("  reverting to be safe.")
        revert(backups, expected_current_hashes=expected_current_hashes)
        return EXIT_ERROR

    if after.degraded or after.status != "completed":
        print(f"  verification scan was degraded or incomplete (status={after.status}). Reverting to be safe.")
        revert(backups, expected_current_hashes=expected_current_hashes)
        return EXIT_ERROR

    was = len(before.vulnerabilities)
    now = len(after.vulnerabilities)

    before_fps = {v.id or v.fingerprint() for v in before.vulnerabilities}
    new_findings = [v for v in after.vulnerabilities if (v.id or v.fingerprint()) not in before_fps]
    if new_findings:
        print(f"  patch introduced {len(new_findings)} new finding(s). Reverting.")
        restored = revert(backups, expected_current_hashes=expected_current_hashes)
        print(f"  restored {restored} file(s).")
        return EXIT_ERROR

    if now > was:
        print(f"  findings went from {was} to {now}. Reverting.")
        restored = revert(backups, expected_current_hashes=expected_current_hashes)
        print(f"  restored {restored} file(s).")
        return EXIT_ERROR

    print(f"  findings: {was} -> {now}")
    if now == was:
        print("  no improvement; changes kept but worth reviewing manually.")
    return EXIT_CLEAN


async def _run_baseline(args: argparse.Namespace) -> int:
    """
    Execute the baseline subcommand.

    Args:
        args: Parsed arguments

    Returns:
        int: Process exit code
    """

    error = _validate_target(args)
    if error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    try:
        result = await Scanner(_options_from(args)).scan()
    except Exception as e:
        logging.exception("Scan failed")
        print(f"error: scan failed: {e}", file=sys.stderr)
        return EXIT_ERROR

    _apply_suppressions(result)

    baseline = Baseline.load(args.output)
    baseline.save(args.output, result.vulnerabilities)

    print(f"\nRecorded {len(result.vulnerabilities)} finding(s) in {args.output}")
    print("Future scans with --baseline --fail-on-new will only fail on new findings.")
    return EXIT_CLEAN


async def _run_init(args: argparse.Namespace) -> int:
    """
    Initialize VulnAgent configuration for host editor.
    """
    adapter = HostAdapter(Path.cwd())
    host = args.host if args.host != "auto" else adapter.detect_host()
    if host == "cursor":
        res = adapter.configure_cursor()
        res_hook = adapter.configure_editor_save_hook(host="cursor")
        print(f"VulnAgent initialized for Cursor.")
        print(f"  MCP configuration: {res['mcp_config']}")
        print(f"  Security rules:    {res['rules_file']}")
        print(f"  On-save hook:      {res_hook['tasks_config']}")
    elif host == "claude":
        res = adapter.configure_claude_code()
        print(f"VulnAgent initialized for Claude Code.")
        print(f"  MCP configuration: {res['mcp_config']}")
        print(f"  Instructions:      {res['instructions']}")
    else:
        print(f"error: Unknown host '{host}'", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


async def _run_doctor(args: argparse.Namespace) -> int:
    """
    Inspect local environment, tools and MCP configurations.
    """
    import shutil
    import subprocess

    print("VulnAgent Environment Doctor:")
    all_ok = True

    # 1. Python runtime
    py_ver = sys.version.split()[0]
    print(f"  [OK] Python {py_ver} ({sys.executable})")

    # 2. Semgrep tool
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        print(f"  [OK] Semgrep executable detected: {semgrep_path}")
    else:
        print("  [ERROR] Semgrep not found on PATH. Fast rule scans will fail unless installed.")
        print("    Remediation: run 'pip install semgrep' or ensure semgrep is on system PATH.")
        all_ok = False

    # 3. Git
    git_path = shutil.which("git")
    if git_path:
        print(f"  [OK] Git available ({git_path})")
    else:
        print("  [WARN] Git not found. Change detection and diff analysis will be limited.")

    # 4. Host MCP configurations
    cursor_mcp = Path.cwd() / ".cursor" / "mcp.json"
    cursor_tasks = Path.cwd() / ".cursor" / "tasks.json"
    claude_mcp = Path.cwd() / ".claude" / "mcp.json"
    if cursor_mcp.exists():
        print(f"  [OK] Cursor MCP config detected: {cursor_mcp}")
        if cursor_tasks.exists():
            print(f"  [OK] Cursor on-save hook detected: {cursor_tasks}")
        else:
            print("  [INFO] Cursor on-save hook not yet configured. Run 'vulnagent init' to configure.")
    elif claude_mcp.exists():
        print(f"  [OK] Claude Code MCP config detected: {claude_mcp}")
    else:
        print("  [INFO] No editor MCP config found in current directory. Run 'vulnagent init' to configure.")

    # 5. Core analysis components
    try:
        from evidence.store import EvidenceStore
        from context.ast_context import ASTContextExtractor
        print("  [OK] EvidenceStore & AST analyzer loaded successfully")
    except Exception as e:
        print(f"  [ERROR] Core components failed to load: {e}")
        all_ok = False

    # 6. MCP handshake smoke test
    try:
        from mcp_server import capabilities as mcp_capabilities
        caps = await mcp_capabilities()
        if "tools" in caps and "schema_version" in caps:
            print(f"  [OK] MCP handshake smoke test passed (mode: {caps.get('mode', 'editor')}, tools: {len(caps['tools'])})")
        else:
            print("  [ERROR] MCP capabilities handshake returned unexpected schema.")
            all_ok = False
    except Exception as e:
        print(f"  [ERROR] MCP in-process handshake failed: {e}")
        all_ok = False

    return EXIT_CLEAN if all_ok else EXIT_ERROR


async def _run_check(args: argparse.Namespace) -> int:
    """
    Run fast security gate check on git changes or before release.
    """
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"error: no such file or directory: {args.target}", file=sys.stderr)
        return EXIT_ERROR

    if args.changes:
        diff_analyzer = DiffScopeAnalyzer(target_path)
        changed_files = diff_analyzer.get_changed_files()
        if not changed_files:
            print("No modified files detected via git.")
            return EXIT_CLEAN

        expanded_files = diff_analyzer.expand_scope(changed_files)
        print(f"Scanning {len(expanded_files)} file(s) in scope (changed: {len(changed_files)})...")
        opts = ScanOptions(
            target=str(target_path),
            files=expanded_files,
            use_llm=bool(args.before_release),
            use_semgrep=True,
            verify=bool(args.before_release),
        )
        result = await Scanner(opts).scan()
    else:
        opts = ScanOptions(
            target=str(target_path),
            use_llm=bool(args.before_release),
            use_semgrep=True,
            verify=bool(args.before_release),
        )
        result = await Scanner(opts).scan()

    _apply_suppressions(result)

    if args.before_release:
        print("\n--- Pre-Release Security Check Summary ---")
        print(f"Files scanned: {len(result.reports)}")
        print(f"Status: {result.status}")
        print(f"Findings: {len(result.vulnerabilities)}")
        if result.refuted_vulnerabilities:
            print(f"Refuted findings (retained): {len(result.refuted_vulnerabilities)}")

        if result.status != "completed" or result.degraded:
            print("[ERROR] Scan completed with degraded coverage or failed engine.", file=sys.stderr)
            return EXIT_ERROR

        if result.vulnerabilities:
            for v in result.vulnerabilities:
                v_type = v.type.value if hasattr(v.type, "value") else str(v.type)
                file_loc = f"{v.location.file_path}:{v.location.start_line}" if v.location else "unknown"
                print(f"  - [{v.severity.value}] {v_type} at {file_loc}")
            print("\nPre-release check completed: Findings must be reviewed/resolved prior to release.")
            return EXIT_FINDINGS

        print("Pre-release check completed: No unresolved findings in scanned scope.")
        return EXIT_CLEAN
    else:
        if result.status != "completed" or result.degraded:
            print(f"[ERROR] Scan completed with degraded coverage or failed engine (status: {result.status}).", file=sys.stderr)
            return EXIT_ERROR
        if result.vulnerabilities:
            for v in result.vulnerabilities:
                v_type = v.type.value if hasattr(v.type, "value") else str(v.type)
                file_loc = f"{v.location.file_path}:{v.location.start_line}" if v.location else "unknown"
                print(f"[{v.severity.value}] {v_type} in {file_loc}")
            return EXIT_FINDINGS
        print("Check completed: No findings detected.")
        return EXIT_CLEAN


async def _run_hook(args: argparse.Namespace) -> int:
    from integrations.host_adapter import EditorHookRunner

    target_dir = getattr(args, "target_opt", None) or getattr(args, "target", None) or "."
    root = Path(target_dir).resolve()
    runner = EditorHookRunner(
        root=root,
        debounce_seconds=getattr(args, "debounce", 3.0),
        max_rounds=getattr(args, "max_rounds", 2),
    )
    files = [Path(f).resolve() for f in args.files] if getattr(args, "files", None) else None

    async def _scan():
        options = ScanOptions(
            target=str(root),
            use_llm=False,
            use_semgrep=True,
            files=files,
        )
        return await Scanner(options).scan()

    result = await runner.run(
        scan_fn=_scan,
        files=files,
        trailing=getattr(args, "trailing", False)
    )
    status = result.get("status")
    print(f"Hook status: {status}")
    if status in ("clean", "skipped"):
        return EXIT_CLEAN
    elif status == "findings_detected":
        return EXIT_FINDINGS
    elif status in ("failed", "rescan_failed"):
        print(f"[ERROR] Hook failed: {result.get('reason')}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point.

    Args:
        argv: Argument vector, defaults to sys.argv

    Returns:
        int: Process exit code
    """

    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "debug", False) else logging.WARNING,
        format="%(levelname)s %(message)s"
    )

    if args.command == "serve":
        import uvicorn
        uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
        return EXIT_CLEAN

    if args.command == "mcp":
        from mcp_server import main as mcp_main
        mcp_main()
        return EXIT_CLEAN

    runners = {
        "scan": _run_scan,
        "fix": _run_fix,
        "baseline": _run_baseline,
        "init": _run_init,
        "doctor": _run_doctor,
        "check": _run_check,
        "hook": _run_hook,
    }
    return asyncio.run(runners[args.command](args))


if __name__ == "__main__":
    sys.exit(main())
