"""Human-readable terminal output."""

import os
import sys
from typing import Dict, List

from analyzer.scanner import ScanResult
from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
)

SEVERITY_ORDER = [
    VulnerabilitySeverity.CRITICAL,
    VulnerabilitySeverity.HIGH,
    VulnerabilitySeverity.MEDIUM,
    VulnerabilitySeverity.LOW,
    VulnerabilitySeverity.INFO,
]

_COLORS = {
    VulnerabilitySeverity.CRITICAL: "\033[1;31m",
    VulnerabilitySeverity.HIGH: "\033[31m",
    VulnerabilitySeverity.MEDIUM: "\033[33m",
    VulnerabilitySeverity.LOW: "\033[36m",
    VulnerabilitySeverity.INFO: "\033[90m",
}
_DIM = "\033[90m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_TAINT_KIND_COLORS = {
    "SOURCE": "\033[33m",          # Yellow
    "PROPAGATION": "\033[36m",     # Cyan
    "PROPAGATOR": "\033[36m",      # Cyan
    "SANITIZER": "\033[32m",        # Green
    "SINK": "\033[31m",             # Red
    "IMPORTED_CALL": "\033[35m",    # Magenta
    "IMPORTED_SINK": "\033[1;31m",  # Bold Red
}

SOURCE_LABEL = {
    FindingSource.CONFIRMED: "confirmed",
    FindingSource.SEMGREP: "rule-only",
    FindingSource.LLM: "llm-only",
}


def _use_color() -> bool:
    """
    Whether ANSI colour should be emitted.

    Returns:
        bool: False when redirected or when NO_COLOR is set
    """

    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or sys.stderr.isatty()


def format_taint_path(taint_path: List[Dict[str, Any]], paint=None) -> List[str]:
    """
    Format visual taint flow steps with line numbers and code snippets for terminal display.

    Args:
        taint_path: List of taint step dictionaries
        paint: Optional styling function (e.g. from render())

    Returns:
        List[str]: Formatted terminal lines
    """
    if not taint_path:
        return []

    if paint is None:
        paint = lambda text, code: f"{code}{text}{_RESET}" if _use_color() else text

    flow_lines: List[str] = []
    flow_lines.append(paint("             Taint Flow:", _BOLD))

    for idx, step in enumerate(taint_path, start=1):
        if not isinstance(step, dict):
            continue
        step_num = step.get("step") or idx
        raw_kind = str(step.get("kind", "step")).upper()
        file_path = step.get("file", "")
        line_num = step.get("line") or 0
        desc = step.get("description") or ""

        loc_str = f" at {file_path}:{line_num}" if line_num and file_path else (f" at {file_path}" if file_path else "")
        kind_color = _TAINT_KIND_COLORS.get(raw_kind, _DIM)

        kind_tag = paint(f"[{step_num}] {raw_kind}", kind_color)
        desc_str = f" - {desc}" if desc else ""
        step_header = f"               {kind_tag}{paint(loc_str + desc_str, _DIM)}"
        flow_lines.append(step_header)

        code_snippet = step.get("code")
        if code_snippet:
            for s_line in str(code_snippet).splitlines():
                if s_line.strip().startswith(">"):
                    flow_lines.append(paint(f"                 {s_line}", _BOLD))
                else:
                    flow_lines.append(paint(f"                 {s_line}", _DIM))

    return flow_lines


def render(result: ScanResult, verbose: bool = False) -> str:
    """
    Render a scan result for the terminal.

    Args:
        result: The scan outcome
        verbose: Include impact and remediation for every finding

    Returns:
        str: The formatted report
    """

    color = _use_color()

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: List[str] = []
    vulns = result.vulnerabilities

    stats = result.stats
    lines.append("")
    lines.append(paint("VulnAgent", _BOLD) + paint(
        f"  {stats.get('files_discovered', 0)} file(s) scanned"
        f"  ·  {stats.get('files_sent_to_llm', 0)} sent to LLM"
        f"  ·  {stats.get('total_seconds', 0)}s",
        _DIM
    ))

    cache_hits = stats.get("cache_hits", 0)
    if cache_hits:
        lines.append(paint(f"  {cache_hits} cached, {stats.get('cache_misses', 0)} fresh", _DIM))

    if stats.get("verified_candidates"):
        lines.append(paint(
            f"  verification agent: {stats['verified_candidates']} candidate(s) -> "
            f"{stats.get('verify_confirmed', 0)} upheld, "
            f"{stats.get('verify_refuted', 0)} refuted, "
            f"{stats.get('verify_uncertain', 0)} uncertain"
            f"  ({stats.get('verify_tool_calls', 0)} tool calls, "
            f"{stats.get('verify_seconds', 0)}s)",
            _DIM
        ))

    if result.degraded:
        lines.append(paint("  WARNING: Scan completed with degraded or failed tiers. Results may be incomplete.", _COLORS[VulnerabilitySeverity.HIGH]))

    if not vulns:
        lines.append("")
        lines.append(paint("  No vulnerabilities found.", _BOLD))
        lines.append("")
        lines.extend(_summary_box(result, paint))
        lines.append("")
        return "\n".join(lines)

    lines.append("")
    by_file: Dict[str, List[Vulnerability]] = {}
    for vuln in vulns:
        by_file.setdefault(vuln.location.file_path, []).append(vuln)

    for file_path in sorted(by_file):
        lines.append(paint(f"  {file_path}", _BOLD))
        findings = sorted(
            by_file[file_path],
            key=lambda v: (SEVERITY_ORDER.index(v.severity), v.location.start_line)
        )
        for vuln in findings:
            span = str(vuln.location.start_line)
            if vuln.location.end_line and vuln.location.end_line != vuln.location.start_line:
                span += f"-{vuln.location.end_line}"

            severity = paint(f"{vuln.severity.value:<8}", _COLORS[vuln.severity])
            label = SOURCE_LABEL.get(vuln.source, vuln.source.value)
            meta = paint(f"[{label} {vuln.confidence:.2f}]", _DIM)

            lines.append(f"    {severity} L{span:<8} {vuln.type.value}  {meta}")

            description = (vuln.description or "").strip().split("\n")[0]
            if description:
                lines.append(paint(f"             {description[:100]}", _DIM))

            if verbose:
                if vuln.impact:
                    lines.append(paint(f"             impact: {vuln.impact[:100]}", _DIM))
                if vuln.remediation:
                    lines.append(paint(f"             fix:    {vuln.remediation[:100]}", _DIM))
                if vuln.taint_path:
                    lines.extend(format_taint_path(vuln.taint_path, paint=paint))
        lines.append("")

    chains = sum(len(r.chained_vulnerabilities) for r in result.reports)
    counts = _severity_counts(vulns)
    summary = "  ".join(
        paint(f"{counts[s]} {s.value.lower()}", _COLORS[s])
        for s in SEVERITY_ORDER if counts[s]
    )
    lines.append(f"  {len(vulns)} finding(s):  {summary}")

    confirmed = sum(1 for v in vulns if v.source == FindingSource.CONFIRMED)
    llm_only = sum(1 for v in vulns if v.source == FindingSource.LLM)
    rule_only = sum(1 for v in vulns if v.source == FindingSource.SEMGREP)
    lines.append(paint(
        f"  {confirmed} confirmed by both tiers  ·  {rule_only} rule-only  ·  {llm_only} llm-only",
        _DIM
    ))

    if chains:
        lines.append(paint(f"  {chains} attack chain(s) identified", _DIM))

    if result.degraded:
        lines.append("")
        lines.append(paint("  WARNING: at least one tier did not complete.", _COLORS[VulnerabilitySeverity.HIGH]))
        for report in result.reports:
            for tier, status in (report.tiers or {}).items():
                if status not in ("ok", "disabled", "not routed"):
                    lines.append(paint(f"    {report.file_name}: {tier} -> {status}", _DIM))

    # Append the comprehensive executive summary box
    lines.append("")
    lines.extend(_summary_box(result, paint))
    lines.append("")
    return "\n".join(lines)


def _summary_box(result: ScanResult, paint) -> List[str]:
    """
    Format a comprehensive terminal summary box with execution metrics and telemetry.
    """
    from collections import Counter
    stats = result.stats or {}
    reports = result.reports or []
    vulns = result.vulnerabilities

    total_sec = stats.get("total_seconds", 0) or 0
    mins_str = f" (~{total_sec/60:.1f} phút)" if total_sec > 60 else ""

    counts = _severity_counts(vulns)
    sev_str = "  ·  ".join(
        paint(f"{counts[s]} {s.value}", _COLORS[s])
        for s in SEVERITY_ORDER if counts[s]
    ) or "0 findings"

    confirmed = sum(1 for v in vulns if v.source == FindingSource.CONFIRMED)
    llm_only = sum(1 for v in vulns if v.source == FindingSource.LLM)
    rule_only = sum(1 for v in vulns if v.source == FindingSource.SEMGREP)

    cwes = Counter(f"{v.cwe_id} ({v.type.value if hasattr(v.type, 'value') else v.type})" for v in vulns if v.cwe_id)
    top_cwes = cwes.most_common(5)

    box: List[str] = [
        paint("=" * 80, _BOLD),
        paint(" " * 18 + "BẢNG TỔNG KẾT QUÉT (SCAN EXECUTION SUMMARY)", _BOLD),
        paint("=" * 80, _BOLD),
        paint("[*] TIẾN TRÌNH & THỜI GIAN (EXECUTION & TIMING):", _BOLD),
        f"  • Tổng thời gian quét    : {total_sec:.2f}s{mins_str}",
    ]

    if stats.get("rule_tier_seconds"):
        box.append(f"    - Tầng 1 (Semgrep SAST): {stats['rule_tier_seconds']:.2f}s")
    if stats.get("llm_tier_seconds"):
        box.append(f"    - Tầng 2 (LLM Scan)    : {stats['llm_tier_seconds']:.2f}s")
    if stats.get("verify_seconds"):
        box.append(f"    - Tầng 3 (Verifier)    : {stats['verify_seconds']:.2f}s")

    files_disc = stats.get("files_discovered", len(reports))
    files_scan = stats.get("files_scanned", len(reports))
    files_llm = stats.get("files_sent_to_llm", 0)
    box.append(f"  • Tệp phát hiện / Quét   : {files_disc} tệp / {files_scan} tệp ({files_llm} tệp gửi sang LLM)")

    if stats.get("cache_hits"):
        box.append(f"  • Bộ nhớ đệm (Cache)     : {stats['cache_hits']} hit, {stats.get('cache_misses', 0)} miss")

    box.extend([
        "",
        paint("[*] THỐNG KÊ LỖ HỔNG (VULNERABILITY METRICS):", _BOLD),
        f"  • Tổng số phát hiện      : {len(vulns)} lỗ hổng",
        f"  • Phân bố theo mức độ    : {sev_str}",
        "  • Phân loại nguồn gốc    :",
        f"    - CONFIRMED (Đồng thuận kép): {confirmed} lỗ hổng (Độ tin cậy 0.98)",
        f"    - LLM-only (Phát hiện ngữ nghĩa): {llm_only} lỗ hổng",
        f"    - SEMGREP (Luật tĩnh): {rule_only} lỗ hổng",
    ])

    chains = sum(len(r.chained_vulnerabilities) for r in reports)
    if chains:
        box.append(f"  • Chuỗi tấn công (Chains): {chains} chuỗi hợp lệ")

    if stats.get("verified_candidates"):
        box.extend([
            "",
            paint("[*] THẨM TRA ĐỐI KHÁNG TẦNG 3 (ADVERSARIAL VERIFIER):", _BOLD),
            f"  • Số ứng viên thẩm tra   : {stats['verified_candidates']} phát hiện",
            f"  • Xác nhận có bằng chứng : {stats.get('verify_confirmed', 0)} phát hiện (Upheld)",
            f"  • Bác bỏ cảnh báo ảo (FP): {stats.get('verify_dropped', 0)} phát hiện (Refuted & Dropped)",
            f"  • Số lệnh gọi đọc code   : {stats.get('verify_tool_calls', 0)} tool calls",
        ])

    telemetry = stats.get("telemetry") or {}
    total_tokens = stats.get("total_tokens") or telemetry.get("total_tokens")
    api_requests = stats.get("api_requests") or telemetry.get("api_requests")
    input_tokens = stats.get("input_tokens") or telemetry.get("input_tokens") or telemetry.get("prompt_tokens") or 0
    output_tokens = stats.get("output_tokens") or telemetry.get("output_tokens") or telemetry.get("completion_tokens") or 0

    if total_tokens or api_requests:
        box.extend([
            "",
            paint("[*] TÀI NGUYÊN & TOKEN (TELEMETRY):", _BOLD),
            f"  • Tổng số API Requests   : {api_requests:,} requests" if api_requests else "",
            f"  • Tổng Tokens tiêu thụ   : {total_tokens:,} tokens (Input: {input_tokens:,} · Output: {output_tokens:,})" if total_tokens else "",
        ])
        box = [b for b in box if b]

    if top_cwes:
        box.extend([
            "",
            paint("[*] TOP CÁC LỖ HỔNG PHỔ BIẾN NHẤT:", _BOLD),
        ])
        for i, (name, count) in enumerate(top_cwes, 1):
            box.append(f"  {i}. {name:<45}: {count} phát hiện")

    box.append(paint("=" * 80, _BOLD))
    return box


def render_summary(result: ScanResult) -> str:
    """
    Render exclusively the summary box without individual file findings.
    """
    color = _use_color()
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text
    return "\n".join(_summary_box(result, paint))


def _severity_counts(vulns: List[Vulnerability]) -> Dict[VulnerabilitySeverity, int]:
    """
    Count findings per severity.

    Args:
        vulns: All findings

    Returns:
        Dict[VulnerabilitySeverity, int]: Counts, zero-filled
    """

    counts = {s: 0 for s in SEVERITY_ORDER}
    for vuln in vulns:
        counts[vuln.severity] += 1
    return counts
