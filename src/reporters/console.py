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
    return sys.stdout.isatty()


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
        lines.append("  No vulnerabilities found.")
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

    lines.append("")
    return "\n".join(lines)


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
