"""SARIF 2.1.0 output.

SARIF is the interchange format that GitHub code scanning, VS Code, GitLab
and Azure DevOps all consume, so emitting it correctly is what lets one
engine surface in every one of those places without per-platform work.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilityReport,
    VulnerabilitySeverity,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_URI = "https://github.com/nam091/VulnAgent_2"

# SARIF only defines four levels; the five-level model collapses onto them.
LEVEL_MAP = {
    VulnerabilitySeverity.CRITICAL: "error",
    VulnerabilitySeverity.HIGH: "error",
    VulnerabilitySeverity.MEDIUM: "warning",
    VulnerabilitySeverity.LOW: "note",
    VulnerabilitySeverity.INFO: "note",
}

# GitHub code scanning sorts and filters on this property, expressed as a
# CVSS-like number in a string.
SECURITY_SEVERITY = {
    VulnerabilitySeverity.CRITICAL: "9.5",
    VulnerabilitySeverity.HIGH: "7.5",
    VulnerabilitySeverity.MEDIUM: "5.0",
    VulnerabilitySeverity.LOW: "3.0",
    VulnerabilitySeverity.INFO: "1.0",
}


def to_sarif(
    reports: List[VulnerabilityReport],
    tool_version: str = "0.2.0",
    base_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Render one or more reports as a SARIF log.

    Args:
        reports: Reports to include
        tool_version: Version string advertised by the tool driver
        base_path: Root that result URIs should be relative to

    Returns:
        Dict[str, Any]: A SARIF 2.1.0 document
    """

    all_vulns: List[Vulnerability] = []
    for report in reports:
        all_vulns.extend(report.vulnerabilities)

    rules = _build_rules(all_vulns)
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}

    results = [
        _to_result(v, rule_index, base_path)
        for v in all_vulns
    ]

    notifications = _tier_notifications(reports)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "VulnAgent",
                "version": tool_version,
                "informationUri": TOOL_URI,
                "rules": rules,
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
    }

    if notifications:
        run["invocations"] = [{
            "executionSuccessful": all(
                not report.degraded for report in reports
            ),
            "toolExecutionNotifications": notifications,
        }]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _build_rules(vulnerabilities: List[Vulnerability]) -> List[Dict[str, Any]]:
    """
    Derive the rule metadata block from the findings present.

    Args:
        vulnerabilities: All findings in the log

    Returns:
        List[Dict[str, Any]]: One rule descriptor per distinct vulnerability type
    """

    seen: Dict[str, Dict[str, Any]] = {}

    for vuln in vulnerabilities:
        rule_id = vuln.type.value
        if rule_id in seen:
            continue

        tags = ["security", "vulnagent"]
        if vuln.cwe_id:
            tags.append(f"external/cwe/{vuln.cwe_id.lower()}")
        if vuln.owasp_category:
            tags.append(f"external/owasp/{vuln.owasp_category.split(':')[0].strip().lower()}")

        help_text = _help_markdown(vuln)

        seen[rule_id] = {
            "id": rule_id,
            "name": _pascal_case(rule_id),
            "shortDescription": {"text": _humanize(rule_id)},
            "fullDescription": {"text": (vuln.description or _humanize(rule_id))[:1000]},
            "help": {"text": help_text, "markdown": help_text},
            "defaultConfiguration": {"level": LEVEL_MAP[vuln.severity]},
            "properties": {
                "tags": tags,
                "security-severity": SECURITY_SEVERITY[vuln.severity],
                "precision": "high" if vuln.confidence >= 0.9 else "medium",
            },
        }
        if vuln.references:
            seen[rule_id]["helpUri"] = vuln.references[0]

    return list(seen.values())


def _to_result(
    vuln: Vulnerability,
    rule_index: Dict[str, int],
    base_path: Optional[str]
) -> Dict[str, Any]:
    """
    Convert one finding into a SARIF result.

    Args:
        vuln: The finding
        rule_index: Map of rule id to its position in the rules array
        base_path: Root that the URI should be relative to

    Returns:
        Dict[str, Any]: A SARIF result object
    """

    rule_id = vuln.type.value
    message = vuln.description or _humanize(rule_id)
    if vuln.source == FindingSource.LLM:
        message += "\n\n(Reported by the LLM tier only - not corroborated by a rule match.)"
    elif vuln.source == FindingSource.SEMGREP:
        message += "\n\n(Reported by the rule tier only.)"

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index.get(rule_id, 0),
        "level": LEVEL_MAP[vuln.severity],
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _uri(vuln.location.file_path, base_path),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": _region(vuln),
            }
        }],
        # GitHub uses partialFingerprints to track a finding across commits,
        # which is exactly what the content-hash id was built for.
        "partialFingerprints": {"vulnagentFingerprint/v1": vuln.id},
        "properties": {
            "source": vuln.source.value,
            "confidence": vuln.confidence,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "cwe": vuln.cwe_id,
            "owasp": vuln.owasp_category,
            "impact": vuln.impact,
            "remediation": vuln.remediation,
        },
    }

    if vuln.merged_rule_ids:
        result["properties"]["semgrep_rules"] = vuln.merged_rule_ids

    fix = _to_fix(vuln, base_path)
    if fix:
        result["fixes"] = [fix]

    return result


def _region(vuln: Vulnerability) -> Dict[str, Any]:
    """
    Build the SARIF region for a finding, omitting unusable values.

    SARIF requires 1-based line and column numbers, so zeros - which the
    model emits when it cannot determine a column - must be dropped rather
    than passed through.

    Args:
        vuln: The finding

    Returns:
        Dict[str, Any]: A SARIF region object
    """

    start_line = max(1, vuln.location.start_line or 1)
    end_line = max(start_line, vuln.location.end_line or start_line)

    region: Dict[str, Any] = {"startLine": start_line, "endLine": end_line}

    if vuln.location.start_col and vuln.location.start_col > 0:
        region["startColumn"] = vuln.location.start_col
    if vuln.location.end_col and vuln.location.end_col > 0:
        region["endColumn"] = vuln.location.end_col
    if vuln.location.context:
        region["snippet"] = {"text": vuln.location.context}

    return region


def _to_fix(vuln: Vulnerability, base_path: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Express the suggested secure rewrite as a SARIF fix.

    Args:
        vuln: The finding
        base_path: Root that the URI should be relative to

    Returns:
        Optional[Dict[str, Any]]: A SARIF fix, or None when no patch exists
    """

    replacement = (vuln.secure_code_example or "").strip()
    if not replacement:
        return None

    start_line = max(1, vuln.location.start_line or 1)
    end_line = max(start_line, vuln.location.end_line or start_line)

    return {
        "description": {"text": vuln.remediation or "Apply the suggested secure implementation."},
        "artifactChanges": [{
            "artifactLocation": {
                "uri": _uri(vuln.location.file_path, base_path),
                "uriBaseId": "%SRCROOT%",
            },
            "replacements": [{
                "deletedRegion": {"startLine": start_line, "endLine": end_line},
                "insertedContent": {"text": replacement},
            }],
        }],
    }


def _tier_notifications(reports: List[VulnerabilityReport]) -> List[Dict[str, Any]]:
    """
    Surface degraded tiers as SARIF notifications.

    A scan that completed with a dead LLM tier must not be indistinguishable
    from a clean scan in the consuming UI.

    Args:
        reports: Reports to inspect

    Returns:
        List[Dict[str, Any]]: SARIF notification objects
    """

    notifications = []
    for report in reports:
        for tier, status in (report.tiers or {}).items():
            if status == "ok":
                continue
            notifications.append({
                "level": "warning",
                "message": {
                    "text": f"Tier '{tier}' did not complete for "
                            f"{report.file_name or report.repository_url}: {status}"
                },
            })
    return notifications


def _uri(file_path: str, base_path: Optional[str]) -> str:
    """
    Normalise a path into a repository-relative posix URI.

    Args:
        file_path: Path as recorded on the finding
        base_path: Root to make the path relative to

    Returns:
        str: A forward-slash relative path
    """

    path = Path(file_path)
    if base_path:
        try:
            path = path.resolve().relative_to(Path(base_path).resolve())
        except (ValueError, OSError):
            pass
    return path.as_posix().lstrip("./")


def _help_markdown(vuln: Vulnerability) -> str:
    """
    Compose the help block shown when a finding is expanded.

    Args:
        vuln: A representative finding of this rule

    Returns:
        str: Markdown help text
    """

    parts = [f"## {_humanize(vuln.type.value)}"]
    if vuln.impact:
        parts.append(f"**Impact:** {vuln.impact}")
    if vuln.remediation:
        parts.append(f"**Remediation:** {vuln.remediation}")
    if vuln.secure_code_example:
        parts.append(f"**Secure implementation:**\n\n```python\n{vuln.secure_code_example}\n```")
    if vuln.references:
        refs = "\n".join(f"- {r}" for r in vuln.references[:5])
        parts.append(f"**References:**\n{refs}")
    return "\n\n".join(parts)


def _humanize(rule_id: str) -> str:
    """
    Turn an enum-style identifier into a readable title.

    Args:
        rule_id: Identifier such as SQL_INJECTION

    Returns:
        str: A title such as "Sql Injection"
    """

    return rule_id.replace("_", " ").title()


def _pascal_case(rule_id: str) -> str:
    """
    Turn an enum-style identifier into PascalCase.

    Args:
        rule_id: Identifier such as SQL_INJECTION

    Returns:
        str: PascalCase name such as SqlInjection
    """

    cleaned = "".join(c if c.isalnum() or c == "_" else "" for c in rule_id)
    return "".join(part.title() for part in cleaned.split("_") if part)
