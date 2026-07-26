"""Tier 1 scanner: rule-based static analysis via Semgrep.

Runs fast (<1s for a single file), never hallucinates, and reports exact
line numbers. Its findings are used both as results in their own right and
as positional anchors for the LLM tier during fusion.
"""

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.vulnerability import (
    CodeLocation,
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)

# Default rule packs. p/python covers language pitfalls, p/security-audit
# adds broader security rules that catch what p/python alone misses.
DEFAULT_CONFIGS = ("p/python", "p/security-audit")

# Semgrep's CWE metadata is authoritative when present and recognised.
CWE_TO_TYPE: Dict[str, VulnerabilityType] = {
    "22": VulnerabilityType.PATH_TRAVERSAL,
    "78": VulnerabilityType.OS_COMMAND_INJECTION,
    "79": VulnerabilityType.CROSS_SITE_SCRIPTING,
    "89": VulnerabilityType.SQL_INJECTION,
    "94": VulnerabilityType.CODE_INJECTION,
    "95": VulnerabilityType.CODE_INJECTION,
    "113": VulnerabilityType.HTTP_METHOD_INJECTION,
    "190": VulnerabilityType.INTEGER_OVERFLOW,
    "209": VulnerabilityType.INFORMATION_EXPOSURE_THROUGH_ERROR_MESSAGES,
    "295": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "319": VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
    "327": VulnerabilityType.WEAK_CRYPTOGRAPHY,
    "328": VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
    "330": VulnerabilityType.SECURE_RANDOMNESS,
    "338": VulnerabilityType.SECURE_RANDOMNESS,
    "352": VulnerabilityType.CSRF,
    "377": VulnerabilityType.INSECURE_DATA_STORAGE,
    "400": VulnerabilityType.DENIAL_OF_SERVICE,
    "502": VulnerabilityType.INSECURE_DESERIALIZATION,
    "521": VulnerabilityType.BROKEN_AUTHENTICATION,
    "601": VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
    "611": VulnerabilityType.XML_EXTERNAL_ENTITY,
    "614": VulnerabilityType.SECURE_COOKIE,
    "732": VulnerabilityType.SECURITY_MISCONFIGURATION,
    "798": VulnerabilityType.HARDCODED_CREDENTIALS,
    "915": VulnerabilityType.UNSAFE_PROPERTY_ACCESS,
    "918": VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
    "1333": VulnerabilityType.REGULAR_EXPRESSION_DENIAL_OF_SERVICE,
}

# Fallback for rules whose CWE metadata is missing or wrong. Observed in the
# wild: `tainted-sql-string` declares CWE-704 (Incorrect Type Conversion)
# while actually detecting SQL injection, so rule-id keywords are checked
# whenever the CWE lookup does not resolve.
RULE_KEYWORD_TO_TYPE: Tuple[Tuple[str, VulnerabilityType], ...] = (
    ("sql", VulnerabilityType.SQL_INJECTION),
    ("subprocess", VulnerabilityType.OS_COMMAND_INJECTION),
    ("shell", VulnerabilityType.OS_COMMAND_INJECTION),
    ("command", VulnerabilityType.OS_COMMAND_INJECTION),
    ("exec", VulnerabilityType.CODE_INJECTION),
    ("eval", VulnerabilityType.CODE_INJECTION),
    ("pickle", VulnerabilityType.INSECURE_DESERIALIZATION),
    ("yaml", VulnerabilityType.INSECURE_DESERIALIZATION),
    ("deserial", VulnerabilityType.INSECURE_DESERIALIZATION),
    ("traversal", VulnerabilityType.PATH_TRAVERSAL),
    ("path", VulnerabilityType.PATH_TRAVERSAL),
    ("xss", VulnerabilityType.CROSS_SITE_SCRIPTING),
    ("html", VulnerabilityType.CROSS_SITE_SCRIPTING),
    ("template", VulnerabilityType.CROSS_SITE_SCRIPTING),
    ("csrf", VulnerabilityType.CSRF),
    ("password", VulnerabilityType.HARDCODED_CREDENTIALS),
    ("secret", VulnerabilityType.EXPOSED_SECRET),
    ("token", VulnerabilityType.EXPOSED_SECRET),
    ("crypt", VulnerabilityType.WEAK_CRYPTOGRAPHY),
    ("hash", VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM),
    ("random", VulnerabilityType.SECURE_RANDOMNESS),
    ("redirect", VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS),
    ("ssrf", VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY),
    ("request", VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY),
    ("xml", VulnerabilityType.XML_EXTERNAL_ENTITY),
    ("debug", VulnerabilityType.EXPOSED_FLASK_DEBUG),
    ("host", VulnerabilityType.SECURITY_MISCONFIGURATION),
    ("cookie", VulnerabilityType.SECURE_COOKIE),
    ("header", VulnerabilityType.INSECURE_HTTP_HEADERS),
)

# Canonical CWE per vulnerability type. Semgrep's own CWE metadata is often
# imprecise - `tainted-sql-string` reports CWE-704 and the Flask template
# rules report CWE-96 - so once the type has been resolved the canonical CWE
# for that type is authoritative. Fusion matches partly on CWE, and reports
# quote it, so leaving the rule's value in place would propagate the error.
TYPE_TO_CANONICAL_CWE: Dict[VulnerabilityType, str] = {
    VulnerabilityType.SQL_INJECTION: "89",
    VulnerabilityType.OS_COMMAND_INJECTION: "78",
    VulnerabilityType.CODE_INJECTION: "94",
    VulnerabilityType.CROSS_SITE_SCRIPTING: "79",
    VulnerabilityType.PATH_TRAVERSAL: "22",
    VulnerabilityType.INSECURE_DESERIALIZATION: "502",
    VulnerabilityType.HARDCODED_CREDENTIALS: "798",
    VulnerabilityType.EXPOSED_SECRET: "798",
    VulnerabilityType.CSRF: "352",
    VulnerabilityType.XML_EXTERNAL_ENTITY: "611",
    VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY: "918",
    VulnerabilityType.WEAK_CRYPTOGRAPHY: "327",
    VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM: "328",
    VulnerabilityType.SECURE_RANDOMNESS: "330",
    VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS: "601",
    VulnerabilityType.REGULAR_EXPRESSION_DENIAL_OF_SERVICE: "1333",
    VulnerabilityType.SECURE_COOKIE: "614",
    VulnerabilityType.REMOTE_CODE_EXECUTION: "94",
    VulnerabilityType.SECURITY_MISCONFIGURATION: "16",
    VulnerabilityType.EXPOSED_FLASK_DEBUG: "489",
    VulnerabilityType.BROKEN_AUTHENTICATION: "287",
    VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE: "639",
    VulnerabilityType.MISSING_AUTHENTICATION: "306",
}

# Types severe enough that an ERROR-level rule hit is treated as CRITICAL
# rather than HIGH. Keyed on the resolved type rather than the reported CWE,
# which cannot be relied on.
CRITICAL_TYPES = {
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.OS_COMMAND_INJECTION,
    VulnerabilityType.CODE_INJECTION,
    VulnerabilityType.INSECURE_DESERIALIZATION,
    VulnerabilityType.REMOTE_CODE_EXECUTION,
}

SEVERITY_MAP = {
    "ERROR": VulnerabilitySeverity.HIGH,
    "WARNING": VulnerabilitySeverity.MEDIUM,
    "INFO": VulnerabilitySeverity.LOW,
}

# Rough CVSS stand-ins per severity. Semgrep publishes no CVSS data, so these
# are documented defaults rather than computed scores.
CVSS_BY_SEVERITY = {
    VulnerabilitySeverity.CRITICAL: 9.0,
    VulnerabilitySeverity.HIGH: 7.5,
    VulnerabilitySeverity.MEDIUM: 5.0,
    VulnerabilitySeverity.LOW: 3.0,
    VulnerabilitySeverity.INFO: 1.0,
}


class SemgrepUnavailable(RuntimeError):
    """Raised when the semgrep executable cannot be found or invoked."""


class SemgrepRunner:
    """
    Wrapper around the semgrep CLI that returns Vulnerability objects.
    """

    def __init__(
        self,
        configs: Tuple[str, ...] = DEFAULT_CONFIGS,
        timeout: int = 300,
        executable: Optional[str] = None
    ) -> None:
        """
        Initialize the runner.

        Args:
            configs: Semgrep rule packs to load
            timeout: Maximum seconds to allow a scan to run
            executable: Path to the semgrep binary (auto-detected if omitted)
        """

        self.configs = configs
        self.timeout = timeout
        self.executable = executable or shutil.which("semgrep")

    @property
    def available(self) -> bool:
        """
        Whether semgrep can be invoked on this machine.
        """

        return self.executable is not None

    def scan(self, target: str) -> List[Vulnerability]:
        """
        Scan a file or directory and return deduplicated vulnerabilities.

        Args:
            target: Path to the file or directory to scan

        Returns:
            List[Vulnerability]: Findings tagged with FindingSource.SEMGREP

        Raises:
            SemgrepUnavailable: If the semgrep binary is missing or fails
        """

        raw = self._run(target)
        findings = [self._to_vulnerability(r) for r in raw]
        findings = [f for f in findings if f is not None]
        self._attach_snippets(findings)
        return self._deduplicate(findings)

    def _attach_snippets(self, findings: List[Vulnerability]) -> None:
        """
        Replace each finding's snippet with the real source from disk.

        Unauthenticated semgrep does not return matched source: it substitutes
        the literal string "requires login" for every result. Passing that
        through is not just a display problem - the finding fingerprint is
        derived from the snippet, so a constant placeholder collapses every
        same-type finding in a file to one identifier and silently breaks
        baselines and suppressions.

        Args:
            findings: Findings to fill in, modified in place
        """

        cache: Dict[str, List[str]] = {}

        for finding in findings:
            path = finding.location.file_path
            if path not in cache:
                try:
                    cache[path] = Path(path).read_text(
                        encoding="utf-8", errors="replace"
                    ).split("\n")
                except OSError as e:
                    logging.debug(f"Could not read {path} for a snippet: {e}")
                    cache[path] = []

            lines = cache[path]
            if not lines:
                finding.location.context = ""
            else:
                start = max(1, finding.location.start_line)
                end = min(
                    max(finding.location.end_line or start, start),
                    len(lines),
                    start + 12          # long matches would swamp the report
                )
                finding.location.context = "\n".join(lines[start - 1:end]).strip()

            # The snippet just changed, so the identifier derived from it must
            # be recomputed rather than left pointing at the placeholder.
            finding.id = ""
            finding.id = finding.fingerprint()

    def _run(self, target: str) -> List[Dict[str, Any]]:
        """
        Invoke semgrep and return its raw `results` array.

        Args:
            target: Path to scan

        Returns:
            List[Dict[str, Any]]: Raw semgrep result objects
        """

        if not self.available:
            raise SemgrepUnavailable(
                "semgrep not found on PATH. Install it with `pip install semgrep`."
            )

        # --no-git-ignore is essential, not a preference. Semgrep otherwise
        # silently skips anything git ignores, so a directory the caller
        # explicitly asked to scan can come back with zero findings while
        # reporting success. File selection is owned by analyzer.discovery,
        # which is the single authority on scope; findings outside that set
        # are dropped by the caller.
        cmd = [
            self.executable, "--json", "--metrics=off", "--quiet",
            "--no-git-ignore", "--disable-version-check",
        ]
        for config in self.configs:
            cmd.extend(["--config", config])
        cmd.append(str(target))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                encoding="utf-8",
                errors="replace"
            )
        except subprocess.TimeoutExpired:
            logging.error(f"Semgrep timed out after {self.timeout}s on {target}")
            return []
        except OSError as e:
            raise SemgrepUnavailable(f"Failed to execute semgrep: {e}")

        # Exit code 1 means findings were reported, which is not an error.
        if proc.returncode not in (0, 1):
            logging.error(f"Semgrep exited {proc.returncode}: {proc.stderr[:500]}")
            return []

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            logging.error(f"Could not parse semgrep JSON output: {e}")
            return []

        for err in payload.get("errors", []):
            logging.warning(f"Semgrep error: {err.get('message', err)}")

        return payload.get("results", [])

    def _to_vulnerability(self, result: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Convert one semgrep result into a Vulnerability.

        Args:
            result: A single entry from semgrep's `results` array

        Returns:
            Optional[Vulnerability]: None if the finding cannot be mapped
        """

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        check_id = result.get("check_id", "")

        cwe_raw = metadata.get("cwe") or []
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]

        cwe_number = self._first_cwe_number(cwe_raw)
        vuln_type = self._resolve_type(cwe_number, check_id)
        if vuln_type is None:
            logging.debug(f"Unmapped semgrep rule: {check_id} (cwe={cwe_raw})")
            return None

        # Prefer the canonical CWE for the resolved type over the rule's own
        # metadata, which is frequently wrong.
        cwe_number = TYPE_TO_CANONICAL_CWE.get(vuln_type, cwe_number)

        severity = SEVERITY_MAP.get(
            str(extra.get("severity", "WARNING")).upper(),
            VulnerabilitySeverity.MEDIUM
        )
        if severity == VulnerabilitySeverity.HIGH and vuln_type in CRITICAL_TYPES:
            severity = VulnerabilitySeverity.CRITICAL

        owasp_raw = metadata.get("owasp") or []
        if isinstance(owasp_raw, str):
            owasp_raw = [owasp_raw]
        owasp = self._preferred_owasp(owasp_raw)

        start = result.get("start", {})
        end = result.get("end", {})
        location = CodeLocation(
            file_path=result.get("path", ""),
            start_line=start.get("line", 0),
            end_line=end.get("line", start.get("line", 0)),
            start_col=start.get("col"),
            end_col=end.get("col"),
            # Filled in by _attach_snippets from the file itself; semgrep's
            # own value is a placeholder unless the CLI is logged in.
            context=""
        )

        references = [r for r in (metadata.get("references") or []) if isinstance(r, str)]
        message = (extra.get("message") or "").strip()

        return Vulnerability(
            type=vuln_type,
            severity=severity,
            location=location,
            description=message or f"Rule {check_id} matched.",
            impact=metadata.get("impact", "") or "See rule documentation.",
            # The LLM tier fills these in; rule engines do not produce them.
            remediation=self._extract_fix(extra) or "",
            cwe_id=f"CWE-{cwe_number}" if cwe_number else "",
            owasp_category=owasp,
            cvss_score=CVSS_BY_SEVERITY[severity],
            references=references,
            proof_of_concept="",
            secure_code_example=self._extract_fix(extra) or "",
            source=FindingSource.SEMGREP,
            confidence=0.9,
            rule_id=check_id
        )

    @staticmethod
    def _first_cwe_number(cwe_entries: List[str]) -> str:
        """
        Extract the numeric part of the first CWE identifier.

        Args:
            cwe_entries: CWE strings such as "CWE-89: Improper Neutralization..."

        Returns:
            str: The bare number, or "" when none is present
        """

        for entry in cwe_entries:
            match = re.search(r"CWE-(\d+)", str(entry))
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _preferred_owasp(owasp_entries: List[str]) -> str:
        """
        Pick the most recent OWASP category available.

        Semgrep lists several editions (2017/2021/2025) per rule; the newest
        published Top 10 that the project already references is 2021.

        Args:
            owasp_entries: OWASP category strings

        Returns:
            str: A single category, or "" if none
        """

        for preferred in ("A0", "2021"):
            for entry in owasp_entries:
                if preferred in str(entry) and "2021" in str(entry):
                    return str(entry)
        return str(owasp_entries[0]) if owasp_entries else ""

    @staticmethod
    def _extract_fix(extra: Dict[str, Any]) -> str:
        """
        Return semgrep's autofix suggestion when the rule provides one.

        Args:
            extra: The `extra` object of a semgrep result

        Returns:
            str: The suggested replacement, or "" when absent
        """

        fix = extra.get("fix")
        return str(fix).strip() if fix else ""

    @staticmethod
    def _resolve_type(cwe_number: str, check_id: str) -> Optional[VulnerabilityType]:
        """
        Map a semgrep rule onto a VulnerabilityType.

        CWE metadata is tried first; when it is absent or unrecognised the
        rule id is scanned for known keywords.

        Args:
            cwe_number: Numeric CWE identifier, or ""
            check_id: Full semgrep rule id

        Returns:
            Optional[VulnerabilityType]: None when no mapping applies
        """

        if cwe_number and cwe_number in CWE_TO_TYPE:
            return CWE_TO_TYPE[cwe_number]

        rule_tail = check_id.lower().rsplit(".", 1)[-1]
        for keyword, vuln_type in RULE_KEYWORD_TO_TYPE:
            if keyword in rule_tail:
                return vuln_type

        return None

    @staticmethod
    def _deduplicate(findings: List[Vulnerability]) -> List[Vulnerability]:
        """
        Collapse overlapping findings that describe the same defect.

        Several rules routinely fire on one line - `subprocess.check_output`
        with `shell=True` triggers three separate command-injection rules -
        which would otherwise inflate every count downstream.

        Args:
            findings: Raw converted findings

        Returns:
            List[Vulnerability]: One finding per (file, type, overlapping span)
        """

        severity_rank = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 3,
            VulnerabilitySeverity.INFO: 4,
        }

        kept: List[Vulnerability] = []
        for finding in sorted(findings, key=lambda f: severity_rank[f.severity]):
            duplicate = False
            for existing in kept:
                same_file = existing.location.file_path == finding.location.file_path
                same_type = existing.type == finding.type
                overlaps = not (
                    finding.location.end_line < existing.location.start_line
                    or finding.location.start_line > existing.location.end_line
                )
                if same_file and same_type and overlaps:
                    # Preserve every rule that contributed to this finding.
                    if finding.rule_id and finding.rule_id not in existing.merged_rule_ids:
                        existing.merged_rule_ids.append(finding.rule_id)
                    duplicate = True
                    break
            if not duplicate:
                if finding.rule_id:
                    finding.merged_rule_ids = [finding.rule_id]
                kept.append(finding)

        return sorted(kept, key=lambda f: (f.location.file_path, f.location.start_line))


def scan_path(target: str, **kwargs: Any) -> List[Vulnerability]:
    """
    Convenience wrapper for a one-off scan.

    Args:
        target: File or directory to scan
        **kwargs: Forwarded to SemgrepRunner

    Returns:
        List[Vulnerability]: Deduplicated findings
    """

    return SemgrepRunner(**kwargs).scan(target)
