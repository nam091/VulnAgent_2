"""Baseline tracking and inline suppression.

Pointing any scanner at an existing codebase produces a wall of findings
that nobody triages, and the tool gets removed. Both mechanisms here exist
to make the *new* problem visible without drowning it in the old one.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from models.vulnerability import FindingSource, Vulnerability

BASELINE_FILENAME = ".vulnagent-baseline.json"
BASELINE_VERSION = 1

# `# vulnagent: ignore[SQL_INJECTION] reason here`  (type list optional)
SUPPRESS_PATTERN = re.compile(
    r"#\s*vulnagent:\s*ignore(?:\[([A-Z_,\s()]+)\])?(?:\s+(.*))?$",
    re.IGNORECASE
)
# Whole-file opt-out, expected near the top of the file.
SUPPRESS_FILE_PATTERN = re.compile(r"#\s*vulnagent:\s*ignore-file\b", re.IGNORECASE)
# Honour the markers developers already use for the tools this sits next to.
FOREIGN_MARKERS = re.compile(r"#\s*(?:nosec|nosemgrep|noqa:\s*S\d+)\b", re.IGNORECASE)


class Baseline:
    """
    A recorded set of findings that are considered accepted debt.
    """

    def __init__(self, fingerprints: Optional[Dict[str, dict]] = None) -> None:
        self.fingerprints: Dict[str, dict] = fingerprints or {}

    @classmethod
    def load(cls, path: str) -> 'Baseline':
        """
        Read a baseline file.

        Args:
            path: Path to the baseline JSON

        Returns:
            Baseline: The loaded baseline, empty when the file is absent
        """

        file_path = Path(path)
        if not file_path.is_file():
            logging.info(f"No baseline at {path}; every finding counts as new")
            return cls()

        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logging.warning(f"Could not read baseline {path}: {e}")
            return cls()

        version = payload.get("version")
        if version != BASELINE_VERSION:
            logging.warning(
                f"Baseline {path} is version {version}, expected {BASELINE_VERSION}; "
                "treating it as empty rather than silently mismatching."
            )
            return cls()

        return cls(payload.get("fingerprints", {}))

    def save(self, path: str, vulnerabilities: Sequence[Vulnerability]) -> None:
        """
        Write the current findings out as the accepted baseline.

        Args:
            path: Destination path
            vulnerabilities: Findings to record
        """

        stamp = datetime.now().isoformat(timespec="seconds")
        fingerprints = {}
        for vuln in vulnerabilities:
            existing = self.fingerprints.get(vuln.id, {})
            fingerprints[vuln.id] = {
                "file": vuln.location.file_path,
                "type": vuln.type.value,
                "severity": vuln.severity.value,
                "source": vuln.source.value,
                "first_seen": existing.get("first_seen", stamp),
            }

        payload = {
            "version": BASELINE_VERSION,
            "updated": stamp,
            "count": len(fingerprints),
            "fingerprints": fingerprints,
        }

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        self.fingerprints = fingerprints

    def partition(
        self,
        vulnerabilities: Sequence[Vulnerability]
    ) -> Tuple[List[Vulnerability], List[Vulnerability]]:
        """
        Split findings into new and previously accepted.

        Args:
            vulnerabilities: Findings from the current scan

        Returns:
            Tuple[List[Vulnerability], List[Vulnerability]]: (new, known)
        """

        new_findings = []
        known_findings = []
        for vuln in vulnerabilities:
            if vuln.id in self.fingerprints:
                known_findings.append(vuln)
            else:
                new_findings.append(vuln)
        return new_findings, known_findings

    def resolved(self, vulnerabilities: Sequence[Vulnerability]) -> List[str]:
        """
        Identify baseline entries that no longer appear.

        Args:
            vulnerabilities: Findings from the current scan

        Returns:
            List[str]: Fingerprints that have been fixed or removed
        """

        current = {v.id for v in vulnerabilities}
        return [fp for fp in self.fingerprints if fp not in current]


class SuppressionIndex:
    """
    Inline `# vulnagent: ignore` directives, read from the scanned sources.
    """

    def __init__(self) -> None:
        self._by_file: Dict[str, Dict[int, Optional[Set[str]]]] = {}
        self._whole_file: Set[str] = set()
        self._cache_loaded: Set[str] = set()

    def load_file(self, relative_path: str, content: str) -> None:
        """
        Parse suppression directives out of one file.

        Args:
            relative_path: Path used as the lookup key
            content: The file's source
        """

        if relative_path in self._cache_loaded:
            return
        self._cache_loaded.add(relative_path)

        lines = content.split("\n")
        directives: Dict[int, Optional[Set[str]]] = {}

        for index, line in enumerate(lines, 1):
            if SUPPRESS_FILE_PATTERN.search(line):
                self._whole_file.add(relative_path)
                return

            match = SUPPRESS_PATTERN.search(line)
            if match:
                types = match.group(1)
                parsed = (
                    {t.strip().upper() for t in types.split(",") if t.strip()}
                    if types else None
                )
                # A directive applies to its own line and the line after it,
                # so it can sit either trailing the code or above it.
                directives[index] = parsed
                directives.setdefault(index + 1, parsed)
            elif FOREIGN_MARKERS.search(line):
                directives.setdefault(index, None)

        self._by_file[relative_path] = directives

    def is_suppressed(self, vuln: Vulnerability) -> bool:
        """
        Whether a finding has been explicitly waived in source.

        Args:
            vuln: The finding

        Returns:
            bool: True when a directive covers it
        """

        path = vuln.location.file_path
        if path in self._whole_file:
            return True

        directives = self._by_file.get(path)
        if not directives:
            return False

        start = vuln.location.start_line
        end = max(vuln.location.end_line or start, start)

        for line in range(start, end + 1):
            if line not in directives:
                continue
            allowed = directives[line]
            if allowed is None or vuln.type.value.upper() in allowed:
                return True

        return False

    def apply(self, vulnerabilities: Sequence[Vulnerability]) -> Tuple[List[Vulnerability], int]:
        """
        Filter out suppressed findings.

        Args:
            vulnerabilities: Findings to filter

        Returns:
            Tuple[List[Vulnerability], int]: (kept findings, suppressed count)
        """

        kept = [v for v in vulnerabilities if not self.is_suppressed(v)]
        return kept, len(vulnerabilities) - len(kept)


def gate(
    vulnerabilities: Sequence[Vulnerability],
    threshold_rank: Optional[int],
    severity_rank: Dict,
    confirmed_only: bool = False
) -> List[Vulnerability]:
    """
    Select the findings that should fail a build.

    Gating on confirmed findings only is the recommended default for CI.
    LLM-only findings fluctuate slightly between runs even at temperature
    zero, so treating them as blocking makes pipelines flap; they remain
    visible as warnings.

    Args:
        vulnerabilities: Findings to consider
        threshold_rank: Severity rank at or above which a finding blocks
        severity_rank: Mapping of severity to numeric rank
        confirmed_only: Restrict blocking to corroborated findings

    Returns:
        List[Vulnerability]: Findings that breach the gate
    """

    if threshold_rank is None:
        return []

    breaching = []
    for vuln in vulnerabilities:
        if severity_rank[vuln.severity] > threshold_rank:
            continue
        if confirmed_only and vuln.source == FindingSource.LLM:
            continue
        breaching.append(vuln)

    return breaching
