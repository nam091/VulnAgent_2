"""Multi-file scan orchestration.

Ties discovery, the two tiers, caching and concurrency together. The rule
tier runs once over the whole tree rather than per file, and the LLM tier
runs concurrently over the subset that routing selected.
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from analyzer import fusion
from analyzer.code_analyzer import CodeAnalyzer
from analyzer.discovery import DiscoveredFile, discover, route_to_llm
from analyzer.semgrep_runner import SemgrepRunner, SemgrepUnavailable
from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilityReport,
)

CACHE_DIRNAME = ".vulnagent-cache"
CACHE_VERSION = "v2"


class ScanOptions:
    """
    Everything that varies between one scan invocation and the next.
    """

    def __init__(
        self,
        target: str,
        use_llm: bool = True,
        use_semgrep: bool = True,
        concurrency: int = 5,
        min_risk: int = 3,
        max_llm_files: Optional[int] = None,
        excludes: Optional[List[str]] = None,
        use_cache: bool = True,
        cache_dir: Optional[str] = None,
        verify: bool = False,
        verify_all: bool = False,
        verify_turns: int = 6,
        progress: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> None:
        self.target = target
        self.use_llm = use_llm
        self.use_semgrep = use_semgrep
        self.concurrency = max(1, concurrency)
        self.min_risk = min_risk
        self.max_llm_files = max_llm_files
        self.excludes = excludes or []
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        # Adversarial verification. By default it runs only on LLM-only
        # findings, which is where the measured false positives are; findings
        # two independent engines already agreed on do not need a third
        # opinion, and paying for one on every finding is mostly waste.
        self.verify = verify
        self.verify_all = verify_all
        self.verify_turns = verify_turns
        # Called with a progress event after each phase and after each file
        # completes, so a caller can show real progress rather than a
        # spinner that says nothing.
        self.progress = progress


class ScanResult:
    """
    Aggregated outcome of a scan across many files.
    """

    def __init__(
        self,
        reports: List[VulnerabilityReport],
        root: Path,
        stats: Dict[str, Any]
    ) -> None:
        self.reports = reports
        self.root = root
        self.stats = stats

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        """
        Every finding across every file.

        Returns:
            List[Vulnerability]: Flattened findings
        """

        found: List[Vulnerability] = []
        for report in self.reports:
            found.extend(report.vulnerabilities)
        return found

    @property
    def degraded(self) -> bool:
        """
        Whether any file's scan ran with a failed tier.

        Returns:
            bool: True when at least one report is degraded
        """

        return any(report.degraded for report in self.reports)


class Scanner:
    """
    Runs the hybrid pipeline over a file or directory tree.
    """

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.analyzer = CodeAnalyzer(use_semgrep=False)  # rule tier is run here
        self.semgrep = SemgrepRunner() if options.use_semgrep else None
        self._cache_dir: Optional[Path] = None

    async def scan(self) -> ScanResult:
        """
        Execute a full scan.

        Returns:
            ScanResult: Reports plus timing and routing statistics
        """

        started = time.perf_counter()
        target_path = Path(self.options.target).resolve()
        root = target_path if target_path.is_dir() else target_path.parent

        self._emit("discovery", "Discovering source files", 2)
        files = discover(self.options.target, extra_excludes=self.options.excludes)
        if not files:
            logging.warning(f"No source files found under {self.options.target}")
            self._emit("done", "No source files found", 100)
            return ScanResult([], root, {"files_discovered": 0})
        self._emit(
            "discovery", f"Found {len(files)} source file(s)", 6,
            files_discovered=len(files)
        )

        # Tier 1: one semgrep invocation for the whole tree.
        self._emit("rules", "Running rule engine over every file", 10)
        rule_started = time.perf_counter()
        rule_by_file = self._run_rule_tier(root, {f.relative for f in files})
        rule_elapsed = time.perf_counter() - rule_started
        rule_total = sum(len(v) for v in rule_by_file.values())
        self._emit(
            "rules", f"Rule engine found {rule_total} finding(s)", 25,
            rule_findings=rule_total
        )

        # Tier 2: LLM over the routed subset only.
        rule_hits = {path: len(v) for path, v in rule_by_file.items()}
        routed = (
            route_to_llm(
                files,
                rule_hits=rule_hits,
                min_risk=self.options.min_risk,
                limit=self.options.max_llm_files
            )
            if self.options.use_llm else []
        )

        if routed:
            self._emit(
                "llm", f"Analysing {len(routed)} file(s) with the LLM", 28,
                total=len(routed), current=0
            )
        llm_started = time.perf_counter()
        llm_by_file, tier_status = await self._run_llm_tier(routed)
        llm_elapsed = time.perf_counter() - llm_started

        self._emit("fusion", "Merging results from both tiers", 72)
        reports = self._assemble(files, rule_by_file, llm_by_file, tier_status)

        verify_stats: Dict[str, Any] = {}
        if self.options.verify:
            verify_started = time.perf_counter()
            verify_stats = await self._run_verification(reports, root)
            verify_stats["verify_seconds"] = round(time.perf_counter() - verify_started, 2)

        stats = {
            "files_discovered": len(files),
            "files_sent_to_llm": len(routed),
            "rule_tier_seconds": round(rule_elapsed, 2),
            "llm_tier_seconds": round(llm_elapsed, 2),
            "total_seconds": round(time.perf_counter() - started, 2),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            **verify_stats,
        }
        logging.info(f"Scan complete: {stats}")
        self._emit(
            "done", "Scan complete", 100,
            findings=sum(len(r.vulnerabilities) for r in reports)
        )

        return ScanResult(reports, root, stats)

    _cache_hits = 0
    _cache_misses = 0

    def _emit(
        self,
        phase: str,
        message: str,
        percent: float,
        **extra: Any
    ) -> None:
        """
        Report progress to the caller, if one asked for it.

        A failing progress callback must never take the scan down with it.

        Args:
            phase: Which stage is running
            message: Human-readable description
            percent: Overall completion, 0-100
            **extra: Additional fields for the event
        """

        if self.options.progress is None:
            return
        event = {
            "phase": phase,
            "message": message,
            "percent": round(max(0.0, min(100.0, percent)), 1),
            **extra,
        }
        try:
            self.options.progress(event)
        except Exception as e:
            logging.debug(f"Progress callback raised: {e}")

    def _run_rule_tier(
        self,
        root: Path,
        in_scope: Set[str]
    ) -> Dict[str, List[Vulnerability]]:
        """
        Run semgrep once and group findings by relative path.

        Args:
            root: Scan root, used to relativise paths
            in_scope: Relative paths that discovery selected

        Returns:
            Dict[str, List[Vulnerability]]: Findings keyed by relative path
        """

        if self.semgrep is None or not self.semgrep.available:
            if self.semgrep is not None:
                logging.warning("semgrep not available; running LLM tier only")
            return {}

        try:
            findings = self.semgrep.scan(self.options.target)
        except SemgrepUnavailable as e:
            logging.warning(f"Rule tier skipped: {e}")
            return {}

        grouped: Dict[str, List[Vulnerability]] = defaultdict(list)
        out_of_scope = 0

        for finding in findings:
            relative = self._relativise(finding.location.file_path, root)
            # Discovery owns scope; semgrep runs with --no-git-ignore so its
            # own exclusion rules cannot silently shrink coverage, and its
            # results are narrowed back to the discovered set here.
            if in_scope and relative not in in_scope:
                out_of_scope += 1
                continue
            finding.location.file_path = relative
            finding.id = ""
            finding.id = finding.fingerprint()
            grouped[relative].append(finding)

        if out_of_scope:
            logging.debug(f"Dropped {out_of_scope} rule finding(s) outside the discovered set")

        return dict(grouped)

    async def _run_llm_tier(
        self,
        routed: List[DiscoveredFile]
    ) -> tuple:
        """
        Analyse the routed files concurrently.

        Args:
            routed: Files selected for LLM analysis

        Returns:
            tuple: (findings by relative path, tier status by relative path)
        """

        if not routed:
            return {}, {}

        semaphore = asyncio.Semaphore(self.options.concurrency)
        results: Dict[str, List[Vulnerability]] = {}
        status: Dict[str, str] = {}
        completed = {"n": 0}
        total = len(routed)

        def tick(relative: str) -> None:
            completed["n"] += 1
            # The LLM tier owns the 28-70 band of the overall progress bar.
            percent = 28 + 42 * (completed["n"] / total)
            self._emit(
                "llm", f"Analysed {completed['n']}/{total}: {relative}", percent,
                current=completed["n"], total=total
            )

        async def analyse(item: DiscoveredFile) -> None:
            async with semaphore:
                relative = item.relative
                try:
                    content = item.path.read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    status[relative] = f"failed: {e}"
                    tick(relative)
                    return

                cached = self._cache_get(content)
                if cached is not None:
                    Scanner._cache_hits += 1
                    results[relative] = self.analyzer._process_ai_response(cached, relative)
                    status[relative] = "ok"
                    tick(relative)
                    return

                Scanner._cache_misses += 1
                parsed = self.analyzer.code_parser.parse(content, relative)
                prompt = self.analyzer._generate_security_prompt(parsed)
                try:
                    raw = await self.analyzer._get_analysis_with_retry(prompt)
                except Exception as e:
                    logging.error(f"LLM tier failed for {relative}: {e}")
                    status[relative] = f"failed: {e}"
                    tick(relative)
                    return

                self._cache_put(content, raw)
                results[relative] = self.analyzer._process_ai_response(raw, relative)
                status[relative] = "ok"
                tick(relative)

        await asyncio.gather(*(analyse(item) for item in routed))
        return results, status

    async def _run_verification(
        self,
        reports: List[VulnerabilityReport],
        root: Path
    ) -> Dict[str, Any]:
        """
        Send candidate findings through the adversarial verification agent.

        Findings the agent refutes with a named mitigating control are
        dropped; findings it upholds gain a confidence boost and the taint
        path it traced. Findings it could not settle are kept unchanged,
        because deleting a real vulnerability is worse than reporting an
        unverified one.

        Args:
            reports: Reports to verify in place
            root: Scan root the agent's tools are confined to

        Returns:
            Dict[str, Any]: Verification counters for the scan statistics
        """

        from agent.verifier import VerificationAgent

        candidates: List[Tuple[VulnerabilityReport, Vulnerability]] = []
        for report in reports:
            for vuln in report.vulnerabilities:
                if self.options.verify_all or vuln.source == FindingSource.LLM:
                    candidates.append((report, vuln))

        if not candidates:
            return {"verified_candidates": 0}

        agent = VerificationAgent(
            client=self.analyzer.ai_client.openai_client,
            model=self.analyzer.ai_client.openai_default_model,
            root=root,
            max_turns=self.options.verify_turns,
            temperature=None if self.analyzer.ai_client._is_reasoning_model(
                self.analyzer.ai_client.openai_default_model
            ) else 0,
        )

        semaphore = asyncio.Semaphore(self.options.concurrency)
        counters = {"confirmed": 0, "refuted": 0, "uncertain": 0, "tool_calls": 0}
        refuted_ids: set = set()
        done = {"n": 0}
        total = len(candidates)
        self._emit("verify", f"Verifying {total} candidate finding(s)", 75, total=total, current=0)

        async def check(report: VulnerabilityReport, vuln: Vulnerability) -> None:
            async with semaphore:
                verdict = await agent.verify(vuln)
                done["n"] += 1
                self._emit(
                    "verify",
                    f"Verified {done['n']}/{total}: {vuln.type.value} -> {verdict.verdict}",
                    75 + 23 * (done["n"] / total),
                    current=done["n"], total=total
                )
                vuln.verification = verdict.as_dict()
                counters["tool_calls"] += verdict.tool_calls
                counters[verdict.verdict] = counters.get(verdict.verdict, 0) + 1

                if verdict.confirmed:
                    vuln.taint_path = verdict.taint_path
                    # Corroboration by independent investigation, not by a
                    # second engine - kept below CONFIRMED-by-fusion.
                    vuln.confidence = max(vuln.confidence, 0.85)
                elif verdict.refuted:
                    refuted_ids.add(vuln.id)

        await asyncio.gather(*(check(r, v) for r, v in candidates))

        dropped = 0
        for report in reports:
            before = len(report.vulnerabilities)
            report.vulnerabilities = [
                v for v in report.vulnerabilities if v.id not in refuted_ids
            ]
            dropped += before - len(report.vulnerabilities)
            if before != len(report.vulnerabilities):
                report.chained_vulnerabilities = self.analyzer._chain_vulnerabilities(
                    report.vulnerabilities
                )
                report.calculate_summary()
                report.calculate_risk_score()

        logging.info(
            "Verification: %d candidate(s) -> %d confirmed, %d refuted, %d uncertain",
            len(candidates), counters["confirmed"], counters["refuted"], counters["uncertain"]
        )

        return {
            "verified_candidates": len(candidates),
            "verify_confirmed": counters["confirmed"],
            "verify_refuted": counters["refuted"],
            "verify_uncertain": counters["uncertain"],
            "verify_dropped": dropped,
            "verify_tool_calls": counters["tool_calls"],
        }

    def _assemble(
        self,
        files: List[DiscoveredFile],
        rule_by_file: Dict[str, List[Vulnerability]],
        llm_by_file: Dict[str, List[Vulnerability]],
        tier_status: Dict[str, str]
    ) -> List[VulnerabilityReport]:
        """
        Fuse both tiers per file and build one report per file with findings.

        Args:
            files: All discovered files
            rule_by_file: Rule-tier findings by relative path
            llm_by_file: LLM-tier findings by relative path
            tier_status: LLM tier outcome by relative path

        Returns:
            List[VulnerabilityReport]: One report per file that had findings
        """

        reports = []
        semgrep_status = (
            "ok" if (self.semgrep and self.semgrep.available)
            else ("disabled" if self.semgrep is None else "unavailable")
        )

        for item in files:
            relative = item.relative
            rule_findings = rule_by_file.get(relative, [])
            llm_findings = llm_by_file.get(relative, [])

            if not rule_findings and not llm_findings:
                continue

            fused = fusion.fuse(rule_findings, llm_findings)
            chains = self.analyzer._chain_vulnerabilities(fused.vulnerabilities)

            tiers = {"semgrep": semgrep_status}
            if not self.options.use_llm:
                tiers["llm"] = "disabled"
            else:
                tiers["llm"] = tier_status.get(relative, "not routed")

            report = VulnerabilityReport(
                file_name=relative,
                vulnerabilities=fused.vulnerabilities,
                chained_vulnerabilities=chains,
                timestamp=datetime.now(),
                tiers=tiers
            )
            report.calculate_summary()
            report.calculate_risk_score()
            reports.append(report)

        return reports

    @staticmethod
    def _relativise(file_path: str, root: Path) -> str:
        """
        Express a path relative to the scan root in posix form.

        Args:
            file_path: Absolute or relative path
            root: Scan root

        Returns:
            str: Relative posix path
        """

        try:
            return Path(file_path).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            return Path(file_path).as_posix()

    # ---- content-hash cache -------------------------------------------------

    def _cache_key(self, content: str) -> str:
        """
        Derive the cache key for a file's LLM analysis.

        The model name is part of the key because switching models must not
        silently reuse another model's findings - that would quietly corrupt
        any model comparison.

        Args:
            content: File contents

        Returns:
            str: Hex digest
        """

        model = os.getenv("OPENAI_MODEL", "default")
        payload = f"{CACHE_VERSION}|{model}|{content}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _resolve_cache_dir(self) -> Optional[Path]:
        """
        Locate (and create) the cache directory.

        Returns:
            Optional[Path]: The directory, or None when caching is disabled
        """

        if not self.options.use_cache:
            return None
        if self._cache_dir is None:
            base = Path(self.options.cache_dir or Path.cwd() / CACHE_DIRNAME)
            try:
                base.mkdir(parents=True, exist_ok=True)
                self._cache_dir = base
            except OSError as e:
                logging.debug(f"Cache disabled, cannot create {base}: {e}")
                return None
        return self._cache_dir

    def _cache_get(self, content: str) -> Optional[Dict[str, Any]]:
        """
        Look up a previously stored LLM analysis.

        Args:
            content: File contents

        Returns:
            Optional[Dict[str, Any]]: The cached raw analysis, or None
        """

        cache_dir = self._resolve_cache_dir()
        if cache_dir is None:
            return None

        path = cache_dir / f"{self._cache_key(content)}.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _cache_put(self, content: str, analysis: Dict[str, Any]) -> None:
        """
        Store an LLM analysis for reuse.

        Args:
            content: File contents
            analysis: Raw analysis dictionary
        """

        cache_dir = self._resolve_cache_dir()
        if cache_dir is None:
            return

        path = cache_dir / f"{self._cache_key(content)}.json"
        try:
            path.write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
        except OSError as e:
            logging.debug(f"Could not write cache entry {path}: {e}")


async def scan(options: ScanOptions) -> ScanResult:
    """
    Convenience entry point for a single scan.

    Args:
        options: Scan configuration

    Returns:
        ScanResult: The aggregated outcome
    """

    return await Scanner(options).scan()
