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
import uuid
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
        progress: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_partial: Optional[Callable[[List[VulnerabilityReport]], None]] = None,
        files: Optional[List[str]] = None,
        semgrep_configs: Optional[Tuple[str, ...]] = None,
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
        self.files = files
        self.semgrep_configs = semgrep_configs
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
        # Called with the reports as soon as they exist, before verification
        # runs. Verification can take minutes; showing what has already been
        # found beats an empty screen with a moving bar.
        self.on_partial = on_partial


class ScanResult:
    """
    Aggregated outcome of a scan across many files.
    """

    def __init__(
        self,
        reports: List[VulnerabilityReport],
        root: Path,
        stats: Dict[str, Any],
        file_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self.reports = reports
        self.root = root
        self.stats = stats
        self.file_hashes: Dict[str, str] = {}
        if file_hashes:
            self.file_hashes.update(file_hashes)
        if "file_hashes" in self.stats and isinstance(self.stats["file_hashes"], dict):
            self.file_hashes.update(self.stats["file_hashes"])
        elif "snapshot_hashes" in self.stats and isinstance(self.stats["snapshot_hashes"], dict):
            self.file_hashes.update(self.stats["snapshot_hashes"])

        for r in self.reports:
            for v in r.vulnerabilities:
                if getattr(v, "file_hash", None):
                    self.file_hashes[v.location.file_path] = v.file_hash
                    try:
                        self.file_hashes[str((self.root / v.location.file_path).resolve())] = v.file_hash
                    except Exception:
                        pass

        self.stats["file_hashes"] = self.file_hashes
        self.stats["snapshot_hashes"] = self.file_hashes

    @property
    def snapshot_hashes(self) -> Dict[str, str]:
        return self.file_hashes

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
        Whether any file's scan ran with a failed tier or global error.

        Returns:
            bool: True when at least one report is degraded or engine failed
        """
        if self.stats.get("engine_failure") or self.stats.get("rule_error") or self.stats.get("global_errors"):
            return True
        if not self.reports and self.stats.get("files_requested"):
            return True
        return any(report.degraded for report in self.reports)

    @property
    def refuted_vulnerabilities(self) -> List[Vulnerability]:
        """
        All findings refuted by verification across files.
        """
        refuted: List[Vulnerability] = []
        for report in self.reports:
            refuted.extend(report.refuted_vulnerabilities)
        return refuted

    @property
    def status(self) -> str:
        """
        Overall run status: completed, partial, or failed.
        Consistent contract across CLI, MCP, SARIF, and UI (B01).
        """
        if self.stats.get("engine_failure") or self.stats.get("rule_error") or self.stats.get("global_errors"):
            return "failed"
        if not self.reports:
            if self.stats.get("files_requested"):
                return "failed"
            return "completed"
        if all(r.status == "failed" or r.degraded for r in self.reports):
            return "failed"
        if any(r.status in ("failed", "partial") or r.degraded for r in self.reports):
            return "partial"
        return "completed"

    @property
    def coverage(self) -> Dict[str, Any]:
        """
        Detailed coverage metrics reflecting requested vs actual analyzed files.
        """
        files_requested = self.stats.get("files_requested", [r.file_name for r in self.reports if r.file_name])
        files_scanned = [r.file_name for r in self.reports if r.file_name]
        files_completed = [r.file_name for r in self.reports if r.status == "completed" and not r.degraded]
        files_failed = [r.file_name for r in self.reports if r.status == "failed" or r.degraded]
        files_partial = [r.file_name for r in self.reports if r.status == "partial"]

        return {
            "requested_count": len(files_requested),
            "scanned_count": len(files_scanned),
            "completed_count": len(files_completed),
            "failed_count": len(files_failed),
            "partial_count": len(files_partial),
            "status": self.status,
            "degraded": self.degraded,
            "file_statuses": {
                r.file_name: {
                    "status": r.status,
                    "degraded": r.degraded,
                    "engine_status": r.engine_status,
                }
                for r in self.reports if r.file_name
            },
            "semgrep": {
                "analyzed_files": [
                    r.file_name for r in self.reports
                    if r.file_name and r.engine_status.get("semgrep", {}).get("status") in ("ok", "completed")
                ],
                "failed_files": [
                    r.file_name for r in self.reports
                    if r.file_name and r.engine_status.get("semgrep", {}).get("status") in ("failed", "parse_error")
                ],
            },
            "llm": {
                "analyzed_files": [
                    r.file_name for r in self.reports
                    if r.file_name and r.engine_status.get("llm", {}).get("status") == "completed"
                ],
                "failed_files": [
                    r.file_name for r in self.reports
                    if r.file_name and r.engine_status.get("llm", {}).get("status") == "failed"
                ],
            },
        }


class Scanner:
    """
    Runs the hybrid pipeline over a file or directory tree.
    """

    def __init__(self, options: ScanOptions) -> None:
        self.options = options
        self.analyzer = CodeAnalyzer(use_semgrep=False, use_llm=options.use_llm)  # rule tier is run here
        semgrep_kw = {"configs": options.semgrep_configs} if options.semgrep_configs else {}
        self.semgrep = SemgrepRunner(**semgrep_kw) if options.use_semgrep else None
        self._cache_dir: Optional[Path] = None
        # Set when the rule tier fails, so a hung or missing engine is
        # reported as a degraded scan rather than as a clean one.
        self._rule_error: str = ""
        # Per-scan counters. These were class attributes, which meant every
        # Scanner shared them: in the web server, where one process runs many
        # scans, each result reported the running total of every scan before
        # it rather than its own.
        self._cache_hits = 0
        self._cache_misses = 0

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
        files = await asyncio.to_thread(
            discover, self.options.target, self.options.excludes
        )
        missing_requested: Set[str] = set()
        requested_files: List[str] = []
        if self.options.files is not None:
            requested_relatives = set()
            for f in self.options.files:
                p = Path(f)
                if p.is_absolute():
                    try:
                        rel = p.resolve().relative_to(root).as_posix()
                    except (ValueError, OSError):
                        rel = p.as_posix()
                else:
                    try:
                        rel = (root / p).resolve().relative_to(root).as_posix()
                    except (ValueError, OSError):
                        rel = p.as_posix().lstrip("./")
                requested_relatives.add(rel)
            requested_files = sorted(list(requested_relatives))
            files = [f for f in files if f.relative in requested_relatives]
            discovered_relatives = {f.relative for f in files}
            missing_requested = requested_relatives - discovered_relatives
        else:
            requested_files = [f.relative for f in files]

        if not files:
            logging.warning(f"No source files found under {self.options.target}")
            self._emit("done", "No source files found", 100)
            failed_reports: List[VulnerabilityReport] = []
            if missing_requested:
                for mf in sorted(missing_requested):
                    failed_reports.append(
                        VulnerabilityReport(
                            file_name=mf,
                            vulnerabilities=[],
                            chained_vulnerabilities=[],
                            timestamp=datetime.now(),
                            tiers={"semgrep": "failed: file not found or inaccessible"},
                            status="failed",
                            engine_status={
                                "semgrep": {
                                    "requested": self.options.use_semgrep,
                                    "status": "failed",
                                    "reason": "Target file missing on disk or inaccessible",
                                    "findings": 0,
                                },
                                "llm": {
                                    "requested": self.options.use_llm,
                                    "status": "not_routed",
                                    "reason": "Target file missing",
                                    "findings": 0,
                                },
                            },
                        )
                    )
            return ScanResult(failed_reports, root, {
                "files_discovered": 0,
                "files_requested": requested_files,
                "files_scanned": len(failed_reports),
                "engine_failure": bool(missing_requested),
            })
        file_hashes: Dict[str, str] = {}
        for f in files:
            try:
                if f.path.is_file():
                    content = f.path.read_text(encoding="utf-8", errors="replace")
                    h = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    file_hashes[f.relative] = h
                    file_hashes[str(f.path.resolve())] = h
            except OSError:
                pass

        self._emit(
            "discovery", f"Found {len(files)} source file(s)", 6,
            files_discovered=len(files)
        )

        # Tier 1: one semgrep invocation for the whole tree.
        self._emit("rules", "Running rule engine over every file", 10)
        rule_started = time.perf_counter()
        rule_by_file = await self._run_rule_tier(root, {f.relative for f in files})
        rule_elapsed = time.perf_counter() - rule_started
        rule_total = sum(len(v) for v in rule_by_file.values())
        self._emit(
            "rules",
            f"Rule engine: {rule_total} finding(s) in {len(rule_by_file)} of "
            f"{len(files)} file(s), {rule_elapsed:.1f}s",
            25, rule_findings=rule_total, files_with_findings=len(rule_by_file)
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
                "llm",
                f"Sending {len(routed)} of {len(files)} file(s) to the LLM "
                f"(the rest carry no risk signal)",
                28, total=len(routed), current=0
            )
        elif self.options.use_llm:
            self._emit("llm", "No file cleared the risk threshold for the LLM tier", 70)
        llm_started = time.perf_counter()
        llm_by_file, tier_status = await self._run_llm_tier(routed)
        llm_elapsed = time.perf_counter() - llm_started

        self._emit("fusion", "Merging results from both tiers", 72)
        reports = self._assemble(files, rule_by_file, llm_by_file, tier_status, missing_files=missing_requested, file_hashes=file_hashes)

        found = sum(len(r.vulnerabilities) for r in reports)
        confirmed = sum(
            1 for r in reports for v in r.vulnerabilities
            if v.source == FindingSource.CONFIRMED
        )
        self._emit(
            "fusion",
            f"Merged: {found} finding(s), {confirmed} confirmed by both tiers",
            74, findings=found, confirmed=confirmed
        )
        if self.options.on_partial is not None:
            try:
                self.options.on_partial(reports)
            except Exception as e:
                logging.debug(f"Partial-result callback raised: {e}")

        verify_stats: Dict[str, Any] = {}
        if self.options.verify:
            verify_started = time.perf_counter()
            verify_stats = await self._run_verification(reports, root)
            verify_stats["verify_seconds"] = round(time.perf_counter() - verify_started, 2)

        stats = {
            "files_discovered": len(files),
            "files_requested": requested_files or [f.relative for f in files],
            "files_scanned": len(reports),
            "files_sent_to_llm": len(routed),
            "rule_tier_seconds": round(rule_elapsed, 2),
            "llm_tier_seconds": round(llm_elapsed, 2),
            "total_seconds": round(time.perf_counter() - started, 2),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "rule_error": self._rule_error,
            "file_hashes": file_hashes,
            "snapshot_hashes": file_hashes,
            **verify_stats,
        }
        logging.info(f"Scan complete: {stats}")
        total_found = sum(len(r.vulnerabilities) for r in reports)
        chains = sum(len(r.chained_vulnerabilities) for r in reports)
        self._emit(
            "done",
            f"Complete: {total_found} finding(s)"
            + (f", {chains} attack chain(s)" if chains else "")
            + f" in {stats['total_seconds']}s",
            100, findings=total_found, chains=chains
        )

        return ScanResult(reports, root, stats, file_hashes=file_hashes)

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

    async def _run_rule_tier(
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
            semgrep_target: Any = self.options.target
            if self.options.files and in_scope:
                semgrep_target = [str((root / rel).resolve()) for rel in in_scope]
            findings = await asyncio.to_thread(self.semgrep.scan, semgrep_target)
        except Exception as e:
            logging.error(f"Rule tier failed: {e}")
            self._rule_error = str(e)
            return {}

        self._file_rule_errors = self.semgrep.get_file_errors(root) if hasattr(self.semgrep, "get_file_errors") else {}
        if "" in self._file_rule_errors and not self._rule_error:
            self._rule_error = "; ".join(
                e.get("message", str(e)) if isinstance(e, dict) else str(e)
                for e in self._file_rule_errors[""]
            )

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
            found = sum(len(v) for v in results.values())
            self._emit(
                "llm",
                f"[{completed['n']}/{total}] {relative} - {found} finding(s) so far",
                percent, current=completed["n"], total=total, findings=found
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
                    self._cache_hits += 1
                    results[relative] = self.analyzer._process_ai_response(cached, relative)
                    status[relative] = "ok"
                    tick(relative)
                    return

                self._cache_misses += 1
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
                    f"[{done['n']}/{total}] {vuln.type.value} at "
                    f"{Path(vuln.location.file_path).name}:{vuln.location.start_line}"
                    f" -> {verdict.verdict}"
                    f"  ({counters['confirmed']} upheld, {counters['refuted']} refuted)",
                    75 + 23 * (done["n"] / total),
                    current=done["n"], total=total,
                    upheld=counters["confirmed"], refuted=counters["refuted"]
                )
                vuln.verification = verdict.as_dict()
                counters["tool_calls"] += verdict.tool_calls
                counters[verdict.verdict] = counters.get(verdict.verdict, 0) + 1

                if verdict.confirmed:
                    vuln.taint_path = verdict.taint_path
                    vuln.assessment_status = "supported"
                    # Corroboration by independent investigation, not by a
                    # second engine - kept below CONFIRMED-by-fusion.
                    vuln.confidence = max(vuln.confidence, 0.85)
                elif verdict.refuted:
                    vuln.assessment_status = "refuted"
                    refuted_ids.add(vuln.id)
                else:
                    vuln.assessment_status = "uncertain"

        await asyncio.gather(*(check(r, v) for r, v in candidates))

        dropped = 0
        for report in reports:
            refuted_in_report = [v for v in report.vulnerabilities if v.id in refuted_ids]
            if refuted_in_report:
                report.refuted_vulnerabilities.extend(refuted_in_report)
                report.vulnerabilities = [
                    v for v in report.vulnerabilities if v.id not in refuted_ids
                ]
                dropped += len(refuted_in_report)
                report.chained_vulnerabilities = self.analyzer._chain_vulnerabilities(
                    report.vulnerabilities
                )
                report.calculate_summary()
                report.calculate_risk_score()

        logging.info(
            "Verification: %d candidate(s) -> %d confirmed, %d refuted, %d uncertain",
            len(candidates), counters["confirmed"], counters["refuted"], counters["uncertain"]
        )

        chain_stats = await self._judge_chains(reports, root)

        return {
            "verified_candidates": len(candidates),
            "verify_confirmed": counters["confirmed"],
            "verify_refuted": counters["refuted"],
            "verify_uncertain": counters["uncertain"],
            "verify_dropped": dropped,
            "verify_tool_calls": counters["tool_calls"],
            **chain_stats,
        }

    async def _judge_chains(
        self,
        reports: List[VulnerabilityReport],
        root: Path
    ) -> Dict[str, Any]:
        """
        Ask the chain judge which proposed attack chains are real.

        The proposing heuristic knows five escalation patterns and otherwise
        reasons from locality, so it cannot tell an attack path from two
        findings that happen to sit near each other. Chains it proposes are
        kept only when a judge that read the code agrees an attacker could
        walk them.

        Args:
            reports: Reports whose chains should be judged, modified in place
            root: Scan root the judge's tools are confined to

        Returns:
            Dict[str, Any]: Chain counters for the scan statistics
        """

        from agent.chain_judge import ChainJudge

        candidates = [
            (report, chain)
            for report in reports
            for chain in report.chained_vulnerabilities
        ]
        if not candidates:
            return {}

        judge = ChainJudge(
            client=self.analyzer.ai_client.openai_client,
            model=self.analyzer.ai_client.openai_default_model,
            root=root,
            temperature=None if self.analyzer.ai_client._is_reasoning_model(
                self.analyzer.ai_client.openai_default_model
            ) else 0,
        )

        semaphore = asyncio.Semaphore(self.options.concurrency)
        upheld: Dict[int, bool] = {}

        async def check(index: int, chain: Any) -> None:
            async with semaphore:
                verdict = await judge.judge(chain)
                chain.judgement = verdict.as_dict()
                if verdict.is_real and verdict.narrative:
                    chain.attack_path = verdict.narrative
                upheld[index] = verdict.is_real

        await asyncio.gather(*(
            check(i, chain) for i, (_, chain) in enumerate(candidates)
        ))

        index = 0
        rejected = 0
        for report in reports:
            kept = []
            for chain in report.chained_vulnerabilities:
                if upheld.get(index, False):
                    kept.append(chain)
                else:
                    rejected += 1
                index += 1
            report.chained_vulnerabilities = kept

        logging.info(
            "Chain judging: %d proposed -> %d upheld, %d rejected",
            len(candidates), len(candidates) - rejected, rejected
        )
        return {
            "chains_proposed": len(candidates),
            "chains_upheld": len(candidates) - rejected,
            "chains_rejected": rejected,
        }

    def _assemble(
        self,
        files: List[DiscoveredFile],
        rule_by_file: Dict[str, List[Vulnerability]],
        llm_by_file: Dict[str, List[Vulnerability]],
        tier_status: Dict[str, str],
        missing_files: Optional[Set[str]] = None,
        file_hashes: Optional[Dict[str, str]] = None,
    ) -> List[VulnerabilityReport]:
        """
        Fuse both tiers per file and build one report per file with findings.

        Args:
            files: All discovered files
            rule_by_file: Rule-tier findings by relative path
            llm_by_file: LLM-tier findings by relative path
            tier_status: LLM tier outcome by relative path
            missing_files: Files requested but not found on disk

        Returns:
            List[VulnerabilityReport]: Reports per file
        """

        reports = []
        file_rule_errors = getattr(self, "_file_rule_errors", {})
        global_rule_err = getattr(self, "_rule_error", "")
        if not global_rule_err and file_rule_errors.get(""):
            global_rule_err = "; ".join(
                e.get("message", str(e)) if isinstance(e, dict) else str(e)
                for e in file_rule_errors[""]
            )
            self._rule_error = global_rule_err

        for item in files:
            relative = item.relative
            rule_findings = rule_by_file.get(relative, [])
            llm_findings = llm_by_file.get(relative, [])

            # Semgrep status for this specific file
            semgrep_reason = ""
            if self.semgrep is None:
                semgrep_status = "disabled"
                semgrep_reason = "Engine disabled"
            elif global_rule_err:
                semgrep_status = "failed"
                semgrep_reason = global_rule_err
            elif not self.semgrep.available:
                semgrep_status = "unavailable"
                semgrep_reason = "Semgrep binary unavailable"
            elif relative in file_rule_errors:
                semgrep_status = "parse_error"
                err_val = file_rule_errors[relative]
                if isinstance(err_val, list) and err_val:
                    err_entry = err_val[0]
                else:
                    err_entry = err_val
                semgrep_reason = err_entry.get("message", "Syntax or parse error") if isinstance(err_entry, dict) else str(err_entry)
            else:
                semgrep_status = "ok"

            # LLM status for this specific file
            llm_reason = ""
            if not self.options.use_llm:
                llm_status = "disabled"
                llm_reason = "LLM tier disabled"
            else:
                raw_llm = tier_status.get(relative, "not routed")
                if raw_llm.startswith("failed"):
                    llm_status = "failed"
                    llm_reason = raw_llm
                elif raw_llm == "not routed":
                    llm_status = "not_routed"
                    llm_reason = "File did not clear risk threshold"
                else:
                    llm_status = "completed"

            is_failed = (
                semgrep_status in ("failed", "parse_error")
                or llm_status == "failed"
            )
            is_partial = (
                semgrep_status == "unavailable"
                or (self.options.use_llm and llm_status == "not_routed")
            )
            report_status = "failed" if is_failed else ("partial" if is_partial else "completed")

            fused = fusion.fuse(rule_findings, llm_findings)
            chains = self.analyzer._chain_vulnerabilities(fused.vulnerabilities)

            tiers = {
                "semgrep": semgrep_status if not semgrep_reason else f"{semgrep_status}: {semgrep_reason}",
                "llm": llm_status if not llm_reason else f"{llm_status}: {llm_reason}",
            }

            engine_status = {
                "semgrep": {
                    "requested": self.options.use_semgrep,
                    "status": semgrep_status,
                    "reason": semgrep_reason,
                    "findings": len(rule_findings),
                },
                "llm": {
                    "requested": self.options.use_llm,
                    "status": llm_status,
                    "reason": llm_reason,
                    "findings": len(llm_findings),
                },
            }

            if file_hashes:
                for v in fused.vulnerabilities:
                    if not getattr(v, "file_hash", None):
                        v.file_hash = file_hashes.get(relative) or file_hashes.get(str(item.path.resolve()))

            report = VulnerabilityReport(
                file_name=relative,
                vulnerabilities=fused.vulnerabilities,
                chained_vulnerabilities=chains,
                timestamp=datetime.now(),
                tiers=tiers,
                status=report_status,
                engine_status=engine_status,
            )
            report.calculate_summary()
            report.calculate_risk_score()
            reports.append(report)

        for mf in sorted(missing_files or []):
            missing_report = VulnerabilityReport(
                file_name=mf,
                vulnerabilities=[],
                chained_vulnerabilities=[],
                timestamp=datetime.now(),
                tiers={"semgrep": "failed: file not found or inaccessible on disk"},
                status="failed",
                engine_status={
                    "semgrep": {
                        "requested": self.options.use_semgrep,
                        "status": "failed",
                        "reason": "Target file missing on disk or inaccessible",
                        "findings": 0,
                    },
                    "llm": {
                        "requested": self.options.use_llm,
                        "status": "not_routed",
                        "reason": "Target file missing",
                        "findings": 0,
                    },
                },
            )
            reports.append(missing_report)

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
        Includes pipeline version, provider, model, endpoint, prompt version, and content hash.
        """
        model = os.getenv("OPENAI_MODEL", "default")
        provider = os.getenv("AI_PROVIDER", "openai")
        endpoint = os.getenv("OPENAI_BASE_URL", os.getenv("AI_ENDPOINT", "default_endpoint"))
        prompt_version = "prompt_v2_structured"
        payload = f"{CACHE_VERSION}|{provider}|{model}|{endpoint}|{prompt_version}|{content}"
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
        Store an LLM analysis for reuse using atomic write.
        Never caches failed, truncated, or invalid analysis.

        Args:
            content: File contents
            analysis: Raw analysis dictionary
        """

        if not analysis or analysis.get("error") or analysis.get("truncated"):
            return

        cache_dir = self._resolve_cache_dir()
        if cache_dir is None:
            return

        path = cache_dir / f"{self._cache_key(content)}.json"
        tmp_path = path.with_suffix(f".tmp_{os.getpid()}_{uuid.uuid4().hex[:8]}")
        try:
            tmp_path.write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
            tmp_path.replace(path)
        except OSError as e:
            logging.debug(f"Could not atomically write cache entry {path}: {e}")
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass


async def scan(options: ScanOptions) -> ScanResult:
    """
    Convenience entry point for a single scan.

    Args:
        options: Scan configuration

    Returns:
        ScanResult: The aggregated outcome
    """

    return await Scanner(options).scan()
