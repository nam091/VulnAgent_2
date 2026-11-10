import ast
import asyncio
import logging
import os
import random
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import git

from analyzer import fusion
from analyzer.prompt_manager import PromptManager
from analyzer.semgrep_runner import SemgrepRunner, SemgrepUnavailable
from evidence.safe_reader import enrich_taint_path, read_code_snippet
from context.ast_slicer import (
    ASTSlicer,
    COMPLETENESS_FAILED,
    _dotted_name,
    _is_sink_call_name,
    find_sink_anchors,
    find_call_site_sink_anchors,
    SinkAnchor,
)
from models.vulnerability import (
    CodeLocation,
    FindingSource,
    Vulnerability,
    VulnerabilityChain,
    VulnerabilityReport,
    VulnerabilitySeverity,
    VulnerabilityType
)
from utils.ai_client import AIClient
from utils.code_parser import CodeParser


class CodeAnalyzer:
    """
    CodeAnalyzer class for analyzing code for security vulnerabilities
    """

    def __init__(
        self,
        use_semgrep: Any = True,
        use_llm: bool = True,
        use_ast_slicer: bool = True,
        options: Optional[Any] = None,
    ) -> None:
        """
        Initialize the code analyzer.

        Args:
            use_semgrep: Run the rule tier alongside the LLM tier (or ScanOptions object).
            use_llm: Enable the LLM tier. When False, AIClient makes zero outbound calls.
            use_ast_slicer: Enable AST backward slicing to enrich LLM prompts with structural facts.
            options: Optional ScanOptions or configuration object.
        """
        if not isinstance(use_semgrep, bool) and hasattr(use_semgrep, "use_ast_slicer"):
            options = use_semgrep
            use_semgrep = getattr(options, "use_semgrep", True)
            use_llm = getattr(options, "use_llm", True)
            use_ast_slicer = getattr(options, "use_ast_slicer", True)
        elif options is not None:
            use_ast_slicer = getattr(options, "use_ast_slicer", use_ast_slicer)
            use_semgrep = getattr(options, "use_semgrep", use_semgrep)
            use_llm = getattr(options, "use_llm", use_llm)

        self.options = options
        self.use_ast_slicer = use_ast_slicer
        self.ast_slicer = ASTSlicer()
        self.prompt_manager = PromptManager()
        # Findings outside the declared scope are dropped before they can
        # reach fusion, chain building or the report. "full" disables it.
        self.cwe_scope = str(getattr(options, "cwe_scope", "core10") or "core10").strip().lower()

        self.ai_client = AIClient(disabled=not use_llm, cwe_scope=self.cwe_scope)
        self.code_parser = CodeParser()
        self._repo_cache: Dict[str, str] = {}
        self.semgrep = SemgrepRunner() if use_semgrep else None

        # Common attack chains based on vulnerability types
        self.attack_chains = {
            VulnerabilityType.SQL_INJECTION: [
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.BROKEN_ACCESS_CONTROL
            ],
            VulnerabilityType.CROSS_SITE_SCRIPTING: [
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.CSRF,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            ],
            VulnerabilityType.BROKEN_AUTHENTICATION: [
                VulnerabilityType.BROKEN_ACCESS_CONTROL,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                VulnerabilityType.FILE_INCLUSION,
                VulnerabilityType.REMOTE_CODE_EXECUTION,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            ],
            VulnerabilityType.INSECURE_DESERIALIZATION: [
                VulnerabilityType.REMOTE_CODE_EXECUTION,
                VulnerabilityType.OS_COMMAND_INJECTION,
                VulnerabilityType.CODE_INJECTION
            ]
        }

    async def analyze_code(self, code_content: str, filename: str) -> VulnerabilityReport:
        """
        Analyze a single file for security vulnerabilities with improved validation.
        Empty files are ignored and return an empty report.

        Args:
            code_content: The code content to analyze
            filename: The name of the file

        Returns:
            VulnerabilityReport: The vulnerability report, empty for empty files
        """

        # Check for empty file
        if not code_content or not isinstance(code_content, str) or code_content.isspace():
            logging.info(f"Skipping empty file: {filename}")
            return VulnerabilityReport(
                file_name=filename,
                vulnerabilities=[],
                chained_vulnerabilities=[],
                timestamp=datetime.now()
            )

        # Validate filename
        if not filename or not isinstance(filename, str) or filename.isspace():
            raise ValueError("Filename must be a non-empty string")

        # Parse the code to get relevant information
        try:
            parsed_code = self.code_parser.parse(code_content, filename)
        except Exception as e:
            logging.error(f"Failed to parse code: {str(e)}")
            raise ValueError(f"Invalid code content: {str(e)}")

        # Generate and validate the security analysis prompt
        analysis_prompt = self._generate_security_prompt(parsed_code, filename=filename)
        if not analysis_prompt:
            raise ValueError("Failed to generate analysis prompt")

        # Run both tiers concurrently. They must stay independent: feeding
        # the rule tier's output into the LLM prompt would remove the basis
        # for treating agreement between them as evidence.
        rule_task = asyncio.create_task(self._run_rule_tier(code_content, filename))
        tiers: Dict[str, str] = {}

        llm_vulnerabilities: List[Vulnerability] = []
        try:
            analysis_result = await self._get_analysis_with_retry(analysis_prompt, cwe_scope=self.cwe_scope)
            llm_vulnerabilities = self._process_ai_response(analysis_result, filename, code_content=code_content)
            tiers["llm"] = "ok"
        except Exception as e:
            # Degrade rather than fail: rule-tier findings are still worth
            # returning, and a scan that reports nothing because an API call
            # hiccuped is worse than one that reports less and says so.
            logging.error(f"LLM tier failed for {filename}: {e}")
            tiers["llm"] = f"failed: {e}"

        rule_vulnerabilities = await rule_task
        if self.semgrep is None:
            tiers["semgrep"] = "disabled"
        elif not self.semgrep.available:
            tiers["semgrep"] = "unavailable"
        else:
            tiers["semgrep"] = "ok"

        if tiers["llm"] != "ok" and not rule_vulnerabilities and tiers["semgrep"] != "ok":
            raise RuntimeError(f"Security analysis failed: no tier completed ({tiers})")

        # Filter both tiers before fusion so out-of-scope rules cannot enter
        # the public report or influence agreement and chain building.
        if self.cwe_scope != "full":
            from models.cwe_scope import eligible
            rule_vulnerabilities = [
                v for v in rule_vulnerabilities if eligible(v.cwe_id, scope=self.cwe_scope, exact_cwe=False)
            ]
            llm_vulnerabilities = [
                v for v in llm_vulnerabilities if eligible(v.cwe_id, scope=self.cwe_scope, exact_cwe=False)
            ]

        # Merge the two tiers and label each finding with its provenance
        fused = fusion.fuse(rule_vulnerabilities, llm_vulnerabilities)
        vulnerabilities = fused.vulnerabilities
        logging.info(f"Fusion stats for {filename}: {fused.stats}")

        # Chain vulnerabilities to find compound risks
        chained_vulnerabilities = self._chain_vulnerabilities(vulnerabilities)

        # Create and return the report
        report = VulnerabilityReport(
            file_name=filename,
            vulnerabilities=vulnerabilities,
            chained_vulnerabilities=chained_vulnerabilities,
            timestamp=datetime.now(),
            tiers=tiers
        )

        # Calculate summary statistics
        report.calculate_summary()
        report.calculate_risk_score()

        return report

    async def _run_rule_tier(self, code_content: str, filename: str) -> List[Vulnerability]:
        """
        Run the Semgrep tier without blocking the event loop.

        Semgrep needs a real path on disk, so content that does not
        correspond to an existing file (an API upload, for example) is
        written to a temporary file whose name is derived from the caller's
        filename rather than taken from it verbatim.

        Args:
            code_content: The source being analyzed
            filename: Logical name of the file

        Returns:
            List[Vulnerability]: Rule-tier findings, empty if semgrep is absent
        """

        if self.semgrep is None or not self.semgrep.available:
            if self.semgrep is not None:
                logging.warning("semgrep not available; running LLM tier only")
            return []

        existing = Path(filename)
        if existing.is_file():
            return await asyncio.to_thread(self.semgrep.scan, str(existing))

        suffix = existing.suffix or ".py"
        tmp_dir = tempfile.mkdtemp(prefix="vulnagent_")
        tmp_path = Path(tmp_dir) / f"source{suffix}"
        try:
            tmp_path.write_text(code_content, encoding="utf-8")
            findings = await asyncio.to_thread(self.semgrep.scan, str(tmp_path))
            # Report the caller's filename, not the temporary one.
            for finding in findings:
                finding.location.file_path = filename
                finding.id = ""
                finding.id = finding.fingerprint()
            return findings
        except SemgrepUnavailable as e:
            logging.warning(f"Rule tier skipped: {e}")
            return []
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
                Path(tmp_dir).rmdir()
            except OSError:
                logging.debug(f"Could not clean temp dir {tmp_dir}")

    async def _get_analysis_with_retry(
        self, prompt: str, max_retries: int = 3, cwe_scope: str = "core10"
    ) -> Dict[str, Any]:
        """
        Get AI analysis with retry logic

        Note: this method must not be wrapped in functools.lru_cache. Caching
        a coroutine function stores the coroutine object, not its result, so
        the second call would replay an already-awaited coroutine and raise.
        Result caching lives in the content-hash cache instead.

        Args:
            prompt: The analysis prompt
            max_retries: Maximum number of retry attempts
            cwe_scope: Reporting scope forwarded to the AI backend

        Returns:
            Dict[str, Any]: The analysis result

        Raises:
            RuntimeError: If all retry attempts fail
        """

        for attempt in range(max_retries):
            try:
                return await self.ai_client.analyze_security(prompt, cwe_scope=cwe_scope)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"Failed to get AI analysis after {max_retries} attempts: {str(e)}")
                err_str = str(e)
                # Parse upstream rate-limit delay if specified (e.g. 'reset after 4s' or 'retry after 5s')
                delay_match = re.search(r"(?:reset|retry)\s+after\s+(\d+(?:\.\d+)?)\s*s?", err_str, re.IGNORECASE)
                if delay_match:
                    try:
                        extracted_delay = float(delay_match.group(1))
                        backoff = max(1.0, min(60.0, round(extracted_delay + random.uniform(0.3, 1.2), 2)))
                    except (ValueError, TypeError):
                        backoff = round((2 ** attempt) * random.uniform(0.75, 1.35), 2)
                else:
                    # Full jitter exponential backoff: prevents thundering herd on concurrent 429s
                    backoff = round((2 ** attempt) * random.uniform(0.75, 1.35), 2)

                logging.warning(f"Retry {attempt + 1}/{max_retries} failed ({err_str}), waiting {backoff}s...")
                await asyncio.sleep(backoff)
                continue

    def _chain_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[VulnerabilityChain]:
        """
        Identify chains of related vulnerabilities with improved detection logic

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            List[VulnerabilityChain]: List of vulnerability chains
        """

        chains: List[VulnerabilityChain] = []
        visited: Set[str] = set()

        for vuln in vulnerabilities:
            if vuln.id in visited:
                continue

            # Find related vulnerabilities with improved relationship detection
            related_vulns = self._find_related_vulnerabilities(vuln, vulnerabilities)
            if len(related_vulns) > 1:
                chain = VulnerabilityChain(
                    vulnerabilities=related_vulns,
                    combined_severity=self._calculate_chain_severity(related_vulns),
                    attack_path=self._generate_attack_path(related_vulns),
                    likelihood=self._calculate_likelihood(related_vulns),
                    prerequisites=self._calculate_prerequisites(related_vulns),
                    mitigation_priority=self._calculate_mitigation_priority(related_vulns)
                )
                chains.append(chain)

            visited.update(v.id for v in related_vulns)

        return chains

    def _calculate_chain_severity(self, chain: List[Vulnerability]) -> VulnerabilitySeverity:
        """
        Calculate the combined severity of a vulnerability chain
        """

        # Define severity weights
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 5,
            VulnerabilitySeverity.HIGH: 4,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1
        }

        # Calculate the maximum severity in the chain
        max_severity = max(severity_weights[v.severity] for v in chain)

        # Increase severity based on chain length
        chain_multiplier = 1 + (len(chain) - 1) * 0.2

        # Calculate the weighted severity
        weighted_severity = max_severity * chain_multiplier

        # Map back to VulnerabilitySeverity enum
        if weighted_severity >= 5:
            return VulnerabilitySeverity.CRITICAL
        elif weighted_severity >= 4:
            return VulnerabilitySeverity.HIGH
        elif weighted_severity >= 3:
            return VulnerabilitySeverity.MEDIUM
        elif weighted_severity >= 2:
            return VulnerabilitySeverity.LOW

        return VulnerabilitySeverity.INFO

    async def analyze_repository(
        self,
        repo_url: str,
        branch: str = "main",
        scan_depth: int = 3
    ) -> VulnerabilityReport:
        """
        Analyze an entire repository for security vulnerabilities

        Args:
            repo_url: The URL of the repository to analyze
            branch: The branch to analyze (default: "main")
            scan_depth: The depth to scan the repository (default: 3)

        Returns:
            VulnerabilityReport: The vulnerability report
        """

        # Clone/fetch repository
        repo_path = await self._fetch_repository(repo_url, branch)

        # Get all relevant files
        files_to_analyze = self._get_repository_files(repo_path, scan_depth)

        # Analyze each file
        all_vulnerabilities = []
        for file_path in files_to_analyze:
            with open(file_path, 'r') as f:
                content = f.read()
            report = await self.analyze_code(content, str(file_path))
            all_vulnerabilities.extend(report.vulnerabilities)

        # Chain vulnerabilities across files
        chained_vulnerabilities = self._chain_vulnerabilities(all_vulnerabilities)

        return VulnerabilityReport(
            repository_url=repo_url,
            branch=branch,
            vulnerabilities=all_vulnerabilities,
            chained_vulnerabilities=chained_vulnerabilities,
            timestamp=datetime.now()
        )

    def _extract_ast_slices(self, code_content: str) -> List[Any]:
        """
        Extract intra-procedural backward slices for candidate dangerous sinks in the code.
        Scans calls, module/function-level static string assignments for sensitive keys (CWE-798),
        and decorator/access control points (CWE-287/CWE-639).

        Args:
            code_content: Source code to analyze.

        Returns:
            List of up to 10 valid SliceResult objects sorted by logical line order.
        """
        if not isinstance(code_content, str) or not code_content.strip():
            return []

        try:
            tree = ast.parse(code_content)
        except Exception:
            return []

        candidate_sinks = self.ast_slicer.find_sink_anchors(tree)

        valid_slices: List[Any] = []
        seen_slice_keys = set()

        for lineno, target_var in candidate_sinks:
            if len(valid_slices) >= 10:
                break
            try:
                res = self.ast_slicer.slice_from_sink(code_content, lineno, target_var=target_var)
                if res.completeness_status == COMPLETENESS_FAILED and target_var is not None:
                    fallback_res = self.ast_slicer.slice_from_sink(code_content, lineno, target_var=None)
                    if fallback_res.completeness_status != COMPLETENESS_FAILED:
                        res = fallback_res
                if res.completeness_status != COMPLETENESS_FAILED and res.sliced_lines:
                    slice_key = (res.target_sink_line, tuple(res.sliced_lines))
                    if slice_key not in seen_slice_keys:
                        seen_slice_keys.add(slice_key)
                        valid_slices.append(res)
            except Exception as e:
                logging.debug(f"Failed to slice candidate sink at line {lineno}: {e}")

        valid_slices.sort(key=lambda s: getattr(s, "target_sink_line", 0))
        return valid_slices[:10]

    @staticmethod
    def _extract_module_constants(code_content: str) -> List[str]:
        """
        Extract module-level constant declarations (e.g. SECRET_KEY = ..., DEBUG = ...).

        Preserves top-level configuration variables in the reference source code context.
        """
        if not isinstance(code_content, str) or not code_content.strip():
            return []
        constants: List[str] = []
        try:
            tree = ast.parse(code_content)
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            constants.append(target.id)
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name):
                        constants.append(node.target.id)
        except Exception:
            pass
        return constants

    @staticmethod
    def _generate_adaptive_reference_content(
        full_content: str,
        slices: list,
        max_full_lines: int = 500
    ) -> str:
        """Adaptive context slicing delegate to PromptManager."""
        return PromptManager._generate_adaptive_reference_content(
            full_content=full_content,
            slices=slices,
            max_full_lines=max_full_lines,
        )

    def _generate_security_prompt(
        self,
        parsed_code: Any,
        filename: str = "",
        max_full_lines: int = 500,
    ) -> str:
        """
        Generate a prompt for security analysis.

        If `use_ast_slicer` is True, extracts backward AST slices for candidate
        dangerous sinks and generates a structured Dual-Scope prompt with AST-verified
        structural facts and semantic taint reasoning rules. Falls back to a general
        security prompt if no slices are found or if AST slicing is disabled.
        """
        resolved_filename = filename or (
            parsed_code.get("filename") if isinstance(parsed_code, dict) else ""
        ) or getattr(parsed_code, "filename", "") or ""

        if self.use_ast_slicer:
            if isinstance(parsed_code, dict):
                content = parsed_code.get("content", "")
            elif isinstance(parsed_code, str):
                content = parsed_code
            else:
                content = getattr(parsed_code, "content", "")

            slices = self._extract_ast_slices(content)
            if slices:
                # Dual-Scope Prompting: Ensure the reference source code passed to
                # PromptManager retains the complete module content with all top-level
                # constant declarations (e.g., SECRET_KEY = ..., DEBUG = ...) intact.
                if isinstance(parsed_code, dict):
                    parsed_payload = dict(parsed_code)
                    if not parsed_payload.get("content"):
                        parsed_payload["content"] = content
                    if "constants" not in parsed_payload:
                        parsed_payload["constants"] = self._extract_module_constants(content)
                elif isinstance(parsed_code, str):
                    parsed_payload = {
                        "content": content,
                        "language": "python",
                        "filename": resolved_filename,
                        "constants": self._extract_module_constants(content),
                    }
                else:
                    parsed_payload = parsed_code

                return self.prompt_manager.generate_sliced_security_prompt(
                    parsed_payload,
                    slices,
                    resolved_filename,
                    max_full_lines=max_full_lines,
                )

        return self.prompt_manager.generate_general_security_prompt(
            parsed_code, resolved_filename
        )

    @staticmethod
    def _number_lines(content: str) -> str:
        """
        Prefix every source line with its line number.

        Without this the model has to count lines itself and drifts
        progressively further off as the file goes on, which makes the
        reported locations unusable for SARIF output, editor annotations and
        for matching against the rule tier during fusion.

        Args:
            content: Raw source code

        Returns:
            str: The same source with a right-aligned line number prefix
        """

        return "\n".join(
            f"{i:>4} | {line}"
            for i, line in enumerate(content.split("\n"), 1)
        )

    def _process_ai_response(
        self,
        analysis_result: Dict[str, Any],
        filename: Optional[str] = None,
        code_content: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Process and validate the AI analysis response into Vulnerability objects.

        Args:
            analysis_result: Raw analysis result from AI
            filename: File under analysis, used when the model omits the path
            code_content: Optional source code content of the analyzed file

        Returns:
            List[Vulnerability]: List of validated vulnerabilities
        """

        vulnerabilities = []
        unprocessed_types = set()

        for vuln_data in analysis_result.get('vulnerabilities', []):
            try:
                # Convert CVSS string or severity label to float score
                raw_cvss = vuln_data.get('cvss_score')
                if isinstance(raw_cvss, (int, float)):
                    vuln_data['cvss_score'] = min(10.0, max(0.0, float(raw_cvss)))
                elif isinstance(raw_cvss, str):
                    s = raw_cvss.strip()
                    if s.startswith('CVSS:'):
                        cvss_metrics = s.split('/')
                        severity_metrics = [m for m in cvss_metrics if ':' in m and m[0] in 'CIA']
                        score = 0.0
                        for metric in severity_metrics:
                            if metric.endswith(':H'):
                                score += 3.3
                            elif metric.endswith(':M'):
                                score += 2.0
                            elif metric.endswith(':L'):
                                score += 1.0
                        vuln_data['cvss_score'] = min(10.0, score)
                    elif s.lower() in ('critical', 'crit'):
                        vuln_data['cvss_score'] = 9.5
                    elif s.lower() in ('high', 'h'):
                        vuln_data['cvss_score'] = 8.0
                    elif s.lower() in ('medium', 'med', 'm'):
                        vuln_data['cvss_score'] = 5.5
                    elif s.lower() in ('low', 'l'):
                        vuln_data['cvss_score'] = 3.0
                    else:
                        try:
                            vuln_data['cvss_score'] = min(10.0, max(0.0, float(s)))
                        except (ValueError, TypeError):
                            vuln_data['cvss_score'] = 5.0
                else:
                    vuln_data['cvss_score'] = 5.0

                # Map severity strings to VulnerabilitySeverity enum
                severity_mapping = {
                    'CRITICAL': VulnerabilitySeverity.CRITICAL,
                    'HIGH': VulnerabilitySeverity.HIGH,
                    'MEDIUM': VulnerabilitySeverity.MEDIUM,
                    'LOW': VulnerabilitySeverity.LOW,
                    'INFO': VulnerabilitySeverity.INFO,
                    # Add case-insensitive variations
                    'Critical': VulnerabilitySeverity.CRITICAL,
                    'High': VulnerabilitySeverity.HIGH,
                    'Medium': VulnerabilitySeverity.MEDIUM,
                    'Low': VulnerabilitySeverity.LOW,
                    'Info': VulnerabilitySeverity.INFO
                }

                # Convert severity string to enum value
                severity_str = vuln_data.get('severity', 'MEDIUM').upper()
                severity = severity_mapping.get(severity_str, VulnerabilitySeverity.MEDIUM)

                # Handle vulnerability type mapping
                try:
                    vuln_type = VulnerabilityType(vuln_data['type'])
                except ValueError:
                    # Map common variations to standard types
                    type_mapping = {
                        'HARD_CODED_CREDENTIALS': VulnerabilityType.HARDCODED_CREDENTIALS,
                        'HARDCODED_CREDENTIAL': VulnerabilityType.HARDCODED_CREDENTIALS,
                        'WEAK_PASSWORD': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'WEAK_PASSWORDS': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'AUTH_BYPASS': VulnerabilityType.BROKEN_AUTHENTICATION,
                        'INSECURE_CONFIGURATION': VulnerabilityType.SECURITY_MISCONFIGURATION,
                        'MISCONFIGURATION': VulnerabilityType.SECURITY_MISCONFIGURATION,
                        'XSS': VulnerabilityType.CROSS_SITE_SCRIPTING,
                        'CROSS_SITE_SCRIPT': VulnerabilityType.CROSS_SITE_SCRIPTING,
                        'SQL_INJECTION_VULNERABILITY': VulnerabilityType.SQL_INJECTION,
                        'SQLI': VulnerabilityType.SQL_INJECTION,
                        'RCE': VulnerabilityType.REMOTE_CODE_EXECUTION,
                        'REMOTE_CODE_EXEC': VulnerabilityType.REMOTE_CODE_EXECUTION,
                        'COMMAND_EXEC': VulnerabilityType.OS_COMMAND_INJECTION,
                        'OS_COMMAND_EXEC': VulnerabilityType.OS_COMMAND_INJECTION,
                        'COMMAND_INJECTION': VulnerabilityType.OS_COMMAND_INJECTION,
                        'CMDI': VulnerabilityType.OS_COMMAND_INJECTION,
                        'PATH_TRAVERSAL_VULNERABILITY': VulnerabilityType.PATH_TRAVERSAL,
                        'DIRECTORY_TRAVERSAL': VulnerabilityType.PATH_TRAVERSAL,
                        'PATHTRAVER': VulnerabilityType.PATH_TRAVERSAL,
                        'CODEINJ': VulnerabilityType.CODE_INJECTION,
                        'DESERIALIZATION': VulnerabilityType.INSECURE_DESERIALIZATION,
                        'SQLI': VulnerabilityType.SQL_INJECTION,
                        'IDOR': VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                        'DIRECT_OBJECT_REFERENCE': VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                        # Four enum values carry a parenthetical suffix; models
                        # naturally emit the bare acronym or the bare name.
                        'CSRF': VulnerabilityType.CSRF,
                        'CROSS_SITE_REQUEST_FORGERY': VulnerabilityType.CSRF,
                        'SSRF': VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
                        'SERVER_SIDE_REQUEST_FORGERY': VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
                        'REMOTE_CODE_EXECUTION': VulnerabilityType.REMOTE_CODE_EXECUTION,
                        'INSECURE_DIRECT_OBJECT_REFERENCE': VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                        # Additional benchmark and CWE mappings
                        'LDAP_INJECTION': VulnerabilityType.LDAP_INJECTION,
                        'LDAPI': VulnerabilityType.LDAP_INJECTION,
                        'LDAP': VulnerabilityType.LDAP_INJECTION,
                        'XPATH_INJECTION': VulnerabilityType.XPATH_INJECTION,
                        'XPATHI': VulnerabilityType.XPATH_INJECTION,
                        'XPATH': VulnerabilityType.XPATH_INJECTION,
                        'WEAK_RANDOMNESS': VulnerabilityType.SECURE_RANDOMNESS,
                        'INSECURE_RANDOMNESS': VulnerabilityType.SECURE_RANDOMNESS,
                        'WEAKRAND': VulnerabilityType.SECURE_RANDOMNESS,
                        'WEAK_HASHING': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                        'WEAK_HASH': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                        'HASH': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                        'USE_OF_A_ONE_WAY_HASH_WITHOUT_A_SALT': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                        'USE_OF_ONE_WAY_HASH_WITHOUT_SALT': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                        'OPEN_REDIRECT': VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
                        'REDIRECT': VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
                        'UNVALIDATED_REDIRECT': VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
                        'XXE': VulnerabilityType.XML_EXTERNAL_ENTITY,
                        'XML_EXTERNAL_ENTITY_INJECTION': VulnerabilityType.XML_EXTERNAL_ENTITY,
                        'TRUST_BOUNDARY_VIOLATION': VulnerabilityType.INSUFFICIENT_INPUT_VALIDATION,
                        'INSECURE_COOKIE': VulnerabilityType.SECURE_COOKIE,
                        'INSECURE_COOKIE_FLAG': VulnerabilityType.SECURE_COOKIE,
                        'SECURECOOKIE': VulnerabilityType.SECURE_COOKIE,
                    }

                    original_type = str(vuln_data.get('type', '')).strip()
                    mapped_type = type_mapping.get(original_type)
                    if mapped_type is None:
                        mapped_type = type_mapping.get(original_type.upper())

                    # CWE-based fallback if type name is unfamiliar
                    if mapped_type is None:
                        cwe_candidate = str(vuln_data.get('cwe_id') or vuln_data.get('cwe') or original_type).upper()
                        cwe_num_match = re.search(r'CWE[-_]?(\d+)', cwe_candidate)
                        cwe_to_type = {
                            '90': VulnerabilityType.LDAP_INJECTION,
                            '643': VulnerabilityType.XPATH_INJECTION,
                            '330': VulnerabilityType.SECURE_RANDOMNESS,
                            '338': VulnerabilityType.SECURE_RANDOMNESS,
                            '328': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                            '327': VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM,
                            '601': VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS,
                            '611': VulnerabilityType.XML_EXTERNAL_ENTITY,
                            '614': VulnerabilityType.SECURE_COOKIE,
                            '94': VulnerabilityType.CODE_INJECTION,
                            '502': VulnerabilityType.INSECURE_DESERIALIZATION,
                            '22': VulnerabilityType.PATH_TRAVERSAL,
                            '78': VulnerabilityType.OS_COMMAND_INJECTION,
                            '89': VulnerabilityType.SQL_INJECTION,
                            '79': VulnerabilityType.CROSS_SITE_SCRIPTING,
                            '918': VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY,
                            '798': VulnerabilityType.HARDCODED_CREDENTIALS,
                            '352': VulnerabilityType.CSRF,
                        }
                        if cwe_num_match:
                            mapped_type = cwe_to_type.get(cwe_num_match.group(1))

                        # Keyword-based semantic mapping fallback
                        if mapped_type is None:
                            orig_lower = original_type.lower()
                            if 'cross-site scripting' in orig_lower or 'xss' in orig_lower or 'input during web page generation' in orig_lower:
                                mapped_type = VulnerabilityType.CROSS_SITE_SCRIPTING
                            elif 'sql' in orig_lower:
                                mapped_type = VulnerabilityType.SQL_INJECTION
                            elif 'command' in orig_lower or 'cmdi' in orig_lower:
                                mapped_type = VulnerabilityType.OS_COMMAND_INJECTION
                            elif 'traversal' in orig_lower or 'path' in orig_lower:
                                mapped_type = VulnerabilityType.PATH_TRAVERSAL
                            elif 'deserializ' in orig_lower:
                                mapped_type = VulnerabilityType.INSECURE_DESERIALIZATION
                            elif 'xpath' in orig_lower:
                                mapped_type = VulnerabilityType.XPATH_INJECTION
                            elif 'ldap' in orig_lower:
                                mapped_type = VulnerabilityType.LDAP_INJECTION
                            elif 'xml' in orig_lower or 'xxe' in orig_lower:
                                mapped_type = VulnerabilityType.XML_EXTERNAL_ENTITY
                            elif 'random' in orig_lower or 'prng' in orig_lower:
                                mapped_type = VulnerabilityType.SECURE_RANDOMNESS
                            elif 'hash' in orig_lower:
                                mapped_type = VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM
                            elif 'redirect' in orig_lower:
                                mapped_type = VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS
                            elif 'csrf' in orig_lower:
                                mapped_type = VulnerabilityType.CSRF
                            elif 'eval' in orig_lower or 'code injection' in orig_lower:
                                mapped_type = VulnerabilityType.CODE_INJECTION
                            elif 'trust boundary' in orig_lower or 'user-controlled key' in orig_lower:
                                mapped_type = VulnerabilityType.INSUFFICIENT_INPUT_VALIDATION

                    if mapped_type is None:
                        logging.warning(f"Unknown vulnerability type encountered: {original_type}")
                        unprocessed_types.add(original_type)
                        continue

                    vuln_type = mapped_type
                    logging.info(f"Mapped vulnerability type '{original_type}' to '{vuln_type.value}'")

                # Create CodeLocation object. The caller always knows which
                # file was submitted, so the model's own file_path is
                # discarded rather than trusted - it routinely invents a
                # plausible name such as "app.py", which would scatter
                # findings across files that do not exist and break both
                # fusion and grouping.
                def _safe_int(val, default=0):
                    try:
                        return int(val)
                    except (ValueError, TypeError):
                        return default

                location_data = vuln_data.get('location', {})
                location = CodeLocation(
                    file_path=filename or location_data.get('file_path') or '',
                    start_line=_safe_int(location_data.get('start_line'), 0),
                    end_line=_safe_int(location_data.get('end_line'), 0),
                    start_col=_safe_int(location_data.get('start_col'), 0),
                    end_col=_safe_int(location_data.get('end_col'), 0),
                    context=str(location_data.get('context', '') or '')
                )

                # Process and normalize taint path with code snippets
                raw_taint = vuln_data.get('taint_path') or []
                enriched_taint = []
                if raw_taint and isinstance(raw_taint, list):
                    target_file = filename or location.file_path or ''
                    enriched_taint = enrich_taint_path(
                        raw_taint,
                        default_file=target_file,
                        default_line=location.start_line,
                        infer_kind=True,
                        fallback_content=code_content,
                    )

                # Derive canonical CWE if missing or generic
                cwe_raw = str(vuln_data.get('cwe_id') or vuln_data.get('cwe') or '').strip()
                if not cwe_raw or cwe_raw in ('CWE-Other', 'CWE-000', 'CWE-Unknown', 'None'):
                    type_canonical_cwe = {
                        VulnerabilityType.CROSS_SITE_SCRIPTING: 'CWE-79',
                        VulnerabilityType.SQL_INJECTION: 'CWE-89',
                        VulnerabilityType.OS_COMMAND_INJECTION: 'CWE-78',
                        VulnerabilityType.CODE_INJECTION: 'CWE-94',
                        VulnerabilityType.PATH_TRAVERSAL: 'CWE-22',
                        VulnerabilityType.INSECURE_DESERIALIZATION: 'CWE-502',
                        VulnerabilityType.XML_EXTERNAL_ENTITY: 'CWE-611',
                        VulnerabilityType.XPATH_INJECTION: 'CWE-643',
                        VulnerabilityType.LDAP_INJECTION: 'CWE-90',
                        VulnerabilityType.SECURE_RANDOMNESS: 'CWE-330',
                        VulnerabilityType.USE_OF_WEAK_HASHING_ALGORITHM: 'CWE-328',
                        VulnerabilityType.UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS: 'CWE-601',
                        VulnerabilityType.SECURE_COOKIE: 'CWE-614',
                        VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY: 'CWE-918',
                        VulnerabilityType.HARDCODED_CREDENTIALS: 'CWE-798',
                        VulnerabilityType.CSRF: 'CWE-352',
                    }
                    cwe_raw = type_canonical_cwe.get(vuln_type, cwe_raw or 'CWE-Other')

                # Create Vulnerability object with validated data
                vulnerability = Vulnerability(
                    type=vuln_type,
                    severity=severity,  # Use mapped severity
                    location=location,
                    description=vuln_data.get('description', ''),
                    impact=vuln_data.get('impact', ''),
                    remediation=vuln_data.get('remediation', ''),
                    cwe_id=cwe_raw,
                    owasp_category=vuln_data.get('owasp_category', ''),
                    cvss_score=float(vuln_data.get('cvss_score', 5.0)),
                    references=vuln_data.get('references', []),
                    proof_of_concept=vuln_data.get('defect_replication_notes') or vuln_data.get('proof_of_concept', ''),
                    secure_code_example=vuln_data.get('secure_code_example', ''),
                    taint_path=enriched_taint,
                )

                vulnerabilities.append(vulnerability)

            except Exception as e:
                logging.error(f"Error processing vulnerability: {vuln_data}. Error: {str(e)}")
                continue

        # Log summary of unprocessed types at the end
        if unprocessed_types:
            logging.warning(
                "Summary of unprocessed vulnerability types:\n" +
                "\n".join(f"- {t}" for t in sorted(unprocessed_types))
            )

        if self.cwe_scope == "full":
            return vulnerabilities

        from models.cwe_scope import eligible
        kept = [v for v in vulnerabilities if eligible(v.cwe_id, scope=self.cwe_scope, exact_cwe=False)]
        dropped = len(vulnerabilities) - len(kept)
        if dropped:
            logging.debug(
                "CWE scope: dropped %d out-of-scope finding(s) for %s",
                dropped, filename or "snippet",
            )
        return kept

    def _find_related_vulnerabilities(
        self,
        source_vuln: Vulnerability,
        all_vulns: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Find vulnerabilities that could be chained together with improved detection logic.

        Args:
            source_vuln: The source vulnerability
            all_vulns: A list of all vulnerabilities

        Returns:
            List[Vulnerability]: A list of related vulnerabilities
        """

        related = [source_vuln]

        for vuln in all_vulns:
            if vuln.id != source_vuln.id:
                if self._are_vulnerabilities_related(source_vuln, vuln):
                    related.append(vuln)

        # Sort related vulnerabilities by severity
        related.sort(
            key=lambda v: {
                VulnerabilitySeverity.CRITICAL: 0,
                VulnerabilitySeverity.HIGH: 1,
                VulnerabilitySeverity.MEDIUM: 2,
                VulnerabilitySeverity.LOW: 3,
                VulnerabilitySeverity.INFO: 4
            }[v.severity]
        )

        return related

    def _are_vulnerabilities_related(
        self,
        vuln1: Vulnerability,
        vuln2: Vulnerability
    ) -> bool:
        """
        Determine if two vulnerabilities could be chained together with improved detection logic.

        Args:
            vuln1: The first vulnerability
            vuln2: The second vulnerability

        Returns:
            bool: True if vulnerabilities are related, False otherwise
        """

        # Check if vulnerabilities are in the same file or connected files
        same_file = vuln1.location.file_path == vuln2.location.file_path
        connected_files = self._are_files_connected(vuln1.location.file_path, vuln2.location.file_path)

        # Check if vulnerabilities are in a known attack chain
        in_attack_chain = (
            vuln2.type in self.attack_chains.get(vuln1.type, []) or
            vuln1.type in self.attack_chains.get(vuln2.type, [])
        )

        # Check if vulnerabilities share common attack vectors or prerequisites
        common_prerequisites = any(
            prereq in self._calculate_prerequisites([vuln2])
            for prereq in self._calculate_prerequisites([vuln1])
        )

        # Check for code proximity if in same file
        code_proximity = False
        if same_file:
            line_distance = abs(vuln1.location.start_line - vuln2.location.start_line)
            code_proximity = line_distance <= 10  # Consider vulnerabilities within 10 lines as related

        # Check for data flow relationship
        data_flow_related = self._check_data_flow_relationship(vuln1, vuln2)

        # Check for common security context
        security_context_related = self._share_security_context(vuln1, vuln2)

        # Proximity is supporting evidence, never sufficient evidence. Under
        # the original weights, same-file (1.0) plus within-ten-lines (1.0)
        # reached the threshold exactly, so any two findings that happened to
        # sit near each other were reported as an attack chain regardless of
        # what they were - a ReDoS and a missing-log-statement three lines
        # apart chained, and the same pair two hundred lines apart did not.
        # That is proximity detection wearing the label of attack-path
        # analysis. Locality now contributes at most 1.0, so a chain needs a
        # real reason: a known escalation pattern, traced dataflow, or a
        # shared security context plus shared prerequisites.
        relationship_score = sum([
            2.0 if in_attack_chain else 0.0,
            0.5 if same_file else (0.25 if connected_files else 0.0),
            1.0 if common_prerequisites else 0.0,
            0.5 if code_proximity else 0.0,
            1.5 if data_flow_related else 0.0,
            1.0 if security_context_related else 0.0
        ])

        # Consider vulnerabilities related if they score above threshold
        RELATIONSHIP_THRESHOLD = 2.0
        return relationship_score >= RELATIONSHIP_THRESHOLD

    def _are_files_connected(self, file1: str, file2: str) -> bool:
        """
        Determine if two files are connected through imports or references.

        Args:
            file1: Path to first file
            file2: Path to second file

        Returns:
            bool: True if files are connected, False otherwise
        """

        # Check if files are in same directory
        same_directory = Path(file1).parent == Path(file2).parent

        # Check if one file imports the other
        # This is a simplified check - could be enhanced with actual import analysis
        imports_connected = False
        try:
            with open(file1, 'r') as f:
                content1 = f.read()
            with open(file2, 'r') as f:
                content2 = f.read()

            file1_name = Path(file1).stem
            file2_name = Path(file2).stem

            imports_connected = (
                file2_name in content1 or
                file1_name in content2
            )
        except Exception:
            pass

        return same_directory or imports_connected

    def _check_data_flow_relationship(self, vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """
        Check whether two vulnerabilities are connected by data flow.

        When the verification agent has traced a taint path for both, that
        evidence is used directly: two defects are related when their paths
        touch the same program point, or when one's sink is the other's
        source. That is real dataflow, established by reading the code.

        Without traced paths this falls back to comparing the vocabulary of
        the two descriptions, which is a weak proxy - it matches on words in
        prose the model wrote, not on how values actually move. Run with
        --verify-findings to get the real thing.

        Args:
            vuln1: First vulnerability
            vuln2: Second vulnerability

        Returns:
            bool: True if vulnerabilities are related through data flow
        """

        if vuln1.taint_path and vuln2.taint_path:
            return self._taint_paths_intersect(vuln1, vuln2)

        # Check if vulnerabilities involve similar data patterns
        data_patterns = {
            'user_input': ['input', 'request', 'param', 'query', 'form'],
            'file_operations': ['file', 'path', 'directory', 'read', 'write'],
            'database': ['sql', 'query', 'db', 'database'],
            'authentication': ['auth', 'login', 'password', 'credential'],
            'session': ['session', 'token', 'cookie']
        }

        def get_data_categories(vuln: Vulnerability) -> Set[str]:
            categories = set()
            text = f"{vuln.description} {vuln.impact}".lower()

            for category, patterns in data_patterns.items():
                if any(pattern in text for pattern in patterns):
                    categories.add(category)
            return categories

        vuln1_categories = get_data_categories(vuln1)
        vuln2_categories = get_data_categories(vuln2)

        return bool(vuln1_categories & vuln2_categories)

    @staticmethod
    def _taint_paths_intersect(vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """
        Decide whether two traced taint paths are connected.

        Two paths are connected when they pass through the same program
        point, or when the sink of one is a point on the other - the shape
        that lets an attacker use the first defect to reach the second.

        Args:
            vuln1: First vulnerability, with a traced path
            vuln2: Second vulnerability, with a traced path

        Returns:
            bool: True when the paths touch
        """

        def points(vuln: Vulnerability) -> Set[Tuple[str, int]]:
            found = set()
            for step in vuln.taint_path:
                path = str(step.get("file") or vuln.location.file_path)
                line = step.get("line")
                if not isinstance(line, int) or line <= 0:
                    continue
                normalised = Path(path).name.lower()
                # Adjacent lines describe the same statement often enough
                # that requiring exact equality loses real connections.
                found.update((normalised, line + offset) for offset in (-1, 0, 1))
            return found

        points1, points2 = points(vuln1), points(vuln2)
        if points1 & points2:
            return True

        def sinks(vuln: Vulnerability) -> Set[Tuple[str, int]]:
            return {
                (Path(str(s.get("file") or vuln.location.file_path)).name.lower(), s["line"])
                for s in vuln.taint_path
                if str(s.get("kind", "")).lower() == "sink"
                and isinstance(s.get("line"), int) and s["line"] > 0
            }

        return bool(sinks(vuln1) & points2 or sinks(vuln2) & points1)

    def _share_security_context(self, vuln1: Vulnerability, vuln2: Vulnerability) -> bool:
        """
        Check if vulnerabilities share a common security context.

        Args:
            vuln1: First vulnerability
            vuln2: Second vulnerability

        Returns:
            bool: True if vulnerabilities share security context
        """

        # Define security contexts
        security_contexts = {
            'authentication': {
                VulnerabilityType.BROKEN_AUTHENTICATION,
                VulnerabilityType.HARDCODED_CREDENTIALS,
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE
            },
            'injection': {
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.OS_COMMAND_INJECTION,
                VulnerabilityType.CODE_INJECTION
            },
            'access_control': {
                VulnerabilityType.BROKEN_ACCESS_CONTROL,
                VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
                VulnerabilityType.CSRF
            },
            'data_exposure': {
                VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                VulnerabilityType.INFORMATION_EXPOSURE_THROUGH_QUERY_STRING,
                VulnerabilityType.EXPOSED_SENSITIVE_INFORMATION
            }
        }

        # Check if vulnerabilities belong to the same security context
        for context_types in security_contexts.values():
            if vuln1.type in context_types and vuln2.type in context_types:
                return True

        return False

    def _generate_attack_path(self, chain: List[Vulnerability]) -> str:
        """
        Generate a detailed description of the attack path based on the vulnerabilities in the chain.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            str: A detailed description of the potential attack path
        """

        if not chain:
            return "No attack path identified"

        # Sort vulnerabilities by severity to prioritize critical/high severity entries
        sorted_chain = sorted(
            chain,
            key=lambda v: {
                VulnerabilitySeverity.CRITICAL: 0,
                VulnerabilitySeverity.HIGH: 1,
                VulnerabilitySeverity.MEDIUM: 2,
                VulnerabilitySeverity.LOW: 3,
                VulnerabilitySeverity.INFO: 4
            }[v.severity]
        )

        # Build the attack path description
        path_steps = []

        for i, vuln in enumerate(sorted_chain, 1):
            # Format the location for better readability
            location = f"{vuln.location.file_path}:{vuln.location.start_line}"
            if vuln.location.end_line != vuln.location.start_line:
                location += f"-{vuln.location.end_line}"

            # Create a detailed step description
            step = (
                f"Step {i}: {vuln.type.value} ({vuln.severity.value})\n"
                f"   Location: {location}\n"
                f"   Attack Vector: {vuln.description.split('.')[0]}\n"
                f"   Potential Impact: {vuln.impact.split('.')[0]}"
            )
            path_steps.append(step)

            # Add connection description between steps
            if i < len(sorted_chain):
                next_vuln = sorted_chain[i]
                if self._are_vulnerabilities_related(vuln, next_vuln):
                    path_steps.append(
                        f"   ↓ Chain Effect: This vulnerability could facilitate or amplify the next attack step"
                    )
                else:
                    path_steps.append(
                        f"   ↓ Parallel Attack: This vulnerability can be exploited independently"
                    )

        # Add overall chain severity and prerequisites
        chain_severity = self._calculate_chain_severity(sorted_chain)
        prerequisites = self._calculate_prerequisites(sorted_chain)

        header = (
            f"Attack Chain Severity: {chain_severity.value}\n"
            f"Prerequisites: {', '.join(prerequisites)}\n"
            f"Attack Path Analysis:\n"
        )

        return header + "\n".join(path_steps)

    def _calculate_likelihood(self, chain: List[Vulnerability]) -> float:
        """
        Calculate the likelihood of a successful attack based on the vulnerabilities in the chain.
        Uses multiple factors including severity, prerequisites, and chain complexity.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            float: A value representing the likelihood of a successful attack (0.0 to 1.0)
        """

        if not chain:
            return 0.0

        # Base weights for different factors
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 1.0,
            VulnerabilitySeverity.HIGH: 0.8,
            VulnerabilitySeverity.MEDIUM: 0.6,
            VulnerabilitySeverity.LOW: 0.4,
            VulnerabilitySeverity.INFO: 0.2
        }

        # Calculate base likelihood from severity
        base_likelihood = sum(severity_weights[v.severity] for v in chain) / len(chain)

        # Adjust based on prerequisites complexity
        prereqs = self._calculate_prerequisites(chain)
        prereq_complexity = len(prereqs) * 0.1  # More prerequisites reduce likelihood

        # Adjust based on chain complexity
        chain_complexity = 1.0
        if len(chain) > 1:
            # Longer chains are harder to exploit
            chain_complexity = 1.0 - (len(chain) - 1) * 0.1

            # Check for related vulnerabilities which might make exploitation easier
            related_pairs = sum(
                1 for i, v1 in enumerate(chain[:-1])
                for v2 in chain[i+1:]
                if self._are_vulnerabilities_related(v1, v2)
            )
            if related_pairs:
                chain_complexity += related_pairs * 0.05  # Related vulns increase likelihood

        # Additional factors that affect likelihood
        factors = {
            'has_public_exploit': 1.2,  # Increase if public exploits exist
            'requires_authentication': 0.7,  # Decrease if auth required
            'requires_user_interaction': 0.8,  # Decrease if user interaction needed
            'network_accessible': 1.1  # Increase if remotely exploitable
        }

        # Apply relevant factors based on vulnerability types
        factor_multiplier = 1.0
        for vuln in chain:
            if 'CVE' in vuln.references:  # Has public exploit
                factor_multiplier *= factors['has_public_exploit']
            if 'authentication' in vuln.description.lower():
                factor_multiplier *= factors['requires_authentication']
            if 'user interaction' in vuln.description.lower():
                factor_multiplier *= factors['requires_user_interaction']
            if 'remote' in vuln.description.lower():
                factor_multiplier *= factors['network_accessible']

        # Calculate final likelihood
        likelihood = (
            base_likelihood *
            max(0.1, chain_complexity) *
            max(0.1, 1.0 - prereq_complexity) *
            factor_multiplier
        )

        # Ensure result is between 0 and 1
        return round(min(1.0, max(0.0, likelihood)), 4)

    def _calculate_prerequisites(self, chain: List[Vulnerability]) -> List[str]:
        """
        Determine the prerequisites for exploiting the vulnerabilities in the chain.
        Analyzes vulnerability types, descriptions, and relationships to identify required conditions.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            List[str]: A list of prerequisites needed to exploit the vulnerabilities
        """

        if not chain:
            return ["None"]

        prerequisites = set()

        # Common prerequisite patterns to check for
        auth_patterns = ['authentication', 'login', 'credentials', 'session']
        access_patterns = ['local access', 'physical access', 'network access', 'admin access']
        user_patterns = ['user interaction', 'user input', 'user-supplied']
        config_patterns = ['configuration', 'settings', 'environment']

        for vuln in chain:
            # Check vulnerability type specific prerequisites
            type_prereqs = {
                VulnerabilityType.SQL_INJECTION: ['Database access', 'Input injection point'],
                VulnerabilityType.CROSS_SITE_SCRIPTING: ['Active user session', 'Input reflection point'],
                VulnerabilityType.CSRF: ['Active user session', 'Predictable form structure'],
                VulnerabilityType.PATH_TRAVERSAL: ['File system access', 'Directory traversal point'],
                VulnerabilityType.OS_COMMAND_INJECTION: ['Command execution context', 'Input injection point'],
                VulnerabilityType.INSECURE_DESERIALIZATION: ['Serialized data input', 'Custom class definitions']
            }

            # Add type-specific prerequisites
            if vuln.type in type_prereqs:
                prerequisites.update(type_prereqs[vuln.type])

            # Analyze description and impact for additional prerequisites
            desc_lower = vuln.description.lower()
            impact_lower = vuln.impact.lower()

            # Check for authentication requirements
            if any(pattern in desc_lower for pattern in auth_patterns):
                prerequisites.add('Valid authentication credentials')

            # Check for access requirements
            if any(pattern in desc_lower for pattern in access_patterns):
                if 'local' in desc_lower:
                    prerequisites.add('Local system access')
                if 'physical' in desc_lower:
                    prerequisites.add('Physical device access')
                if 'network' in desc_lower:
                    prerequisites.add('Network connectivity')
                if 'admin' in desc_lower:
                    prerequisites.add('Administrative privileges')

            # Check for user interaction requirements
            if any(pattern in desc_lower for pattern in user_patterns):
                prerequisites.add('User interaction')

            # Check for configuration requirements
            if any(pattern in desc_lower for pattern in config_patterns):
                if 'debug' in desc_lower:
                    prerequisites.add('Debug mode enabled')
                if 'environment' in desc_lower:
                    prerequisites.add('Specific environment configuration')

            # Check CVSS metrics if available
            if hasattr(vuln, 'cvss_score') and vuln.cvss_score:
                if vuln.cvss_score >= 7.0:
                    prerequisites.add('No special access required (High severity)')
                elif 'network' in desc_lower:
                    prerequisites.add('Network access')

            # Add specific technical prerequisites based on vulnerability details
            if 'bypass' in impact_lower:
                prerequisites.add('Knowledge of security mechanism')
            if 'memory' in impact_lower:
                prerequisites.add('Memory manipulation capability')
            if 'race condition' in desc_lower:
                prerequisites.add('Ability to perform concurrent requests')

        # Sort prerequisites for consistent output
        return sorted(list(prerequisites))

    def _calculate_mitigation_priority(self, chain: List[Vulnerability]) -> int:
        """
        Calculate the priority for mitigating the vulnerabilities in the chain.

        Args:
            chain: List of vulnerabilities in the chain

        Returns:
            int: A priority level for mitigation (1 = highest priority, higher numbers = lower priority)
        """

        # Mapping of severity levels to numeric values
        severity_to_value = {
            VulnerabilitySeverity.CRITICAL: 1,
            VulnerabilitySeverity.HIGH: 2,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 4,
            VulnerabilitySeverity.INFO: 5
        }

        if not chain:
            return 5  # Default low priority if no vulnerabilities

        return max(severity_to_value[vuln.severity] for vuln in chain)  # Assuming lower severity value means higher priority

    async def _fetch_repository(self, repo_url: str, branch: str) -> str:
        """
        Clone or fetch the repository from the given URL.

        Args:
            repo_url: The URL of the repository to clone or fetch
            branch: The branch to check out

        Returns:
            str: The local path to the cloned or fetched repository
        """

        # Validate the repo_url format
        if not re.match(r'^https?://', repo_url):
            raise ValueError("Invalid repository URL")

        repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_url.split('/')[-1].replace('.git', ''))

        # Get system-appropriate temporary directory
        if os.name == 'nt':  # Windows
            temp_dir = os.path.join(os.environ.get('TEMP') or os.environ.get('TMP') or 'C:\\Windows\\Temp')
        else:  # Unix-like systems
            temp_dir = '/tmp'

        repo_path = os.path.normpath(os.path.join(temp_dir, repo_name))

        # Ensure the repo_path is within the temp directory
        if not repo_path.startswith(os.path.normpath(temp_dir)):
            raise ValueError("Invalid repository path")

        if os.path.exists(repo_path):
            # If the repository already exists, fetch the latest changes
            repo = git.Repo(repo_path)
            origin = repo.remotes.origin
            origin.fetch()
            repo.git.checkout(branch)
        else:
            # Clone the repository if it doesn't exist
            repo = git.Repo.clone_from(repo_url, repo_path, branch=branch)

        return repo_path

    def _get_repository_files(self, repo_path: str, scan_depth: int) -> List[str]:
        """
        Get all relevant files from the repository up to a specified scan depth.

        Args:
            repo_path: The local path to the repository
            scan_depth: The depth to scan the repository

        Returns:
            List[str]: A list of file paths to analyze
        """

        relevant_files = []
        for root, dirs, files in os.walk(repo_path):
            # Calculate the current depth
            current_depth = root.count(os.sep) - repo_path.count(os.sep)
            if current_depth < scan_depth:
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add logic to filter files if needed (e.g., only .py files)
                    if file.endswith('.py'):  # Example: only analyze Python files
                        relevant_files.append(file_path)

        return relevant_files
