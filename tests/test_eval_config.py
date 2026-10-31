"""Unit tests for eval/run_eval.py configurations and ScanOptions forwarding."""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from eval.run_eval import CONFIGURATIONS, run_vulnagent
from analyzer.scanner import ScanOptions


def test_eval_configurations_contain_ast_and_3tier():
    """Verify that CONFIGURATIONS defines ast, deep-verify and 3tier with exact specs."""
    assert "ast" in CONFIGURATIONS
    assert "3tier" in CONFIGURATIONS
    assert "deep-verify" in CONFIGURATIONS
    assert "llm" in CONFIGURATIONS

    # Check "deep-verify" config
    name_dv, kwargs_dv = CONFIGURATIONS["deep-verify"]
    assert "DeepVerify" in name_dv
    assert kwargs_dv == dict(use_llm=True, use_semgrep=True, use_ast_slicer=True, verify=True, verify_all=True, suppress_unconfirmed_rules=True, min_risk=0)

    # Check "ast" config
    name_ast, kwargs_ast = CONFIGURATIONS["ast"]
    assert "AST-Slicer" in name_ast
    assert kwargs_ast == dict(use_llm=True, use_semgrep=False, use_ast_slicer=True)

    # Check "llm" config maintains baseline without AST-slicer
    name_llm, kwargs_llm = CONFIGURATIONS["llm"]
    assert kwargs_llm == dict(use_llm=True, use_semgrep=False, use_ast_slicer=False)

    # Check "3tier" alias points to DeepVerify
    name_3tier, kwargs_3tier = CONFIGURATIONS["3tier"]
    assert "DeepVerify" in name_3tier
    assert kwargs_3tier == kwargs_dv


def test_argparse_choices_include_ast_and_3tier():
    """Verify that CLI parser allows --only ast and --only 3tier."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--only", choices=list(CONFIGURATIONS.keys()) + ["bandit"], action="append"
    )

    args_ast = parser.parse_args(["--only", "ast"])
    assert args_ast.only == ["ast"]

    args_3tier = parser.parse_args(["--only", "3tier"])
    assert args_3tier.only == ["3tier"]

    args_llm = parser.parse_args(["--only", "llm"])
    assert args_llm.only == ["llm"]


@pytest.mark.asyncio
async def test_run_vulnagent_forwards_use_ast_slicer(tmp_path: Path):
    """Verify that run_vulnagent forwards use_ast_slicer to ScanOptions."""
    captured_options = []

    class MockScanner:
        def __init__(self, options: ScanOptions):
            captured_options.append(options)

        async def scan(self):
            mock_res = MagicMock()
            mock_res.status = "completed"
            mock_res.degraded = False
            mock_res.stats = {}
            mock_res.vulnerabilities = []
            mock_res.reports = []
            return mock_res

    with patch("eval.run_eval.Scanner", MockScanner):
        # Run with use_ast_slicer=True
        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=False,
            use_ast_slicer=True,
        )
        assert len(captured_options) == 1
        assert captured_options[0].use_ast_slicer is True
        assert captured_options[0].use_llm is True
        assert captured_options[0].use_semgrep is False

        # Run with use_ast_slicer=False
        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=False,
            use_ast_slicer=False,
        )
        assert len(captured_options) == 2
        assert captured_options[1].use_ast_slicer is False


@pytest.mark.asyncio
async def test_run_vulnagent_forwards_suppress_unconfirmed_rules(tmp_path: Path):
    """Verify that run_vulnagent forwards suppress_unconfirmed_rules to ScanOptions."""
    captured_options = []

    class MockScanner:
        def __init__(self, options: ScanOptions):
            captured_options.append(options)

        async def scan(self):
            mock_res = MagicMock()
            mock_res.status = "completed"
            mock_res.degraded = False
            mock_res.stats = {}
            mock_res.vulnerabilities = []
            mock_res.reports = []
            return mock_res

    with patch("eval.run_eval.Scanner", MockScanner):
        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=True,
            suppress_unconfirmed_rules=True,
        )
        assert len(captured_options) == 1
        assert captured_options[0].suppress_unconfirmed_rules is True

        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=True,
            suppress_unconfirmed_rules=False,
        )
        assert len(captured_options) == 2
        assert captured_options[1].suppress_unconfirmed_rules is False


@pytest.mark.asyncio
async def test_run_vulnagent_forwards_min_risk(tmp_path: Path):
    """Verify that run_vulnagent forwards min_risk to ScanOptions."""
    captured_options = []

    class MockScanner:
        def __init__(self, options: ScanOptions):
            captured_options.append(options)

        async def scan(self):
            mock_res = MagicMock()
            mock_res.status = "completed"
            mock_res.degraded = False
            mock_res.stats = {}
            mock_res.vulnerabilities = []
            mock_res.reports = []
            return mock_res

    with patch("eval.run_eval.Scanner", MockScanner):
        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=True,
            min_risk=0,
        )
        assert len(captured_options) == 1
        assert captured_options[0].min_risk == 0

        await run_vulnagent(
            samples_dir=tmp_path,
            use_llm=True,
            use_semgrep=True,
            min_risk=4,
        )
        assert len(captured_options) == 2
        assert captured_options[1].min_risk == 4


def test_scan_options_verification_and_confidence_defaults():
    """Verify ScanOptions defaults for verify, verify_all, suppress_unconfirmed_rules and min_confidence."""
    # When verify=True and explicit flags omitted: verify_all and suppress_unconfirmed_rules default to True, min_risk defaults to 0
    opts_verify = ScanOptions(target=".", verify=True)
    assert opts_verify.verify is True
    assert opts_verify.verify_all is True
    assert opts_verify.suppress_unconfirmed_rules is True
    assert opts_verify.min_confidence is None
    assert opts_verify.min_risk == 0

    # Explicit override: verify_all=False
    opts_no_verify_all = ScanOptions(target=".", verify=True, verify_all=False)
    assert opts_no_verify_all.verify is True
    assert opts_no_verify_all.verify_all is False
    assert opts_no_verify_all.suppress_unconfirmed_rules is True
    assert opts_no_verify_all.min_risk == 0

    # Explicit override: suppress_unconfirmed_rules=False
    opts_no_suppress = ScanOptions(target=".", verify=True, suppress_unconfirmed_rules=False)
    assert opts_no_suppress.verify is True
    assert opts_no_suppress.verify_all is True
    assert opts_no_suppress.suppress_unconfirmed_rules is False
    assert opts_no_suppress.min_risk == 0

    # When verify=False (default): verify_all and suppress_unconfirmed_rules default to False, min_risk defaults to 3
    opts_default = ScanOptions(target=".")
    assert opts_default.verify is False
    assert opts_default.verify_all is False
    assert opts_default.suppress_unconfirmed_rules is False
    assert opts_default.min_confidence is None
    assert opts_default.min_risk == 3

    # Custom min_confidence
    opts_conf = ScanOptions(target=".", min_confidence=0.85)
    assert opts_conf.min_confidence == 0.85

    # Explicit min_risk override with verify=True
    opts_explicit_risk = ScanOptions(target=".", verify=True, min_risk=5)
    assert opts_explicit_risk.min_risk == 5


def test_cli_parser_min_confidence_and_verify_flags():
    """Verify that CLI parser correctly parses --min-confidence, --verify, and --no-verify-all."""
    from cli import build_parser

    parser = build_parser()

    # parse --min-confidence
    args = parser.parse_args(["scan", "--min-confidence", "0.75", "src"])
    assert args.min_confidence == 0.75
    assert args.verify_findings is False
    assert args.verify_all is None
    assert args.min_risk is None

    # parse --verify
    args_verify = parser.parse_args(["scan", "--verify", "src"])
    assert args_verify.verify_findings is True
    assert args_verify.verify_all is None
    assert args_verify.min_risk is None

    # parse --verify and --no-verify-all
    args_no_all = parser.parse_args(["scan", "--verify", "--no-verify-all", "src"])
    assert args_no_all.verify_findings is True
    assert args_no_all.verify_all is False
    assert args_no_all.min_risk is None

    # parse explicit --min-risk
    args_risk = parser.parse_args(["scan", "--min-risk", "2", "src"])
    assert args_risk.min_risk == 2


def test_cli_options_from_verification_and_confidence():
    """Verify that _options_from sets verification defaults and forwards min_confidence."""
    from cli import _options_from

    # When --verify or --verify-findings is on, verify_all and suppress_unconfirmed_rules auto-activate
    args_verify = argparse.Namespace(
        target="src",
        verify_findings=True,
        verify_all=None,
        suppress_unconfirmed_rules=None,
        min_confidence=0.8,
    )
    opts = _options_from(args_verify)
    assert opts.verify is True
    assert opts.verify_all is True
    assert opts.suppress_unconfirmed_rules is True
    assert opts.min_confidence == 0.8
    assert opts.min_risk == 0

    # When user actively turns off verify_all
    args_no_all = argparse.Namespace(
        target="src",
        verify_findings=True,
        verify_all=False,
        suppress_unconfirmed_rules=None,
    )
    opts_no_all = _options_from(args_no_all)
    assert opts_no_all.verify is True
    assert opts_no_all.verify_all is False
    assert opts_no_all.suppress_unconfirmed_rules is True
    assert opts_no_all.min_risk == 0

    # When verify is off
    args_off = argparse.Namespace(
        target="src",
        verify_findings=False,
    )
    opts_off = _options_from(args_off)
    assert opts_off.verify is False
    assert opts_off.verify_all is False
    assert opts_off.suppress_unconfirmed_rules is False
    assert opts_off.min_confidence is None
    assert opts_off.min_risk == 3

    # When explicit min_risk is provided
    args_custom_risk = argparse.Namespace(
        target="src",
        verify_findings=True,
        min_risk=4,
    )
    opts_custom = _options_from(args_custom_risk)
    assert opts_custom.min_risk == 4

    args_custom_zero = argparse.Namespace(
        target="src",
        verify_findings=False,
        min_risk=0,
    )
    opts_custom_zero = _options_from(args_custom_zero)
    assert opts_custom_zero.min_risk == 0


@pytest.mark.asyncio
async def test_run_scan_filters_by_min_confidence(tmp_path: Path):
    """Verify that _run_scan filters vulnerabilities by min_confidence and updates summary/risk_score."""
    from datetime import datetime
    from unittest.mock import AsyncMock
    from cli import _run_scan, EXIT_CLEAN
    from conftest import make_vuln
    from models.vulnerability import VulnerabilityReport, VulnerabilitySeverity
    from analyzer.scanner import ScanResult

    v_high_conf = make_vuln(file_path="app.py", start_line=10, severity=VulnerabilitySeverity.HIGH)
    v_high_conf.confidence = 0.9

    v_low_conf = make_vuln(file_path="app.py", start_line=20, severity=VulnerabilitySeverity.MEDIUM)
    v_low_conf.confidence = 0.5

    report = VulnerabilityReport(
        file_name="app.py",
        vulnerabilities=[v_high_conf, v_low_conf],
        chained_vulnerabilities=[],
        status="completed",
        timestamp=datetime.now(),
    )
    report.calculate_summary()
    report.calculate_risk_score()
    initial_risk = report.risk_score
    assert report.summary["total"] == 2

    fake_result = ScanResult([report], tmp_path, {})

    target_file = tmp_path / "app.py"
    target_file.write_text("print('hello')", encoding="utf-8")

    args = argparse.Namespace(
        command="scan",
        target=str(target_file),
        no_llm=False,
        no_semgrep=False,
        no_suppressions=True,
        baseline=None,
        fail_on_new=False,
        fail_on="never",
        confirmed_only=False,
        format="json",
        output=None,
        verbose=False,
        min_confidence=0.75,
    )

    with patch("cli.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = fake_result
        exit_code = await _run_scan(args)
        assert exit_code == EXIT_CLEAN

    # Only v_high_conf should remain
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0] is v_high_conf
    assert report.summary["total"] == 1
    assert report.summary["high"] == 1
    assert report.summary["medium"] == 0
    assert report.risk_score < initial_risk


