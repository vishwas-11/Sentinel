"""Comprehensive unit and integration tests for Sentinel CLI."""

from __future__ import annotations

import json
from pathlib import Path

from app.cli.main import main
from app.cli.parser import create_parser
from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.scoring.engine import ScoringEngine
from tests.unit.test_scoring import _make_eval_result


def _save_sample_report(path: Path, items: list) -> None:
    """Helper to calculate and save a ScoringReport to disk."""
    engine = ScoringEngine()
    report = engine.calculate(items)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


# ==============================================================================
# 1. Argument Parser Tests
# ==============================================================================


def test_parser_help_exits_zero() -> None:
    """Test top-level --help produces exit code 0."""
    parser = create_parser()
    try:
        parser.parse_args(["--help"])
    except SystemExit as exc:
        assert exc.code == 0


def test_parser_subcommands_help_exit_zero() -> None:
    """Test scan, gate, version --help produce exit code 0."""
    parser = create_parser()
    for subcmd in ["scan", "gate", "version"]:
        try:
            parser.parse_args([subcmd, "--help"])
        except SystemExit as exc:
            assert exc.code == 0


def test_parser_invalid_subcommand() -> None:
    """Test unknown subcommand raises system exit."""
    parser = create_parser()
    try:
        parser.parse_args(["nonexistent"])
    except SystemExit as exc:
        assert exc.code != 0


def test_parser_gate_requires_baseline_and_candidate() -> None:
    """Test gate subcommand fails without baseline or candidate flags."""
    parser = create_parser()
    try:
        parser.parse_args(["gate", "--baseline", "base.json"])
    except SystemExit as exc:
        assert exc.code != 0


def test_parser_scan_valid_arguments() -> None:
    """Test parser parses scan arguments into proper typed values."""
    parser = create_parser()
    args = parser.parse_args(
        [
            "scan",
            "--target-url",
            "http://target.local:8001",
            "--category",
            "prompt_injection",
            "--concurrency",
            "3",
            "--reset-policy",
            "per_attack",
            "--format",
            "json",
        ]
    )
    assert args.command == "scan"
    assert args.target_url == "http://target.local:8001"
    assert args.category == "prompt_injection"
    assert args.concurrency == 3
    assert args.reset_policy == "per_attack"
    assert args.format == "json"


def test_parser_scan_mutation_arguments() -> None:
    """Test parser parses scan mutation flags and parameters."""
    parser = create_parser()
    args = parser.parse_args(
        [
            "scan",
            "--mutations",
            "--mutation-strategies",
            "base64,delimiter",
            "--mutations-per-attack",
            "2",
            "--mutation-seed",
            "42",
        ]
    )
    assert args.command == "scan"
    assert args.mutations is True
    assert args.mutation_strategies == "base64,delimiter"
    assert args.mutations_per_attack == 2
    assert args.mutation_seed == 42


def test_parser_gate_valid_arguments() -> None:
    """Test parser parses gate arguments with policy overrides."""
    parser = create_parser()
    args = parser.parse_args(
        [
            "gate",
            "--baseline",
            "base.json",
            "--candidate",
            "cand.json",
            "--max-new-critical",
            "1",
            "--max-asr-degradation",
            "0.05",
            "--fail-on-removed",
            "--format",
            "json",
        ]
    )
    assert args.command == "gate"
    assert args.baseline == "base.json"
    assert args.candidate == "cand.json"
    assert args.max_new_critical == 1
    assert args.max_asr_degradation == 0.05
    assert args.fail_on_removed is True
    assert args.format == "json"


# ==============================================================================
# 2. Version Command Tests
# ==============================================================================


def test_version_command_text(capsys) -> None:
    """Test version command in text format returns 0 and prints version."""
    exit_code = main(["version"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Sentinel v0.1.0" in captured.out
    assert "Python:" in captured.out


def test_version_command_json(capsys) -> None:
    """Test version command in json format returns valid JSON on stdout."""
    exit_code = main(["version", "--format", "json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["sentinel_version"] == "0.1.0"
    assert "python_version" in data


# ==============================================================================
# 3. Gate Command Tests
# ==============================================================================


def test_gate_command_pass(tmp_path: Path, capsys) -> None:
    """Test gate returns 0 when candidate has no regressions."""
    base_file = tmp_path / "base.json"
    cand_file = tmp_path / "cand.json"

    items = [
        _make_eval_result(
            "t1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result("t2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    _save_sample_report(base_file, items)
    _save_sample_report(cand_file, items)

    exit_code = main(["gate", "--baseline", str(base_file), "--candidate", str(cand_file)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "[PASSED]" in captured.out
    assert "All configured security policies satisfied" in captured.out


def test_gate_command_fail_on_critical_regression(tmp_path: Path, capsys) -> None:
    """Test gate returns 1 when candidate introduces a new CRITICAL failure."""
    base_file = tmp_path / "base.json"
    cand_file = tmp_path / "cand.json"

    base_items = [
        _make_eval_result(
            "t1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
        ),
    ]
    cand_items = [
        _make_eval_result(
            "t1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    _save_sample_report(base_file, base_items)
    _save_sample_report(cand_file, cand_items)

    exit_code = main(["gate", "--baseline", str(base_file), "--candidate", str(cand_file)])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "[FAILED]" in captured.out
    assert "max_new_critical_failures" in captured.out


def test_gate_command_json_output(tmp_path: Path, capsys) -> None:
    """Test gate output in JSON format."""
    base_file = tmp_path / "base.json"
    cand_file = tmp_path / "cand.json"

    items = [
        _make_eval_result("t1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
    ]
    _save_sample_report(base_file, items)
    _save_sample_report(cand_file, items)

    exit_code = main(
        ["gate", "--baseline", str(base_file), "--candidate", str(cand_file), "--format", "json"]
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["passed"] is True
    assert "policy" in data
    assert "comparison" in data


def test_gate_command_missing_file_error(capsys) -> None:
    """Test gate returns 1 and prints message to stderr on missing file."""
    exit_code = main(["gate", "--baseline", "missing_base.json", "--candidate", "cand.json"])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "Error loading reports:" in captured.err


def test_gate_command_malformed_json_error(tmp_path: Path, capsys) -> None:
    """Test gate returns 1 on malformed JSON file."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json", encoding="utf-8")

    exit_code = main(["gate", "--baseline", str(bad_file), "--candidate", str(bad_file)])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "Malformed JSON" in captured.err


# ==============================================================================
# 4. Scan Command Tests
# ==============================================================================


def test_scan_service_direct(monkeypatch) -> None:
    """Test ScanService execution pipeline with a mock target adapter."""
    from app.core.scan_service import ScanService
    from app.domain.targets import TargetAdapter, TargetResult

    class FakeAdapter(TargetAdapter):
        async def execute(self, test_case):
            return TargetResult(response_text="I cannot fulfill that request.", status="success")

    service = ScanService()
    import asyncio

    report = asyncio.run(service.run_scan(target_adapter=FakeAdapter()))
    assert report.total_attacks > 0
    assert report.evaluated_attacks > 0
    assert report.security_score is not None


def test_scan_command_target_unavailable(capsys) -> None:
    """Test sentinel scan handles unreachable target URL and exits 1."""
    # Connecting to port 1 where no server is running
    exit_code = main(["scan", "--target-url", "http://127.0.0.1:1"])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "Scan execution failed:" in captured.err
