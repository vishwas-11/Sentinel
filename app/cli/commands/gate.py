"""Gate command handler for Sentinel CLI."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from pydantic import ValidationError

from app.cli.output import print_gate_result_text, print_json
from app.domain.gates import ComparisonEngine, SecurityGate, SecurityPolicy
from app.domain.scoring.models import ScoringReport

logger = logging.getLogger("sentinel.cli.gate")


def _load_report(path_str: str) -> ScoringReport:
    """Load and strictly validate a ScoringReport from a JSON file path."""
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Report path is not a file: {path}")

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        return ScoringReport.model_validate(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in report file '{path}': {exc}") from exc
    except ValidationError as exc:
        raise ValueError(f"Invalid ScoringReport schema in '{path}': {exc}") from exc


def handle_gate(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute the gate command."""
    # 1. Load baseline and candidate reports
    try:
        baseline_report = _load_report(args.baseline)
        candidate_report = _load_report(args.candidate)
    except Exception as exc:
        print(f"Error loading reports: {exc}", file=stderr)
        return 1

    # 2. Construct SecurityPolicy from CLI arguments
    policy = SecurityPolicy(
        max_new_critical_failures=args.max_new_critical,
        max_new_high_failures=args.max_new_high,
        max_asr_degradation=args.max_asr_degradation,
        max_security_score_drop=args.max_score_drop,
        min_evaluation_coverage=args.min_coverage,
        fail_on_removed_attacks=args.fail_on_removed,
    )

    # 3. Diff reports and evaluate gate policy
    comparison_engine = ComparisonEngine()
    comparison_report = comparison_engine.compare(baseline_report, candidate_report)

    security_gate = SecurityGate(policy=policy)
    gate_result = security_gate.evaluate(comparison_report)

    # 4. Render output according to format flag
    if args.format == "json":
        payload = {
            "passed": gate_result.passed,
            "policy": policy.model_dump(mode="json"),
            "comparison": comparison_report.model_dump(mode="json"),
            "violations": [v.model_dump(mode="json") for v in gate_result.violations],
            "warnings": [w.model_dump(mode="json") for w in gate_result.warnings],
            "summary": gate_result.summary_message,
        }
        print_json(payload, file=stdout)
    else:
        print_gate_result_text(
            result=gate_result,
            score_delta=comparison_report.score_delta,
            asr_delta=comparison_report.asr_delta,
            file=stdout,
        )

    # 5. Return process exit code (0 if passed, 1 if failed)
    return 0 if gate_result.passed else 1
