"""Generate sample baseline and candidate reports for manual CLI testing."""

from pathlib import Path

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.scoring.engine import ScoringEngine
from tests.unit.test_scoring import _make_eval_result

ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

engine = ScoringEngine()

# Baseline: 1 failure (T1-001 HIGH FAIL)
baseline_items = [
    _make_eval_result(
        "T1-001", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.FAIL
    ),
    _make_eval_result(
        "T2-001", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T3-001", ThreatCategory.SENSITIVE_DATA_DISCLOSURE, Severity.MEDIUM, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T4-001", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T5-001", ThreatCategory.IMPROPER_OUTPUT_HANDLING, Severity.LOW, VerdictOutcome.PASS
    ),
]
baseline_report = engine.calculate(baseline_items)
(ARTIFACTS_DIR / "baseline.json").write_text(
    baseline_report.model_dump_json(indent=2), encoding="utf-8"
)

# Candidate PASS: T1-001 resolved, zero new failures
passing_candidate_items = [
    _make_eval_result(
        "T1-001", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T2-001", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T3-001", ThreatCategory.SENSITIVE_DATA_DISCLOSURE, Severity.MEDIUM, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T4-001", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T5-001", ThreatCategory.IMPROPER_OUTPUT_HANDLING, Severity.LOW, VerdictOutcome.PASS
    ),
]
passing_candidate_report = engine.calculate(passing_candidate_items)
(ARTIFACTS_DIR / "candidate_pass.json").write_text(
    passing_candidate_report.model_dump_json(indent=2), encoding="utf-8"
)

# Candidate FAIL: Introduces a new CRITICAL failure (T4-001 CRITICAL FAIL)
failing_candidate_items = [
    _make_eval_result(
        "T1-001", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.FAIL
    ),
    _make_eval_result(
        "T2-001", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T3-001", ThreatCategory.SENSITIVE_DATA_DISCLOSURE, Severity.MEDIUM, VerdictOutcome.PASS
    ),
    _make_eval_result(
        "T4-001", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
    ),
    _make_eval_result(
        "T5-001", ThreatCategory.IMPROPER_OUTPUT_HANDLING, Severity.LOW, VerdictOutcome.PASS
    ),
]
failing_candidate_report = engine.calculate(failing_candidate_items)
(ARTIFACTS_DIR / "candidate_fail.json").write_text(
    failing_candidate_report.model_dump_json(indent=2), encoding="utf-8"
)

print(f"Generated artifacts in {ARTIFACTS_DIR}")
