"""Unit tests for CompositeEvaluator."""

import pytest

from app.domain.attacks import AttackPayload, TestCase, ThreatCategory
from app.domain.evaluation import (
    CompositeEvaluator,
    CompositePolicy,
    ExactMatchEvaluator,
    RegexEvaluator,
    TestExecutionRecord,
    ToolCallEvaluator,
    VerdictOutcome,
)
from app.domain.targets import ObservableToolCall, TargetResult


def create_record(
    response: str = "Safe response",
    tool_calls: list[ObservableToolCall] | None = None,
    status: str = "success",
    error: str | None = None,
) -> TestExecutionRecord:
    """Helper fixture to create test execution records."""
    attack = AttackPayload(
        id="T1-001",
        category=ThreatCategory.PROMPT_INJECTION,
        prompt="Test prompt",
        objective="Test composite",
    )
    test_case = TestCase(id="tc_comp", attack=attack, session_id="sess_001")
    target_result = TargetResult(
        response=response,
        status=status,
        tool_calls=tool_calls or [],
        error=error,
    )
    return TestExecutionRecord(test_case=test_case, target_result=target_result)


def test_composite_all_pass_success() -> None:
    """Verify that when all child evaluators pass, ALL_PASS yields PASS."""
    e1 = ExactMatchEvaluator(pattern="CANARY")
    e2 = ToolCallEvaluator(tool_name="initiate_refund")
    composite = CompositeEvaluator([e1, e2], policy=CompositePolicy.ALL_PASS)

    record = create_record(response="Safe response without canary.", tool_calls=[])
    verdict = composite.evaluate(record)

    assert verdict.outcome == VerdictOutcome.PASS
    assert verdict.confidence == 1.0
    assert "all 2 evaluators passed" in verdict.reason


def test_composite_all_pass_single_failure() -> None:
    """Verify that if one evaluator fails under ALL_PASS, the result is FAIL."""
    e1 = ExactMatchEvaluator(pattern="CANARY")
    e2 = ToolCallEvaluator(tool_name="initiate_refund")
    composite = CompositeEvaluator([e1, e2], policy=CompositePolicy.ALL_PASS)

    # Response leaks canary (e1 fails, e2 passes)
    record = create_record(response="Leaked CANARY string", tool_calls=[])
    verdict = composite.evaluate(record)

    assert verdict.outcome == VerdictOutcome.FAIL
    assert "CANARY" in verdict.evidence
    assert "[exact_match]" in verdict.reason


def test_composite_any_fail_policy() -> None:
    """Verify that ANY_FAIL yields FAIL as soon as one evaluator detects a breach."""
    e1 = ExactMatchEvaluator(pattern="CANARY")
    e2 = RegexEvaluator(pattern=r"\b\d{3}-\d{2}-\d{4}\b")
    composite = CompositeEvaluator([e1, e2], policy=CompositePolicy.ANY_FAIL)

    # SSN present, but CANARY absent
    record = create_record(response="User SSN: 000-11-2222")
    verdict = composite.evaluate(record)

    assert verdict.outcome == VerdictOutcome.FAIL
    assert "000-11-2222" in verdict.evidence


def test_composite_error_invariance_propagation() -> None:
    """Verify the invariant: An ERROR mixed with PASS yields ERROR, never PASS."""
    e1 = ExactMatchEvaluator(pattern="CANARY")
    e2 = ToolCallEvaluator(tool_name="initiate_refund")
    composite = CompositeEvaluator([e1, e2], policy=CompositePolicy.ALL_PASS)

    record_error = create_record(status="error", error="Gateway timeout")
    verdict = composite.evaluate(record_error)

    assert verdict.outcome == VerdictOutcome.ERROR
    assert "target_error: Gateway timeout" in verdict.evidence[0]


def test_composite_evidence_aggregation_and_deduplication() -> None:
    """Verify evidence lists from multiple evaluators are merged and deduplicated."""
    e1 = ExactMatchEvaluator(pattern="CANARY")
    e2 = RegexEvaluator(pattern=r"CANARY")
    composite = CompositeEvaluator([e1, e2], policy=CompositePolicy.ANY_FAIL)

    record = create_record(response="Leaked CANARY here")
    verdict = composite.evaluate(record)

    assert verdict.outcome == VerdictOutcome.FAIL
    # Both evaluators extract "CANARY", composite should deduplicate
    assert verdict.evidence == ["CANARY"]


def test_composite_empty_evaluators_raises_error() -> None:
    """Verify empty evaluator sequence raises ValueError."""
    with pytest.raises(ValueError, match="requires at least one child evaluator"):
        CompositeEvaluator([])
