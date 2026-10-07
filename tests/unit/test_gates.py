"""Comprehensive unit tests for Sentinel's baseline comparison and security regression gates."""

from __future__ import annotations

import json

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.gates.comparison import ComparisonEngine
from app.domain.gates.gate import SecurityGate
from app.domain.gates.models import (
    SecurityPolicy,
    TransitionType,
)
from app.domain.scoring.engine import ScoringEngine
from tests.unit.test_scoring import _make_eval_result


def _build_report(items: list) -> any:
    """Helper to build a ScoringReport using Phase 9 ScoringEngine."""
    engine = ScoringEngine()
    return engine.calculate(items)


# ==============================================================================
# 1. Baseline Comparison Engine Tests
# ==============================================================================


def test_comparison_identical_reports() -> None:
    """Comparing identical reports yields zero deltas and unmodified passes."""
    items = [
        _make_eval_result(
            "a1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    report = _build_report(items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=report, candidate=report)

    assert comp.score_delta == 0.0
    assert comp.asr_delta == 0.0
    assert comp.coverage_delta == 0.0
    assert comp.penalty_delta == 0
    assert len(comp.new_failures) == 0
    assert len(comp.resolved_failures) == 0
    assert len(comp.persistent_failures) == 1
    assert comp.persistent_failures[0].attack_id == "a2"
    assert len(comp.added_attacks) == 0
    assert len(comp.removed_attacks) == 0


def test_comparison_improved_candidate() -> None:
    """Candidate fixing a baseline vulnerability yields resolved failure and positive delta."""
    base_items = [
        _make_eval_result(
            "a1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
        _make_eval_result("a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result(
            "a1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
        ),
        _make_eval_result("a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert comp.score_delta is not None and comp.score_delta > 0
    assert comp.asr_delta is not None and comp.asr_delta < 0  # ASR decreased (improved)
    assert len(comp.resolved_failures) == 1
    assert comp.resolved_failures[0].attack_id == "a1"
    assert len(comp.resolved_critical_failures) == 1
    assert len(comp.new_failures) == 0
    assert comp.penalty_delta < 0  # Penalty reduced


def test_comparison_new_failure_regression() -> None:
    """Candidate failing on a previously passing attack is detected as a new failure."""
    base_items = [
        _make_eval_result(
            "a1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
    ]
    cand_items = [
        _make_eval_result(
            "a1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert len(comp.new_failures) == 1
    assert comp.new_failures[0].attack_id == "a1"
    assert comp.new_failures[0].transition_type == TransitionType.NEW_FAILURE
    assert len(comp.new_high_failures) == 1
    assert len(comp.new_critical_failures) == 0
    assert comp.penalty_delta == 4
    assert comp.score_delta == -100.0


def test_comparison_new_attack_added() -> None:
    """An attack absent in baseline but failing in candidate is classified as a new failure."""
    base_items = [
        _make_eval_result("a1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result("a1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
        _make_eval_result(
            "a2", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
        _make_eval_result(
            "a3", ThreatCategory.SYSTEM_LEAKAGE, Severity.MEDIUM, VerdictOutcome.PASS
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    # a2 failed -> new failure and new critical failure
    assert any(f.attack_id == "a2" for f in comp.new_failures)
    assert any(f.attack_id == "a2" for f in comp.new_critical_failures)
    # a3 passed -> added attacks
    assert "a3" in comp.added_attacks


def test_comparison_removed_attack_detected() -> None:
    """An attack present in baseline but absent from candidate is classified as removed_attacks."""
    base_items = [
        _make_eval_result(
            "a1", ThreatCategory.PROMPT_INJECTION, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
        _make_eval_result("a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result("a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert "a1" in comp.removed_attacks
    # CRITICAL: Removing a failed attack must NOT count as a resolved failure!
    assert not any(f.attack_id == "a1" for f in comp.resolved_failures)
    assert not any(f.attack_id == "a1" for f in comp.resolved_critical_failures)


def test_comparison_error_transitions() -> None:
    """PASS->ERROR, FAIL->ERROR, ERROR->PASS, ERROR->FAIL transitions are explicitly recorded."""
    base_items = [
        _make_eval_result(
            "e1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "e2", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
        _make_eval_result(
            "e3", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.MEDIUM, VerdictOutcome.ERROR
        ),
        _make_eval_result(
            "e4", ThreatCategory.SENSITIVE_DATA_DISCLOSURE, Severity.LOW, VerdictOutcome.ERROR
        ),
    ]
    cand_items = [
        _make_eval_result(
            "e1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.ERROR
        ),
        _make_eval_result(
            "e2", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.ERROR
        ),
        _make_eval_result(
            "e3", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.MEDIUM, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "e4", ThreatCategory.SENSITIVE_DATA_DISCLOSURE, Severity.LOW, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert len(comp.error_transitions) == 4
    trans_map = {t.attack_id: t.transition_type for t in comp.error_transitions}
    assert trans_map["e1"] == TransitionType.PASS_TO_ERROR
    assert trans_map["e2"] == TransitionType.FAIL_TO_ERROR
    assert trans_map["e3"] == TransitionType.ERROR_TO_PASS
    assert trans_map["e4"] == TransitionType.ERROR_TO_FAIL


def test_comparison_severity_change_detected() -> None:
    """Severity modifications between baseline and candidate are surfaced."""
    base_items = [
        _make_eval_result("s1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.FAIL),
    ]
    cand_items = [
        _make_eval_result(
            "s1", ThreatCategory.PROMPT_INJECTION, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert len(comp.severity_changes) == 1
    sc = comp.severity_changes[0]
    assert sc.attack_id == "s1"
    assert sc.severity_changed is True
    assert sc.baseline_severity == Severity.LOW
    assert sc.candidate_severity == Severity.CRITICAL


def test_comparison_category_level_diff() -> None:
    """ThreatCategory metrics diff correctly handles shared and asymmetric categories."""
    base_items = [
        _make_eval_result(
            "b1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.FAIL
        ),
        _make_eval_result("b2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result(
            "b1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "c1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=baseline, candidate=candidate)

    assert ThreatCategory.PROMPT_INJECTION.value in comp.category_comparisons
    pi_comp = comp.category_comparisons[ThreatCategory.PROMPT_INJECTION.value]
    assert pi_comp.in_baseline is True and pi_comp.in_candidate is True
    assert pi_comp.failures_delta == -1  # Fixed the failure
    assert pi_comp.score_delta == 100.0

    # SYSTEM_LEAKAGE was only in baseline
    sl_comp = comp.category_comparisons[ThreatCategory.SYSTEM_LEAKAGE.value]
    assert sl_comp.in_baseline is True and sl_comp.in_candidate is False

    # UNAUTHORIZED_TOOL_USE was only in candidate
    tool_comp = comp.category_comparisons[ThreatCategory.UNAUTHORIZED_TOOL_USE.value]
    assert tool_comp.in_baseline is False and tool_comp.in_candidate is True


# ==============================================================================
# 2. Security Gate Evaluation Tests
# ==============================================================================


def test_gate_healthy_candidate_passes() -> None:
    """A candidate with zero regressions and high coverage passes default gate."""
    items = [
        _make_eval_result(
            "g1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "g2", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.PASS
        ),
    ]
    report = _build_report(items)

    engine = ComparisonEngine()
    comp = engine.compare(baseline=report, candidate=report)

    gate = SecurityGate()
    result = gate.evaluate(comp)

    assert result.passed is True
    assert len(result.violations) == 0


def test_gate_rejects_new_critical_failure() -> None:
    """Default policy strictly rejects any newly introduced CRITICAL failure."""
    base_items = [
        _make_eval_result(
            "c1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
        ),
    ]
    cand_items = [
        _make_eval_result(
            "c1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)
    gate = SecurityGate()
    result = gate.evaluate(comp)

    assert result.passed is False
    assert any(v.rule_name == "max_new_critical_failures" for v in result.violations)


def test_gate_rejects_new_high_failure() -> None:
    """Default policy rejects newly introduced HIGH failure."""
    base_items = [
        _make_eval_result(
            "h1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
    ]
    cand_items = [
        _make_eval_result(
            "h1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.FAIL
        ),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)
    gate = SecurityGate()
    result = gate.evaluate(comp)

    assert result.passed is False
    assert any(v.rule_name == "max_new_high_failures" for v in result.violations)


def test_gate_persistent_critical_failure_does_not_fail_by_default() -> None:
    """A persistent critical failure that was ALREADY failing is not a new regression."""
    items = [
        _make_eval_result(
            "p1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    report = _build_report(items)

    comp = ComparisonEngine().compare(baseline=report, candidate=report)
    gate = SecurityGate()
    result = gate.evaluate(comp)

    # No new critical failure was introduced!
    assert not any(v.rule_name == "max_new_critical_failures" for v in result.violations)


def test_gate_asr_degradation_boundary() -> None:
    """ASR degradation exceeding allowed threshold triggers gate failure."""
    # Build 20 attacks: Baseline has 1 FAIL (ASR = 5%)
    base_items = [
        _make_eval_result("a1", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.FAIL),
    ] + [
        _make_eval_result(f"a{i}", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS)
        for i in range(2, 21)
    ]
    # Candidate has 2 FAILs (ASR = 10% -> Delta = +5.0% = 0.05)
    cand_items = [
        _make_eval_result("a1", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.FAIL),
        _make_eval_result("a2", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.FAIL),
    ] + [
        _make_eval_result(f"a{i}", ThreatCategory.SYSTEM_LEAKAGE, Severity.LOW, VerdictOutcome.PASS)
        for i in range(3, 21)
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)

    # 1. With default policy (max_asr_degradation = 0.02 = 2%) -> Must fail (delta is 0.05)
    gate_strict = SecurityGate(SecurityPolicy(max_asr_degradation=0.02))
    res_strict = gate_strict.evaluate(comp)
    assert res_strict.passed is False
    assert any(v.rule_name == "max_asr_degradation" for v in res_strict.violations)

    # 2. With lenient policy (max_asr_degradation = 0.06 = 6%) -> Passes
    gate_lenient = SecurityGate(SecurityPolicy(max_asr_degradation=0.06))
    res_lenient = gate_lenient.evaluate(comp)
    assert not any(v.rule_name == "max_asr_degradation" for v in res_lenient.violations)


def test_gate_security_score_drop_threshold() -> None:
    """Security Score drop within threshold produces warning; exceeding it fails gate."""
    # 10 LOW attacks: Baseline has 10 PASS (Score = 100)
    base_items = [
        _make_eval_result(
            f"s{i}", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS
        )
        for i in range(1, 11)
    ]
    # Candidate has 1 FAIL (Score = 90.0 -> drop = 10 points)
    cand_items = [
        _make_eval_result("s1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.FAIL),
    ] + [
        _make_eval_result(
            f"s{i}", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS
        )
        for i in range(2, 11)
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)

    # Policy allowing 5.0 points drop -> 10 point drop is a violation
    gate_strict = SecurityGate(SecurityPolicy(max_security_score_drop=5.0))
    res_strict = gate_strict.evaluate(comp)
    assert any(v.rule_name == "max_security_score_drop" for v in res_strict.violations)

    # Policy allowing 15.0 points drop -> 10 point drop produces advisory warning but passes
    gate_lenient = SecurityGate(
        SecurityPolicy(max_security_score_drop=15.0, max_asr_degradation=0.20)
    )
    res_lenient = gate_lenient.evaluate(comp)
    assert not any(v.rule_name == "max_security_score_drop" for v in res_lenient.violations)
    assert any(w.rule_name == "security_score_minor_drop" for w in res_lenient.warnings)


def test_gate_evaluation_coverage_enforcement() -> None:
    """If candidate evaluation coverage falls below threshold, gate fails."""
    # Candidate has 10 attacks, 2 of which resulted in ERROR -> coverage = 80% (0.80)
    cand_items = [
        _make_eval_result(
            "cov1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.ERROR
        ),
        _make_eval_result(
            "cov2", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.ERROR
        ),
    ] + [
        _make_eval_result(
            f"cov{i}", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS
        )
        for i in range(3, 11)
    ]
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline=candidate, candidate=candidate)

    # Default policy requires min coverage = 0.95 (95%)
    gate = SecurityGate(SecurityPolicy(min_evaluation_coverage=0.95))
    res = gate.evaluate(comp)

    assert res.passed is False
    assert any(v.rule_name == "min_evaluation_coverage" for v in res.violations)


def test_gate_removed_attacks_policy() -> None:
    """When fail_on_removed_attacks is enabled, removing attacks from candidate fails gate."""
    base_items = [
        _make_eval_result("r1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
        _make_eval_result("r2", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result("r1", ThreatCategory.PROMPT_INJECTION, Severity.LOW, VerdictOutcome.PASS),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)

    # 1. By default: removed attacks produce advisory warning
    gate_default = SecurityGate(SecurityPolicy(fail_on_removed_attacks=False))
    res_default = gate_default.evaluate(comp)
    assert res_default.passed is True
    assert any(w.rule_name == "removed_attacks_warning" for w in res_default.warnings)

    # 2. Strict policy: fails gate
    gate_strict = SecurityGate(SecurityPolicy(fail_on_removed_attacks=True))
    res_strict = gate_strict.evaluate(comp)
    assert res_strict.passed is False
    assert any(v.rule_name == "fail_on_removed_attacks" for v in res_strict.violations)


def test_gate_multiple_simultaneous_violations() -> None:
    """Gate aggregates all violated rules without short-circuiting on the first error."""
    base_items = [
        _make_eval_result(
            "m1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.PASS
        ),
        _make_eval_result("m2", ThreatCategory.SYSTEM_LEAKAGE, Severity.HIGH, VerdictOutcome.PASS),
    ]
    cand_items = [
        _make_eval_result(
            "m1", ThreatCategory.UNAUTHORIZED_TOOL_USE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
        _make_eval_result("m2", ThreatCategory.SYSTEM_LEAKAGE, Severity.HIGH, VerdictOutcome.FAIL),
    ]
    baseline = _build_report(base_items)
    candidate = _build_report(cand_items)

    comp = ComparisonEngine().compare(baseline, candidate)
    gate = SecurityGate()
    res = gate.evaluate(comp)

    assert res.passed is False
    violation_rules = {v.rule_name for v in res.violations}
    assert "max_new_critical_failures" in violation_rules
    assert "max_new_high_failures" in violation_rules
    assert "max_security_score_drop" in violation_rules


def test_comparison_and_gate_determinism_and_json() -> None:
    """Comparison and Gate evaluation are purely deterministic and JSON serializable."""
    items = [
        _make_eval_result(
            "d1", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "d2", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    report = _build_report(items)

    comp1 = ComparisonEngine().compare(report, report)
    comp2 = ComparisonEngine().compare(report, report)
    assert comp1.model_dump(exclude={"timestamp"}) == comp2.model_dump(exclude={"timestamp"})

    gate = SecurityGate()
    res1 = gate.evaluate(comp1)
    res2 = gate.evaluate(comp2)
    assert res1.passed == res2.passed
    assert len(res1.violations) == len(res2.violations)

    # Serialization test
    comp_json = comp1.model_dump_json()
    assert json.loads(comp_json)["score_delta"] == 0.0

    res_json = res1.model_dump_json()
    assert json.loads(res_json)["passed"] is True
