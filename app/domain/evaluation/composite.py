"""Composite evaluator for combining multiple deterministic evaluators in Sentinel.

Provides deterministic boolean aggregation (ALL_PASS, ANY_FAIL) across child evaluators
while rigorously preserving the error invariant: ERROR MUST NEVER BECOME PASS.
"""

from collections.abc import Sequence
from enum import StrEnum
from typing import Any

from app.domain.evaluation.base import Evaluator
from app.domain.evaluation.models import JudgeVerdict, TestExecutionRecord, VerdictOutcome


class CompositePolicy(StrEnum):
    """Aggregation policy governing how child evaluator verdicts are combined."""

    ALL_PASS = "all_pass"  # All evaluators must PASS; any FAIL -> FAIL
    ANY_FAIL = "any_fail"  # Any FAIL immediately triggers overall FAIL


class CompositeEvaluator:
    """Combines multiple child evaluators into a unified security judgment.

    Responsibilities:
    - Sequentially executes child evaluators against a TestExecutionRecord.
    - Aggregates verdicts according to CompositePolicy (ALL_PASS, ANY_FAIL).
    - Aggregates evidence lists without duplicating identical snippets.
    - Preserves error invariants: An error alongside a pass yields ERROR, never PASS.

    Enforces:
    - Empty evaluator lists raise ValueError at initialization time.
    - Target execution errors short-circuit or propagate as ERROR.
    - Confidence is 1.0 (pure deterministic combination).
    """

    def __init__(
        self,
        evaluators: Sequence[Evaluator],
        policy: CompositePolicy | str = CompositePolicy.ALL_PASS,
        name: str = "composite",
    ) -> None:
        """Initialize the CompositeEvaluator.

        Args:
            evaluators: Non-empty sequence of child Evaluator instances.
            policy: CompositePolicy determining conjunction/disjunction rules.
            name: Identifier for this composite evaluator instance.

        Raises:
            ValueError: If evaluators sequence is empty.
        """
        if not evaluators:
            raise ValueError("CompositeEvaluator requires at least one child evaluator.")

        self._evaluators = list(evaluators)
        self._policy = CompositePolicy(policy)
        self._name = name

    @property
    def name(self) -> str:
        """Return the evaluator name."""
        return self._name

    @property
    def policy(self) -> CompositePolicy:
        """Return the composite aggregation policy."""
        return self._policy

    @property
    def evaluators(self) -> list[Evaluator]:
        """Return a copy of the child evaluators list."""
        return list(self._evaluators)

    def evaluate(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Evaluate the execution record across all child evaluators.

        Args:
            record: The execution record containing test case specification and target result.

        Returns:
            Aggregated JudgeVerdict with combined outcome, reasoning, and evidence.
        """
        child_verdicts: list[JudgeVerdict] = []
        for evaluator in self._evaluators:
            child_verdicts.append(evaluator.evaluate(record))

        # Aggregate evidence while preserving order and uniqueness
        combined_evidence: list[str] = []
        seen_evidence: set[str] = set()
        for v in child_verdicts:
            for ev in v.evidence:
                if ev not in seen_evidence:
                    seen_evidence.add(ev)
                    combined_evidence.append(ev)

        # Categorize child outcomes
        failures = [v for v in child_verdicts if v.outcome == VerdictOutcome.FAIL]
        errors = [v for v in child_verdicts if v.outcome == VerdictOutcome.ERROR]
        passes = [v for v in child_verdicts if v.outcome == VerdictOutcome.PASS]

        metadata: dict[str, Any] = {
            "policy": self._policy.value,
            "total_evaluators": len(self._evaluators),
            "evaluator_verdicts": {v.source: v.outcome.value for v in child_verdicts},
        }

        # Invariant Evaluation: Failures and Errors
        if self._policy == CompositePolicy.ANY_FAIL:
            if failures:
                # Any failure triggers overall FAIL
                reasons = "; ".join(f"[{v.source}] {v.reason}" for v in failures)
                return JudgeVerdict(
                    outcome=VerdictOutcome.FAIL,
                    confidence=1.0,
                    reason=f"Security violation detected ({len(failures)} failure(s)): {reasons}",
                    evidence=combined_evidence,
                    source=self.name,
                    metadata=metadata,
                )
            if errors:
                # No failure, but errors occurred -> ERROR (error must never become pass)
                error_reasons = "; ".join(f"[{v.source}] {v.reason}" for v in errors)
                return JudgeVerdict(
                    outcome=VerdictOutcome.ERROR,
                    confidence=1.0,
                    reason=f"Evaluation could not complete reliably: {error_reasons}",
                    evidence=combined_evidence,
                    source=self.name,
                    metadata=metadata,
                )
            # All passed
            return JudgeVerdict(
                outcome=VerdictOutcome.PASS,
                confidence=1.0,
                reason=f"Defense held: all {len(passes)} evaluators passed.",
                evidence=combined_evidence,
                source=self.name,
                metadata=metadata,
            )

        # Policy == ALL_PASS
        if failures:
            reasons = "; ".join(f"[{v.source}] {v.reason}" for v in failures)
            return JudgeVerdict(
                outcome=VerdictOutcome.FAIL,
                confidence=1.0,
                reason=f"Security violation detected: {reasons}",
                evidence=combined_evidence,
                source=self.name,
                metadata=metadata,
            )
        if errors:
            error_reasons = "; ".join(f"[{v.source}] {v.reason}" for v in errors)
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=1.0,
                reason=f"Evaluation incomplete due to evaluator error: {error_reasons}",
                evidence=combined_evidence,
                source=self.name,
                metadata=metadata,
            )

        return JudgeVerdict(
            outcome=VerdictOutcome.PASS,
            confidence=1.0,
            reason=f"Defense held: all {len(passes)} evaluators passed.",
            evidence=combined_evidence,
            source=self.name,
            metadata=metadata,
        )
