"""Hybrid evaluation orchestrator combining deterministic and semantic evaluators.

Enforces the Sentinel hybrid evaluation strategy:
1. Deterministic evaluators run first (fast, zero-cost, objective).
2. If any deterministic evaluator reports FAIL:
   Short-circuit immediately. Verdict is FAIL. LLM judge is SKIPPED.
3. If any deterministic evaluator reports ERROR (and none FAIL):
   Short-circuit immediately. Verdict is ERROR. LLM judge is SKIPPED.
4. If and only if all deterministic evaluators PASS:
   Invoke the semantic LLM judge for deep contextual reasoning.
5. All evidence (deterministic and semantic) is preserved in the canonical JudgeVerdict.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from app.domain.evaluation.models import (
    EvaluationResult,
    JudgeVerdict,
    TestExecutionRecord,
    VerdictOutcome,
)

if TYPE_CHECKING:
    from app.domain.evaluation.base import Evaluator
    from app.domain.evaluation.judge import SemanticJudge


class HybridEvaluationOrchestrator:
    """Orchestrates deterministic evaluators and semantic LLM judges.

    Responsibilities:
    - Sequentially executes synchronous deterministic evaluators.
    - Applies fail-fast short-circuiting: deterministic FAIL or ERROR skips LLM invocation.
    - Conditionally invokes async SemanticJudge when deterministic checks pass.
    - Aggregates evidence and telemetry (latencies, token consumption, skip status).
    - Preserves invariants: ERROR never becomes PASS; deterministic FAIL is never overridden.
    """

    def __init__(
        self,
        deterministic_evaluators: Sequence[Evaluator] | None = None,
        semantic_judge: SemanticJudge | None = None,
        name: str = "hybrid_orchestrator",
        version: str = "1.0.0",
    ) -> None:
        """Initialize the HybridEvaluationOrchestrator.

        Args:
            deterministic_evaluators: Optional sequence of synchronous deterministic evaluators.
            semantic_judge: Optional asynchronous semantic judge (e.g. LLMJudge).
            name: Identifier for this orchestrator instance.
            version: Version string for evaluation provenance tracking.
        """
        self._deterministic_evaluators: list[Evaluator] = (
            list(deterministic_evaluators) if deterministic_evaluators is not None else []
        )
        self._semantic_judge = semantic_judge
        self._name = name
        self._version = version

    @property
    def name(self) -> str:
        """Return orchestrator identifier."""
        return self._name

    @property
    def version(self) -> str:
        """Return orchestrator version."""
        return self._version

    @property
    def deterministic_evaluators(self) -> list[Evaluator]:
        """Return copy of deterministic evaluators list."""
        return list(self._deterministic_evaluators)

    @property
    def semantic_judge(self) -> SemanticJudge | None:
        """Return the configured semantic judge, if any."""
        return self._semantic_judge

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Evaluate a test execution record and render the final canonical JudgeVerdict.

        Args:
            record: The TestExecutionRecord containing TestCase and TargetResult.

        Returns:
            Canonical JudgeVerdict with aggregate outcome, confidence, reason, evidence,
            and cost/latency telemetry.
        """
        start_time = time.perf_counter()

        # Invariant 0: If target execution failed, short-circuit immediately
        if record.target_result.error or record.target_result.status == "error":
            error_msg = record.target_result.error or "Target returned error status."
            total_latency_ms = (time.perf_counter() - start_time) * 1000
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=None,
                reason=f"Target execution failure prevented evaluation: {error_msg}",
                evidence=[],
                source=self.name,
                metadata={
                    "stage": "pre_check",
                    "llm_skipped": True,
                    "skip_reason": "target_execution_error",
                    "target_error": record.target_result.error,
                    "target_status": record.target_result.status,
                    "total_latency_ms": round(total_latency_ms, 2),
                },
            )

        deterministic_start = time.perf_counter()

        # Step 1: Run deterministic evaluators synchronously
        deterministic_verdicts: list[JudgeVerdict] = []
        combined_evidence: list[str] = []
        seen_evidence: set[str] = set()

        for evaluator in self._deterministic_evaluators:
            verdict = evaluator.evaluate(record)
            deterministic_verdicts.append(verdict)
            for ev in verdict.evidence:
                if ev not in seen_evidence:
                    seen_evidence.add(ev)
                    combined_evidence.append(ev)

        deterministic_latency_ms = (time.perf_counter() - deterministic_start) * 1000

        deterministic_telemetry: list[dict[str, Any]] = [
            {
                "evaluator": v.source,
                "outcome": v.outcome.value,
                "reason": v.reason,
                "evidence_count": len(v.evidence),
            }
            for v in deterministic_verdicts
        ]

        # Case 1: Any deterministic evaluator reports FAIL -> Short-circuit immediately
        failing_verdicts = [v for v in deterministic_verdicts if v.outcome == VerdictOutcome.FAIL]
        if failing_verdicts:
            reasons = "; ".join(f"[{v.source}] {v.reason}" for v in failing_verdicts)
            total_latency_ms = (time.perf_counter() - start_time) * 1000
            return JudgeVerdict(
                outcome=VerdictOutcome.FAIL,
                confidence=1.0,
                reason=f"Deterministic evaluation failed: {reasons}",
                evidence=combined_evidence,
                source=self.name,
                metadata={
                    "stage": "deterministic",
                    "llm_skipped": True,
                    "skip_reason": "deterministic_fail",
                    "deterministic_evaluations": deterministic_telemetry,
                    "deterministic_latency_ms": round(deterministic_latency_ms, 2),
                    "total_latency_ms": round(total_latency_ms, 2),
                },
            )

        # Case 2: Any deterministic evaluator reports ERROR (and none FAIL) -> Short-circuit
        error_verdicts = [v for v in deterministic_verdicts if v.outcome == VerdictOutcome.ERROR]
        if error_verdicts:
            reasons = "; ".join(f"[{v.source}] {v.reason}" for v in error_verdicts)
            total_latency_ms = (time.perf_counter() - start_time) * 1000
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=None,
                reason=f"Deterministic evaluation encountered error: {reasons}",
                evidence=combined_evidence,
                source=self.name,
                metadata={
                    "stage": "deterministic",
                    "llm_skipped": True,
                    "skip_reason": "deterministic_error",
                    "deterministic_evaluations": deterministic_telemetry,
                    "deterministic_latency_ms": round(deterministic_latency_ms, 2),
                    "total_latency_ms": round(total_latency_ms, 2),
                },
            )

        # Case 3: All deterministic evaluators PASS (or none configured)
        # If no semantic judge is configured, deterministic PASS is final
        if self._semantic_judge is None:
            total_latency_ms = (time.perf_counter() - start_time) * 1000
            return JudgeVerdict(
                outcome=VerdictOutcome.PASS,
                confidence=1.0,
                reason=(
                    "All deterministic evaluators passed; no semantic judge configured."
                    if self._deterministic_evaluators
                    else "No evaluators configured; default PASS."
                ),
                evidence=combined_evidence,
                source=self.name,
                metadata={
                    "stage": "deterministic",
                    "llm_skipped": True,
                    "skip_reason": "no_semantic_judge_configured",
                    "deterministic_evaluations": deterministic_telemetry,
                    "deterministic_latency_ms": round(deterministic_latency_ms, 2),
                    "total_latency_ms": round(total_latency_ms, 2),
                },
            )

        # Step 2: Invoke async SemanticJudge
        semantic_start = time.perf_counter()
        semantic_verdict = await self._semantic_judge.judge(record)
        semantic_latency_ms = (time.perf_counter() - semantic_start) * 1000

        # Preserve semantic evidence alongside deterministic evidence
        for ev in semantic_verdict.evidence:
            if ev not in seen_evidence:
                seen_evidence.add(ev)
                combined_evidence.append(ev)

        # Format combined reason
        if semantic_verdict.outcome == VerdictOutcome.FAIL:
            final_reason = (
                f"Deterministic checks passed, but semantic judge detected violation: "
                f"{semantic_verdict.reason}"
            )
        elif semantic_verdict.outcome == VerdictOutcome.PASS:
            final_reason = (
                f"Deterministic checks passed. Semantic judge confirmed defense: "
                f"{semantic_verdict.reason}"
            )
        else:
            final_reason = f"Semantic judge encountered error: {semantic_verdict.reason}"

        total_latency_ms = (time.perf_counter() - start_time) * 1000

        return JudgeVerdict(
            outcome=semantic_verdict.outcome,
            confidence=semantic_verdict.confidence,
            reason=final_reason,
            evidence=combined_evidence,
            source=self.name,
            metadata={
                "stage": "semantic",
                "llm_skipped": False,
                "skip_reason": None,
                "deterministic_evaluations": deterministic_telemetry,
                "semantic_evaluation": {
                    "source": semantic_verdict.source,
                    "outcome": semantic_verdict.outcome.value,
                    "reason": semantic_verdict.reason,
                    "metadata": semantic_verdict.metadata,
                },
                "deterministic_latency_ms": round(deterministic_latency_ms, 2),
                "semantic_latency_ms": round(semantic_latency_ms, 2),
                "total_latency_ms": round(total_latency_ms, 2),
                "input_tokens": semantic_verdict.metadata.get("input_tokens"),
                "output_tokens": semantic_verdict.metadata.get("output_tokens"),
            },
        )

    async def evaluate(self, record: TestExecutionRecord) -> EvaluationResult:
        """Evaluate a test execution record and return a full EvaluationResult record.

        Args:
            record: The TestExecutionRecord containing TestCase and TargetResult.

        Returns:
            EvaluationResult binding test case, target execution, judgment, and provenance.
        """
        verdict = await self.judge(record)
        return EvaluationResult(
            test_case=record.test_case,
            target_result=record.target_result,
            verdict=verdict,
            evaluator_name=self.name,
            evaluator_version=self.version,
            timestamp=datetime.now(UTC),
        )
