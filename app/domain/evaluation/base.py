"""Base contracts and protocols for Sentinel evaluators."""

from typing import Protocol, runtime_checkable

from app.domain.evaluation.models import JudgeVerdict, TestExecutionRecord


@runtime_checkable
class Evaluator(Protocol):
    """Abstract interface contract for all Sentinel evaluators.

    Responsibilities:
    - Pure in-memory inspection of a TestExecutionRecord.
    - Synchronous, deterministic, and free of network I/O.
    - Returns a structured JudgeVerdict with explicit outcome, reason, and evidence.
    - Enforces the invariant: Target or evaluation errors must never yield PASS.

    Non-Responsibilities:
    - Does NOT execute attacks or communicate over HTTP.
    - Does NOT calculate aggregate benchmark scores (ASR, weighted scores).
    - Does NOT store results in databases or compare against baselines.
    """

    @property
    def name(self) -> str:
        """Unique identifier of the evaluator (e.g. 'exact_match', 'tool_call')."""
        ...

    def evaluate(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Evaluate a test execution record and render a security verdict.

        Args:
            record: The execution record containing both TestCase and TargetResult.

        Returns:
            JudgeVerdict containing outcome (PASS/FAIL/ERROR), reason, and evidence.
        """
        ...
