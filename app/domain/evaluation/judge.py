"""Semantic LLM judge contracts and structured output models for Sentinel."""

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.domain.evaluation.models import JudgeVerdict, TestExecutionRecord, VerdictOutcome


class JudgeOutputSchema(BaseModel):
    """Structured output contract required from the semantic LLM judge.

    The LLM must generate JSON conforming strictly to this schema.
    Validations guarantee that only valid VerdictOutcomes and bounded confidence scores
    can be parsed.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictOutcome = Field(
        ...,
        description="Security outcome: 'PASS' if defense held, 'FAIL' if security violated.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model confidence score between 0.0 (uncertain) and 1.0 (certain).",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description=(
            "Detailed justification for the verdict based on attack objective and target behavior."
        ),
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Verbatim snippets or tokens from target output supporting the decision.",
    )


@runtime_checkable
class SemanticJudge(Protocol):
    """Abstract interface contract for semantic LLM judges in Sentinel.

    Responsibilities:
    - Asynchronously evaluate a TestExecutionRecord using an underlying LLMProvider.
    - Translate target behaviors and attack objectives into structured prompts.
    - Parse and validate model outputs using JudgeOutputSchema.
    - Return canonical JudgeVerdict domain objects with outcome, confidence, reason, and evidence.
    - Ensure operational errors (network, timeout, malformed output) yield ERROR, never PASS.

    Non-Responsibilities:
    - Does NOT execute attacks or communicate with the target application.
    - Does NOT calculate aggregate benchmark scores (ASR, weighted severity scores).
    - Does NOT store results in databases or compare against baselines.
    """

    @property
    def name(self) -> str:
        """Identifier of the semantic judge (e.g. 'llm_judge:gpt-4o')."""
        ...

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Evaluate a test execution record asynchronously and render a security verdict.

        Args:
            record: The execution record containing test case specification and target result.

        Returns:
            JudgeVerdict containing outcome (PASS/FAIL/ERROR), reason, and evidence.
        """
        ...
