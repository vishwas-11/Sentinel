"""Semantic LLM judge contracts, structured output models, and implementation for Sentinel."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.domain.evaluation.models import JudgeVerdict, TestExecutionRecord, VerdictOutcome
from app.domain.evaluation.prompts import JUDGE_SYSTEM_INSTRUCTION, build_judge_prompt

if TYPE_CHECKING:
    from app.domain.llm import LLMProvider

logger = logging.getLogger(__name__)


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


class LLMJudge:
    """Concrete semantic LLM judge implementation for Sentinel.

    Evaluates a TestExecutionRecord by constructing an adversarial-hardened prompt,
    invoking an injected LLMProvider with structured output constraints,
    and validating the generated response into a canonical JudgeVerdict.

    Enforces critical invariants:
    - Target execution errors short-circuit to VerdictOutcome.ERROR.
    - LLM provider failures (timeout, auth, network) yield VerdictOutcome.ERROR, NEVER PASS.
    - Model parsing or schema validation failures yield VerdictOutcome.ERROR, NEVER PASS.
    - Preserves provider telemetry (token counts, latency, model name) in verdict metadata.
    """

    def __init__(
        self,
        provider: LLMProvider,
        name: str | None = None,
        system_instruction: str = JUDGE_SYSTEM_INSTRUCTION,
        temperature: float = 0.0,
        max_tokens: int = 1000,
    ) -> None:
        """Initialize the LLMJudge.

        Args:
            provider: Concrete LLMProvider implementation (OpenAI, Mock, etc.).
            name: Optional descriptive judge identifier; defaults to 'llm_judge:{model_name}'.
            system_instruction: Trusted system prompt defining evaluation guidelines.
            temperature: Sampling temperature for evaluation (default 0.0 for deterministic output).
            max_tokens: Maximum tokens allowed for the evaluation reasoning.
        """
        self._provider = provider
        self._name = name or f"llm_judge:{provider.model_name}"
        self._system_instruction = system_instruction
        self._temperature = temperature
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        """Return the judge identifier."""
        return self._name

    @property
    def provider(self) -> LLMProvider:
        """Return the underlying LLM provider."""
        return self._provider

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Evaluate a TestExecutionRecord asynchronously and render a canonical JudgeVerdict.

        Args:
            record: The execution record containing TestCase and TargetResult.

        Returns:
            Canonical JudgeVerdict with outcome, confidence, reason, evidence, and telemetry.
        """
        # Invariant 1: If the target execution itself resulted in an error, return ERROR
        if record.target_result.error or record.target_result.status == "error":
            error_msg = record.target_result.error or "Target returned error status."
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=1.0,
                reason=f"Target execution failure prevented semantic evaluation: {error_msg}",
                evidence=[],
                source=self.name,
                metadata={"target_error": record.target_result.error},
            )

        # Invariant 2: Construct secure prompt with XML boundaries
        prompt = build_judge_prompt(record)

        # Invariant 3: Request structured generation via injected provider
        try:
            response = await self._provider.generate(
                prompt=prompt,
                system_instruction=self._system_instruction,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
                json_schema=JudgeOutputSchema,
            )
        except Exception as err:
            logger.error("LLM judge provider failed during generation: %s", err)
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=None,
                reason=f"LLM provider error occurred during evaluation: {err}",
                evidence=[],
                source=self.name,
                metadata={
                    "error_type": type(err).__name__,
                    "error_detail": str(err),
                },
            )

        # Invariant 4: Parse and validate structured output against JudgeOutputSchema
        try:
            parsed = JudgeOutputSchema.model_validate_json(response.content)
        except (ValidationError, ValueError) as err:
            logger.error("LLM judge failed schema validation: %s", err)
            return JudgeVerdict(
                outcome=VerdictOutcome.ERROR,
                confidence=None,
                reason=(
                    f"LLM judge generated malformed response that failed schema validation: {err}"
                ),
                evidence=[],
                source=self.name,
                metadata={
                    "raw_content": response.content,
                    "parse_error": str(err),
                    "model": self._provider.model_name,
                    "latency_ms": response.latency_ms,
                },
            )

        # Invariant 5: Return canonical JudgeVerdict preserving provider telemetry
        return JudgeVerdict(
            outcome=parsed.verdict,
            confidence=parsed.confidence,
            reason=parsed.reason,
            evidence=parsed.evidence,
            source=self.name,
            metadata={
                "model": self._provider.model_name,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "latency_ms": response.latency_ms,
            },
        )
