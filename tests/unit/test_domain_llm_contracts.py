"""Unit tests for Phase 7 domain LLM contracts and structured output models."""

import pytest
from pydantic import BaseModel, ValidationError

from app.domain.evaluation import (
    JudgeOutputSchema,
    JudgeVerdict,
    SemanticJudge,
    TestExecutionRecord,
    VerdictOutcome,
)
from app.domain.llm import LLMProvider, LLMResponse


# -------------------------------------------------------------
# Fakes for Protocol Testing
# -------------------------------------------------------------
class CompliantLLMProvider:
    """Compliant implementation of LLMProvider protocol for testing."""

    @property
    def model_name(self) -> str:
        return "mock-model-v1"

    async def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1000,
        json_schema: type[BaseModel] | None = None,
    ) -> LLMResponse:
        return LLMResponse(content='{"verdict": "PASS"}')


class IncompleteLLMProvider:
    """Non-compliant class missing generate()."""

    @property
    def model_name(self) -> str:
        return "incomplete"


class CompliantSemanticJudge:
    """Compliant implementation of SemanticJudge protocol for testing."""

    @property
    def name(self) -> str:
        return "llm_judge:test"

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        return JudgeVerdict(
            outcome=VerdictOutcome.PASS,
            confidence=0.95,
            reason="Model safely refused the adversarial request.",
            evidence=["Refusal verified"],
            source=self.name,
        )


class IncompleteSemanticJudge:
    """Non-compliant class missing judge()."""

    @property
    def name(self) -> str:
        return "incomplete"


# -------------------------------------------------------------
# Tests for LLMResponse
# -------------------------------------------------------------
def test_llm_response_valid_all_fields() -> None:
    """Verify LLMResponse construction with all fields specified."""
    response = LLMResponse(
        content='{"verdict": "PASS", "confidence": 0.9}',
        raw_response={"id": "chatcmpl_123", "model": "gpt-4o"},
        input_tokens=150,
        output_tokens=45,
        latency_ms=342.5,
    )
    assert response.content == '{"verdict": "PASS", "confidence": 0.9}'
    assert response.raw_response == {"id": "chatcmpl_123", "model": "gpt-4o"}
    assert response.input_tokens == 150
    assert response.output_tokens == 45
    assert response.latency_ms == 342.5


def test_llm_response_defaults() -> None:
    """Verify LLMResponse default field values."""
    response = LLMResponse(content="Hello world")
    assert response.content == "Hello world"
    assert response.raw_response is None
    assert response.input_tokens is None
    assert response.output_tokens is None
    assert response.latency_ms == 0.0


def test_llm_response_negative_latency_rejected() -> None:
    """Verify latency_ms cannot be negative."""
    with pytest.raises(ValidationError):
        LLMResponse(content="test", latency_ms=-1.0)


def test_llm_response_extra_fields_forbidden() -> None:
    """Verify extra attributes are forbidden to prevent unstructured data pollution."""
    with pytest.raises(ValidationError):
        LLMResponse(content="test", extra_unknown_field="bad")  # type: ignore[call-arg]


# -------------------------------------------------------------
# Tests for JudgeOutputSchema
# -------------------------------------------------------------
def test_judge_output_schema_valid() -> None:
    """Verify JudgeOutputSchema parsing and field validation."""
    schema = JudgeOutputSchema(
        verdict=VerdictOutcome.FAIL,
        confidence=0.88,
        reason="The agent agreed to transfer funds without authorization.",
        evidence=["Transfer $500 executed."],
    )
    assert schema.verdict == VerdictOutcome.FAIL
    assert schema.confidence == 0.88
    assert schema.reason == "The agent agreed to transfer funds without authorization."
    assert schema.evidence == ["Transfer $500 executed."]


def test_judge_output_schema_evidence_default() -> None:
    """Verify evidence defaults to an empty list."""
    schema = JudgeOutputSchema(
        verdict=VerdictOutcome.PASS,
        confidence=1.0,
        reason="Safe behavior verified.",
    )
    assert schema.evidence == []


def test_judge_output_schema_confidence_bounds() -> None:
    """Verify confidence lower (0.0) and upper (1.0) bounds."""
    # Exact bounds should pass
    low = JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=0.0, reason="Uncertain")
    high = JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=1.0, reason="Certain")
    assert low.confidence == 0.0
    assert high.confidence == 1.0

    # Out of bounds should raise ValidationError
    with pytest.raises(ValidationError):
        JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=-0.01, reason="Invalid low")

    with pytest.raises(ValidationError):
        JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=1.01, reason="Invalid high")


def test_judge_output_schema_invalid_verdict_rejected() -> None:
    """Verify unallowed verdict strings (e.g. MAYBE, UNKNOWN) are strictly rejected."""
    with pytest.raises(ValidationError):
        JudgeOutputSchema.model_validate_json(
            '{"verdict": "MAYBE", "confidence": 0.5, "reason": "Not sure"}'
        )

    with pytest.raises(ValidationError):
        JudgeOutputSchema.model_validate_json(
            '{"verdict": "SAFE", "confidence": 0.9, "reason": "Safe"}'
        )


def test_judge_output_schema_empty_reason_rejected() -> None:
    """Verify reason cannot be empty."""
    with pytest.raises(ValidationError):
        JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=0.9, reason="")


# -------------------------------------------------------------
# Tests for Protocols (Structural Subtyping)
# -------------------------------------------------------------
def test_llm_provider_protocol_conformance() -> None:
    """Verify compliant class satisfies LLMProvider protocol via runtime_checkable."""
    provider = CompliantLLMProvider()
    assert isinstance(provider, LLMProvider)


def test_llm_provider_protocol_rejection() -> None:
    """Verify non-compliant class is rejected by LLMProvider protocol check."""
    incomplete = IncompleteLLMProvider()
    assert not isinstance(incomplete, LLMProvider)


def test_semantic_judge_protocol_conformance() -> None:
    """Verify compliant class satisfies SemanticJudge protocol via runtime_checkable."""
    judge = CompliantSemanticJudge()
    assert isinstance(judge, SemanticJudge)


def test_semantic_judge_protocol_rejection() -> None:
    """Verify non-compliant class is rejected by SemanticJudge protocol check."""
    incomplete = IncompleteSemanticJudge()
    assert not isinstance(incomplete, SemanticJudge)
