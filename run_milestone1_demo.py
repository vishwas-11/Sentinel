"""Educational manual verification script for Phase 7 Milestone 1 contracts."""

from pydantic import ValidationError

from app.domain.evaluation import (
    JudgeOutputSchema,
    JudgeVerdict,
    SemanticJudge,
    TestExecutionRecord,
    VerdictOutcome,
)
from app.domain.llm import LLMProvider, LLMResponse


class DummyProvider:
    @property
    def model_name(self) -> str:
        return "dummy-gpt-4o"

    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        return LLMResponse(content='{"verdict": "FAIL"}', latency_ms=120.0)


class DummyJudge:
    @property
    def name(self) -> str:
        return "dummy-judge"

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        return JudgeVerdict(
            outcome=VerdictOutcome.FAIL,
            confidence=0.92,
            reason="Violation observed.",
            source=self.name,
        )


def main() -> None:
    print("=" * 60)
    print("SENTINEL PHASE 7 MILESTONE 1 — MANUAL CONTRACT VERIFICATION")
    print("=" * 60)

    # 1. Valid Structured JSON parsing
    raw_json = (
        '{"verdict": "FAIL", "confidence": 0.95, "reason": "Leaked internal key", '
        '"evidence": ["sk_live_12345"]}'
    )
    schema = JudgeOutputSchema.model_validate_json(raw_json)
    print(f"\n[1] Valid JudgeOutputSchema successfully parsed:\n    Verdict: {schema.verdict}")
    print(f"    Confidence: {schema.confidence}")
    print(f"    Reason: {schema.reason}")
    print(f"    Evidence: {schema.evidence}")
    assert schema.verdict == VerdictOutcome.FAIL

    # 2. Rejection of unallowed verdict
    print("\n[2] Testing rejection of unallowed verdict ('MAYBE'):")
    try:
        JudgeOutputSchema.model_validate_json(
            '{"verdict": "MAYBE", "confidence": 0.5, "reason": "Not sure"}'
        )
        raise AssertionError("Should have failed")
    except ValidationError as exc:
        print(f"    Expected ValidationError: {exc.errors()[0]['msg']}")

    # 3. Rejection of out-of-bounds confidence
    print("\n[3] Testing rejection of out-of-bounds confidence (1.2):")
    try:
        JudgeOutputSchema(verdict=VerdictOutcome.PASS, confidence=1.2, reason="Overconfident")
        raise AssertionError("Should have failed")
    except ValidationError as exc:
        print(f"    Expected ValidationError: {exc.errors()[0]['msg']}")

    # 4. Protocol structural subtyping verification
    print("\n[4] Testing Protocol Structural Subtyping:")
    provider = DummyProvider()
    judge = DummyJudge()
    print(f"    isinstance(DummyProvider(), LLMProvider) -> {isinstance(provider, LLMProvider)}")
    print(f"    isinstance(DummyJudge(), SemanticJudge) -> {isinstance(judge, SemanticJudge)}")
    assert isinstance(provider, LLMProvider)
    assert isinstance(judge, SemanticJudge)

    print("\n" + "=" * 60)
    print("ALL MILESTONE 1 MANUAL VERIFICATION CHECKS PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    main()
