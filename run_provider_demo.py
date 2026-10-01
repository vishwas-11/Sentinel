"""Educational manual verification demo for Phase 7 LLM Provider Layer."""

import asyncio

from pydantic import SecretStr

from app.core.config import Settings
from app.domain.evaluation import JudgeOutputSchema
from app.infrastructure.llm import (
    LLMConfigurationError,
    MockLLMProvider,
    OpenAIProvider,
    create_llm_provider,
)


async def main() -> None:
    print("=" * 70)
    print("SENTINEL PHASE 7 — MANUAL LLM PROVIDER LAYER VERIFICATION")
    print("=" * 70)

    # 1. Default Factory Selection -> MockLLMProvider
    print("\n[1] Testing Factory with default settings (LLM_PROVIDER=mock):")
    default_settings = Settings()
    provider = create_llm_provider(default_settings)
    print(f"    Selected Provider:  {type(provider).__name__}")
    print(f"    Model Name:         {provider.model_name}")
    assert isinstance(provider, MockLLMProvider)

    # 2. Mock Generation with Structured Output
    print("\n[2] Testing MockLLMProvider generation with JudgeOutputSchema:")
    structured_mock_response = (
        '{"verdict": "FAIL", "confidence": 0.92, '
        '"reason": "Target confirmed unauthorized fund transfer.", '
        '"evidence": ["Transfer $500 approved."]}'
    )
    custom_mock = MockLLMProvider(
        default_response=structured_mock_response,
        model_name="mock-gpt-4o",
    )
    response = await custom_mock.generate(
        prompt="Evaluate security breach on T4-001",
        json_schema=JudgeOutputSchema,
    )
    print(f"    Generated Content:  {response.content}")
    print(f"    Input Tokens:       {response.input_tokens}")
    print(f"    Output Tokens:      {response.output_tokens}")
    print(f"    Recorded Call:      {custom_mock.calls[0]['json_schema']}")

    # Validate that generated content parses into JudgeOutputSchema
    parsed_verdict = JudgeOutputSchema.model_validate_json(response.content)
    print(
        f"    Parsed Verdict:     {parsed_verdict.verdict} "
        f"(Confidence: {parsed_verdict.confidence})"
    )
    assert parsed_verdict.verdict.value == "FAIL"

    # 3. Factory Selection for OpenAIProvider
    print("\n[3] Testing Factory with LLM_PROVIDER=openai:")
    openai_settings = Settings(
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_api_key=SecretStr("fake-test-key-no-network"),
    )
    openai_provider = create_llm_provider(openai_settings)
    print(f"    Selected Provider:  {type(openai_provider).__name__}")
    print(f"    Configured Model:   {openai_provider.model_name}")
    assert isinstance(openai_provider, OpenAIProvider)

    # 4. Strict Failure on Missing Key
    print("\n[4] Testing strict failure when OpenAI is selected without API key:")
    missing_key_settings = Settings(llm_provider="openai", llm_api_key=None)
    try:
        create_llm_provider(missing_key_settings)
        raise AssertionError("Should have raised LLMConfigurationError")
    except LLMConfigurationError as exc:
        print(f"    Correctly rejected: {exc}")

    # 5. Strict Failure on Unimplemented Gemini (Zero Silent Fallback)
    print("\n[5] Testing strict failure for unimplement Gemini (no silent fallback):")
    gemini_settings = Settings(llm_provider="gemini")
    try:
        create_llm_provider(gemini_settings)
        raise AssertionError("Should have raised LLMConfigurationError")
    except LLMConfigurationError as exc:
        print(f"    Correctly rejected: {exc}")

    print("\n" + "=" * 70)
    print("ALL LLM PROVIDER LAYER VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
