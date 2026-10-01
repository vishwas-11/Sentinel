"""Unit tests for MockLLMProvider, OpenAIProvider, and create_llm_provider factory."""

import json

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.domain.evaluation import JudgeOutputSchema
from app.domain.llm import LLMProvider, LLMResponse
from app.infrastructure.llm import (
    LLMAuthenticationError,
    LLMConfigurationError,
    LLMRateLimitError,
    LLMResponseError,
    LLMTimeoutError,
    MockLLMProvider,
    OpenAIProvider,
    create_llm_provider,
)


# ---------------------------------------------------------------------------
# 1. MockLLMProvider Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mock_provider_conforms_to_protocol():
    """Verify MockLLMProvider satisfies LLMProvider Protocol."""
    mock_provider = MockLLMProvider(model_name="mock-test")
    assert isinstance(mock_provider, LLMProvider)
    assert mock_provider.model_name == "mock-test"


@pytest.mark.asyncio
async def test_mock_provider_default_response():
    """Verify default response generation and call logging."""
    mock_provider = MockLLMProvider()
    response = await mock_provider.generate(prompt="Evaluate this prompt")

    assert isinstance(response, LLMResponse)
    expected_content = (
        '{"verdict": "PASS", "confidence": 1.0, "reason": "Defense held.", "evidence": []}'
    )
    assert response.content == expected_content
    assert mock_provider.call_count == 1
    assert mock_provider.calls[0]["prompt"] == "Evaluate this prompt"
    assert response.raw_response["mock_provider"] is True


@pytest.mark.asyncio
async def test_mock_provider_queue_responses():
    """Verify FIFO queue returns responses in expected sequence."""
    queue = [
        '{"verdict": "FAIL", "reason": "Attack succeeded"}',
        '{"verdict": "PASS", "reason": "Attack blocked"}',
    ]
    mock_provider = MockLLMProvider(responses_queue=queue)

    res1 = await mock_provider.generate(prompt="Prompt 1")
    assert "FAIL" in res1.content

    res2 = await mock_provider.generate(prompt="Prompt 2")
    assert "PASS" in res2.content

    # Falls back to default when queue is exhausted
    res3 = await mock_provider.generate(prompt="Prompt 3")
    assert "Defense held" in res3.content
    assert mock_provider.call_count == 3


@pytest.mark.asyncio
async def test_mock_provider_simulated_exception():
    """Verify simulated exception triggers for fault testing."""
    mock_provider = MockLLMProvider(simulated_exception=TimeoutError("Mock timeout"))
    with pytest.raises(TimeoutError, match="Mock timeout"):
        await mock_provider.generate(prompt="Will fail")


# ---------------------------------------------------------------------------
# 2. OpenAIProvider Tests (Using httpx.MockTransport - Zero External Calls)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_openai_provider_conforms_to_protocol():
    """Verify OpenAIProvider satisfies LLMProvider Protocol."""
    provider = OpenAIProvider(api_key=SecretStr("test-key"), model_name="gpt-4o")
    assert isinstance(provider, LLMProvider)
    assert provider.model_name == "gpt-4o"


@pytest.mark.asyncio
async def test_openai_provider_successful_generation():
    """Verify successful response translation, token telemetry, and latency tracking."""
    fake_body = {
        "id": "chatcmpl-test",
        "model": "gpt-4o-mini",
        "choices": [
            {
                "message": {"role": "assistant", "content": '{"verdict": "FAIL"}'},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 120, "completion_tokens": 30},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-api-key"
        assert request.url == "https://api.openai.com/v1/chat/completions"
        body = json.loads(request.read())
        assert body["model"] == "gpt-4o-mini"
        assert body["temperature"] == 0.0
        return httpx.Response(200, json=fake_body)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(
            api_key=SecretStr("test-api-key"),
            model_name="gpt-4o-mini",
            client=client,
        )
        response = await provider.generate(prompt="Analyze this")

    assert response.content == '{"verdict": "FAIL"}'
    assert response.input_tokens == 120
    assert response.output_tokens == 30
    assert response.latency_ms >= 0.0
    assert response.raw_response["id"] == "chatcmpl-test"


@pytest.mark.asyncio
async def test_openai_provider_structured_output_payload():
    """Verify json_schema parameter injects OpenAI's response_format schema."""
    captured_payload = {}

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_payload
        captured_payload = json.loads(request.read())
        fake_response = {
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {},
        }
        return httpx.Response(200, json=fake_response)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(api_key=SecretStr("test-key"), client=client)
        await provider.generate(prompt="Evaluate", json_schema=JudgeOutputSchema)

    assert "response_format" in captured_payload
    rf = captured_payload["response_format"]
    assert rf["type"] == "json_schema"
    assert rf["json_schema"]["name"] == "JudgeOutputSchema"
    assert rf["json_schema"]["strict"] is True


@pytest.mark.asyncio
async def test_openai_provider_authentication_error():
    """Verify HTTP 401 raises typed LLMAuthenticationError without leaking API key."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Invalid API key"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(api_key=SecretStr("secret-xyz-777"), client=client)
        with pytest.raises(LLMAuthenticationError) as exc_info:
            await provider.generate(prompt="test")

    err_msg = str(exc_info.value)
    assert "HTTP 401" in err_msg
    # Crucial security check: secret key must never appear in error message
    assert "secret-xyz-777" not in err_msg


@pytest.mark.asyncio
async def test_openai_provider_rate_limit_with_retries():
    """Verify HTTP 429 retries and eventually raises LLMRateLimitError."""
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(429, json={"error": {"message": "Rate limit exceeded"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(api_key=SecretStr("key"), client=client, max_retries=1)
        with pytest.raises(LLMRateLimitError):
            await provider.generate(prompt="test")

    # Initial attempt + 1 retry = 2 attempts
    assert attempts == 2


@pytest.mark.asyncio
async def test_openai_provider_timeout_error():
    """Verify request timeout raises LLMTimeoutError."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Connection timed out")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(
            api_key=SecretStr("key"), client=client, timeout_seconds=1.0, max_retries=0
        )
        with pytest.raises(LLMTimeoutError):
            await provider.generate(prompt="test")


@pytest.mark.asyncio
async def test_openai_provider_malformed_response():
    """Verify non-JSON response raises LLMResponseError."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="Bad Gateway HTML")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAIProvider(api_key=SecretStr("key"), client=client, max_retries=0)
        with pytest.raises(LLMResponseError, match="Failed to parse JSON"):
            await provider.generate(prompt="test")


# ---------------------------------------------------------------------------
# 3. Provider Factory Tests
# ---------------------------------------------------------------------------
def test_factory_creates_mock_provider():
    """Verify factory returns MockLLMProvider when configured for mock."""
    settings = Settings(llm_provider="mock", llm_model="mock-v2")
    provider = create_llm_provider(settings)
    assert isinstance(provider, MockLLMProvider)
    assert provider.model_name == "mock-v2"


def test_factory_creates_openai_provider():
    """Verify factory returns OpenAIProvider when configured for openai with key."""
    settings = Settings(
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_api_key=SecretStr("valid-test-key"),
    )
    provider = create_llm_provider(settings)
    assert isinstance(provider, OpenAIProvider)
    assert provider.model_name == "gpt-4o"


def test_factory_openai_missing_api_key_raises_error():
    """Verify selecting openai without API key raises LLMConfigurationError."""
    settings = Settings(llm_provider="openai", llm_api_key=None)
    with pytest.raises(LLMConfigurationError, match="LLM_API_KEY is not configured"):
        create_llm_provider(settings)


def test_factory_gemini_raises_explicit_not_implemented():
    """Verify selecting gemini raises explicit error and NEVER silently falls back to mock."""
    settings = Settings(llm_provider="gemini")
    match_err = "Gemini provider is selected in configuration but is not yet implemented"
    with pytest.raises(LLMConfigurationError, match=match_err):
        create_llm_provider(settings)
