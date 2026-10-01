"""OpenAI REST API implementation of the LLMProvider protocol using httpx."""

import asyncio
import logging
import time
from typing import Any

import httpx
from pydantic import BaseModel, SecretStr

from app.domain.llm import LLMResponse
from app.infrastructure.llm.exceptions import (
    LLMAuthenticationError,
    LLMRateLimitError,
    LLMResponseError,
    LLMServerError,
    LLMTimeoutError,
)

logger = logging.getLogger("sentinel.infrastructure.llm.openai")

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider:
    """Communicates with OpenAI API endpoints using an async httpx client.

    Responsibilities:
    - Enforces configured model, timeouts, and headers (Bearer authentication).
    - Supports native OpenAI structured outputs when json_schema is provided.
    - Implements bounded exponential backoff retries for transient errors (429, 5xx).
    - Normalizes raw JSON responses into domain LLMResponse envelopes.
    - Strictly redacts API credentials from error messages and logs.
    """

    def __init__(
        self,
        api_key: SecretStr,
        model_name: str = "gpt-4o-mini",
        base_url: str = DEFAULT_OPENAI_BASE_URL,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the OpenAIProvider.

        Args:
            api_key: SecretStr containing the OpenAI API credential.
            model_name: Name of the OpenAI model to invoke.
            base_url: Base endpoint URL (allows pointing to custom gateways or vLLM).
            timeout_seconds: Maximum generation duration in seconds.
            max_retries: Maximum number of retry attempts on transient network or 429/5xx errors.
            client: Optional injected httpx.AsyncClient (for tests or connection pooling).
        """
        self._api_key = api_key
        self._model_name = model_name
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = max(0.1, timeout_seconds)
        self._max_retries = max(0, max_retries)
        self._client = client

    @property
    def model_name(self) -> str:
        """Return the configured OpenAI model name."""
        return self._model_name

    def _build_payload(
        self,
        prompt: str,
        system_instruction: str | None,
        temperature: float,
        max_tokens: int,
        json_schema: type[BaseModel] | None,
    ) -> dict[str, Any]:
        """Construct the JSON payload for OpenAI's /chat/completions endpoint."""
        messages: list[dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self._model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        # Apply OpenAI native structured outputs format if schema provided
        if json_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": json_schema.__name__,
                    "strict": True,
                    "schema": json_schema.model_json_schema(),
                },
            }

        return payload

    async def _send_request_with_retries(
        self, client: httpx.AsyncClient, payload: dict[str, Any]
    ) -> httpx.Response:
        """Dispatch HTTP POST with bounded exponential backoff on retryable failures."""
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }

        attempts = 0
        backoff_delay = 0.5

        while True:
            attempts += 1
            try:
                response = await client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self._timeout_seconds,
                )

                # Check HTTP status codes
                if response.status_code == 200:
                    return response

                # Non-retryable authentication failure
                if response.status_code in (401, 403):
                    raise LLMAuthenticationError(
                        f"OpenAI authentication failed (HTTP {response.status_code}). "
                        "Check API key.",
                        provider="openai",
                    )

                # Retryable rate limit (429) or server errors (500, 502, 503, 504)
                if response.status_code in (429, 500, 502, 503, 504):
                    if attempts > self._max_retries:
                        if response.status_code == 429:
                            raise LLMRateLimitError(
                                "OpenAI rate limit or quota exceeded (HTTP 429) "
                                f"after {attempts} attempts.",
                                provider="openai",
                            )
                        raise LLMServerError(
                            f"OpenAI server error (HTTP {response.status_code}) "
                            f"after {attempts} attempts.",
                            provider="openai",
                        )

                    logger.warning(
                        "OpenAI request returned HTTP %d. Retrying attempt %d/%d in %.2fs",
                        response.status_code,
                        attempts,
                        self._max_retries,
                        backoff_delay,
                    )
                    await asyncio.sleep(backoff_delay)
                    backoff_delay *= 2
                    continue

                # Any other 4xx client errors (e.g. 400 Bad Request, unretryable)
                raise LLMResponseError(
                    f"OpenAI API client error (HTTP {response.status_code}): {response.text[:200]}",
                    provider="openai",
                )

            except httpx.TimeoutException as exc:
                if attempts > self._max_retries:
                    raise LLMTimeoutError(
                        f"OpenAI request timed out after {self._timeout_seconds}s.",
                        provider="openai",
                    ) from exc
                logger.warning(
                    "OpenAI timeout on attempt %d/%d. Retrying in %.2fs",
                    attempts,
                    self._max_retries,
                    backoff_delay,
                )
                await asyncio.sleep(backoff_delay)
                backoff_delay *= 2

            except (httpx.ConnectError, httpx.NetworkError) as exc:
                if attempts > self._max_retries:
                    raise LLMServerError(
                        f"OpenAI network connection failed: {exc}",
                        provider="openai",
                    ) from exc
                logger.warning(
                    "OpenAI network error on attempt %d/%d. Retrying in %.2fs",
                    attempts,
                    self._max_retries,
                    backoff_delay,
                )
                await asyncio.sleep(backoff_delay)
                backoff_delay *= 2

    async def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1000,
        json_schema: type[BaseModel] | None = None,
    ) -> LLMResponse:
        """Invoke OpenAI /chat/completions and return a normalized LLMResponse envelope."""
        payload = self._build_payload(
            prompt=prompt,
            system_instruction=system_instruction,
            temperature=temperature,
            max_tokens=max_tokens,
            json_schema=json_schema,
        )

        start_time = time.perf_counter()

        if self._client is not None:
            response = await self._send_request_with_retries(self._client, payload)
        else:
            async with httpx.AsyncClient() as client:
                response = await self._send_request_with_retries(client, payload)

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        try:
            data = response.json()
        except Exception as exc:
            raise LLMResponseError(
                f"Failed to parse JSON from OpenAI response: {exc}", provider="openai"
            ) from exc

        choices = data.get("choices", [])
        if not choices:
            raise LLMResponseError("OpenAI response missing 'choices' array.", provider="openai")

        content = choices[0].get("message", {}).get("content", "")
        if content is None:
            content = ""

        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")

        sanitized_raw = {
            "id": data.get("id"),
            "model": data.get("model"),
            "finish_reason": choices[0].get("finish_reason"),
        }

        return LLMResponse(
            content=content,
            raw_response=sanitized_raw,
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            latency_ms=round(latency_ms, 2),
        )
