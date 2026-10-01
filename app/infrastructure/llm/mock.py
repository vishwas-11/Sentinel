"""In-memory mock LLM provider for zero-cost offline security testing."""

import asyncio
from typing import Any

from pydantic import BaseModel

from app.domain.llm import LLMResponse


class MockLLMProvider:
    """Mock implementation of the LLMProvider Protocol for offline testing.

    Features:
    - Zero network calls and zero token charges.
    - Deterministic fixed or FIFO queue response output.
    - Configurable simulated latency and exceptions.
    - Complete inspection telemetry of dispatched calls.
    """

    def __init__(
        self,
        default_response: str = (
            '{"verdict": "PASS", "confidence": 1.0, "reason": "Defense held.", "evidence": []}'
        ),
        responses_queue: list[str] | None = None,
        model_name: str = "mock-judge",
        simulated_latency_ms: float = 0.0,
        simulated_exception: Exception | None = None,
    ) -> None:
        """Initialize the MockLLMProvider.

        Args:
            default_response: Text returned when responses_queue is empty or not provided.
            responses_queue: Optional list of responses returned sequentially in FIFO order.
            model_name: Model identifier exposed by protocol property.
            simulated_latency_ms: Optional sleep duration in milliseconds to simulate network lag.
            simulated_exception: Optional Exception to raise on generate() for fault testing.
        """
        self._default_response = default_response
        self._responses_queue = list(responses_queue) if responses_queue else []
        self._model_name = model_name
        self._simulated_latency_ms = max(0.0, simulated_latency_ms)
        self._simulated_exception = simulated_exception

        self.call_count: int = 0
        self.calls: list[dict[str, Any]] = []

    @property
    def model_name(self) -> str:
        """Return the model identifier."""
        return self._model_name

    async def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1000,
        json_schema: type[BaseModel] | None = None,
    ) -> LLMResponse:
        """Simulate generation, recording call telemetry and returning queued/default output."""
        self.call_count += 1
        call_record = {
            "prompt": prompt,
            "system_instruction": system_instruction,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "json_schema": json_schema.__name__ if json_schema else None,
        }
        self.calls.append(call_record)

        if self._simulated_latency_ms > 0:
            await asyncio.sleep(self._simulated_latency_ms / 1000.0)

        if self._simulated_exception is not None:
            raise self._simulated_exception

        if self._responses_queue:
            content = self._responses_queue.pop(0)
        else:
            content = self._default_response

        return LLMResponse(
            content=content,
            raw_response={"mock_provider": True, "call_index": self.call_count},
            input_tokens=len(prompt.split()),
            output_tokens=len(content.split()),
            latency_ms=self._simulated_latency_ms,
        )
