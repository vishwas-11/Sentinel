"""HTTP Target Adapter for Sentinel.

Communicates with external AI applications over HTTP REST endpoints (e.g. /chat, /reset).
Conforms to the TargetAdapter Protocol, translating target-specific transport envelopes
into normalized Sentinel domain models (TargetResult, ObservableToolCall).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.adapters.exceptions import (
    TargetConnectionError,
    TargetResetError,
    TargetTimeoutError,
)
from app.core.config import Settings, get_settings
from app.domain.attacks import TestCase
from app.domain.targets import ObservableToolCall, TargetResult

logger = logging.getLogger("sentinel.adapters.http")


class HttpTargetAdapter:
    """TargetAdapter implementation communicating with REST-enabled AI agents over HTTP.

    Translates TestCase inputs into the target's expected HTTP payload format (/chat),
    and normalizes the target's response envelope into a domain TargetResult.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        connect_timeout_seconds: float | None = None,
        client: httpx.AsyncClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Initialize the HTTP target adapter.

        Args:
            base_url: Target application base URL (e.g. 'http://localhost:8001').
            timeout_seconds: Total read/write timeout in seconds.
            connect_timeout_seconds: Connection establishment timeout in seconds.
            client: Optional injected httpx.AsyncClient (for testing or connection reuse).
            settings: Optional explicit Settings instance; defaults to get_settings().
        """
        cfg = settings or get_settings()

        self.base_url = (base_url or cfg.target_base_url).rstrip("/")
        self.timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else cfg.target_timeout_seconds
        )
        self.connect_timeout_seconds = (
            connect_timeout_seconds
            if connect_timeout_seconds is not None
            else cfg.target_connect_timeout_seconds
        )

        self._injected_client = client
        self._internal_client: httpx.AsyncClient | None = None

    def _get_timeout(self) -> httpx.Timeout:
        """Construct granular timeout configuration."""
        return httpx.Timeout(
            timeout=self.timeout_seconds,
            connect=self.connect_timeout_seconds,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Obtain or lazily instantiate an HTTP client."""
        if self._injected_client is not None:
            return self._injected_client
        if self._internal_client is None or self._internal_client.is_closed:
            self._internal_client = httpx.AsyncClient(timeout=self._get_timeout())
        return self._internal_client

    async def aclose(self) -> None:
        """Close the internal HTTP client pool if created by this adapter."""
        if self._internal_client is not None and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    async def __aenter__(self) -> HttpTargetAdapter:
        """Support async context manager protocol."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Ensure HTTP resources are cleanly closed on context exit."""
        await self.aclose()

    async def execute(self, test_case: TestCase) -> TargetResult:
        """Execute a test case against the target application via HTTP POST /chat.

        Args:
            test_case: Domain test case with attack prompt, metadata, and session ID.

        Returns:
            Normalized TargetResult with conversational response, tool calls, and telemetry.
        """
        client = await self._get_client()
        url = f"{self.base_url}/chat"

        payload = {
            "session_id": test_case.session_id,
            "message": test_case.attack.prompt,
        }

        start_time = time.perf_counter()

        try:
            response = await client.post(
                url,
                json=payload,
                timeout=self._get_timeout(),
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        except httpx.ConnectError as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Connection failure to target %s: %s", url, err)
            return TargetResult(
                response=None,
                status="error",
                status_code=None,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"error_type": "ConnectionError", "endpoint": url},
                error=f"Failed to connect to target at {url}: {err}",
            )

        except httpx.TimeoutException as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning(
                "Timeout connecting to target %s after %ss: %s", url, self.timeout_seconds, err
            )
            return TargetResult(
                response=None,
                status="error",
                status_code=408,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={
                    "error_type": "TimeoutError",
                    "endpoint": url,
                    "timeout_seconds": self.timeout_seconds,
                },
                error=(
                    f"Request to target at {url} timed out after {self.timeout_seconds}s: {err}"
                ),
            )

        except httpx.NetworkError as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Network failure to target %s: %s", url, err)
            return TargetResult(
                response=None,
                status="error",
                status_code=None,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"error_type": "NetworkError", "endpoint": url},
                error=f"Network error communicating with target at {url}: {err}",
            )

        # Process HTTP Response
        return self._parse_target_response(response, elapsed_ms, test_case, url)

    def _parse_target_response(
        self,
        response: httpx.Response,
        elapsed_ms: float,
        test_case: TestCase,
        url: str,
    ) -> TargetResult:
        """Parse, validate, and normalize HTTP response into TargetResult."""
        status_code = response.status_code

        # Attempt to decode JSON
        try:
            data = response.json()
        except Exception:
            return TargetResult(
                response=response.text if response.text else None,
                status="error",
                status_code=status_code,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"endpoint": url, "raw_text": response.text[:500]},
                error=f"Target returned non-JSON response (HTTP {status_code})",
            )

        # If server returned non-dictionary JSON
        if not isinstance(data, dict):
            return TargetResult(
                response=str(data),
                status="error",
                status_code=status_code,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"endpoint": url},
                error=f"Target returned unexpected JSON type: {type(data).__name__}",
            )

        # Handle HTTP 5xx or server crash
        if status_code >= 500:
            error_detail = (
                data.get("detail") or data.get("errors") or data.get("message") or response.text
            )
            return TargetResult(
                response=data.get("response"),
                status="error",
                status_code=status_code,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"endpoint": url, "raw_data": data},
                error=f"Target internal error (HTTP {status_code}): {error_detail}",
            )

        # Handle HTTP 4xx client errors (e.g. 422 Unprocessable Entity, 400 Bad Request)
        if status_code >= 400:
            # If target provided a valid response envelope despite 4xx (e.g. rejection)
            if "response" in data and "status" in data:
                return self._build_normalized_result(data, status_code, elapsed_ms, test_case, url)

            detail = data.get("detail", response.text)
            return TargetResult(
                response=None,
                status="error",
                status_code=status_code,
                tool_calls=[],
                latency_ms=round(elapsed_ms, 2),
                metadata={"endpoint": url, "raw_data": data},
                error=f"Target rejected request with HTTP {status_code}: {detail}",
            )

        # Normal 2xx response
        return self._build_normalized_result(data, status_code, elapsed_ms, test_case, url)

    def _build_normalized_result(
        self,
        data: dict[str, Any],
        status_code: int,
        elapsed_ms: float,
        test_case: TestCase,
        url: str,
    ) -> TargetResult:
        """Construct normalized TargetResult from envelope dictionary."""
        response_text = data.get("response")
        target_status = data.get("status", "success")

        # Normalize tool execution records into ObservableToolCall models
        observable_tools: list[ObservableToolCall] = []
        raw_tools = data.get("tool_calls", [])
        if isinstance(raw_tools, list):
            for raw_tool in raw_tools:
                if isinstance(raw_tool, dict):
                    observable_tools.append(
                        ObservableToolCall(
                            tool_name=str(raw_tool.get("tool_name", "unknown")),
                            arguments=raw_tool.get("arguments")
                            if isinstance(raw_tool.get("arguments"), dict)
                            else {},
                            result=raw_tool.get("result"),
                            error=raw_tool.get("error"),
                            success=bool(raw_tool.get("success", True)),
                        )
                    )

        # Extract target telemetry metadata
        raw_meta = data.get("metadata", {})
        target_latency_ms = None
        if isinstance(raw_meta, dict):
            target_latency_ms = raw_meta.get("latency_ms")

        combined_metadata: dict[str, Any] = {
            "endpoint": url,
            "session_id": test_case.session_id,
            "adapter_latency_ms": round(elapsed_ms, 2),
            "target_latency_ms": target_latency_ms,
        }
        if isinstance(raw_meta, dict):
            combined_metadata["target_metadata"] = raw_meta

        # Format error if present
        error_msg: str | None = None
        raw_errors = data.get("errors")
        if raw_errors and isinstance(raw_errors, list):
            err_items: list[str] = []
            for err in raw_errors:
                if isinstance(err, dict):
                    msg = err.get("message") or err.get("code") or str(err)
                    err_items.append(msg)
                else:
                    err_items.append(str(err))
            if err_items:
                error_msg = "; ".join(err_items)
        elif target_status == "error":
            error_msg = "Target reported execution error"

        return TargetResult(
            response=str(response_text) if response_text is not None else None,
            status=str(target_status),
            status_code=status_code,
            tool_calls=observable_tools,
            latency_ms=round(elapsed_ms, 2),
            metadata=combined_metadata,
            error=error_msg,
        )

    async def reset(self) -> None:
        """Reset external target state between test suites via HTTP POST /reset.

        Ensures test isolation by restoring conversation dialogue history and application data.

        Raises:
            TargetConnectionError: If target application is unreachable.
            TargetTimeoutError: If reset call exceeds configured timeout.
            TargetResetError: If target returns a non-200 status code.
        """
        client = await self._get_client()
        url = f"{self.base_url}/reset"

        try:
            response = await client.post(url, timeout=self._get_timeout())
        except httpx.ConnectError as err:
            logger.error("Failed to connect to target reset endpoint %s: %s", url, err)
            raise TargetConnectionError(f"Target unreachable at {url}: {err}") from err
        except httpx.TimeoutException as err:
            logger.error("Timeout resetting target at %s: %s", url, err)
            raise TargetTimeoutError(f"Reset request to {url} timed out: {err}") from err
        except httpx.NetworkError as err:
            logger.error("Network error resetting target at %s: %s", url, err)
            raise TargetConnectionError(f"Network error resetting target at {url}: {err}") from err

        if response.status_code != 200:
            logger.error(
                "Target reset failed with HTTP %s: %s", response.status_code, response.text
            )
            raise TargetResetError(
                f"Target reset returned HTTP {response.status_code}: {response.text[:200]}"
            )
