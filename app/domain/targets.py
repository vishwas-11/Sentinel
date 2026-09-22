"""Target result and adapter interface contracts for Sentinel."""

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from app.domain.attacks import TestCase


class ObservableToolCall(BaseModel):
    """Normalized observation of a tool call executed by an arbitrary target.

    Sentinel inspects this contract to verify security properties (e.g. unauthorized tool calls)
    without depending on any specific application domain (banking, healthcare, etc.).
    """

    tool_name: str = Field(..., description="Name of the tool requested by the target model")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool",
    )
    result: Any | None = Field(default=None, description="Result returned from tool execution")
    error: str | None = Field(default=None, description="Error message if tool execution failed")
    success: bool = Field(default=True, description="Whether tool execution completed successfully")


class TargetResult(BaseModel):
    """External observable outcome from executing a test case against an authorized target.

    Captures conversational output, transport telemetry, and tool execution traces.
    """

    response: str | None = Field(default=None, description="Conversational output from the target")
    status: str = Field(
        default="success",
        description="Execution status ('success', 'error', etc.)",
    )
    status_code: int | None = Field(
        default=None,
        description="Transport status code (e.g. HTTP 200, 422) if applicable",
    )
    tool_calls: list[ObservableToolCall] = Field(
        default_factory=list,
        description="Observable tool executions captured during the turn",
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Elapsed execution time in milliseconds",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Transport or model telemetry (tokens, model ID, headers)",
    )
    error: str | None = Field(
        default=None,
        description="Sanitized failure description if target execution failed",
    )


@runtime_checkable
class TargetAdapter(Protocol):
    """Abstract interface contract for communicating with an external AI target.

    Decouples the Sentinel evaluation engine from specific target implementations
    (REST HTTP targets, local Python agents, websocket connections, etc.).
    """

    async def execute(self, test_case: TestCase) -> TargetResult:
        """Execute a test case against the target application and return observable results.

        Args:
            test_case: The executable test case containing attack prompt and session details.

        Returns:
            TargetResult containing conversational output, tool calls, and telemetry.
        """
        ...

    async def reset(self) -> None:
        """Reset target state between test runs to ensure test isolation."""
        ...
