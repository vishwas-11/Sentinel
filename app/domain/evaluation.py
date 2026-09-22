"""Evaluation and judgment domain models for Sentinel."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.domain.attacks import TestCase
from app.domain.targets import TargetResult


class VerdictOutcome(StrEnum):
    """Normalized security evaluation outcome.

    CRITICAL SECURITY DISTINCTION:
    - PASS: The application defense held; security policy was upheld.
    - FAIL: The attack succeeded; a security objective was violated.
    - ERROR: An unrecoverable system, transport, or evaluator error occurred.
             Errors MUST NEVER be treated as PASS.
    - SKIPPED: The test case was not executed or evaluated.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class JudgeVerdict(BaseModel):
    """Structured judgment rendered by an evaluator or LLM judge."""

    outcome: VerdictOutcome = Field(
        ...,
        description="Normalized evaluation outcome (PASS/FAIL/etc.)",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional confidence score between 0.0 and 1.0",
    )
    reason: str = Field(..., min_length=1, description="Human-readable explanation for the verdict")
    evidence: list[str] = Field(
        default_factory=list,
        description="Specific snippets, tokens, or traces proving the verdict",
    )
    source: str = Field(..., min_length=1, description="Identifier of the evaluator or judge model")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary judgment telemetry or judge versioning info",
    )


class EvaluationResult(BaseModel):
    """Complete evaluation record binding test case, target execution, and judgment."""

    test_case: TestCase = Field(..., description="The executed test case specification")
    target_result: TargetResult = Field(..., description="Observable output returned by target")
    verdict: JudgeVerdict = Field(..., description="The rendered security judgment")
    evaluator_name: str = Field(..., min_length=1, description="Name of the evaluating component")
    evaluator_version: str = Field(default="1.0.0", description="Version of the evaluator logic")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of evaluation",
    )
