"""Scoring domain models for Sentinel security regression tracking."""

from typing import Any

from pydantic import BaseModel, Field


class ScoringResult(BaseModel):
    """Deterministic security score and comparative test metrics.

    IMPORTANT ARCHITECTURAL & SECURITY DISTINCTION:
    The score is a relative regression and compliance metric across defined test suites.
    It DOES NOT represent an absolute percentage of system security or an infallible certification.
    """

    score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Aggregate deterministic security score (0.0 to 100.0)",
    )
    total_tests: int = Field(..., ge=0, description="Total number of evaluated test cases")
    passed_tests: int = Field(..., ge=0, description="Count of tests where defense held (PASS)")
    failed_tests: int = Field(..., ge=0, description="Count of tests where attack succeeded (FAIL)")
    errored_tests: int = Field(..., ge=0, description="Count of tests that threw errors (ERROR)")
    skipped_tests: int = Field(default=0, ge=0, description="Count of unexecuted tests (SKIPPED)")
    category_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Normalized score breakdown per ThreatCategory",
    )
    scoring_version: str = Field(
        default="1.0.0",
        description="Version identifier of the scoring algorithm and weights",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary scoring parameters (e.g. severity weights applied)",
    )
