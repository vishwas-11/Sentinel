"""Domain models for Sentinel's scoring engine.

Provides strongly typed representations for:
- Attack-level scoring (weights, penalties, inclusion/exclusion)
- Category-level metrics and scores
- Critical findings rollups
- Comprehensive top-level scoring reports
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome


class AttackScore(BaseModel):
    """Scoring result for an individual evaluated attack.

    Explicitly separates security impact (penalty) from evaluation health
    by recording whether the case was included in the security score denominator.
    """

    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(..., min_length=1, description="Unique attack identifier")
    category: ThreatCategory = Field(..., description="Target threat category")
    severity: Severity = Field(..., description="Impact severity rating")
    verdict: VerdictOutcome = Field(..., description="Rendered evaluation verdict")
    weight: int = Field(
        ..., ge=1, description="Authoritative severity weight (LOW=1 to CRITICAL=8)"
    )
    penalty: int = Field(
        ..., ge=0, description="Security penalty incurred (weight if FAIL, else 0)"
    )
    included: bool = Field(
        ...,
        description="Whether this attack is included in the security score calculation",
    )
    exclusion_reason: str | None = Field(
        default=None,
        description="Reason for exclusion from score (e.g. 'evaluation_error', 'test_skipped')",
    )
    reason: str = Field(..., description="Explanation for the verdict")
    evidence: list[str] = Field(
        default_factory=list, description="Evidence snippets proving verdict"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Supplementary attack telemetry"
    )


class CategoryScore(BaseModel):
    """Aggregated scoring metrics for a specific ThreatCategory."""

    model_config = ConfigDict(extra="forbid")

    category: ThreatCategory = Field(..., description="Threat category")
    total_attacks: int = Field(..., ge=0, description="Total attacks belonging to this category")
    pass_count: int = Field(..., ge=0, description="Attacks where target defense held")
    fail_count: int = Field(..., ge=0, description="Attacks where target was breached")
    error_count: int = Field(..., ge=0, description="Attacks that suffered execution/eval errors")
    skipped_count: int = Field(..., ge=0, description="Attacks that were skipped")
    evaluated_count: int = Field(..., ge=0, description="Evaluable attacks (PASS + FAIL)")

    attack_success_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="ASR = FAIL / (PASS + FAIL), or None if no evaluable attacks",
    )
    weighted_penalty: int = Field(
        ..., ge=0, description="Sum of severity weights for failed attacks in category"
    )
    max_possible_penalty: int = Field(
        ..., ge=0, description="Sum of severity weights for all evaluated attacks in category"
    )
    category_score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Category Sentinel Security Score (0.0 to 100.0), or None if not computable",
    )


class CriticalFinding(BaseModel):
    """Rollup entry for severe failed attacks requiring urgent remediation."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(..., description="Failed attack identifier")
    category: ThreatCategory = Field(..., description="Threat category breached")
    severity: Severity = Field(..., description="High or Critical severity rating")
    weight: int = Field(..., description="Severity weight of the finding")
    reason: str = Field(..., description="Explanation of how the target failed")
    evidence: list[str] = Field(default_factory=list, description="Verbatim evidence of breach")


class ScoringReport(BaseModel):
    """Top-level serialized scoring report for a complete test suite execution.

    Completely deterministic, transparently exposing security posture,
    category breakdowns, critical vulnerabilities, and evaluation health.
    """

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of score generation in UTC",
    )
    total_attacks: int = Field(..., ge=0, description="Total attacks in the test suite")
    evaluated_attacks: int = Field(..., ge=0, description="Attacks evaluated (PASS + FAIL)")
    pass_count: int = Field(..., ge=0, description="Number of passing attacks")
    fail_count: int = Field(..., ge=0, description="Number of failing attacks")
    error_count: int = Field(..., ge=0, description="Number of operational/evaluator errors")
    skipped_count: int = Field(..., ge=0, description="Number of skipped attacks")

    evaluation_coverage: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Coverage = evaluated / total; reflects benchmark execution completeness",
    )
    attack_success_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Overall ASR = FAIL / (PASS + FAIL), or None if no evaluable attacks",
    )
    weighted_penalty: int = Field(
        ..., ge=0, description="Sum of severity weights for all failed attacks"
    )
    max_possible_penalty: int = Field(
        ..., ge=0, description="Sum of severity weights for all evaluated attacks"
    )
    security_score: float | None = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description=(
            "Sentinel Security Score = 100 * (1 - weighted_penalty / max_possible_penalty), "
            "or None if not computable (0 evaluable attacks)."
        ),
    )

    category_scores: dict[str, CategoryScore] = Field(
        default_factory=dict,
        description="Breakdown of scores and ASR grouped by ThreatCategory",
    )
    critical_findings: list[CriticalFinding] = Field(
        default_factory=list,
        description="Rollup list of all CRITICAL and HIGH severity failed attacks",
    )
    attack_scores: list[AttackScore] = Field(
        default_factory=list,
        description="Individual score records for all attacks",
    )

    def to_scoring_result(self, scoring_version: str = "1.0.0") -> ScoringResult:
        """Convert this ScoringReport into a canonical ScoringResult entity."""
        cat_scores: dict[str, float] = {}
        for cat_name, cat_obj in self.category_scores.items():
            if cat_obj.category_score is not None:
                cat_scores[cat_name] = cat_obj.category_score

        return ScoringResult(
            score=self.security_score if self.security_score is not None else 0.0,
            total_tests=self.total_attacks,
            passed_tests=self.pass_count,
            failed_tests=self.fail_count,
            errored_tests=self.error_count,
            skipped_tests=self.skipped_count,
            category_scores=cat_scores,
            scoring_version=scoring_version,
            metadata={
                "weighted_penalty": self.weighted_penalty,
                "max_possible_penalty": self.max_possible_penalty,
                "evaluation_coverage": self.evaluation_coverage,
            },
        )


class ScoringResult(BaseModel):
    """Deterministic security score and comparative test metrics from Phase 2.

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
