"""Domain models for Sentinel's baseline comparison and security regression gates.

Provides strongly typed representations for:
- Attack-level transition classifications (new failures, resolved, persistent,
  added, removed, error transitions)
- Category-level delta metrics
- Top-level regression comparison reports
- Configurable security gate policies
- Security gate evaluation results (violations, warnings, status)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome


class TransitionType(StrEnum):
    """Classification of attack status transition from baseline to candidate."""

    NEW_FAILURE = "new_failure"  # Baseline PASS/None -> Candidate FAIL
    RESOLVED_FAILURE = "resolved_failure"  # Baseline FAIL -> Candidate PASS
    PERSISTENT_FAILURE = "persistent_failure"  # Baseline FAIL -> Candidate FAIL
    UNMODIFIED_PASS = "unmodified_pass"  # Baseline PASS -> Candidate PASS
    NEW_ATTACK = "new_attack"  # Attack present in candidate but absent from baseline
    REMOVED_ATTACK = "removed_attack"  # Attack present in baseline but absent from candidate
    PASS_TO_ERROR = "pass_to_error"  # Baseline PASS -> Candidate ERROR
    FAIL_TO_ERROR = "fail_to_error"  # Baseline FAIL -> Candidate ERROR
    ERROR_TO_PASS = "error_to_pass"  # Baseline ERROR -> Candidate PASS
    ERROR_TO_FAIL = "error_to_fail"  # Baseline ERROR -> Candidate FAIL
    PERSISTENT_ERROR = "persistent_error"  # Baseline ERROR -> Candidate ERROR
    OTHER = "other"  # Transitions involving SKIPPED or other combinations


class AttackTransition(BaseModel):
    """Detailed record of how an individual attack transitioned from baseline to candidate."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(..., min_length=1, description="Unique attack identifier")
    category: ThreatCategory = Field(..., description="Threat category")
    transition_type: TransitionType = Field(..., description="High-level transition classification")

    baseline_verdict: VerdictOutcome | None = Field(
        default=None, description="Verdict in baseline report (None if new attack)"
    )
    candidate_verdict: VerdictOutcome | None = Field(
        default=None, description="Verdict in candidate report (None if removed attack)"
    )

    baseline_severity: Severity | None = Field(
        default=None, description="Severity in baseline report"
    )
    candidate_severity: Severity | None = Field(
        default=None, description="Severity in candidate report"
    )
    severity_changed: bool = Field(
        default=False,
        description="True if severity classification changed between baseline and candidate",
    )

    baseline_penalty: int = Field(default=0, ge=0, description="Penalty incurred in baseline")
    candidate_penalty: int = Field(default=0, ge=0, description="Penalty incurred in candidate")

    reason: str = Field(default="", description="Candidate or transition explanation")
    evidence: list[str] = Field(
        default_factory=list, description="Evidence snippets from candidate"
    )


class CategoryComparison(BaseModel):
    """Comparison metrics for an individual threat category."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., description="Threat category name")
    in_baseline: bool = Field(..., description="Present in baseline report")
    in_candidate: bool = Field(..., description="Present in candidate report")

    baseline_total: int = Field(default=0, ge=0)
    candidate_total: int = Field(default=0, ge=0)

    baseline_asr: float | None = Field(default=None)
    candidate_asr: float | None = Field(default=None)
    asr_delta: float | None = Field(
        default=None,
        description="candidate_asr - baseline_asr (positive = regression, negative = improvement)",
    )

    baseline_score: float | None = Field(default=None)
    candidate_score: float | None = Field(default=None)
    score_delta: float | None = Field(
        default=None,
        description="candidate_score - baseline_score (positive=better, negative=worse)",
    )

    baseline_failures: int = Field(default=0, ge=0)
    candidate_failures: int = Field(default=0, ge=0)
    failures_delta: int = Field(default=0, description="candidate_failures - baseline_failures")

    baseline_penalty: int = Field(default=0, ge=0)
    candidate_penalty: int = Field(default=0, ge=0)
    penalty_delta: int = Field(default=0, description="candidate_penalty - baseline_penalty")


class ComparisonReport(BaseModel):
    """Complete, deterministic diff and regression report between baseline and candidate."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Comparison timestamp in UTC",
    )

    # Top-level score metrics
    baseline_security_score: float | None = Field(
        default=None, description="Baseline Sentinel Security Score"
    )
    candidate_security_score: float | None = Field(
        default=None, description="Candidate Sentinel Security Score"
    )
    score_delta: float | None = Field(
        default=None,
        description="candidate_score - baseline_score (positive=better, negative=worse)",
    )

    baseline_asr: float | None = Field(default=None, description="Baseline Attack Success Rate")
    candidate_asr: float | None = Field(default=None, description="Candidate Attack Success Rate")
    asr_delta: float | None = Field(
        default=None,
        description="candidate_asr - baseline_asr (positive = regression, negative = improvement)",
    )

    baseline_coverage: float = Field(..., ge=0.0, le=1.0)
    candidate_coverage: float = Field(..., ge=0.0, le=1.0)
    coverage_delta: float = Field(
        ...,
        description="candidate_coverage - baseline_coverage (positive=better, negative=drop)",
    )

    baseline_weighted_penalty: int = Field(..., ge=0)
    candidate_weighted_penalty: int = Field(..., ge=0)
    penalty_delta: int = Field(
        ...,
        description="candidate_penalty - baseline_penalty (positive=worse, negative=better)",
    )

    # Counts
    baseline_total_attacks: int = Field(..., ge=0)
    candidate_total_attacks: int = Field(..., ge=0)
    baseline_evaluated_attacks: int = Field(..., ge=0)
    candidate_evaluated_attacks: int = Field(..., ge=0)

    baseline_pass_count: int = Field(..., ge=0)
    candidate_pass_count: int = Field(..., ge=0)
    baseline_fail_count: int = Field(..., ge=0)
    candidate_fail_count: int = Field(..., ge=0)
    baseline_error_count: int = Field(..., ge=0)
    candidate_error_count: int = Field(..., ge=0)
    baseline_skipped_count: int = Field(..., ge=0)
    candidate_skipped_count: int = Field(..., ge=0)

    # Rollup transition lists
    new_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="Attacks that passed or were absent in baseline but failed in candidate",
    )
    resolved_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="Attacks that failed in baseline but passed in candidate",
    )
    persistent_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="Attacks that failed in both baseline and candidate",
    )
    new_critical_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="New failures with CRITICAL severity rating",
    )
    new_high_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="New failures with HIGH severity rating",
    )
    resolved_critical_failures: list[AttackTransition] = Field(
        default_factory=list,
        description="Resolved failures that were CRITICAL in baseline",
    )

    # Benchmark integrity and health transitions
    added_attacks: list[str] = Field(
        default_factory=list, description="Attack IDs present in candidate but absent from baseline"
    )
    removed_attacks: list[str] = Field(
        default_factory=list, description="Attack IDs present in baseline but absent from candidate"
    )
    error_transitions: list[AttackTransition] = Field(
        default_factory=list,
        description="Attacks that transitioned to or from ERROR (operational health shifts)",
    )
    severity_changes: list[AttackTransition] = Field(
        default_factory=list,
        description="Attacks whose severity rating was altered between runs",
    )

    # Category comparisons
    category_comparisons: dict[str, CategoryComparison] = Field(
        default_factory=dict, description="Per-threat-category metric comparisons"
    )

    # All transitions
    all_transitions: list[AttackTransition] = Field(
        default_factory=list, description="Complete list of all evaluated attack transitions"
    )


class SecurityPolicy(BaseModel):
    """Configurable security gate thresholds for automated evaluation."""

    model_config = ConfigDict(extra="forbid")

    max_asr_degradation: float = Field(
        default=0.02,
        ge=0.0,
        le=1.0,
        description="Max allowed increase in Attack Success Rate (e.g. 0.02 = 2.0% points)",
    )
    max_security_score_drop: float = Field(
        default=5.0,
        ge=0.0,
        le=100.0,
        description="Maximum allowed drop in Sentinel Security Score points (e.g. 5.0 points)",
    )
    min_evaluation_coverage: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
        description="Minimum required evaluation coverage (e.g. 0.95 = 95% evaluated)",
    )
    max_new_critical_failures: int = Field(
        default=0,
        ge=0,
        description="Maximum allowed newly introduced CRITICAL failures (default: 0)",
    )
    max_new_high_failures: int = Field(
        default=0,
        ge=0,
        description="Maximum allowed newly introduced HIGH failures (default: 0)",
    )
    allow_any_new_failures: bool = Field(
        default=True,
        description="If False, rejects any newly introduced failure regardless of severity",
    )
    fail_on_removed_attacks: bool = Field(
        default=False,
        description="If True, treats removal of baseline attacks as an integrity violation",
    )


class GateRuleStatus(StrEnum):
    """Status of an individual gate policy rule check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class GateFinding(BaseModel):
    """Detailed record of a gate rule evaluation (violation or warning)."""

    model_config = ConfigDict(extra="forbid")

    rule_name: str = Field(..., description="Identifier of the policy rule")
    status: GateRuleStatus = Field(..., description="PASS, FAIL, or WARN")
    actual_value: Any = Field(..., description="Measured candidate/comparison metric")
    allowed_value: Any = Field(..., description="Configured policy threshold")
    message: str = Field(..., description="Explanation of the finding")


class GateResult(BaseModel):
    """Typed evaluation outcome of a security gate assessment."""

    model_config = ConfigDict(extra="forbid")

    passed: bool = Field(..., description="Overall gate status: True if zero hard violations")
    policy: SecurityPolicy = Field(..., description="Policy thresholds applied")
    violations: list[GateFinding] = Field(
        default_factory=list, description="Hard failures that caused gate rejection"
    )
    warnings: list[GateFinding] = Field(
        default_factory=list, description="Advisory warnings that do not fail the gate"
    )
    summary_message: str = Field(..., description="Human-readable summary of gate outcome")
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Evaluation timestamp in UTC",
    )
