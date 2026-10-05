"""Domain models for Sentinel's LLM judge validation and benchmark suite."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domain.attacks import AttackPayload, Severity, TestCase, ThreatCategory
from app.domain.evaluation.models import (
    JudgeVerdict,
    TestExecutionRecord,
    VerdictOutcome,
)
from app.domain.targets import ObservableToolCall, TargetResult


class ValidationCase(BaseModel):
    """A human-labeled benchmark case for validating evaluator accuracy.

    Encapsulates complete context required to reconstruct a TestExecutionRecord,
    paired with human ground-truth verdict and detailed rationale.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Unique validation benchmark case identifier")
    attack_id: str = Field(..., min_length=1, description="Associated attack payload identifier")
    category: ThreatCategory = Field(..., description="Target threat category under test")
    severity: Severity = Field(default=Severity.MEDIUM, description="Vulnerability severity impact")
    prompt: str = Field(..., min_length=1, description="Adversarial attack prompt")
    objective: str = Field(..., min_length=1, description="Security violation objective")
    target_response: str | None = Field(
        default=None,
        description="Target application output text to evaluate",
    )
    target_status: str = Field(
        default="success",
        description="Execution status of the target application ('success' or 'error')",
    )
    observed_tool_calls: list[ObservableToolCall] = Field(
        default_factory=list,
        description="Tool call traces captured during target execution",
    )
    target_error: str | None = Field(
        default=None,
        description="Target transport or execution error if status is 'error'",
    )
    expected_verdict: VerdictOutcome = Field(
        ...,
        description="Human-labeled ground-truth outcome (PASS, FAIL, etc.)",
    )
    rationale: str = Field(
        ...,
        min_length=10,
        description="Human annotator justification explaining why this verdict was assigned",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Classification tags (e.g. 'clear_pass', 'prompt_injection')",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary benchmark provenance or target metadata",
    )

    @field_validator("id", "attack_id", "prompt", "objective", "rationale")
    @classmethod
    def validate_non_whitespace(cls, v: str) -> str:
        """Ensure string fields contain non-whitespace characters."""
        if not v.strip():
            raise ValueError("Field must contain non-whitespace characters.")
        return v.strip()

    def to_execution_record(self) -> TestExecutionRecord:
        """Convert this validation benchmark case into a canonical TestExecutionRecord.

        Returns:
            TestExecutionRecord instance ready for evaluator execution.
        """
        attack = AttackPayload(
            id=self.attack_id,
            category=self.category,
            severity=self.severity,
            prompt=self.prompt,
            objective=self.objective,
            tags=self.tags,
            metadata=self.metadata,
        )
        test_case = TestCase(
            id=self.id,
            attack=attack,
            session_id=f"sess_{self.id}",
            metadata={"validation_case_id": self.id},
        )
        target_result = TargetResult(
            response=self.target_response,
            status=self.target_status,
            tool_calls=self.observed_tool_calls,
            latency_ms=0.0,
            error=self.target_error,
        )
        return TestExecutionRecord(test_case=test_case, target_result=target_result)


class ValidationPrediction(BaseModel):
    """Individual prediction record comparing expected ground truth against judge verdict."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Validation case identifier")
    category: ThreatCategory = Field(..., description="Threat category")
    expected_verdict: VerdictOutcome = Field(..., description="Human ground-truth verdict")
    predicted_verdict: VerdictOutcome = Field(..., description="Evaluator predicted verdict")
    confidence: float | None = Field(
        default=None,
        description="Judge model self-assessed confidence score (0.0 to 1.0)",
    )
    reason: str = Field(..., description="Judge explanation for the verdict")
    evidence: list[str] = Field(default_factory=list, description="Extracted evidence snippets")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Evaluation latency in milliseconds")
    tags: list[str] = Field(default_factory=list, description="Tags associated with the case")
    is_correct: bool = Field(..., description="Whether predicted verdict matches expected verdict")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Evaluation telemetry or stage information",
    )

    @classmethod
    def from_verdict(
        cls,
        case: ValidationCase,
        verdict: JudgeVerdict,
        latency_ms: float = 0.0,
    ) -> ValidationPrediction:
        """Create a ValidationPrediction by evaluating a ValidationCase with a JudgeVerdict."""
        is_correct = case.expected_verdict == verdict.outcome
        return cls(
            case_id=case.id,
            category=case.category,
            expected_verdict=case.expected_verdict,
            predicted_verdict=verdict.outcome,
            confidence=verdict.confidence,
            reason=verdict.reason,
            evidence=verdict.evidence,
            latency_ms=latency_ms,
            tags=case.tags,
            is_correct=is_correct,
            metadata=verdict.metadata,
        )


class ValidationMetrics(BaseModel):
    """Statistical evaluation metrics for the security judge benchmark.

    Security Classification Convention:
    - Positive Class (+) = FAIL (Security vulnerability detected)
    - Negative Class (-) = PASS (Defense held / Security maintained)
    """

    model_config = ConfigDict(extra="forbid")

    total_evaluated: int = Field(..., ge=0, description="Total binary-evaluable cases (PASS/FAIL)")
    true_positives: int = Field(..., ge=0, description="Expected FAIL, Predicted FAIL")
    true_negatives: int = Field(..., ge=0, description="Expected PASS, Predicted PASS")
    false_positives: int = Field(
        ..., ge=0, description="Expected PASS, Predicted FAIL (False Alarm)"
    )
    false_negatives: int = Field(
        ..., ge=0, description="Expected FAIL, Predicted PASS (False Pass / Silent Breach)"
    )

    accuracy: float = Field(..., ge=0.0, le=1.0, description="(TP + TN) / Total")
    precision: float = Field(..., ge=0.0, le=1.0, description="TP / (TP + FP)")
    recall: float = Field(..., ge=0.0, le=1.0, description="Sensitivity / TPR = TP / (TP + FN)")
    specificity: float = Field(
        ..., ge=0.0, le=1.0, description="TNR = TN / (TN + FP), defense verification rate"
    )
    f1_score: float = Field(
        ..., ge=0.0, le=1.0, description="Harmonic mean of precision and recall"
    )
    false_pass_rate: float = Field(
        ..., ge=0.0, le=1.0, description="Security FNR = FN / (TP + FN); missed breaches"
    )
    false_fail_rate: float = Field(
        ..., ge=0.0, le=1.0, description="Security FPR = FP / (TN + FP); false alarms"
    )
    cohens_kappa: float = Field(
        ..., ge=-1.0, le=1.0, description="Inter-annotator agreement chance-corrected metric"
    )


class ConfidenceAnalysis(BaseModel):
    """Analysis of model self-assessed confidence scores vs empirical correctness."""

    model_config = ConfigDict(extra="forbid")

    avg_confidence_correct: float | None = Field(
        default=None,
        description="Average confidence when the judge predicted correctly",
    )
    avg_confidence_incorrect: float | None = Field(
        default=None,
        description="Average confidence when the judge was wrong",
    )
    high_confidence_false_passes: list[str] = Field(
        default_factory=list,
        description="Case IDs where model had high confidence (>= 0.8) on a False PASS",
    )
    high_confidence_errors: list[str] = Field(
        default_factory=list,
        description="Case IDs where model had high confidence (>= 0.8) on any incorrect verdict",
    )


class CategoryValidationSummary(BaseModel):
    """Per-category metrics breakdown."""

    model_config = ConfigDict(extra="forbid")

    category: ThreatCategory = Field(..., description="Threat category")
    total_cases: int = Field(..., ge=0, description="Total cases in category")
    accuracy: float = Field(..., ge=0.0, le=1.0, description="Accuracy in category")
    false_pass_rate: float = Field(..., ge=0.0, le=1.0, description="False pass rate in category")
    false_fail_rate: float = Field(..., ge=0.0, le=1.0, description="False fail rate in category")


class ValidationReport(BaseModel):
    """Complete serialized report of a validation suite benchmark execution."""

    model_config = ConfigDict(extra="forbid")

    evaluator_name: str = Field(..., description="Identifier of the evaluated judge or pipeline")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Execution timestamp in UTC",
    )
    total_cases: int = Field(..., ge=0, description="Total validation cases loaded")
    evaluated_cases: int = Field(..., ge=0, description="Total cases evaluated")
    skipped_cases: int = Field(..., ge=0, description="Cases skipped or not evaluable")
    error_cases: int = Field(..., ge=0, description="Cases that produced an ERROR verdict")
    metrics: ValidationMetrics = Field(..., description="Overall statistical evaluation metrics")
    confidence_analysis: ConfidenceAnalysis = Field(
        ..., description="Model confidence breakdown and high-confidence failure alerts"
    )
    prompt_injection_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Resistance statistics against prompt-injection cases",
    )
    per_category_metrics: dict[str, CategoryValidationSummary] = Field(
        default_factory=dict,
        description="Metrics breakdown grouped by threat category",
    )
    predictions: list[ValidationPrediction] = Field(
        default_factory=list,
        description="Individual prediction details for all evaluated benchmark cases",
    )
