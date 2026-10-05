"""Validation runner for executing benchmarks against semantic judges and hybrid pipelines."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from app.domain.evaluation.models import JudgeVerdict, TestExecutionRecord, VerdictOutcome
from app.domain.validation.metrics import (
    compute_category_metrics,
    compute_confidence_analysis,
    compute_metrics,
)
from app.domain.validation.models import (
    ValidationCase,
    ValidationPrediction,
    ValidationReport,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


class JudgeEvaluator(Protocol):
    """Protocol for any evaluator capable of asynchronously rendering a JudgeVerdict."""

    @property
    def name(self) -> str:
        """Evaluator identifier."""
        ...

    async def judge(self, record: TestExecutionRecord) -> JudgeVerdict:
        """Render a JudgeVerdict for a TestExecutionRecord."""
        ...


class JudgeValidationRunner:
    """Orchestrates benchmark validation of Sentinel judges against human ground truth.

    Responsibilities:
    - Loads and validates benchmark datasets from JSON files or in-memory lists.
    - Ensures unique benchmark case IDs and valid ground-truth annotations.
    - Executes benchmark cases sequentially against any JudgeEvaluator (LLMJudge or Orchestrator).
    - Preserves evidence, telemetry, latency, and model confidence scores.
    - Generates typed, serializable ValidationReport summaries.
    """

    def __init__(self, cases: Sequence[ValidationCase] | None = None) -> None:
        """Initialize the validation runner with an optional list of benchmark cases."""
        self._cases: list[ValidationCase] = []
        if cases is not None:
            self.load_cases(cases)

    @classmethod
    def from_json_file(cls, file_path: str | Path) -> JudgeValidationRunner:
        """Load benchmark cases from a JSON file and instantiate runner.

        Args:
            file_path: Absolute or relative path to the benchmark JSON dataset.

        Returns:
            Configured JudgeValidationRunner instance.

        Raises:
            FileNotFoundError: If file_path does not exist.
            ValueError: If JSON is malformed or contains duplicate case IDs.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Validation dataset file not found: {path.resolve()}")

        try:
            with open(path, encoding="utf-8") as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as err:
            raise ValueError(f"Malformed JSON in validation dataset '{path}': {err}") from err

        if not isinstance(raw_data, list):
            raise ValueError(
                f"Validation dataset must be a JSON array of cases, got {type(raw_data).__name__}"
            )

        runner = cls()
        runner.load_raw_cases(raw_data)
        return runner

    def load_cases(self, cases: Sequence[ValidationCase]) -> None:
        """Load and validate an in-memory sequence of ValidationCase instances.

        Args:
            cases: Sequence of ValidationCase objects.

        Raises:
            ValueError: If duplicate case IDs are detected.
        """
        seen_ids: set[str] = set()
        validated: list[ValidationCase] = []

        for case in cases:
            if case.id in seen_ids:
                raise ValueError(f"Duplicate validation case ID detected: '{case.id}'")
            seen_ids.add(case.id)
            validated.append(case)

        self._cases = validated

    def load_raw_cases(self, raw_cases: Sequence[dict[str, Any]]) -> None:
        """Parse, validate, and load raw case dictionaries.

        Args:
            raw_cases: Sequence of raw case dictionaries.

        Raises:
            ValueError: If validation fails or duplicate IDs exist.
        """
        parsed_cases: list[ValidationCase] = []
        for idx, item in enumerate(raw_cases):
            try:
                parsed_cases.append(ValidationCase.model_validate(item))
            except Exception as err:
                case_id = item.get("id", "unknown")
                raise ValueError(
                    f"Validation failed for case at index {idx} (ID: {case_id}): {err}"
                ) from err

        self.load_cases(parsed_cases)

    @property
    def cases(self) -> list[ValidationCase]:
        """Return a copy of the loaded benchmark cases."""
        return list(self._cases)

    async def run(
        self,
        evaluator: JudgeEvaluator,
        cases: Sequence[ValidationCase] | None = None,
    ) -> ValidationReport:
        """Execute benchmark cases against the given evaluator and generate a ValidationReport.

        Args:
            evaluator: Evaluator implementing JudgeEvaluator (LLMJudge or Orchestrator).
            cases: Optional subset of cases to execute; defaults to all loaded cases.

        Returns:
            ValidationReport with full confusion matrix, metrics, and failure diagnostics.
        """
        active_cases = list(cases) if cases is not None else self._cases
        if not active_cases:
            logger.warning("JudgeValidationRunner executed with 0 cases.")

        predictions: list[ValidationPrediction] = []
        error_count = 0
        skipped_count = 0

        for case in active_cases:
            rec = case.to_execution_record()
            start = time.perf_counter()
            try:
                verdict = await evaluator.judge(rec)
            except Exception as err:
                logger.error(
                    "Evaluator '%s' raised unexpected exception on case '%s': %s",
                    evaluator.name,
                    case.id,
                    err,
                )
                verdict = JudgeVerdict(
                    outcome=VerdictOutcome.ERROR,
                    confidence=None,
                    reason=f"Runner caught unhandled evaluator exception: {err}",
                    evidence=[],
                    source=evaluator.name,
                    metadata={"runner_error": str(err)},
                )

            latency_ms = (time.perf_counter() - start) * 1000.0

            if verdict.outcome == VerdictOutcome.ERROR:
                error_count += 1
            elif verdict.outcome == VerdictOutcome.SKIPPED:
                skipped_count += 1

            pred = ValidationPrediction.from_verdict(case, verdict, latency_ms)
            predictions.append(pred)

        # Compute metrics
        metrics = compute_metrics(predictions)
        confidence_analysis = compute_confidence_analysis(predictions)
        category_metrics = compute_category_metrics(predictions)

        # Prompt injection robustness summary
        pi_preds = [p for p in predictions if "prompt_injection" in p.tags]
        pi_total = len(pi_preds)
        pi_correct = sum(1 for p in pi_preds if p.is_correct)
        pi_false_passes = [
            p.case_id
            for p in pi_preds
            if p.expected_verdict == VerdictOutcome.FAIL
            and p.predicted_verdict == VerdictOutcome.PASS
        ]

        prompt_injection_summary = {
            "total_cases": pi_total,
            "resisted_count": pi_correct,
            "bypassed_count": pi_total - pi_correct,
            "resistance_rate": round(pi_correct / pi_total, 4) if pi_total > 0 else 1.0,
            "bypassed_case_ids": pi_false_passes,
        }

        return ValidationReport(
            evaluator_name=evaluator.name,
            timestamp=datetime.now(UTC),
            total_cases=len(active_cases),
            evaluated_cases=len(predictions),
            skipped_cases=skipped_count,
            error_cases=error_count,
            metrics=metrics,
            confidence_analysis=confidence_analysis,
            prompt_injection_summary=prompt_injection_summary,
            per_category_metrics=category_metrics,
            predictions=predictions,
        )
