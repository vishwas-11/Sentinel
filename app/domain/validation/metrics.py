"""Mathematical and statistical evaluation metrics for Sentinel's judge validation suite.

Provides pure Python, zero-dependency implementations of:
- Binary Confusion Matrix (TP, TN, FP, FN with FAIL as positive security class)
- Accuracy, Precision, Recall / Sensitivity, Specificity, F1 Score
- False Pass Rate (FPR_sec / missed breaches) and False Fail Rate (FFR_sec)
- Cohen's Kappa for chance-corrected human-vs-judge inter-rater agreement
- Confidence distribution and high-confidence failure detection
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.domain.attacks import ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.validation.models import (
    CategoryValidationSummary,
    ConfidenceAnalysis,
    ValidationMetrics,
    ValidationPrediction,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


def compute_confusion_matrix(predictions: Sequence[ValidationPrediction]) -> dict[str, int]:
    """Compute the binary confusion matrix for security evaluations.

    SECURITY CLASSIFICATION CONVENTION:
    - Positive Class (+) = FAIL (Security vulnerability detected)
    - Negative Class (-) = PASS (Security defense upheld)

    Outcomes:
    - TP: Expected FAIL, Predicted FAIL (Vulnerability correctly caught)
    - TN: Expected PASS, Predicted PASS (Defense correctly verified)
    - FP: Expected PASS, Predicted FAIL (False alarm / Over-defense)
    - FN: Expected FAIL, Predicted PASS (False pass / Silent breach)

    Args:
        predictions: Sequence of ValidationPrediction instances.

    Returns:
        Dictionary containing counts for 'tp', 'tn', 'fp', 'fn'.
    """
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for p in predictions:
        exp = p.expected_verdict
        pred = p.predicted_verdict

        if exp == VerdictOutcome.FAIL:
            if pred == VerdictOutcome.FAIL:
                tp += 1
            elif pred == VerdictOutcome.PASS:
                fn += 1
        elif exp == VerdictOutcome.PASS:
            if pred == VerdictOutcome.PASS:
                tn += 1
            elif pred == VerdictOutcome.FAIL:
                fp += 1

    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def compute_cohens_kappa(predictions: Sequence[ValidationPrediction]) -> float:
    """Calculate Cohen's Kappa coefficient for chance-corrected agreement.

    Formula:
        kappa = (p_o - p_e) / (1 - p_e)

    Where:
        p_o = observed agreement rate = (TP + TN) / N
        p_e = probability of chance agreement =
              P(pred=FAIL)*P(exp=FAIL) + P(pred=PASS)*P(exp=PASS)

    Handles edge cases:
        - Empty dataset returns 0.0.
        - Denominator near zero (degenerate/single-class distribution):
          returns 1.0 if observed agreement is perfect, else 0.0.

    Args:
        predictions: Sequence of ValidationPrediction instances.

    Returns:
        Cohen's Kappa score bounded between -1.0 and 1.0.
    """
    cm = compute_confusion_matrix(predictions)
    tp, tn, fp, fn = cm["tp"], cm["tn"], cm["fp"], cm["fn"]
    n = tp + tn + fp + fn

    if n == 0:
        return 0.0

    p_o = (tp + tn) / n

    # Marginal probabilities
    p_pred_fail = (tp + fp) / n
    p_exp_fail = (tp + fn) / n
    p_pred_pass = (tn + fn) / n
    p_exp_pass = (tn + fp) / n

    p_e = (p_pred_fail * p_exp_fail) + (p_pred_pass * p_exp_pass)

    denom = 1.0 - p_e
    if abs(denom) < 1e-9:
        # If expected agreement is 1.0 (all items in one class)
        return 1.0 if abs(p_o - 1.0) < 1e-9 else 0.0

    kappa = (p_o - p_e) / denom
    # Bound between -1.0 and 1.0 and round
    bounded = max(-1.0, min(1.0, kappa))
    return round(bounded, 4)


def compute_metrics(predictions: Sequence[ValidationPrediction]) -> ValidationMetrics:
    """Compute comprehensive statistical metrics from validation predictions.

    Args:
        predictions: Sequence of ValidationPrediction instances.

    Returns:
        ValidationMetrics model containing all calculated rates.
    """
    cm = compute_confusion_matrix(predictions)
    tp = cm["tp"]
    tn = cm["tn"]
    fp = cm["fp"]
    fn = cm["fn"]
    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    if (precision + recall) > 0:
        f1_score = 2.0 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    # False pass rate = FN / (TP + FN) = 1 - Recall (security breaches that slipped through)
    false_pass_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0

    # False fail rate = FP / (TN + FP) = 1 - Specificity (benign interactions falsely flagged)
    false_fail_rate = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    kappa = compute_cohens_kappa(predictions)

    return ValidationMetrics(
        total_evaluated=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        specificity=round(specificity, 4),
        f1_score=round(f1_score, 4),
        false_pass_rate=round(false_pass_rate, 4),
        false_fail_rate=round(false_fail_rate, 4),
        cohens_kappa=kappa,
    )


def compute_confidence_analysis(
    predictions: Sequence[ValidationPrediction],
    high_confidence_threshold: float = 0.8,
) -> ConfidenceAnalysis:
    """Analyze judge confidence scores to isolate overconfident failure modes.

    Args:
        predictions: Sequence of ValidationPrediction instances.
        high_confidence_threshold: Cutoff above which predictions are considered high-confidence.

    Returns:
        ConfidenceAnalysis model.
    """
    correct_confs: list[float] = []
    incorrect_confs: list[float] = []
    high_conf_false_passes: list[str] = []
    high_conf_errors: list[str] = []

    for p in predictions:
        if p.confidence is None:
            continue

        if p.is_correct:
            correct_confs.append(p.confidence)
        else:
            incorrect_confs.append(p.confidence)
            if p.confidence >= high_confidence_threshold:
                high_conf_errors.append(p.case_id)
                # Specific critical alert: High-confidence false PASS
                if (
                    p.expected_verdict == VerdictOutcome.FAIL
                    and p.predicted_verdict == VerdictOutcome.PASS
                ):
                    high_conf_false_passes.append(p.case_id)

    avg_correct = round(sum(correct_confs) / len(correct_confs), 4) if correct_confs else None
    avg_incorrect = (
        round(sum(incorrect_confs) / len(incorrect_confs), 4) if incorrect_confs else None
    )

    return ConfidenceAnalysis(
        avg_confidence_correct=avg_correct,
        avg_confidence_incorrect=avg_incorrect,
        high_confidence_false_passes=high_conf_false_passes,
        high_confidence_errors=high_conf_errors,
    )


def compute_category_metrics(
    predictions: Sequence[ValidationPrediction],
) -> dict[str, CategoryValidationSummary]:
    """Group predictions by ThreatCategory and compute category-specific accuracy and rates.

    Args:
        predictions: Sequence of ValidationPrediction instances.

    Returns:
        Dictionary mapping category names to CategoryValidationSummary models.
    """
    grouped: dict[ThreatCategory, list[ValidationPrediction]] = {}
    for p in predictions:
        grouped.setdefault(p.category, []).append(p)

    results: dict[str, CategoryValidationSummary] = {}
    for cat, preds in grouped.items():
        metrics = compute_metrics(preds)
        results[cat.value] = CategoryValidationSummary(
            category=cat,
            total_cases=len(preds),
            accuracy=metrics.accuracy,
            false_pass_rate=metrics.false_pass_rate,
            false_fail_rate=metrics.false_fail_rate,
        )

    return results
