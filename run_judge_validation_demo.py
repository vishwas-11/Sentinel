"""Educational manual verification demo for Sentinel Phase 8 Judge Validation Suite.

Demonstrates running the benchmark dataset against an LLM judge, calculating
security-focused confusion matrix metrics, Cohen's Kappa, prompt-injection
resistance rates, and confidence risk analysis.

Usage:
    # Run deterministic mock validation (default, zero API cost)
    uv run python run_judge_validation_demo.py

    # Optional: Run against live OpenAI provider (requires LLM_API_KEY)
    uv run python run_judge_validation_demo.py --provider openai
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from app.core.config import get_settings
from app.domain.evaluation.judge import LLMJudge
from app.domain.evaluation.models import VerdictOutcome
from app.domain.validation.runner import JudgeValidationRunner
from app.infrastructure.llm.factory import create_llm_provider
from app.infrastructure.llm.mock import MockLLMProvider


async def main() -> None:
    """Run validation benchmark and print structured report."""
    parser = argparse.ArgumentParser(description="Sentinel Judge Validation Suite Demo")
    parser.add_argument(
        "--provider",
        choices=["mock", "openai"],
        default="mock",
        help="LLM provider to validate (default: mock)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Number of benchmark cases to evaluate (default: all)",
    )
    args = parser.parse_args()

    print("=" * 68)
    print("SENTINEL PHASE 8 — JUDGE VALIDATION & BENCHMARK SUITE")
    print("=" * 68)

    # 1. Load benchmark dataset
    dataset_path = Path(__file__).parent / "validation" / "datasets" / "judge_validation.json"
    if not dataset_path.is_file():
        print(f"ERROR: Benchmark dataset missing at {dataset_path.resolve()}", file=sys.stderr)
        sys.exit(1)

    runner = JudgeValidationRunner.from_json_file(dataset_path)
    total_available = len(runner.cases)
    active_cases = runner.cases[: args.limit] if args.limit else runner.cases

    print("\n[1] Benchmark Dataset Loaded:")
    print(f"    Total Cases in Dataset: {total_available}")
    print(f"    Evaluating Active Cases: {len(active_cases)}")
    print(f"    Source File:            {dataset_path.name}")

    # 2. Configure Evaluator Provider
    settings = get_settings()
    is_live_provider = False

    if args.provider == "openai":
        if not settings.llm_api_key and not os.getenv("LLM_API_KEY"):
            print("\n[!] WARNING: OpenAI provider requested but LLM_API_KEY is not configured.")
            print(
                "    Real-provider validation was not executed; falling back to informative notice."
            )
            print("    Run with valid LLM_API_KEY in environment to execute real API validation.")
            return

        print("\n[2] Configuring Live Provider (OpenAI):")
        print(f"    Model: {settings.llm_model}")
        provider = create_llm_provider(settings)
        is_live_provider = True
    else:
        print("\n[2] Configuring Deterministic Mock Provider (Zero API Cost):")
        print("    NOTE: Real-provider validation was not executed; deterministic")
        print("    MockLLMProvider validation is being performed for pipeline demonstration.")
        # Build realistic responses: 97% aligned with ground truth, simulating 2 realistic
        # subtle failures (1 false pass on a tricky prompt injection, 1 false alarm)
        # to showcase the confusion matrix, Cohen's Kappa, and High-Confidence False Pass alerting.
        responses_queue = []
        for case in active_cases:
            if case.id == "val_pi_001":
                # Simulated subtle failure: judge fooled by prompt injection into predicting PASS
                verdict_val = "PASS"
                conf_val = 0.90
                reason_val = "Simulated false pass: Evaluator followed injected text instruction."
            elif case.id == "val_edge_006":
                # Simulated false alarm: judge was overly strict on creative writing framing
                verdict_val = "FAIL"
                conf_val = 0.75
                reason_val = "Simulated false alarm: Flagged fictional narrative as violation."
            else:
                verdict_val = case.expected_verdict.value
                conf_val = 0.96
                reason_val = f"Evaluated defense evidence for {case.id} correctly."

            payload = {
                "verdict": verdict_val,
                "confidence": conf_val,
                "reason": reason_val,
                "evidence": [case.target_response[:60]] if case.target_response else [],
            }
            import json

            responses_queue.append(json.dumps(payload))

        provider = MockLLMProvider(
            responses_queue=responses_queue,
            model_name="mock-calibrated-judge",
        )

    judge = LLMJudge(provider=provider, name=f"calibrated_{provider.model_name}")

    # 3. Execute Benchmark Run
    print(f"\n[3] Executing Benchmark across {len(active_cases)} cases...")
    report = await runner.run(judge, cases=active_cases)

    # 4. Display Report Summary
    cm = report.metrics
    conf = report.confidence_analysis
    pi = report.prompt_injection_summary

    exp_fail = sum(1 for c in active_cases if c.expected_verdict == VerdictOutcome.FAIL)
    exp_pass = sum(1 for c in active_cases if c.expected_verdict == VerdictOutcome.PASS)

    pred_fail = cm.true_positives + cm.false_positives
    pred_pass = cm.true_negatives + cm.false_negatives

    print("\n" + "=" * 68)
    print("VALIDATION BENCHMARK RESULTS")
    print("=" * 68)
    print(f"Evaluator:              {report.evaluator_name}")
    print(f"Provider Type:          {'LIVE API' if is_live_provider else 'DETERMINISTIC MOCK'}")
    print(f"Total Evaluated:        {report.evaluated_cases}")
    print(f"Execution Timestamp:    {report.timestamp.isoformat()}")

    print("\n[Ground Truth vs Predictions]")
    print(f"  Expected FAIL (Breaches):   {exp_fail}")
    print(f"  Expected PASS (Defenses):   {exp_pass}")
    print(f"  Predicted FAIL:             {pred_fail}")
    print(f"  Predicted PASS:             {pred_pass}")

    print("\n[Confusion Matrix (FAIL = Positive Security Class)]")
    print(f"  True Positives  (TP):       {cm.true_positives:<4} [Caught Breaches]")
    print(f"  True Negatives  (TN):       {cm.true_negatives:<4} [Verified Defenses]")
    print(f"  False Positives (FP):       {cm.false_positives:<4} [False Alarms / Over-Defense]")
    print(f"  False Negatives (FN):       {cm.false_negatives:<4} [FALSE PASS / Missed Breaches]")

    print("\n[Statistical Metrics]")
    print(f"  Accuracy:                   {cm.accuracy * 100:.2f}%")
    print(f"  Precision:                  {cm.precision * 100:.2f}%")
    print(f"  Recall (Sensitivity / TPR): {cm.recall * 100:.2f}%")
    print(f"  Specificity (TNR):          {cm.specificity * 100:.2f}%")
    print(f"  F1 Score:                   {cm.f1_score:.4f}")
    print(f"  Cohen's Kappa (Agreement):  {cm.cohens_kappa:.4f}")
    print(
        f"  False Pass Rate (FPR_sec):  {cm.false_pass_rate * 100:.2f}%  <-- Critical Security Risk"
    )
    print(f"  False Fail Rate (FFR_sec):  {cm.false_fail_rate * 100:.2f}%")

    print("\n[Prompt-Injection Robustness Analysis]")
    print(f"  Total Injected Cases:       {pi.get('total_cases', 0)}")
    print(f"  Resisted Deceptions:        {pi.get('resisted_count', 0)}")
    print(f"  Bypassed / Tricked:         {pi.get('bypassed_count', 0)}")
    print(f"  Resistance Rate:            {pi.get('resistance_rate', 1.0) * 100:.2f}%")

    print("\n[Confidence Analysis]")
    print(f"  Avg Confidence (Correct):   {conf.avg_confidence_correct or 'N/A'}")
    print(f"  Avg Confidence (Incorrect): {conf.avg_confidence_incorrect or 'N/A'}")
    print(f"  High-Conf False Passes:     {len(conf.high_confidence_false_passes)}")
    if conf.high_confidence_false_passes:
        print(f"  Alert Case IDs:             {conf.high_confidence_false_passes}")

    print("\n[Threat Category Breakdown]")
    for cat_name, cat_summary in report.per_category_metrics.items():
        print(
            f"  {cat_name:<28} Cases: {cat_summary.total_cases:<2} "
            f"Acc: {cat_summary.accuracy * 100:.1f}% "
            f"FPR: {cat_summary.false_pass_rate * 100:.1f}%"
        )

    print("\n" + "=" * 68)
    print("VALIDATION SUITE DEMONSTRATION COMPLETE")
    print("=" * 68)


if __name__ == "__main__":
    asyncio.run(main())
