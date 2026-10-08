"""Output formatters for Sentinel CLI commands.

Separates human-readable terminal rendering from machine-readable JSON output.
Ensures stdout and stderr streams are used appropriately.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from app.domain.gates.models import GateResult
from app.domain.scoring.models import ScoringReport


def print_json(data: Any, file=sys.stdout) -> None:
    """Render data as clean indented JSON to the designated stream."""
    if hasattr(data, "model_dump_json"):
        print(data.model_dump_json(indent=2), file=file)
    else:
        print(json.dumps(data, indent=2), file=file)


def print_scan_report_text(report: ScoringReport, file=sys.stdout) -> None:
    """Format and print human-readable summary of a ScoringReport."""
    print("=" * 65, file=file)
    print("SENTINEL SECURITY SCAN REPORT", file=file)
    print("=" * 65, file=file)

    print("\nOVERALL METRICS:", file=file)
    print("-" * 65, file=file)
    print(f"Total Attacks Requested:     {report.total_attacks}", file=file)
    print(f"Evaluated Attacks:           {report.evaluated_attacks}", file=file)
    print(f"PASS Count:                  {report.pass_count}", file=file)
    print(f"FAIL Count:                  {report.fail_count}", file=file)
    print(
        f"ERROR Count:                 {report.error_count}  (excluded from security score)",
        file=file,
    )
    print(
        f"SKIPPED Count:               {report.skipped_count}  (excluded from security score)",
        file=file,
    )
    print(file=file)

    asr_str = (
        f"{report.attack_success_rate:.2%}" if report.attack_success_rate is not None else "N/A"
    )
    score_str = (
        f"{report.security_score:.2f} / 100.0" if report.security_score is not None else "N/A"
    )

    print(f"Attack Success Rate (ASR):   {asr_str}", file=file)
    print(f"Weighted Security Penalty:   {report.weighted_penalty}", file=file)
    print(f"Max Possible Penalty:        {report.max_possible_penalty}", file=file)
    print(f"Sentinel Security Score:     {score_str}", file=file)
    print(f"Evaluation Coverage:         {report.evaluation_coverage:.2%}", file=file)

    if report.category_scores:
        print("\nCATEGORY BREAKDOWN:", file=file)
        print("-" * 65, file=file)
        print(
            f"{'Category':<28} {'Total':<6} {'Pass':<5} {'Fail':<5} "
            f"{'ASR':<8} {'Pen/Max':<10} {'Score':<8}",
            file=file,
        )
        print("-" * 75, file=file)
        for cat_name, cat in sorted(report.category_scores.items()):
            pen_str = f"{cat.weighted_penalty}/{cat.max_possible_penalty}"
            cat_score_str = f"{cat.category_score:.1f}" if cat.category_score is not None else "N/A"
            cat_asr_str = (
                f"{cat.attack_success_rate:.1%}" if cat.attack_success_rate is not None else "N/A"
            )
            print(
                f"{cat_name:<28} {cat.total_attacks:<6} {cat.pass_count:<5} {cat.fail_count:<5} "
                f"{cat_asr_str:<8} {pen_str:<10} {cat_score_str:<8}",
                file=file,
            )

    if report.critical_findings:
        print("\nCRITICAL & HIGH FINDINGS:", file=file)
        print("-" * 65, file=file)
        for finding in report.critical_findings:
            print(
                f"• [{finding.severity.upper()}] {finding.attack_id} ({finding.category})",
                file=file,
            )
            print(f"    Reason:   {finding.reason}", file=file)
            if finding.evidence:
                print(f"    Evidence: {finding.evidence[0]}", file=file)

    print("=" * 65, file=file)


def print_gate_result_text(
    result: GateResult,
    score_delta: float | None = None,
    asr_delta: float | None = None,
    file=sys.stdout,
) -> None:
    """Format and print human-readable summary of a GateResult."""
    print("=" * 65, file=file)
    print("SENTINEL SECURITY REGRESSION GATE", file=file)
    print("=" * 65, file=file)

    if score_delta is not None or asr_delta is not None:
        print("\nMETRIC DELTAS:", file=file)
        print("-" * 65, file=file)
        if score_delta is not None:
            print(
                f"Security Score Delta:     {score_delta:+.2f} points (negative = regression)",
                file=file,
            )
        if asr_delta is not None:
            print(
                f"Attack Success Rate Delta:{asr_delta:+.2%} (positive = regression)",
                file=file,
            )

    print("\nPOLICY RULE CHECKS:", file=file)
    print("-" * 65, file=file)

    for v in result.violations:
        print(f"[FAIL] {v.rule_name}", file=file)
        print(f"       Actual: {v.actual_value} | Allowed: {v.allowed_value}", file=file)
        print(f"       Reason: {v.message}", file=file)

    for w in result.warnings:
        print(f"[WARN] {w.rule_name}", file=file)
        print(f"       Actual: {w.actual_value}", file=file)
        print(f"       Notice: {w.message}", file=file)

    if not result.violations and not result.warnings:
        print("All configured security policies satisfied with zero warnings.", file=file)

    print("-" * 65, file=file)
    status_label = "[PASSED]" if result.passed else "[FAILED]"
    print(f"FINAL RESULT: {status_label} — {result.summary_message}", file=file)
    print("=" * 65, file=file)
