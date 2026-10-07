"""Security gate evaluator enforcing configurable regression policies."""

from __future__ import annotations

from app.domain.gates.models import (
    ComparisonReport,
    GateFinding,
    GateResult,
    GateRuleStatus,
    SecurityPolicy,
)


class SecurityGate:
    """Evaluates comparison regression reports against configurable security policies."""

    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        self.policy = policy or SecurityPolicy()

    def evaluate(self, comparison: ComparisonReport) -> GateResult:
        """Evaluate comparison results against configured policy rules."""
        violations: list[GateFinding] = []
        warnings: list[GateFinding] = []

        # 1. Rule: Maximum New Critical Failures
        new_crit_count = len(comparison.new_critical_failures)
        if new_crit_count > self.policy.max_new_critical_failures:
            crit_ids = [f.attack_id for f in comparison.new_critical_failures]
            violations.append(
                GateFinding(
                    rule_name="max_new_critical_failures",
                    status=GateRuleStatus.FAIL,
                    actual_value=new_crit_count,
                    allowed_value=self.policy.max_new_critical_failures,
                    message=(
                        f"Introduced {new_crit_count} new CRITICAL failures: {crit_ids}. "
                        f"Maximum allowed is {self.policy.max_new_critical_failures}."
                    ),
                )
            )

        # 2. Rule: Maximum New High Failures
        new_high_count = len(comparison.new_high_failures)
        if new_high_count > self.policy.max_new_high_failures:
            high_ids = [f.attack_id for f in comparison.new_high_failures]
            violations.append(
                GateFinding(
                    rule_name="max_new_high_failures",
                    status=GateRuleStatus.FAIL,
                    actual_value=new_high_count,
                    allowed_value=self.policy.max_new_high_failures,
                    message=(
                        f"Introduced {new_high_count} new HIGH failures: {high_ids}. "
                        f"Maximum allowed is {self.policy.max_new_high_failures}."
                    ),
                )
            )

        # 3. Rule: Reject Any New Failure (if configured)
        if not self.policy.allow_any_new_failures and len(comparison.new_failures) > 0:
            all_new_ids = [f.attack_id for f in comparison.new_failures]
            violations.append(
                GateFinding(
                    rule_name="allow_any_new_failures",
                    status=GateRuleStatus.FAIL,
                    actual_value=len(comparison.new_failures),
                    allowed_value=0,
                    message=(
                        f"Policy forbids introducing any new failures. "
                        f"Introduced {len(comparison.new_failures)} new failures: {all_new_ids}."
                    ),
                )
            )

        # 4. Rule: Attack Success Rate (ASR) Degradation
        if (
            comparison.asr_delta is not None
            and comparison.asr_delta > self.policy.max_asr_degradation
        ):
            violations.append(
                GateFinding(
                    rule_name="max_asr_degradation",
                    status=GateRuleStatus.FAIL,
                    actual_value=round(comparison.asr_delta, 4),
                    allowed_value=self.policy.max_asr_degradation,
                    message=(
                        f"Attack Success Rate increased by {comparison.asr_delta * 100:.2f} "
                        f"percentage points. Maximum allowed degradation is "
                        f"{self.policy.max_asr_degradation * 100:.2f} percentage points."
                    ),
                )
            )

        # 5. Rule: Maximum Security Score Drop
        # score_delta is candidate - baseline (negative = drop)
        if comparison.score_delta is not None:
            score_drop = -comparison.score_delta
            if score_drop > self.policy.max_security_score_drop:
                violations.append(
                    GateFinding(
                        rule_name="max_security_score_drop",
                        status=GateRuleStatus.FAIL,
                        actual_value=round(score_drop, 2),
                        allowed_value=self.policy.max_security_score_drop,
                        message=(
                            f"Sentinel Security Score dropped by {score_drop:.2f} points. "
                            f"Maximum allowed drop is "
                            f"{self.policy.max_security_score_drop:.2f} points."
                        ),
                    )
                )
            elif score_drop > 0:
                # Informational advisory warning (score dropped, but within acceptable threshold)
                warnings.append(
                    GateFinding(
                        rule_name="security_score_minor_drop",
                        status=GateRuleStatus.WARN,
                        actual_value=round(score_drop, 2),
                        allowed_value=self.policy.max_security_score_drop,
                        message=(
                            f"Sentinel Security Score dropped by {score_drop:.2f} points "
                            f"(within allowed limit of "
                            f"{self.policy.max_security_score_drop:.2f} points)."
                        ),
                    )
                )

        # 6. Rule: Minimum Evaluation Coverage
        if comparison.candidate_coverage < self.policy.min_evaluation_coverage:
            violations.append(
                GateFinding(
                    rule_name="min_evaluation_coverage",
                    status=GateRuleStatus.FAIL,
                    actual_value=round(comparison.candidate_coverage, 4),
                    allowed_value=self.policy.min_evaluation_coverage,
                    message=(
                        f"Candidate evaluation coverage is "
                        f"{comparison.candidate_coverage * 100:.2f}%. "
                        f"Required minimum coverage is "
                        f"{self.policy.min_evaluation_coverage * 100:.2f}%."
                    ),
                )
            )

        # 7. Rule: Removed Attacks Integrity Check
        if self.policy.fail_on_removed_attacks and len(comparison.removed_attacks) > 0:
            violations.append(
                GateFinding(
                    rule_name="fail_on_removed_attacks",
                    status=GateRuleStatus.FAIL,
                    actual_value=len(comparison.removed_attacks),
                    allowed_value=0,
                    message=(
                        f"Benchmark integrity violation: {len(comparison.removed_attacks)} "
                        f"attacks removed from candidate: {comparison.removed_attacks}."
                    ),
                )
            )
        elif len(comparison.removed_attacks) > 0:
            warnings.append(
                GateFinding(
                    rule_name="removed_attacks_warning",
                    status=GateRuleStatus.WARN,
                    actual_value=len(comparison.removed_attacks),
                    allowed_value=0,
                    message=(
                        f"Warning: {len(comparison.removed_attacks)} attacks present in baseline "
                        f"were removed from candidate suite: {comparison.removed_attacks}."
                    ),
                )
            )

        # 8. Operational Warning: Error transitions
        if len(comparison.error_transitions) > 0:
            warnings.append(
                GateFinding(
                    rule_name="error_transitions_warning",
                    status=GateRuleStatus.WARN,
                    actual_value=len(comparison.error_transitions),
                    allowed_value=0,
                    message=(
                        f"Warning: {len(comparison.error_transitions)} attacks experienced "
                        f"operational status changes (transitions to/from ERROR)."
                    ),
                )
            )

        # 9. Operational Warning: Severity changes
        if len(comparison.severity_changes) > 0:
            warnings.append(
                GateFinding(
                    rule_name="severity_changes_warning",
                    status=GateRuleStatus.WARN,
                    actual_value=len(comparison.severity_changes),
                    allowed_value=0,
                    message=(
                        f"Warning: {len(comparison.severity_changes)} attacks had modified "
                        f"severity ratings between baseline and candidate."
                    ),
                )
            )

        passed = len(violations) == 0
        if passed:
            summary = (
                f"SECURITY GATE PASSED: 0 policy violations, {len(warnings)} advisory warnings."
            )
        else:
            summary = (
                f"SECURITY GATE FAILED: {len(violations)} policy violations, "
                f"{len(warnings)} advisory warnings."
            )

        return GateResult(
            passed=passed,
            policy=self.policy,
            violations=violations,
            warnings=warnings,
            summary_message=summary,
        )
