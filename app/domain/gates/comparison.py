"""Comparison engine for diffing baseline and candidate ScoringReports."""

from __future__ import annotations

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.gates.models import (
    AttackTransition,
    CategoryComparison,
    ComparisonReport,
    TransitionType,
)
from app.domain.scoring.models import AttackScore, ScoringReport


class ComparisonEngine:
    """Computes deterministic diffs and regression metrics between two ScoringReports."""

    @staticmethod
    def _classify_transition(
        base_att: AttackScore | None,
        cand_att: AttackScore | None,
    ) -> tuple[TransitionType, bool]:
        """Classify how an attack transitioned from baseline to candidate.

        Returns (transition_type, severity_changed).
        """
        if base_att is None and cand_att is not None:
            # Attack was added to candidate
            severity_changed = False
            if cand_att.verdict == VerdictOutcome.FAIL:
                return TransitionType.NEW_FAILURE, severity_changed
            return TransitionType.NEW_ATTACK, severity_changed

        if base_att is not None and cand_att is None:
            # Attack was removed from candidate
            return TransitionType.REMOVED_ATTACK, False

        assert base_att is not None and cand_att is not None

        severity_changed = base_att.severity != cand_att.severity
        bv = base_att.verdict
        cv = cand_att.verdict

        # Normal PASS/FAIL matrix
        if bv == VerdictOutcome.PASS and cv == VerdictOutcome.PASS:
            return TransitionType.UNMODIFIED_PASS, severity_changed
        if bv == VerdictOutcome.PASS and cv == VerdictOutcome.FAIL:
            return TransitionType.NEW_FAILURE, severity_changed
        if bv == VerdictOutcome.FAIL and cv == VerdictOutcome.PASS:
            return TransitionType.RESOLVED_FAILURE, severity_changed
        if bv == VerdictOutcome.FAIL and cv == VerdictOutcome.FAIL:
            return TransitionType.PERSISTENT_FAILURE, severity_changed

        # Error transitions
        if bv == VerdictOutcome.PASS and cv == VerdictOutcome.ERROR:
            return TransitionType.PASS_TO_ERROR, severity_changed
        if bv == VerdictOutcome.FAIL and cv == VerdictOutcome.ERROR:
            return TransitionType.FAIL_TO_ERROR, severity_changed
        if bv == VerdictOutcome.ERROR and cv == VerdictOutcome.PASS:
            return TransitionType.ERROR_TO_PASS, severity_changed
        if bv == VerdictOutcome.ERROR and cv == VerdictOutcome.FAIL:
            return TransitionType.ERROR_TO_FAIL, severity_changed
        if bv == VerdictOutcome.ERROR and cv == VerdictOutcome.ERROR:
            return TransitionType.PERSISTENT_ERROR, severity_changed

        return TransitionType.OTHER, severity_changed

    def compare(
        self,
        baseline: ScoringReport,
        candidate: ScoringReport,
    ) -> ComparisonReport:
        """Compare baseline ScoringReport against candidate ScoringReport."""
        # Index attack scores by attack_id
        base_attacks: dict[str, AttackScore] = {a.attack_id: a for a in baseline.attack_scores}
        cand_attacks: dict[str, AttackScore] = {a.attack_id: a for a in candidate.attack_scores}

        all_ids = sorted(set(base_attacks.keys()) | set(cand_attacks.keys()))

        all_transitions: list[AttackTransition] = []
        new_failures: list[AttackTransition] = []
        resolved_failures: list[AttackTransition] = []
        persistent_failures: list[AttackTransition] = []
        new_critical_failures: list[AttackTransition] = []
        new_high_failures: list[AttackTransition] = []
        resolved_critical_failures: list[AttackTransition] = []
        added_attacks: list[str] = []
        removed_attacks: list[str] = []
        error_transitions: list[AttackTransition] = []
        severity_changes: list[AttackTransition] = []

        for att_id in all_ids:
            b = base_attacks.get(att_id)
            c = cand_attacks.get(att_id)

            t_type, sev_changed = self._classify_transition(b, c)

            category = (
                c.category
                if c is not None
                else (b.category if b is not None else ThreatCategory.PROMPT_INJECTION)
            )
            reason = c.reason if c is not None else (b.reason if b is not None else "")
            evidence = c.evidence if c is not None else []

            transition = AttackTransition(
                attack_id=att_id,
                category=category,
                transition_type=t_type,
                baseline_verdict=b.verdict if b is not None else None,
                candidate_verdict=c.verdict if c is not None else None,
                baseline_severity=b.severity if b is not None else None,
                candidate_severity=c.severity if c is not None else None,
                severity_changed=sev_changed,
                baseline_penalty=b.penalty if b is not None else 0,
                candidate_penalty=c.penalty if c is not None else 0,
                reason=reason,
                evidence=evidence,
            )
            all_transitions.append(transition)

            if t_type == TransitionType.NEW_FAILURE:
                new_failures.append(transition)
                if c is not None and c.severity == Severity.CRITICAL:
                    new_critical_failures.append(transition)
                elif c is not None and c.severity == Severity.HIGH:
                    new_high_failures.append(transition)
            elif t_type == TransitionType.RESOLVED_FAILURE:
                resolved_failures.append(transition)
                if b is not None and b.severity == Severity.CRITICAL:
                    resolved_critical_failures.append(transition)
            elif t_type == TransitionType.PERSISTENT_FAILURE:
                persistent_failures.append(transition)
            elif t_type == TransitionType.NEW_ATTACK:
                added_attacks.append(att_id)
            elif t_type == TransitionType.REMOVED_ATTACK:
                removed_attacks.append(att_id)

            if t_type in (
                TransitionType.PASS_TO_ERROR,
                TransitionType.FAIL_TO_ERROR,
                TransitionType.ERROR_TO_PASS,
                TransitionType.ERROR_TO_FAIL,
                TransitionType.PERSISTENT_ERROR,
            ):
                error_transitions.append(transition)

            if sev_changed:
                severity_changes.append(transition)

        # Delta calculations
        score_delta: float | None = None
        if candidate.security_score is not None and baseline.security_score is not None:
            score_delta = round(candidate.security_score - baseline.security_score, 2)

        asr_delta: float | None = None
        if candidate.attack_success_rate is not None and baseline.attack_success_rate is not None:
            asr_delta = round(candidate.attack_success_rate - baseline.attack_success_rate, 4)

        coverage_delta = round(candidate.evaluation_coverage - baseline.evaluation_coverage, 4)
        penalty_delta = candidate.weighted_penalty - baseline.weighted_penalty

        # Category comparisons
        all_categories = sorted(
            set(baseline.category_scores.keys()) | set(candidate.category_scores.keys())
        )
        cat_comparisons: dict[str, CategoryComparison] = {}

        for cat_name in all_categories:
            b_cat = baseline.category_scores.get(cat_name)
            c_cat = candidate.category_scores.get(cat_name)

            c_asr_delta: float | None = None
            if (
                c_cat is not None
                and b_cat is not None
                and c_cat.attack_success_rate is not None
                and b_cat.attack_success_rate is not None
            ):
                c_asr_delta = round(c_cat.attack_success_rate - b_cat.attack_success_rate, 4)

            c_score_delta: float | None = None
            if (
                c_cat is not None
                and b_cat is not None
                and c_cat.category_score is not None
                and b_cat.category_score is not None
            ):
                c_score_delta = round(c_cat.category_score - b_cat.category_score, 2)

            b_fail = b_cat.fail_count if b_cat else 0
            c_fail = c_cat.fail_count if c_cat else 0

            b_pen = b_cat.weighted_penalty if b_cat else 0
            c_pen = c_cat.weighted_penalty if c_cat else 0

            cat_comparisons[cat_name] = CategoryComparison(
                category=cat_name,
                in_baseline=b_cat is not None,
                in_candidate=c_cat is not None,
                baseline_total=b_cat.total_attacks if b_cat else 0,
                candidate_total=c_cat.total_attacks if c_cat else 0,
                baseline_asr=b_cat.attack_success_rate if b_cat else None,
                candidate_asr=c_cat.attack_success_rate if c_cat else None,
                asr_delta=c_asr_delta,
                baseline_score=b_cat.category_score if b_cat else None,
                candidate_score=c_cat.category_score if c_cat else None,
                score_delta=c_score_delta,
                baseline_failures=b_fail,
                candidate_failures=c_fail,
                failures_delta=c_fail - b_fail,
                baseline_penalty=b_pen,
                candidate_penalty=c_pen,
                penalty_delta=c_pen - b_pen,
            )

        return ComparisonReport(
            baseline_security_score=baseline.security_score,
            candidate_security_score=candidate.security_score,
            score_delta=score_delta,
            baseline_asr=baseline.attack_success_rate,
            candidate_asr=candidate.attack_success_rate,
            asr_delta=asr_delta,
            baseline_coverage=baseline.evaluation_coverage,
            candidate_coverage=candidate.evaluation_coverage,
            coverage_delta=coverage_delta,
            baseline_weighted_penalty=baseline.weighted_penalty,
            candidate_weighted_penalty=candidate.weighted_penalty,
            penalty_delta=penalty_delta,
            baseline_total_attacks=baseline.total_attacks,
            candidate_total_attacks=candidate.total_attacks,
            baseline_evaluated_attacks=baseline.evaluated_attacks,
            candidate_evaluated_attacks=candidate.evaluated_attacks,
            baseline_pass_count=baseline.pass_count,
            candidate_pass_count=candidate.pass_count,
            baseline_fail_count=baseline.fail_count,
            candidate_fail_count=candidate.fail_count,
            baseline_error_count=baseline.error_count,
            candidate_error_count=candidate.error_count,
            baseline_skipped_count=baseline.skipped_count,
            candidate_skipped_count=candidate.skipped_count,
            new_failures=new_failures,
            resolved_failures=resolved_failures,
            persistent_failures=persistent_failures,
            new_critical_failures=new_critical_failures,
            new_high_failures=new_high_failures,
            resolved_critical_failures=resolved_critical_failures,
            added_attacks=added_attacks,
            removed_attacks=removed_attacks,
            error_transitions=error_transitions,
            severity_changes=severity_changes,
            category_comparisons=cat_comparisons,
            all_transitions=all_transitions,
        )
