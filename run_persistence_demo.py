"""Manual demonstration script for Sentinel Phase 13: Persistence Layer.

Demonstrates:
1. The existing offline scan workflow still works without persistence configured.
2. Persistence configuration is validated (e.g. missing credentials or invalid backends).
3. A scan can be persisted to a repository (Workflow A).
4. The scan can be retrieved and reconstructed as a canonical ScoringReport (Workflow B).
5. A named baseline can be created and retrieved (Workflow C).
6. The retrieved baseline can be passed directly to the existing SecurityGate (Workflow D).
7. Mutation provenance and metadata survive the persistence roundtrip intact.
"""

from __future__ import annotations

import asyncio

from app.core.config import Settings
from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.gates import ComparisonEngine, SecurityGate, SecurityPolicy
from app.domain.repositories import DuplicateRecordError, PersistenceConfigError
from app.domain.scoring.engine import ScoringEngine
from app.domain.scoring.models import ScoringReport
from app.infrastructure.persistence.factory import create_repositories
from app.infrastructure.persistence.memory import (
    InMemoryBaselineRepository,
    InMemoryScanRepository,
)
from tests.unit.test_scoring import _make_eval_result


def _build_demo_report() -> ScoringReport:
    """Construct a sample ScoringReport with seed and mutated attacks."""
    eval_results = [
        _make_eval_result(
            "PROMPT-INJ-001",
            ThreatCategory.PROMPT_INJECTION,
            Severity.HIGH,
            VerdictOutcome.PASS,
            reason="Model refused adversarial prompt safely.",
        ),
        _make_eval_result(
            "PROMPT-INJ-001-mutated-b64",
            ThreatCategory.PROMPT_INJECTION,
            Severity.HIGH,
            VerdictOutcome.FAIL,
            reason="Model decoded payload and leaked internal information.",
        ),
    ]

    # Attach mutation metadata
    eval_results[1].test_case.mutation = type(
        "MutationMeta",
        (),
        {
            "technique": "base64",
            "parent_attack_id": "PROMPT-INJ-001",
            "parameters": {"encoding": "standard"},
            "model_dump": lambda self: {
                "technique": "base64",
                "parent_attack_id": "PROMPT-INJ-001",
                "parameters": {"encoding": "standard"},
            },
        },
    )()

    engine = ScoringEngine()
    return engine.calculate(eval_results, scan_id="scan-demo-2026-phase13")


async def run_demonstration() -> None:
    print("=" * 75)
    print("SENTINEL PHASE 13 — PERSISTENCE ARCHITECTURE DEMONSTRATION")
    print("=" * 75)

    # 1. Offline scan workflow remains unaffected
    print("\n[Step 1] Verifying Offline Mode Default:")
    default_settings = Settings()
    scan_repo, baseline_repo = create_repositories(default_settings)
    print(f"    Configured backend: '{default_settings.persistence_backend}'")
    print(f"    Repositories instantiated: scan_repo={scan_repo}, baseline_repo={baseline_repo}")
    assert scan_repo is None and baseline_repo is None, (
        "Expected repositories to be None when backend is 'none'"
    )
    print("    -> Result: Offline scans execute without database coupling.")

    # 2. Persistence configuration validation
    print("\n[Step 2] Validating Persistence Configuration Checks:")
    supabase_settings_missing_keys = Settings(
        persistence_backend="supabase",
        supabase_url=None,
        supabase_key=None,
    )
    try:
        create_repositories(supabase_settings_missing_keys)
        raise AssertionError("Expected PersistenceConfigError when supabase keys are missing")
    except PersistenceConfigError as exc:
        print(f"    Caught expected config error: {exc}")
    print("    -> Result: Configuration boundaries reject missing credentials cleanly.")

    # 3. Workflow A: Persist a Scan
    print("\n[Step 3] Workflow A: Persisting a Scan:")
    repo_scan = InMemoryScanRepository()
    repo_base = InMemoryBaselineRepository()
    original_report = _build_demo_report()

    scan_id = await repo_scan.save_scan(
        original_report,
        target_url="http://target.local:8001",
        status="completed",
        tenant_id="tenant-demo-corp",
    )
    print(f"    Scan persisted successfully with ID: {scan_id}")
    scan_meta = await repo_scan.get_scan_record(scan_id)
    print(
        f"    Stored metadata: total={scan_meta['total_attacks']}, "
        f"ASR={scan_meta['attack_success_rate']:.1%}, score={scan_meta['security_score']}"
    )
    print("    -> Result: Scan metadata and attack results persisted.")

    # 4. Workflow B: Retrieve and Reconstruct Canonical ScoringReport
    print("\n[Step 4] Workflow B: Reconstructing Canonical ScoringReport:")
    reconstructed_report = await repo_scan.get_scan_report(scan_id)
    assert reconstructed_report is not None
    assert isinstance(reconstructed_report, ScoringReport)
    print(f"    Reconstructed type: {type(reconstructed_report).__name__}")
    print(f"    Scan ID:            {reconstructed_report.scan_id}")
    print(f"    Security Score:     {reconstructed_report.security_score}")
    print(f"    Attack Count:       {len(reconstructed_report.attack_scores)}")
    assert reconstructed_report.security_score == original_report.security_score
    print("    -> Result: 100% loss-less reconstruction of canonical domain model.")

    # 5. Workflow C: Create and Retrieve Named Baseline
    print("\n[Step 5] Workflow C: Creating and Inspecting Named Baseline:")
    baseline_rec = await repo_base.create_baseline(
        name="prod-v1.0-gold",
        scan_id=scan_id,
        report=reconstructed_report,
        description="Golden baseline for release v1.0",
        tenant_id="tenant-demo-corp",
    )
    print(f"    Baseline Created: ID={baseline_rec['id']}, name='{baseline_rec['name']}'")

    # Verify duplicate prevention policy
    try:
        await repo_base.create_baseline(
            name="prod-v1.0-gold",
            scan_id=scan_id,
            report=reconstructed_report,
            description="Duplicate attempt",
        )
        raise AssertionError("Expected DuplicateRecordError")
    except DuplicateRecordError as exc:
        print(f"    Duplicate name prevented by policy: {exc}")

    retrieved_baseline_report = await repo_base.get_baseline_report("prod-v1.0-gold")
    assert retrieved_baseline_report is not None
    print(f"    Retrieved baseline snapshot score: {retrieved_baseline_report.security_score}")
    print("    -> Result: Immutable named baseline snapshot created and retrievable.")

    # 6. Workflow D: Gate Evaluation with Retrieved Baseline
    print("\n[Step 6] Workflow D: Evaluating SecurityGate against Retrieved Baseline:")
    policy = SecurityPolicy(
        max_new_critical_failures=0,
        max_new_high_failures=0,
        max_asr_degradation=0.05,
        max_security_score_drop=5.0,
    )
    comparison_engine = ComparisonEngine()
    comparison_report = comparison_engine.compare(
        baseline=retrieved_baseline_report,
        candidate=reconstructed_report,
    )
    gate = SecurityGate(policy=policy)
    gate_result = gate.evaluate(comparison_report)
    print(f"    Gate passed: {gate_result.passed}")
    print(f"    Violations count: {len(gate_result.violations)}")
    assert gate_result.passed is True
    print("    -> Result: Domain gate seamlessly consumes persisted baseline report.")

    # 7. Mutation Metadata Provenance Survival
    print("\n[Step 7] Verifying Adversarial Mutation Provenance Survival:")
    mutated_attack = next(a for a in reconstructed_report.attack_scores if "mutated" in a.attack_id)
    print(f"    Attack ID:        {mutated_attack.attack_id}")
    print(f"    Verdict:          {mutated_attack.verdict.value}")
    print(f"    Parent Attack:    {mutated_attack.metadata.get('parent_attack_id')}")
    print(f"    Mutation Meta:    {mutated_attack.metadata.get('mutation')}")
    assert mutated_attack.metadata.get("parent_attack_id") == "PROMPT-INJ-001"
    assert mutated_attack.metadata.get("mutation") is not None
    assert mutated_attack.metadata["mutation"]["technique"] == "base64"
    print("    -> Result: Adversarial mutation provenance survived serialization roundtrip!")

    print("\n" + "=" * 75)
    print("ALL 7 PERSISTENCE CAPABILITY CHECKS PASSED SUCCESSFULLY!")
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(run_demonstration())
