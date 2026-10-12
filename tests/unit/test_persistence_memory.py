"""Unit tests for Sentinel in-memory repository implementations."""

from __future__ import annotations

import pytest

from app.domain.attacks import Severity, ThreatCategory
from app.domain.evaluation.models import VerdictOutcome
from app.domain.repositories import (
    DuplicateRecordError,
    RecordNotFoundError,
)
from app.domain.scoring.engine import ScoringEngine
from app.infrastructure.persistence.memory import (
    InMemoryBaselineRepository,
    InMemoryScanRepository,
)
from tests.unit.test_scoring import _make_eval_result


def _build_sample_report(scan_id: str = "scan_test_001"):
    eval_results = [
        _make_eval_result(
            "T1-001", ThreatCategory.PROMPT_INJECTION, Severity.HIGH, VerdictOutcome.PASS
        ),
        _make_eval_result(
            "T2-001", ThreatCategory.SYSTEM_LEAKAGE, Severity.CRITICAL, VerdictOutcome.FAIL
        ),
    ]
    # Add mutation provenance to one attack
    eval_results[0].test_case.mutation = type(
        "MutationMeta",
        (),
        {
            "technique": "base64",
            "parent_attack_id": "T1-SEED",
            "parameters": {"format": "raw"},
            "model_dump": lambda self: {
                "technique": "base64",
                "parent_attack_id": "T1-SEED",
                "parameters": {"format": "raw"},
            },
        },
    )()
    engine = ScoringEngine()
    return engine.calculate(eval_results, scan_id=scan_id)


@pytest.mark.asyncio
async def test_in_memory_scan_save_and_get_roundtrip():
    repo = InMemoryScanRepository()
    original_report = _build_sample_report("scan_roundtrip_1")

    saved_id = await repo.save_scan(
        report=original_report,
        target_url="http://localhost:8001",
        status="completed",
        mutation_config={"enabled": True},
        metadata={"run_env": "test"},
    )
    assert saved_id == "scan_roundtrip_1"

    # Reconstruct report
    retrieved_report = await repo.get_scan_report(saved_id)
    assert retrieved_report is not None
    assert retrieved_report.scan_id == "scan_roundtrip_1"
    assert retrieved_report.total_attacks == original_report.total_attacks
    assert retrieved_report.evaluated_attacks == original_report.evaluated_attacks
    assert retrieved_report.pass_count == original_report.pass_count
    assert retrieved_report.fail_count == original_report.fail_count
    assert retrieved_report.security_score == original_report.security_score
    assert retrieved_report.attack_success_rate == original_report.attack_success_rate
    assert len(retrieved_report.attack_scores) == len(original_report.attack_scores)

    # Verify mutation provenance survived roundtrip
    mutated_attack = next(a for a in retrieved_report.attack_scores if a.attack_id == "T1-001")
    assert mutated_attack.metadata["parent_attack_id"] == "T1-SEED"
    assert mutated_attack.metadata["mutation"]["technique"] == "base64"


@pytest.mark.asyncio
async def test_in_memory_scan_get_record_and_list():
    repo = InMemoryScanRepository()
    report1 = _build_sample_report("scan_1")
    report2 = _build_sample_report("scan_2")

    await repo.save_scan(report1, target_url="http://target1:8001", tenant_id="tenant_a")
    await repo.save_scan(report2, target_url="http://target2:8001", tenant_id="tenant_b")

    rec1 = await repo.get_scan_record("scan_1")
    assert rec1 is not None
    assert rec1["id"] == "scan_1"
    assert rec1["target_url"] == "http://target1:8001"
    assert rec1["tenant_id"] == "tenant_a"

    # List all
    all_scans = await repo.list_scans(limit=10)
    assert len(all_scans) == 2

    # List by tenant
    tenant_a_scans = await repo.list_scans(tenant_id="tenant_a")
    assert len(tenant_a_scans) == 1
    assert tenant_a_scans[0]["id"] == "scan_1"

    # Non-existent scan
    assert await repo.get_scan_record("nonexistent") is None
    assert await repo.get_scan_report("nonexistent") is None


@pytest.mark.asyncio
async def test_in_memory_baseline_lifecycle():
    scan_repo = InMemoryScanRepository()
    baseline_repo = InMemoryBaselineRepository(scan_repo=scan_repo)

    report = _build_sample_report("scan_base_1")
    await scan_repo.save_scan(report)

    # 1. Create baseline
    created = await baseline_repo.create_baseline(
        name="prod-v1.0",
        scan_id="scan_base_1",
        report=report,
        description="Production candidate benchmark",
    )
    assert created["name"] == "prod-v1.0"
    assert created["scan_id"] == "scan_base_1"
    assert "id" in created

    # 2. Retrieve by name and by ID
    by_name = await baseline_repo.get_baseline_by_name("prod-v1.0")
    assert by_name is not None
    assert by_name["id"] == created["id"]

    by_id = await baseline_repo.get_baseline_by_id(created["id"])
    assert by_id is not None
    assert by_id["name"] == "prod-v1.0"

    # 3. Retrieve reconstructed ScoringReport snapshot
    retrieved_report = await baseline_repo.get_baseline_report("prod-v1.0")
    assert retrieved_report is not None
    assert retrieved_report.total_attacks == report.total_attacks
    assert retrieved_report.security_score == report.security_score

    # Also retrieve by ID
    retrieved_by_id = await baseline_repo.get_baseline_report(created["id"])
    assert retrieved_by_id is not None
    assert retrieved_by_id.security_score == report.security_score

    # 4. Enforce duplicate name policy
    with pytest.raises(DuplicateRecordError):
        await baseline_repo.create_baseline(
            name="prod-v1.0",
            scan_id="scan_base_1",
            report=report,
        )

    # 5. Enforce non-existent scan ID validation
    with pytest.raises(RecordNotFoundError):
        await baseline_repo.create_baseline(
            name="prod-v2.0",
            scan_id="scan_does_not_exist",
            report=report,
        )

    # 6. Reject empty name
    with pytest.raises(ValueError):
        await baseline_repo.create_baseline(
            name="   ",
            scan_id="scan_base_1",
            report=report,
        )

    # 7. List baselines
    baselines = await baseline_repo.list_baselines()
    assert len(baselines) == 1
    assert baselines[0]["name"] == "prod-v1.0"
