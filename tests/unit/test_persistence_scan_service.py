"""Integration tests for ScanService with persistence enabled."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.core.config import Settings
from app.core.scan_service import ScanService
from app.domain.attacks import ThreatCategory
from app.domain.repositories import PersistenceConfigError
from app.domain.targets import TargetAdapter, TargetResult
from app.infrastructure.persistence.memory import InMemoryScanRepository


@pytest.mark.asyncio
async def test_scan_service_persistence_disabled_by_default():
    mock_adapter = AsyncMock(spec=TargetAdapter)
    mock_adapter.reset = AsyncMock()
    mock_adapter.execute = AsyncMock(
        return_value=TargetResult(
            response="I am a secure banking assistant.",
            status="success",
            status_code=200,
        )
    )

    settings = Settings(persistence_backend="none")
    service = ScanService(settings=settings)

    report = await service.run_scan(
        category=ThreatCategory.PROMPT_INJECTION,
        target_adapter=mock_adapter,
        persist=False,
    )
    # Scan executed successfully, report has run_id from runner
    assert report.total_attacks > 0


@pytest.mark.asyncio
async def test_scan_service_persists_to_in_memory_repository():
    mock_adapter = AsyncMock(spec=TargetAdapter)
    mock_adapter.reset = AsyncMock()
    mock_adapter.execute = AsyncMock(
        return_value=TargetResult(
            response="I am a secure banking assistant.",
            status="success",
            status_code=200,
        )
    )

    repo = InMemoryScanRepository()
    settings = Settings(persistence_backend="none")  # Injected repo takes precedence
    service = ScanService(settings=settings)

    report = await service.run_scan(
        category=ThreatCategory.PROMPT_INJECTION,
        target_adapter=mock_adapter,
        persist=True,
        scan_repository=repo,
        enable_mutations=True,
        mutation_strategies=["base64"],
        mutations_per_attack=1,
    )

    assert report.scan_id is not None
    # Verify persisted in repository
    persisted_report = await repo.get_scan_report(report.scan_id)
    assert persisted_report is not None
    assert persisted_report.scan_id == report.scan_id
    assert persisted_report.total_attacks == report.total_attacks

    # Verify mutations were stored with lineage
    mutated_scores = [s for s in persisted_report.attack_scores if "mutation" in s.metadata]
    assert len(mutated_scores) > 0


@pytest.mark.asyncio
async def test_scan_service_raises_config_error_when_no_backend():
    mock_adapter = AsyncMock(spec=TargetAdapter)
    mock_adapter.reset = AsyncMock()
    mock_adapter.execute = AsyncMock(
        return_value=TargetResult(
            response="I am a secure banking assistant.",
            status="success",
            status_code=200,
        )
    )

    settings = Settings(persistence_backend="none")
    service = ScanService(settings=settings)

    with pytest.raises(PersistenceConfigError):
        await service.run_scan(
            category=ThreatCategory.PROMPT_INJECTION,
            target_adapter=mock_adapter,
            persist=True,  # Explicitly requested, but backend is 'none'
        )
