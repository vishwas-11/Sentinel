"""Unit tests for Supabase PostgREST repositories using HTTP mock transports."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from app.domain.repositories import (
    DuplicateRecordError,
    PersistenceConnectionError,
)
from app.infrastructure.persistence.supabase import (
    SupabaseBaselineRepository,
    SupabaseScanRepository,
)
from tests.unit.test_persistence_memory import _build_sample_report


@pytest.mark.asyncio
async def test_supabase_scan_save_success():
    saved_requests = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        saved_requests.append(request)
        assert request.headers["apikey"] == "test-supabase-key"
        assert request.headers["authorization"] == "Bearer test-supabase-key"

        if request.url.path == "/rest/v1/scans" and request.method == "POST":
            return httpx.Response(201, json=[{"id": "scan_sb_1"}])
        if request.url.path == "/rest/v1/attack_results" and request.method == "POST":
            return httpx.Response(201, json=[{"id": 1}, {"id": 2}])
        return httpx.Response(404, json={"error": "Not Found"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    repo = SupabaseScanRepository(
        supabase_url="https://xyz.supabase.co",
        supabase_key="test-supabase-key",
        client=client,
    )

    report = _build_sample_report("scan_sb_1")
    scan_id = await repo.save_scan(report, target_url="http://target:8001")
    assert scan_id == "scan_sb_1"
    assert len(saved_requests) == 2


@pytest.mark.asyncio
async def test_supabase_scan_get_report_reconstructs_canonical_model():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/v1/scans":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "scan_recon_1",
                        "created_at": "2026-10-12T12:00:00Z",
                        "total_attacks": 2,
                        "evaluated_attacks": 2,
                        "pass_count": 1,
                        "fail_count": 1,
                        "error_count": 0,
                        "skipped_count": 0,
                        "evaluation_coverage": 1.0,
                        "attack_success_rate": 0.5,
                        "weighted_penalty": 8,
                        "max_possible_penalty": 12,
                        "security_score": 33.33,
                        "category_scores": {},
                        "critical_findings": [],
                        "report_schema_version": "1.0.0",
                    }
                ],
            )
        if request.url.path == "/rest/v1/attack_results":
            return httpx.Response(
                200,
                json=[
                    {
                        "attack_id": "T1-001",
                        "category": "prompt_injection",
                        "severity": "HIGH",
                        "verdict": "PASS",
                        "weight": 4,
                        "penalty": 0,
                        "included": True,
                        "exclusion_reason": None,
                        "reason": "Defense held",
                        "evidence": [],
                        "metadata": {"parent_attack_id": "T1-SEED"},
                    },
                    {
                        "attack_id": "T2-001",
                        "category": "system_leakage",
                        "severity": "CRITICAL",
                        "verdict": "FAIL",
                        "weight": 8,
                        "penalty": 8,
                        "included": True,
                        "exclusion_reason": None,
                        "reason": "Breach observed",
                        "evidence": ["System instructions revealed"],
                        "metadata": {},
                    },
                ],
            )
        return httpx.Response(404, json=[])

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    repo = SupabaseScanRepository(
        supabase_url="https://xyz.supabase.co",
        supabase_key="key",
        client=client,
    )

    report = await repo.get_scan_report("scan_recon_1")
    assert report is not None
    assert report.scan_id == "scan_recon_1"
    assert report.pass_count == 1
    assert report.fail_count == 1
    assert len(report.attack_scores) == 2
    assert report.attack_scores[0].metadata["parent_attack_id"] == "T1-SEED"


@pytest.mark.asyncio
async def test_supabase_baseline_duplicate_name_error_mapping():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/v1/baselines" and request.method == "POST":
            return httpx.Response(
                409,
                text="duplicate key value violates unique constraint 'idx_baselines_name'",
            )
        return httpx.Response(404, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    repo = SupabaseBaselineRepository(
        supabase_url="https://xyz.supabase.co",
        supabase_key="key",
        client=client,
    )

    report = _build_sample_report("scan_1")
    with pytest.raises(DuplicateRecordError):
        await repo.create_baseline(name="duplicate-base", scan_id="scan_1", report=report)


@pytest.mark.asyncio
async def test_supabase_timeout_maps_to_connection_error():
    mock_client = MagicMock(spec=httpx.AsyncClient)
    mock_client.request = MagicMock()

    async def raise_timeout(*args, **kwargs):
        raise httpx.TimeoutException("Connection timed out")

    mock_client.request.side_effect = raise_timeout

    repo = SupabaseScanRepository(
        supabase_url="https://xyz.supabase.co",
        supabase_key="key",
        client=mock_client,
    )
    with pytest.raises(PersistenceConnectionError):
        await repo.get_scan_record("scan_timeout")


def test_supabase_url_validation():
    with pytest.raises(ValueError, match="Invalid Supabase URL scheme"):
        SupabaseScanRepository(
            supabase_url="ftp://invalid-url.com",
            supabase_key="key",
        )
