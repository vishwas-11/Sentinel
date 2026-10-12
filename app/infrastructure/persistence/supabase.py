"""Supabase PostgREST repository implementation for Sentinel."""

from __future__ import annotations

import copy
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import SecretStr

from app.domain.repositories import (
    BaselineRepository,
    DuplicateRecordError,
    PersistenceConnectionError,
    PersistenceError,
    RecordNotFoundError,
    ScanRepository,
)
from app.domain.scoring.models import ScoringReport

logger = logging.getLogger("sentinel.infrastructure.persistence.supabase")


class BaseSupabaseClient:
    """Helper base managing sanitized PostgREST HTTP calls to Supabase."""

    def __init__(
        self,
        supabase_url: str,
        supabase_key: SecretStr | str,
        timeout_seconds: float = 15.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        raw_url = supabase_url.rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raise ValueError(f"Invalid Supabase URL scheme: {supabase_url}")

        self.base_url = f"{raw_url}/rest/v1"
        self._key = (
            supabase_key.get_secret_value()
            if isinstance(supabase_key, SecretStr)
            else str(supabase_key)
        )
        self.timeout_seconds = timeout_seconds
        self._injected_client = client

    def _headers(self, prefer: str = "return=representation") -> dict[str, str]:
        return {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Prefer": prefer,
        }

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
        prefer: str = "return=representation",
    ) -> httpx.Response:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = self._headers(prefer=prefer)

        try:
            if self._injected_client is not None:
                resp = await self._injected_client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        json=json_data,
                        headers=headers,
                    )
            return resp
        except httpx.TimeoutException as exc:
            raise PersistenceConnectionError(
                f"Supabase request timed out after {self.timeout_seconds}s: {type(exc).__name__}"
            ) from exc
        except httpx.RequestError as exc:
            raise PersistenceConnectionError(
                f"Supabase transport connection failed: {type(exc).__name__}"
            ) from exc


class SupabaseScanRepository(BaseSupabaseClient, ScanRepository):
    """PostgREST implementation of ScanRepository against Supabase PostgreSQL."""

    async def save_scan(
        self,
        report: ScoringReport,
        target_url: str = "",
        status: str = "completed",
        mutation_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> str:
        scan_id = report.scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        # 1. Prepare scan parent record
        scan_payload = {
            "id": scan_id,
            "created_at": now,
            "target_url": target_url,
            "status": status,
            "total_attacks": report.total_attacks,
            "evaluated_attacks": report.evaluated_attacks,
            "pass_count": report.pass_count,
            "fail_count": report.fail_count,
            "error_count": report.error_count,
            "skipped_count": report.skipped_count,
            "evaluation_coverage": report.evaluation_coverage,
            "attack_success_rate": report.attack_success_rate,
            "weighted_penalty": report.weighted_penalty,
            "max_possible_penalty": report.max_possible_penalty,
            "security_score": report.security_score,
            "category_scores": {
                k: v.model_dump(mode="json") for k, v in report.category_scores.items()
            },
            "critical_findings": [f.model_dump(mode="json") for f in report.critical_findings],
            "mutation_config": copy.deepcopy(mutation_config or {}),
            "report_schema_version": report.report_schema_version,
            "metadata": copy.deepcopy(metadata or {}),
            "tenant_id": tenant_id,
        }

        # 2. Insert scan record
        resp_scan = await self._request("POST", "scans", json_data=scan_payload)
        if resp_scan.status_code >= 400:
            raise PersistenceError(
                f"Failed to insert scan record into Supabase (status {resp_scan.status_code}): "
                f"{resp_scan.text}"
            )

        # 3. Batch insert child attack_results rows with mutation provenance
        if report.attack_scores:
            results_payload = [
                {
                    "scan_id": scan_id,
                    "attack_id": att.attack_id,
                    "category": att.category.value,
                    "severity": att.severity.value,
                    "verdict": att.verdict.value,
                    "weight": att.weight,
                    "penalty": att.penalty,
                    "included": att.included,
                    "exclusion_reason": att.exclusion_reason,
                    "reason": att.reason,
                    "evidence": list(att.evidence),
                    "parent_attack_id": att.metadata.get("parent_attack_id"),
                    "mutation_metadata": copy.deepcopy(att.metadata.get("mutation")),
                    "metadata": copy.deepcopy(att.metadata),
                    "tenant_id": tenant_id,
                }
                for att in report.attack_scores
            ]

            resp_results = await self._request("POST", "attack_results", json_data=results_payload)
            if resp_results.status_code >= 400:
                raise PersistenceError(
                    f"Failed to insert attack results into Supabase "
                    f"(status {resp_results.status_code}): {resp_results.text}"
                )

        return scan_id

    async def get_scan_record(self, scan_id: str) -> dict[str, Any] | None:
        resp = await self._request(
            "GET",
            "scans",
            params={"id": f"eq.{scan_id}", "select": "*"},
        )
        if resp.status_code >= 400:
            raise PersistenceError(f"Failed to fetch scan record from Supabase: {resp.text}")
        data = resp.json()
        if not data:
            return None
        return data[0]

    async def get_scan_report(self, scan_id: str) -> ScoringReport | None:
        scan_record = await self.get_scan_record(scan_id)
        if scan_record is None:
            return None

        # Fetch all child attack results
        resp_att = await self._request(
            "GET",
            "attack_results",
            params={"scan_id": f"eq.{scan_id}", "select": "*", "order": "id.asc"},
        )
        if resp_att.status_code >= 400:
            raise PersistenceError(
                f"Failed to fetch attack results for scan {scan_id}: {resp_att.text}"
            )

        attack_rows = resp_att.json()

        # Reconstruct canonical ScoringReport
        report_data = {
            "scan_id": scan_record["id"],
            "report_schema_version": scan_record.get("report_schema_version", "1.0.0"),
            "timestamp": scan_record["created_at"],
            "total_attacks": scan_record["total_attacks"],
            "evaluated_attacks": scan_record["evaluated_attacks"],
            "pass_count": scan_record["pass_count"],
            "fail_count": scan_record["fail_count"],
            "error_count": scan_record["error_count"],
            "skipped_count": scan_record["skipped_count"],
            "evaluation_coverage": scan_record["evaluation_coverage"],
            "attack_success_rate": scan_record["attack_success_rate"],
            "weighted_penalty": scan_record["weighted_penalty"],
            "max_possible_penalty": scan_record["max_possible_penalty"],
            "security_score": scan_record["security_score"],
            "category_scores": scan_record["category_scores"],
            "critical_findings": scan_record["critical_findings"],
            "attack_scores": [
                {
                    "attack_id": r["attack_id"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "verdict": r["verdict"],
                    "weight": r["weight"],
                    "penalty": r["penalty"],
                    "included": r["included"],
                    "exclusion_reason": r["exclusion_reason"],
                    "reason": r["reason"],
                    "evidence": r["evidence"],
                    "metadata": r["metadata"],
                }
                for r in attack_rows
            ],
        }
        return ScoringReport.model_validate(report_data)

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "select": "*",
            "order": "created_at.desc",
            "limit": str(limit),
            "offset": str(offset),
        }
        if tenant_id is not None:
            params["tenant_id"] = f"eq.{tenant_id}"

        resp = await self._request("GET", "scans", params=params)
        if resp.status_code >= 400:
            raise PersistenceError(f"Failed to list scans from Supabase: {resp.text}")
        return resp.json()


class SupabaseBaselineRepository(BaseSupabaseClient, BaselineRepository):
    """PostgREST implementation of BaselineRepository against Supabase PostgreSQL."""

    async def create_baseline(
        self,
        name: str,
        scan_id: str,
        report: ScoringReport,
        description: str = "",
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("Baseline name cannot be empty.")

        baseline_id = f"base_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()
        report_snapshot = report.model_dump(mode="json")

        payload = {
            "id": baseline_id,
            "name": cleaned_name,
            "description": description,
            "scan_id": scan_id,
            "created_at": now,
            "report_snapshot": report_snapshot,
            "metadata": copy.deepcopy(metadata or {}),
            "tenant_id": tenant_id,
        }

        resp = await self._request("POST", "baselines", json_data=payload)
        if resp.status_code == 409 or (
            resp.status_code >= 400 and "duplicate key" in resp.text.lower()
        ):
            raise DuplicateRecordError(
                f"A baseline with name '{cleaned_name}' already exists in Supabase."
            )
        if resp.status_code >= 400 and "foreign key" in resp.text.lower():
            raise RecordNotFoundError(f"Referenced scan_id '{scan_id}' does not exist in Supabase.")
        if resp.status_code >= 400:
            raise PersistenceError(
                f"Failed to create baseline in Supabase (status {resp.status_code}): {resp.text}"
            )

        data = resp.json()
        return data[0] if isinstance(data, list) and data else payload

    async def get_baseline_by_name(self, name: str) -> dict[str, Any] | None:
        resp = await self._request(
            "GET",
            "baselines",
            params={"name": f"eq.{name.strip()}", "select": "*"},
        )
        if resp.status_code >= 400:
            raise PersistenceError(f"Failed to fetch baseline by name from Supabase: {resp.text}")
        data = resp.json()
        return data[0] if data else None

    async def get_baseline_by_id(self, baseline_id: str) -> dict[str, Any] | None:
        resp = await self._request(
            "GET",
            "baselines",
            params={"id": f"eq.{baseline_id}", "select": "*"},
        )
        if resp.status_code >= 400:
            raise PersistenceError(f"Failed to fetch baseline by ID from Supabase: {resp.text}")
        data = resp.json()
        return data[0] if data else None

    async def get_baseline_report(self, identifier: str) -> ScoringReport | None:
        rec = await self.get_baseline_by_name(identifier)
        if rec is None:
            rec = await self.get_baseline_by_id(identifier)
        if rec is None:
            return None
        return ScoringReport.model_validate(rec["report_snapshot"])

    async def list_baselines(
        self,
        limit: int = 50,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "select": "*",
            "order": "created_at.desc",
            "limit": str(limit),
            "offset": str(offset),
        }
        if tenant_id is not None:
            params["tenant_id"] = f"eq.{tenant_id}"

        resp = await self._request("GET", "baselines", params=params)
        if resp.status_code >= 400:
            raise PersistenceError(f"Failed to list baselines from Supabase: {resp.text}")
        return resp.json()
