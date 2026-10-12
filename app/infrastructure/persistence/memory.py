"""In-memory repository implementations for local runs, offline testing, and CI."""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime
from typing import Any

from app.domain.repositories import (
    BaselineRepository,
    DuplicateRecordError,
    RecordNotFoundError,
    ScanRepository,
)
from app.domain.scoring.models import ScoringReport


class InMemoryScanRepository(ScanRepository):
    """In-memory implementation of ScanRepository.

    Validates schema mapping and JSON round-tripping without requiring external databases.
    """

    def __init__(self) -> None:
        self.scans: dict[str, dict[str, Any]] = {}
        self.attack_results: dict[str, list[dict[str, Any]]] = {}

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
        now = datetime.now(UTC)

        # 1. Store scan record
        scan_row: dict[str, Any] = {
            "id": scan_id,
            "created_at": now.isoformat(),
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
        self.scans[scan_id] = scan_row

        # 2. Store child attack_results rows with mutation provenance
        results_rows: list[dict[str, Any]] = []
        for att in report.attack_scores:
            res_row: dict[str, Any] = {
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
            results_rows.append(res_row)

        self.attack_results[scan_id] = results_rows
        return scan_id

    async def get_scan_report(self, scan_id: str) -> ScoringReport | None:
        scan_row = self.scans.get(scan_id)
        if scan_row is None:
            return None

        attack_rows = self.attack_results.get(scan_id, [])

        # Reconstruct canonical report via Pydantic model_validate
        report_data = {
            "scan_id": scan_row["id"],
            "report_schema_version": scan_row.get("report_schema_version", "1.0.0"),
            "timestamp": scan_row["created_at"],
            "total_attacks": scan_row["total_attacks"],
            "evaluated_attacks": scan_row["evaluated_attacks"],
            "pass_count": scan_row["pass_count"],
            "fail_count": scan_row["fail_count"],
            "error_count": scan_row["error_count"],
            "skipped_count": scan_row["skipped_count"],
            "evaluation_coverage": scan_row["evaluation_coverage"],
            "attack_success_rate": scan_row["attack_success_rate"],
            "weighted_penalty": scan_row["weighted_penalty"],
            "max_possible_penalty": scan_row["max_possible_penalty"],
            "security_score": scan_row["security_score"],
            "category_scores": scan_row["category_scores"],
            "critical_findings": scan_row["critical_findings"],
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

    async def get_scan_record(self, scan_id: str) -> dict[str, Any] | None:
        rec = self.scans.get(scan_id)
        return copy.deepcopy(rec) if rec is not None else None

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        matching = [
            s for s in self.scans.values() if tenant_id is None or s.get("tenant_id") == tenant_id
        ]
        # Sort descending by creation timestamp
        matching.sort(key=lambda s: s["created_at"], reverse=True)
        return copy.deepcopy(matching[offset : offset + limit])


class InMemoryBaselineRepository(BaselineRepository):
    """In-memory implementation of BaselineRepository.

    Enforces baseline immutability and uniqueness.
    """

    def __init__(self, scan_repo: InMemoryScanRepository | None = None) -> None:
        self.scan_repo = scan_repo
        self.baselines_by_id: dict[str, dict[str, Any]] = {}
        self.baselines_by_name: dict[str, str] = {}  # name -> id

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

        if cleaned_name in self.baselines_by_name:
            raise DuplicateRecordError(f"A baseline with name '{cleaned_name}' already exists.")

        if self.scan_repo is not None and scan_id not in self.scan_repo.scans:
            raise RecordNotFoundError(f"Referenced scan_id '{scan_id}' does not exist.")

        baseline_id = f"base_{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        # Immutable snapshot of the ScoringReport
        report_snapshot = report.model_dump(mode="json")

        baseline_record: dict[str, Any] = {
            "id": baseline_id,
            "name": cleaned_name,
            "description": description,
            "scan_id": scan_id,
            "created_at": now,
            "report_snapshot": report_snapshot,
            "metadata": copy.deepcopy(metadata or {}),
            "tenant_id": tenant_id,
        }

        self.baselines_by_id[baseline_id] = baseline_record
        self.baselines_by_name[cleaned_name] = baseline_id
        return copy.deepcopy(baseline_record)

    async def get_baseline_by_name(self, name: str) -> dict[str, Any] | None:
        base_id = self.baselines_by_name.get(name.strip())
        if base_id is None:
            return None
        return copy.deepcopy(self.baselines_by_id.get(base_id))

    async def get_baseline_by_id(self, baseline_id: str) -> dict[str, Any] | None:
        rec = self.baselines_by_id.get(baseline_id)
        return copy.deepcopy(rec) if rec is not None else None

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
        matching = [
            b
            for b in self.baselines_by_id.values()
            if tenant_id is None or b.get("tenant_id") == tenant_id
        ]
        matching.sort(key=lambda b: b["created_at"], reverse=True)
        return copy.deepcopy(matching[offset : offset + limit])
