"""Domain repository interfaces and persistence exception contracts for Sentinel."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.domain.scoring.models import ScoringReport

# ==============================================================================
# Persistence Exceptions Hierarchy
# ==============================================================================


class PersistenceError(Exception):
    """Base exception for all persistence-related failures."""


class RecordNotFoundError(PersistenceError):
    """Raised when an expected scan or baseline record is not found."""


class DuplicateRecordError(PersistenceError):
    """Raised when a unique constraint (such as a duplicate baseline name) is violated."""


class PersistenceConfigError(PersistenceError):
    """Raised when persistence is requested but required configuration or keys are missing."""


class PersistenceConnectionError(PersistenceError):
    """Raised when transport or network connectivity to the database backend fails."""


# ==============================================================================
# Repository Protocols
# ==============================================================================


@runtime_checkable
class ScanRepository(Protocol):
    """Repository contract for persisting and retrieving security scan runs.

    Responsibilities:
    - Atomically save scan runs along with their granular attack-level findings.
    - Preserve mutation provenance and telemetry without secret leakage.
    - Reconstruct canonical, typed ScoringReport instances from database rows.
    - Provide paginated scan summaries for listing and dashboards.

    Non-Responsibilities:
    - Does NOT compute scores (handled by ScoringEngine).
    - Does NOT execute attacks or evaluate target behaviors.
    """

    async def save_scan(
        self,
        report: ScoringReport,
        target_url: str = "",
        status: str = "completed",
        mutation_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> str:
        """Persist a scan run and its granular attack results atomically.

        Args:
            report: Canonical ScoringReport to persist.
            target_url: Target application base URL evaluated.
            status: Execution status ('completed', 'failed', etc.).
            mutation_config: Optional mutation configuration summary.
            metadata: Optional execution context metadata.
            tenant_id: Optional tenant identifier for multi-tenant isolation.

        Returns:
            The unique, assigned scan_id string.

        Raises:
            PersistenceError: If the write operation fails.
        """
        ...

    async def get_scan_report(self, scan_id: str) -> ScoringReport | None:
        """Retrieve and reconstruct the canonical ScoringReport for a scan ID.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            Fully reconstructed and validated ScoringReport, or None if not found.

        Raises:
            PersistenceError: On database error or corrupted report schema.
        """
        ...

    async def get_scan_record(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve top-level summary metadata for a scan run without child results.

        Args:
            scan_id: Unique scan identifier.

        Returns:
            Dictionary containing scan record columns, or None if not found.
        """
        ...

    async def list_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List scan summary records ordered by creation timestamp descending.

        Args:
            limit: Maximum number of scan records to return.
            offset: Number of records to skip for pagination.
            tenant_id: Optional tenant filter.

        Returns:
            List of scan summary dictionaries.
        """
        ...


@runtime_checkable
class BaselineRepository(Protocol):
    """Repository contract for managing named, immutable security baselines.

    Responsibilities:
    - Associate a human-readable baseline name with an immutable ScoringReport snapshot.
    - Enforce unique baseline naming policies.
    - Retrieve and reconstruct baseline reports for regression gate evaluations.
    - Support listing baselines with timestamps and metadata.

    Non-Responsibilities:
    - Does NOT evaluate gate policy or compute regression diffs (handled by SecurityGate).
    """

    async def create_baseline(
        self,
        name: str,
        scan_id: str,
        report: ScoringReport,
        description: str = "",
        metadata: dict[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a named baseline referencing a scan with an immutable report snapshot.

        Args:
            name: Unique human-readable baseline name (e.g. 'v1.0-release', 'main-nightly').
            scan_id: Originating scan identifier.
            report: Canonical ScoringReport to snapshot immutably.
            description: Optional descriptive context for the baseline.
            metadata: Optional supplementary telemetry.
            tenant_id: Optional tenant identifier.

        Returns:
            Created baseline dictionary record.

        Raises:
            DuplicateRecordError: If a baseline with the specified name already exists.
            RecordNotFoundError: If the referenced scan_id does not exist.
            PersistenceError: If the persistence write fails.
        """
        ...

    async def get_baseline_by_name(self, name: str) -> dict[str, Any] | None:
        """Retrieve baseline record metadata by human-readable name."""
        ...

    async def get_baseline_by_id(self, baseline_id: str) -> dict[str, Any] | None:
        """Retrieve baseline record metadata by unique baseline_id."""
        ...

    async def get_baseline_report(self, identifier: str) -> ScoringReport | None:
        """Retrieve and reconstruct the canonical ScoringReport by baseline name or ID.

        Args:
            identifier: Either the baseline name or baseline ID.

        Returns:
            Reconstructed canonical ScoringReport, or None if not found.
        """
        ...

    async def list_baselines(
        self,
        limit: int = 50,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List baseline records ordered by creation timestamp descending."""
        ...
