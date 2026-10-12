"""Factory for instantiating configured persistence repositories."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.config import get_settings
from app.domain.repositories import (
    BaselineRepository,
    PersistenceConfigError,
    ScanRepository,
)
from app.infrastructure.persistence.memory import (
    InMemoryBaselineRepository,
    InMemoryScanRepository,
)
from app.infrastructure.persistence.supabase import (
    SupabaseBaselineRepository,
    SupabaseScanRepository,
)

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger("sentinel.infrastructure.persistence.factory")

# Global singleton in-memory repositories for persistent state across CLI calls within a process
_IN_MEMORY_SCAN_REPO: InMemoryScanRepository | None = None
_IN_MEMORY_BASELINE_REPO: InMemoryBaselineRepository | None = None


def get_in_memory_repositories() -> tuple[InMemoryScanRepository, InMemoryBaselineRepository]:
    """Return singleton in-memory repositories preserving state within the process."""
    global _IN_MEMORY_SCAN_REPO, _IN_MEMORY_BASELINE_REPO
    if _IN_MEMORY_SCAN_REPO is None:
        _IN_MEMORY_SCAN_REPO = InMemoryScanRepository()
        _IN_MEMORY_BASELINE_REPO = InMemoryBaselineRepository(scan_repo=_IN_MEMORY_SCAN_REPO)
    assert _IN_MEMORY_BASELINE_REPO is not None
    return _IN_MEMORY_SCAN_REPO, _IN_MEMORY_BASELINE_REPO


def create_repositories(
    settings: Settings | None = None,
) -> tuple[ScanRepository | None, BaselineRepository | None]:
    """Create and configure scan and baseline repositories based on application Settings.

    Args:
        settings: Application settings. Defaults to cached get_settings().

    Returns:
        Tuple of (ScanRepository, BaselineRepository), or (None, None) if persistence is 'none'.

    Raises:
        PersistenceConfigError: If a backend is selected but required parameters are missing.
    """
    effective_settings = settings or get_settings()
    backend = effective_settings.persistence_backend.lower()

    if backend == "none":
        return None, None

    if backend == "memory":
        return get_in_memory_repositories()

    if backend == "supabase":
        url = effective_settings.supabase_url
        key = effective_settings.supabase_key
        if not url:
            raise PersistenceConfigError(
                "Persistence backend 'supabase' requires configured 'SUPABASE_URL'."
            )
        if not key:
            raise PersistenceConfigError(
                "Persistence backend 'supabase' requires configured 'SUPABASE_KEY'."
            )

        timeout = effective_settings.persistence_timeout_seconds
        scan_repo = SupabaseScanRepository(
            supabase_url=url,
            supabase_key=key,
            timeout_seconds=timeout,
        )
        baseline_repo = SupabaseBaselineRepository(
            supabase_url=url,
            supabase_key=key,
            timeout_seconds=timeout,
        )
        return scan_repo, baseline_repo

    raise PersistenceConfigError(f"Unsupported persistence backend: '{backend}'")
