"""Global test fixtures for Sentinel."""

import pytest

from app.core.config import Settings


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing isolated, known settings for testing."""
    return Settings(
        sentinel_env="testing",
        log_level="DEBUG",
        target_timeout_seconds=5.0,
    )
