"""Unit tests for configuration and logging."""

import logging

import pytest

from app.core.config import Settings, get_settings
from app.core.logging import setup_logging


def test_default_settings():
    """Verify default configuration settings."""
    settings = Settings()
    assert settings.sentinel_env == "development"
    assert settings.log_level == "INFO"
    assert settings.target_timeout_seconds == 30.0


def test_custom_settings(test_settings: Settings):
    """Verify test fixture settings override defaults."""
    assert test_settings.sentinel_env == "testing"
    assert test_settings.log_level == "DEBUG"
    assert test_settings.target_timeout_seconds == 5.0


def test_settings_env_override(monkeypatch: pytest.MonkeyPatch):
    """Verify environment variables correctly override default settings."""
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("TARGET_TIMEOUT_SECONDS", "15.5")

    settings = Settings()
    assert settings.sentinel_env == "production"
    assert settings.log_level == "WARNING"
    assert settings.target_timeout_seconds == 15.5


def test_get_settings_singleton():
    """Verify get_settings returns a cached instance."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_setup_logging():
    """Verify logging setup initializes logger with proper level."""
    logger = setup_logging("DEBUG")
    assert logger.name == "sentinel"
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) >= 1

    # Re-running setup_logging adjusts level without duplicate handlers
    logger2 = setup_logging("INFO")
    assert logger2.level == logging.INFO
    assert len(logger2.handlers) == len(logger.handlers)
