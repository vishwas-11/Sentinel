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


def test_default_llm_settings():
    """Verify default LLM provider and judge settings."""
    settings = Settings()
    assert settings.llm_provider == "mock"
    assert settings.llm_model == "gpt-4o-mini"
    assert settings.llm_api_key is None
    assert settings.llm_timeout_seconds == 30.0
    assert settings.llm_max_retries == 2


def test_llm_settings_env_override(monkeypatch: pytest.MonkeyPatch):
    """Verify environment variables correctly override LLM settings."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_API_KEY", "test-secret-key-12345")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "15.0")
    monkeypatch.setenv("LLM_MAX_RETRIES", "0")

    settings = Settings()
    assert settings.llm_provider == "openai"
    assert settings.llm_model == "gpt-4o"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-secret-key-12345"
    assert settings.llm_timeout_seconds == 15.0
    assert settings.llm_max_retries == 0


def test_llm_api_key_secret_str_masking():
    """Verify that SecretStr hides the raw secret in string representations."""
    from pydantic import SecretStr

    settings = Settings(llm_api_key=SecretStr("super-confidential-key"))
    assert settings.llm_api_key is not None
    # SecretStr must mask the content in str() and repr()
    assert "super-confidential-key" not in str(settings.llm_api_key)
    assert "super-confidential-key" not in repr(settings.llm_api_key)
    assert "super-confidential-key" not in repr(settings)
    assert settings.llm_api_key.get_secret_value() == "super-confidential-key"


def test_llm_settings_validation_errors():
    """Verify validation boundaries for LLM settings."""
    from pydantic import ValidationError

    # Invalid provider literal
    with pytest.raises(ValidationError):
        Settings(llm_provider="unsupported_provider")  # type: ignore[arg-type]

    # Non-positive timeout
    with pytest.raises(ValidationError):
        Settings(llm_timeout_seconds=0.0)

    with pytest.raises(ValidationError):
        Settings(llm_timeout_seconds=-5.0)

    # Negative max_retries
    with pytest.raises(ValidationError):
        Settings(llm_max_retries=-1)

    # Empty model string
    with pytest.raises(ValidationError):
        Settings(llm_model="")
