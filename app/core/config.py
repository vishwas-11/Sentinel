"""Configuration management for Sentinel using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central typed settings for Sentinel backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # Runtime Environment
    sentinel_env: Literal["development", "testing", "production"] = Field(
        default="development",
        description="Operating environment name",
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Log output severity threshold",
    )

    # Target Adapter Configuration
    target_base_url: str = Field(
        default="http://localhost:8001",
        alias="sentinel_target_url",
        description="Base URL of target application (defaults to reference-target at port 8001)",
    )
    target_timeout_seconds: float = Field(
        default=30.0,
        description="Default total timeout in seconds for target HTTP adapter calls",
    )
    target_connect_timeout_seconds: float = Field(
        default=5.0,
        description="Connect timeout in seconds for establishing connection to target",
    )

    # Runner Orchestration Configuration
    runner_max_concurrency: int = Field(
        default=1,
        ge=1,
        description="Default concurrency limit for attack execution (1 = sequential)",
    )
    runner_reset_policy: str = Field(
        default="per_run",
        description="Default target reset policy: 'per_run', 'per_attack', or 'never'",
    )

    # LLM Judge & Provider Configuration
    llm_provider: Literal["mock", "openai", "gemini"] = Field(
        default="mock",
        description="Configured LLM provider implementation ('mock' for offline testing)",
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        min_length=1,
        description="Identifier of the configured model (e.g. 'gpt-4o-mini', 'gemini-1.5-pro')",
    )
    llm_api_key: SecretStr | None = Field(
        default=None,
        description="API key for real LLM provider (optional when llm_provider='mock')",
    )
    llm_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        description="Timeout in seconds for LLM generation requests",
    )
    llm_max_retries: int = Field(
        default=2,
        ge=0,
        description="Maximum retry attempts on transient network or rate-limit failures",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of Settings."""
    return Settings()
