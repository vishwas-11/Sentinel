"""Configuration management for Sentinel using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central typed settings for Sentinel backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
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

    # Target Adapter Defaults
    target_timeout_seconds: float = Field(
        default=30.0,
        description="Default timeout in seconds for target HTTP adapter calls",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of Settings."""
    return Settings()
