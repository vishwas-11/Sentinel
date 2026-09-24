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


@lru_cache
def get_settings() -> Settings:
    """Return a cached singleton instance of Settings."""
    return Settings()
