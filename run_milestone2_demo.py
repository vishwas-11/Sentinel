"""Educational manual verification script for Phase 7 Milestone 2 configuration."""

from pydantic import SecretStr, ValidationError
import pytest

from app.core.config import Settings


def main() -> None:
    print("=" * 65)
    print("SENTINEL PHASE 7 MILESTONE 2 — MANUAL CONFIGURATION VERIFICATION")
    print("=" * 65)

    # 1. Default Configuration
    default_settings = Settings()
    print("\n[1] Default Settings Inspection:")
    print(f"    llm_provider:        {default_settings.llm_provider} (safe offline default)")
    print(f"    llm_model:           {default_settings.llm_model}")
    print(f"    llm_api_key:         {default_settings.llm_api_key}")
    print(f"    llm_timeout_seconds: {default_settings.llm_timeout_seconds}s")
    print(f"    llm_max_retries:     {default_settings.llm_max_retries}")
    assert default_settings.llm_provider == "mock"
    assert default_settings.llm_api_key is None

    # 2. SecretStr Protection Verification
    secret_key = SecretStr("sk-prod-super-secret-key-xyz123")
    configured_settings = Settings(
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_api_key=secret_key,
        llm_timeout_seconds=20.0,
        llm_max_retries=1,
    )
    print("\n[2] SecretStr Redaction & Access Inspection:")
    print(f"    str(settings.llm_api_key):          {str(configured_settings.llm_api_key)}")
    print(f"    repr(settings.llm_api_key):         {repr(configured_settings.llm_api_key)}")
    print(f"    repr(settings) snippet:             ...{repr(configured_settings)[-90:]}")
    print(f"    Explicit .get_secret_value():       {configured_settings.llm_api_key.get_secret_value()}")
    assert "sk-prod-super-secret-key" not in str(configured_settings.llm_api_key)
    assert "sk-prod-super-secret-key" not in repr(configured_settings)
    assert configured_settings.llm_api_key.get_secret_value() == "sk-prod-super-secret-key-xyz123"

    # 3. Validation Bounds Enforcement
    print("\n[3] Validation Constraints Inspection:")
    # Invalid provider
    try:
        Settings(llm_provider="unsupported-vendor")  # type: ignore[arg-type]
        raise AssertionError("Failed to reject invalid provider")
    except ValidationError as exc:
        print(f"    Rejected invalid provider: {exc.errors()[0]['msg']}")

    # Invalid timeout <= 0
    try:
        Settings(llm_timeout_seconds=0.0)
        raise AssertionError("Failed to reject non-positive timeout")
    except ValidationError as exc:
        print(f"    Rejected non-positive timeout: {exc.errors()[0]['msg']}")

    # Invalid retries < 0
    try:
        Settings(llm_max_retries=-1)
        raise AssertionError("Failed to reject negative retry count")
    except ValidationError as exc:
        print(f"    Rejected negative retry count: {exc.errors()[0]['msg']}")

    print("\n" + "=" * 65)
    print("ALL MILESTONE 2 MANUAL CONFIGURATION CHECKS PASSED!")
    print("=" * 65)


if __name__ == "__main__":
    main()
