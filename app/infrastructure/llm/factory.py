"""Factory for instantiating LLMProvider implementations from application Settings."""

from app.core.config import Settings, get_settings
from app.domain.llm import LLMProvider
from app.infrastructure.llm.exceptions import LLMConfigurationError
from app.infrastructure.llm.mock import MockLLMProvider
from app.infrastructure.llm.openai import OpenAIProvider


def create_llm_provider(settings: Settings | None = None) -> LLMProvider:
    """Instantiate and return the configured LLMProvider.

    Args:
        settings: Optional Settings instance; defaults to singleton get_settings().

    Returns:
        Configured LLMProvider conforming to the domain protocol.

    Raises:
        LLMConfigurationError: If requested provider requires missing credentials,
                               is unsupported, or has not been implemented yet.
    """
    cfg = settings or get_settings()
    provider_name = cfg.llm_provider.lower().strip()

    if provider_name == "mock":
        return MockLLMProvider(model_name=cfg.llm_model)

    if provider_name == "openai":
        if cfg.llm_api_key is None or not cfg.llm_api_key.get_secret_value().strip():
            raise LLMConfigurationError(
                "OpenAI provider selected (LLM_PROVIDER=openai) but LLM_API_KEY is not configured.",
                provider="openai",
            )
        return OpenAIProvider(
            api_key=cfg.llm_api_key,
            model_name=cfg.llm_model,
            timeout_seconds=cfg.llm_timeout_seconds,
            max_retries=cfg.llm_max_retries,
        )

    if provider_name == "gemini":
        # Strict explicit failure: Never silently fall back to mock
        raise LLMConfigurationError(
            "Gemini provider is selected in configuration but is not yet implemented. "
            "Please configure LLM_PROVIDER=mock or LLM_PROVIDER=openai.",
            provider="gemini",
        )

    raise LLMConfigurationError(
        f"Unsupported LLM provider '{provider_name}'. Supported options are: 'mock', 'openai'.",
        provider=provider_name,
    )
