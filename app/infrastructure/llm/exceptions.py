"""Normalized exception hierarchy for LLM providers in Sentinel."""


class LLMProviderError(Exception):
    """Base exception for all LLM provider failures."""

    def __init__(self, message: str, provider: str = "unknown") -> None:
        super().__init__(message)
        self.provider = provider


class LLMConfigurationError(LLMProviderError):
    """Raised when provider configuration or credentials are missing or invalid."""


class LLMAuthenticationError(LLMProviderError):
    """Raised when provider rejects credentials (e.g. HTTP 401/403)."""


class LLMTimeoutError(LLMProviderError):
    """Raised when an LLM generation call exceeds configured timeout."""


class LLMRateLimitError(LLMProviderError):
    """Raised when an LLM provider rejects requests due to rate or quota limits (e.g. HTTP 429)."""


class LLMServerError(LLMProviderError):
    """Raised when the LLM provider experiences server-side downtime (e.g. HTTP 500/502/503/504)."""


class LLMResponseError(LLMProviderError):
    """Raised when provider returns an empty, corrupted, or malformed response payload."""
