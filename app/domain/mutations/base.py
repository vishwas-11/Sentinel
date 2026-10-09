"""Base contracts, protocols, and exceptions for Sentinel mutation strategies."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.domain.attacks import AttackPayload
from app.domain.mutations.models import MutationOutput


class MutationError(Exception):
    """Base exception for mutation engine failures."""


class StrategyUnavailableError(MutationError):
    """Raised when a requested mutation strategy cannot run due to missing prerequisites."""


class InvalidPayloadError(MutationError):
    """Raised when an attack payload cannot be transformed due to validation failure."""


@runtime_checkable
class MutationStrategy(Protocol):
    """Abstract protocol for individual adversarial payload mutation strategies.

    Responsibilities:
    - Transform an adversarial prompt while preserving its core security goal.
    - Support deterministic execution with seed/index when applicable.
    - Emit typed MutationOutput envelopes containing the transformed prompt and parameters.

    Non-Responsibilities:
    - Does NOT synthesize AttackPayload or TestCase IDs (handled by MutationEngine).
    - Does NOT execute attacks against targets or evaluators.
    - Does NOT log to external databases or services.
    """

    @property
    def technique(self) -> str:
        """Unique identifier of the mutation technique (e.g. 'base64', 'delimiter')."""
        ...

    async def mutate(
        self,
        attack: AttackPayload,
        count: int = 1,
        seed: int | None = None,
    ) -> list[MutationOutput]:
        """Generate one or more mutated prompt variations for the provided attack.

        Args:
            attack: Original seed AttackPayload to mutate.
            count: Number of variations requested from this strategy.
            seed: Optional seed for deterministic variation selection.

        Returns:
            List of MutationOutput objects containing transformed prompts and parameters.

        Raises:
            StrategyUnavailableError: If required dependencies (e.g. LLM provider) are missing.
            InvalidPayloadError: If the input attack prompt is empty or malformed.
        """
        ...
