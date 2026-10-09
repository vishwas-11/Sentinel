"""Mutation engine coordinating adversarial payload transformations and provenance tracking."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from app.domain.attacks import AttackPayload, MutationMetadata
from app.domain.mutations.base import (
    MutationError,
    MutationStrategy,
    StrategyUnavailableError,
)
from app.domain.mutations.models import MutationConfig
from app.domain.mutations.strategies import (
    Base64MutationStrategy,
    DelimiterMutationStrategy,
    MultilingualMutationStrategy,
    ParaphraseMutationStrategy,
)

if TYPE_CHECKING:
    from app.domain.llm import LLMProvider

logger = logging.getLogger("sentinel.domain.mutations.engine")


class MutationEngine:
    """Orchestrates mutation strategies to expand attack coverage.

    Responsibilities:
    - Maintains a registry of active mutation strategies.
    - Validates mutation inputs and enforces payload length and count limits.
    - Eliminates duplicates and prevents unchanged payloads from generating tests.
    - Generates non-colliding, deterministic AttackPayload IDs.
    - Attaches comprehensive MutationMetadata provenance to every generated payload.
    - Gracefully isolates individual strategy failures without aborting the scan.

    Non-Responsibilities:
    - Does NOT execute target HTTP calls (handled by AttackRunner).
    - Does NOT score or render verdicts (handled by Evaluators and ScoringEngine).
    - Does NOT duplicate CLI or FastAPI parameters.
    """

    def __init__(
        self,
        strategies: Sequence[MutationStrategy] | None = None,
        provider: LLMProvider | None = None,
    ) -> None:
        """Initialize the mutation engine with registered strategies.

        Args:
            strategies: Optional explicit sequence of strategies. If None, default
                        strategies (Base64, Delimiter, Paraphrase, Multilingual) are loaded.
            provider: Optional LLMProvider forwarded to generative strategies.
        """
        self._registry: dict[str, MutationStrategy] = {}

        if strategies is not None:
            for strat in strategies:
                self.register_strategy(strat)
        else:
            # Register default standard strategies
            self.register_strategy(Base64MutationStrategy())
            self.register_strategy(DelimiterMutationStrategy())
            self.register_strategy(ParaphraseMutationStrategy(provider=provider))
            self.register_strategy(MultilingualMutationStrategy(provider=provider))

    def register_strategy(self, strategy: MutationStrategy) -> None:
        """Register or replace a mutation strategy in the engine."""
        self._registry[strategy.technique] = strategy
        logger.debug("Registered mutation strategy: %s", strategy.technique)

    def get_strategy(self, technique: str) -> MutationStrategy | None:
        """Retrieve a registered strategy by technique name."""
        return self._registry.get(technique)

    @property
    def registered_techniques(self) -> list[str]:
        """List of all currently registered strategy technique identifiers."""
        return sorted(self._registry.keys())

    async def mutate_attack(
        self,
        attack: AttackPayload,
        config: MutationConfig | None = None,
    ) -> list[AttackPayload]:
        """Generate mutated variations for a single seed AttackPayload.

        Args:
            attack: Original seed AttackPayload.
            config: Optional MutationConfig controlling strategies, limits, and seed.

        Returns:
            List of valid, mutated AttackPayload objects with provenance attached.
        """
        cfg = config or MutationConfig()
        if not attack.enabled:
            return []

        active_strategies: list[MutationStrategy] = []
        for strat_name in cfg.strategies:
            strat = self._registry.get(strat_name)
            if strat:
                active_strategies.append(strat)
            else:
                logger.warning("Requested mutation strategy '%s' is not registered.", strat_name)

        if not active_strategies:
            return []

        mutated_attacks: list[AttackPayload] = []
        seen_prompts: set[str] = {attack.prompt.strip()}
        strategy_counters: dict[str, int] = {}

        for strat in active_strategies:
            # Determine how many variations to request from this strategy
            variations_to_request = cfg.mutations_per_attack

            try:
                outputs = await strat.mutate(
                    attack=attack,
                    count=variations_to_request,
                    seed=cfg.seed,
                )
            except StrategyUnavailableError as exc:
                logger.info(
                    "Strategy '%s' unavailable for attack %s: %s",
                    strat.technique,
                    attack.id,
                    exc,
                )
                continue
            except MutationError as exc:
                logger.warning(
                    "Mutation error in strategy '%s' for attack %s: %s",
                    strat.technique,
                    attack.id,
                    exc,
                )
                continue
            except Exception as exc:
                logger.error(
                    "Unexpected exception in strategy '%s' for attack %s: %s",
                    strat.technique,
                    attack.id,
                    exc,
                )
                continue

            for out in outputs:
                candidate_prompt = out.mutated_prompt.strip()

                # Invariant 1: Reject empty output
                if not candidate_prompt:
                    continue

                # Invariant 2: Reject unchanged payload (mutation must transform the prompt)
                if candidate_prompt in seen_prompts:
                    continue

                # Invariant 3: Enforce maximum payload length bound to mitigate DoS
                if len(candidate_prompt) > cfg.max_payload_length:
                    logger.warning(
                        "Discarding mutation exceeding max length (%d > %d)",
                        len(candidate_prompt),
                        cfg.max_payload_length,
                    )
                    continue

                seen_prompts.add(candidate_prompt)
                idx = strategy_counters.get(out.technique, 0)
                strategy_counters[out.technique] = idx + 1

                # Deterministic, unique attack ID preserving parent lineage
                mutated_id = f"{attack.id}_mut_{out.technique}_{idx:02d}"

                # Structured provenance
                mutation_meta = MutationMetadata(
                    technique=out.technique,
                    parent_attack_id=attack.id,
                    parameters=out.parameters,
                )

                # Distinct tags combining seed tags with mutation provenance
                new_tags = sorted(list(set(attack.tags + ["mutated", out.technique])))

                mutated_payload = AttackPayload(
                    id=mutated_id,
                    category=attack.category,
                    severity=attack.severity,
                    prompt=candidate_prompt,
                    objective=attack.objective,
                    tags=new_tags,
                    enabled=True,
                    metadata={
                        "parent_attack_id": attack.id,
                        "mutation": mutation_meta.model_dump(),
                    },
                )
                mutated_attacks.append(mutated_payload)

        return mutated_attacks

    async def generate_mutations(
        self,
        attacks: list[AttackPayload],
        config: MutationConfig | None = None,
    ) -> list[AttackPayload]:
        """Generate mutations for a sequence of attacks, returning original + mutated.

        Args:
            attacks: List of seed AttackPayload objects.
            config: Optional MutationConfig controlling mutation behavior.

        Returns:
            Combined list containing original seed attacks followed by generated mutations.
        """
        cfg = config or MutationConfig()
        if not cfg.enabled:
            return attacks

        combined: list[AttackPayload] = list(attacks)

        for attack in attacks:
            mutated = await self.mutate_attack(attack=attack, config=cfg)
            combined.extend(mutated)

        logger.info(
            "Mutation engine generated %d mutated payloads from %d seed attacks (total: %d)",
            len(combined) - len(attacks),
            len(attacks),
            len(combined),
        )
        return combined
