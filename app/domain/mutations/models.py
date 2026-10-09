"""Domain models and configuration schemas for the Sentinel mutation engine."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.domain.attacks import AttackPayload, MutationMetadata


class MutationTechnique(StrEnum):
    """Supported mutation technique identifiers."""

    BASE64 = "base64"
    DELIMITER = "delimiter"
    PARAPHRASE = "paraphrase"
    MULTILINGUAL = "multilingual"


class MutationConfig(BaseModel):
    """Runtime configuration for adversarial payload mutation."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Whether adversarial mutation is active during the scan",
    )
    strategies: list[str] = Field(
        default_factory=lambda: [
            MutationTechnique.BASE64.value,
            MutationTechnique.DELIMITER.value,
        ],
        description="List of mutation strategy names to apply",
    )
    mutations_per_attack: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Target number of mutated variations to generate per seed attack",
    )
    seed: int | None = Field(
        default=None,
        description="Random seed for reproducible deterministic mutations",
    )
    max_payload_length: int = Field(
        default=10000,
        gt=0,
        description="Maximum character length of generated mutation payloads to prevent DoS",
    )


class MutationOutput(BaseModel):
    """Container for an individual mutation generation attempt."""

    model_config = ConfigDict(extra="forbid")

    mutated_prompt: str = Field(..., min_length=1, description="Transformed adversarial prompt")
    technique: str = Field(..., description="Mutation technique identifier")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters applied during mutation (e.g. delimiter style, language)",
    )


class MutatedAttack(BaseModel):
    """An AttackPayload bundled with its formal MutationMetadata provenance."""

    model_config = ConfigDict(extra="forbid")

    payload: AttackPayload
    metadata: MutationMetadata
