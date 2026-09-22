"""Attack and test case domain models for Sentinel."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ThreatCategory(StrEnum):
    """V1 threat categories defined in the Sentinel threat model."""

    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_LEAKAGE = "system_leakage"
    SENSITIVE_DATA_DISCLOSURE = "sensitive_data_disclosure"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    IMPROPER_OUTPUT_HANDLING = "improper_output_handling"


class Severity(StrEnum):
    """Standard vulnerability severity ratings with scoring weights."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Deterministic numeric scoring weight defined in functional requirements."""
        weights = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 4,
            Severity.CRITICAL: 8,
        }
        return weights[self]


class AttackPayload(BaseModel):
    """Core adversarial input contract.

    Represents an untrusted attack definition independent of any specific target application.
    """

    id: str = Field(..., min_length=1, description="Unique attack identifier (e.g. 'atk_t1_001')")
    category: ThreatCategory = Field(..., description="Target threat category")
    severity: Severity = Field(default=Severity.MEDIUM, description="Potential impact rating")
    prompt: str = Field(..., min_length=1, description="Raw adversarial prompt payload")
    objective: str = Field(..., min_length=1, description="Expected security violation goal")
    tags: list[str] = Field(default_factory=list, description="Descriptive classification tags")
    enabled: bool = Field(default=True, description="Whether this attack is active in test runs")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary provenance or attack library metadata",
    )


class MutationMetadata(BaseModel):
    """Provenance tracking for mutated attack variations."""

    technique: str = Field(..., description="Mutation technique (e.g. 'paraphrase', 'roleplay')")
    parent_attack_id: str = Field(..., description="ID of the source seed attack")
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration parameters applied during mutation",
    )


class TestCase(BaseModel):
    """An executable test case binding an attack payload to an execution context."""

    __test__ = False  # Prevent pytest from treating domain TestCase as a test suite class

    id: str = Field(..., min_length=1, description="Unique execution test case identifier")
    attack: AttackPayload = Field(..., description="The adversarial payload being executed")
    session_id: str = Field(..., min_length=1, description="Correlation session ID for the target")
    mutation: MutationMetadata | None = Field(
        default=None,
        description="Mutation provenance if this test case is a variation",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Execution context metadata (e.g. target configuration, run id)",
    )
