"""Domain layer containing pure Sentinel business rules and protocols.

This module has NO dependencies on web frameworks (FastAPI), databases (Supabase),
or external LLM provider SDKs.
"""

from app.domain.attacks import (
    AttackPayload,
    MutationMetadata,
    Severity,
    TestCase,
    ThreatCategory,
)
from app.domain.evaluation import (
    EvaluationResult,
    JudgeVerdict,
    VerdictOutcome,
)
from app.domain.scoring import (
    ScoringResult,
)
from app.domain.targets import (
    ObservableToolCall,
    TargetAdapter,
    TargetResult,
)

__all__ = [
    "AttackPayload",
    "EvaluationResult",
    "JudgeVerdict",
    "MutationMetadata",
    "ObservableToolCall",
    "ScoringResult",
    "Severity",
    "TargetAdapter",
    "TargetResult",
    "TestCase",
    "ThreatCategory",
    "VerdictOutcome",
]
