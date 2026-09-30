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
    CompositeEvaluator,
    CompositePolicy,
    EvaluationResult,
    Evaluator,
    ExactMatchEvaluator,
    JudgeOutputSchema,
    JudgeVerdict,
    RegexEvaluator,
    SemanticJudge,
    TestExecutionRecord,
    ToolCallEvaluator,
    VerdictOutcome,
)
from app.domain.llm import (
    LLMProvider,
    LLMResponse,
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
    "CompositeEvaluator",
    "CompositePolicy",
    "EvaluationResult",
    "Evaluator",
    "ExactMatchEvaluator",
    "JudgeOutputSchema",
    "JudgeVerdict",
    "LLMProvider",
    "LLMResponse",
    "MutationMetadata",
    "ObservableToolCall",
    "RegexEvaluator",
    "ScoringResult",
    "SemanticJudge",
    "Severity",
    "TargetAdapter",
    "TargetResult",
    "TestCase",
    "TestExecutionRecord",
    "ThreatCategory",
    "ToolCallEvaluator",
    "VerdictOutcome",
]
