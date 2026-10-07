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
from app.domain.gates import (
    ComparisonEngine,
    ComparisonReport,
    GateFinding,
    GateResult,
    SecurityGate,
    SecurityPolicy,
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
    "ComparisonEngine",
    "ComparisonReport",
    "CompositeEvaluator",
    "CompositePolicy",
    "EvaluationResult",
    "Evaluator",
    "ExactMatchEvaluator",
    "GateFinding",
    "GateResult",
    "JudgeOutputSchema",
    "JudgeVerdict",
    "LLMProvider",
    "LLMResponse",
    "MutationMetadata",
    "ObservableToolCall",
    "RegexEvaluator",
    "ScoringResult",
    "SecurityGate",
    "SecurityPolicy",
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
