"""Application service coordinating end-to-end security scans.

Connects:
AttackLoader -> TargetAdapter -> AttackRunner -> Evaluator -> ScoringEngine -> ScoringReport

Keeps the execution pipeline completely decoupled from user interfaces (CLI, API, CI).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path

from app.adapters.http import HttpTargetAdapter
from app.attacks.loader import AttackLoader
from app.core.config import Settings, get_settings
from app.core.runner import AttackRunner, ResetPolicy, RunnerResult
from app.domain.attacks import ThreatCategory
from app.domain.evaluation import (
    Evaluator,
    HybridEvaluationOrchestrator,
    LLMJudge,
    SemanticJudge,
)
from app.domain.evaluation.models import EvaluationResult
from app.domain.mutations import MutationConfig, MutationEngine
from app.domain.scoring import ScoringEngine, ScoringReport
from app.domain.targets import TargetAdapter
from app.infrastructure.llm.factory import create_llm_provider

logger = logging.getLogger("sentinel.core.scan_service")


class ScanService:
    """Application Service encapsulating the entire security scan pipeline.

    Responsibilities:
    - Loads attacks from the attack library.
    - Configures target transport adapter and lifecycle policies.
    - Executes test cases concurrently with bounded concurrency.
    - Evaluates observed target behaviors using configured evaluators.
    - Aggregates metrics and computes the final authoritative ScoringReport.

    Non-Responsibilities:
    - Does NOT parse command line arguments (handled by CLI parser).
    - Does NOT render terminal colors or ANSI formatting (handled by CLI output).
    - Does NOT terminate Python processes or assign exit codes.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        scoring_engine: ScoringEngine | None = None,
    ) -> None:
        """Initialize the scan service.

        Args:
            settings: Optional explicit settings instance. Defaults to cached get_settings().
            scoring_engine: Optional injected scoring engine. Defaults to standard ScoringEngine().
        """
        self.settings = settings or get_settings()
        self.scoring_engine = scoring_engine or ScoringEngine()

    async def run_scan(
        self,
        target_url: str | None = None,
        attacks_dir: Path | str | None = None,
        category: ThreatCategory | str | None = None,
        concurrency: int | None = None,
        reset_policy: ResetPolicy | str | None = None,
        evaluators: Sequence[Evaluator] | None = None,
        target_adapter: TargetAdapter | None = None,
        enable_mutations: bool | None = None,
        mutation_strategies: Sequence[str] | None = None,
        mutations_per_attack: int | None = None,
        mutation_seed: int | None = None,
        mutation_engine: MutationEngine | None = None,
    ) -> ScoringReport:
        """Execute a complete end-to-end security benchmark scan.

        Configuration precedence:
        explicit method argument -> configured environment settings -> default

        Args:
            target_url: Target base URL override.
            attacks_dir: Path to directory containing attack JSON definitions.
            category: Threat category to filter attacks by.
            concurrency: Max concurrent asynchronous attack requests.
            reset_policy: Target reset lifecycle policy.
            evaluators: Sequence of evaluators; defaults to standard deterministic evaluators.
            target_adapter: Optional injected target adapter (e.g. for testing or mock targets).
            enable_mutations: Optional boolean override to enable adversarial payload mutations.
            mutation_strategies: Optional sequence of mutation strategies to execute.
            mutations_per_attack: Number of mutated variations to generate per seed attack.
            mutation_seed: Optional seed for reproducible deterministic mutations.
            mutation_engine: Optional injected MutationEngine instance.

        Returns:
            Authoritative, serializable ScoringReport with scores, ASR, and findings.
        """
        # 1. Resolve configuration with explicit precedence
        effective_url = target_url or self.settings.target_base_url
        effective_concurrency = (
            concurrency if concurrency is not None else self.settings.runner_max_concurrency
        )

        resolved_reset = reset_policy or self.settings.runner_reset_policy
        if isinstance(resolved_reset, str):
            effective_reset_policy = ResetPolicy(resolved_reset)
        else:
            effective_reset_policy = resolved_reset

        resolved_category: ThreatCategory | None = None
        if category is not None:
            resolved_category = ThreatCategory(category) if isinstance(category, str) else category

        logger.info(
            "Starting Sentinel security scan against %s (concurrency=%d, reset=%s)",
            effective_url,
            effective_concurrency,
            effective_reset_policy.value,
        )

        # 2. Load and filter attack payloads
        loader = AttackLoader(attacks_dir=attacks_dir)
        if resolved_category:
            attacks = loader.get_by_category(resolved_category)
        else:
            attacks = loader.load_attacks(include_disabled=False)

        if not attacks:
            logger.warning("No attack definitions discovered to execute.")
            # Calculate empty scoring report
            return self.scoring_engine.calculate([])

        # 2b. Optional adversarial mutation expansion
        effective_enable_mutations = (
            enable_mutations if enable_mutations is not None else self.settings.enable_mutations
        )
        if effective_enable_mutations:
            effective_strategies = list(
                mutation_strategies
                if mutation_strategies is not None
                else self.settings.default_mutation_strategies
            )
            effective_count = (
                mutations_per_attack
                if mutations_per_attack is not None
                else self.settings.default_mutations_per_attack
            )

            mut_config = MutationConfig(
                enabled=True,
                strategies=effective_strategies,
                mutations_per_attack=effective_count,
                seed=mutation_seed,
            )

            engine = mutation_engine
            if engine is None:
                llm_provider = None
                try:
                    llm_provider = create_llm_provider(self.settings)
                except Exception as exc:
                    logger.debug("LLM provider unavailable for mutations: %s", exc)
                engine = MutationEngine(provider=llm_provider)

            attacks = await engine.generate_mutations(attacks, config=mut_config)

        # 3. Initialize target adapter if not injected
        adapter = target_adapter or HttpTargetAdapter(
            base_url=effective_url,
            timeout_seconds=self.settings.target_timeout_seconds,
            connect_timeout_seconds=self.settings.target_connect_timeout_seconds,
            settings=self.settings,
        )

        # 4. Execute attacks via AttackRunner
        runner = AttackRunner(
            adapter=adapter,
            max_concurrency=effective_concurrency,
            reset_policy=effective_reset_policy,
        )
        runner_result: RunnerResult = await runner.run(attacks)

        # 5. Evaluate execution records via HybridEvaluationOrchestrator
        active_judge: SemanticJudge | None = None
        try:
            llm_provider = create_llm_provider(self.settings)
            active_judge = LLMJudge(provider=llm_provider)
        except Exception as exc:
            logger.warning("Could not initialize LLM judge: %s. Using deterministic only.", exc)

        orchestrator = HybridEvaluationOrchestrator(
            deterministic_evaluators=evaluators or [],
            semantic_judge=active_judge,
        )

        evaluation_results: list[EvaluationResult] = []
        for record in runner_result.records:
            eval_res = await orchestrator.evaluate(record)
            evaluation_results.append(eval_res)

        # 6. Compute scores and compile final ScoringReport
        scoring_report = self.scoring_engine.calculate(evaluation_results)
        logger.info(
            "Scan complete. Evaluated: %d, ASR: %s, Security Score: %s",
            scoring_report.evaluated_attacks,
            f"{scoring_report.attack_success_rate:.1%}"
            if scoring_report.attack_success_rate is not None
            else "N/A",
            f"{scoring_report.security_score:.2f}"
            if scoring_report.security_score is not None
            else "N/A",
        )
        return scoring_report
