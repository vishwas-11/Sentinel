"""Attack Runner application service for Sentinel.

Coordinates the end-to-end execution of attack suites against an external target,
managing run IDs, session isolation, reset policies, concurrency limits, and result collection.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field

from app.domain.attacks import AttackPayload, TestCase
from app.domain.evaluation import TestExecutionRecord
from app.domain.targets import TargetAdapter, TargetResult

logger = logging.getLogger("sentinel.core.runner")


class ResetPolicy(StrEnum):
    """Lifecycle policy controlling when the external target state is reset."""

    PER_RUN = "per_run"  # Reset once before the test suite begins (default)
    PER_ATTACK = "per_attack"  # Reset before every individual attack (strict isolation)
    NEVER = "never"  # Never invoke reset (for stateless or live staging targets)


class RunnerResult(BaseModel):
    """Aggregated outcome of an entire benchmark test suite execution."""

    run_id: str = Field(..., description="Correlation ID for this benchmark run")
    records: list[TestExecutionRecord] = Field(
        default_factory=list,
        description="Ordered list of execution records matching input attack sequence",
    )
    total_duration_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Total wall-clock duration of the test run in milliseconds",
    )

    @computed_field
    @property
    def total_attacks(self) -> int:
        """Total number of attacks evaluated in this run (single source of truth)."""
        return len(self.records)

    @computed_field
    @property
    def successful_executions(self) -> int:
        """Count of test cases whose target execution completed with status='success'."""
        return sum(1 for r in self.records if r.target_result.status == "success")

    @computed_field
    @property
    def error_executions(self) -> int:
        """Count of test cases that experienced transport or execution errors."""
        return sum(1 for r in self.records if r.target_result.status == "error")


class AttackRunner:
    """Application service orchestrating attack suite execution against an external target."""

    def __init__(
        self,
        adapter: TargetAdapter,
        max_concurrency: int = 1,
        reset_policy: ResetPolicy | str = ResetPolicy.PER_RUN,
    ) -> None:
        """Initialize the AttackRunner.

        Args:
            adapter: Concrete TargetAdapter implementation for target communication.
            max_concurrency: Maximum number of concurrent attack executions (default 1).
            reset_policy: ResetPolicy determining when target state is reset.

        Raises:
            ValueError: If PER_ATTACK reset policy is specified with max_concurrency > 1.
        """
        self.adapter = adapter
        self.reset_policy = ResetPolicy(reset_policy)
        self.max_concurrency = max(1, max_concurrency)

        if self.reset_policy == ResetPolicy.PER_ATTACK and self.max_concurrency > 1:
            raise ValueError(
                "ResetPolicy.PER_ATTACK requires max_concurrency=1 to prevent "
                "race conditions on target state resets."
            )

        self._semaphore = asyncio.Semaphore(self.max_concurrency)

    def _create_test_case(self, attack: AttackPayload, run_id: str) -> TestCase:
        """Construct an executable TestCase binding the attack to an isolated session."""
        session_id = f"sentinel_{run_id}_{attack.id}"
        test_case_id = f"tc_{run_id}_{attack.id}"

        return TestCase(
            id=test_case_id,
            attack=attack,
            session_id=session_id,
            metadata={"run_id": run_id},
        )

    async def _execute_single(self, attack: AttackPayload, run_id: str) -> TestExecutionRecord:
        """Execute a single attack against the target, handling per-attack reset if configured."""
        if self.reset_policy == ResetPolicy.PER_ATTACK:
            await self.adapter.reset()

        test_case = self._create_test_case(attack, run_id)

        try:
            target_result = await self.adapter.execute(test_case)
        except Exception as exc:
            logger.error("Unhandled exception during test case %s: %s", test_case.id, exc)
            target_result = TargetResult(
                response=None,
                status="error",
                status_code=None,
                tool_calls=[],
                latency_ms=0.0,
                metadata={"error_type": type(exc).__name__},
                error=f"Unhandled runner exception: {exc}",
            )

        return TestExecutionRecord(
            test_case=test_case,
            target_result=target_result,
        )

    async def run(
        self,
        attacks: list[AttackPayload],
        run_id: str | None = None,
    ) -> RunnerResult:
        """Execute a collection of attacks against the target application.

        Args:
            attacks: List of validated AttackPayload objects to execute.
            run_id: Optional correlation ID for the run (defaults to generated ID).

        Returns:
            RunnerResult containing ordered execution records and summary metrics.

        Raises:
            TargetConnectionError: If initial target reset fails due to connection drop.
            TargetResetError: If initial target reset returns a non-200 failure.
        """
        effective_run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"

        if not attacks:
            return RunnerResult(
                run_id=effective_run_id,
                records=[],
                total_duration_ms=0.0,
            )

        start_time = time.perf_counter()

        # Execute pre-run target reset if policy specifies
        if self.reset_policy == ResetPolicy.PER_RUN:
            logger.info("Executing pre-run target reset for %s", effective_run_id)
            await self.adapter.reset()

        # Dispatch attacks based on concurrency settings
        if self.max_concurrency == 1:
            records: list[TestExecutionRecord] = []
            for attack in attacks:
                record = await self._execute_single(attack, effective_run_id)
                records.append(record)
        else:
            ordered_records: list[TestExecutionRecord | None] = [None] * len(attacks)

            async def _bounded_worker(index: int, payload: AttackPayload) -> None:
                async with self._semaphore:
                    ordered_records[index] = await self._execute_single(payload, effective_run_id)

            tasks = [
                asyncio.create_task(_bounded_worker(idx, atk)) for idx, atk in enumerate(attacks)
            ]
            await asyncio.gather(*tasks)
            records = [r for r in ordered_records if r is not None]

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return RunnerResult(
            run_id=effective_run_id,
            records=records,
            total_duration_ms=round(elapsed_ms, 2),
        )
