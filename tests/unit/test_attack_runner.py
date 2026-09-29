"""Comprehensive unit tests for AttackRunner and orchestration models.

Tests cover run ID generation, session isolation, reset policy lifecycle enforcement,
concurrency limiting via semaphores, deterministic result ordering, and error propagation.
"""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.exceptions import TargetResetError
from app.core.runner import AttackRunner, ResetPolicy, RunnerResult
from app.domain.attacks import AttackPayload, Severity, TestCase, ThreatCategory
from app.domain.targets import TargetAdapter, TargetResult


def create_sample_attack(
    attack_id: str = "T1-001",
    prompt: str = "Ignore instructions",
    category: ThreatCategory = ThreatCategory.PROMPT_INJECTION,
) -> AttackPayload:
    """Helper creating a valid AttackPayload instance."""
    return AttackPayload(
        id=attack_id,
        category=category,
        severity=Severity.HIGH,
        prompt=prompt,
        objective="Test defense override",
        tags=["unit_test"],
    )


class MockTargetAdapter:
    """Mock TargetAdapter recording invocations and returning configurable responses."""

    def __init__(
        self,
        default_status: str = "success",
        delay_seconds: float = 0.0,
        fail_reset: bool = False,
    ) -> None:
        self.default_status = default_status
        self.delay_seconds = delay_seconds
        self.fail_reset = fail_reset
        self.reset_call_count = 0
        self.executed_test_cases: list[TestCase] = []
        self.active_concurrent_executions = 0
        self.max_observed_concurrency = 0

    async def reset(self) -> None:
        """Record reset call or raise error if configured to fail."""
        self.reset_call_count += 1
        if self.fail_reset:
            raise TargetResetError("Target reset hook failed with HTTP 500")

    async def execute(self, test_case: TestCase) -> TargetResult:
        """Record test execution and simulate network latency / concurrency."""
        self.executed_test_cases.append(test_case)
        self.active_concurrent_executions += 1
        if self.active_concurrent_executions > self.max_observed_concurrency:
            self.max_observed_concurrency = self.active_concurrent_executions

        try:
            if self.delay_seconds > 0.0:
                await asyncio.sleep(self.delay_seconds)

            if self.default_status == "error":
                return TargetResult(
                    response=None,
                    status="error",
                    status_code=500,
                    tool_calls=[],
                    latency_ms=10.0,
                    error="Simulated target failure",
                )

            return TargetResult(
                response=f"Response for {test_case.attack.id}",
                status="success",
                status_code=200,
                tool_calls=[],
                latency_ms=15.0,
            )
        finally:
            self.active_concurrent_executions -= 1


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_mock_adapter_conforms_to_protocol():
    """Verify mock adapter satisfies TargetAdapter Protocol."""
    adapter = MockTargetAdapter()
    assert isinstance(adapter, TargetAdapter)


@pytest.mark.asyncio
async def test_empty_attack_list():
    """Verify runner handles empty attack list gracefully without calling reset."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter)

    result = await runner.run([])

    assert isinstance(result, RunnerResult)
    assert result.total_attacks == 0
    assert result.records == []
    assert result.total_duration_ms >= 0.0
    assert adapter.reset_call_count == 0


@pytest.mark.asyncio
async def test_run_id_generation_and_preservation():
    """Verify run_id is generated when omitted, and preserved when provided."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter)
    attack = create_sample_attack()

    # Case A: Generated run_id
    res1 = await runner.run([attack])
    assert res1.run_id.startswith("run_")
    assert len(res1.run_id) > 5

    # Case B: Explicit run_id
    res2 = await runner.run([attack], run_id="custom_batch_42")
    assert res2.run_id == "custom_batch_42"


@pytest.mark.asyncio
async def test_session_id_generation_formula():
    """Verify session_id follows sentinel_{run_id}_{attack.id} formula."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter)
    attack = create_sample_attack(attack_id="T4-001")

    result = await runner.run([attack], run_id="run_abc123")

    assert len(result.records) == 1
    tc = result.records[0].test_case
    assert tc.session_id == "sentinel_run_abc123_T4-001"
    assert tc.id == "tc_run_abc123_T4-001"


@pytest.mark.asyncio
async def test_per_run_reset_lifecycle():
    """Verify PER_RUN invokes adapter.reset() exactly once before executing attacks."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter, reset_policy=ResetPolicy.PER_RUN)
    attacks = [create_sample_attack("T1-001"), create_sample_attack("T1-002")]

    result = await runner.run(attacks)

    assert result.total_attacks == 2
    assert adapter.reset_call_count == 1
    assert len(adapter.executed_test_cases) == 2


@pytest.mark.asyncio
async def test_per_attack_reset_lifecycle():
    """Verify PER_ATTACK invokes adapter.reset() before each attack."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter, reset_policy=ResetPolicy.PER_ATTACK)
    attacks = [
        create_sample_attack("T1-001"),
        create_sample_attack("T1-002"),
        create_sample_attack("T1-003"),
    ]

    result = await runner.run(attacks)

    assert result.total_attacks == 3
    assert adapter.reset_call_count == 3


@pytest.mark.asyncio
async def test_never_reset_lifecycle():
    """Verify NEVER policy completely skips adapter.reset()."""
    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter, reset_policy=ResetPolicy.NEVER)
    attacks = [create_sample_attack("T1-001"), create_sample_attack("T1-002")]

    result = await runner.run(attacks)

    assert result.total_attacks == 2
    assert adapter.reset_call_count == 0


def test_per_attack_with_concurrency_rejected():
    """Verify PER_ATTACK + max_concurrency > 1 raises ValueError immediately."""
    adapter = MockTargetAdapter()

    with pytest.raises(ValueError, match="ResetPolicy.PER_ATTACK requires max_concurrency=1"):
        AttackRunner(adapter=adapter, max_concurrency=3, reset_policy=ResetPolicy.PER_ATTACK)


@pytest.mark.asyncio
async def test_initial_reset_failure_aborts_run():
    """Verify target reset failure during PER_RUN raises exception and aborts suite."""
    adapter = MockTargetAdapter(fail_reset=True)
    runner = AttackRunner(adapter=adapter, reset_policy=ResetPolicy.PER_RUN)
    attacks = [create_sample_attack()]

    with pytest.raises(TargetResetError, match="Target reset hook failed"):
        await runner.run(attacks)

    # Attacks must NOT have been executed
    assert len(adapter.executed_test_cases) == 0


@pytest.mark.asyncio
async def test_individual_attack_error_continues_suite():
    """Verify individual attack failures are captured as status='error' while suite continues."""
    attack1 = create_sample_attack("T1-001")
    attack2 = create_sample_attack("T1-002")
    attack3 = create_sample_attack("T1-003")

    class SelectiveFailAdapter(MockTargetAdapter):
        async def execute(self, test_case: TestCase) -> TargetResult:
            if test_case.attack.id == "T1-002":
                return TargetResult(
                    response=None,
                    status="error",
                    status_code=500,
                    tool_calls=[],
                    latency_ms=25.0,
                    error="Target crashed on T1-002",
                )
            return await super().execute(test_case)

    adapter = SelectiveFailAdapter()
    runner = AttackRunner(adapter=adapter)

    result = await runner.run([attack1, attack2, attack3])

    assert result.total_attacks == 3
    assert result.successful_executions == 2
    assert result.error_executions == 1

    r1, r2, r3 = result.records
    assert r1.target_result.status == "success"
    assert r2.target_result.status == "error"
    assert "Target crashed on T1-002" in (r2.target_result.error or "")
    assert r3.target_result.status == "success"


@pytest.mark.asyncio
async def test_unexpected_runner_exception_wrapped_cleanly():
    """Verify unexpected exception in adapter is caught and recorded as status='error'."""
    attack = create_sample_attack("T1-001")

    class ExplodingAdapter(MockTargetAdapter):
        async def execute(self, test_case: TestCase) -> TargetResult:
            raise RuntimeError("Unexpected adapter memory corruption")

    adapter = ExplodingAdapter()
    runner = AttackRunner(adapter=adapter)

    result = await runner.run([attack])

    assert result.total_attacks == 1
    assert result.error_executions == 1
    assert result.successful_executions == 0
    record = result.records[0]
    assert record.target_result.status == "error"
    assert "Unexpected adapter memory corruption" in (record.target_result.error or "")
    assert record.target_result.metadata["error_type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_semaphore_concurrency_limit_and_order_preservation():
    """Verify max_concurrency bounds active tasks while preserving deterministic input order."""
    attacks = [create_sample_attack(f"T1-{i:03d}") for i in range(1, 7)]

    class VariableDelayAdapter(MockTargetAdapter):
        async def execute(self, test_case: TestCase) -> TargetResult:
            # Stagger delays so earlier attacks finish later
            delays = {
                "T1-001": 0.08,
                "T1-002": 0.01,
                "T1-003": 0.05,
                "T1-004": 0.02,
                "T1-005": 0.07,
                "T1-006": 0.01,
            }
            self.delay_seconds = delays.get(test_case.attack.id, 0.02)
            return await super().execute(test_case)

    adapter = VariableDelayAdapter()
    concurrency_limit = 2
    runner = AttackRunner(adapter=adapter, max_concurrency=concurrency_limit)

    result = await runner.run(attacks)

    # Verify concurrency limit respected
    assert adapter.max_observed_concurrency <= concurrency_limit
    assert result.total_attacks == 6

    # Verify input order preserved deterministically despite out-of-order completion
    expected_ids = [f"T1-{i:03d}" for i in range(1, 7)]
    actual_ids = [r.test_case.attack.id for r in result.records]
    assert actual_ids == expected_ids


@pytest.mark.asyncio
async def test_runner_result_computed_counters_and_single_source_of_truth():
    """Verify computed_field counters dynamically reflect records content."""
    attack1 = create_sample_attack("T1-001")
    attack2 = create_sample_attack("T1-002")

    adapter = MockTargetAdapter()
    runner = AttackRunner(adapter=adapter)

    result = await runner.run([attack1, attack2])

    assert result.total_attacks == 2
    assert result.successful_executions == 2
    assert result.error_executions == 0

    # Test serialization includes computed fields
    dumped = result.model_dump()
    assert "total_attacks" in dumped
    assert "successful_executions" in dumped
    assert "error_executions" in dumped
    assert dumped["total_attacks"] == 2
    assert dumped["successful_executions"] == 2
    assert dumped["error_executions"] == 0
