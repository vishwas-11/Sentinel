"""Manual demonstration of Sentinel Phase 12 Mutation Engine.

Demonstrates:
1. Loading a static seed attack payload from the attack library.
2. Generating mutations using all 4 strategies (Base64, Delimiter, Paraphrase, Multilingual).
3. Verifying deterministic attack IDs and MutationMetadata traceability.
4. Performing an end-to-end security benchmark scan with mutations disabled.
5. Performing an end-to-end security benchmark scan with mutations enabled against reference-target.
6. Displaying the resulting scoring breakdown and attack provenance.
"""

from __future__ import annotations

import asyncio
import json
import logging

import httpx

from app.attacks.loader import AttackLoader
from app.core.scan_service import ScanService
from app.domain.attacks import ThreatCategory
from app.domain.mutations import (
    Base64MutationStrategy,
    DelimiterMutationStrategy,
    MultilingualMutationStrategy,
    MutationConfig,
    MutationEngine,
    ParaphraseMutationStrategy,
)

# Suppress debug logs for clean demo output
logging.basicConfig(level=logging.WARNING)


async def check_reference_target() -> bool:
    """Check if the reference target service is reachable."""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get("http://localhost:8001/health")
            return resp.status_code == 200
    except Exception:
        return False


async def run_demo() -> None:
    print("=" * 80)
    print("SENTINEL PHASE 12: MUTATION ENGINE DEMONSTRATION")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # 1. Inspect Static Seed Attack
    # --------------------------------------------------------------------------
    print("\n[Step 1] Loading Static Seed Attack from Library:")
    loader = AttackLoader()
    attacks = loader.get_by_category(ThreatCategory.PROMPT_INJECTION)
    if not attacks:
        print("ERROR: No prompt_injection attacks found in attack library!")
        return

    seed_attack = attacks[0]
    print(f"  Seed Attack ID : {seed_attack.id}")
    print(f"  Category       : {seed_attack.category.value}")
    print(f"  Severity       : {seed_attack.severity.value}")
    print(f"  Objective      : {seed_attack.objective}")
    print(f"  Original Prompt: {seed_attack.prompt!r}")

    # --------------------------------------------------------------------------
    # 2. Strategy Transformations
    # --------------------------------------------------------------------------
    print("\n[Step 2] Executing Individual Mutation Strategies:")

    # A. Base64
    b64_strat = Base64MutationStrategy()
    b64_out = await b64_strat.mutate(seed_attack, count=1, seed=0)
    print(f"\n  [Strategy: Base64] ({b64_out[0].parameters})")
    print(f"  Transformed Prompt:\n    {b64_out[0].mutated_prompt}")

    # B. Delimiter
    delim_strat = DelimiterMutationStrategy()
    delim_out = await delim_strat.mutate(seed_attack, count=1, seed=0)
    print(f"\n  [Strategy: Delimiter] ({delim_out[0].parameters})")
    print(f"  Transformed Prompt:\n    {delim_out[0].mutated_prompt}")

    # C. Paraphrase (Rule-based offline)
    para_strat = ParaphraseMutationStrategy(provider=None)
    para_out = await para_strat.mutate(seed_attack, count=1, seed=0)
    print(f"\n  [Strategy: Paraphrase (Offline)] ({para_out[0].parameters})")
    print(f"  Transformed Prompt:\n    {para_out[0].mutated_prompt}")

    # D. Multilingual (Curated offline)
    multi_strat = MultilingualMutationStrategy(provider=None)
    multi_out = await multi_strat.mutate(seed_attack, count=1, seed=0)
    print(f"\n  [Strategy: Multilingual (Offline)] ({multi_out[0].parameters})")
    print(f"  Transformed Prompt:\n    {multi_out[0].mutated_prompt}")

    # --------------------------------------------------------------------------
    # 3. Engine Orchestration and Provenance Tracking
    # --------------------------------------------------------------------------
    print("\n[Step 3] MutationEngine Orchestration & Traceability:")
    engine = MutationEngine()
    config = MutationConfig(
        enabled=True,
        strategies=["base64", "delimiter"],
        mutations_per_attack=1,
        seed=42,
    )

    generated = await engine.mutate_attack(seed_attack, config=config)
    print(f"  Generated {len(generated)} mutated test cases for {seed_attack.id}:")
    for g in generated:
        print(f"    - ID       : {g.id}")
        print(f"      Tags     : {g.tags}")
        print(f"      Parent ID: {g.metadata.get('parent_attack_id')}")
        print(f"      Mutation : {json.dumps(g.metadata.get('mutation'))}")

    # --------------------------------------------------------------------------
    # 4. End-to-End Scan: Mutations Disabled vs Mutations Enabled
    # --------------------------------------------------------------------------
    target_available = await check_reference_target()
    print("\n[Step 4] Live Target Verification:")
    if not target_available:
        print("  WARNING: Reference target at http://localhost:8001 is offline.")
        print("  Skipping live HTTP scan. Offline test suite covers execution.")
        return

    print("  Reference target at http://localhost:8001 is ONLINE (status=ok).")
    service = ScanService()

    # Scan 1: Mutations Disabled
    print("\n[Step 5] Running Scan with Mutations DISABLED:")
    report_baseline = await service.run_scan(
        target_url="http://localhost:8001",
        category=ThreatCategory.PROMPT_INJECTION,
        enable_mutations=False,
    )
    print(f"  Attacks Evaluated    : {report_baseline.evaluated_attacks}")
    print(f"  Attack Success Rate  : {report_baseline.attack_success_rate:.1%}")
    print(f"  Sentinel Sec Score   : {report_baseline.security_score:.2f}")

    # Scan 2: Mutations Enabled
    print("\n[Step 6] Running Scan with Mutations ENABLED (strategies: base64, delimiter):")
    report_mutated = await service.run_scan(
        target_url="http://localhost:8001",
        category=ThreatCategory.PROMPT_INJECTION,
        enable_mutations=True,
        mutation_strategies=["base64", "delimiter"],
        mutations_per_attack=1,
        mutation_seed=42,
    )
    print(f"  Attacks Evaluated    : {report_mutated.evaluated_attacks}")
    print(f"  Attack Success Rate  : {report_mutated.attack_success_rate:.1%}")
    print(f"  Sentinel Sec Score   : {report_mutated.security_score:.2f}")

    # Display provenance breakdown
    original_scores = [s for s in report_mutated.attack_scores if "mutation" not in s.metadata]
    mutated_scores = [s for s in report_mutated.attack_scores if "mutation" in s.metadata]

    print("\n[Step 7] Test Provenance Breakdown:")
    print(f"  Original Seed Attacks Executed: {len(original_scores)}")
    print(f"  Mutated Attacks Executed      : {len(mutated_scores)}")

    print("\n  Sample Mutated Execution Scores:")
    for ms in mutated_scores[:4]:
        mut_info = ms.metadata.get("mutation", {})
        technique = mut_info.get("technique")
        parent = mut_info.get("parent_attack_id")
        print(
            f"    - Attack ID: {ms.attack_id:<28} | Parent: {parent} | "
            f"Strategy: {technique:<10} | Verdict: {ms.verdict.value}"
        )

    print("\n" + "=" * 80)
    print("DEMO COMPLETE: MUTATION ENGINE IS FULLY OPERATIONAL AND PROVENANCE-TRACEABLE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_demo())
