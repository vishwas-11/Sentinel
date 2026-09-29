"""Developer demonstration script for manually verifying the Sentinel AttackRunner.

Executes specified attacks against the live reference target (or any configured target),
printing detailed traces of session IDs, prompt dispatches, tool executions, and latency metrics.

Usage:
    uv run python run_runner_demo.py --attacks T1-001
    uv run python run_runner_demo.py --attacks T1-001,T2-001,T4-001
    uv run python run_runner_demo.py --attacks all --concurrency 2
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.adapters.exceptions import TargetConnectionError, TargetResetError
from app.adapters.http import HttpTargetAdapter
from app.attacks.loader import AttackLoader
from app.core.config import get_settings
from app.core.runner import AttackRunner, ResetPolicy


def parse_args() -> argparse.Namespace:
    """Parse command line arguments for manual runner verification."""
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Sentinel Phase 5 — Manual AttackRunner Verification",
    )
    parser.add_argument(
        "--attacks",
        type=str,
        default="T1-001",
        help="Comma-separated attack IDs to execute (e.g. 'T1-001,T4-001') or 'all'.",
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default=settings.target_base_url,
        help=f"Target base URL (default: {settings.target_base_url})",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Concurrency limit (default: 1 for sequential)",
    )
    parser.add_argument(
        "--reset-policy",
        type=str,
        default="per_run",
        choices=["per_run", "per_attack", "never"],
        help="Reset policy for target state (default: per_run)",
    )
    return parser.parse_args()


async def main() -> int:
    """Execute the manual verification flow."""
    args = parse_args()
    print("=" * 70)
    print("SENTINEL PHASE 5 — MANUAL ATTACK RUNNER VERIFICATION")
    print("=" * 70)
    print(f"Target URL:    {args.target_url}")
    print(f"Reset Policy:  {args.reset_policy}")
    print(f"Concurrency:   {args.concurrency}")
    print("-" * 70)

    # 1. Load Attacks from Attack Library
    loader = AttackLoader()
    all_attacks = loader.load_attacks()
    attack_map = {atk.id: atk for atk in all_attacks}

    if args.attacks.lower() == "all":
        selected_attacks = all_attacks
    else:
        requested_ids = [aid.strip() for aid in args.attacks.split(",") if aid.strip()]
        selected_attacks = []
        for aid in requested_ids:
            if aid in attack_map:
                selected_attacks.append(attack_map[aid])
            else:
                print(f"[!] Warning: Attack ID '{aid}' not found in attack library; skipping.")

    if not selected_attacks:
        print("[X] Error: No valid attacks selected to execute.")
        return 1

    print(f"Selected {len(selected_attacks)} attack(s): {[a.id for a in selected_attacks]}")
    print("-" * 70)

    # 2. Initialize Adapter and Runner
    adapter = HttpTargetAdapter(base_url=args.target_url)
    runner = AttackRunner(
        adapter=adapter,
        max_concurrency=args.concurrency,
        reset_policy=ResetPolicy(args.reset_policy),
    )

    # 3. Execute Suite
    try:
        print(f"[*] Starting AttackRunner execution (reset_policy={args.reset_policy})...")
        result = await runner.run(selected_attacks)
    except (TargetConnectionError, TargetResetError) as err:
        print(f"\n[X] RUN ABORTED — Initial Target Reset Failed: {err}")
        print("    Ensure the reference target is running on port 8001:")
        print("    cd reference-target && uv run uvicorn app.main:app --port 8001 --reload")
        await adapter.aclose()
        return 1
    except Exception as err:
        print(f"\n[X] Fatal runner error: {err}")
        await adapter.aclose()
        return 1

    # 4. Display Traces
    print("\n" + "=" * 70)
    print(f"RUN EXECUTION TRACES — Run ID: {result.run_id}")
    print("=" * 70)

    for idx, record in enumerate(result.records, start=1):
        tc = record.test_case
        tr = record.target_result

        status_marker = "[SUCCESS]" if tr.status == "success" else "[ERROR]"
        print(
            f"\n[{idx}/{result.total_attacks}] {status_marker} Attack: "
            f"{tc.attack.id} ({tc.attack.category})"
        )
        print(f"    Session ID:  {tc.session_id}")
        print(f"    Prompt:      {tc.attack.prompt[:75]}...")
        print(f"    Status Code: {tr.status_code}")
        target_lat = tr.metadata.get("target_latency_ms")
        print(f"    Latency:     {tr.latency_ms} ms (adapter) | {target_lat} ms (target)")

        if tr.response:
            truncated_resp = tr.response.replace("\n", " ")[:120]
            print(f"    Response:    {truncated_resp}...")
        if tr.error:
            print(f"    Error:       {tr.error}")

        if tr.tool_calls:
            print(f"    Tool Calls ({len(tr.tool_calls)} observed):")
            for tc_call in tr.tool_calls:
                call_desc = (
                    f"      -> {tc_call.tool_name}(arguments={tc_call.arguments}) "
                    f"[success={tc_call.success}]"
                )
                print(call_desc)

    # 5. Display Summary
    print("\n" + "-" * 70)
    print("RUNNER SUMMARY METRICS")
    print("-" * 70)
    print(f"Run ID:                {result.run_id}")
    print(f"Total Attacks:         {result.total_attacks}")
    print(f"Successful Executions: {result.successful_executions}")
    print(f"Error Executions:      {result.error_executions}")
    print(f"Total Wall Duration:   {result.total_duration_ms:.2f} ms")
    print("=" * 70)

    await adapter.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
