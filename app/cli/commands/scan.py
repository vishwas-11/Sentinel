"""Scan command handler for Sentinel CLI."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from app.cli.output import print_json, print_scan_report_text
from app.core.config import get_settings
from app.core.scan_service import ScanService

logger = logging.getLogger("sentinel.cli.scan")


def handle_scan(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute the scan command."""
    settings = get_settings()

    # Apply CLI argument overrides with precedence over configuration
    target_url = args.target_url or settings.target_base_url
    attacks_dir = args.attacks_dir
    category = args.category
    concurrency = args.concurrency or settings.runner_max_concurrency
    reset_policy = args.reset_policy or settings.runner_reset_policy

    # Mutation options
    enable_mutations = args.mutations or settings.enable_mutations
    mutation_strategies = None
    if args.mutation_strategies:
        mutation_strategies = [s.strip() for s in args.mutation_strategies.split(",") if s.strip()]
    mutations_per_attack = args.mutations_per_attack
    mutation_seed = args.mutation_seed

    service = ScanService(settings=settings)

    try:
        # Run async scan pipeline synchronously from CLI entrypoint
        report = asyncio.run(
            service.run_scan(
                target_url=target_url,
                attacks_dir=attacks_dir,
                category=category,
                concurrency=concurrency,
                reset_policy=reset_policy,
                enable_mutations=enable_mutations,
                mutation_strategies=mutation_strategies,
                mutations_per_attack=mutations_per_attack,
                mutation_seed=mutation_seed,
            )
        )
    except Exception as exc:
        print(f"Scan execution failed: {exc}", file=stderr)
        return 1

    # Save to file if output path requested
    if args.output:
        try:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            if args.format != "json":
                print(f"Scoring report saved to {out_path}", file=stderr)
        except Exception as exc:
            print(f"Failed to save output file: {exc}", file=stderr)
            return 1

    # Render console output
    if args.format == "json":
        print_json(report, file=stdout)
    else:
        print_scan_report_text(report, file=stdout)

    return 0
