"""Baseline command handlers for Sentinel CLI."""

from __future__ import annotations

import asyncio
import logging
import sys

from app.cli.output import (
    print_baseline_record_text,
    print_baselines_list_text,
    print_json,
    print_scan_report_text,
)
from app.core.config import get_settings
from app.domain.repositories import (
    DuplicateRecordError,
    PersistenceConfigError,
    RecordNotFoundError,
)
from app.infrastructure.persistence.factory import create_repositories

logger = logging.getLogger("sentinel.cli.baseline")


def handle_baseline_create(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute 'sentinel baseline create --scan-id <id> --name <name>' command."""
    settings = get_settings()

    try:
        scan_repo, baseline_repo = create_repositories(settings)
        if scan_repo is None or baseline_repo is None:
            print(
                "Error: No persistence backend configured. "
                "Set PERSISTENCE_BACKEND='memory' or PERSISTENCE_BACKEND='supabase'.",
                file=stderr,
            )
            return 1

        # Fetch scan report to snapshot
        report = asyncio.run(scan_repo.get_scan_report(args.scan_id))
        if report is None:
            print(f"Error: Scan ID '{args.scan_id}' not found.", file=stderr)
            return 1

        baseline_record = asyncio.run(
            baseline_repo.create_baseline(
                name=args.name,
                scan_id=args.scan_id,
                report=report,
                description=args.description or "",
            )
        )
    except DuplicateRecordError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1
    except RecordNotFoundError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1
    except PersistenceConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return 1
    except Exception as exc:
        print(f"Failed to create baseline: {exc}", file=stderr)
        return 1

    if args.format == "json":
        print_json(baseline_record, file=stdout)
    else:
        print(
            f"Successfully created baseline '{args.name}' from scan '{args.scan_id}'.",
            file=stdout,
        )
        print_baseline_record_text(baseline_record, file=stdout)

    return 0


def handle_baseline_list(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute 'sentinel baseline list' command."""
    settings = get_settings()

    try:
        _, baseline_repo = create_repositories(settings)
        if baseline_repo is None:
            print(
                "Error: No persistence backend configured. "
                "Set PERSISTENCE_BACKEND='memory' or PERSISTENCE_BACKEND='supabase'.",
                file=stderr,
            )
            return 1

        baselines = asyncio.run(baseline_repo.list_baselines(limit=args.limit, offset=args.offset))
    except PersistenceConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return 1
    except Exception as exc:
        print(f"Failed to list baselines: {exc}", file=stderr)
        return 1

    if args.format == "json":
        print_json(baselines, file=stdout)
    else:
        print_baselines_list_text(baselines, file=stdout)

    return 0


def handle_baseline_show(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute 'sentinel baseline show <identifier>' command."""
    settings = get_settings()

    try:
        _, baseline_repo = create_repositories(settings)
        if baseline_repo is None:
            print(
                "Error: No persistence backend configured. "
                "Set PERSISTENCE_BACKEND='memory' or PERSISTENCE_BACKEND='supabase'.",
                file=stderr,
            )
            return 1

        rec = asyncio.run(baseline_repo.get_baseline_by_name(args.identifier))
        if rec is None:
            rec = asyncio.run(baseline_repo.get_baseline_by_id(args.identifier))

        if rec is None:
            print(f"Error: Baseline '{args.identifier}' not found.", file=stderr)
            return 1

        report = asyncio.run(baseline_repo.get_baseline_report(args.identifier))
    except PersistenceConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return 1
    except Exception as exc:
        print(f"Failed to retrieve baseline '{args.identifier}': {exc}", file=stderr)
        return 1

    if args.format == "json":
        print_json(rec, file=stdout)
    else:
        print_baseline_record_text(rec, file=stdout)
        if report is not None:
            print("\nBASELINE SNAPSHOT REPORT SUMMARY:", file=stdout)
            print_scan_report_text(report, file=stdout)

    return 0
