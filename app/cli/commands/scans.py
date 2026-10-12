"""Scans command handlers for Sentinel CLI."""

from __future__ import annotations

import asyncio
import logging
import sys

from app.cli.output import print_json, print_scan_report_text, print_scans_list_text
from app.core.config import get_settings
from app.domain.repositories import PersistenceConfigError
from app.infrastructure.persistence.factory import create_repositories

logger = logging.getLogger("sentinel.cli.scans")


def handle_scans_list(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute 'sentinel scans list' command."""
    settings = get_settings()

    try:
        scan_repo, _ = create_repositories(settings)
        if scan_repo is None:
            print(
                "Error: No persistence backend configured. "
                "Set PERSISTENCE_BACKEND='memory' or PERSISTENCE_BACKEND='supabase'.",
                file=stderr,
            )
            return 1

        scans = asyncio.run(scan_repo.list_scans(limit=args.limit, offset=args.offset))
    except PersistenceConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return 1
    except Exception as exc:
        print(f"Failed to list scans: {exc}", file=stderr)
        return 1

    if args.format == "json":
        print_json(scans, file=stdout)
    else:
        print_scans_list_text(scans, file=stdout)

    return 0


def handle_scans_show(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute 'sentinel scans show <scan_id>' command."""
    settings = get_settings()

    try:
        scan_repo, _ = create_repositories(settings)
        if scan_repo is None:
            print(
                "Error: No persistence backend configured. "
                "Set PERSISTENCE_BACKEND='memory' or PERSISTENCE_BACKEND='supabase'.",
                file=stderr,
            )
            return 1

        report = asyncio.run(scan_repo.get_scan_report(args.scan_id))
        if report is None:
            print(f"Error: Scan '{args.scan_id}' not found.", file=stderr)
            return 1
    except PersistenceConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return 1
    except Exception as exc:
        print(f"Failed to retrieve scan '{args.scan_id}': {exc}", file=stderr)
        return 1

    if args.format == "json":
        print_json(report, file=stdout)
    else:
        print_scan_report_text(report, file=stdout)

    return 0
