"""Command line argument parser for Sentinel CLI."""

from __future__ import annotations

import argparse

from app.cli.commands import (
    handle_baseline_create,
    handle_baseline_list,
    handle_baseline_show,
    handle_gate,
    handle_scan,
    handle_scans_list,
    handle_scans_show,
    handle_version,
)


def create_parser() -> argparse.ArgumentParser:
    """Build and configure the top-level argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=(
            "Sentinel — continuous red-teaming and security-regression testing engine "
            "for LLM applications"
        ),
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        required=True,
        help="Subcommand to execute",
    )

    # --------------------------------------------------------------------------
    # Subcommand: scan
    # --------------------------------------------------------------------------
    scan_parser = subparsers.add_parser(
        "scan",
        help="Execute security attack benchmark against an AI target",
        description="Run attack suite against target and compute deterministic security scores",
    )
    scan_parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Target base URL (default: configured target_base_url, e.g. http://localhost:8001)",
    )
    scan_parser.add_argument(
        "--attacks-dir",
        type=str,
        default=None,
        help="Path to attack library directory (default: backend/attacks/)",
    )
    scan_parser.add_argument(
        "--category",
        type=str,
        default=None,
        choices=[
            "prompt_injection",
            "system_leakage",
            "sensitive_data_disclosure",
            "unauthorized_tool_use",
            "improper_output_handling",
        ],
        help="Filter attacks by ThreatCategory",
    )
    scan_parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Maximum concurrent asynchronous requests (default: 1)",
    )
    scan_parser.add_argument(
        "--reset-policy",
        type=str,
        default=None,
        choices=["per_run", "per_attack", "never"],
        help="Target reset policy (default: per_run)",
    )
    scan_parser.add_argument(
        "--mutations",
        action="store_true",
        default=False,
        help="Enable adversarial payload mutations to expand benchmark test coverage",
    )
    scan_parser.add_argument(
        "--mutation-strategies",
        type=str,
        default=None,
        help=(
            "Comma-separated list of mutation strategies to execute "
            "(choices: base64, delimiter, paraphrase, multilingual)"
        ),
    )
    scan_parser.add_argument(
        "--mutations-per-attack",
        type=int,
        default=None,
        help="Number of mutated variations to generate per seed attack (default: 1)",
    )
    scan_parser.add_argument(
        "--mutation-seed",
        type=int,
        default=None,
        help="Random seed for reproducible deterministic mutations",
    )
    scan_parser.add_argument(
        "--persist",
        action="store_true",
        default=False,
        help="Persist scan results to configured database backend (e.g. Supabase)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Destination path to write ScoringReport JSON file",
    )
    scan_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    scan_parser.set_defaults(handler=handle_scan)

    # --------------------------------------------------------------------------
    # Subcommand: scans
    # --------------------------------------------------------------------------
    scans_parser = subparsers.add_parser(
        "scans",
        help="Manage and inspect historical scan runs",
        description="List and display historical scan records and reports from persistence backend",
    )
    scans_sub = scans_parser.add_subparsers(title="action", dest="scans_action", required=True)

    # scans list
    scans_list_parser = scans_sub.add_parser("list", help="List historical scans")
    scans_list_parser.add_argument(
        "--limit", type=int, default=20, help="Maximum scans to return (default: 20)"
    )
    scans_list_parser.add_argument(
        "--offset", type=int, default=0, help="Pagination offset (default: 0)"
    )
    scans_list_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    scans_list_parser.set_defaults(handler=handle_scans_list)

    # scans show <scan_id>
    scans_show_parser = scans_sub.add_parser(
        "show", help="Display details and report for a specific scan"
    )
    scans_show_parser.add_argument("scan_id", type=str, help="Scan identifier")
    scans_show_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    scans_show_parser.set_defaults(handler=handle_scans_show)

    # --------------------------------------------------------------------------
    # Subcommand: baseline
    # --------------------------------------------------------------------------
    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Manage named security regression baselines",
        description="Create, list, and view immutable named baselines in persistence backend",
    )
    baseline_sub = baseline_parser.add_subparsers(
        title="action", dest="baseline_action", required=True
    )

    # baseline create
    baseline_create_parser = baseline_sub.add_parser(
        "create", help="Create a named baseline from a scan"
    )
    baseline_create_parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Unique baseline name (e.g. 'v1-stable')",
    )
    baseline_create_parser.add_argument(
        "--scan-id", type=str, required=True, help="Scan ID to baseline"
    )
    baseline_create_parser.add_argument(
        "--description", type=str, default="", help="Optional description"
    )
    baseline_create_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    baseline_create_parser.set_defaults(handler=handle_baseline_create)

    # baseline list
    baseline_list_parser = baseline_sub.add_parser("list", help="List all named baselines")
    baseline_list_parser.add_argument(
        "--limit", type=int, default=20, help="Maximum baselines to return (default: 20)"
    )
    baseline_list_parser.add_argument(
        "--offset", type=int, default=0, help="Pagination offset (default: 0)"
    )
    baseline_list_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    baseline_list_parser.set_defaults(handler=handle_baseline_list)

    # baseline show
    baseline_show_parser = baseline_sub.add_parser(
        "show", help="Display details and report for a specific baseline"
    )
    baseline_show_parser.add_argument("identifier", type=str, help="Baseline name or ID")
    baseline_show_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    baseline_show_parser.set_defaults(handler=handle_baseline_show)

    # --------------------------------------------------------------------------
    # Subcommand: gate
    # --------------------------------------------------------------------------
    gate_parser = subparsers.add_parser(
        "gate",
        help="Evaluate regression gate comparing baseline and candidate reports",
        description="Diff baseline and candidate ScoringReports against security policies",
    )
    gate_parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Path to baseline ScoringReport JSON file",
    )
    gate_parser.add_argument(
        "--baseline-name",
        type=str,
        default=None,
        help="Name of stored baseline in repository (alternative to --baseline file)",
    )
    gate_parser.add_argument(
        "--candidate",
        type=str,
        required=True,
        help="Path to candidate ScoringReport JSON file",
    )
    gate_parser.add_argument(
        "--max-new-critical",
        type=int,
        default=0,
        help="Maximum allowed new CRITICAL failures (default: 0)",
    )
    gate_parser.add_argument(
        "--max-new-high",
        type=int,
        default=0,
        help="Maximum allowed new HIGH failures (default: 0)",
    )
    gate_parser.add_argument(
        "--max-asr-degradation",
        type=float,
        default=0.02,
        help="Max allowed increase in Attack Success Rate (e.g. 0.02 = 2%% points, default: 0.02)",
    )
    gate_parser.add_argument(
        "--max-score-drop",
        type=float,
        default=5.0,
        help="Maximum allowed drop in Sentinel Security Score points (default: 5.0)",
    )
    gate_parser.add_argument(
        "--min-coverage",
        type=float,
        default=0.95,
        help="Minimum required evaluation coverage (default: 0.95 = 95%%)",
    )
    gate_parser.add_argument(
        "--fail-on-removed",
        action="store_true",
        default=False,
        help="Fail gate if any baseline attack was removed from candidate suite",
    )
    gate_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    gate_parser.set_defaults(handler=handle_gate)

    # --------------------------------------------------------------------------
    # Subcommand: version
    # --------------------------------------------------------------------------
    version_parser = subparsers.add_parser(
        "version",
        help="Display Sentinel version and environment information",
    )
    version_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text)",
    )
    version_parser.set_defaults(handler=handle_version)

    return parser
