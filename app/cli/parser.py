"""Command line argument parser for Sentinel CLI."""

from __future__ import annotations

import argparse

from app.cli.commands import handle_gate, handle_scan, handle_version


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
        required=True,
        help="Path to baseline ScoringReport JSON file",
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
