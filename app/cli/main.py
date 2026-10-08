"""Main entrypoint for Sentinel CLI."""

from __future__ import annotations

import logging
import sys
from collections.abc import Sequence

from app.cli.parser import create_parser

logger = logging.getLogger("sentinel.cli")


def main(
    argv: Sequence[str] | None = None,
    stdout=None,
    stderr=None,
) -> int:
    """Execute Sentinel CLI application.

    Args:
        argv: Command-line arguments sequence; defaults to sys.argv[1:].
        stdout: Standard output stream; defaults to sys.stdout at execution time.
        stderr: Standard error stream; defaults to sys.stderr at execution time.

    Returns:
        Process exit code integer (0 for success, non-zero for failure).
    """
    out_stream = stdout if stdout is not None else sys.stdout
    err_stream = stderr if stderr is not None else sys.stderr
    parser = create_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "handler"):
        parser.print_help(file=err_stream)
        return 1

    try:
        return args.handler(args, stdout=out_stream, stderr=err_stream)
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=err_stream)
        return 1


if __name__ == "__main__":
    sys.exit(main())
