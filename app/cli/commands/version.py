"""Version command handler for Sentinel CLI."""

from __future__ import annotations

import platform
import sys

from app.cli.output import print_json

SENTINEL_VERSION = "0.1.0"


def handle_version(args, stdout=sys.stdout, stderr=sys.stderr) -> int:
    """Execute the version command."""
    info = {
        "sentinel_version": SENTINEL_VERSION,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.architecture()[0],
    }

    if getattr(args, "format", "text") == "json":
        print_json(info, file=stdout)
    else:
        print(f"Sentinel v{SENTINEL_VERSION}", file=stdout)
        print(f"Python:   {info['python_version']}", file=stdout)
        print(f"Platform: {info['platform']} ({info['architecture']})", file=stdout)

    return 0
