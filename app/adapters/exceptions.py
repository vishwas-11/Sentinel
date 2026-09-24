"""Exceptions for Target Adapters in Sentinel.

Provides dedicated domain/transport error representations distinguishing
infrastructure and connectivity failures from target application behaviors.
"""


class TargetAdapterError(Exception):
    """Base exception for all target adapter failures."""


class TargetConnectionError(TargetAdapterError):
    """Raised when the target cannot be reached (e.g. connection refused, network unreachable)."""


class TargetTimeoutError(TargetAdapterError):
    """Raised when a request to the target times out (connect, read, or total timeout)."""


class TargetResponseError(TargetAdapterError):
    """Raised when the target returns a malformed, non-JSON, or unexpected response envelope."""


class TargetResetError(TargetAdapterError):
    """Raised when resetting target test state fails (e.g. /reset endpoint error)."""
