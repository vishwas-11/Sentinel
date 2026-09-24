"""Target adapters for external AI applications.

Provides concrete implementations of the domain TargetAdapter protocol,
including HttpTargetAdapter for REST-based targets.
"""

from app.adapters.exceptions import (
    TargetAdapterError,
    TargetConnectionError,
    TargetResetError,
    TargetResponseError,
    TargetTimeoutError,
)
from app.adapters.http import HttpTargetAdapter

__all__ = [
    "HttpTargetAdapter",
    "TargetAdapterError",
    "TargetConnectionError",
    "TargetResetError",
    "TargetResponseError",
    "TargetTimeoutError",
]
