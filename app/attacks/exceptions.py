"""Custom exceptions for the Sentinel attack library and loader."""


class AttackLibraryError(Exception):
    """Base exception for all attack library errors."""


class MalformedAttackError(AttackLibraryError):
    """Raised when an attack definition file cannot be parsed or fails schema validation."""


class DuplicateAttackIdError(AttackLibraryError):
    """Raised when two or more attack definitions share the same attack ID."""


class AttackNotFoundError(AttackLibraryError):
    """Raised when an attack with a requested ID does not exist."""
