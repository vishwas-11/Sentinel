"""Attack library loader for discovering, validating, and serving AttackPayload objects."""

import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from app.attacks.exceptions import (
    AttackNotFoundError,
    DuplicateAttackIdError,
    MalformedAttackError,
)
from app.domain.attacks import AttackPayload, ThreatCategory

DEFAULT_ATTACKS_DIR = Path(__file__).resolve().parent.parent.parent / "attacks"


class AttackLoader:
    """Discovers, parses, validates, and serves static attack definitions from disk.

    Responsibilities:
    - Scans the attacks directory recursively for structured attack files (.json).
    - Parses and strictly validates each file against the domain AttackPayload schema.
    - Rejects malformed definitions with informative error messages.
    - Detects duplicate attack IDs across files to guarantee identity uniqueness.
    - Guarantees deterministic ordering by sorting attacks by attack ID.
    - Supports filtering by ThreatCategory and enabled status.

    Non-Responsibilities:
    - Does NOT execute attacks or communicate with AI targets.
    - Does NOT mutate or generate dynamic attack variations.
    - Does NOT judge target responses or calculate scores.
    """

    def __init__(self, attacks_dir: Path | str | None = None) -> None:
        """Initialize the loader with a target directory of attack definitions.

        Args:
            attacks_dir: Path to the attack library folder. Defaults to backend/attacks/.
        """
        self.attacks_dir = Path(attacks_dir) if attacks_dir else DEFAULT_ATTACKS_DIR

    def _discover_attack_files(self) -> Sequence[Path]:
        """Find all attack definition files (.json) in the attacks directory."""
        if not self.attacks_dir.exists() or not self.attacks_dir.is_dir():
            return []
        # Return files sorted by relative path for deterministic reading order
        return sorted(self.attacks_dir.rglob("*.json"))

    def load_attacks(self, include_disabled: bool = False) -> list[AttackPayload]:
        """Load, validate, and return all attack payloads sorted deterministically by ID.

        Args:
            include_disabled: If True, includes attacks marked with enabled=False.

        Returns:
            List of validated AttackPayload domain objects sorted by ID.

        Raises:
            MalformedAttackError: If any attack file cannot be read, parsed, or validated.
            DuplicateAttackIdError: If two or more attack files share the same ID.
        """
        files = self._discover_attack_files()
        attacks: list[AttackPayload] = []
        seen_ids: dict[str, Path] = {}

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as read_err:
                raise MalformedAttackError(
                    f"Failed to read attack file '{file_path}': {read_err}"
                ) from read_err

            try:
                # Strictly validate JSON syntax first
                raw_data = json.loads(content)
            except json.JSONDecodeError as json_err:
                raise MalformedAttackError(
                    f"Invalid JSON in attack file '{file_path}': {json_err}"
                ) from json_err

            try:
                # Validate against pure domain AttackPayload model
                attack = AttackPayload.model_validate(raw_data)
            except ValidationError as val_err:
                raise MalformedAttackError(
                    f"Schema validation failed for attack file '{file_path}': {val_err}"
                ) from val_err

            # Enforce global ID uniqueness
            if attack.id in seen_ids:
                conflicting_file = seen_ids[attack.id]
                raise DuplicateAttackIdError(
                    f"Duplicate attack ID '{attack.id}' found in '{file_path}' "
                    f"(already defined in '{conflicting_file}')."
                )

            seen_ids[attack.id] = file_path

            if attack.enabled or include_disabled:
                attacks.append(attack)

        # Guarantee deterministic ascending order by attack ID
        attacks.sort(key=lambda a: a.id)
        return attacks

    def get_attack(self, attack_id: str) -> AttackPayload:
        """Retrieve a single attack payload by its unique identifier.

        Args:
            attack_id: The exact ID of the attack to look up (e.g. 'T1-001').

        Returns:
            The matching AttackPayload.

        Raises:
            AttackNotFoundError: If no attack matches the provided ID.
        """
        # Search all attacks including disabled ones
        all_attacks = self.load_attacks(include_disabled=True)
        for attack in all_attacks:
            if attack.id == attack_id:
                return attack
        raise AttackNotFoundError(f"Attack with ID '{attack_id}' not found in library.")

    def get_by_category(
        self,
        category: ThreatCategory,
        include_disabled: bool = False,
    ) -> list[AttackPayload]:
        """Retrieve all attacks belonging to a specific threat category.

        Args:
            category: ThreatCategory filter enum.
            include_disabled: If True, includes disabled attacks for this category.

        Returns:
            List of matching AttackPayload objects sorted by ID.
        """
        all_attacks = self.load_attacks(include_disabled=include_disabled)
        return [a for a in all_attacks if a.category == category]
