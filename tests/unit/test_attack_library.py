"""Comprehensive unit tests for Sentinel Attack Library and AttackLoader."""

import json
from pathlib import Path

import pytest

from app.attacks import (
    AttackLoader,
    AttackNotFoundError,
    DuplicateAttackIdError,
    MalformedAttackError,
)
from app.domain import AttackPayload, ThreatCategory


@pytest.fixture
def loader() -> AttackLoader:
    """Fixture providing an AttackLoader pointing to the default static attack library."""
    return AttackLoader()


# --- Static Attack Library Content & Integrity Tests ---


def test_load_all_seed_attacks(loader: AttackLoader):
    """Verify loading the full static attack library succeeds."""
    attacks = loader.load_attacks()
    assert len(attacks) == 30


def test_every_attack_is_valid_attack_payload(loader: AttackLoader):
    """Verify every loaded definition conforms strictly to the AttackPayload domain model."""
    attacks = loader.load_attacks()
    for attack in attacks:
        assert isinstance(attack, AttackPayload)
        assert attack.id.strip() != ""
        assert attack.prompt.strip() != ""
        assert attack.objective.strip() != ""
        assert attack.category in ThreatCategory


def test_all_five_threat_categories_represented(loader: AttackLoader):
    """Verify that all 5 V1 threat categories exist with roughly 6 attacks each."""
    attacks = loader.load_attacks()
    categories_found = {a.category for a in attacks}
    assert categories_found == set(ThreatCategory)

    for cat in ThreatCategory:
        cat_attacks = loader.get_by_category(cat)
        assert len(cat_attacks) == 6


def test_attack_ids_are_unique(loader: AttackLoader):
    """Verify that every attack in the library has a globally unique ID."""
    attacks = loader.load_attacks()
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))


def test_attack_ids_are_deterministic_and_sorted(loader: AttackLoader):
    """Verify that attacks are loaded in strictly deterministic ascending order by ID."""
    attacks = loader.load_attacks()
    ids = [a.id for a in attacks]
    sorted_ids = sorted(ids)
    assert ids == sorted_ids

    # Verify ID structure: T1-001 through T5-006
    for i in range(1, 7):
        assert f"T1-00{i}" in ids
        assert f"T2-00{i}" in ids
        assert f"T3-00{i}" in ids
        assert f"T4-00{i}" in ids
        assert f"T5-00{i}" in ids


def test_attack_metadata_survives_loading(loader: AttackLoader):
    """Verify that arbitrary attack metadata, tags, and severity survive loading intact."""
    t2_001 = loader.get_attack("T2-001")
    assert t2_001.metadata.get("target_canary") == "APEX-SEC-9981"
    assert "direct_leakage" in t2_001.tags
    assert t2_001.severity.weight == 8  # CRITICAL


def test_attack_lookup_by_id_and_not_found(loader: AttackLoader):
    """Verify single attack retrieval and AttackNotFoundError on missing ID."""
    attack = loader.get_attack("T4-001")
    assert attack.id == "T4-001"
    assert attack.category == ThreatCategory.UNAUTHORIZED_TOOL_USE

    with pytest.raises(AttackNotFoundError):
        loader.get_attack("NON_EXISTENT_ID")


# --- Filtering & State Tests ---


def test_disabled_attack_filtering(tmp_path: Path):
    """Verify that disabled attacks are excluded by default and included when requested."""
    attacks_dir = tmp_path / "attacks"
    attacks_dir.mkdir()

    active_attack = {
        "id": "T1-001",
        "category": "prompt_injection",
        "prompt": "Active test",
        "objective": "Test",
        "enabled": True,
    }
    disabled_attack = {
        "id": "T1-002",
        "category": "prompt_injection",
        "prompt": "Disabled test",
        "objective": "Test",
        "enabled": False,
    }

    (attacks_dir / "active.json").write_text(json.dumps(active_attack), encoding="utf-8")
    (attacks_dir / "disabled.json").write_text(json.dumps(disabled_attack), encoding="utf-8")

    custom_loader = AttackLoader(attacks_dir=attacks_dir)

    # Default: disabled attack excluded
    active_only = custom_loader.load_attacks(include_disabled=False)
    assert len(active_only) == 1
    assert active_only[0].id == "T1-001"

    # With include_disabled=True: both included
    all_attacks = custom_loader.load_attacks(include_disabled=True)
    assert len(all_attacks) == 2
    assert [a.id for a in all_attacks] == ["T1-001", "T1-002"]


# --- Error Detection & Validation Tests ---


def test_duplicate_attack_ids_rejected(tmp_path: Path):
    """Verify loader raises DuplicateAttackIdError when two files define the same attack ID."""
    attacks_dir = tmp_path / "attacks"
    attacks_dir.mkdir()

    attack_data = {
        "id": "DUPLICATE-01",
        "category": "prompt_injection",
        "prompt": "Sample attack",
        "objective": "Sample objective",
    }

    (attacks_dir / "file_a.json").write_text(json.dumps(attack_data), encoding="utf-8")
    (attacks_dir / "file_b.json").write_text(json.dumps(attack_data), encoding="utf-8")

    custom_loader = AttackLoader(attacks_dir=attacks_dir)
    with pytest.raises(DuplicateAttackIdError) as exc_info:
        custom_loader.load_attacks()
    assert "DUPLICATE-01" in str(exc_info.value)


def test_malformed_json_file_rejected(tmp_path: Path):
    """Verify loader raises MalformedAttackError on invalid JSON syntax."""
    attacks_dir = tmp_path / "attacks"
    attacks_dir.mkdir()

    (attacks_dir / "broken.json").write_text("{ this is not valid json }", encoding="utf-8")

    custom_loader = AttackLoader(attacks_dir=attacks_dir)
    with pytest.raises(MalformedAttackError) as exc_info:
        custom_loader.load_attacks()
    assert "Invalid JSON" in str(exc_info.value)
    assert "broken.json" in str(exc_info.value)


def test_schema_validation_failure_rejected(tmp_path: Path):
    """Verify loader raises MalformedAttackError when JSON violates AttackPayload schema."""
    attacks_dir = tmp_path / "attacks"
    attacks_dir.mkdir()

    # Missing required 'prompt' and 'objective', invalid category
    invalid_data = {
        "id": "T1-BAD",
        "category": "not_a_real_category",
    }

    (attacks_dir / "invalid_schema.json").write_text(json.dumps(invalid_data), encoding="utf-8")

    custom_loader = AttackLoader(attacks_dir=attacks_dir)
    with pytest.raises(MalformedAttackError) as exc_info:
        custom_loader.load_attacks()
    assert "Schema validation failed" in str(exc_info.value)


def test_empty_or_missing_directory_returns_empty_list(tmp_path: Path):
    """Verify non-existent or empty directories return an empty list gracefully."""
    empty_loader = AttackLoader(attacks_dir=tmp_path / "does_not_exist")
    assert empty_loader.load_attacks() == []


# --- Security & Architecture Boundary Tests ---


def test_attacks_remain_pure_data_without_execution(loader: AttackLoader):
    """Verify attacks remain inert data objects and are never executed as code."""
    attacks = loader.load_attacks()
    for attack in attacks:
        # Prompt must be a pure string
        assert isinstance(attack.prompt, str)
        # Verify no executable callables attached
        assert not callable(attack.prompt)
        assert not hasattr(attack, "execute")
        assert not hasattr(attack, "run")
