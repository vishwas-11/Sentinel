"""Unit and integration tests for Sentinel CLI persistence commands."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from app.cli.main import main
from app.core.config import get_settings
from app.infrastructure.persistence.factory import get_in_memory_repositories
from tests.unit.test_persistence_memory import _build_sample_report


@pytest.fixture(autouse=True)
def setup_memory_persistence(monkeypatch):
    """Configure PERSISTENCE_BACKEND='memory' for CLI persistence tests."""
    monkeypatch.setenv("SENTINEL_PERSISTENCE_BACKEND", "memory")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_cli_scans_and_baseline_workflow(tmp_path: Path):
    import asyncio

    scan_repo, baseline_repo = get_in_memory_repositories()

    # Pre-populate a scan
    report = _build_sample_report("scan_cli_123")
    asyncio.run(scan_repo.save_scan(report, target_url="http://target.local:8001"))

    # 1. Test `sentinel scans list`
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["scans", "list", "--format", "json"], stdout=stdout, stderr=stderr)
    assert code == 0
    scans_data = json.loads(stdout.getvalue())
    assert len(scans_data) >= 1
    assert any(s["id"] == "scan_cli_123" for s in scans_data)

    # 2. Test `sentinel scans show scan_cli_123`
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["scans", "show", "scan_cli_123", "--format", "json"], stdout=stdout, stderr=stderr)
    assert code == 0
    report_data = json.loads(stdout.getvalue())
    assert report_data["scan_id"] == "scan_cli_123"

    # 3. Test `sentinel baseline create --scan-id scan_cli_123 --name v1.0`
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        [
            "baseline",
            "create",
            "--scan-id",
            "scan_cli_123",
            "--name",
            "v1.0",
            "--description",
            "Release baseline",
            "--format",
            "json",
        ],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == 0
    base_data = json.loads(stdout.getvalue())
    assert base_data["name"] == "v1.0"

    # 4. Test `sentinel baseline list`
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["baseline", "list", "--format", "json"], stdout=stdout, stderr=stderr)
    assert code == 0
    baselines_list = json.loads(stdout.getvalue())
    assert len(baselines_list) >= 1
    assert any(b["name"] == "v1.0" for b in baselines_list)

    # 5. Test `sentinel baseline show v1.0`
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["baseline", "show", "v1.0", "--format", "json"], stdout=stdout, stderr=stderr)
    assert code == 0
    show_data = json.loads(stdout.getvalue())
    assert show_data["name"] == "v1.0"

    # 6. Test `sentinel gate --baseline-name v1.0 --candidate <cand_path>`
    cand_path = tmp_path / "cand.json"
    cand_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(
        ["gate", "--baseline-name", "v1.0", "--candidate", str(cand_path), "--format", "json"],
        stdout=stdout,
        stderr=stderr,
    )
    # The candidate report matches baseline perfectly, so gate passes
    assert code == 0
    gate_data = json.loads(stdout.getvalue())
    assert gate_data["passed"] is True


def test_cli_scans_show_not_found():
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["scans", "show", "non_existent_scan_id"], stdout=stdout, stderr=stderr)
    assert code == 1
    assert "not found" in stderr.getvalue().lower()


def test_cli_baseline_create_duplicate_error():
    import asyncio

    scan_repo, baseline_repo = get_in_memory_repositories()
    report = _build_sample_report("scan_cli_dup")
    asyncio.run(scan_repo.save_scan(report, target_url="http://target.local:8001"))

    stdout1 = io.StringIO()
    stderr1 = io.StringIO()
    code1 = main(
        ["baseline", "create", "--scan-id", "scan_cli_dup", "--name", "dup_v1.0"],
        stdout=stdout1,
        stderr=stderr1,
    )
    assert code1 == 0

    stdout2 = io.StringIO()
    stderr2 = io.StringIO()
    # Attempting to create duplicate name
    code2 = main(
        ["baseline", "create", "--scan-id", "scan_cli_dup", "--name", "dup_v1.0"],
        stdout=stdout2,
        stderr=stderr2,
    )
    assert code2 == 1
    assert "already exists" in stderr2.getvalue().lower()


def test_cli_gate_missing_baseline_args(tmp_path: Path):
    cand_path = tmp_path / "cand.json"
    cand_path.write_text("{}", encoding="utf-8")

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(["gate", "--candidate", str(cand_path)], stdout=stdout, stderr=stderr)
    assert code == 1
    assert "either --baseline" in stderr.getvalue().lower()
