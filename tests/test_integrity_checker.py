from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import integrity_checker


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "integrity_checker.py"


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"hello world\n")

    assert (
        integrity_checker.sha256_file(sample)
        == "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
    )


def test_sha256_file_handles_empty_and_chunked_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert integrity_checker.sha256_file(empty) == hashlib.sha256(b"").hexdigest()

    data = (b"abc123" * integrity_checker.CHUNK_SIZE) + b"tail"
    large = tmp_path / "large.bin"
    large.write_bytes(data)
    assert integrity_checker.sha256_file(large) == hashlib.sha256(data).hexdigest()


def test_baseline_round_trip_and_empty_baseline_error(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    baseline = tmp_path / "baseline.sha256"
    empty_baseline = tmp_path / "empty.sha256"
    target.write_text("trusted content\n", encoding="utf-8")

    integrity_checker.write_baseline(target, baseline)

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    assert baseline.read_text(encoding="utf-8") == f"{digest}  notes.txt\n"
    assert integrity_checker.read_baseline_hash(baseline) == digest

    empty_baseline.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Baseline file is empty"):
        integrity_checker.read_baseline_hash(empty_baseline)


def test_verify_file_returns_true_for_unchanged_and_false_for_changed(tmp_path: Path) -> None:
    target = tmp_path / "watched.txt"
    baseline = tmp_path / "baseline.sha256"
    target.write_text("original\n", encoding="utf-8")
    integrity_checker.write_baseline(target, baseline)

    assert integrity_checker.verify_file(target, baseline) is True

    target.write_text("tampered\n", encoding="utf-8")
    assert integrity_checker.verify_file(target, baseline) is False


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_readme_flow_passes_then_alerts_after_change(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    baseline = tmp_path / "baseline.sha256"
    sample.write_text("hello world\n", encoding="utf-8")

    baseline_result = run_cli("baseline", str(sample), "--out", str(baseline), cwd=tmp_path)
    assert baseline_result.returncode == 0
    assert "[OK] Baseline written" in baseline_result.stdout

    verify_result = run_cli("verify", str(sample), "--baseline", str(baseline), cwd=tmp_path)
    assert verify_result.returncode == 0
    assert "[OK] Integrity check passed" in verify_result.stdout

    sample.write_text("hello world\nchanged\n", encoding="utf-8")
    changed_result = run_cli("verify", str(sample), "--baseline", str(baseline), cwd=tmp_path)
    assert changed_result.returncode == 1
    assert "[ALERT] Integrity check failed" in changed_result.stdout


def test_cli_reports_missing_inputs_with_exit_code_2(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")

    missing_target = run_cli("baseline", str(tmp_path / "missing.txt"), cwd=tmp_path)
    assert missing_target.returncode == 2
    assert "[ERROR] Target file not found" in missing_target.stderr

    missing_baseline = run_cli("verify", str(sample), cwd=tmp_path)
    assert missing_baseline.returncode == 2
    assert "[ERROR] Baseline file not found" in missing_baseline.stderr


def test_cli_uses_default_baseline_path(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")

    baseline_result = run_cli("baseline", str(sample), cwd=tmp_path)
    assert baseline_result.returncode == 0
    assert (tmp_path / "baseline.sha256").is_file()

    verify_result = run_cli("verify", str(sample), cwd=tmp_path)
    assert verify_result.returncode == 0
    assert "[OK] Integrity check passed" in verify_result.stdout
