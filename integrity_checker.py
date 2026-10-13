#!/usr/bin/env python3
"""Very basic file integrity checker using SHA-256.

Usage examples:
  python3 integrity_checker.py baseline notes.txt --out baseline.sha256
  python3 integrity_checker.py verify notes.txt --baseline baseline.sha256
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


CHUNK_SIZE = 8192


def sha256_file(file_path: Path) -> str:
    """Return SHA-256 hex digest for a file, read in chunks."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_baseline(file_path: Path, baseline_path: Path) -> None:
    digest = sha256_file(file_path)
    baseline_path.write_text(f"{digest}  {file_path.name}\n", encoding="utf-8")
    print(f"[OK] Baseline written to: {baseline_path}")
    print(f"[OK] SHA-256 for {file_path}: {digest}")


def read_baseline_hash(baseline_path: Path) -> str:
    line = baseline_path.read_text(encoding="utf-8").strip()
    if not line:
        raise ValueError("Baseline file is empty.")
    return line.split()[0]


def verify_file(file_path: Path, baseline_path: Path) -> bool:
    expected = read_baseline_hash(baseline_path)
    current = sha256_file(file_path)

    print(f"Expected: {expected}")
    print(f"Current : {current}")

    if current == expected:
        print("[OK] Integrity check passed. File has not changed.")
        return True

    print("[ALERT] Integrity check failed. File content changed.")
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Beginner-friendly SHA-256 file integrity checker"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser(
        "baseline", help="Generate a baseline hash file"
    )
    baseline_parser.add_argument("file", type=Path, help="File to baseline")
    baseline_parser.add_argument(
        "--out",
        type=Path,
        default=Path("baseline.sha256"),
        help="Output baseline file path (default: baseline.sha256)",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a file against a baseline hash"
    )
    verify_parser.add_argument("file", type=Path, help="File to verify")
    verify_parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("baseline.sha256"),
        help="Baseline file path (default: baseline.sha256)",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target_file: Path = args.file
    if not target_file.exists() or not target_file.is_file():
        print(f"[ERROR] Target file not found: {target_file}", file=sys.stderr)
        return 2

    if args.command == "baseline":
        write_baseline(target_file, args.out)
        return 0

    if not args.baseline.exists() or not args.baseline.is_file():
        print(
            f"[ERROR] Baseline file not found: {args.baseline}",
            file=sys.stderr,
        )
        return 2

    try:
        ok = verify_file(target_file, args.baseline)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
