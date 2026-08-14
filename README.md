# Day 2: Basic file integrity checker (SHA-256)

[![CI](https://github.com/ZombieDuckling/cyber-day2-file-integrity-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/ZombieDuckling/cyber-day2-file-integrity-checker/actions/workflows/ci.yml)

This mini project builds a beginner-friendly file integrity checker in Python.
It creates a SHA-256 baseline hash for a file, then verifies whether the file
has changed.

## Research (quick references)

I used these references to keep the design aligned with standard practice:

1. Python `hashlib` docs (official):
   https://docs.python.org/3/library/hashlib.html
2. NIST FIPS 180-4 Secure Hash Standard:
   https://csrc.nist.gov/pubs/fips/180-4/upd1/final
3. NIST glossary definition for file integrity checking:
   https://csrc.nist.gov/glossary/term/file_integrity_checking

## Key learning points

- SHA-256 generates a fixed-length digest that changes when file content
  changes.
- Read files in chunks for memory efficiency instead of loading full files at
  once.
- Keep a trusted baseline hash, then compare current hash to detect tampering
  or accidental changes.
- Integrity checking detects change, but it does not explain who changed the
  file or why.

## Project files

- `integrity_checker.py` - script with two commands:
  - `baseline`: generate and store a baseline hash
  - `verify`: compare current file hash to baseline

## Learn + execute

Run these commands from this directory.

1. Create a sample file:

   ```bash
   echo "hello world" > sample.txt
   ```

2. Generate a baseline:

   ```bash
   python3 integrity_checker.py baseline sample.txt --out baseline.sha256
   ```

3. Verify unchanged file:

   ```bash
   python3 integrity_checker.py verify sample.txt --baseline baseline.sha256
   ```

4. Modify the file, then verify again:

   ```bash
   echo "changed" >> sample.txt
   python3 integrity_checker.py verify sample.txt --baseline baseline.sha256
   ```

Expected behavior:

- Unchanged file: integrity check passes.
- Changed file: integrity check fails with an alert and exit code `1`.

## Tests

Run the characterization suite before changing the checker logic:

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

GitHub Actions runs the same pytest suite on Python 3.10 and 3.12 for pull requests and pushes to `main`.

## Legal and ethical use

Use this project only on files and systems you own or are authorized to test.
This is a defensive integrity check tool for learning and monitoring, not an
offensive tool.

## Push (optional)

If GitHub CLI (`gh`) is authenticated, publish this folder as a public repo,
for example under `ZombieDuckling/cyber-day2-file-integrity-checker`.
