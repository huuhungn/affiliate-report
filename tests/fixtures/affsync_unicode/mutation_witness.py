"""Prove the frozen samples reject Unicode/encoding regressions, in memory only.

The command succeeds only when pytest observes the expected mutation failures.
Production source and fixture files are never changed. See README.md.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
import unicodedata

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import pytest
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import affiliate_report.sync_service as sync


class Outcomes:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = 0

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.passed += int(report.passed)
            self.failed += int(report.failed)
        elif report.failed:
            self.errors += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mutation", choices=("normalize-nfc", "utf16-le"))
    args = parser.parse_args()
    source = REPO / "affiliate_report" / "sync_service.py"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    original = sync._derive_key
    outcomes = Outcomes()

    def mutated_key(passphrase, salt):
        if args.mutation == "normalize-nfc":
            return original(unicodedata.normalize("NFC", passphrase), salt)
        return Scrypt(
            salt=salt, length=32, n=sync._SCRYPT_N, r=sync._SCRYPT_R, p=sync._SCRYPT_P,
        ).derive(passphrase.encode("utf-16-le"))

    sync._derive_key = mutated_key
    try:
        exit_code = pytest.main([
            str(REPO / "tests" / "test_sync_service.py"), "-q", "--tb=no",
            "-k", "unicode_golden_static_file_decrypts_to_exact_payload",
        ], plugins=[outcomes])
    finally:
        sync._derive_key = original
    expected = (2, 4) if args.mutation == "normalize-nfc" else (0, 6)
    unchanged = hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    print(f"Mutation {args.mutation}: passed={outcomes.passed}, failed={outcomes.failed}, errors={outcomes.errors}, pytest_exit={exit_code}; production_source_unchanged={unchanged}")
    return 0 if (
        exit_code == pytest.ExitCode.TESTS_FAILED
        and (outcomes.passed, outcomes.failed) == expected
        and outcomes.errors == 0 and unchanged
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
