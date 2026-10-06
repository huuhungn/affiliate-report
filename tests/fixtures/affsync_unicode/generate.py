"""Generate public Unicode .affsync samples using the real source-tree producer.

Run manually, never during pytest. See README.md for isolated environment setup.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, date, datetime
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unicodedata
from unittest.mock import patch
from uuid import UUID, uuid5

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from sqlalchemy import update

from affiliate_report.accounts import create_account
from affiliate_report.db import (
    accounts, device_identity, get_engine, import_batches, import_rows, init_db,
    monthly_targets, target_sync_id,
)
from affiliate_report.parser import EXPECTED_HEADERS, normalize_row
import affiliate_report.sync_service as sync
from affiliate_report.version import APP_VERSION

NAMESPACE = UUID("8c3db1b8-d3e8-4f4d-bbd4-273612a0632d")
DEVICE_ID = str(uuid5(NAMESPACE, "synthetic-windows-producer"))
FROZEN_TIME = datetime(2026, 10, 6, 0, 0, tzinfo=UTC)
# Escapes make the intentional decomposition immune to editor normalization.
NFC_PASSWORD = "M\u1eadt kh\u1ea9u \u0111\u1ed3ng b\u1ed9 Vi\u1ec7t Nam 2026!"
PASSWORDS = {
    "nfc": NFC_PASSWORD,
    "nfd": unicodedata.normalize("NFD", NFC_PASSWORD),
    "emoji_mixed": "\U0001f512\U0001f1fb\U0001f1f3 M\u1eadt-kh\u1ea9u Vi\u00ea\u0323t \u0111\u1ed3ng b\u1ed9 \U0001f9ea 2026!",
}


def raw_order() -> dict:
    row = {header: "/" for header in EXPECTED_HEADERS}
    row.update({
        "ID đơn hàng": "UNICODE-O1",
        "ID SKU": "UNICODE-S1",
        "Tên sản phẩm": "Áo dài Việt Nam 🧵 - a\u0306\u0301",
        "ID sản phẩm": "UNICODE-P1",
        "Tên cửa hàng": "Cửa hàng thử nghiệm Việt Nam",
        "Mã cửa hàng": "UNICODE-SHOP1",
        "Trạng thái quyết toán đơn hàng": "Đã quyết toán",
        "GMV": "123.456",
        "Số món bán ra": "2",
        "Số món đã hoàn tiền": "0",
        "Hoa hồng tiêu chuẩn ước tính": "12.000",
        "Hoa hồng Quảng cáo cửa hàng ước tính": "1.000",
        "Thưởng ước tính": "500",
        "Tổng số tiền nhận được cuối cùng": "13.500",
        "Ngày đặt hàng": "01/10/2026 10:30:00",
        "Ngày quyết toán hoa hồng": "05/10/2026 12:00:00",
        "Đơn vị tiền tệ": "VND",
    })
    return row


def populate_source(engine) -> None:
    init_db(engine)
    with engine.begin() as conn:
        conn.execute(update(device_identity).where(device_identity.c.id == 1).values(
            device_id=DEVICE_ID, device_name="Synthetic Windows Unicode producer",
            platform=platform.system().lower(), created_at=FROZEN_TIME,
        ))
    create_account(engine, "UNICODE", display_name="Cửa hàng Việt Nam 🧪", display_order=1)
    row = raw_order()
    import_rows(
        engine, filename="affiliate_orders_unicode.xlsx", file_bytes=b"public synthetic Unicode order source v1",
        account="UNICODE", rows=[normalize_row(row, "UNICODE")],
    )
    with engine.begin() as conn:
        conn.execute(update(accounts).values(
            created_at=FROZEN_TIME, updated_at=FROZEN_TIME, sync_updated_at=FROZEN_TIME,
        ))
        conn.execute(update(import_batches).values(
            created_at=FROZEN_TIME, source_created_at=FROZEN_TIME, source_device_id=DEVICE_ID,
        ))
        conn.execute(monthly_targets.insert().values(
            account="UNICODE", month=date(2026, 10, 1), daily_target_commission=54321,
            sync_id=target_sync_id("UNICODE", date(2026, 10, 1)),
            source_device_id=DEVICE_ID, sync_updated_at=FROZEN_TIME,
        ))


def generate(args) -> None:
    version = cryptography.__version__
    if version != args.expected_cryptography:
        raise SystemExit(f"Expected cryptography {args.expected_cryptography}, observed {version}")
    if platform.system() != "Windows":
        raise SystemExit("These fixtures intentionally record a Windows producer; create a new cohort for another OS")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {
        "schema": 1,
        "passwords_are_public_synthetic_test_data": True,
        "notes": "Real source-tree Windows SyncService exports; NOT Android or packaged production exports. Raw UTF-8 passwords, no Unicode normalization. Random salt/nonce retained in frozen files.",
        "samples": [],
    }
    if not args.replace_version and any(sample["producer"]["cryptography"] == version for sample in manifest["samples"]):
        raise SystemExit("Refusing to overwrite frozen samples; review and pass --replace-version intentionally")
    filenames = [f"windows_crypto_{version.replace('.', '_')}_{case}.affsync" for case in PASSWORDS]
    if not args.replace_version and any((output / filename).exists() for filename in filenames):
        raise SystemExit("Refusing to overwrite an existing sample")
    provenance = {
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "python": platform.python_version(),
        "cryptography": version,
        "openssl": backend.openssl_version_text(),
        "sqlalchemy": __import__("sqlalchemy").__version__,
        "pandas": __import__("pandas").__version__,
        "entrypoint": "SyncService.export_package",
        "packaged_runtime": False,
        "app_version": APP_VERSION,
        "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "source_sha256": {
            path: hashlib.sha256((REPO / path).read_bytes()).hexdigest()
            for path in ("affiliate_report/sync_service.py", "affiliate_report/db.py", "affiliate_report/parser.py")
        },
    }
    samples = []
    with tempfile.TemporaryDirectory(prefix="affsync-unicode-", dir=args.scratch_dir) as work:
        engine = get_engine(f"sqlite:///{(Path(work) / 'source.db').as_posix()}")
        try:
            populate_source(engine)
            service = sync.SyncService(engine)
            for case, password in PASSWORDS.items():
                captured = []
                encrypt = sync._encrypt_payload

                def capture_plaintext(payload, passphrase):
                    captured.append(deepcopy(payload))
                    return encrypt(payload, passphrase)

                # Freeze logical ids/timestamps only. The production cipher/KDF and
                # os.urandom (salt/nonce) run unmodified under this interpreter.
                with patch.object(sync, "_encrypt_payload", capture_plaintext), patch.object(
                    sync, "_utcnow", return_value=FROZEN_TIME,
                ), patch.object(sync, "uuid4", return_value=uuid5(NAMESPACE, f"{version}:{case}")):
                    package, _ = service.export_package(password)
                expected = captured[0]
                assert sync._decrypt_payload(package, password) == expected
                sync.SyncService._validate_payload(deepcopy(expected))
                filename = f"windows_crypto_{version.replace('.', '_')}_{case}.affsync"
                (output / filename).write_bytes(package)
                sample = {
                    "case": case,
                    "filename": filename,
                    "passphrase": password,
                    "passphrase_codepoints": [f"U+{ord(char):04X}" for char in password],
                    "passphrase_utf8_hex": password.encode("utf-8").hex(),
                    "producer": provenance,
                    "size_bytes": len(package),
                    "package_sha256": hashlib.sha256(package).hexdigest(),
                    "plaintext_sha256": hashlib.sha256(sync._canonical(expected)).hexdigest(),
                    "expected_payload": expected,
                }
                samples.append(sample)
                print(json.dumps({"filename": filename, "bytes": len(package), "sha256": sample["package_sha256"], "cryptography": version}, ensure_ascii=True))
        finally:
            engine.dispose()
    manifest["samples"] = sorted(
        [sample for sample in manifest["samples"] if sample["producer"]["cryptography"] != version] + samples,
        key=lambda sample: (sample["producer"]["cryptography"], sample["case"]),
    )
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Observed producer: {provenance}; manifest samples: {len(manifest['samples'])}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-cryptography", required=True, choices=("42.0.8", "48.0.1"))
    parser.add_argument("--scratch-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--replace-version", action="store_true")
    generate(parser.parse_args())
