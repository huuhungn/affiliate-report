from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
import hashlib
import json
import re
import threading
import time
import unicodedata

from cryptography.exceptions import InvalidTag
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

import affiliate_report.sync_service as sync_module
import affiliate_report.api as api_module
from affiliate_report.accounts import create_account, delete_account, update_account
from affiliate_report.api import create_app
from affiliate_report.db import (
    accounts,
    app_users,
    auth_sessions,
    ensure_device_identity,
    get_engine,
    import_batches,
    import_rows,
    init_db,
    monthly_targets,
    order_line_versions,
    raw_import_rows,
    record_sync_tombstone,
    sync_history,
    sync_tombstones,
    user_account_access,
)
from affiliate_report.sync_service import (
    CONFIRMATION_PHRASE,
    SyncError,
    SyncPackageTooLarge,
    SyncPreviewExpired,
    SyncService,
    _decrypt_payload,
)
from affiliate_report.imports import undo_confirmation_phrase, undo_import
from affiliate_report.reset_data import reset_sqlite_business_data
from affiliate_report.version import APP_VERSION
from tests.test_api import normalized
from tests.test_api_auth import login, oidc_api

PASSPHRASE = "mat-khau-dong-bo-rat-manh"

# Frozen source-tree producer samples, never encrypted by the tests themselves.
UNICODE_FIXTURES = Path(__file__).parent / "fixtures" / "affsync_unicode"
UNICODE_CASES = [
    (version, case)
    for version in ("42.0.8", "48.0.1")
    for case in ("nfc", "nfd", "emoji_mixed")
]
UNICODE_CASE_IDS = [f"crypto-{version}-{case}" for version, case in UNICODE_CASES]
AUTHENTICATION_ERROR = "Mật khẩu không đúng hoặc gói đồng bộ đã bị chỉnh sửa."


def unicode_golden_sample(version: str, case: str) -> tuple[dict, bytes]:
    manifest = json.loads((UNICODE_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    matches = [
        sample for sample in manifest["samples"]
        if sample["producer"]["cryptography"] == version and sample["case"] == case
    ]
    assert len(matches) == 1, (version, case)
    sample = matches[0]
    package = (UNICODE_FIXTURES / sample["filename"]).read_bytes()
    assert len(package) == sample["size_bytes"]
    assert hashlib.sha256(package).hexdigest() == sample["package_sha256"]
    return sample, package


def test_affsync_unicode_golden_manifest_covers_both_producers_and_exact_codepoints():
    manifest = json.loads((UNICODE_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == 1
    assert manifest["passwords_are_public_synthetic_test_data"] is True
    assert len(manifest["samples"]) == len(UNICODE_CASES) == 6
    assert {
        (sample["producer"]["cryptography"], sample["case"])
        for sample in manifest["samples"]
    } == set(UNICODE_CASES)
    assert {path.name for path in UNICODE_FIXTURES.glob("*.affsync")} == {
        sample["filename"] for sample in manifest["samples"]
    }
    for version in ("42.0.8", "48.0.1"):
        samples = {case: unicode_golden_sample(version, case)[0] for case in ("nfc", "nfd", "emoji_mixed")}
        nfc, nfd, mixed = (samples[case]["passphrase"] for case in ("nfc", "nfd", "emoji_mixed"))
        assert unicodedata.normalize("NFC", nfc) == nfc
        assert unicodedata.normalize("NFD", nfc) == nfd
        assert nfc != nfd and nfc.encode("utf-8") != nfd.encode("utf-8")
        assert unicodedata.normalize("NFC", mixed) != mixed
        assert unicodedata.normalize("NFD", mixed) != mixed
        assert any(ord(char) > 0xFFFF for char in mixed)
        for sample in samples.values():
            password = sample["passphrase"]
            assert sample["passphrase_codepoints"] == [f"U+{ord(char):04X}" for char in password]
            assert sample["passphrase_utf8_hex"] == password.encode("utf-8").hex()
            assert sample["producer"]["platform_system"] == "Windows"
            assert sample["producer"]["packaged_runtime"] is False
            assert sample["producer"]["entrypoint"] == "SyncService.export_package"
            assert hashlib.sha256(sync_module._canonical(sample["expected_payload"])).hexdigest() == sample["plaintext_sha256"]


@pytest.mark.parametrize("version,case", UNICODE_CASES, ids=UNICODE_CASE_IDS)
def test_affsync_unicode_golden_static_file_decrypts_to_exact_payload(version, case):
    sample, package = unicode_golden_sample(version, case)
    assert package.startswith(b"AFFSYNC1")
    payload = _decrypt_payload(package, sample["passphrase"])
    assert payload == sample["expected_payload"]
    # A full, valid package, not an arbitrary dictionary accepted only by AES-GCM.
    SyncService._validate_payload(payload)


@pytest.mark.parametrize("version,case", UNICODE_CASES, ids=UNICODE_CASE_IDS)
def test_affsync_unicode_golden_wrong_password_has_authentication_error(version, case):
    sample, package = unicode_golden_sample(version, case)
    with pytest.raises(SyncError, match=f"^{re.escape(AUTHENTICATION_ERROR)}$") as caught:
        _decrypt_payload(package, sample["passphrase"] + "-wrong")
    assert type(caught.value) is SyncError
    assert isinstance(caught.value.__cause__, InvalidTag)


@pytest.mark.parametrize("version,case", UNICODE_CASES, ids=UNICODE_CASE_IDS)
def test_affsync_unicode_golden_rejects_different_normalization(version, case):
    sample, package = unicode_golden_sample(version, case)
    # NFC and NFD look alike but derive different keys. A mixed string rejects both.
    alternate_forms = ("NFD",) if case == "nfc" else ("NFC",) if case == "nfd" else ("NFC", "NFD")
    for form in alternate_forms:
        alternate = unicodedata.normalize(form, sample["passphrase"])
        assert alternate != sample["passphrase"]
        with pytest.raises(SyncError, match=f"^{re.escape(AUTHENTICATION_ERROR)}$") as caught:
            _decrypt_payload(package, alternate)
        assert type(caught.value) is SyncError
        assert isinstance(caught.value.__cause__, InvalidTag)


@pytest.mark.parametrize("version,case", UNICODE_CASES, ids=UNICODE_CASE_IDS)
def test_affsync_unicode_golden_api_preview_imports_frozen_package(tmp_path, version, case):
    sample, package = unicode_golden_sample(version, case)
    payload = sample["expected_payload"]
    target = engine_at(tmp_path / "unicode-golden.db")
    app = create_app(target)
    try:
        with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
            rejected = client.post(
                "/api/v1/sync/preview",
                data={"passphrase": sample["passphrase"] + "-wrong"},
                files={"package": (sample["filename"], package, "application/vnd.affiliate-report.sync")},
            )
            assert rejected.status_code == 422
            assert rejected.json() == {"detail": AUTHENTICATION_ERROR}
            assert app.state.sync._previews == {}

            preview = client.post(
                "/api/v1/sync/preview",
                data={"passphrase": sample["passphrase"]},
                files={"package": (sample["filename"], package, "application/vnd.affiliate-report.sync")},
            )
            assert preview.status_code == 200, preview.text
            body = preview.json()
            assert body["package_id"] == payload["manifest"]["package_id"]
            assert body["counts"] == payload["manifest"]["counts"]
            assert body["source_device"] == payload["manifest"]["source_device"]
            assert body["conflicts"] == []
            assert body["duplicate"] is False
            with target.connect() as conn:
                assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 0

            imported = client.post(
                "/api/v1/sync/import",
                json={"preview_id": body["preview_id"], "confirmation": CONFIRMATION_PHRASE, "conflict_resolutions": {}},
            )
            assert imported.status_code == 200, imported.text
            assert imported.json()["package_id"] == payload["manifest"]["package_id"]
            assert imported.json()["rebuilt"] == {"versions": 1, "current": 1, "raw_rows": 1}
            assert imported.json()["changed"] is True
            with target.connect() as conn:
                account = conn.execute(select(accounts)).mappings().one()
                assert account["code"] == payload["data"]["accounts"][0]["code"]
                assert account["display_name"] == payload["data"]["accounts"][0]["display_name"]
                batch = conn.execute(select(import_batches)).mappings().one()
                assert batch["file_sha"] == payload["data"]["import_batches"][0]["file_sha"]
                raw = conn.execute(select(raw_import_rows)).mappings().one()
                assert raw["raw_json"] == payload["data"]["raw_rows"][0]["raw_json"]
                order = conn.execute(select(order_line_versions)).mappings().one()
                assert order["business_key"] == payload["data"]["raw_rows"][0]["business_key"]
                assert order["product_name"] == raw["raw_json"]["Tên sản phẩm"]
                assert order["gmv"] == raw["raw_json"]["GMV"] == 123456
                assert order["estimated_commission"] == 13500
                assert order["is_current"] is True
                target_row = conn.execute(select(monthly_targets)).mappings().one()
                assert target_row["daily_target_commission"] == payload["data"]["targets"][0]["daily_target_commission"]
                history = conn.execute(select(sync_history)).mappings().one()
                assert history["package_hash"] == sample["package_sha256"]
                assert history["direction"] == "import"
    finally:
        target.dispose()


@pytest.mark.parametrize("state", ["fresh", "restored"])
def test_affsync_unicode_android_cross_check_phase_round_trips_through_desktop(tmp_path, monkeypatch, state):
    """Run the emulator cross-check phase in-process against the real Android-mode FastAPI app."""
    from scripts.ci import android_runtime_smoke as smoke

    token = "android-test-token-which-is-at-least-32-bytes"
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", token)
    if state == "fresh":
        engine = engine_at(tmp_path / "android.db")
    else:
        # Mirrors the emulator order: cross-check runs after restore rebuilt the DB from a package.
        source = imported_engine(tmp_path / "before-clear.db", account=smoke.ACCOUNT)
        try:
            package, _ = SyncService(source).export_package(smoke.PASSPHRASE)
        finally:
            source.dispose()
        engine = engine_at(tmp_path / "android.db")
        restore = SyncService(engine)
        preview = restore.preview(package, smoke.PASSPHRASE)
        restore.import_preview(preview["preview_id"], CONFIRMATION_PHRASE, {})
    try:
        with TestClient(
            create_app(engine),
            base_url="http://127.0.0.1",
            client=("127.0.0.1", 50000),
            headers={"X-Android-Local-Token": token},
        ) as client:
            result = smoke._cross_check(client, APP_VERSION)
    finally:
        engine.dispose()

    manifest = json.loads((UNICODE_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    imported = result["desktop_to_android"]
    assert [item["filename"] for item in imported] == sorted(sample["filename"] for sample in manifest["samples"])
    assert all(item["rejected_normalizations"] >= 1 for item in imported)
    assert sum(item["summary"]["new_accounts"] for item in imported) == 1
    assert all(item["summary"]["new_raw_rows"] == 0 for item in imported[1:])
    returned = result["android_to_desktop"]
    assert returned["rejected_normalizations"] >= 1
    assert set(returned["return_summary"].values()) == {0}
    assert returned["counts"]["accounts"] == 1 + (state == "restored")


def engine_at(path: Path):
    engine = get_engine(f"sqlite:///{path.as_posix()}")
    init_db(engine)
    return engine


def imported_engine(path: Path, *, account: str = "SHOP", file_bytes: bytes = b"source"):
    engine = engine_at(path)
    create_account(engine, account, display_name=account)
    import_rows(
        engine,
        filename="orders.xlsx",
        file_bytes=file_bytes,
        account=account,
        rows=[normalized(account)],
        uploaded_by_label="Owner Name",
        auth_method="oidc",
        auth_subject="https://issuer.example:user-secret",
    )
    return engine


def import_package(service: SyncService, package: bytes, *, resolution: str | None = None) -> dict:
    preview = service.preview(package, PASSPHRASE)
    if preview["conflicts"] and resolution is None:
        raise AssertionError("Test must choose every sync conflict explicitly")
    resolutions = {item["key"]: resolution for item in preview["conflicts"]}
    return service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE, resolutions)


def test_affsync_round_trip_preserves_current_orders_and_excludes_auth(tmp_path):
    source = imported_engine(tmp_path / "source.db")
    target = engine_at(tmp_path / "target.db")
    source_service = SyncService(source)
    target_service = SyncService(target)

    package, manifest = source_service.export_package(PASSPHRASE)
    assert package.startswith(b"AFFSYNC1")
    assert manifest["counts"]["import_batches"] == 1
    payload = _decrypt_payload(package, PASSPHRASE)
    serialized = sync_module._canonical(payload)
    assert b"user-secret" not in serialized
    assert b"Owner Name" not in serialized
    assert b"auth_subject" not in serialized

    preview = target_service.preview(package, PASSPHRASE)
    result = target_service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)

    assert result["duplicate"] is False
    assert result["rebuilt"] == {"versions": 1, "current": 1, "raw_rows": 1}
    with source.connect() as source_conn, target.connect() as target_conn:
        source_rows = source_conn.execute(select(
            order_line_versions.c.business_key,
            order_line_versions.c.normalized_hash,
            order_line_versions.c.gmv,
            order_line_versions.c.estimated_commission,
            order_line_versions.c.is_current,
        )).all()
        target_rows = target_conn.execute(select(
            order_line_versions.c.business_key,
            order_line_versions.c.normalized_hash,
            order_line_versions.c.gmv,
            order_line_versions.c.estimated_commission,
            order_line_versions.c.is_current,
        )).all()
    assert target_rows == source_rows
    assert Path(result["backup_path"]).exists()


def test_wrong_password_tamper_oversize_and_duplicate_are_fail_closed(tmp_path, monkeypatch):
    source = imported_engine(tmp_path / "source.db")
    target = engine_at(tmp_path / "target.db")
    package, _ = SyncService(source).export_package(PASSPHRASE)
    service = SyncService(target)

    with pytest.raises(SyncError, match="Mật khẩu không đúng"):
        service.preview(package, "mat-khau-sai-nhung-du-dai")
    tampered = bytearray(package)
    tampered[-1] ^= 1
    with pytest.raises(SyncError, match="đã bị chỉnh sửa"):
        service.preview(bytes(tampered), PASSPHRASE)
    monkeypatch.setattr(sync_module, "MAX_PACKAGE_BYTES", 32)
    with pytest.raises(SyncPackageTooLarge, match="100 MiB"):
        service.preview(b"x" * 33, PASSPHRASE)
    monkeypatch.setattr(sync_module, "MAX_PACKAGE_BYTES", 100 * 1024 * 1024)

    preview = service.preview(package, PASSPHRASE)
    service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)
    second = service.preview(package, PASSPHRASE)
    duplicate = service.import_preview(second["preview_id"], CONFIRMATION_PHRASE)
    assert second["duplicate"] is True
    assert duplicate["duplicate"] is True
    assert duplicate["already_imported"] is True
    assert duplicate["package_id"] == second["manifest"]["package_id"]
    assert duplicate["changed"] is False
    with target.connect() as conn:
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 1
        assert conn.execute(select(func.count()).select_from(sync_history).where(sync_history.c.direction == "import")).scalar_one() == 1


def test_preview_expires_after_fifteen_minutes(tmp_path):
    source = imported_engine(tmp_path / "source.db")
    target = engine_at(tmp_path / "target.db")
    package, _ = SyncService(source).export_package(PASSPHRASE)
    service = SyncService(target)
    preview = service.preview(package, PASSPHRASE)
    service._previews[preview["preview_id"]].expires_at = datetime.now(UTC) - timedelta(seconds=1)

    with pytest.raises(sync_module.SyncPreviewExpired, match="hết hạn"):
        service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)


def test_sync_api_preview_and_import_round_trip(tmp_path):
    source = imported_engine(tmp_path / "source.db")
    package, _ = SyncService(source).export_package(PASSPHRASE)
    target = engine_at(tmp_path / "target.db")
    client = TestClient(
        create_app(target), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    )

    preview = client.post(
        "/api/v1/sync/preview",
        data={"passphrase": PASSPHRASE},
        files={"package": ("transfer.affsync", package, "application/vnd.affiliate-report.sync")},
    )
    assert preview.status_code == 200
    imported = client.post(
        "/api/v1/sync/import",
        json={
            "preview_id": preview.json()["preview_id"],
            "confirmation": CONFIRMATION_PHRASE,
            "conflict_resolutions": {},
        },
    )
    assert imported.status_code == 200
    assert imported.json()["counts"]["import_batches"] == 1
    with target.connect() as conn:
        assert conn.execute(select(func.count()).select_from(order_line_versions)).scalar_one() == 1


def test_conflict_preview_requires_explicit_choice_and_accepts_local_or_incoming(tmp_path):
    source = engine_at(tmp_path / "source.db")
    target = engine_at(tmp_path / "target.db")
    create_account(source, "SHOP", display_name="Tên từ điện thoại")
    create_account(target, "SHOP", display_name="Tên trên máy tính")
    with source.begin() as conn:
        conn.execute(monthly_targets.insert().values(account="SHOP", month=date(2026, 8, 1), daily_target_commission=200))
    with target.begin() as conn:
        conn.execute(monthly_targets.insert().values(account="SHOP", month=date(2026, 8, 1), daily_target_commission=100))
    source_service = SyncService(source)
    target_service = SyncService(target)

    package, _ = source_service.export_package(PASSPHRASE)
    preview = target_service.preview(package, PASSPHRASE)
    keys = {item["key"] for item in preview["conflicts"]}
    assert keys == {"account:SHOP", "target:SHOP|2026-08-01"}
    with pytest.raises(SyncError, match="Lựa chọn xử lý xung đột"):
        target_service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)
    target_service.import_preview(
        preview["preview_id"],
        CONFIRMATION_PHRASE,
        {key: "local" for key in keys},
    )
    with target.connect() as conn:
        assert conn.execute(select(accounts.c.display_name).where(accounts.c.code == "SHOP")).scalar_one() == "Tên trên máy tính"
        assert conn.execute(select(monthly_targets.c.daily_target_commission)).scalar_one() == 100

    package2, _ = source_service.export_package(PASSPHRASE)
    preview2 = target_service.preview(package2, PASSPHRASE)
    target_service.import_preview(
        preview2["preview_id"],
        CONFIRMATION_PHRASE,
        {key: "incoming" for key in keys},
    )
    with target.connect() as conn:
        assert conn.execute(select(accounts.c.display_name).where(accounts.c.code == "SHOP")).scalar_one() == "Tên từ điện thoại"
        assert conn.execute(select(monthly_targets.c.daily_target_commission)).scalar_one() == 200


def test_imported_tombstone_removes_batch_and_rebuilds_without_it(tmp_path):
    target = imported_engine(tmp_path / "target.db")
    with target.connect() as conn:
        target_sync_id = conn.execute(select(import_batches.c.sync_id)).scalar_one()
    source = engine_at(tmp_path / "source.db")
    with source.begin() as conn:
        device_id = ensure_device_identity(conn)["device_id"]
        conn.execute(sync_tombstones.insert().values(
            entity_type="import_batch",
            entity_key=target_sync_id,
            source_device_id=device_id,
        ))

    package, _ = SyncService(source).export_package(PASSPHRASE)
    service = SyncService(target)
    preview = service.preview(package, PASSPHRASE)
    delete_key = f"delete:import_batch:{target_sync_id}"
    assert {item["key"] for item in preview["conflicts"]} == {delete_key}
    result = service.import_preview(
        preview["preview_id"],
        CONFIRMATION_PHRASE,
        {delete_key: "incoming"},
    )

    assert result["applied"]["tombstones"] == 1
    with target.connect() as conn:
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(raw_import_rows)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(order_line_versions)).scalar_one() == 0


def test_undo_import_records_exportable_tombstone(tmp_path):
    engine = imported_engine(tmp_path / "source.db")
    with engine.connect() as conn:
        batch = conn.execute(select(import_batches.c.id, import_batches.c.sync_id)).one()

    undo_import(engine, batch.id, undo_confirmation_phrase(batch.id))
    with engine.connect() as conn:
        tombstone = conn.execute(select(sync_tombstones)).mappings().one()
    assert tombstone["entity_type"] == "import_batch"
    assert tombstone["entity_key"] == batch.sync_id

    package, _ = SyncService(engine).export_package(PASSPHRASE)
    payload = _decrypt_payload(package, PASSPHRASE)
    assert payload["data"]["tombstones"][0]["entity_key"] == batch.sync_id


def test_logical_records_converge_to_same_sync_ids_on_independent_devices(tmp_path):
    left = imported_engine(tmp_path / "left.db", file_bytes=b"same-file")
    right = imported_engine(tmp_path / "right.db", file_bytes=b"same-file")
    month = date(2026, 8, 1)
    with left.begin() as conn:
        conn.execute(monthly_targets.insert().values(account="SHOP", month=month, daily_target_commission=100))
    with right.begin() as conn:
        conn.execute(monthly_targets.insert().values(account="SHOP", month=month, daily_target_commission=200))

    # Export canonicalizes legacy/null identities before serializing the package.
    SyncService(left).export_package(PASSPHRASE)
    SyncService(right).export_package(PASSPHRASE)
    with left.connect() as left_conn, right.connect() as right_conn:
        assert left_conn.execute(select(accounts.c.sync_id)).scalar_one() == right_conn.execute(select(accounts.c.sync_id)).scalar_one()
        assert left_conn.execute(select(import_batches.c.sync_id)).scalar_one() == right_conn.execute(select(import_batches.c.sync_id)).scalar_one()
        assert left_conn.execute(select(monthly_targets.c.sync_id)).scalar_one() == right_conn.execute(select(monthly_targets.c.sync_id)).scalar_one()


def test_local_tombstones_block_stale_account_target_and_batch_packages(tmp_path):
    source = imported_engine(tmp_path / "source-stale.db")
    target = engine_at(tmp_path / "target-stale.db")
    month = date(2026, 8, 1)
    with source.begin() as conn:
        conn.execute(monthly_targets.insert().values(account="SHOP", month=month, daily_target_commission=100))
    service = SyncService(source)
    seed, _ = service.export_package(PASSPHRASE)
    stale, _ = service.export_package(PASSPHRASE)
    target_service = SyncService(target)
    import_package(target_service, seed)

    with source.begin() as conn:
        target_row = conn.execute(select(monthly_targets.c.id, monthly_targets.c.sync_id)).one()
        record_sync_tombstone(conn, "target", target_row.sync_id)
        conn.execute(monthly_targets.delete().where(monthly_targets.c.id == target_row.id))
    with source.connect() as conn:
        batch_id = conn.execute(select(import_batches.c.id)).scalar_one()
    undo_import(source, batch_id, confirmation=undo_confirmation_phrase(batch_id))
    delete_account(source, "SHOP", hard=True)
    deleted, _ = service.export_package(PASSPHRASE)
    deleted_preview = target_service.preview(deleted, PASSPHRASE)
    deleted_keys = {item["key"] for item in deleted_preview["conflicts"]}
    account_delete_key = next(key for key in deleted_keys if key.startswith("delete:account:"))
    mixed_resolutions = {key: "local" for key in deleted_keys}
    mixed_resolutions[account_delete_key] = "incoming"
    with pytest.raises(SyncError, match="xóa account.*giữ mục tiêu hoặc lịch sử nhập"):
        target_service.import_preview(
            deleted_preview["preview_id"],
            CONFIRMATION_PHRASE,
            mixed_resolutions,
        )
    target_service.import_preview(
        deleted_preview["preview_id"],
        CONFIRMATION_PHRASE,
        {key: "incoming" for key in deleted_keys},
    )
    stale_preview = target_service.preview(stale, PASSPHRASE)
    assert {item["key"] for item in stale_preview["conflicts"]} == {
        f"delete:account:{next(row['entity_key'] for row in _decrypt_payload(deleted, PASSPHRASE)['data']['tombstones'] if row['entity_type'] == 'account')}",
        f"delete:target:{next(row['entity_key'] for row in _decrypt_payload(deleted, PASSPHRASE)['data']['tombstones'] if row['entity_type'] == 'target')}",
        f"delete:import_batch:{next(row['entity_key'] for row in _decrypt_payload(deleted, PASSPHRASE)['data']['tombstones'] if row['entity_type'] == 'import_batch')}",
    }
    target_service.import_preview(
        stale_preview["preview_id"],
        CONFIRMATION_PHRASE,
        {item["key"]: "local" for item in stale_preview["conflicts"]},
    )

    with target.connect() as conn:
        assert conn.execute(select(func.count()).select_from(accounts)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(monthly_targets)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 0


def test_delete_then_recreate_requires_explicit_resurrection_and_converges(tmp_path):
    source = imported_engine(tmp_path / "source-recreate.db")
    target = engine_at(tmp_path / "target-recreate.db")
    month = date(2026, 8, 1)
    source_client = TestClient(
        create_app(source), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    )
    assert source_client.put("/api/v1/targets/SHOP/2026-08", json={"daily_target_commission": 100}).status_code == 200
    source_service = SyncService(source)
    target_service = SyncService(target)
    seed, _ = source_service.export_package(PASSPHRASE)
    import_package(target_service, seed)

    with source.connect() as conn:
        batch_id = conn.execute(select(import_batches.c.id)).scalar_one()
        target_row = conn.execute(select(monthly_targets.c.id, monthly_targets.c.sync_id)).one()
    undo_import(source, batch_id, confirmation=undo_confirmation_phrase(batch_id))
    with source.begin() as conn:
        record_sync_tombstone(conn, "target", target_row.sync_id)
        conn.execute(monthly_targets.delete().where(monthly_targets.c.id == target_row.id))
    delete_account(source, "SHOP", hard=True)
    deleted, _ = source_service.export_package(PASSPHRASE)
    import_package(target_service, deleted, resolution="incoming")

    create_account(source, "SHOP", display_name="SHOP phục hồi")
    import_rows(
        source,
        filename="orders.xlsx",
        file_bytes=b"source",
        account="SHOP",
        rows=[normalized("SHOP")],
    )
    assert source_client.put("/api/v1/targets/SHOP/2026-08", json={"daily_target_commission": 250}).status_code == 200
    recreated, _ = source_service.export_package(PASSPHRASE)
    preview = target_service.preview(recreated, PASSPHRASE)
    conflict_keys = {item["key"] for item in preview["conflicts"]}
    assert len(conflict_keys) == 3
    assert all(key.startswith("delete:") for key in conflict_keys)
    target_service.import_preview(
        preview["preview_id"],
        CONFIRMATION_PHRASE,
        {key: "incoming" for key in conflict_keys},
    )

    with target.connect() as conn:
        assert conn.execute(select(accounts.c.display_name).where(accounts.c.code == "SHOP")).scalar_one() == "SHOP phục hồi"
        assert conn.execute(select(monthly_targets.c.daily_target_commission).where(
            monthly_targets.c.account == "SHOP", monthly_targets.c.month == month,
        )).scalar_one() == 250
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 1
        assert conn.execute(select(func.count()).select_from(sync_tombstones)).scalar_one() == 0


def test_preview_fails_closed_when_account_target_and_tombstone_change_before_confirm(tmp_path):
    source = imported_engine(tmp_path / "source-preview-race.db")
    target = engine_at(tmp_path / "target-preview-race.db")
    month = date(2026, 8, 1)
    with source.begin() as conn:
        conn.execute(monthly_targets.insert().values(
            account="SHOP",
            month=month,
            daily_target_commission=100,
        ))
    source_service = SyncService(source)
    target_service = SyncService(target)
    seed, _ = source_service.export_package(PASSPHRASE)
    import_package(target_service, seed)
    with target.begin() as conn:
        conn.execute(accounts.update().where(accounts.c.code == "SHOP").values(display_name="Tên local A"))
        conn.execute(monthly_targets.update().where(
            monthly_targets.c.account == "SHOP",
            monthly_targets.c.month == month,
        ).values(daily_target_commission=200))

    candidate, _ = source_service.export_package(PASSPHRASE)
    preview = target_service.preview(candidate, PASSPHRASE)
    assert {item["entity"] for item in preview["conflicts"]} == {"account", "target"}
    stale_resolutions = {item["key"]: "incoming" for item in preview["conflicts"]}

    with target.begin() as conn:
        conn.execute(accounts.update().where(accounts.c.code == "SHOP").values(display_name="Tên local B"))
        conn.execute(monthly_targets.update().where(
            monthly_targets.c.account == "SHOP",
            monthly_targets.c.month == month,
        ).values(daily_target_commission=300))
    with target.connect() as conn:
        batch_id = conn.execute(select(import_batches.c.id)).scalar_one()
    undo_import(target, batch_id, confirmation=undo_confirmation_phrase(batch_id))

    with pytest.raises(SyncPreviewExpired, match="đã thay đổi sau khi xem trước"):
        target_service.import_preview(
            preview["preview_id"],
            CONFIRMATION_PHRASE,
            stale_resolutions,
        )
    with target.connect() as conn:
        assert conn.execute(select(accounts.c.display_name).where(accounts.c.code == "SHOP")).scalar_one() == "Tên local B"
        assert conn.execute(select(monthly_targets.c.daily_target_commission).where(
            monthly_targets.c.account == "SHOP",
            monthly_targets.c.month == month,
        )).scalar_one() == 300
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 0


def test_preview_expires_when_new_child_would_be_cascade_deleted(tmp_path):
    source = imported_engine(tmp_path / "source-cascade-preview.db")
    target = engine_at(tmp_path / "target-cascade-preview.db")
    source_service = SyncService(source)
    target_service = SyncService(target)
    seed, _ = source_service.export_package(PASSPHRASE)
    import_package(target_service, seed)

    with source.begin() as conn:
        account_row = conn.execute(select(accounts.c.sync_id).where(accounts.c.code == "SHOP")).one()
        record_sync_tombstone(conn, "account", account_row.sync_id)
        conn.execute(order_line_versions.delete())
        conn.execute(raw_import_rows.delete())
        conn.execute(import_batches.delete())
        conn.execute(monthly_targets.delete())
        conn.execute(accounts.delete().where(accounts.c.code == "SHOP"))
    deleted, _ = source_service.export_package(PASSPHRASE)
    preview = target_service.preview(deleted, PASSPHRASE)
    assert [item["entity"] for item in preview["conflicts"]] == ["account"]

    new_month = date(2026, 9, 1)
    with target.begin() as conn:
        conn.execute(monthly_targets.insert().values(
            account="SHOP",
            month=new_month,
            daily_target_commission=777,
        ))

    with pytest.raises(SyncPreviewExpired, match="đã thay đổi sau khi xem trước"):
        target_service.import_preview(
            preview["preview_id"],
            CONFIRMATION_PHRASE,
            {preview["conflicts"][0]["key"]: "incoming"},
        )
    with target.connect() as conn:
        assert conn.execute(select(monthly_targets.c.daily_target_commission).where(
            monthly_targets.c.account == "SHOP",
            monthly_targets.c.month == new_month,
        )).scalar_one() == 777


def test_export_holds_one_sqlite_snapshot_while_collecting_all_tables(tmp_path, monkeypatch):
    engine = imported_engine(tmp_path / "export-snapshot.db")
    service = SyncService(engine)
    original_export_data = service._export_data
    writer_started = threading.Event()
    writer_finished = threading.Event()
    writer_thread: threading.Thread | None = None

    def write_during_export():
        writer_started.set()
        with engine.begin() as conn:
            conn.execute(accounts.update().where(accounts.c.code == "SHOP").values(display_name="Đã đổi"))
        writer_finished.set()

    def wrapped_export_data(conn, device_id):
        nonlocal writer_thread
        writer_thread = threading.Thread(target=write_during_export, daemon=True)
        writer_thread.start()
        assert writer_started.wait(1)
        time.sleep(0.15)
        assert not writer_finished.is_set(), "Writer must stay blocked until the export snapshot commits"
        return original_export_data(conn, device_id)

    monkeypatch.setattr(service, "_export_data", wrapped_export_data)
    package, _ = service.export_package(PASSPHRASE)
    assert package.startswith(b"AFFSYNC1")
    assert writer_thread is not None
    writer_thread.join(timeout=3)
    assert writer_finished.is_set()


def test_reset_exports_batch_tombstones_and_keeps_sync_history_idempotence(tmp_path):
    source = imported_engine(tmp_path / "source-reset.db")
    target = engine_at(tmp_path / "target-reset.db")
    seed, _ = SyncService(source).export_package(PASSPHRASE)
    import_package(SyncService(target), seed)

    reset_sqlite_business_data(source)
    with source.connect() as conn:
        assert conn.execute(select(func.count()).select_from(sync_history)).scalar_one() >= 1
        assert conn.execute(select(func.count()).select_from(sync_tombstones)).scalar_one() == 1
    deleted, _ = SyncService(source).export_package(PASSPHRASE)
    import_package(SyncService(target), deleted, resolution="incoming")
    with target.connect() as conn:
        assert conn.execute(select(func.count()).select_from(import_batches)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(raw_import_rows)).scalar_one() == 0


def test_import_rolls_back_all_database_changes_when_rebuild_fails(tmp_path, monkeypatch):
    target = imported_engine(tmp_path / "target.db", file_bytes=b"existing")
    source = imported_engine(tmp_path / "source.db", account="OTHER", file_bytes=b"incoming")
    package, _ = SyncService(source).export_package(PASSPHRASE)
    service = SyncService(target)
    preview = service.preview(package, PASSPHRASE)
    with target.connect() as conn:
        before = (
            conn.execute(select(func.count()).select_from(import_batches)).scalar_one(),
            conn.execute(select(func.count()).select_from(order_line_versions)).scalar_one(),
        )

    def fail_rebuild(_conn):
        raise RuntimeError("forced rebuild failure")

    monkeypatch.setattr(service, "_rebuild_versions", fail_rebuild)
    with pytest.raises(RuntimeError, match="forced rebuild failure"):
        service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)
    with target.connect() as conn:
        after = (
            conn.execute(select(func.count()).select_from(import_batches)).scalar_one(),
            conn.execute(select(func.count()).select_from(order_line_versions)).scalar_one(),
        )
    assert after == before
    assert list((tmp_path / "backups").glob("*sync-import*.db"))
    assert list(tmp_path.glob(".*-sync-stage-*.db*")) == []


def test_sync_api_is_local_only_and_oidc_still_checks_owner_and_csrf(tmp_path):
    client, engine, auth = oidc_api(tmp_path)
    viewer, viewer_tokens = login(client, auth, "viewer@example.test", "viewer")
    auth.update_user(viewer.user_id or 0, role="viewer")
    assert client.get("/api/v1/sync/status").status_code == 403
    assert client.post(
        "/api/v1/sync/export",
        json={"passphrase": PASSPHRASE},
        headers={"X-CSRF-Token": viewer_tokens.csrf_token},
    ).status_code == 403

    owner, owner_tokens = login(client, auth, "owner@example.test", "owner-sync")
    auth.update_user(owner.user_id or 0, role="owner")
    assert client.post("/api/v1/sync/export", json={"passphrase": PASSPHRASE}).status_code == 403
    response = client.post(
        "/api/v1/sync/export",
        json={"passphrase": PASSPHRASE},
        headers={"X-CSRF-Token": owner_tokens.csrf_token},
    )
    assert response.status_code == 409
    assert client.get("/api/v1/meta").json()["capabilities"]["sync"]["available"] is False

    local_engine = engine_at(tmp_path / "local-api.db")
    local_client = TestClient(
        create_app(local_engine), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    )
    local_response = local_client.post("/api/v1/sync/export", json={"passphrase": PASSPHRASE})
    assert local_response.status_code == 200
    assert local_response.content.startswith(b"AFFSYNC1")
    assert local_response.headers["content-type"].startswith("application/vnd.affiliate-report.sync")
    assert "AffiliateReport-" in local_response.headers["content-disposition"]


def test_staging_replace_preserves_auth_session_and_account_access(tmp_path):
    _client, target, auth = oidc_api(tmp_path)
    principal = auth.provision_user(
        issuer=auth.settings.oidc_issuer or "",
        subject="preserved-user",
        email="owner@example.test",
    )
    auth.update_user(principal.user_id or 0, role="owner", accounts=["CHIISTORE"])
    auth.create_session(principal)
    source = imported_engine(tmp_path / "incoming.db", account="OTHER")
    package, _ = SyncService(source).export_package(PASSPHRASE)
    service = SyncService(target)
    preview = service.preview(package, PASSPHRASE)

    with target.connect() as conn:
        before = {
            table.name: [dict(row) for row in conn.execute(select(table)).mappings()]
            for table in (app_users, auth_sessions, user_account_access)
        }
    service.import_preview(preview["preview_id"], CONFIRMATION_PHRASE)
    with target.connect() as conn:
        after = {
            table.name: [dict(row) for row in conn.execute(select(table)).mappings()]
            for table in (app_users, auth_sessions, user_account_access)
        }
    assert after == before


def test_android_sync_export_uses_one_time_loopback_download(tmp_path, monkeypatch):
    engine = imported_engine(tmp_path / "android-export.db")
    token = "android-test-token-which-is-at-least-32-bytes"
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", token)
    client = TestClient(
        create_app(engine),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
        headers={"X-Android-Local-Token": token},
    )

    prepared = client.post("/api/v1/sync/export/prepare", json={"passphrase": PASSPHRASE})
    assert prepared.status_code == 200
    body = prepared.json()
    assert body["download_url"].startswith("/api/v1/sync/export/download/")
    assert body["filename"].endswith(".affsync")
    assert body["size"] > 0

    first_url = body["download_url"]
    first_entry = next(iter(client.app.state.sync_export_tokens.values()))
    first_path = Path(first_entry["path"])
    assert first_path.is_file()
    replacement = client.post("/api/v1/sync/export/prepare", json={"passphrase": PASSPHRASE})
    assert replacement.status_code == 200
    body = replacement.json()
    assert len(client.app.state.sync_export_tokens) == 1
    assert not first_path.exists()
    assert client.get(first_url).status_code == 404

    downloaded = client.get(body["download_url"])
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"AFFSYNC1")
    assert downloaded.headers["content-length"] == str(body["size"])
    assert client.get(body["download_url"]).status_code == 404


def test_android_sync_export_spool_is_swept_on_app_restart(tmp_path, monkeypatch):
    engine = imported_engine(tmp_path / "android-export-restart.db")
    token = "android-test-token-which-is-at-least-32-bytes"
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", token)
    first_client = TestClient(
        create_app(engine),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
        headers={"X-Android-Local-Token": token},
    )
    prepared = first_client.post("/api/v1/sync/export/prepare", json={"passphrase": PASSPHRASE})
    assert prepared.status_code == 200
    package_path = Path(next(iter(first_client.app.state.sync_export_tokens.values()))["path"])
    orphan_tmp = package_path.parent / "interrupted.tmp"
    orphan_tmp.write_bytes(b"partial")
    assert package_path.is_file() and orphan_tmp.is_file()

    restarted = create_app(engine)
    assert restarted.state.sync_export_tokens == {}
    assert not package_path.exists()
    assert not orphan_tmp.exists()


def test_android_apk_prepare_is_platform_gated_and_one_time(tmp_path, monkeypatch):
    engine = engine_at(tmp_path / "android.db")
    monkeypatch.setenv("APP_PLATFORM", "windows")
    windows_client = TestClient(
        create_app(engine), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    )
    assert windows_client.post("/api/v1/update/android/prepare").status_code == 409

    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", "android-test-token-which-is-at-least-32-bytes")
    android_client = TestClient(
        create_app(engine),
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
        headers={"X-Android-Local-Token": "android-test-token-which-is-at-least-32-bytes"},
    )

    def fake_download(data_dir: Path):
        apk = data_dir / "updates" / "v2.1.1" / "AffiliateReport-v2.1.1-arm64.apk"
        apk.parent.mkdir(parents=True, exist_ok=True)
        apk.write_bytes(b"verified-apk")
        return {
            "version": "2.1.1",
            "apk_path": str(apk),
            "sha256": "A" * 64,
            "release_url": "https://example.test/v2.1.1",
        }

    monkeypatch.setattr(api_module, "download_latest_android", fake_download)
    prepared = android_client.post("/api/v1/update/android/prepare")
    assert prepared.status_code == 200
    assert prepared.json()["filename"] == "AffiliateReport-v2.1.1-arm64.apk"
    assert prepared.json()["size"] == len(b"verified-apk")
    download_url = prepared.json()["download_url"]
    downloaded = android_client.get(download_url)
    assert downloaded.status_code == 200
    assert downloaded.content == b"verified-apk"
    assert downloaded.headers["content-type"] == "application/vnd.android.package-archive"
    assert downloaded.headers["x-affiliate-report-version"] == "2.1.1"
    assert downloaded.headers["x-affiliate-report-size"] == str(len(b"verified-apk"))
    assert downloaded.headers["x-affiliate-report-sha256"] == "A" * 64
    assert android_client.get(download_url).status_code == 404

    expired = android_client.post("/api/v1/update/android/prepare").json()["download_url"]
    expired_token = expired.rsplit("/", 1)[-1]
    android_client.app.state.android_apk_tokens[expired_token]["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
    assert android_client.get(expired).status_code == 404


def test_android_apk_prepare_checks_csrf_then_rejects_oidc_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", "android-test-token-which-is-at-least-32-bytes")
    client, engine, auth = oidc_api(tmp_path)
    owner, tokens = login(client, auth, "owner@example.test", "owner-android-update")
    auth.update_user(owner.user_id or 0, role="owner")

    def fake_download(data_dir: Path):
        apk = data_dir / "updates" / "v2.1.1" / "AffiliateReport-v2.1.1-arm64.apk"
        apk.parent.mkdir(parents=True, exist_ok=True)
        apk.write_bytes(b"verified-apk")
        return {
            "version": "2.1.1", "apk_path": str(apk), "sha256": "A" * 64,
            "release_url": "https://example.test/v2.1.1",
        }

    monkeypatch.setattr(api_module, "download_latest_android", fake_download)
    assert client.post("/api/v1/update/android/prepare").status_code == 401
    assert client.post(
        "/api/v1/update/android/prepare",
        headers={
            "X-CSRF-Token": tokens.csrf_token,
            "X-Android-Local-Token": "android-test-token-which-is-at-least-32-bytes",
        },
    ).status_code == 409


def test_android_local_api_requires_private_native_token(tmp_path, monkeypatch):
    engine = engine_at(tmp_path / "android-private.db")
    token = "android-private-token-with-more-than-32-bytes"
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.setenv("ANDROID_LOCAL_TOKEN", token)
    update_checks = 0

    def fake_android_update():
        nonlocal update_checks
        update_checks += 1
        return {"current_version": "2.1.0", "available": False, "installable": False}

    monkeypatch.setattr(api_module, "check_for_android_update", fake_android_update)
    client = TestClient(
        create_app(engine), base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
    )

    assert client.get("/health").status_code == 200
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"X-Android-Local-Token": "wrong-token"}).status_code == 401
    assert client.post(
        "/api/v1/accounts", json={"code": "PRIVATE", "display_name": "Private"}
    ).status_code == 401
    assert client.get("/auth/me", headers={"X-Android-Local-Token": token}).status_code == 200
    created = client.post(
        "/api/v1/accounts",
        json={"code": "PRIVATE", "display_name": "Private"},
        headers={"X-Android-Local-Token": token},
    )
    assert created.status_code == 201
    client.cookies.set("android_local_token", token)
    meta = client.get("/api/v1/meta")
    assert meta.status_code == 200
    assert meta.json()["android_update"] is None
    assert update_checks == 0
    assert client.get("/api/v1/update/android/status").status_code == 200
    assert update_checks == 1


def test_android_runtime_fails_closed_without_private_token(tmp_path, monkeypatch):
    engine = engine_at(tmp_path / "android-missing-token.db")
    monkeypatch.setenv("APP_PLATFORM", "android")
    monkeypatch.delenv("ANDROID_LOCAL_TOKEN", raising=False)
    with pytest.raises(ValueError, match="ANDROID_LOCAL_TOKEN"):
        create_app(engine)
