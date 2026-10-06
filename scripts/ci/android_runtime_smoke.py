from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from typing import Any

import httpx


REPO_ROOT = Path(__file__).resolve().parents[2]
UNICODE_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "affsync_unicode"
PASSPHRASE = "Android-Smoke-2026!"
# Key derivation hashes the raw UTF-8 bytes of the passphrase, so the cross-check uses one
# decomposed (NFD) and one composed (NFC) Vietnamese passphrase: both runtimes must treat a
# visually identical passphrase in another normalization form as a different key.
ANDROID_EXPORT_PASSPHRASE = unicodedata.normalize("NFD", "Kiểm chéo Android → Desktop 🔐 Đồng bộ 2026")
DESKTOP_RETURN_PASSPHRASE = unicodedata.normalize("NFC", "Kiểm chéo Desktop → Android 🔁 Đồng bộ 2026")
SYNC_MEDIA_TYPE = "application/vnd.affiliate-report.sync"
ACCOUNT = "ANDROIDSMOKE"
ROUTES = (
    "/",
    "/analytics/",
    "/orders/",
    "/imports/",
    "/targets/",
    "/accounts/",
    "/settings/preferences/",
    "/settings/data/",
    "/settings/sync/",
    "/settings/update/",
    "/settings/users/",
)


def _wait(client: httpx.Client, timeout: float = 90) -> dict:
    deadline = time.monotonic() + timeout
    error = "not started"
    while time.monotonic() < deadline:
        try:
            response = client.get("/health", timeout=3)
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001 - preserve last runtime failure in CI
            error = str(exc)
            time.sleep(1)
    raise RuntimeError(f"Android loopback runtime did not become healthy: {error}")


def _assert_routes(client: httpx.Client) -> None:
    for route in ROUTES:
        response = client.get(route)
        if response.status_code != 200 or "<!DOCTYPE html" not in response.text[:200]:
            raise RuntimeError(f"Static route {route} failed: HTTP {response.status_code}")


def _seed(client: httpx.Client, fixture: Path, package: Path) -> dict:
    health = _wait(client)
    if health.get("app_version") != "2.2.0":
        raise RuntimeError(f"Unexpected Android runtime version: {health!r}")
    _assert_routes(client)
    account = client.post(
        "/api/v1/accounts",
        json={"code": ACCOUNT, "display_name": "Android Smoke", "display_order": 10},
    )
    if account.status_code not in {201, 409}:
        raise RuntimeError(f"Could not seed Android account: {account.status_code} {account.text}")
    with fixture.open("rb") as stream:
        imported = client.post(
            "/api/v1/imports",
            data={"account": ACCOUNT},
            files={"file": (fixture.name, stream, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
            timeout=120,
        )
    imported.raise_for_status()
    result = imported.json()
    if result.get("inserted", 0) + result.get("updated", 0) + result.get("unchanged", 0) < 1:
        raise RuntimeError(f"Real Excel fixture produced no accepted rows: {result!r}")
    exported = client.post("/api/v1/sync/export", json={"passphrase": PASSPHRASE}, timeout=120)
    exported.raise_for_status()
    if not exported.content.startswith(b"AFFSYNC1"):
        raise RuntimeError("Android sync export did not produce AFFSYNC1")
    package.write_bytes(exported.content)
    return {"health": health, "import": result, "package_bytes": package.stat().st_size}


def _verify_persistence(client: httpx.Client, expected_version: str) -> dict:
    health = _wait(client)
    if health.get("app_version") != expected_version:
        raise RuntimeError(f"Android runtime did not upgrade to {expected_version}: {health!r}")
    meta = client.get("/api/v1/meta").json()
    history = client.get("/api/v1/imports", params={"account": ACCOUNT, "limit": 10}).json()
    if ACCOUNT not in meta.get("accounts", []) or history.get("count", 0) < 1:
        raise RuntimeError("Android process restart did not preserve the seeded database")
    return {"health": health, "imports": history["count"]}


def _restore(client: httpx.Client, package: Path) -> dict:
    health = _wait(client)
    with package.open("rb") as stream:
        preview_response = client.post(
            "/api/v1/sync/preview",
            data={"passphrase": PASSPHRASE},
            files={"package": (package.name, stream, "application/vnd.affiliate-report.sync")},
            timeout=120,
        )
    preview_response.raise_for_status()
    preview = preview_response.json()
    resolutions = {item["key"]: "incoming" for item in preview.get("conflicts", [])}
    imported = client.post(
        "/api/v1/sync/import",
        json={
            "preview_id": preview["preview_id"],
            "confirmation": "DONG BO",
            "conflict_resolutions": resolutions,
        },
        timeout=120,
    )
    imported.raise_for_status()
    meta = client.get("/api/v1/meta").json()
    history = client.get("/api/v1/imports", params={"account": ACCOUNT, "limit": 10}).json()
    if ACCOUNT not in meta.get("accounts", []) or history.get("count", 0) < 1:
        raise RuntimeError("AFFSYNC1 restore did not recreate the imported Android data")
    return {"health": health, "preview": preview["preview_id"], "result": imported.json(), "imports": history["count"]}


def _other_normalizations(passphrase: str) -> list[str]:
    alternates = []
    for form in ("NFC", "NFD"):
        alternate = unicodedata.normalize(form, passphrase)
        if alternate != passphrase and alternate not in alternates:
            alternates.append(alternate)
    if not alternates:
        raise RuntimeError("Cross-check passphrase must have a different NFC or NFD form")
    return alternates


def _post_preview(client: httpx.Client, package: bytes, filename: str, passphrase: str) -> httpx.Response:
    return client.post(
        "/api/v1/sync/preview",
        data={"passphrase": passphrase},
        files={"package": (filename, package, SYNC_MEDIA_TYPE)},
        timeout=120,
    )


def _assert_other_normalizations_rejected(
    client: httpx.Client,
    package: bytes,
    filename: str,
    passphrase: str,
    authentication_error: str,
) -> int:
    alternates = _other_normalizations(passphrase)
    for alternate in alternates:
        response = _post_preview(client, package, filename, alternate)
        if response.status_code != 422 or response.json().get("detail") != authentication_error:
            raise RuntimeError(
                f"Android accepted {filename} with a different Unicode normalization: "
                f"HTTP {response.status_code} {response.text}"
            )
    return len(alternates)


def _preview_and_import(
    client: httpx.Client,
    package: bytes,
    filename: str,
    passphrase: str,
    confirmation: str,
) -> tuple[dict, dict]:
    response = _post_preview(client, package, filename, passphrase)
    if response.status_code != 200:
        raise RuntimeError(f"Android preview of {filename} failed: HTTP {response.status_code} {response.text}")
    preview = response.json()
    if preview.get("conflicts"):
        raise RuntimeError(f"Cross-check package {filename} must not conflict: {preview['conflicts']!r}")
    imported = client.post(
        "/api/v1/sync/import",
        json={"preview_id": preview["preview_id"], "confirmation": confirmation, "conflict_resolutions": {}},
        timeout=120,
    )
    if imported.status_code != 200:
        raise RuntimeError(f"Android import of {filename} failed: HTTP {imported.status_code} {imported.text}")
    return preview, imported.json()


def _unchanged_summary(data: dict[str, list]) -> dict[str, int]:
    return {
        "new_accounts": 0,
        "new_targets": 0,
        "new_import_batches": 0,
        "new_raw_rows": 0,
        "tombstones": len(data["tombstones"]),
    }


def _data_fingerprint(data: dict[str, list]) -> str:
    """Hash package rows independently of the order each device stores them in.

    data_sha256 hashes raw rows in local autoincrement batch order, which legitimately differs
    between two devices holding the same rows, so it only identifies data on one device.
    """
    canonical = {
        table: sorted(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for row in rows)
        for table, rows in data.items()
    }
    return hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _cross_check(client: httpx.Client, expected_version: str) -> dict:
    """Prove desktop and Android exchange AFFSYNC1 packages protected by Vietnamese passphrases.

    Desktop -> Android: every golden package frozen by the desktop runtime (cryptography 42.0.8
    and 48.0.1, NFC/NFD/mixed passphrases) must decrypt on Android, reject the other Unicode
    normalization and import the exact oracle rows. Android -> desktop: the Android export must
    decrypt and import with the real desktop SyncService; the desktop re-export must keep the
    same data_sha256 and import back into Android as a no-op.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    # Imported lazily: the signed upgrade smoke reuses this script with only httpx installed.
    from cryptography.exceptions import InvalidTag

    from affiliate_report.db import get_engine, init_db
    from affiliate_report.sync_service import CONFIRMATION_PHRASE, SyncError, SyncService, _decrypt_payload

    health = _wait(client)
    if health.get("app_version") != expected_version:
        raise RuntimeError(f"Unexpected Android runtime version: {health!r}")
    oracle = json.loads((UNICODE_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    samples = sorted(oracle["samples"], key=lambda sample: sample["filename"])
    if not samples:
        raise RuntimeError("Unicode AFFSYNC1 oracle has no golden packages")

    packages = {}
    for sample in samples:
        package = (UNICODE_FIXTURES / sample["filename"]).read_bytes()
        if hashlib.sha256(package).hexdigest() != sample["package_sha256"]:
            raise RuntimeError(f"Golden package {sample['filename']} does not match its oracle hash")
        packages[sample["filename"]] = package
    first = samples[0]
    try:
        _decrypt_payload(packages[first["filename"]], _other_normalizations(first["passphrase"])[0])
    except SyncError as exc:
        authentication_error = str(exc)
    else:
        raise RuntimeError("Desktop decrypted a golden package with a different Unicode normalization")

    accounts_before = {item["code"] for item in client.get("/api/v1/accounts").json()["items"]}
    imported_hashes = set()
    desktop_to_android = []
    for sample in samples:
        expected = sample["expected_payload"]
        manifest = expected["manifest"]
        data = expected["data"]
        package = packages[sample["filename"]]
        rejected = _assert_other_normalizations_rejected(
            client,
            package,
            sample["filename"],
            sample["passphrase"],
            authentication_error,
        )
        preview, result = _preview_and_import(
            client,
            package,
            sample["filename"],
            sample["passphrase"],
            CONFIRMATION_PHRASE,
        )
        if preview["package_id"] != manifest["package_id"] or preview["manifest"] != manifest:
            raise RuntimeError(f"Android decrypted a different manifest from {sample['filename']}")
        fresh = manifest["data_sha256"] not in imported_hashes and not {
            account["code"] for account in data["accounts"]
        } & accounts_before
        expected_summary = {
            "new_accounts": manifest["counts"]["accounts"],
            "new_targets": manifest["counts"]["targets"],
            "new_import_batches": manifest["counts"]["import_batches"],
            "new_raw_rows": manifest["counts"]["raw_rows"],
            "tombstones": manifest["counts"]["tombstones"],
        } if fresh else _unchanged_summary(data)
        if preview["summary"] != expected_summary:
            raise RuntimeError(
                f"Android preview of {sample['filename']} reported {preview['summary']!r}, expected {expected_summary!r}"
            )
        expected_counts = manifest["counts"] if fresh else {key: 0 for key in manifest["counts"]}
        if result.get("counts") != expected_counts:
            raise RuntimeError(f"Android import of {sample['filename']} applied {result.get('counts')!r}")
        imported_hashes.add(manifest["data_sha256"])
        desktop_to_android.append({
            "filename": sample["filename"],
            "cryptography": sample["producer"]["cryptography"],
            "case": sample["case"],
            "package_id": manifest["package_id"],
            "data_sha256": manifest["data_sha256"],
            "rejected_normalizations": rejected,
            "summary": preview["summary"],
        })

    accounts_after = {item["code"]: item for item in client.get("/api/v1/accounts").json()["items"]}
    for sample in samples:
        for account in sample["expected_payload"]["data"]["accounts"]:
            stored = accounts_after.get(account["code"])
            if stored is None or stored["display_name"] != account["display_name"]:
                raise RuntimeError(f"Android did not keep Unicode account {account['code']!r} byte-for-byte")

    exported = client.post("/api/v1/sync/export", json={"passphrase": ANDROID_EXPORT_PASSPHRASE}, timeout=120)
    exported.raise_for_status()
    android_package = exported.content
    if not android_package.startswith(b"AFFSYNC1"):
        raise RuntimeError("Android cross-check export did not produce AFFSYNC1")
    for alternate in _other_normalizations(ANDROID_EXPORT_PASSPHRASE):
        try:
            _decrypt_payload(android_package, alternate)
        except SyncError as exc:
            if not isinstance(exc.__cause__, InvalidTag):
                raise RuntimeError(f"Desktop rejected the Android package for the wrong reason: {exc}") from exc
        else:
            raise RuntimeError("Desktop decrypted the Android package with a different Unicode normalization")
    android_payload = _decrypt_payload(android_package, ANDROID_EXPORT_PASSPHRASE)
    android_manifest = android_payload["manifest"]
    if exported.headers.get("X-Affsync-Package-Id") != android_manifest["package_id"]:
        raise RuntimeError("Android export header does not match the encrypted package_id")
    for sample in samples:
        for table, rows in sample["expected_payload"]["data"].items():
            missing = [row for row in rows if row not in android_payload["data"][table]]
            if missing:
                raise RuntimeError(f"Android export changed {table} imported from {sample['filename']}: {missing!r}")

    with tempfile.TemporaryDirectory(prefix="affsync-cross-check-", ignore_cleanup_errors=True) as temp_dir:
        engine = get_engine(f"sqlite:///{(Path(temp_dir) / 'desktop.db').as_posix()}")
        try:
            init_db(engine)
            desktop = SyncService(engine)
            desktop_preview = desktop.preview(android_package, ANDROID_EXPORT_PASSPHRASE)
            if desktop_preview["conflicts"]:
                raise RuntimeError(f"Fresh desktop database conflicted with Android export: {desktop_preview['conflicts']!r}")
            desktop.import_preview(desktop_preview["preview_id"], CONFIRMATION_PHRASE, {})
            desktop_package, desktop_manifest = desktop.export_package(DESKTOP_RETURN_PASSPHRASE)
        finally:
            engine.dispose()
    android_fingerprint = _data_fingerprint(android_payload["data"])
    desktop_fingerprint = _data_fingerprint(_decrypt_payload(desktop_package, DESKTOP_RETURN_PASSPHRASE)["data"])
    if desktop_fingerprint != android_fingerprint:
        raise RuntimeError(
            "Desktop re-export changed Android data: "
            f"{desktop_fingerprint} != {android_fingerprint}"
        )

    returned_name = desktop_manifest["filename"]
    rejected_return = _assert_other_normalizations_rejected(
        client,
        desktop_package,
        returned_name,
        DESKTOP_RETURN_PASSPHRASE,
        authentication_error,
    )
    returned_preview, returned_result = _preview_and_import(
        client,
        desktop_package,
        returned_name,
        DESKTOP_RETURN_PASSPHRASE,
        CONFIRMATION_PHRASE,
    )
    if returned_preview["package_id"] != desktop_manifest["package_id"]:
        raise RuntimeError("Android decrypted a different desktop return package")
    if returned_preview["manifest"]["data_sha256"] != desktop_manifest["data_sha256"]:
        raise RuntimeError("Android decrypted different data from the desktop return package")
    if returned_preview["summary"] != _unchanged_summary(android_payload["data"]):
        raise RuntimeError(f"Desktop return package was not a no-op on Android: {returned_preview['summary']!r}")
    if any(returned_result.get("counts", {}).values()):
        raise RuntimeError(f"Desktop return package changed Android data: {returned_result!r}")

    final = client.post("/api/v1/sync/export", json={"passphrase": PASSPHRASE}, timeout=120)
    final.raise_for_status()
    final_manifest = _decrypt_payload(final.content, PASSPHRASE)["manifest"]
    if final_manifest["data_sha256"] != android_manifest["data_sha256"]:
        raise RuntimeError("Android data changed after importing the desktop return package")

    return {
        "health": health,
        "desktop_to_android": desktop_to_android,
        "android_to_desktop": {
            "android_package_id": android_manifest["package_id"],
            "android_source_device": android_manifest["source_device"],
            "desktop_package_id": desktop_manifest["package_id"],
            "data_sha256": android_manifest["data_sha256"],
            "data_fingerprint": android_fingerprint,
            "counts": android_manifest["counts"],
            "rejected_normalizations": rejected_return,
            "return_summary": returned_preview["summary"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("seed", "persist", "cross-check", "restore"), required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:9876")
    parser.add_argument("--fixture", type=Path, default=Path("tests/fixtures/affiliate_orders_e2e-sample.xlsx"))
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-version", default="2.2.0")
    parser.add_argument("--android-token", default=os.getenv("ANDROID_LOCAL_TOKEN", ""))
    args = parser.parse_args()
    if len(args.android_token) < 32:
        raise RuntimeError("Private Android local token is required for runtime smoke")
    with httpx.Client(
        base_url=args.base_url,
        headers={"X-Android-Local-Token": args.android_token},
        follow_redirects=True,
        timeout=30,
    ) as client:
        if args.phase == "seed":
            result = _seed(client, args.fixture, args.package)
        elif args.phase == "persist":
            result = _verify_persistence(client, args.expected_version)
        elif args.phase == "cross-check":
            result = _cross_check(client, args.expected_version)
        else:
            result = _restore(client, args.package)
    print(json.dumps({"phase": args.phase, **result}, sort_keys=True))


if __name__ == "__main__":
    main()
