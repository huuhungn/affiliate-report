import os
import re
import subprocess
import sys
from pathlib import Path

from affiliate_report.version import APP_VERSION
from scripts.sync_version import CODE, NEXT, NEXT_CODE, version_code


def test_release_bundle_verifier_cli_imports_from_repo_root_without_pythonpath():
    env = os.environ.copy()
    env["PYTHONPATH"] = ""
    result = subprocess.run(
        [sys.executable, "-m", "scripts.ci.verify_release_bundle", "--help"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Verify the exact Affiliate Report release bundle" in result.stdout


def test_full_installer_preserves_data_and_excludes_portable_release():
    launcher = Path("desktop_launcher.py").read_text(encoding="utf-8")
    installer = Path("packaging/AffiliateReport.iss").read_text(encoding="utf-8")
    build = Path("packaging/build_installer.ps1").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'data_dir = run_dir / "data"' in launcher
    assert "AppId={{E729344A-643D-4B99-98B4-455B79060530}" in installer
    assert 'Name: "{app}\\data"; Flags: uninsneveruninstall' in installer
    assert "[UninstallDelete]" not in installer
    assert ".db" not in installer
    assert "dist\\TikTokAffiliateReport.exe" not in installer + build + readme
    assert "Get-FileHash -Algorithm SHA256 $setupExe, $bootstrapFile" in build
    assert "Get-FileHash -Algorithm SHA256 $appExe, $setupExe" not in build
    assert "$staleMetadata = @($checksumFile, (Join-Path $outputDir 'stable.json'), (Join-Path $outputDir 'stable.json.sig'))" in build
    assert "Remove-Item -LiteralPath $staleMetadata" in build


def test_visible_installer_and_shortcuts_use_affiliate_report_brand():
    installer = Path("packaging/AffiliateReport.iss").read_text(encoding="utf-8")
    build = Path("packaging/build_installer.ps1").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    candidate = Path(".github/workflows/windows-installer-smoke.yml").read_text(encoding="utf-8")

    assert "OutputBaseFilename=AffiliateReportSetup-v{#MyAppVersion}" in installer
    assert "OutputBaseFilename=TikTokAffiliateReportSetup" not in installer
    assert 'UsePreviousGroup=no' in installer
    assert 'Name: "{group}\\Affiliate Report"' in installer
    assert 'Name: "{autodesktop}\\Affiliate Report"' in installer
    assert 'Type: filesandordirs; Name: "{userprograms}\\TikTok Affiliate Report"' in installer
    assert 'Type: files; Name: "{userdesktop}\\TikTok Affiliate Report.lnk"' in installer
    assert 'Type: files; Name: "{userprograms}\\Affiliate Report\\TikTok Affiliate Report.lnk"' in installer

    current_name = f"AffiliateReportSetup-v{APP_VERSION}.exe"
    legacy_current_name = f"TikTok{current_name}"
    assert current_name in readme
    assert legacy_current_name not in readme
    assert 'artifacts\\installer\\AffiliateReportSetup-v$version.exe' in release
    assert 'artifacts\\installer\\TikTokAffiliateReportSetup-v$version.exe' not in release
    assert 'artifacts\\installer\\AffiliateReportSetup-v$currentVersion.exe' in candidate
    assert 'artifacts\\installer\\TikTokAffiliateReportSetup-v$currentVersion.exe' not in candidate
    assert 'artifacts\\installer\\AffiliateReportSetup-v$AppVersion.exe' in build


def test_app_ships_as_onedir_so_first_launch_never_unpacks_to_temp():
    """Bản onefile giải nén runtime ra %TEMP% mỗi lần chạy; ngay sau khi cài, antivirus quét đống
    file vừa rơi xuống và làm hỏng bước nạp python3xx.dll. onedir bỏ hẳn bước giải nén đó."""
    batch = Path("BUILD_EXE.bat").read_text(encoding="utf-8")
    installer = Path("packaging/AffiliateReport.iss").read_text(encoding="utf-8")
    updater = Path("affiliate_report/updater.py").read_text(encoding="utf-8")

    assert "--onedir" in batch
    assert "--onefile" not in batch
    # onedir xuất ra một THƯ MỤC. Cổng riêng tư phải trỏ vào thư mục đó, không phải file .exe —
    # đổi --onedir mà quên dòng này thì build đỏ ngay ở bước cuối, đúng như đã xảy ra ở v1.3.2.
    assert '-Path "%APP_STAGE%\\TikTokAffiliateReport"' in batch
    assert '-Path "%APP_STAGE%\\TikTokAffiliateReport.exe"' not in batch
    # Installer phải chép cả thư mục, và dọn runtime cũ để không sót .dll lệch phiên bản.
    # Thư mục dàn dựng mang tên tệp chạy, mà tên đó giữ nguyên tên cũ — xem ghi chú ở
    # desktop_launcher.py: đổi nó thì bootstrap không mở lại được app sau khi cài.
    # Thư mục dàn dựng mang tên tệp chạy, mà tên đó giữ nguyên tên cũ — xem ghi chú ở
    # desktop_launcher.py: đổi nó thì bootstrap không mở lại được app sau khi cài.
    assert 'Source: "..\\build\\installer-app\\TikTokAffiliateReport\\*"' in installer
    assert "recursesubdirs" in installer
    assert 'Type: filesandordirs; Name: "{app}\\_internal"' in installer
    # Dữ liệu người dùng không bao giờ nằm trong diện dọn dẹp.
    assert '{app}\\data' not in installer.split("[InstallDelete]")[1].split("[Files]")[0]
    # Mở lần hai khi lần đầu chưa phản hồi chính là thứ sinh ra hộp thoại "Failed to load Python
    # DLL": hai tiến trình cùng giải nén tranh nhau đĩa và antivirus.
    assert "retrying launch once" not in updater


def test_v124_installer_and_release_workflow_support_verified_auto_update():
    batch = Path("BUILD_EXE.bat").read_text(encoding="utf-8")
    installer = Path("packaging/AffiliateReport.iss").read_text(encoding="utf-8")
    build = Path("packaging/build_installer.ps1").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    # Phiên bản chỉ được khai ở version.py; mọi nơi khác phải bám theo nó, kể cả README —
    # người dùng đối chiếu tên file setup trong README với file tải về.
    assert f"[string]$AppVersion = '{APP_VERSION}'" in build
    assert f'#define MyAppVersion "{APP_VERSION}"' in installer
    readme = Path("README.md").read_text(encoding="utf-8")
    assert f"AffiliateReportSetup-v{APP_VERSION}.exe" in readme
    stale = {
        line.strip()
        for line in readme.splitlines()
        if "AffiliateReportSetup-v" in line and f"v{APP_VERSION}.exe" not in line
    }
    assert not stale, f"README còn nhắc phiên bản cũ: {stale}"
    assert "actions/checkout@v7" in workflow
    assert "actions/setup-python@v7" in workflow
    assert "pnpm/action-setup@v6" in workflow
    assert "actions/setup-node@v7" in workflow
    assert "--hidden-import affiliate_report.updater" in batch
    assert "--hidden-import affiliate_report.version" in batch
    assert "--hidden-import pystray._win32" in batch
    # segno chỉ được nhập BÊN TRONG hàm ma_qr_svg, và pairing được nhập gián tiếp qua api.
    # Thiếu hai dòng này thì gói vẫn dựng xong, chỉ vỡ lúc người dùng bấm bật ghép cặp.
    assert "--hidden-import segno" in batch
    assert "--hidden-import affiliate_report.pairing" in batch
    assert "--hidden-import affiliate_report.cloud_pairing" in batch
    assert '--add-data "%CD%\\packaging\\app.ico;packaging"' in batch
    assert 'pystray==0.19.5; sys_platform == "win32"' in Path("requirements-api.txt").read_text(encoding="utf-8")
    assert "TikTokAffiliateReport.SingleInstance" in Path("desktop_launcher.py").read_text(encoding="utf-8")
    assert 'pystray.MenuItem("Thoát ứng dụng"' in Path("desktop_launcher.py").read_text(encoding="utf-8")
    assert "Flags: nowait postinstall skipifsilent" in installer
    assert 'tags:\n      - "v*.*.*"' in workflow
    assert "permissions:\n  actions: read\n  contents: read" in workflow
    assert "windows-installer:\n    needs: verify" in workflow
    assert "windows-installer:\n    needs: verify\n    runs-on: windows-latest\n" in workflow
    # Job này chạm UPDATE_SIGNING_KEY_B64 và publish feed công khai mà mọi máy người dùng
    # tin theo, nên phải DỪNG chờ duyệt thủ công trước khi chạm secret — không chạy thẳng
    # một mạch từ lúc tag được push. Environment "release" đã tạo trên GitHub với
    # required_reviewers=anhtahaylove; dòng dưới đây là thứ THỰC SỰ bật cổng đó cho job.
    # Thiếu dòng này thì GitHub tạo một environment rỗng lúc chạy — không reviewer, không
    # chặn gì — mà nhìn log lại tưởng nhầm là đã có cơ chế duyệt.
    assert "\n    environment: release\n" in workflow
    assert "\n    permissions:\n      actions: write\n      contents: write" in workflow
    assert "POSTGRES_TEST_URL" in workflow
    assert '"artifacts\\installer\\SHA256SUMS.txt"' in workflow
    assert "UPDATE_SIGNING_KEY_B64" in workflow
    # Một repo duy nhất nên không còn PAT chéo repo: mọi thao tác release và ghi feed dùng
    # token của chính workflow, và job phải tự khai quyền ghi. PAT chéo repo từng làm v2.0.12
    # và v2.0.13 chết vì 403 trên repo nguồn.
    assert "UPDATE_FEED_TOKEN" not in workflow
    assert "permissions:\n      actions: write\n      contents: write" in workflow
    assert "-m scripts.sign_update_feed" in workflow
    assert r'--bootstrap "artifacts\installer\TikTokAffiliateUpdater-v1.0.0.ps1"' in workflow
    assert r'--bootstrap-url "https://github.com/$repo/releases/download/$tag/TikTokAffiliateUpdater-v1.0.0.ps1"' in workflow
    # Một repo duy nhất từ v2.0.13: asset, feed và mã nguồn cùng chỗ. Vẫn canh để không ai
    # vô tình trỏ ngược về repo cũ.
    assert '$repo = "anhtahaylove/affiliate-report"' in workflow
    assert "tiktok-affiliate-report-updates" not in workflow
    assert "stable.json.sig" in workflow
    assert "-m scripts.ci.verify_release_bundle" in workflow
    assert "scripts\\ci\\verify_release_bundle.py" not in workflow
    assert "AffiliateReport-v$version-arm64.apk" in workflow
    assert "--android-min-sdk 24 --android-abi arm64-v8a" in workflow
    assert "gh release create $tag @assets --repo $repo --draft --latest=false" in workflow
    assert "gh release edit $tag --repo $repo --draft=false --prerelease" in workflow
    assert '$public.isDraft -or !$public.isPrerelease -or $public.tagName -ne $tag' in workflow
    assert "gh release edit $tag --repo $repo --draft=false --prerelease=false --latest" in workflow
    assert "Public draft manifest verification failed" in workflow
    assert "Private release $tag is already published" in workflow
    assert "Public release $tag is already published" in workflow
    assert "gh release delete $tag --yes" in workflow
    # Không còn xoá-rồi-tạo-lại release công khai: một repo thì bản nháp đã xác minh chính là
    # bản sẽ công bố. Vẫn canh để không ai đưa vòng churn đó trở lại.
    assert "gh release delete $tag --repo $repo --yes" not in workflow
    assert "Reusing the verified draft release as the public release." in workflow
    # Workflow chạy do push tag, nên checkout thư mục feed PHẢI nói rõ nhánh; thiếu dòng này thì
    # nó ở detached HEAD và git push chết với "You are not currently on a branch" (v2.0.15).
    assert "ref: main" in workflow
    assert "Anonymous public release assets did not become available or match the build" in workflow
    assert "Live raw feed does not match signed build artifacts" in workflow
    assert 'gh release list --repo $repo --limit 100 --json tagName,isDraft,isLatest,isPrerelease' in workflow
    assert '$env:GH_TOKEN = ""' in workflow
    assert "concurrency:\n  group: signed-public-update-release\n  cancel-in-progress: false" in workflow
    assert 'gh release download $previousLatestTag --repo $repo --pattern stable.json --pattern stable.json.sig' in workflow
    assert 'git reset --hard origin/main' in workflow
    assert 'Rollback stable feed from $tag to $previousLatestTag' in workflow
    assert 'Live raw feed rollback verification failed' in workflow
    assert 'Private release rollback verification failed' in workflow
    assert 'Public release rollback verification failed' in workflow
    assert 'gh release edit $previousLatestTag --repo $repo --latest' in workflow
    assert 'Previous public latest release was not restored' in workflow
    assert 'Rollback also failed:' in workflow
    assert workflow.index("gh release create $tag @assets --repo $repo --draft --latest=false") < workflow.index("Promote public stable feed and releases")
    promote = workflow.index("Promote public stable feed and releases")
    anonymous_publish = workflow.index("gh release edit $tag --repo $repo --draft=false", promote)
    anonymous_download = workflow.index('Invoke-WebRequest -UseBasicParsing "https://github.com/$repo/releases/download/$tag/$asset"', promote)
    feed_push = workflow.index("git push", promote)
    raw_download = workflow.index('Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/$feedRepo/main/stable.json?', promote)
    # Một repo duy nhất: bản "riêng" và bản "công khai" là cùng một release, nên gỡ nháp, gỡ cờ
    # tiền phát hành và đánh dấu mới nhất gộp thành một lệnh. Nó phải nằm SAU khi feed đã lên
    # và đã đối chiếu qua raw — thứ tự đó mới là thứ đáng canh.
    latest = workflow.index("gh release edit $tag --repo $repo --draft=false --prerelease=false --latest", promote)
    private_verify = workflow.index("Private release publish verification failed", promote)
    assert anonymous_publish < anonymous_download < feed_push < raw_download < latest < private_verify


def test_all_workflows_have_no_node20_action_versions():
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in Path(".github/workflows").glob("*.yml"))
    for old_action in (
        "actions/checkout@v4",
        "actions/setup-node@v4",
        "actions/setup-python@v5",
        "pnpm/action-setup@v4",
    ):
        assert old_action not in workflows


def test_windows_installer_smoke_is_version_parameterized():
    workflow = Path(".github/workflows/windows-installer-smoke.yml").read_text(encoding="utf-8")
    smoke = Path("scripts/ci/windows_installer_smoke.ps1").read_text(encoding="utf-8")
    combined = workflow + smoke

    for old_token in ("V120", "V111", "fresh-install-v120", "upgrade-v111-to-v120"):
        assert old_token not in combined
    assert "'1.2.0' =" not in smoke
    assert "'1.1.1' =" not in smoke

    for parameter in (
        "CurrentInstaller",
        "CurrentVersion",
        "CurrentChecksumFile",
        "PreviousInstaller",
        "PreviousVersion",
        "PreviousChecksumFile",
    ):
        assert f"[string]${parameter}" in smoke

    assert "Assert-Installer $CurrentInstaller $CurrentVersion $CurrentChecksumFile" in smoke
    assert "Assert-Installer $PreviousInstaller $PreviousVersion $PreviousChecksumFile" in smoke
    assert 'AffiliateReportSetup-v$Version.exe' in smoke
    assert "Get-Content -LiteralPath $ChecksumFile" in smoke
    assert "Get-FileHash -LiteralPath $Path -Algorithm SHA256" in smoke
    assert "'/settings/preferences'" in smoke
    assert "Assert-Routes $baseUrl -IncludePreferences" in smoke
    assert "'/settings/data'" in smoke
    assert "PreviousVersion must be lower than CurrentVersion" in smoke

    assert "workflow_dispatch:" in workflow
    assert "current_version:" in workflow
    assert f'default: "{APP_VERSION}"' in workflow
    assert "previous_version:" in workflow
    assert 'default: "2.0.29"' in workflow
    assert "fresh-install:" in workflow
    assert "upgrade-install:" in workflow
    assert "if: github.event_name == 'workflow_dispatch'" in workflow
    assert "AffiliateReportSetup-v$currentVersion.exe" in workflow
    # Bản trước được tải qua Get-PreviousInstaller vì asset có thể còn mang tên trước khi đổi
    # thương hiệu; tên vẫn dựng từ biến phiên bản, không được ghim số cứng.
    assert "AffiliateReportSetup-v$Version.exe" in workflow
    assert "TikTokAffiliateReportSetup-v$Version.exe" in workflow
    assert "$previousVersion" in workflow
    assert "SHA256SUMS-current.txt" in workflow
    assert "SHA256SUMS-previous.txt" in workflow
    assert "-CurrentVersion $currentVersion" in workflow
    assert "-PreviousVersion $previousVersion" in workflow
    assert "Invalid current_version" in workflow
    assert "Invalid previous_version" in workflow
    assert "previous_version must be lower than current_version" in workflow
    assert "CURRENT_VERSION: ${{ inputs.current_version }}" in workflow
    assert "PREVIOUS_VERSION: ${{ inputs.previous_version }}" in workflow
    assert '$currentVersion = $env:CURRENT_VERSION' in workflow
    assert '$previousVersion = $env:PREVIOUS_VERSION' in workflow
    assert '"${{ inputs.current_version }}"' not in workflow
    assert '"${{ inputs.previous_version }}"' not in workflow
    assert "python -m pip install pytest" in workflow
    assert "python -m pip install -r requirements.txt" not in workflow
    assert "Smoke account was not preserved during upgrade." in smoke
    assert "daily_target_commission" in smoke
    assert "@{ target_commission = $Value }" not in smoke
    assert "v$PreviousVersion legacy account is missing" not in smoke
    assert smoke.count("-TimeoutSec 15") >= 4
    assert 'Write-SmokePhase "Beginning upgrade smoke v$PreviousVersion -> v$CurrentVersion"' in smoke
    assert "timeout-minutes: 8" in workflow


def test_android_signer_fingerprint_parser_is_build_tools_tolerant():
    builder = Path("scripts/ci/build_android_candidate.ps1").read_text(encoding="utf-8")

    assert "SHA[^0-9]*256" in builder
    assert "[^0-9a-fA-F]" in builder
    assert "(?:[0-9a-f]{2}(?:[:\\s-]?)){31}[0-9a-f]{2}" in builder
    assert "certificate SHA-256 fields" in builder
    assert "Signer #1 certificate SHA-256 digest" not in builder


def test_v207_release_candidate_and_public_updater_ui_workflows_are_fail_closed():
    candidate = Path(".github/workflows/windows-installer-smoke.yml").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    updater_ui = Path(".github/workflows/windows-updater-ui-smoke.yml").read_text(encoding="utf-8")
    updater_smoke = Path("scripts/ci/windows_updater_ui_smoke.ps1").read_text(encoding="utf-8")
    browser_smoke = Path("web/scripts/windows-updater-ui-smoke.mjs").read_text(encoding="utf-8")

    assert "pull_request:" in candidate
    assert "push:" in candidate
    assert "branches: [main]" in candidate
    for runtime_path in (
        '"affiliate_report/**"',
        '"web/**"',
        '"packaging/**"',
        '"scripts/**"',
        '"requirements*.txt"',
        '"web/pnpm-lock.yaml"',
        '"BUILD_EXE.bat"',
        '"CHANGELOG.md"',
    ):
        assert runtime_path in candidate
    assert "github.event.pull_request.head.repo.full_name" in candidate
    assert "Fork pull requests cannot run installer candidates" in candidate
    assert "pull_request_target" not in candidate
    assert "workflow_run" not in candidate
    assert "UPDATE_SIGNING_KEY_B64" not in candidate
    assert "UPDATE_FEED_TOKEN" not in candidate
    assert "EXPECTED_SHA: ${{ github.sha }}" in candidate
    assert "$actualSha = git rev-parse HEAD" in candidate
    assert "Candidate checkout does not match PR merge SHA" in candidate
    assert "actions/upload-artifact@v7" in candidate
    assert "actions/download-artifact@v8" in candidate
    assert "retention-days: 3" in candidate
    assert "candidate-release-gate:" in candidate
    assert "github.event_name == 'push'" in candidate
    assert candidate.count("if: always() && needs.candidate-build.result == 'success'") == 3
    assert "scripts\\ci\\windows_installer_smoke.ps1 -Mode Fresh" in candidate
    assert "scripts\\ci\\windows_installer_smoke.ps1 -Mode Upgrade" in candidate
    assert '"- Upgrade $previousVersion -> ${currentVersion}: PASS"' in candidate
    assert "$currentVersion: PASS" not in candidate
    assert "Run exact-head Windows updater helper runtime tests" in candidate
    assert "tests/test_updater.py tests/test_updater_diagnostics.py" in candidate
    assert "AffiliateReportSetup-v*.exe" in candidate
    assert "TikTokAffiliateUpdater-v1.0.0.ps1" in candidate
    assert "SHA256SUMS.txt" in candidate
    assert "stable.json" not in candidate
    assert ".db" not in candidate

    assert "actions: write" in release
    assert "Require successful installer smoke for this exact main commit" in release
    assert "head_sha=$RELEASE_SHA&event=push&status=completed" in release
    assert 'select(.head_branch == "main" and .conclusion == "success")' in release
    assert "has no successful post-merge Windows installer smoke on main" in release
    assert "gh workflow run windows-updater-ui-smoke.yml" in release
    assert "gh workflow run windows-updater-ui-smoke.yml --ref $tag" in release
    assert "gh workflow run windows-updater-ui-smoke.yml --ref main" not in release
    assert "-f release_nonce=$releaseNonce" in release
    assert '$_.displayTitle -eq $smokeTitle -and $_.headSha -eq $releaseSha' in release
    assert "Public updater UI gate did not pass 5/5" in release
    assert release.index("gh workflow run windows-updater-ui-smoke.yml") < release.index("gh release edit $tag --repo $repo --draft=false --prerelease=false --latest")
    assert "SHA256SUMS.txt" in release
    assert "AffiliateReport-v$version-arm64.apk" in release
    assert "Candidate SHA256SUMS must contain exactly the installer and updater bootstrap" in candidate
    assert "candidate-bootstrap-runtime:" in candidate
    assert "-Mode Bootstrap" in candidate
    assert "Packaged bootstrap runtime: PASS" in candidate
    assert 'previous_version: ["2.0.25", "2.0.29"]' in candidate
    assert '$previousVersion = "${{ matrix.previous_version }}"' in candidate

    assert "workflow_dispatch:" in updater_ui
    assert "pull_request:" not in updater_ui
    assert "permissions:\n  contents: read" in updater_ui
    assert "smoke_run_count:" in updater_ui
    assert "fromJSON(inputs.smoke_run_count == '1' && '[1]' || '[1,2,3,4,5]')" in updater_ui
    assert "[${{ inputs.release_nonce || 'manual' }}]" in updater_ui
    assert "Release-gated runs require a unique 32-character hexadecimal nonce" in updater_ui
    assert "ref: ${{ inputs.release_sha || github.sha }}" in updater_ui
    assert "Workflow source SHA" in updater_ui
    # release.yml từng chép cứng previous_version=2.0.6 và trôi lại đó khi lane smoke đã chuyển
    # sang 2.0.7, nên smoke sau phát hành đi qua helper legacy thay vì bootstrap độc lập — không
    # có gì canh nên không ai thấy. Giờ nó phải đọc từ đúng một nguồn.
    release_workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "-f previous_version=$previousVersion" in release_workflow
    assert "-f smoke_run_count=5" in release_workflow
    assert "$legacyVersion" not in release_workflow
    assert "Legacy public updater UI gate" not in release_workflow
    assert not re.search(r"-f previous_version=\d+\.\d+\.\d+", release_workflow)

    # Cặp canary: v2.0.7 tự cài v2.0.9 bằng chính bootstrap độc lập đã ký của nó.
    assert f'default: "{APP_VERSION}"' in updater_ui
    assert 'default: "2.0.29"' in updater_ui
    assert "UPDATE_SIGNING_KEY_B64" not in updater_ui
    assert "UPDATE_FEED_TOKEN" not in updater_ui
    assert "actions/upload-artifact@v7" in updater_ui
    assert "pnpm --dir web exec playwright install chromium" in updater_ui
    assert "windows_updater_ui_smoke.ps1" in updater_ui

    assert "This destructive updater UI smoke only runs on an ephemeral GitHub Actions runner." in updater_smoke
    assert "Assert-Installer $CurrentInstaller $CurrentVersion $CurrentChecksumFile" in updater_smoke
    assert "Install-App $PreviousInstaller" in updater_smoke
    assert "Install-App $CurrentInstaller" not in updater_smoke
    assert "UPDATER_SMOKE" in updater_smoke
    assert "pnpm --dir web exec node scripts/windows-updater-ui-smoke.mjs" in updater_smoke
    assert "Export-ScrubbedUpdaterDiagnostics" in updater_smoke
    assert "update-status.json" in updater_smoke
    assert "updater-bootstrap.log" in updater_smoke
    assert "installer.log" in updater_smoke
    assert "[install dir]" in updater_smoke
    assert "[workspace]" in updater_smoke
    assert "[user profile]" in updater_smoke

    assert 'getByRole("button", { name: "Kiểm tra lại" })' in browser_smoke
    assert 'getByRole("button", { name: `Cài bản ${currentVersion}` })' in browser_smoke
    assert 'getByRole("button", { name: "Cài bản cập nhật" })' in browser_smoke
    assert 'phase !== "installed"' in browser_smoke
    assert "observeUpdaterTransition" in browser_smoke
    assert 'progress.phase === "failed"' in browser_smoke
    assert "Updater never produced an observable application disconnect." in browser_smoke
    assert "disconnect_observed: true" in browser_smoke
    assert "disconnected_at" in browser_smoke
    assert "recovered_at" in browser_smoke
    assert "UPDATER_SMOKE" in browser_smoke
    assert "screenshot" in browser_smoke


def test_android_candidate_is_signed_once_and_promoted_by_exact_sha():
    android = Path(".github/workflows/android-candidate.yml").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    gradle = Path("android/native/app/build.gradle").read_text(encoding="utf-8")
    package = Path("android/package.json").read_text(encoding="utf-8")

    assert android.index("Build web bundle and x86_64 CI APK") < android.index(
        "Verify generated Android scaffold contract"
    )
    assert 'script: bash scripts/ci/android_emulator_smoke.sh "${{ matrix.api-level }}"' in android
    assert "script: bash scripts/ci/android_signed_upgrade_smoke.sh" in android
    assert android.count("Enable KVM group permissions") == 2
    assert android.count("udevadm trigger --name-match=kvm") == 2
    for script in (
        Path("scripts/ci/android_emulator_smoke.sh"),
        Path("scripts/ci/android_signed_upgrade_smoke.sh"),
    ):
        text = script.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
        assert "trap dump_diagnostics ERR" in text
        assert "cat cache/startup-error.txt" in text
        assert "^[A-Za-z0-9_-]{43}$" in text
        assert 'test "${#raw}" -eq 43' in text
    upgrade_smoke = Path("scripts/ci/android_signed_upgrade_smoke.sh").read_text(encoding="utf-8")
    emulator_smoke = Path("scripts/ci/android_emulator_smoke.sh").read_text(encoding="utf-8")
    runtime_smoke = Path("scripts/ci/android_runtime_smoke.py").read_text(encoding="utf-8")

    # Cross-check runs after restore and drives the real desktop SyncService against the
    # emulator, so the job must install the desktop runtime stack, not httpx alone.
    restore_phase = 'android_runtime_smoke.py --phase restore --package "$package"'
    cross_check_phase = 'android_runtime_smoke.py --phase cross-check --package "$package"'
    assert emulator_smoke.index(restore_phase) < emulator_smoke.index(cross_check_phase)
    assert "--phase cross-check" not in upgrade_smoke
    emulator_job = android[android.index("  emulator-smoke:"):android.index("  signed-candidate:")]
    assert "pip install --disable-pip-version-check -r requirements-api.txt" in emulator_job
    assert 'choices=("seed", "persist", "cross-check", "restore")' in runtime_smoke
    assert 'UNICODE_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "affsync_unicode"' in runtime_smoke
    assert 'unicodedata.normalize("NFD"' in runtime_smoke
    assert 'unicodedata.normalize("NFC"' in runtime_smoke

    assert "push:\n    branches: [main]" in android
    assert "pull_request:\n    branches: [main]" in android
    assert "github.event_name == 'pull_request' && github.ref || github.sha" in android
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in android
    assert "ANDROID_KEYSTORE_B64" in android
    assert "GITHUB_ENV" not in android
    assert "Remove-Item -LiteralPath $keystore -Force" in android
    assert "Remove-Item Env:ANDROID_KEYSTORE_PATH" in android
    assert "if: github.event_name == 'push'" in android
    assert "arm64Release" in android and "ciRelease" in android and "ciDebug" in android
    assert "verify --verbose --print-certs $apk" in android
    assert "vn\\.io\\.huuhungn\\.affiliatereport" in android
    assert f"versionCode='{CODE}'" in android
    # Các gate Android kiểm phiên bản bằng regex có escape dấu chấm. Bump bằng cách thay chuỗi
    # "2.1.1" không chạm tới "2\.1\.1", nên workflow vẫn kiểm số cũ trong khi APK đã mang số mới
    # — hỏng ở phút thứ 20 của CI thay vì ngay tại đây. Ràng chúng vào APP_VERSION.
    escaped_version = APP_VERSION.replace(".", "\\.")
    assert f'APP_VERSION = "{escaped_version}"' in android
    assert f'versionName "{escaped_version}"' in android
    assert f"versionName='{escaped_version}'" in android
    assert "affiliate-report-android-${{ github.sha }}" in android
    assert "actions/upload-artifact@v7" in android
    assert "signed-update-smoke:" in android
    assert "needs: signed-candidate" in android
    assert "release-emulator-gate:" in android
    assert "name: Android release gate" in android
    assert "needs: [emulator-smoke, signed-update-smoke]" in android
    assert "Fresh/runtime smoke: API 24 and API 36 passed" in android
    assert f"AffiliateReport-v{APP_VERSION}-x86_64-release.apk" in android
    assert f"AffiliateReport-v{NEXT}-x86_64-release.apk" in android
    assert 'adb install -r "$target"' in upgrade_smoke
    assert f"--expected-version {NEXT}" in upgrade_smoke
    assert f"versionCode={NEXT_CODE}" in upgrade_smoke
    assert "storeType 'PKCS12'" in gradle
    assert f'"version": "{APP_VERSION}"' in package

    assert "Require successful signed Android candidate for this exact main commit" in release
    assert "android-candidate.yml/runs?head_sha=$RELEASE_SHA&event=push&status=completed" in release
    assert '/actions/runs/$run_id/jobs?filter=latest&per_page=100' in release
    assert '.name == "Android release gate" and .conclusion == "success"' in release
    assert "did not complete the API 24/36 emulator release gate" in release
    assert '$artifactName = "affiliate-report-android-$env:RELEASE_SHA"' in release
    assert "gh run download $run[0].id --name $artifactName" in release
    assert "AffiliateReport-v$version-arm64.apk" in release
    assert "--android-apk" in release
    assert "--android-url" in release
    assert "-m scripts.ci.verify_release_bundle" in release
    assert '$_.isLatest -and !$_.isDraft -and !$_.isPrerelease' in release
    assert "Sort-Object publishedAt -Descending | Select-Object -First 1" not in release


def test_local_android_emulator_scripts_cover_supported_api_levels_and_cleanup():
    setup = Path("scripts/dev/setup_android_emulators.ps1").read_text(encoding="utf-8-sig")
    smoke = Path("scripts/dev/smoke_android_emulator.ps1").read_text(encoding="utf-8-sig")

    for contract in (
        '"build-tools;36.0.0"',
        '"system-images;android-24;google_apis;x86_64"',
        '"system-images;android-36;google_apis;x86_64"',
        'Name = "AffiliateReport_API24"',
        'Name = "AffiliateReport_API36"',
        '"pixel_2"',
        '"installed and usable"',
        "[string]$SdkRoot",
        "[switch]$PersistUserEnvironment",
    ):
        assert contract in setup

    for contract in (
        "[ValidateSet(24, 36)]",
        '"-wipe-data"',
        'Invoke-RuntimeSmoke -Phase "seed"',
        'Invoke-RuntimeSmoke -Phase "persist"',
        'Invoke-RuntimeSmoke -Phase "restore"',
        '$crossChecked = Invoke-RuntimeSmoke -Phase "cross-check"',
        "cross_checked = $crossChecked",
        'Invoke-Adb -Arguments @("-s", $serial, "emu", "kill")',
        'schema = "affiliate-report.android-local-smoke.v1"',
        'AffiliateReport-v$appVersion-x86_64-debug.apk',
        "apk_sha256 = $apkSha256",
        "--expected-version $appVersion",
        '"tcp:0", "tcp:8765"',
        '"Local\\AffiliateReport.AndroidEmulatorSmoke"',
        "Stop-Process -Id $emulatorProcess.Id -Force",
        '"-SkipBuild requires -ApkPath so the reused APK is explicit."',
        '& $setupScript -SdkRoot $sdkRoot',
        'function Get-ConnectedSerialState',
        '$devices = Invoke-Adb -Arguments @("devices")',
        '$escapedSerial = [regex]::Escape($serial)',
        'if ($existingState)',
        '$serialOwned = $true',
        'if ($serialOwned -and -not $KeepEmulator)',
        'if ($runningAvdName -cne $avdName)',
    ):
        assert contract in smoke

    assert 'if ($existingState.Trim() -eq "device")' not in smoke
    avd_pattern = re.search(r"\$avdResponsePattern = '([^']+)'", smoke)
    assert avd_pattern is not None
    parsed_avd = re.fullmatch(avd_pattern.group(1), "AffiliateReport_API36\r\nOK\r\n")
    assert parsed_avd is not None
    assert parsed_avd.group(1) == "AffiliateReport_API36"
    windows_adb_avd = re.fullmatch(
        avd_pattern.group(1), "AffiliateReport_API36\r\n\r\nOK\r\n"
    )
    assert windows_adb_avd is not None
    assert windows_adb_avd.group(1) == "AffiliateReport_API36"
    assert re.fullmatch(avd_pattern.group(1), "AffiliateReport_API36\r\nKO\r\n") is None


def _png_size(path: Path) -> tuple[int, int]:
    """Đọc kích thước PNG từ khối IHDR, không cần Pillow.

    Pillow chỉ có trên Windows (đi kèm pystray, mà requirements-api.txt ghim theo
    sys_platform == "win32"), nên test hợp đồng không được phụ thuộc vào nó — nếu không
    nó xanh ở máy Windows và đỏ trên CI Linux.
    """
    raw = path.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", f"{path}: không phải PNG"
    return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")


def _ico_sizes(path: Path) -> list[tuple[int, int]]:
    """Đọc danh sách độ phân giải trong .ico từ bảng thư mục ảnh."""
    raw = path.read_bytes()
    assert raw[:4] == b"\x00\x00\x01\x00", f"{path}: không phải ICO"
    count = int.from_bytes(raw[4:6], "little")
    sizes = []
    for index in range(count):
        entry = 6 + index * 16
        # 0 trong trường bề rộng/cao nghĩa là 256 — ICO chỉ dành một byte cho mỗi chiều.
        sizes.append((raw[entry] or 256, raw[entry + 1] or 256))
    return sorted(sizes)


def test_app_icons_are_generated_from_the_single_svg_source():
    from scripts.build_icons import ANDROID_RES, DENSITIES, ICO_SIZES, MASTER, WEB_ICONS

    assert MASTER.is_file()
    icon = Path("packaging/app.ico")
    assert icon.is_file()
    # Windows chọn cỡ theo ngữ cảnh: thiếu 16/32 là taskbar phải tự thu nhỏ bản lớn và bị răng cưa.
    assert _ico_sizes(icon) == sorted((size, size) for size in ICO_SIZES)

    for size, path in WEB_ICONS.items():
        assert path.is_file(), path
        assert _png_size(path) == (size, size), path

    for density, scale in DENSITIES.items():
        folder = ANDROID_RES / f"mipmap-{density}"
        for name, base in (("ic_launcher.png", 48), ("ic_launcher_round.png", 48), ("ic_launcher_foreground.png", 108)):
            path = folder / name
            assert path.is_file(), path
            assert _png_size(path) == (round(base * scale), round(base * scale)), path


def test_android_adaptive_background_matches_the_icon_artwork():
    # Khe quanh đồng xu trong icon-foreground.svg được tô đúng màu nền adaptive để đọc thành
    # khoảng hở. Lệch hai giá trị này là khe biến thành một vòng tròn màu lạ trên launcher.
    from scripts.build_icons import ICON_DIR

    background = Path("android/native/app/src/main/res/values/ic_launcher_background.xml").read_text(encoding="utf-8")
    colour = re.search(r'name="ic_launcher_background">(#[0-9A-Fa-f]{6})<', background)
    assert colour, "không đọc được màu nền adaptive"
    master = (ICON_DIR / "icon.svg").read_text(encoding="utf-8")
    foreground = (ICON_DIR / "icon-foreground.svg").read_text(encoding="utf-8")
    assert colour.group(1).lower() in master.lower()
    assert colour.group(1).lower() in foreground.lower()


def test_powershell_scripts_with_non_ascii_keep_a_utf8_bom():
    # Windows PowerShell 5.1 đọc .ps1 không BOM theo bảng mã ANSI, nên chuỗi tiếng Việt
    # bị vỡ và script chết với "string is missing the terminator" — khó lần ra nguyên nhân.
    # BUILD_EXE.bat gọi assert_no_embedded_database.ps1 bằng powershell.exe (5.1) ngay cả
    # trong CI, nên đây là bẫy thật chứ không phải giả định.
    offenders = []
    for script in sorted(Path("packaging").rglob("*.ps1")) + sorted(Path("scripts").rglob("*.ps1")):
        raw = script.read_bytes()
        if raw.decode("utf-8", errors="replace").isascii():
            continue
        if not raw.startswith(b"\xef\xbb\xbf"):
            offenders.append(str(script))
    assert not offenders, f"thiếu UTF-8 BOM, sẽ vỡ dưới PowerShell 5.1: {offenders}"


def test_android_version_code_formula_is_pinned():
    # Ghim công thức bằng số literal độc lập. Phần còn lại của test hợp đồng suy ra
    # versionCode từ scripts.sync_version, nên nếu công thức trôi thì mọi assertion
    # kia trôi theo mà vẫn xanh — đúng cái bẫy đã xảy ra với regex escape dấu chấm.
    assert version_code((2, 1, 2)) == 2001002
    assert version_code((2, 0, 29)) == 2000029
    assert version_code((10, 0, 0)) == 10000000
    # versionCode của Android phải tăng đơn điệu theo thứ tự phiên bản.
    assert version_code((2, 1, 3)) > version_code((2, 1, 2)) > version_code((2, 0, 29))


def test_version_pins_stay_in_sync_with_app_version():
    # Nguồn sự thật là affiliate_report/version.py; mọi chỗ khác do
    # scripts.sync_version ghi lại. Lệch phải hỏng ở đây, không phải ở phút thứ 20 của CI.
    result = subprocess.run(
        [sys.executable, "-m", "scripts.sync_version", "--check"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"


def test_settings_data_page_is_not_ignored():
    ignored = Path(".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/data/" in ignored
    assert "data/" not in ignored
    assert Path("web/src/app/settings/data/page.tsx").is_file()
