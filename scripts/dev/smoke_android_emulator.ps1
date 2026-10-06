[CmdletBinding()]
param(
    [ValidateSet(24, 36)]
    [int]$ApiLevel = 36,
    [switch]$SkipBuild,
    [string]$ApkPath,
    [switch]$KeepEmulator,
    [switch]$PreserveAvdData,
    [ValidateRange(120, 900)]
    [int]$BootTimeoutSeconds = 360
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$sdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }
$emulator = Join-Path $sdkRoot "emulator\emulator.exe"
$adb = Join-Path $sdkRoot "platform-tools\adb.exe"
$setupScript = Join-Path $PSScriptRoot "setup_android_emulators.ps1"
$buildScript = Join-Path $repo "scripts\ci\build_android_candidate.ps1"
$runtimeSmoke = Join-Path $repo "scripts\ci\android_runtime_smoke.py"
$fixture = Join-Path $repo "tests\fixtures\affiliate_orders_e2e-sample.xlsx"
$python = Join-Path $repo ".venv\Scripts\python.exe"
$avdName = "AffiliateReport_API$ApiLevel"
$emulatorPort = if ($ApiLevel -eq 24) { 5560 } else { 5562 }
$serial = "emulator-$emulatorPort"
$forwardPort = $null
$packageName = "vn.io.huuhungn.affiliatereport"
$activity = "$packageName/.MainActivity"
$startedAt = [System.DateTimeOffset]::UtcNow
$runId = $startedAt.ToString("yyyyMMdd-HHmmss") + "-api$ApiLevel-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$evidenceDir = Join-Path $repo "artifacts\android\local-smoke\$runId"
$syncPackage = Join-Path $evidenceDir "AffiliateReport-$runId.affsync"
$summaryPath = Join-Path $evidenceDir "summary.json"
$emulatorProcess = $null
$serialOwned = $false
$forwardCreated = $false
$smokePassed = $false
$mutexAcquired = $false
$smokeMutex = [System.Threading.Mutex]::new($false, "Local\AffiliateReport.AndroidEmulatorSmoke")

function Invoke-Adb {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $rawOutput = @(& $adb @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $output = ($rawOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "adb failed with exit code ${exitCode}: $output"
    }
    return $output
}

function Wait-ForBoot {
    $deadline = [System.DateTimeOffset]::UtcNow.AddSeconds($BootTimeoutSeconds)
    while ([System.DateTimeOffset]::UtcNow -lt $deadline) {
        if ($emulatorProcess -and $emulatorProcess.HasExited) {
            throw "Android Emulator exited before boot completed with code $($emulatorProcess.ExitCode)."
        }
        $state = Invoke-Adb -Arguments @("-s", $serial, "get-state") -AllowFailure
        if ($state.Trim() -eq "device") {
            $completed = Invoke-Adb -Arguments @("-s", $serial, "shell", "getprop", "sys.boot_completed") -AllowFailure
            if ($completed.Trim() -eq "1") {
                return
            }
        }
        Start-Sleep -Seconds 2
    }
    throw "Android Emulator did not finish booting within $BootTimeoutSeconds seconds."
}

function Get-ConnectedSerialState {
    $devices = Invoke-Adb -Arguments @("devices")
    $escapedSerial = [regex]::Escape($serial)
    $match = [regex]::Match($devices, "(?m)^${escapedSerial}\s+(\S+)(?:\s|$)")
    if ($match.Success) {
        return $match.Groups[1].Value
    }
    return $null
}

function Start-App {
    $output = Invoke-Adb -Arguments @("-s", $serial, "shell", "am", "start", "-W", "-n", $activity)
    Write-Output $output
}

function Read-AndroidToken {
    $deadline = [System.DateTimeOffset]::UtcNow.AddSeconds(90)
    while ([System.DateTimeOffset]::UtcNow -lt $deadline) {
        $raw = Invoke-Adb -Arguments @("-s", $serial, "exec-out", "run-as", $packageName, "cat", "files/android-local-token") -AllowFailure
        $token = $raw.Trim()
        if ($token -match "^[A-Za-z0-9_-]{43}$") {
            return $token
        }
        Start-Sleep -Seconds 2
    }
    throw "Android private local token was not created within 90 seconds."
}

function Invoke-RuntimeSmoke {
    param([Parameter(Mandatory = $true)][ValidateSet("seed", "persist", "restore", "cross-check")][string]$Phase)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $rawOutput = @(
            & $python $runtimeSmoke `
                --phase $Phase `
                --base-url "http://127.0.0.1:$forwardPort" `
                --fixture $fixture `
                --package $syncPackage `
                --expected-version $appVersion 2>&1
        )
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $output = ($rawOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "Android runtime smoke phase '$Phase' failed with exit code ${exitCode}: $output"
    }
    Write-Host $output
    return ($output | ConvertFrom-Json)
}

function Write-Diagnostics {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    $startupError = Invoke-Adb -Arguments @("-s", $serial, "exec-out", "run-as", $packageName, "cat", "cache/startup-error.txt") -AllowFailure
    [System.IO.File]::WriteAllText((Join-Path $evidenceDir "startup-error.txt"), $startupError, [System.Text.UTF8Encoding]::new($false))
    $logcat = Invoke-Adb -Arguments @("-s", $serial, "logcat", "-d", "-t", "1000", "AffiliateReport:E", "AndroidRuntime:E", "python.stderr:V", "chaquopy:V", "*:S") -AllowFailure
    [System.IO.File]::WriteAllText((Join-Path $evidenceDir "logcat.txt"), $logcat, [System.Text.UTF8Encoding]::new($false))
}

try {
    try {
        $mutexAcquired = $smokeMutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        $mutexAcquired = $true
    }
    if (-not $mutexAcquired) {
        throw "Another Affiliate Report Android emulator smoke is already running."
    }

    $env:ANDROID_HOME = $sdkRoot
    $env:ANDROID_SDK_ROOT = $sdkRoot
    $env:Path = (Join-Path $sdkRoot "platform-tools") + ";" + (Join-Path $sdkRoot "emulator") + ";" + $env:Path

    if ((-not (Test-Path -LiteralPath $emulator -PathType Leaf)) -or (-not (Test-Path -LiteralPath $adb -PathType Leaf))) {
        & $setupScript -SdkRoot $sdkRoot
        $emulator = Join-Path $sdkRoot "emulator\emulator.exe"
        $adb = Join-Path $sdkRoot "platform-tools\adb.exe"
    }
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw "Project Python environment is missing: $python"
    }
    $versionSource = Get-Content -LiteralPath (Join-Path $repo "affiliate_report\version.py") -Raw
    $versionMatch = [regex]::Match($versionSource, 'APP_VERSION\s*=\s*"(\d+\.\d+\.\d+)"')
    if (-not $versionMatch.Success) {
        throw "Could not resolve APP_VERSION from affiliate_report/version.py."
    }
    $appVersion = $versionMatch.Groups[1].Value
    if ($SkipBuild -and -not $ApkPath) {
        throw "-SkipBuild requires -ApkPath so the reused APK is explicit."
    }
    if (-not $SkipBuild -and $ApkPath) {
        throw "-ApkPath can only be used together with -SkipBuild."
    }

    $availableAvds = @(& $emulator -list-avds)
    if ($availableAvds -notcontains $avdName) {
        & $setupScript -SdkRoot $sdkRoot
        $availableAvds = @(& $emulator -list-avds)
    }
    if ($availableAvds -notcontains $avdName) {
        throw "Required AVD is missing: $avdName"
    }

    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    $existingState = Get-ConnectedSerialState
    if ($existingState) {
        throw "Emulator serial $serial is already present with state '$existingState'. Stop it before starting an isolated smoke."
    }

    $emulatorArguments = @(
        "-avd", $avdName,
        "-port", $emulatorPort,
        "-no-window",
        "-gpu", "swiftshader_indirect",
        "-noaudio",
        "-no-boot-anim",
        "-camera-back", "none",
        "-no-snapshot",
        "-netdelay", "none",
        "-netspeed", "full"
    )
    if (-not $PreserveAvdData) {
        $emulatorArguments += "-wipe-data"
    }

    Write-Output "[INFO] Starting $avdName as $serial."
    $emulatorProcess = Start-Process -FilePath $emulator -ArgumentList $emulatorArguments -PassThru -WindowStyle Hidden
    Wait-ForBoot
    $runningAvd = Invoke-Adb -Arguments @("-s", $serial, "emu", "avd", "name")
    $avdResponsePattern = '^([^\r\n]+)(?:\r?\n)+OK(?:\r?\n)*$'
    $avdResponse = [regex]::Match($runningAvd, $avdResponsePattern)
    if (-not $avdResponse.Success) {
        throw "Emulator serial $serial returned an invalid AVD identity response."
    }
    $runningAvdName = $avdResponse.Groups[1].Value.Trim()
    if ($runningAvdName -cne $avdName) {
        throw "Emulator serial $serial booted unexpected AVD '$runningAvdName' instead of '$avdName'."
    }
    $serialOwned = $true
    Invoke-Adb -Arguments @("-s", $serial, "shell", "settings", "put", "global", "window_animation_scale", "0") | Out-Null
    Invoke-Adb -Arguments @("-s", $serial, "shell", "settings", "put", "global", "transition_animation_scale", "0") | Out-Null
    Invoke-Adb -Arguments @("-s", $serial, "shell", "settings", "put", "global", "animator_duration_scale", "0") | Out-Null

    if (-not $SkipBuild) {
        Write-Output "[INFO] Building the x86_64 CI APK."
        & $buildScript -Variant ciDebug
        if ($LASTEXITCODE -ne 0) {
            throw "Android CI APK build failed with exit code $LASTEXITCODE."
        }
        $apk = Join-Path $repo "artifacts\android\AffiliateReport-v$appVersion-x86_64-debug.apk"
    } else {
        $apk = (Resolve-Path -LiteralPath $ApkPath).Path
    }

    if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
        throw "The exact APP_VERSION x86_64 debug APK was not found: $apk"
    }
    $expectedApkName = "AffiliateReport-v$appVersion-x86_64-debug.apk"
    if ([System.IO.Path]::GetFileName($apk) -cne $expectedApkName) {
        throw "The APK name must match current APP_VERSION exactly: $expectedApkName"
    }
    $apkSize = (Get-Item -LiteralPath $apk).Length
    $apkSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $apk).Hash.ToLowerInvariant()
    Write-Output "[INFO] Installing $apk."
    Invoke-Adb -Arguments @("-s", $serial, "install", "-r", $apk) | Out-Host
    Start-App
    $allocatedPort = (Invoke-Adb -Arguments @("-s", $serial, "forward", "tcp:0", "tcp:8765")).Trim()
    if ($allocatedPort -notmatch '^\d+$') {
        throw "adb did not allocate a valid host port: $allocatedPort"
    }
    $forwardPort = [int]$allocatedPort
    $forwardCreated = $true

    $env:ANDROID_LOCAL_TOKEN = Read-AndroidToken
    $seed = Invoke-RuntimeSmoke -Phase "seed"

    Invoke-Adb -Arguments @("-s", $serial, "shell", "settings", "put", "system", "accelerometer_rotation", "0") | Out-Null
    Invoke-Adb -Arguments @("-s", $serial, "shell", "settings", "put", "system", "user_rotation", "1") | Out-Null
    Start-Sleep -Seconds 2
    $rotated = Invoke-RuntimeSmoke -Phase "persist"

    Invoke-Adb -Arguments @("-s", $serial, "shell", "am", "force-stop", $packageName) | Out-Null
    Start-App
    $restarted = Invoke-RuntimeSmoke -Phase "persist"

    Invoke-Adb -Arguments @("-s", $serial, "shell", "pm", "clear", $packageName) | Out-Host
    Start-App
    $env:ANDROID_LOCAL_TOKEN = Read-AndroidToken
    $restored = Invoke-RuntimeSmoke -Phase "restore"
    $crossChecked = Invoke-RuntimeSmoke -Phase "cross-check"

    $summary = [ordered]@{
        schema = "affiliate-report.android-local-smoke.v1"
        result = "passed"
        api_level = $ApiLevel
        avd = $avdName
        serial = $serial
        apk = $apk
        apk_version = $appVersion
        apk_size = $apkSize
        apk_sha256 = $apkSha256
        started_at = $startedAt.ToString("o")
        finished_at = [System.DateTimeOffset]::UtcNow.ToString("o")
        seed = $seed
        rotated = $rotated
        restarted = $restarted
        restored = $restored
        cross_checked = $crossChecked
    }
    $summaryJson = $summary | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($summaryPath, $summaryJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    $smokePassed = $true
    Write-Output "[OK] Android API $ApiLevel local smoke passed."
    Write-Output "[INFO] Evidence: $summaryPath"
} catch {
    $failure = $_.Exception.Message
    try { Write-Diagnostics } catch {}
    $failureSummary = [ordered]@{
        schema = "affiliate-report.android-local-smoke.v1"
        result = "failed"
        api_level = $ApiLevel
        avd = $avdName
        serial = $serial
        started_at = $startedAt.ToString("o")
        finished_at = [System.DateTimeOffset]::UtcNow.ToString("o")
        error = $failure
    }
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    [System.IO.File]::WriteAllText($summaryPath, (($failureSummary | ConvertTo-Json -Depth 6) + [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
    throw
} finally {
    Remove-Item Env:ANDROID_LOCAL_TOKEN -ErrorAction SilentlyContinue
    if ($forwardCreated) {
        try { Invoke-Adb -Arguments @("-s", $serial, "forward", "--remove", "tcp:$forwardPort") -AllowFailure | Out-Null } catch {}
    }
    if ($serialOwned -and -not $KeepEmulator) {
        try { Invoke-Adb -Arguments @("-s", $serial, "emu", "kill") -AllowFailure | Out-Null } catch {}
    }
    if (-not $KeepEmulator) {
        if ($emulatorProcess -and -not $emulatorProcess.HasExited) {
            try {
                if (-not $emulatorProcess.WaitForExit(15000)) {
                    Stop-Process -Id $emulatorProcess.Id -Force -ErrorAction Stop
                    $emulatorProcess.WaitForExit(5000) | Out-Null
                }
            } catch {
                Write-Warning "Could not stop emulator process $($emulatorProcess.Id): $($_.Exception.Message)"
            }
        }
    }
    if ($mutexAcquired) {
        try { $smokeMutex.ReleaseMutex() } catch {}
    }
    $smokeMutex.Dispose()
    if (-not $smokePassed) {
        Write-Warning "Android local smoke failed. Diagnostics: $evidenceDir"
    }
}
