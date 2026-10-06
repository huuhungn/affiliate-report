#!/usr/bin/env bash
set -euo pipefail

api_level="${1:?Android API level is required}"
apk="$GITHUB_WORKSPACE/candidate/AffiliateReport-v2.2.0-x86_64-debug.apk"
package="$RUNNER_TEMP/android-${api_level}.affsync"

dump_diagnostics() {
  status=$?
  set +e
  echo "::group::Android runtime diagnostics"
  adb shell run-as vn.io.huuhungn.affiliatereport cat cache/startup-error.txt 2>/dev/null || true
  adb logcat -d -t 500 -s AffiliateReport:E AndroidRuntime:E python.stderr:V chaquopy:V 2>/dev/null || true
  echo "::endgroup::"
  exit "$status"
}
trap dump_diagnostics ERR

read_token() {
  local raw=""
  for _ in $(seq 1 30); do
    raw="$(adb exec-out run-as vn.io.huuhungn.affiliatereport cat files/android-local-token 2>/dev/null | tr -d '\r\n' || true)"
    if [[ "$raw" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
      break
    fi
    raw=""
    sleep 1
  done
  test "${#raw}" -eq 43
  ANDROID_LOCAL_TOKEN="$raw"
  echo "::add-mask::$ANDROID_LOCAL_TOKEN"
  export ANDROID_LOCAL_TOKEN
}

adb install -r "$apk"
adb shell am start -W -n vn.io.huuhungn.affiliatereport/.MainActivity
adb forward tcp:9876 tcp:8765
read_token
python scripts/ci/android_runtime_smoke.py --phase seed --package "$package"
adb shell settings put system accelerometer_rotation 0
adb shell settings put system user_rotation 1
sleep 2
python scripts/ci/android_runtime_smoke.py --phase persist --package "$package"
adb shell am force-stop vn.io.huuhungn.affiliatereport
adb shell am start -W -n vn.io.huuhungn.affiliatereport/.MainActivity
python scripts/ci/android_runtime_smoke.py --phase persist --package "$package"
adb shell pm clear vn.io.huuhungn.affiliatereport
adb shell am start -W -n vn.io.huuhungn.affiliatereport/.MainActivity
read_token
python scripts/ci/android_runtime_smoke.py --phase restore --package "$package"
python scripts/ci/android_runtime_smoke.py --phase cross-check --package "$package"
adb shell pidof vn.io.huuhungn.affiliatereport
