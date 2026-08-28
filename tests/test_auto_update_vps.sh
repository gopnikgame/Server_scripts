#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=${BASH_SOURCE[0]%/*}
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
# shellcheck source=../auto_update_vps.sh
source "$ROOT_DIR/auto_update_vps.sh"

failures=0
assert_eq() {
    local expected="$1" actual="$2" label="$3"
    if [[ "$expected" != "$actual" ]]; then
        printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$label" "$expected" "$actual" >&2
        ((failures++))
    fi
}
assert_true() { local label="$1"; shift; if ! "$@"; then printf 'FAIL: %s\n' "$label" >&2; ((failures++)); fi; }
assert_false() { local label="$1"; shift; if "$@"; then printf 'FAIL: %s\n' "$label" >&2; ((failures++)); fi; }

assert_true 'XanMod image is protected' is_protected_package linux-image-6.18.44-x64v2-xanmod1
assert_true 'XanMod metapackage is protected' is_protected_package linux-xanmod-lts-x64v2
assert_true 'Ubuntu kernel is protected' is_protected_package linux-generic-hwe-24.04
assert_true 'SSH is protected' is_protected_package openssh-server
assert_true 'Xray is protected' is_protected_package xray
assert_false 'ordinary library is not protected' is_protected_package libssl3

assert_eq '*-*-* 03:05:00' "$(calendar_for_period daily 03:05)" 'daily calendar'
assert_eq 'Sun *-*-* 04:30:00' "$(calendar_for_period weekly 04:30)" 'weekly calendar'
assert_eq '*-*-01 23:59:00' "$(calendar_for_period monthly 23:59)" 'monthly calendar'
assert_true 'valid strict time' valid_time 09:07
assert_false 'reject missing leading zero' valid_time 9:07
assert_false 'reject invalid hour' valid_time 24:00
assert_true 'real os-release can be loaded without readonly collisions' require_supported_system
systemctl() { printf 'not-found\n'; return 1; }
assert_eq 'не настроен' "$(timer_enabled_status)" 'timer status is not duplicated'
unset -f systemctl

plan=$'Inst openssl [1] (2 Debian:stable)\nRemv linux-image-6.18.1-x64v2-xanmod1 [6.18.1]\nRemv old-library [1]'
assert_eq $'linux-image-6.18.1-x64v2-xanmod1\nold-library' "$(printf '%s\n' "$plan" | simulation_removals)" 'parse removals'
assert_false 'protected removal blocks plan' check_protected_removals <<< 'linux-image-6.18.1-x64v2-xanmod1'
assert_true 'ordinary removal passes guard' check_protected_removals <<< 'old-library'

(
    preflight() { return 0; }
    apt-get() { return 42; }
    simulation() { printf 'Inst fixture [1] (2 test)\n'; }
    confirm() { return 0; }
    create_snapshot() { printf '/tmp/should-not-exist\n'; }
    service_state() { printf inactive; }
    postflight() { return 0; }
    if perform_update safe >/dev/null 2>&1; then
        printf 'FAIL: apt-get update failure was reported as success\n' >&2
        exit 1
    fi
) || ((failures++))

(
    apt_calls=0
    preflight() { return 0; }
    apt-get() { apt_calls=$((apt_calls + 1)); (( apt_calls == 1 )) && return 0; return 42; }
    simulation() { printf 'Inst fixture [1] (2 test)\n'; }
    confirm() { return 0; }
    create_snapshot() { printf '/tmp/fixture-snapshot\n'; }
    service_state() { printf inactive; }
    postflight() { return 0; }
    if perform_update safe >/dev/null 2>&1; then
        printf 'FAIL: apt-get upgrade failure was reported as success\n' >&2
        exit 1
    fi
) || ((failures++))

if (( failures > 0 )); then
    printf '%d auto-update test(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'Auto-update tests: OK\n'
