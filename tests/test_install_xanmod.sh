#!/bin/bash

set -euo pipefail

TEST_DIR=${BASH_SOURCE[0]%/*}
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
TEST_BACKUP_DIR=$(mktemp -d)
export XANMOD_BACKUP_DIR="$TEST_BACKUP_DIR"

# shellcheck source=../install_xanmod.sh
source "$ROOT_DIR/install_xanmod.sh"

failures=0

assert_eq() {
    local expected="$1" actual="$2" label="$3"
    if [[ "$expected" != "$actual" ]]; then
        printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$label" "$expected" "$actual" >&2
        ((failures++))
    fi
}

assert_true() {
    local label="$1"
    shift
    if ! "$@"; then
        printf 'FAIL: %s\n' "$label" >&2
        ((failures++))
    fi
}

assert_eq x64v1 "$(detect_psabi_from_flags 'sse2')" 'legacy CPU -> x64v1'
assert_eq x64v2 "$(detect_psabi_from_flags 'sse4_2 ssse3 popcnt cx16')" 'v2 flags -> x64v2'
assert_eq x64v3 "$(detect_psabi_from_flags 'sse4_2 ssse3 popcnt cx16 avx2 bmi1 bmi2 f16c fma lzcnt movbe')" 'v3 flags -> x64v3'
assert_true 'noble is supported' codename_supported noble
if codename_supported jammy; then
    printf 'FAIL: stale codename jammy must not pass current XanMod matrix\n' >&2
    ((failures++))
fi

assert_eq 8388608 "$(buffer_limit_for_ram 512)" '512 MB buffer ceiling'
assert_eq 16777216 "$(buffer_limit_for_ram 1024)" '1 GB buffer ceiling'
assert_eq 16777216 "$(buffer_limit_for_ram 4095)" 'under 4 GB buffer ceiling'
assert_eq 33554432 "$(buffer_limit_for_ram 4096)" '4 GB buffer ceiling'

packages=$'linux-xanmod-x64v3\nlinux-xanmod-lts-x64v3\nlinux-xanmod-rt-x64v3'
assert_eq linux-xanmod-lts-x64v3 "$(recommended_package x64v3 "$packages")" 'prefer LTS for VLESS server'
packages=$'linux-xanmod-x64v2\nlinux-xanmod-rt-x64v2'
assert_eq linux-xanmod-x64v2 "$(recommended_package x64v2 "$packages")" 'fallback to MAIN'
packages='linux-xanmod-lts-x64v1'
assert_eq linux-xanmod-lts-x64v1 "$(recommended_package x64v1 "$packages")" 'x64v1 uses LTS'

sysctl() {
    case "$2" in
        net.core.somaxconn) printf '4096\n' ;;
        net.ipv4.tcp_max_syn_backlog) printf '16384\n' ;;
        *) return 1 ;;
    esac
}

profile=$(render_vless_profile 2048)
grep -q '^net.core.default_qdisc=fq$' <<<"$profile" || ((failures++))
grep -q '^net.ipv4.tcp_congestion_control=bbr$' <<<"$profile" || ((failures++))
grep -q '^net.core.somaxconn=8192$' <<<"$profile" || ((failures++))
grep -q '^net.ipv4.tcp_max_syn_backlog=16384$' <<<"$profile" || ((failures++))
grep -q '^net.core.rmem_max=16777216$' <<<"$profile" || ((failures++))
if grep -Eq 'tcp_tw_reuse|tcp_fin_timeout|busy_poll|rmem_default|tcp_fastopen|tcp_keepalive' <<<"$profile"; then
    printf 'FAIL: unsafe or workload-unproven settings leaked into stable profile\n' >&2
    ((failures++))
fi

curl() {
    [[ "$*" == *'-f'* ]] && return 99
    return 0
}
assert_true 'repository reachability accepts an HTTP 404 response' repo_reachable

sysctl() {
    if [[ "$1" == '-n' ]]; then
        case "$2" in
            net.core.default_qdisc) printf 'fq_codel\n' ;;
            net.ipv4.tcp_congestion_control) printf 'cubic\n' ;;
            *) printf '123\n' ;;
        esac
    fi
}
runtime_file=$(backup_runtime_profile)
grep -q '^net.core.default_qdisc=fq_codel$' "$runtime_file" || ((failures++))
grep -q '^net.ipv4.tcp_congestion_control=cubic$' "$runtime_file" || ((failures++))
rm -rf "$TEST_BACKUP_DIR"

if (( failures > 0 )); then
    printf '%d XanMod installer test(s) failed\n' "$failures" >&2
    exit 1
fi

printf 'XanMod installer tests: OK\n'
