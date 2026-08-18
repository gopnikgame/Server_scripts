#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/server-scripts-tests.XXXXXX")
trap 'rm -rf -- "$TMP_ROOT"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

(
    # shellcheck source=../server_launcher.sh
    source "$ROOT_DIR/server_launcher.sh"
    [[ "$REPOSITORY_BRANCH" == main ]] || fail "launcher does not track main by default"
    if download_script '../bad.sh' "$TMP_ROOT/bad" '1111111111111111111111111111111111111111'; then
        fail "launcher accepted an unsafe module name"
    fi
    curl() {
        local previous='' output='' argument
        for argument in "$@"; do
            if [[ "$previous" == '--output' ]]; then output="$argument"; break; fi
            previous="$argument"
        done
        if [[ -z "$output" ]]; then
            printf '{\n  "sha": "1111111111111111111111111111111111111111"\n}\n'
            return 0
        fi
        [[ -n "$output" ]] || return 2
        printf '#!/usr/bin/env bash\nprintf "fixture\\n"\n' > "$output"
    }
    [[ $(resolve_latest_commit) == '1111111111111111111111111111111111111111' ]] || fail "launcher latest-main resolution failed"
    download_script 'fixture.sh' "$TMP_ROOT/fixture.sh" '1111111111111111111111111111111111111111'
    bash -n "$TMP_ROOT/fixture.sh" || fail "launcher did not install a valid fixture atomically"
)

(
    # shellcheck source=../speed_dns.sh
    source "$ROOT_DIR/speed_dns.sh"
    _exists bash || fail "speed_dns command detection failed"
    [[ "$(_green ok)" == *ok* ]] || fail "speed_dns formatter failed"
)

(
    export SWAPFILE="$TMP_ROOT/swapfile"
    export FSTAB_FILE="$TMP_ROOT/fstab"
    export LOG_FILE="$TMP_ROOT/swap.log"
    : > "$FSTAB_FILE"
    # shellcheck source=../snapfile.sh
    source "$ROOT_DIR/snapfile.sh"
    ensure_fstab_entry
    ensure_fstab_entry
    [[ $(grep -Fxc "$SWAPFILE none swap sw 0 0" "$FSTAB_FILE") -eq 1 ]] || fail "swap fstab entry is not idempotent"
    swapon() { printf '%s\n' "$SWAPFILE"; }
    is_swap_active || fail "exact active swap detection failed"
)

(
    # shellcheck source=../bbr_info.sh
    source "$ROOT_DIR/bbr_info.sh"
    sysctl() { return 1; }
    [[ $(value_or_unknown net.ipv4.tcp_congestion_control) == unknown ]] || fail "BBR unknown fallback failed"
)

printf 'Remaining script tests: OK\n'
