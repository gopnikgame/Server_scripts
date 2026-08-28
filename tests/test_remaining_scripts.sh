#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/server-scripts-tests.XXXXXX")
trap 'rm -rf -- "$TMP_ROOT"' EXIT

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

(
    export SERVER_SCRIPTS_SCRIPT_DIR="$TMP_ROOT/launcher/script"
    export SERVER_SCRIPTS_MODULES_DIR="$TMP_ROOT/launcher/modules"
    export SERVER_SCRIPTS_LOG_DIR="$TMP_ROOT/launcher/log"
    export SERVER_SCRIPTS_STATE_DIR="$TMP_ROOT/launcher/state"
    export SERVER_SCRIPTS_BACKUP_ROOT="$TMP_ROOT/launcher/backups"
    export SERVER_SCRIPTS_BIN_LINK="$TMP_ROOT/launcher/bin/server_launcher.sh"
    export SERVER_SCRIPTS_LOCK_FILE="$TMP_ROOT/launcher/run/launcher.lock"
    # shellcheck source=../server_launcher.sh
    source "$ROOT_DIR/server_launcher.sh"
    [[ "$REPOSITORY_BRANCH" == main ]] || fail "launcher does not track main by default"
    if download_script '../bad.sh' "$TMP_ROOT/bad" '1111111111111111111111111111111111111111'; then
        fail "launcher accepted an unsafe module name"
    fi
    curl() {
        local previous='' output='' argument source_url=''
        for argument in "$@"; do
            [[ "$argument" == http* ]] && source_url="$argument"
            if [[ "$previous" == '--output' ]]; then output="$argument"; fi
            previous="$argument"
        done
        if [[ -z "$output" ]]; then
            printf '{\n  "sha": "1111111111111111111111111111111111111111"\n}\n'
            return 0
        fi
        [[ -n "$output" ]] || return 2
        if [[ -n "${FAIL_DOWNLOAD_NAME:-}" && "$source_url" == *"/$FAIL_DOWNLOAD_NAME"* ]]; then return 22; fi
        printf '#!/usr/bin/env bash\n# Version: 2.0.0\nprintf "fixture\\n"\n' > "$output"
    }
    [[ $(resolve_latest_commit) == '1111111111111111111111111111111111111111' ]] || fail "launcher latest-main resolution failed"
    download_script 'fixture.sh' "$TMP_ROOT/fixture.sh" '1111111111111111111111111111111111111111'
    bash -n "$TMP_ROOT/fixture.sh" || fail "launcher did not install a valid fixture atomically"

    create_directories
    stage_one="$TMP_ROOT/stage-one"
    stage_snapshot '1111111111111111111111111111111111111111' "$stage_one"
    validate_snapshot "$stage_one" || fail "launcher rejected a complete staged snapshot"
    backup_one=$(backup_current_snapshot '1111111111111111111111111111111111111111')
    activate_snapshot "$stage_one" '1111111111111111111111111111111111111111' "$backup_one"
    snapshot_is_current "$stage_one" || fail "launcher did not activate the complete snapshot"
    [[ $(grep -c '^SNAPSHOT_COMMIT=1111111111111111111111111111111111111111$' "$STATE_DIR/snapshot.env") -eq 1 ]] || fail "launcher state was not recorded"

    launcher_hash=$(sha256sum "$SCRIPT_DIR/$SCRIPT_NAME" | awk '{print $1}')
    module_hash=$(sha256sum "$MODULES_DIR/${MODULE_ORDER[0]}" | awk '{print $1}')
    stage_bad="$TMP_ROOT/stage-bad"
    cp -a "$stage_one" "$stage_bad"
    printf 'if (\n' > "$stage_bad/modules/${MODULE_ORDER[0]}"
    backup_bad=$(backup_current_snapshot '2222222222222222222222222222222222222222')
    if activate_snapshot "$stage_bad" '2222222222222222222222222222222222222222' "$backup_bad"; then
        fail "launcher activated a broken snapshot"
    fi
    [[ $(sha256sum "$SCRIPT_DIR/$SCRIPT_NAME" | awk '{print $1}') == "$launcher_hash" ]] || fail "launcher rollback did not restore launcher"
    [[ $(sha256sum "$MODULES_DIR/${MODULE_ORDER[0]}" | awk '{print $1}') == "$module_hash" ]] || fail "launcher rollback did not restore modules"

    FAIL_DOWNLOAD_NAME=${MODULE_ORDER[1]}
    if stage_snapshot '3333333333333333333333333333333333333333' "$TMP_ROOT/stage-failed"; then
        fail "launcher accepted an incomplete download"
    fi
    [[ $(sha256sum "$MODULES_DIR/${MODULE_ORDER[0]}" | awk '{print $1}') == "$module_hash" ]] || fail "failed download changed active modules"
)

(
    # shellcheck source=../speed_dns.sh
    source "$ROOT_DIR/speed_dns.sh"
    _exists bash || fail "speed_dns command detection failed"
    [[ "$(_green ok)" == *ok* ]] || fail "speed_dns formatter failed"
    dig_fixture=$';; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n;; Query time: 19 msec\n'
    printf '%s' "$dig_fixture" | query_succeeded || fail "speed_dns rejected a successful dig response"
    [[ $(printf '%s' "$dig_fixture" | parse_query_time) == 19 ]] || fail "speed_dns query-time parser failed"
    failed_fixture=${dig_fixture/status: NOERROR/status: SERVFAIL}
    if printf '%s' "$failed_fixture" | query_succeeded; then fail "speed_dns accepted SERVFAIL as success"; fi
)

(
    export SWAPFILE="$TMP_ROOT/swapfile"
    export FSTAB_FILE="$TMP_ROOT/fstab"
    export LOG_FILE="$TMP_ROOT/swap.log"
    export BACKUP_ROOT="$TMP_ROOT/swap-backups"
    export MIN_FREE_AFTER_MB=256
    printf '# fixture\n%s none swap defaults 0 0\n%s none swap sw 0 0\n%s-extra none swap sw 0 0\n' \
        "$SWAPFILE" "$SWAPFILE" "$SWAPFILE" > "$FSTAB_FILE"
    # shellcheck source=../snapfile.sh
    source "$ROOT_DIR/snapfile.sh"
    ensure_fstab_entry
    ensure_fstab_entry
    [[ $(grep -Fxc "$SWAPFILE none swap sw 0 0" "$FSTAB_FILE") -eq 1 ]] || fail "swap fstab entry is not idempotent"
    grep -Fqx "$SWAPFILE-extra none swap sw 0 0" "$FSTAB_FILE" || fail "swap fstab rewrite removed a similarly named path"
    remove_fstab_entry
    if fstab_has_swap; then fail "swap fstab entry was not removed"; fi
    grep -Fqx "$SWAPFILE-extra none swap sw 0 0" "$FSTAB_FILE" || fail "swap removal changed a similarly named path"

    swapon() {
        [[ " $* " == *' --show=NAME '* ]] || fail "swap detection did not request the NAME column"
        printf '%s\n' "$SWAPFILE"
    }
    is_swap_active || fail "exact active swap detection failed"

    : > "$SWAPFILE"
    ensure_fstab_entry
    before_fstab=$(sha256sum "$FSTAB_FILE" | awk '{print $1}')
    confirm() { return 1; }
    swapoff() { fail "swapoff ran after delete cancellation"; }
    is_swap_active() { return 0; }
    disable_swap true
    [[ -f "$SWAPFILE" ]] || fail "delete cancellation removed the swap file"
    [[ $(sha256sum "$FSTAB_FILE" | awk '{print $1}') == "$before_fstab" ]] || fail "delete cancellation changed fstab"

    available_mb() { printf '300\n'; }
    if validate_size 45; then fail "swap size check did not preserve the free-space reserve"; fi
    validate_size 44 || fail "swap size check rejected a valid size"
)

(
    # shellcheck source=../bbr_info.sh
    source "$ROOT_DIR/bbr_info.sh"
    sysctl() { return 1; }
    [[ $(value_or_unknown net.ipv4.tcp_congestion_control) == unknown ]] || fail "BBR unknown fallback failed"
    systemctl() { printf 'inactive\n'; return 3; }
    [[ $(service_status xray) == inactive ]] || fail "inactive service status was duplicated"
    tc() { printf 'qdisc noqueue 0: dev lo root\nqdisc fq_codel 0: dev eth0 root\n'; }
    if live_qdiscs_are_fq; then fail "fq_codel live qdisc accepted as fq"; fi
    tc() { printf 'qdisc noqueue 0: dev lo root\nqdisc fq 0: dev eth0 root\n'; }
    live_qdiscs_are_fq || fail "fq live qdisc was rejected"
)

printf 'Remaining script tests: OK\n'
