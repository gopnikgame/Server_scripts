#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
MODULE=${1:-/tmp/server-scripts-proxy-test/setup_proxy.sh}
TEST_ADDRESS=${2:-192.168.88.1}
TEST_USER=${3:-root}
BLOCKER=/etc/ssh/sshd_config.d/99-server-scripts-proxy-test-block.conf
MANAGED=/etc/ssh/sshd_config.d/10-server-scripts-proxy.conf
MAIN=/etc/ssh/sshd_config
before_hash=$(sha256sum "$MAIN" | awk '{print $1}')

[[ ! -e "$BLOCKER" && ! -e "$MANAGED" ]] || { echo 'Test drop-in already exists' >&2; exit 1; }
cleanup() {
    rm -f -- "$BLOCKER" "$MANAGED"
    if [[ -f /etc/server-scripts/proxy-sessions/sshd_config.backup ]]; then
        cp -a -- /etc/server-scripts/proxy-sessions/sshd_config.backup "$MAIN"
        rm -f -- /etc/server-scripts/proxy-sessions/sshd_config.backup
    fi
    sshd -t && systemctl reload ssh
}
trap cleanup EXIT

install -d -m 0755 /etc/ssh/sshd_config.d
printf '%s\n' "Match User $TEST_USER Address $TEST_ADDRESS" '    DisableForwarding yes' '    AllowTcpForwarding no' 'Match all' > "$BLOCKER"
chmod 0644 "$BLOCKER"
sshd -t && systemctl reload ssh

# shellcheck disable=SC1090
source "$MODULE"
if sshd_forwarding_allowed "$TEST_USER" "$TEST_ADDRESS" localhost; then
    echo 'Fixture failed to disable forwarding' >&2; exit 1
fi
enable_temporary_ssh_forwarding "$TEST_USER" "$TEST_ADDRESS" localhost
[[ $SSHD_CHANGED == 1 ]]
sshd_forwarding_allowed "$TEST_USER" "$TEST_ADDRESS" localhost
restore_temporary_ssh_forwarding "$SSHD_CHANGED"
if sshd_forwarding_allowed "$TEST_USER" "$TEST_ADDRESS" localhost; then
    echo 'Rollback did not restore disabled forwarding' >&2; exit 1
fi
[[ ! -e "$MANAGED" ]]
[[ $(sha256sum "$MAIN" | awk '{print $1}') == "$before_hash" ]]
server_create ssh-socks localhost 22 "$TEST_ADDRESS/32" 10 "$TEST_USER"
load_state "$SERVER_STATE"
[[ "$MODE" == ssh-socks && "$SSHD_CHANGED" == 1 ]]
server_remove "$SESSION_ID"
if sshd_forwarding_allowed "$TEST_USER" "$TEST_ADDRESS" localhost; then
    echo 'Server session rollback did not restore disabled forwarding' >&2; exit 1
fi
echo 'SSH forwarding enable/rollback live test passed'
