#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
MODULE=${1:-/tmp/server-scripts-proxy-test/setup_proxy.sh}
TEST_ROOT=/etc/server-scripts/proxy-ssh-client-live-test
AUTH_KEYS=/root/.ssh/authorized_keys
AUTH_BACKUP=/tmp/proxy-authorized-keys.backup
KEY=/root/.ssh/proxy-client-test-key

export PROXY_STATE_ROOT="$TEST_ROOT"
export PROXY_LOG_FILE=/tmp/proxy-client-live.log
export PROXY_ENV_FILE=/tmp/proxy-client-environment
export PROXY_APT_CONF=/tmp/proxy-client-apt.conf
export PROXY_PROFILE=/tmp/proxy-client-profile.sh
export SERVER_UNIT=/etc/systemd/system/server-scripts-proxy-live-server.service
export CLIENT_UNIT=/etc/systemd/system/server-scripts-proxy-live-client.service
export SSH_UNIT=/etc/systemd/system/server-scripts-proxy-live-ssh.service
export EXPIRE_SERVICE=/etc/systemd/system/server-scripts-proxy-live-expire.service
export EXPIRE_TIMER=/etc/systemd/system/server-scripts-proxy-live-expire.timer

# shellcheck disable=SC1090
source "$MODULE"

cleanup() {
    client_remove >/dev/null 2>&1 || true
    if [[ -f "$AUTH_BACKUP" ]]; then cp -a -- "$AUTH_BACKUP" "$AUTH_KEYS"; fi
    rm -f -- "$AUTH_BACKUP" "$KEY" "$KEY.pub" /tmp/proxy-client-{environment,apt.conf,profile.sh,live.log}
    rm -rf -- "$TEST_ROOT"
    systemctl daemon-reload
}
trap cleanup EXIT

[[ -f "$AUTH_KEYS" ]] || { echo 'root authorized_keys is required for this disposable-VM test' >&2; exit 1; }
cp -a -- "$AUTH_KEYS" "$AUTH_BACKUP"
ssh-keygen -q -t ed25519 -N '' -f "$KEY"
chmod 0600 "$KEY"
printf '%s\n' "$(<"$KEY.pub")" >> "$AUTH_KEYS"

client_connect_ssh_socks 127.0.0.1 22 root "$KEY" 18088
systemctl is-active --quiet "$(basename -- "$SSH_UNIT")"
ss -H -lnt 'sport = :18088' | grep -q .
test_http_proxy socks5h://127.0.0.1:18088
client_remove
[[ ! -e "$CLIENT_STATE" && ! -e "$SSH_UNIT" && ! -e "$CLIENT_UNIT" ]]
echo 'SSH SOCKS client end-to-end live test passed'
