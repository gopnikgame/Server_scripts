#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=${BASH_SOURCE[0]%/*}
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
TEST_TMP=$(mktemp -d)
trap 'rm -rf -- "$TEST_TMP"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=${PYTHON_BIN:-/c/Users/Иван/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe}
    export PYTHON_BIN
fi
export PROXY_STATE_ROOT="$TEST_TMP/state"
export PROXY_CONFIG_ROOT="$TEST_TMP/config"
export PROXY_LOG_FILE="$TEST_TMP/setup_proxy.log"
export PROXY_ENV_FILE="$TEST_TMP/environment"
export PROXY_APT_CONF="$TEST_TMP/apt-proxy.conf"
export PROXY_PROFILE="$TEST_TMP/proxy-profile.sh"
export SERVER_UNIT="$TEST_TMP/server.service"
export CLIENT_UNIT="$TEST_TMP/client.service"
export SSH_UNIT="$TEST_TMP/ssh.service"
export EXPIRE_SERVICE="$TEST_TMP/expire.service"
export EXPIRE_TIMER="$TEST_TMP/expire.timer"
export SSHD_CONFIG="$TEST_TMP/sshd_config"
export SSHD_DROPIN="$TEST_TMP/sshd_config.d/10-server-scripts-proxy.conf"
export XRAY_BIN="$TEST_TMP/xray"

# shellcheck source=../setup_proxy.sh
source "$ROOT_DIR/setup_proxy.sh"

failures=0
assert_true() { local label="$1"; shift; if ! "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }
assert_false() { local label="$1"; shift; if "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }
assert_eq() { local label="$1" expected="$2" actual="$3"; if [[ "$expected" != "$actual" ]]; then printf 'FAIL: %s (expected=%q actual=%q)\n' "$label" "$expected" "$actual" >&2; failures=$((failures + 1)); fi; }

mkdir -p "$STATE_ROOT" "$CONFIG_ROOT"
assert_true 'authenticated HTTP proxy URL accepted' validate_proxy_url 'http://alice:p%40ss@example.test:3128'
assert_false 'URL without explicit port rejected' validate_proxy_url 'http://example.test'
assert_false 'URL with shell newline rejected' validate_proxy_url $'http://example.test:80\nINJECT=1'
assert_true 'SOCKS5h proxy URL accepted' validate_proxy_url 'socks5h://127.0.0.1:1080'
assert_false 'SOCKS5 without remote DNS rejected' validate_proxy_url 'socks5://127.0.0.1:1080'

bundle=$(encode_bundle socks5 proxy.example.test 31080 alice 'p@ss' session-1 '2026-08-30T00:00:00+03:00')
assert_true 'connection bundle decoded' decode_bundle "$bundle"
assert_eq 'bundle mode round-trip' socks5 "$BUNDLE_MODE"
assert_eq 'bundle password round-trip' 'p@ss' "$BUNDLE_PASS"
assert_false 'damaged bundle rejected' decode_bundle "${bundle}x"

parse_vless_link 'vless://11111111-1111-4111-8111-111111111111@example.test:443?security=reality&sni=cdn.example.test&pbk=public-key&sid=abcd&type=tcp#stable'
assert_true 'valid VLESS REALITY TCP accepted' validate_vless_params
assert_eq 'VLESS remark decoded' stable "$VLESS_REMARK"
VLESS_PORT=70000
assert_false 'invalid VLESS port rejected' validate_vless_params

generate_server_config http 3128 alice secret
assert_true 'HTTP server config has authenticated inbound' "$PYTHON_BIN" -c 'import json,sys; c=json.load(open(sys.argv[1])); i=c["inbounds"][0]; assert i["protocol"]=="http" and i["settings"]["accounts"][0]["user"]=="alice"' "$SERVER_CONFIG"
generate_server_config socks5 1080 bob secret
assert_true 'SOCKS server config has password auth' "$PYTHON_BIN" -c 'import json,sys; i=json.load(open(sys.argv[1]))["inbounds"][0]; assert i["protocol"]=="socks" and i["settings"]["auth"]=="password"' "$SERVER_CONFIG"

save_proxy_state http 'http://alice:p%40ss@example.test:3128' $'value"; touch /tmp/not-created; #'
assert_eq 'state mode is 0600' 600 "$(stat -c '%a' "$CLIENT_STATE")"
unset PROXY_MODE PROXY_URL PROXY_DETAILS PROXY_CONFIGURED
load_state "$CLIENT_STATE"
assert_eq 'state URL round-trip' 'http://alice:p%40ss@example.test:3128' "$PROXY_URL"
assert_eq 'state shell metacharacters are data' $'value"; touch /tmp/not-created; #' "$PROXY_DETAILS"

printf 'KEEP=this-line\nhttp_proxy=old\n' > "$PROXY_ENV_FILE"
printf 'original-profile\n' > "$PROXY_PROFILE"
apply_system_proxy 'socks5h://127.0.0.1:10808'
assert_true 'APT receives socks5h proxy' grep -Fq 'socks5h://127.0.0.1:10808' "$PROXY_APT_CONF"
assert_true 'unrelated environment line preserved' grep -Fq 'KEEP=this-line' "$PROXY_ENV_FILE"
restore_client_proxy_files
assert_true 'environment restored exactly' grep -Fxq 'http_proxy=old' "$PROXY_ENV_FILE"
assert_true 'profile restored exactly' grep -Fxq 'original-profile' "$PROXY_PROFILE"
assert_false 'originally absent APT file removed' test -e "$PROXY_APT_CONF"

SSHD_TEST_ALLOW=local; SSHD_TEST_DISABLE=no
sshd_effective_value() { [[ "$4" == allowtcpforwarding ]] && printf '%s\n' "$SSHD_TEST_ALLOW" || printf '%s\n' "$SSHD_TEST_DISABLE"; }
assert_true 'SSH local forwarding accepted' sshd_forwarding_allowed root 192.0.2.1 server.example
SSHD_TEST_DISABLE=yes
assert_false 'DisableForwarding overrides AllowTcpForwarding' sshd_forwarding_allowed root 192.0.2.1 server.example
SSHD_TEST_DISABLE=no; SSHD_TEST_ALLOW=remote
assert_false 'remote-only forwarding cannot provide local SOCKS' sshd_forwarding_allowed root 192.0.2.1 server.example
assert_eq 'CIDR gets a concrete sshd -T probe address' 192.0.2.1 "$(cidr_probe_address 192.0.2.0/24)"

if (( failures > 0 )); then
    printf '%d setup_proxy test(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'All setup_proxy tests passed\n'
