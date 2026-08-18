#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=${BASH_SOURCE[0]%/*}
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
TEST_TMP=$(mktemp -d)
trap 'rm -rf -- "$TEST_TMP"' EXIT

if ! command -v python3 >/dev/null 2>&1 && command -v python.exe >/dev/null 2>&1; then
    PYTHON_BIN=python.exe
    export PYTHON_BIN
fi

# shellcheck source=../setup_proxy.sh
source "$ROOT_DIR/setup_proxy.sh"

failures=0
assert_true() { local label="$1"; shift; if ! "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }
assert_false() { local label="$1"; shift; if "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }

assert_true 'authenticated HTTP proxy URL accepted' validate_proxy_url 'http://alice:p%40ss@example.test:3128'
assert_true 'HTTPS proxy URL accepted' validate_proxy_url 'https://127.0.0.1:8443'
assert_false 'URL without explicit port rejected' validate_proxy_url 'http://example.test'
assert_false 'URL with shell newline rejected' validate_proxy_url $'http://example.test:80\nINJECT=1'
assert_false 'unsupported proxy scheme rejected' validate_proxy_url 'socks5://127.0.0.1:1080'

parse_vless_link 'vless://11111111-1111-4111-8111-111111111111@example.test:443?security=reality&sni=cdn.example.test&pbk=public-key&sid=abcd&type=tcp#stable'
assert_true 'valid VLESS REALITY TCP accepted' validate_vless_params
[[ "$VLESS_NETWORK" == tcp ]] || failures=$((failures + 1))
[[ "$VLESS_REMARK" == stable ]] || failures=$((failures + 1))

VLESS_PORT=70000
export VLESS_PORT
assert_false 'invalid VLESS port rejected' validate_vless_params

PROXY_STATE_FILE="$TEST_TMP/proxy.conf"
save_proxy_state 'http' 'http://alice:p%40ss@example.test:3128' $'value"; touch /tmp/not-created; #'
[[ $(stat -c '%a' "$PROXY_STATE_FILE") == 600 ]] || failures=$((failures + 1))
unset PROXY_MODE PROXY_URL PROXY_DETAILS PROXY_CONFIGURED
# Generated fixture path is intentionally dynamic.
# shellcheck disable=SC1090
source "$PROXY_STATE_FILE"
[[ "$PROXY_URL" == 'http://alice:p%40ss@example.test:3128' ]] || failures=$((failures + 1))
[[ "$PROXY_DETAILS" == $'value"; touch /tmp/not-created; #' ]] || failures=$((failures + 1))

if (( failures > 0 )); then
    printf '%d setup_proxy test(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'All setup_proxy tests passed\n'
