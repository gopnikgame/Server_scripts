#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
MODULE=${1:-/tmp/server-scripts-proxy-test/setup_proxy.sh}

# shellcheck disable=SC1090
source "$MODULE"
cleanup() { server_remove >/dev/null 2>&1 || true; }
trap cleanup EXIT

[[ ! -e "$SERVER_STATE" ]] || { echo 'Existing server session found' >&2; exit 1; }

server_create http 127.0.0.1 23128 127.0.0.1/32 10
load_state "$SERVER_STATE"
http_url=$(url_with_credentials http "$HOST" "$PORT" "$USERNAME" "$PASSWORD")
test_http_proxy "$http_url"
systemctl is-active --quiet "$(basename -- "$SERVER_UNIT")"
server_remove "$SESSION_ID"
[[ ! -e "$SERVER_STATE" && ! -e "$SERVER_UNIT" ]]

server_create socks5 127.0.0.1 23180 127.0.0.1/32 10
load_state "$SERVER_STATE"
socks_url=$(url_with_credentials socks5h "$HOST" "$PORT" "$USERNAME" "$PASSWORD")
test_http_proxy "$socks_url"
systemctl is-active --quiet "$(basename -- "$SERVER_UNIT")"
server_remove "$SESSION_ID"
[[ ! -e "$SERVER_STATE" && ! -e "$SERVER_UNIT" ]]

echo 'HTTP and SOCKS5 server end-to-end live tests passed'
