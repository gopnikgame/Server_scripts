#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=${BASH_SOURCE[0]%/*}
ROOT_DIR=$(cd "$TEST_DIR/.." && pwd)
# shellcheck source=../ubuntu_pre_install.sh
source "$ROOT_DIR/ubuntu_pre_install.sh"

failures=0
assert_true() { local label="$1"; shift; if ! "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }
assert_false() { local label="$1"; shift; if "$@"; then printf 'FAIL: %s\n' "$label" >&2; failures=$((failures + 1)); fi; }

assert_true 'lowest port' valid_port 1
assert_true 'highest port' valid_port 65535
assert_false 'zero port rejected' valid_port 0
assert_false 'overflow port rejected' valid_port 65536
assert_false 'shell input rejected as port' valid_port '22;id'

SSH_CONNECTION='192.0.2.10 50000 198.51.100.5 2222'
if [[ "$(detect_ssh_port)" != 2222 ]]; then
    printf 'FAIL: current SSH server port was not preferred\n' >&2
    failures=$((failures + 1))
fi
unset SSH_CONNECTION

assert_true 'IPv4 host accepted' valid_ip_or_cidr 192.0.2.10
assert_true 'IPv4 CIDR accepted' valid_ip_or_cidr 198.51.100.0/24
if python3 -c 'import ipaddress' >/dev/null 2>&1; then
    assert_true 'IPv6 CIDR accepted' valid_ip_or_cidr 2001:db8::/32
fi
assert_false 'invalid octets rejected' valid_ip_or_cidr 999.999.999.999
assert_false 'shell whitespace rejected' valid_ip_or_cidr '192.0.2.1; id'

dropin="$(render_ssh_dropin)"
grep -q '^PermitRootLogin prohibit-password$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^PubkeyAuthentication yes$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^PasswordAuthentication no$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^KbdInteractiveAuthentication no$' <<< "$dropin" || failures=$((failures + 1))
if grep -q '^Protocol ' <<< "$dropin"; then
    printf 'FAIL: obsolete Protocol directive present\n' >&2
    failures=$((failures + 1))
fi

backup_line=$(grep -n 'cp -a /etc/ufw.*BACKUP_DIR/ufw' "$ROOT_DIR/ubuntu_pre_install.sh" | head -n1 | cut -d: -f1)
reset_line=$(grep -n 'ufw --force reset' "$ROOT_DIR/ubuntu_pre_install.sh" | head -n1 | cut -d: -f1)
if [[ -z "$backup_line" || -z "$reset_line" || "$backup_line" -ge "$reset_line" ]]; then
    printf 'FAIL: UFW backup must happen before reset\n' >&2
    failures=$((failures + 1))
fi

if (( failures > 0 )); then
    printf '%d pre-install test(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'Ubuntu pre-install tests: OK\n'
