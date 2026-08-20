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

(
    dpkg-query() { printf 'ii '; }
    package_is_installed example
) || {
    printf 'FAIL: installed package status was not recognized\n' >&2
    failures=$((failures + 1))
}
(
    dpkg-query() { printf 'un '; }
    ! package_is_installed example
) || {
    printf 'FAIL: uninstalled package status was accepted\n' >&2
    failures=$((failures + 1))
}

if grep -Eq 'apt-cache show (neo|fast)fetch|required_packages\+=\("\$system_info_package"\)' "$ROOT_DIR/ubuntu_pre_install.sh"; then
    printf 'FAIL: decorative system-info packages must not be auto-installed\n' >&2
    failures=$((failures + 1))
fi
grep -q 'apt-get -s install -- "${packages_to_install\[@\]}"' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: package installation is not simulated before mutation\n' >&2
    failures=$((failures + 1))
}
grep -q 'package_is_installed mtr-tiny' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: an existing mtr-tiny installation is not preserved\n' >&2
    failures=$((failures + 1))
}

dnscrypt_fixture=$(mktemp)
trap 'rm -f "$dnscrypt_fixture"' EXIT
printf '%s\n' 'https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/main/lib/common.sh' > "$dnscrypt_fixture"
dnscrypt_commit=1111111111111111111111111111111111111111
assert_true 'DNSCrypt snapshot pinned' pin_dnscrypt_installer_snapshot "$dnscrypt_fixture" "$dnscrypt_commit"
grep -q "/${dnscrypt_commit}/lib/common.sh" "$dnscrypt_fixture" || {
    printf 'FAIL: DNSCrypt installer dependency URL was not pinned\n' >&2
    failures=$((failures + 1))
}
assert_false 'invalid DNSCrypt commit rejected' pin_dnscrypt_installer_snapshot "$dnscrypt_fixture" main

dnscrypt_main_fixture=$(mktemp)
trap 'rm -f "$dnscrypt_fixture" "$dnscrypt_main_fixture"' EXIT
printf '%s\n' '#!/usr/bin/env bash' 'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"' > "$dnscrypt_main_fixture"
chmod 0755 "$dnscrypt_main_fixture"
assert_true 'DNSCrypt entrypoint normalized' normalize_dnscrypt_manager_entrypoint "$dnscrypt_main_fixture"
grep -q '^SCRIPT_PATH="$(readlink -f "${BASH_SOURCE\[0\]}")"$' "$dnscrypt_main_fixture" || {
    printf 'FAIL: DNSCrypt entrypoint does not resolve its symlink\n' >&2
    failures=$((failures + 1))
}
assert_true 'already normalized entrypoint accepted' normalize_dnscrypt_manager_entrypoint "$dnscrypt_main_fixture"

SSH_CONNECTION='192.0.2.10 50000 198.51.100.5 2222'
export SSH_CONNECTION
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

dropin="$(render_ssh_dropin no)"
grep -q '^PermitRootLogin prohibit-password$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^PubkeyAuthentication yes$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^PasswordAuthentication no$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^KbdInteractiveAuthentication no$' <<< "$dropin" || failures=$((failures + 1))
grep -q '^AllowTcpForwarding no$' <<< "$dropin" || failures=$((failures + 1))
if grep -q '^Protocol ' <<< "$dropin"; then
    printf 'FAIL: obsolete Protocol directive present\n' >&2
    failures=$((failures + 1))
fi

for forwarding_mode in yes local remote no; do
    dropin="$(render_ssh_dropin "$forwarding_mode")"
    grep -q "^AllowTcpForwarding $forwarding_mode$" <<< "$dropin" || {
        printf 'FAIL: AllowTcpForwarding %s was not rendered\n' "$forwarding_mode" >&2
        failures=$((failures + 1))
    }
done
assert_false 'invalid TCP forwarding mode rejected' render_ssh_dropin 'yes; Match all'

[[ "$(vless_buffer_limit_for_ram 512)" == 8388608 ]] || failures=$((failures + 1))
[[ "$(vless_buffer_limit_for_ram 960)" == 16777216 ]] || failures=$((failures + 1))
[[ "$(vless_buffer_limit_for_ram 3921)" == 33554432 ]] || failures=$((failures + 1))
[[ "$(vless_buffer_limit_for_ram 7900)" == 67108864 ]] || failures=$((failures + 1))

(
    modprobe() { return 0; }
    sysctl() { printf 'reno cubic bbr\n'; }
    ensure_running_kernel_bbr
) || { printf 'FAIL: available kernel BBR was not selected\n' >&2; failures=$((failures + 1)); }
(
    modprobe() { return 1; }
    sysctl() { printf 'reno cubic\n'; }
    ! ensure_running_kernel_bbr
) || { printf 'FAIL: missing kernel BBR was accepted\n' >&2; failures=$((failures + 1)); }

profile=$(
    sysctl() {
        case "$2" in
            net.core.somaxconn) printf '4096\n' ;;
            net.ipv4.tcp_max_syn_backlog) printf '32768\n' ;;
            net.ipv4.ip_local_port_range) printf '15000 62000\n' ;;
            *) return 1 ;;
        esac
    }
    render_vless_high_connection_profile 4096
)
grep -q '^net.core.default_qdisc=fq$' <<< "$profile" || failures=$((failures + 1))
grep -q '^net.ipv4.tcp_congestion_control=bbr$' <<< "$profile" || failures=$((failures + 1))
grep -q '^net.core.somaxconn=16384$' <<< "$profile" || failures=$((failures + 1))
grep -q '^net.ipv4.tcp_max_syn_backlog=32768$' <<< "$profile" || failures=$((failures + 1))
grep -q '^net.ipv4.ip_local_port_range=10240 65535$' <<< "$profile" || failures=$((failures + 1))
grep -q '^net.core.rmem_max=33554432$' <<< "$profile" || failures=$((failures + 1))
if grep -Eq 'tcp_max_tw_buckets|tcp_tw_reuse|tcp_fin_timeout|busy_poll|tcp_fastopen|tcp_keepalive' <<< "$profile"; then
    printf 'FAIL: unsafe or unmeasured TCP settings leaked into VLESS profile\n' >&2
    failures=$((failures + 1))
fi
grep -q '/etc/sysctl.d/90-server-scripts-vless-tcp.conf' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: canonical VLESS sysctl profile path is missing\n' >&2
    failures=$((failures + 1))
}

backup_line=$(grep -n 'cp -a /etc/ufw.*BACKUP_DIR/ufw' "$ROOT_DIR/ubuntu_pre_install.sh" | head -n1 | cut -d: -f1)
reset_line=$(grep -n 'ufw --force reset' "$ROOT_DIR/ubuntu_pre_install.sh" | head -n1 | cut -d: -f1)
if [[ -z "$backup_line" || -z "$reset_line" || "$backup_line" -ge "$reset_line" ]]; then
    printf 'FAIL: UFW backup must happen before reset\n' >&2
    failures=$((failures + 1))
fi

grep -q 'Сохранить существующие правила и добавить новые' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: additive UFW mode is missing\n' >&2
    failures=$((failures + 1))
}
grep -q '\[\[ "$firewall_mode" == 2 \]\]' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: UFW reset is not gated by explicit replace mode\n' >&2
    failures=$((failures + 1))
}
grep -Fq 'if [[ "$firewall_mode" == 2 ]] || (( UFW_WAS_ACTIVE == 0 )); then' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: replace mode does not re-enable UFW before verification\n' >&2
    failures=$((failures + 1))
}
grep -q 'if (( rc == 0 )); then' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: a user-requested rollback is still logged as an execution error\n' >&2
    failures=$((failures + 1))
}
if grep -q 'Выполнить все задачи автоматически' "$ROOT_DIR/ubuntu_pre_install.sh"; then
    printf 'FAIL: obsolete automatic profile is still present\n' >&2
    failures=$((failures + 1))
fi
grep -q 'if ! read -r -p "Вторая SSH-сессия успешно подключилась?' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: UFW confirmation EOF is not handled safely\n' >&2
    failures=$((failures + 1))
}
grep -q 'if ! read -r -p "Вход по ключу во второй сессии успешен?' "$ROOT_DIR/ubuntu_pre_install.sh" || {
    printf 'FAIL: SSH confirmation EOF is not handled safely\n' >&2
    failures=$((failures + 1))
}

if (( failures > 0 )); then
    printf '%d pre-install test(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'Ubuntu pre-install tests: OK\n'
