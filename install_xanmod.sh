#!/bin/bash

# Version: 2.1.0
# Description: Interactive XanMod installer for VLESS TCP servers
# Repository: https://github.com/gopnikgame/Server_scripts
# License: MIT

set -Eeuo pipefail

readonly SCRIPT_VERSION="2.1.0"
readonly LOG_FILE="${XANMOD_LOG_FILE:-/var/log/xanmod_install.log}"
readonly STATE_FILE="${XANMOD_STATE_FILE:-/var/lib/server-scripts/xanmod.state}"
readonly SYSCTL_CONFIG="${XANMOD_SYSCTL_CONFIG:-/etc/sysctl.d/90-server-scripts-vless-tcp.conf}"
readonly LEGACY_SYSCTL_CONFIG="${XANMOD_LEGACY_SYSCTL_CONFIG:-/etc/sysctl.d/99-xanmod-vless-tcp.conf}"
readonly APT_PROXY_CONFIG="${XANMOD_APT_PROXY_CONFIG:-/etc/apt/apt.conf.d/99xanmod-proxy}"
readonly KEYRING_FILE="${XANMOD_KEYRING_FILE:-/etc/apt/keyrings/xanmod-archive-keyring.gpg}"
readonly SOURCE_FILE="${XANMOD_SOURCE_FILE:-/etc/apt/sources.list.d/xanmod-release.list}"
readonly BACKUP_DIR="${XANMOD_BACKUP_DIR:-/var/backups/server-scripts/xanmod}"
readonly XANMOD_KEY_URL="https://dl.xanmod.org/archive.key"
readonly XANMOD_REPO_URL="http://deb.xanmod.org"
readonly SUPPORTED_CODENAMES="bookworm trixie forky sid noble plucky questing resolute stonking faye gigi wilma xia zara zena"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

PROXY_ADDR=""
SELECTED_PACKAGE=""
OS_ID="unknown"
OS_NAME="unknown"
OS_CODENAME="unknown"
PSABI_LEVEL="unknown"
RAM_MB=0
ROOT_FREE_MB=0
BOOT_FREE_MB=0
BOOTLOADER="unknown"
SECURE_BOOT="unknown"
DKMS_STATUS="not-installed"

profile_keys() {
    printf '%s\n' \
        net.core.default_qdisc \
        net.ipv4.tcp_congestion_control \
        net.ipv4.tcp_mtu_probing \
        net.ipv4.tcp_syncookies \
        net.core.somaxconn \
        net.ipv4.tcp_max_syn_backlog \
        net.ipv4.ip_local_port_range \
        net.core.rmem_max \
        net.core.wmem_max \
        net.ipv4.tcp_rmem \
        net.ipv4.tcp_wmem
}

init_runtime() {
    umask 077
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

log() { printf '%b[%s]%b %s\n' "$BLUE" "$(date '+%F %T')" "$NC" "$*" | tee -a "$LOG_FILE"; }
success() { printf '%b[OK]%b %s\n' "$GREEN" "$NC" "$*" | tee -a "$LOG_FILE"; }
warn() { printf '%b[ВНИМАНИЕ]%b %s\n' "$YELLOW" "$NC" "$*" | tee -a "$LOG_FILE"; }
error() { printf '%b[ОШИБКА]%b %s\n' "$RED" "$NC" "$*" | tee -a "$LOG_FILE" >&2; }
header() { printf '\n%b=== %s ===%b\n\n' "$GREEN" "$*" "$NC"; }
pause() { read -rp "Нажмите Enter, чтобы продолжить..." _; }
confirm() { local answer; read -rp "$1 [y/N]: " answer; [[ "$answer" =~ ^[Yy]$ ]]; }

require_root() {
    if (( EUID != 0 )); then
        error "Запустите скрипт с правами root: sudo ./install_xanmod.sh"
        return 1
    fi
}

read_os_release() {
    if [[ ! -r /etc/os-release ]]; then
        error "/etc/os-release не найден"
        return 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-$OS_ID}"
    OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-unknown}}"
}

codename_supported() {
    local codename="${1:-}"
    [[ " $SUPPORTED_CODENAMES " == *" $codename "* ]]
}

cpu_has_flags() {
    local flags=" $1 " required
    shift
    for required in "$@"; do
        [[ "$flags" == *" $required "* ]] || return 1
    done
}

detect_psabi_from_flags() {
    local flags="$1"
    local level="x64v1"
    if cpu_has_flags "$flags" sse4_2 ssse3 popcnt cx16; then
        level="x64v2"
    fi
    if [[ "$level" == "x64v2" ]] && cpu_has_flags "$flags" avx2 bmi1 bmi2 f16c fma lzcnt movbe; then
        level="x64v3"
    fi
    printf '%s\n' "$level"
}

detect_psabi() {
    local flags
    flags=$(awk -F: '/^flags/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)
    PSABI_LEVEL=$(detect_psabi_from_flags "$flags")
}

detect_bootloader() {
    if command -v bootctl >/dev/null 2>&1 && bootctl is-installed >/dev/null 2>&1; then
        BOOTLOADER="systemd-boot"
    elif command -v update-grub >/dev/null 2>&1 || [[ -d /boot/grub ]]; then
        BOOTLOADER="grub"
    else
        BOOTLOADER="unknown"
    fi
}

detect_secure_boot() {
    if command -v mokutil >/dev/null 2>&1; then
        SECURE_BOOT=$(mokutil --sb-state 2>/dev/null | head -n1 || echo unknown)
    elif [[ -d /sys/firmware/efi ]]; then
        SECURE_BOOT="unknown (mokutil отсутствует)"
    else
        SECURE_BOOT="not-applicable (BIOS)"
    fi
}

detect_dkms() {
    if command -v dkms >/dev/null 2>&1; then
        DKMS_STATUS=$(dkms status 2>/dev/null || true)
        [[ -n "$DKMS_STATUS" ]] || DKMS_STATUS="установлен, модулей нет"
    fi
}

free_mb_for() {
    df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

collect_system_info() {
    read_os_release || return 1
    detect_psabi
    detect_bootloader
    detect_secure_boot
    detect_dkms
    RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    ROOT_FREE_MB=$(free_mb_for /)
    BOOT_FREE_MB=$(free_mb_for /boot)
    [[ -n "$BOOT_FREE_MB" ]] || BOOT_FREE_MB="$ROOT_FREE_MB"
}

show_system_report() {
    collect_system_info || return 1
    header "Диагностика системы"
    printf 'ОС:                    %s\n' "$OS_NAME"
    printf 'Codename:              %s\n' "$OS_CODENAME"
    printf 'Архитектура:           %s\n' "$(uname -m)"
    printf 'Текущее ядро:          %s\n' "$(uname -r)"
    printf 'CPU psABI:             %s\n' "$PSABI_LEVEL"
    printf 'Оперативная память:    %s МБ\n' "$RAM_MB"
    printf 'Свободно в /:          %s МБ\n' "$ROOT_FREE_MB"
    printf 'Свободно в /boot:      %s МБ\n' "$BOOT_FREE_MB"
    printf 'Загрузчик:             %s\n' "$BOOTLOADER"
    printf 'Secure Boot:           %s\n' "$SECURE_BOOT"
    printf 'Виртуализация:         %s\n' "$(systemd-detect-virt 2>/dev/null || echo unknown)"
    printf 'DKMS:                  %s\n' "$DKMS_STATUS"
    if codename_supported "$OS_CODENAME"; then
        success "Codename опубликован в текущем списке поддержки XanMod"
    else
        warn "Codename '$OS_CODENAME' отсутствует в списке поддержки XanMod"
    fi
    if [[ "$(uname -r)" == *xanmod* ]]; then
        success "Сейчас загружено ядро XanMod"
    else
        warn "Сейчас загружено не XanMod-ядро"
    fi
}

preflight_install() {
    collect_system_info || return 1
    [[ "$OS_ID" == debian || "$OS_ID" == ubuntu ]] || { error "Поддерживаются Debian и Ubuntu"; return 1; }
    [[ "$(uname -m)" == x86_64 ]] || { error "Поддерживается только x86_64"; return 1; }
    codename_supported "$OS_CODENAME" || { error "XanMod не публикует пакеты для '$OS_CODENAME'"; return 1; }
    (( ROOT_FREE_MB >= 2048 )) || { error "В / требуется минимум 2 ГБ свободного места"; return 1; }
    (( BOOT_FREE_MB >= 350 )) || { error "В /boot требуется минимум 350 МБ свободного места"; return 1; }
    [[ "$BOOTLOADER" != unknown ]] || warn "Загрузчик не определён; установка возможна, но автоматическое обновление меню не гарантируется"
    [[ "$SECURE_BOOT" != *enabled* && "$SECURE_BOOT" != *Enabled* ]] || { error "Secure Boot включён. Сначала подготовьте доверенную подпись ядра или отключите Secure Boot"; return 1; }
    if [[ "$DKMS_STATUS" != "not-installed" && "$DKMS_STATUS" != "установлен, модулей нет" ]]; then
        warn "Обнаружены DKMS-модули. Последнее XanMod-ядро может быть с ними несовместимо:"
        printf '%s\n' "$DKMS_STATUS"
        confirm "Продолжить после проверки списка DKMS?" || return 1
    fi
}

cleanup_proxy() {
    rm -f "$APT_PROXY_CONFIG"
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY 2>/dev/null || true
    PROXY_ADDR=""
}

repo_reachable() {
    # The repository root currently answers HTTP 404 while valid APT paths work.
    # Any completed HTTP response proves transport reachability; only connection
    # failures/timeouts should trigger proxy setup.
    curl -sSI --connect-timeout 8 "$XANMOD_KEY_URL" >/dev/null 2>&1 &&
        curl -sSI --connect-timeout 8 "$XANMOD_REPO_URL" >/dev/null 2>&1
}

configure_proxy_interactive() {
    header "Сеть и прокси"
    if repo_reachable; then
        success "Ресурсы XanMod доступны напрямую"
        return 0
    fi
    warn "Ресурсы XanMod недоступны напрямую. ICMP/ping для решения не используется."
    printf 'Введите HTTP/HTTPS-прокси. Полный адрес останется видимым для копирования.\n'
    printf 'Пример: http://login:password@host:port\n\n'
    read -rp "Прокси (Enter — отмена): " PROXY_ADDR
    [[ -n "$PROXY_ADDR" ]] || return 1
    [[ "$PROXY_ADDR" =~ ^https?://[^[:space:]]+$ ]] || { error "Ожидается URL http:// или https:// без пробелов"; return 1; }
    case "$PROXY_ADDR" in
        *\"*|*\\*) error "Кавычки и обратная косая черта в URL должны быть percent-encoded"; return 1 ;;
    esac
    export http_proxy="$PROXY_ADDR" https_proxy="$PROXY_ADDR"
    export HTTP_PROXY="$PROXY_ADDR" HTTPS_PROXY="$PROXY_ADDR"
    no_proxy="localhost,127.0.0.1,::1"
    export no_proxy
    NO_PROXY="$no_proxy"
    export NO_PROXY
    mkdir -p "$(dirname "$APT_PROXY_CONFIG")"
    printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "$PROXY_ADDR" "$PROXY_ADDR" > "$APT_PROXY_CONFIG"
    chmod 600 "$APT_PROXY_CONFIG"
    printf '\n%bТекущий прокси: %s%b\n' "$CYAN" "$PROXY_ADDR" "$NC"
    log "Пользователь настроил авторизованный прокси (полный адрес показан только в интерактивной консоли)"
    repo_reachable || { error "Ресурсы XanMod недоступны и через указанный прокси"; return 1; }
    success "Прокси работает"
}

backup_file() {
    local source="$1" label="$2" stamp target
    [[ -e "$source" ]] || return 0
    stamp=$(date '+%Y%m%d-%H%M%S')
    mkdir -p "$BACKUP_DIR"
    target="$BACKUP_DIR/${label}.${stamp}"
    cp -a "$source" "$target"
    printf '%s\n' "$target"
}

backup_runtime_profile() {
    local stamp target key value
    stamp=$(date '+%Y%m%d-%H%M%S')
    mkdir -p "$BACKUP_DIR"
    target="$BACKUP_DIR/runtime.$stamp"
    while IFS= read -r key; do
        value=$(sysctl -n "$key" 2>/dev/null) || continue
        printf '%s=%s\n' "$key" "$value" >> "$target"
    done < <(profile_keys)
    chmod 600 "$target"
    printf '%s\n' "$target"
}

setup_repository() {
    header "Настройка репозитория XanMod"
    command -v curl >/dev/null 2>&1 || apt-get install -y curl
    command -v gpg >/dev/null 2>&1 || apt-get install -y gnupg
    mkdir -p "$(dirname "$KEYRING_FILE")" "$(dirname "$SOURCE_FILE")"
    backup_file "$KEYRING_FILE" keyring >/dev/null
    backup_file "$SOURCE_FILE" source-list >/dev/null
    local temporary_key
    temporary_key=$(mktemp)
    curl -fsSL "$XANMOD_KEY_URL" -o "$temporary_key"
    gpg --batch --yes --dearmor -o "$KEYRING_FILE" "$temporary_key"
    rm -f "$temporary_key"
    chmod 644 "$KEYRING_FILE"
    printf 'deb [signed-by=%s] %s %s main\n' "$KEYRING_FILE" "$XANMOD_REPO_URL" "$OS_CODENAME" > "$SOURCE_FILE"
    chmod 644 "$SOURCE_FILE"
    apt-get update
    success "Ключ и source list XanMod настроены"
}

available_metapackages() {
    apt-cache pkgnames | grep -E '^linux-xanmod(-(lts|rt|edge))?-x64v[123]$' | sort -u || true
}

recommended_package() {
    local psabi="$1" packages="$2" candidate
    for candidate in "linux-xanmod-lts-$psabi" "linux-xanmod-$psabi" "linux-xanmod-rt-$psabi"; do
        grep -qx "$candidate" <<<"$packages" && { printf '%s\n' "$candidate"; return 0; }
    done
    if [[ "$psabi" == x64v1 ]]; then
        grep -x 'linux-xanmod-lts-x64v1' <<<"$packages" || true
    fi
}

select_package_interactive() {
    local packages recommended choice selected index=1
    packages=$(available_metapackages)
    [[ -n "$packages" ]] || { error "APT не вернул метапакеты XanMod"; return 1; }
    recommended=$(recommended_package "$PSABI_LEVEL" "$packages")
    [[ -n "$recommended" ]] || { error "Нет пакета, совместимого с $PSABI_LEVEL"; return 1; }
    header "Выбор ядра"
    printf 'Для стабильного VLESS TCP сервера рекомендуется LTS: %b%s%b\n\n' "$GREEN" "$recommended" "$NC"
    local compatible=()
    while IFS= read -r selected; do
        [[ "$selected" == *"-$PSABI_LEVEL" ]] || continue
        compatible+=("$selected")
        printf '%d) %s%s\n' "$index" "$selected" "$([[ "$selected" == "$recommended" ]] && echo ' (рекомендуется)')"
        index=$((index + 1))
    done <<<"$packages"
    printf '0) Отмена\n'
    read -rp "Выберите пакет [по умолчанию рекомендуемый]: " choice
    if [[ -z "$choice" ]]; then
        SELECTED_PACKAGE="$recommended"
    elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#compatible[@]} )); then
        SELECTED_PACKAGE="${compatible[choice-1]}"
    else
        return 1
    fi
}

save_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    printf 'installed_package=%q\nprevious_kernel=%q\ninstalled_at=%q\n' "$1" "$(uname -r)" "$(date -Is)" > "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

install_kernel_interactive() {
    require_root || return 1
    preflight_install || return 1
    configure_proxy_interactive || return 1
    setup_repository || return 1
    local package
    SELECTED_PACKAGE=""
    select_package_interactive || { warn "Установка отменена"; return 0; }
    package="$SELECTED_PACKAGE"
    header "Подтверждение установки"
    printf 'Пакет:              %s\n' "$package"
    printf 'Текущее ядро:       %s (будет сохранено)\n' "$(uname -r)"
    printf 'Загрузчик:          %s\n' "$BOOTLOADER"
    printf 'Профиль сети:       будет применён только после загрузки XanMod\n'
    confirm "Установить выбранное ядро?" || return 0
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
    if [[ "$BOOTLOADER" == grub ]] && command -v update-grub >/dev/null 2>&1; then
        update-grub
    fi
    save_state "$package"
    success "Пакет установлен. Старое ядро не удалено."
    warn "Профиль VLESS TCP Stable ещё не применён: сначала нужно загрузить новое ядро."
    if confirm "Перезагрузить сервер сейчас? Убедитесь, что доступна консоль провайдера"; then
        cleanup_proxy
        reboot
    else
        printf 'Перезагрузите сервер позже и снова откройте это интерактивное меню.\n'
    fi
}

buffer_limit_for_ram() {
    local ram_mb="$1"
    # MemTotal is lower than nominal VM RAM because firmware/kernel reserve memory.
    if (( ram_mb < 768 )); then printf '%s\n' 8388608
    elif (( ram_mb < 3584 )); then printf '%s\n' 16777216
    elif (( ram_mb < 7680 )); then printf '%s\n' 33554432
    else printf '%s\n' 67108864
    fi
}

local_port_range_for_proxy() {
    local low high
    read -r low high < <(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || printf '32768 60999\n')
    [[ "$low" =~ ^[0-9]+$ ]] || low=32768
    [[ "$high" =~ ^[0-9]+$ ]] || high=60999
    (( low > 10240 )) && low=10240
    (( high < 65535 )) && high=65535
    printf '%s %s\n' "$low" "$high"
}

max_current_or() {
    local key="$1" wanted="$2" current
    current=$(sysctl -n "$key" 2>/dev/null || echo 0)
    [[ "$current" =~ ^[0-9]+$ ]] || current=0
    (( current > wanted )) && printf '%s\n' "$current" || printf '%s\n' "$wanted"
}

render_vless_profile() {
    local ram_mb="$1" buffer somax synbacklog port_range
    buffer=$(buffer_limit_for_ram "$ram_mb")
    somax=$(max_current_or net.core.somaxconn 16384)
    synbacklog=$(max_current_or net.ipv4.tcp_max_syn_backlog 16384)
    port_range=$(local_port_range_for_proxy)
    cat <<EOF
# Server_scripts: VLESS TCP Stable
# Generated: $(date -Is)
# Designed for Xray/VLESS RAW(TCP) with TLS or REALITY.
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_syncookies=1
net.core.somaxconn=$somax
net.ipv4.tcp_max_syn_backlog=$synbacklog
net.ipv4.ip_local_port_range=$port_range
net.core.rmem_max=$buffer
net.core.wmem_max=$buffer
net.ipv4.tcp_rmem=4096 131072 $buffer
net.ipv4.tcp_wmem=4096 16384 $buffer
EOF
}

validate_profile_keys() {
    local file="$1" key missing=0
    while IFS='=' read -r key _; do
        [[ "$key" =~ ^[[:space:]]*# || -z "${key// }" ]] && continue
        key="${key//[[:space:]]/}"
        sysctl -n "$key" >/dev/null 2>&1 || { error "Ядро не поддерживает sysctl: $key"; missing=1; }
    done < "$file"
    (( missing == 0 ))
}

apply_vless_profile() {
    require_root || return 1
    collect_system_info || return 1
    [[ "$(uname -r)" == *xanmod* ]] || { error "Сначала загрузите установленное ядро XanMod"; return 1; }
    local temporary backup="" legacy_backup="" runtime_backup transaction had_profile=0
    modprobe tcp_bbr 2>/dev/null || true
    sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr || { error "Загруженное ядро не предоставляет BBR"; return 1; }
    temporary=$(mktemp)
    render_vless_profile "$RAM_MB" > "$temporary"
    validate_profile_keys "$temporary" || { rm -f "$temporary"; return 1; }
    header "Профиль VLESS TCP Stable"
    cat "$temporary"
    printf '\nПрофиль не меняет keepalive, TIME_WAIT, FIN timeout, ECN, busy_poll или глобальные default-буферы.\n'
    confirm "Применить этот профиль?" || { rm -f "$temporary"; return 0; }
    runtime_backup=$(backup_runtime_profile)
    log "Снимок прежних runtime sysctl: $runtime_backup"
    if [[ -e "$SYSCTL_CONFIG" ]]; then backup=$(backup_file "$SYSCTL_CONFIG" sysctl); had_profile=1; fi
    [[ ! -e "$LEGACY_SYSCTL_CONFIG" ]] || legacy_backup=$(backup_file "$LEGACY_SYSCTL_CONFIG" legacy-sysctl)
    transaction="$BACKUP_DIR/profile-state.$(date '+%Y%m%d-%H%M%S')"
    printf 'had_profile=%s\nprofile_backup=%s\nlegacy_backup=%s\nruntime_backup=%s\n' \
        "$had_profile" "$backup" "$legacy_backup" "$runtime_backup" > "$transaction"
    chmod 0600 "$transaction"
    install -m 0644 "$temporary" "$SYSCTL_CONFIG"
    rm -f "$temporary" "$LEGACY_SYSCTL_CONFIG"
    if ! sysctl --system >>"$LOG_FILE" 2>&1; then
        error "Применение sysctl завершилось ошибкой"
        if (( had_profile == 1 )); then cp -a "$backup" "$SYSCTL_CONFIG"; else rm -f "$SYSCTL_CONFIG"; fi
        [[ -z "$legacy_backup" ]] || cp -a "$legacy_backup" "$LEGACY_SYSCTL_CONFIG"
        sysctl -p "$runtime_backup" >>"$LOG_FILE" 2>&1 || true
        rm -f "$transaction"
        return 1
    fi
    success "Профиль применён"
    verify_configuration
}

verify_configuration() {
    header "Проверка XanMod и VLESS TCP"
    local kernel cc qdisc available profile="нет" xray_status live_qdisc
    kernel=$(uname -r)
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)
    xray_status=$(systemctl is-active xray 2>/dev/null || true)
    [[ -n "$xray_status" ]] || xray_status="не-найден"
    live_qdisc=$(tc qdisc show 2>/dev/null | awk '$2 != "noqueue" {print $2; exit}')
    [[ -n "$live_qdisc" ]] || live_qdisc="unknown"
    [[ -f "$SYSCTL_CONFIG" ]] && profile="да"
    printf 'Ядро:                %s\n' "$kernel"
    printf 'Доступные CC:         %s\n' "$available"
    printf 'Активный CC:          %s\n' "$cc"
    printf 'Qdisc по умолчанию:   %s\n' "$qdisc"
    printf 'Профиль установлен:   %s\n' "$profile"
    printf 'Qdisc интерфейса:     %s\n' "$live_qdisc"
    printf 'Xray:                 %s\n' "$xray_status"
    printf 'Failed services:      %s\n' "$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')"
    printf 'Socket summary:\n'; ss -s 2>/dev/null || true
    if [[ "$kernel" == *xanmod* && "$cc" == bbr && "$qdisc" == fq && "$live_qdisc" == fq ]]; then
        success "XanMod + BBR + fq активны, включая очередь интерфейса"
    elif [[ "$kernel" == *xanmod* && "$cc" == bbr && "$qdisc" == fq ]]; then
        warn "Параметры активны, но существующий интерфейс ещё использует '$live_qdisc'; после перезагрузки ожидается fq"
    else
        warn "Конфигурация ещё не соответствует профилю VLESS TCP Stable"
    fi
}

rollback_profile() {
    require_root || return 1
    header "Откат сетевого профиля"
    [[ -f "$SYSCTL_CONFIG" ]] || { warn "Активный профиль не найден"; return 0; }
    local backups selected runtime_backup transaction had_profile legacy_backup profile_backup
    transaction=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'profile-state.*' 2>/dev/null | sort -r | head -n1 || true)
    if [[ -n "$transaction" ]]; then
        had_profile=$(awk -F= '$1=="had_profile" {print $2}' "$transaction")
        profile_backup=$(awk -F= '$1=="profile_backup" {sub(/^[^=]*=/, ""); print}' "$transaction")
        legacy_backup=$(awk -F= '$1=="legacy_backup" {sub(/^[^=]*=/, ""); print}' "$transaction")
        runtime_backup=$(awk -F= '$1=="runtime_backup" {sub(/^[^=]*=/, ""); print}' "$transaction")
        printf 'Будет восстановлена транзакция: %s\n' "$transaction"
        confirm "Откатить последнее применение профиля?" || return 0
        if [[ "$had_profile" == 1 ]]; then cp -a "$profile_backup" "$SYSCTL_CONFIG"; else rm -f "$SYSCTL_CONFIG"; fi
        if [[ -n "$legacy_backup" ]]; then cp -a "$legacy_backup" "$LEGACY_SYSCTL_CONFIG"; else rm -f "$LEGACY_SYSCTL_CONFIG"; fi
        sysctl --system >>"$LOG_FILE" 2>&1
        sysctl -p "$runtime_backup" >>"$LOG_FILE" 2>&1
        mv "$transaction" "$transaction.restored"
        success "Прежний профиль и runtime-значения восстановлены из транзакции."
        return 0
    fi
    backups=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'sysctl.*' 2>/dev/null | sort -r || true)
    if [[ -n "$backups" ]]; then
        selected=$(head -n1 <<<"$backups")
        printf 'Будет восстановлена копия: %s\n' "$selected"
        confirm "Восстановить предыдущий профиль?" || return 0
        cp -a "$selected" "$SYSCTL_CONFIG"
    else
        warn "Предыдущей копии нет. Файл профиля будет удалён, затем применятся остальные sysctl-файлы."
        confirm "Удалить профиль VLESS TCP Stable?" || return 0
        rm -f "$SYSCTL_CONFIG"
    fi
    sysctl --system >>"$LOG_FILE" 2>&1
    runtime_backup=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'runtime.*' 2>/dev/null | sort -r | head -n1 || true)
    if [[ -n "$runtime_backup" ]]; then
        sysctl -p "$runtime_backup" >>"$LOG_FILE" 2>&1
        success "Прежние runtime-значения восстановлены из $runtime_backup"
    else
        warn "Снимок прежних runtime-значений отсутствует; для полного возврата потребуется перезагрузка"
    fi
    success "Сетевой профиль откачен. Пакеты ядра не удалялись."
}

show_proxy() {
    header "Текущий временный прокси"
    if [[ -n "$PROXY_ADDR" ]]; then
        printf '%b%s%b\n' "$CYAN" "$PROXY_ADDR" "$NC"
    elif [[ -r "$APT_PROXY_CONFIG" ]]; then
        cat "$APT_PROXY_CONFIG"
    else
        printf 'Прокси установщика не настроен.\n'
    fi
}

main_menu() {
    while true; do
        clear
        printf '%b=== XanMod для VLESS TCP, версия %s ===%b\n\n' "$BLUE" "$SCRIPT_VERSION" "$NC"
        printf '1) Диагностика системы (без изменений)\n'
        printf '2) Установить или обновить XanMod\n'
        printf '3) Применить профиль VLESS TCP Stable\n'
        printf '4) Проверить ядро, BBR, fq и Xray\n'
        printf '5) Откатить сетевой профиль\n'
        printf '6) Показать текущий прокси\n'
        printf '7) Показать план аварийного возврата к старому ядру\n'
        printf '0) Выход\n\n'
        local choice
        read -rp "Выберите действие: " choice
        case "$choice" in
            1) show_system_report || true; pause ;;
            2) install_kernel_interactive || true; pause ;;
            3) apply_vless_profile || true; pause ;;
            4) verify_configuration || true; pause ;;
            5) rollback_profile || true; pause ;;
            6) show_proxy || true; pause ;;
            7)
                header "Аварийный возврат к старому ядру"
                printf '1. Откройте консоль провайдера до перезагрузки.\n'
                printf '2. В меню загрузчика выберите сохранённое предыдущее ядро.\n'
                printf '3. После загрузки подтвердите его командой: uname -r\n'
                printf '4. Только затем удаляйте выбранный XanMod-метапакет через apt.\n'
                printf 'Установщик намеренно не удаляет ядра автоматически.\n'
                if [[ -r "$STATE_FILE" ]]; then
                    printf '\nСостояние последней установки:\n'
                    cat "$STATE_FILE"
                fi
                pause
                ;;
            0) break ;;
            *) warn "Неизвестный пункт"; sleep 1 ;;
        esac
    done
}

on_exit() { cleanup_proxy; }

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if (( EUID != 0 )); then
        printf 'Запустите скрипт с правами root: sudo ./install_xanmod.sh\n' >&2
        exit 1
    fi
    init_runtime
    trap on_exit EXIT
    main_menu
fi
