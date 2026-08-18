#!/usr/bin/env bash
# Version: 2.0.0
# Official references checked 2026-08-14:
# https://manpages.debian.org/unstable/apt/apt-get.8.en.html
# https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html
set -Eeuo pipefail

readonly VERSION="2.0.0"
readonly RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' NC='\033[0m'
readonly CONFIG_FILE="/etc/server-scripts-update.conf"
readonly RUNNER_FILE="/usr/local/sbin/server-scripts-update-runner"
readonly SERVICE_FILE="/etc/systemd/system/server-scripts-update.service"
readonly TIMER_FILE="/etc/systemd/system/server-scripts-update.timer"
readonly LOCK_FILE="/run/lock/server-scripts-update.lock"
readonly BACKUP_ROOT="/var/backups/server-scripts/package-update"
readonly LEGACY_CRON="/etc/cron.d/auto_update_vps"
readonly LEGACY_RUNNER="/usr/local/sbin/auto_update_script.sh"
readonly LEGACY_CONFIG="/etc/auto_update_vps.conf"
readonly LEGACY_APT_CONFIG="/etc/apt/apt.conf.d/99auto-update"

print_header() { printf '\n%b=== %s ===%b\n\n' "$BLUE" "$1" "$NC"; }
print_step() { printf '%b→%b %s\n' "$YELLOW" "$NC" "$1"; }
print_success() { printf '%b✓%b %s\n' "$GREEN" "$NC" "$1"; }
print_warning() { printf '%b!%b %s\n' "$YELLOW" "$NC" "$1"; }
print_error() { printf '%b✗%b %s\n' "$RED" "$NC" "$1" >&2; }
pause_menu() { read -r -p "Нажмите Enter для продолжения..." _ || true; }
confirm() { local answer; read -r -p "$1 [y/N]: " answer || return 1; [[ "$answer" =~ ^[Yy]$ ]]; }

require_root() { (( EUID == 0 )) || { print_error "Запустите модуль от root."; exit 1; }; }
require_supported_system() {
    [[ -r /etc/os-release ]] || { print_error "Не найден /etc/os-release."; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in debian|ubuntu) ;; *) print_error "Поддерживаются Debian и Ubuntu (обнаружено: ${ID:-неизвестно})."; return 1 ;; esac
    command -v apt-get >/dev/null && command -v dpkg >/dev/null && command -v flock >/dev/null || {
        print_error "Нужны apt-get, dpkg и flock."; return 1;
    }
}

with_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    flock -n 9 || { print_error "Другая операция обновления уже выполняется."; return 1; }
    "$@"
}

preflight() {
    if [[ -e "$LEGACY_APT_CONFIG" ]]; then
        print_error "Найден старый $LEGACY_APT_CONFIG с небезопасными глобальными параметрами APT."
        print_error "Сначала выберите пункт меню «Обезвредить старую версию»."
        return 1
    fi
    print_step "Проверка dpkg, зависимостей и свободного места"
    local audit; audit="$(dpkg --audit 2>&1 || true)"
    [[ -z "$audit" ]] || { print_error "dpkg сообщает о незавершённых операциях:"; printf '%s\n' "$audit"; return 1; }
    apt-get check
    df -h / /boot 2>/dev/null || df -h /
}

create_snapshot() {
    local dir
    dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
    install -d -m 0700 "$dir"
    dpkg-query -W -f='${binary:Package}\t${Version}\n' > "$dir/packages.tsv"
    apt-mark showmanual > "$dir/manual-packages.txt"
    apt-mark showhold > "$dir/held-packages.txt"
    uname -a > "$dir/running-kernel.txt"
    find /boot -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort > "$dir/boot-files.txt" || true
    systemctl --failed --no-legend > "$dir/failed-units-before.txt" 2>/dev/null || true
    printf '%s\n' "$dir"
}

simulation() {
    case "$1" in
        safe) apt-get -s upgrade --with-new-pkgs --no-remove ;;
        expanded) apt-get -s dist-upgrade --no-remove ;;
        autoremove) apt-get -s autoremove ;;
        *) return 2 ;;
    esac
}
simulation_removals() { sed -n 's/^Remv \([^ ]*\).*/\1/p'; }

is_protected_package() {
    local p="${1%%:*}"
    case "$p" in
        linux-image-*|linux-headers-*|linux-modules-*|linux-xanmod-*|linux-generic*|linux-virtual*|grub*|systemd*|\
        initramfs-tools*|openssh-server|ssh|xray|xray-core|network-manager|netplan.io|ifupdown) return 0 ;;
        *) return 1 ;;
    esac
}

check_protected_removals() {
    local p found=0
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if is_protected_package "$p"; then print_error "План предлагает удалить защищённый пакет: $p"; found=1; fi
    done
    (( found == 0 ))
}

service_state() { systemctl is-active --quiet "$1" 2>/dev/null && printf active || printf inactive; }
postflight() {
    local ssh_before="$1" xray_before="$2" failed=0
    print_step "Контроль после обновления"
    [[ -z "$(dpkg --audit 2>&1 || true)" ]] || failed=1
    apt-get check || failed=1
    if [[ "$ssh_before" == active ]] && ! systemctl is-active --quiet ssh 2>/dev/null && ! systemctl is-active --quiet sshd 2>/dev/null; then
        print_error "SSH был активен, но теперь неактивен. Не закрывайте текущую сессию."; failed=1
    fi
    if [[ "$xray_before" == active ]] && ! systemctl is-active --quiet xray 2>/dev/null; then
        print_error "Xray был активен, но теперь неактивен."; failed=1
    fi
    ip route show default || { print_error "Не найден маршрут по умолчанию."; failed=1; }
    getent ahosts deb.debian.org >/dev/null 2>&1 || getent ahosts archive.ubuntu.com >/dev/null 2>&1 || {
        print_warning "Не удалось подтвердить DNS через стандартные архивы."; failed=1;
    }
    systemctl --failed --no-pager 2>/dev/null || true
    [[ ! -e /var/run/reboot-required ]] || print_warning "Требуется ручная перезагрузка; автоматически она не выполняется."
    (( failed == 0 ))
}

legacy_present() {
    [[ -e "$LEGACY_CRON" || -e "$LEGACY_RUNNER" || -e "$LEGACY_CONFIG" || -e "$LEGACY_APT_CONFIG" ]]
}

disable_legacy() {
    legacy_present || { print_success "Файлы старой версии не найдены."; return 0; }
    print_warning "Будут отключены старый cron, runner и глобальный APT force-yes. Старый журнал сохранится."
    confirm "Создать резервную копию и отключить старую версию?" || return 0
    local dir file
    dir="$BACKUP_ROOT/legacy-$(date +%Y%m%d-%H%M%S)"
    install -d -m 0700 "$dir"
    for file in "$LEGACY_CRON" "$LEGACY_RUNNER" "$LEGACY_CONFIG" "$LEGACY_APT_CONFIG"; do
        if [[ -e "$file" ]]; then
            cp -a "$file" "$dir/"
            rm -f "$file"
        fi
    done
    print_success "Старая версия отключена. Резервная копия: $dir"
}

perform_update() {
    local mode="$1" plan backup ssh_before xray_before
    preflight || return 1
    print_step "Обновление индексов APT"; apt-get update
    plan="$(simulation "$mode")" || { print_error "APT не смог построить план."; return 1; }
    printf '\n%s\n' "$plan"
    check_protected_removals < <(printf '%s\n' "$plan" | simulation_removals) || {
        print_error "Операция заблокирована."; return 1;
    }
    grep -qE '^(Inst|Remv|Conf) ' <<< "$plan" || { print_success "Доступных обновлений нет."; return 0; }
    confirm "Применить этот план без autoremove и перезагрузки?" || { print_warning "Отменено."; return 0; }
    backup="$(create_snapshot)"; print_success "Снимок состояния: $backup"
    ssh_before="$(service_state ssh)"; [[ "$ssh_before" == active ]] || ssh_before="$(service_state sshd)"
    xray_before="$(service_state xray)"
    export DEBIAN_FRONTEND=noninteractive
    case "$mode" in
        safe) apt-get upgrade --with-new-pkgs --no-remove -y -o Dpkg::Options::=--force-confold ;;
        expanded) apt-get dist-upgrade --no-remove -y -o Dpkg::Options::=--force-confold ;;
    esac
    postflight "$ssh_before" "$xray_before"
}

show_status() {
    print_header "Состояние сервера"
    # shellcheck disable=SC1091
    . /etc/os-release
    printf 'Система: %s\nЯдро: %s\nПерезагрузка: %s\nТаймер: %s\n' "${PRETTY_NAME:-неизвестно}" "$(uname -r)" \
        "$([[ -e /var/run/reboot-required ]] && echo требуется || echo 'не требуется')" \
        "$(systemctl is-enabled server-scripts-update.timer 2>/dev/null || echo 'не настроен')"
    printf '\nОбновления по текущим индексам:\n'
    apt-get -s upgrade --with-new-pkgs --no-remove 2>/dev/null | grep '^Inst ' || echo "  не найдены или индексы устарели"
    printf '\nСлужбы с ошибками:\n'; systemctl --failed --no-pager 2>/dev/null || true
    df -h / /boot 2>/dev/null || df -h /
}

show_autoremove_plan() {
    print_header "Только просмотр autoremove"
    print_warning "Модуль никогда не запускает autoremove автоматически."
    local plan removals; plan="$(simulation autoremove)"; printf '%s\n' "$plan"
    removals="$(printf '%s\n' "$plan" | simulation_removals)"
    [[ -z "$removals" ]] || check_protected_removals <<< "$removals" || print_warning "Удаление заблокировано."
}

valid_time() { [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; }
calendar_for_period() {
    case "$1" in
        daily) printf '*-*-* %s:00' "$2" ;;
        weekly) printf 'Sun *-*-* %s:00' "$2" ;;
        monthly) printf '*-*-01 %s:00' "$2" ;;
        *) return 1 ;;
    esac
}

install_scheduler() {
    command -v systemctl >/dev/null || { print_error "systemd не найден."; return 1; }
    legacy_present && { print_error "Сначала обезвредьте старую версию через пункт 9."; return 1; }
    print_header "Расписание безопасных обновлений"
    echo "1. Ежедневно"; echo "2. Еженедельно (рекомендуется)"; echo "3. Ежемесячно"
    local choice period time mode calendar
    read -r -p "Период [1-3]: " choice
    case "$choice" in 1) period=daily ;; 2) period=weekly ;; 3) period=monthly ;; *) print_error "Неверный выбор."; return 1 ;; esac
    read -r -p "Время ЧЧ:ММ [03:00]: " time; time="${time:-03:00}"
    valid_time "$time" || { print_error "Неверное время."; return 1; }
    echo "1. Только проверять (рекомендуется)"; echo "2. Устанавливать без удаления пакетов"
    read -r -p "Режим [1-2]: " choice
    case "$choice" in 1) mode=check ;; 2) mode=upgrade ;; *) print_error "Неверный выбор."; return 1 ;; esac
    [[ "$mode" == check ]] || confirm "Разрешить плановую установку без reboot и autoremove?" || return 0
    calendar="$(calendar_for_period "$period" "$time")"
    install -d -m 0755 "$(dirname "$RUNNER_FILE")"
    cat > "$RUNNER_FILE" <<'RUNNER'
#!/usr/bin/env bash
set -Eeuo pipefail
exec 9>/run/lock/server-scripts-update.lock
flock -n 9 || exit 0
mode="${1:-check}"
apt-get update
apt-get check
case "$mode" in
 check) apt-get -s upgrade --with-new-pkgs --no-remove ;;
 upgrade)
  backup="/var/backups/server-scripts/package-update/scheduled-$(date +%Y%m%d-%H%M%S)"
  install -d -m 0700 "$backup"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' > "$backup/packages.tsv"
  apt-mark showmanual > "$backup/manual-packages.txt"
  apt-mark showhold > "$backup/held-packages.txt"
  uname -a > "$backup/running-kernel.txt"
  ssh_before=inactive; xray_before=inactive
  systemctl is-active --quiet ssh 2>/dev/null && ssh_before=active || true
  systemctl is-active --quiet sshd 2>/dev/null && ssh_before=active || true
  systemctl is-active --quiet xray 2>/dev/null && xray_before=active || true
  export DEBIAN_FRONTEND=noninteractive
  apt-get upgrade --with-new-pkgs --no-remove -y -o Dpkg::Options::=--force-confold
  test -z "$(dpkg --audit 2>&1 || true)"; apt-get check
  [ "$ssh_before" != active ] || systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd
  [ "$xray_before" != active ] || systemctl is-active --quiet xray
  ip route show default
  systemctl --failed --no-pager || true
  [ ! -e /var/run/reboot-required ] || echo "Требуется ручная перезагрузка."
  ;;
 *) echo "Неизвестный режим: $mode" >&2; exit 2 ;;
esac
RUNNER
    chmod 0755 "$RUNNER_FILE"
    printf 'MODE=%s\nPERIOD=%s\nTIME=%s\n' "$mode" "$period" "$time" > "$CONFIG_FILE"; chmod 0600 "$CONFIG_FILE"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Server Scripts safe APT maintenance
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$RUNNER_FILE $mode
EOF
    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Schedule Server Scripts safe APT maintenance
[Timer]
OnCalendar=$calendar
Persistent=true
RandomizedDelaySec=15m
Unit=server-scripts-update.service
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload; systemctl enable --now server-scripts-update.timer
    systemctl list-timers server-scripts-update.timer --no-pager
    print_success "Расписание установлено. Автоматические reboot и autoremove отключены."
}

disable_scheduler() {
    systemctl disable --now server-scripts-update.timer 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$TIMER_FILE" "$RUNNER_FILE" "$CONFIG_FILE"
    systemctl daemon-reload 2>/dev/null || true
    print_success "Расписание удалено; журнал сохранён."
}
view_logs() { journalctl -u server-scripts-update.service -n 150 --no-pager 2>/dev/null || print_warning "Журнал пуст."; }
manual_reboot() {
    [[ -e /var/run/reboot-required ]] || { print_warning "Перезагрузка не требуется."; return 0; }
    print_warning "SSH-сессия будет разорвана. Убедитесь, что доступна консоль провайдера."
    if confirm "Перезагрузить сейчас?"; then systemctl reboot; fi
}

main_menu() {
    require_root; require_supported_system
    while true; do
        print_header "Безопасное обновление VPS v$VERSION"
        echo "1. Состояние и доступные обновления"
        echo "2. Безопасное обновление (рекомендуется)"
        echo "3. Расширенное обновление без удаления пакетов"
        echo "4. Просмотреть autoremove (без выполнения)"
        echo "5. Настроить расписание systemd"
        echo "6. Показать журнал расписания"
        echo "7. Отключить расписание"
        echo "8. Ручная перезагрузка, если требуется"
        echo "9. Обезвредить старую версию (cron / force-yes)"
        echo "0. Назад"
        legacy_present && print_warning "Обнаружены активные файлы старого автообновления. Выберите пункт 9."
        local choice; read -r -p "Действие [0-9]: " choice
        case "$choice" in
            1) show_status ;; 2) with_lock perform_update safe || true ;;
            3) print_warning "APT остановится при попытке удалить любой пакет."; with_lock perform_update expanded || true ;;
            4) show_autoremove_plan || true ;; 5) install_scheduler || true ;; 6) view_logs ;;
            7) if confirm "Удалить расписание?"; then disable_scheduler; fi ;; 8) manual_reboot ;; 9) disable_legacy ;; 0) return 0 ;;
            *) print_error "Неверный выбор." ;;
        esac
        echo; pause_menu
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main_menu "$@"; fi
