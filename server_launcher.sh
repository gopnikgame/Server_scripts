#!/usr/bin/env bash

set -Eeuo pipefail

# Version: 2.0.0
# Description: Transactional launcher and module snapshot manager for Ubuntu 24.04

SCRIPT_VERSION='2.0.0'
SCRIPT_NAME='server_launcher.sh'
SCRIPT_DIR="${SERVER_SCRIPTS_SCRIPT_DIR:-/root/server-scripts}"
MODULES_DIR="${SERVER_SCRIPTS_MODULES_DIR:-/usr/local/server-scripts/modules}"
LOG_DIR="${SERVER_SCRIPTS_LOG_DIR:-/var/log/server-scripts}"
STATE_DIR="${SERVER_SCRIPTS_STATE_DIR:-/var/lib/server-scripts}"
BACKUP_ROOT="${SERVER_SCRIPTS_BACKUP_ROOT:-/var/backups/server-scripts/launcher}"
BIN_LINK="${SERVER_SCRIPTS_BIN_LINK:-/usr/local/bin/server_launcher.sh}"
LOCK_FILE="${SERVER_SCRIPTS_LOCK_FILE:-/run/lock/server-scripts-launcher.lock}"
REPOSITORY_BRANCH="${SERVER_SCRIPTS_BRANCH:-main}"
GITHUB_API="${SERVER_SCRIPTS_GITHUB_API:-https://api.github.com/repos/gopnikgame/Server_scripts}"
GITHUB_RAW="${SERVER_SCRIPTS_GITHUB_RAW:-https://raw.githubusercontent.com/gopnikgame/Server_scripts}"
readonly SCRIPT_VERSION SCRIPT_NAME SCRIPT_DIR MODULES_DIR LOG_DIR STATE_DIR BACKUP_ROOT BIN_LINK LOCK_FILE
readonly REPOSITORY_BRANCH GITHUB_API GITHUB_RAW

MODULE_ORDER=(
    ubuntu_pre_install.sh
    setup_proxy.sh
    install_xanmod.sh
    bbr_info.sh
    snapfile.sh
    speed_dns.sh
    auto_update_vps.sh
)
readonly MODULE_ORDER

declare -A MODULES=(
    [ubuntu_pre_install.sh]='Первоначальная настройка Ubuntu 24.04'
    [setup_proxy.sh]='Настройка прокси сервера (HTTP / SSH+Privoxy / VPN / VLESS)'
    [install_xanmod.sh]='Установка XanMod Kernel с BBR3'
    [bbr_info.sh]='Проверка и настройка конфигурации BBR'
    [snapfile.sh]='Управление файлом подкачки (Swap)'
    [speed_dns.sh]='Диагностика DNS'
    [auto_update_vps.sh]='Автоматическое обновление VPS'
)
readonly MODULES

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi
readonly RED GREEN YELLOW BLUE NC
DOWNLOAD_CHANNEL='auto'

print_header() { printf '\n%b========== %s ==========%b\n\n' "$BLUE" "$1" "$NC"; }
print_step() { printf '%b➜%b %s\n' "$YELLOW" "$NC" "$1"; }
print_success() { printf '%b✔%b %s\n' "$GREEN" "$NC" "$1"; }
print_error() { printf '%b✘%b %s\n' "$RED" "$NC" "$1" >&2; }

log() {
    local level="$1"; shift
    install -d -m 0750 -- "$LOG_DIR"
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >> "$LOG_DIR/server-scripts.log"
}

check_root() {
    (( EUID == 0 )) || { print_error 'Этот скрипт должен быть запущен с правами root'; return 1; }
}

validate_paths() {
    local path
    for path in "$SCRIPT_DIR" "$MODULES_DIR" "$LOG_DIR" "$STATE_DIR" "$BACKUP_ROOT" "$BIN_LINK" "$LOCK_FILE"; do
        [[ "$path" == /* && "$path" != / ]] || { print_error "Недопустимый системный путь: $path"; return 1; }
    done
    for path in "$SCRIPT_DIR" "$MODULES_DIR" "$LOG_DIR" "$STATE_DIR" "$BACKUP_ROOT"; do
        [[ $(realpath -m -- "$path") == "$path" ]] || { print_error "Путь содержит переход или символическую ссылку: $path"; return 1; }
    done
    [[ $(realpath -m -- "$(dirname -- "$BIN_LINK")") == "$(dirname -- "$BIN_LINK")" ]] || {
        print_error "Каталог командной ссылки содержит переход или символическую ссылку: $BIN_LINK"
        return 1
    }
    [[ "$SCRIPT_DIR" != "$MODULES_DIR" ]] || { print_error 'Каталоги launcher и модулей должны различаться'; return 1; }
    for path in "$SCRIPT_DIR" "$MODULES_DIR" "$STATE_DIR" "$BACKUP_ROOT"; do
        [[ ! -L "$path" ]] || { print_error "Символическая ссылка вместо управляемого каталога: $path"; return 1; }
    done
}

create_directories() {
    install -d -m 0755 -- "$SCRIPT_DIR" "$(dirname -- "$MODULES_DIR")"
    install -d -m 0750 -- "$LOG_DIR"
    install -d -m 0700 -- "$STATE_DIR" "$BACKUP_ROOT"
    install -d -m 0755 -- "$(dirname -- "$BIN_LINK")"
    install -d -m 0755 -- "$(dirname -- "$LOCK_FILE")"
}

check_dependencies() {
    local -A command_packages=(
        [awk]=mawk [bash]=bash [cmp]=diffutils [cp]=coreutils [curl]=curl [env]=coreutils
        [flock]=util-linux [grep]=grep [install]=coreutils [mktemp]=coreutils
        [modinfo]=kmod [realpath]=coreutils [sed]=sed [sysctl]=procps
    )
    local command_name package
    local -a missing_commands=() missing_packages=()

    print_header 'ПРОВЕРКА ЗАВИСИМОСТЕЙ'
    for command_name in "${!command_packages[@]}"; do
        if command -v "$command_name" >/dev/null 2>&1; then
            print_success "$command_name найден"
        else
            print_error "$command_name не найден"
            missing_commands+=("$command_name")
            package="${command_packages[$command_name]}"
            if [[ ! " ${missing_packages[*]} " =~ [[:space:]]${package}[[:space:]] ]]; then
                missing_packages+=("$package")
            fi
        fi
    done
    (( ${#missing_commands[@]} == 0 )) && return 0
    [[ -r /etc/os-release ]] || { print_error 'Не удалось определить ОС'; return 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || {
        print_error 'Автоматическая установка зависимостей поддерживается только на Ubuntu 24.04'
        return 1
    }
    print_step "Установка пакетов: ${missing_packages[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_packages[@]}"
    for command_name in "${missing_commands[@]}"; do
        command -v "$command_name" >/dev/null 2>&1 || { print_error "Команда $command_name не появилась после установки"; return 1; }
    done
}

acquire_lock() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || { print_error 'Другой экземпляр launcher уже выполняется'; return 1; }
}

resolve_latest_commit() {
    local response commit
    response=$(curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
        --retry 3 --retry-all-errors --retry-delay 2 \
        -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$GITHUB_API/commits/$REPOSITORY_BRANCH") || return 1
    commit=$(sed -n 's/^[[:space:]]*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' <<< "$response" | head -n 1)
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { print_error "GitHub API не вернул commit для $REPOSITORY_BRANCH"; return 1; }
    printf '%s\n' "$commit"
}

fetch_script() {
    local name="$1" destination="$2" repository_ref="$3"
    [[ "$repository_ref" =~ ^[0-9a-f]{40}$ ]] || { print_error 'Некорректный commit snapshot'; return 2; }
    [[ "$name" =~ ^[a-z0-9_]+\.sh$ ]] || { print_error "Недопустимое имя модуля: $name"; return 2; }
    if [[ "$DOWNLOAD_CHANNEL" != api ]] && curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 90 \
        "$GITHUB_RAW/$repository_ref/$name" --output "$destination"; then
        DOWNLOAD_CHANNEL=raw
    else
        if [[ "$DOWNLOAD_CHANNEL" != api ]]; then
            print_step "Основной raw-канал недоступен; использую GitHub Contents API для snapshot"
        fi
        DOWNLOAD_CHANNEL=api
        if ! curl --fail --silent --show-error --location \
            --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 90 \
            --retry 3 --retry-all-errors --retry-delay 2 \
            -H 'Accept: application/vnd.github.raw+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
            "$GITHUB_API/contents/$name?ref=$repository_ref" --output "$destination"; then
            return 1
        fi
    fi
    [[ -s "$destination" ]] || { print_error "Получен пустой файл: $name"; return 1; }
    bash -n "$destination" || { print_error "$name не прошёл bash -n"; return 1; }
    chmod 0755 -- "$destination"
}

# Совместимый атомарный загрузчик одного файла; полный update использует stage_snapshot.
download_script() {
    local name="$1" destination="$2" repository_ref="$3" temp_dir candidate stage
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/server-scripts-download.XXXXXX") || return 1
    candidate="$temp_dir/$name"
    if ! fetch_script "$name" "$candidate" "$repository_ref"; then
        rm -rf -- "$temp_dir"
        return 1
    fi
    install -d -m 0755 -- "$(dirname -- "$destination")"
    stage=$(mktemp "$(dirname -- "$destination")/.${name}.XXXXXX") || { rm -rf -- "$temp_dir"; return 1; }
    if ! install -m 0755 -- "$candidate" "$stage" || ! mv -f -- "$stage" "$destination"; then
        rm -f -- "$stage"
        rm -rf -- "$temp_dir"
        return 1
    fi
    rm -rf -- "$temp_dir"
}

stage_snapshot() {
    local repository_ref="$1" stage_root="$2" module
    install -d -m 0700 -- "$stage_root/modules"
    print_step "Загрузка launcher из ${repository_ref:0:12}"
    fetch_script "$SCRIPT_NAME" "$stage_root/$SCRIPT_NAME" "$repository_ref" || return 1
    for module in "${MODULE_ORDER[@]}"; do
        print_step "Загрузка $module"
        fetch_script "$module" "$stage_root/modules/$module" "$repository_ref" || return 1
    done
}

validate_snapshot() {
    local stage_root="$1" module version
    version=$(awk '$1 == "#" && $2 == "Version:" {print $3; exit}' "$stage_root/$SCRIPT_NAME")
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { print_error 'Launcher не содержит корректную версию'; return 1; }
    bash -n "$stage_root/$SCRIPT_NAME" || return 1
    for module in "${MODULE_ORDER[@]}"; do
        [[ -s "$stage_root/modules/$module" ]] && bash -n "$stage_root/modules/$module" || return 1
    done
}

snapshot_is_current() {
    local stage_root="$1" module target_launcher="$SCRIPT_DIR/$SCRIPT_NAME"
    [[ -f "$target_launcher" ]] && cmp -s -- "$stage_root/$SCRIPT_NAME" "$target_launcher" || return 1
    [[ -d "$MODULES_DIR" ]] || return 1
    for module in "${MODULE_ORDER[@]}"; do
        [[ -f "$MODULES_DIR/$module" ]] && cmp -s -- "$stage_root/modules/$module" "$MODULES_DIR/$module" || return 1
    done
}

backup_current_snapshot() {
    local repository_ref="$1" timestamp backup_dir
    timestamp=$(date '+%Y%m%d-%H%M%S')
    backup_dir="$BACKUP_ROOT/${timestamp}-${repository_ref:0:12}-$$"
    install -d -m 0700 -- "$backup_dir"
    if [[ -f "$SCRIPT_DIR/$SCRIPT_NAME" ]]; then
        install -p -m 0755 -- "$SCRIPT_DIR/$SCRIPT_NAME" "$backup_dir/$SCRIPT_NAME"
    else
        : > "$backup_dir/launcher.absent"
    fi
    if [[ -d "$MODULES_DIR" ]]; then
        cp -a -- "$MODULES_DIR" "$backup_dir/modules"
    else
        : > "$backup_dir/modules.absent"
    fi
    if [[ -f "$STATE_DIR/snapshot.env" ]]; then
        install -p -m 0600 -- "$STATE_DIR/snapshot.env" "$backup_dir/snapshot.env"
    fi
    printf '%s\n' "$backup_dir"
}

restore_snapshot() {
    local backup_dir="$1"
    print_step "Откат из $backup_dir"
    rm -rf -- "$MODULES_DIR"
    if [[ -d "$backup_dir/modules" ]]; then cp -a -- "$backup_dir/modules" "$MODULES_DIR"; fi
    if [[ -f "$backup_dir/$SCRIPT_NAME" ]]; then
        install -m 0755 -- "$backup_dir/$SCRIPT_NAME" "$SCRIPT_DIR/$SCRIPT_NAME"
    else
        rm -f -- "$SCRIPT_DIR/$SCRIPT_NAME"
    fi
    if [[ -f "$backup_dir/snapshot.env" ]]; then
        install -m 0600 -- "$backup_dir/snapshot.env" "$STATE_DIR/snapshot.env"
    else
        rm -f -- "$STATE_DIR/snapshot.env"
    fi
}

write_snapshot_state() {
    local repository_ref="$1" version="$2" temp_file
    temp_file=$(mktemp "$STATE_DIR/.snapshot.env.XXXXXX") || return 1
    printf 'SNAPSHOT_COMMIT=%s\nLAUNCHER_VERSION=%s\nUPDATED_AT=%q\n' \
        "$repository_ref" "$version" "$(date --iso-8601=seconds)" > "$temp_file"
    chmod 0600 -- "$temp_file"
    mv -f -- "$temp_file" "$STATE_DIR/snapshot.env"
}

activate_snapshot() {
    local stage_root="$1" repository_ref="$2" backup_dir="$3"
    local parent candidate previous='' version target_launcher launcher_stage
    parent=$(dirname -- "$MODULES_DIR")
    candidate=$(mktemp -d "$parent/.modules.candidate.XXXXXX") || return 1
    cp -a -- "$stage_root/modules/." "$candidate/"
    if [[ -d "$MODULES_DIR" ]]; then
        previous=$(mktemp -d "$parent/.modules.previous.XXXXXX") || { rm -rf -- "$candidate"; return 1; }
        rmdir -- "$previous"
        mv -- "$MODULES_DIR" "$previous" || { rm -rf -- "$candidate"; return 1; }
    fi
    if ! mv -- "$candidate" "$MODULES_DIR"; then
        rm -rf -- "$candidate"
        [[ -n "$previous" ]] && mv -- "$previous" "$MODULES_DIR"
        return 1
    fi

    target_launcher="$SCRIPT_DIR/$SCRIPT_NAME"
    launcher_stage=$(mktemp "$SCRIPT_DIR/.${SCRIPT_NAME}.XXXXXX") || {
        restore_snapshot "$backup_dir"; rm -rf -- "$previous"; return 1;
    }
    if ! install -m 0755 -- "$stage_root/$SCRIPT_NAME" "$launcher_stage" || ! mv -f -- "$launcher_stage" "$target_launcher"; then
        rm -f -- "$launcher_stage"
        restore_snapshot "$backup_dir"
        rm -rf -- "$previous"
        return 1
    fi
    version=$(awk '$1 == "#" && $2 == "Version:" {print $3; exit}' "$target_launcher")
    if ! validate_installed_snapshot || ! write_snapshot_state "$repository_ref" "$version"; then
        restore_snapshot "$backup_dir"
        rm -rf -- "$previous"
        return 1
    fi
    rm -rf -- "$previous"
}

validate_installed_snapshot() {
    local module
    bash -n "$SCRIPT_DIR/$SCRIPT_NAME" || return 1
    for module in "${MODULE_ORDER[@]}"; do
        [[ -f "$MODULES_DIR/$module" ]] && bash -n "$MODULES_DIR/$module" || return 1
    done
}

ensure_command_link() {
    local expected="$SCRIPT_DIR/$SCRIPT_NAME"
    if [[ -e "$BIN_LINK" && ! -L "$BIN_LINK" ]]; then
        print_error "$BIN_LINK существует и не является символической ссылкой; файл не изменён"
        return 1
    fi
    ln -sfn -- "$expected" "$BIN_LINK"
}

validate_command_link() {
    if [[ -e "$BIN_LINK" && ! -L "$BIN_LINK" ]]; then
        print_error "$BIN_LINK существует и не является символической ссылкой; обновление отменено"
        return 1
    fi
}

maybe_restart_launcher() {
    local installed="$SCRIPT_DIR/$SCRIPT_NAME"
    [[ -x "$installed" ]] || return 0
    if ! cmp -s -- "$installed" "${BASH_SOURCE[0]}"; then
        print_success 'Launcher обновлён; перезапускаю новую версию'
        exec env SERVER_SCRIPTS_SKIP_REFRESH_ONCE=1 "$installed" --no-refresh
    fi
}

refresh_snapshot() {
    local repository_ref stage_root backup_dir version changed=false
    validate_command_link || return 1
    repository_ref=$(resolve_latest_commit) || { print_error "Не удалось определить свежий commit $REPOSITORY_BRANCH"; return 1; }
    stage_root=$(mktemp -d "${TMPDIR:-/tmp}/server-scripts-snapshot.XXXXXX") || return 1
    chmod 0700 -- "$stage_root"
    if ! stage_snapshot "$repository_ref" "$stage_root" || ! validate_snapshot "$stage_root"; then
        rm -rf -- "$stage_root"
        print_error 'Snapshot не прошёл загрузку или проверку; текущая установка не изменена'
        return 1
    fi
    if snapshot_is_current "$stage_root"; then
        version=$(awk '$1 == "#" && $2 == "Version:" {print $3; exit}' "$stage_root/$SCRIPT_NAME")
        if ! write_snapshot_state "$repository_ref" "$version"; then
            rm -rf -- "$stage_root"
            print_error 'Не удалось записать состояние snapshot'
            return 1
        fi
        rm -rf -- "$stage_root"
        print_success "Уже установлен последний snapshot ${repository_ref:0:12}"
        ensure_command_link || return 1
        return 0
    fi

    backup_dir=$(backup_current_snapshot "$repository_ref") || { rm -rf -- "$stage_root"; return 1; }
    print_step "Резервная копия: $backup_dir"
    if activate_snapshot "$stage_root" "$repository_ref" "$backup_dir"; then
        changed=true
        rm -rf -- "$stage_root"
        ensure_command_link || { print_error 'Snapshot установлен, но командная ссылка не создана'; return 1; }
        log INFO "Активирован snapshot $repository_ref; backup=$backup_dir" || print_error 'Не удалось записать журнал обновления'
        print_success "Snapshot ${repository_ref:0:12} установлен целиком"
    else
        rm -rf -- "$stage_root"
        print_error "Активация не удалась; восстановлен предыдущий snapshot из $backup_dir"
        return 1
    fi
    [[ "$changed" == true ]]
}

# Старое имя оставлено для совместимости с тестами и внешними вызовами.
check_and_download_modules() { refresh_snapshot; }
self_update() { refresh_snapshot; }

show_status() {
    print_header 'СОСТОЯНИЕ SNAPSHOT'
    if [[ -f "$STATE_DIR/snapshot.env" ]]; then
        sed 's/^/  /' "$STATE_DIR/snapshot.env"
    else
        echo '  Состояние ещё не записано.'
    fi
    local module
    for module in "${MODULE_ORDER[@]}"; do
        if [[ -f "$MODULES_DIR/$module" ]]; then print_success "$module"
        else print_error "$module отсутствует"; fi
    done
}

run_module() {
    local module_name="$1"
    [[ "$module_name" =~ ^[a-z0-9_]+\.sh$ ]] || { print_error 'Недопустимое имя модуля'; return 2; }
    if [[ -f "$MODULES_DIR/$module_name" && ! -L "$MODULES_DIR/$module_name" ]]; then
        print_header "ЗАПУСК МОДУЛЯ: $module_name"
        bash "$MODULES_DIR/$module_name"
    else
        print_error "Модуль $module_name не найден или является ссылкой"
        return 1
    fi
}

show_main_menu() {
    while true; do
        print_header "SERVER SCRIPTS MANAGER v$SCRIPT_VERSION"
        local index=1 module choice refresh_index status_index
        for module in "${MODULE_ORDER[@]}"; do
            printf '%d) %b%s%b\n' "$index" "$GREEN" "${MODULES[$module]}" "$NC"
            ((index += 1))
        done
        refresh_index=$index; printf '%d) %bПроверить и обновить весь snapshot%b\n' "$index" "$YELLOW" "$NC"; ((index += 1))
        status_index=$index; printf '%d) Показать состояние snapshot\n' "$index"
        printf '0) %bВыход%b\n\n' "$RED" "$NC"
        read -r -p "Выберите опцию [0-$index]: " choice
        case "$choice" in
            0) print_success 'До свидания!'; return 0 ;;
            "$refresh_index") if refresh_snapshot; then maybe_restart_launcher; fi ;;
            "$status_index") show_status ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice > 0 && choice < refresh_index )); then
                    run_module "${MODULE_ORDER[$((choice - 1))]}" || true
                else
                    print_error 'Неверный выбор'
                fi
                ;;
        esac
        echo
        read -r -p 'Нажмите Enter для продолжения...'
    done
}

usage() {
    cat <<'USAGE'
Использование: server_launcher.sh [--refresh|--status|--no-refresh|--help]
  без аргументов  обновить snapshot и открыть интерактивное меню
  --refresh       обновить launcher и все модули, затем завершить работу
  --status        показать локальное состояние без доступа к сети
  --no-refresh    открыть меню без автоматического обновления
USAGE
}

main() {
    check_root
    validate_paths
    create_directories
    check_dependencies
    acquire_lock
    case "${1:-}" in
        '')
            if [[ "${SERVER_SCRIPTS_SKIP_REFRESH_ONCE:-0}" != 1 ]]; then
                refresh_snapshot || print_error 'Используется последний установленный исправный snapshot'
                maybe_restart_launcher
            fi
            show_main_menu
            ;;
        --refresh) refresh_snapshot ;;
        --status) show_status ;;
        --no-refresh) show_main_menu ;;
        -h|--help) usage ;;
        *) usage >&2; return 2 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
