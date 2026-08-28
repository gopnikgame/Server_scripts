#!/bin/bash

# Version: 2.0.0
# Description: Transactional swap file management module

set -Eeuo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

SCRIPT_VERSION='2.0.0'
SWAPFILE="${SWAPFILE:-/swapfile}"
LOG_FILE="${LOG_FILE:-/var/log/system_setup.log}"
FSTAB_FILE="${FSTAB_FILE:-/etc/fstab}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/server-scripts/swap}"
MIN_FREE_AFTER_MB="${MIN_FREE_AFTER_MB:-256}"
readonly SCRIPT_VERSION SWAPFILE LOG_FILE FSTAB_FILE BACKUP_ROOT MIN_FREE_AFTER_MB

print_header() {
    local title="$1"
    printf '\n%b%s%b\n\n' "$BLUE" "========== $title ==========" "$NC"
}
print_step() { printf '%b➜%b %s\n' "$YELLOW" "$NC" "$1"; }
print_success() { printf '%b✔%b %s\n' "$GREEN" "$NC" "$1"; }
print_error() { printf '%b✘%b %s\n' "$RED" "$NC" "$1" >&2; }

log() {
    local level="$1"; shift
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s [%s] %s\n' "$timestamp" "$level" "$*" | tee -a "$LOG_FILE"
}

confirm() {
    local answer
    read -r -p "$1 [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

check_root() {
    if (( EUID != 0 )); then
        print_error 'Этот скрипт должен быть запущен с правами root'
        return 1
    fi
}

validate_paths() {
    [[ "$SWAPFILE" == /* && "$SWAPFILE" != / ]] || {
        print_error 'Путь к swap должен быть абсолютным и не равным /'
        return 1
    }
    [[ -f "$FSTAB_FILE" && ! -L "$FSTAB_FILE" ]] || {
        print_error "$FSTAB_FILE должен быть обычным файлом, а не символической ссылкой"
        return 1
    }
    if [[ -e "$SWAPFILE" ]]; then
        [[ -f "$SWAPFILE" && ! -L "$SWAPFILE" ]] || {
            print_error "$SWAPFILE должен быть обычным файлом"
            return 1
        }
        [[ $(stat -c %h -- "$SWAPFILE") -eq 1 ]] || {
            print_error "$SWAPFILE имеет дополнительные жесткие ссылки; операция отменена"
            return 1
        }
    fi
    local command_name
    for command_name in awk blkid chmod chown dd df dirname fallocate free grep install mkswap mktemp mv rm stat swapoff swapon; do
        command -v "$command_name" >/dev/null || {
            print_error "Не найдена обязательная команда: $command_name"
            return 1
        }
    done
}

is_swap_active() {
    swapon --noheadings --raw --show=NAME 2>/dev/null | grep -Fxq -- "$SWAPFILE"
}

fstab_has_swap() {
    awk -v path="$SWAPFILE" '$1 == path && $3 == "swap" { found=1 } END { exit !found }' "$FSTAB_FILE"
}

render_fstab_without_swap() {
    awk -v path="$SWAPFILE" 'NF == 0 || $1 != path || $3 != "swap"' "$FSTAB_FILE"
}

backup_fstab() {
    local operation="$1" timestamp backup_dir backup_file
    timestamp=$(date '+%Y%m%d-%H%M%S')
    backup_dir="$BACKUP_ROOT/${timestamp}-${operation}-$$"
    install -d -m 0700 -- "$backup_dir"
    backup_file="$backup_dir/fstab"
    install -p -m "$(stat -c %a -- "$FSTAB_FILE")" -- "$FSTAB_FILE" "$backup_file"
    printf '%s\n' "$backup_file"
}

restore_fstab() {
    local backup_file="$1"
    install -p -m "$(stat -c %a -- "$backup_file")" -- "$backup_file" "$FSTAB_FILE"
}

write_fstab_state() {
    local state="$1" fstab_dir temp_file mode owner group
    fstab_dir=$(dirname -- "$FSTAB_FILE")
    temp_file=$(mktemp "$fstab_dir/.fstab.server-scripts.XXXXXX")
    mode=$(stat -c %a -- "$FSTAB_FILE")
    owner=$(stat -c %u -- "$FSTAB_FILE")
    group=$(stat -c %g -- "$FSTAB_FILE")

    if ! render_fstab_without_swap > "$temp_file"; then
        rm -f -- "$temp_file"
        return 1
    fi
    if [[ "$state" == present ]]; then
        printf '%s none swap sw 0 0\n' "$SWAPFILE" >> "$temp_file"
    fi
    chmod "$mode" "$temp_file"
    chown "$owner:$group" "$temp_file"
    mv -f -- "$temp_file" "$FSTAB_FILE"
}

ensure_fstab_entry() { write_fstab_state present; }
remove_fstab_entry() { write_fstab_state absent; }

available_mb() {
    df -Pm -- "$(dirname -- "$SWAPFILE")" | awk 'NR == 2 { print $4 }'
}

validate_size() {
    local size_mb="$1" free_mb
    if [[ ! "$size_mb" =~ ^[0-9]+$ ]] || (( size_mb <= 0 )); then
        print_error 'Размер должен быть целым числом больше нуля'
        return 1
    fi
    free_mb=$(available_mb)
    if (( size_mb + MIN_FREE_AFTER_MB > free_mb )); then
        print_error "Недостаточно места: доступно ${free_mb} MB, после операции должно остаться не менее ${MIN_FREE_AFTER_MB} MB"
        return 1
    fi
}

allocate_and_enable() {
    local size_mb="$1"
    if ! fallocate -l "${size_mb}M" -- "$SWAPFILE" 2>/dev/null; then
        print_step 'fallocate недоступен; создаю файл через dd'
        dd if=/dev/zero of="$SWAPFILE" bs=1M count="$size_mb" status=progress
    fi
    chmod 0600 -- "$SWAPFILE"
    mkswap -- "$SWAPFILE"
    swapon -- "$SWAPFILE"
}

create_swap() {
    local size_mb="$1" fstab_backup
    [[ ! -e "$SWAPFILE" ]] || { print_error "$SWAPFILE уже существует"; return 1; }
    validate_size "$size_mb" || return 1
    fstab_backup=$(backup_fstab create) || return 1
    print_step "Создание swap размером ${size_mb} MB"
    if allocate_and_enable "$size_mb" && ensure_fstab_entry; then
        log INFO "Swap $SWAPFILE создан и включен; резервная копия: $fstab_backup"
        print_success 'Swap создан, включен и добавлен в fstab'
        return 0
    fi
    print_error 'Создание не завершено; возвращаю исходное состояние'
    if is_swap_active; then swapoff -- "$SWAPFILE" || true; fi
    rm -f -- "$SWAPFILE"
    restore_fstab "$fstab_backup" || true
    return 1
}

enable_existing_swap() {
    local fstab_backup
    [[ -f "$SWAPFILE" ]] || { print_error "$SWAPFILE не найден"; return 1; }
    [[ $(blkid -o value -s TYPE -- "$SWAPFILE" 2>/dev/null) == swap ]] || {
        print_error "$SWAPFILE не содержит корректную сигнатуру swap"
        return 1
    }
    fstab_backup=$(backup_fstab enable) || return 1
    chmod 0600 -- "$SWAPFILE"
    if swapon -- "$SWAPFILE" && ensure_fstab_entry; then
        log INFO "Swap $SWAPFILE включен; резервная копия: $fstab_backup"
        print_success 'Swap включен и добавлен в fstab'
        return 0
    fi
    if is_swap_active; then swapoff -- "$SWAPFILE" || true; fi
    restore_fstab "$fstab_backup" || true
    print_error 'Включение не завершено; fstab восстановлен'
    return 1
}

resize_swap() {
    local new_size_mb="$1" was_active=false fstab_backup transaction_dir old_file
    [[ -f "$SWAPFILE" ]] || { print_error "$SWAPFILE не найден"; return 1; }
    validate_size "$new_size_mb" || return 1
    is_swap_active && was_active=true
    fstab_backup=$(backup_fstab resize) || return 1
    transaction_dir=$(mktemp -d "$(dirname -- "$SWAPFILE")/.swap-rollback.XXXXXX") || return 1
    old_file="$transaction_dir/$(basename -- "$SWAPFILE")"

    print_step "Изменение размера swap на ${new_size_mb} MB"
    if [[ "$was_active" == true ]] && ! swapoff -- "$SWAPFILE"; then
        rmdir -- "$transaction_dir"
        print_error 'Не удалось отключить текущий swap; изменений нет'
        return 1
    fi
    mv -- "$SWAPFILE" "$old_file"
    if allocate_and_enable "$new_size_mb" && ensure_fstab_entry; then
        rm -f -- "$old_file"
        rmdir -- "$transaction_dir"
        log INFO "Swap изменен до ${new_size_mb} MB; резервная копия fstab: $fstab_backup"
        print_success 'Размер swap изменен'
        return 0
    fi

    print_error 'Новый swap не активирован; восстанавливаю прежний'
    if is_swap_active; then swapoff -- "$SWAPFILE" || true; fi
    rm -f -- "$SWAPFILE"
    mv -- "$old_file" "$SWAPFILE"
    rmdir -- "$transaction_dir"
    restore_fstab "$fstab_backup" || true
    if [[ "$was_active" == true ]]; then
        swapon -- "$SWAPFILE" || print_error 'Не удалось повторно включить восстановленный swap'
    fi
    return 1
}

disable_swap() {
    local delete_file="${1:-false}" was_active=false fstab_backup
    if [[ "$delete_file" == true ]] && ! confirm "Удалить $SWAPFILE после отключения?"; then
        print_step 'Удаление отменено; состояние не изменено'
        return 0
    fi
    is_swap_active && was_active=true
    fstab_backup=$(backup_fstab disable) || return 1
    if [[ "$was_active" == true ]] && ! swapoff -- "$SWAPFILE"; then
        print_error 'Не удалось отключить swap; изменений нет'
        return 1
    fi
    if ! remove_fstab_entry; then
        restore_fstab "$fstab_backup" || true
        if [[ "$was_active" == true ]]; then swapon -- "$SWAPFILE" || true; fi
        print_error 'Не удалось обновить fstab; состояние восстановлено'
        return 1
    fi
    if [[ "$delete_file" == true ]]; then
        if ! rm -f -- "$SWAPFILE"; then
            restore_fstab "$fstab_backup" || true
            if [[ "$was_active" == true ]]; then swapon -- "$SWAPFILE" || true; fi
            print_error 'Не удалось удалить swap-файл; состояние восстановлено'
            return 1
        fi
        log INFO "Swap удален; резервная копия fstab: $fstab_backup"
        print_success 'Swap отключен и файл удален'
    else
        log INFO "Swap отключен; резервная копия fstab: $fstab_backup"
        print_success 'Swap отключен; файл сохранен'
    fi
}

recommended_swap_mb() {
    local ram_mb
    ram_mb=$(free -m | awk '/^Mem:/ { print $2 }')
    if (( ram_mb <= 2048 )); then echo $((ram_mb * 2))
    elif (( ram_mb <= 8192 )); then echo "$ram_mb"
    else echo $((ram_mb / 2)); fi
}

read_swap_size() {
    local default_size="$1" value
    while true; do
        read -r -p "Размер swap в MB [$default_size]: " value
        value="${value:-$default_size}"
        if validate_size "$value"; then printf '%s\n' "$value"; return 0; fi
    done
}

show_status() {
    echo -e "${CYAN}Текущее состояние:${NC}"
    if is_swap_active; then
        print_success "$SWAPFILE активен ($(stat -c %s -- "$SWAPFILE" | awk '{printf "%.0f MB", $1/1048576}'))"
    elif [[ -f "$SWAPFILE" ]]; then
        echo -e "${YELLOW}$SWAPFILE существует, но отключен${NC}"
    else
        echo -e "${RED}Swap-файл не настроен${NC}"
    fi
    swapon --show 2>/dev/null || true
}

manage_swap() {
    check_root
    validate_paths
    while true; do
        local recommended choice size current_size
        print_header "УПРАВЛЕНИЕ SWAP v$SCRIPT_VERSION"
        show_status
        recommended=$(recommended_swap_mb)
        echo "Ориентировочный размер для этой системы: ${recommended} MB"
        if is_swap_active; then
            echo '1. Изменить размер'; echo '2. Отключить (файл сохранить)'; echo '3. Отключить и удалить'
        elif [[ -f "$SWAPFILE" ]]; then
            echo '1. Включить'; echo '2. Изменить размер и включить'; echo '3. Удалить файл'
        else
            echo '1. Создать и включить'
        fi
        echo '0. Вернуться в главное меню'
        read -r -p 'Выберите действие: ' choice
        case "$choice" in
            0) return 0 ;;
            1)
                if is_swap_active; then
                    current_size=$(stat -c %s -- "$SWAPFILE"); current_size=$((current_size / 1048576))
                    size=$(read_swap_size "$recommended")
                    if [[ "$size" -eq "$current_size" ]]; then
                        print_step 'Размер не изменен'
                    else
                        resize_swap "$size"
                    fi
                elif [[ -f "$SWAPFILE" ]]; then enable_existing_swap
                else size=$(read_swap_size "$recommended"); create_swap "$size"; fi
                ;;
            2)
                if is_swap_active; then disable_swap false
                elif [[ -f "$SWAPFILE" ]]; then size=$(read_swap_size "$recommended"); resize_swap "$size"
                else print_error 'Неверный выбор'; fi
                ;;
            3)
                if [[ -f "$SWAPFILE" ]]; then disable_swap true; else print_error 'Неверный выбор'; fi
                ;;
            *) print_error 'Неверный выбор' ;;
        esac
        echo
        read -r -p 'Нажмите Enter для продолжения...'
    done
}

main() { manage_swap; }
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
