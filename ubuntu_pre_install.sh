#!/usr/bin/env bash
# Official references checked 2026-08-14:
# https://documentation.ubuntu.com/server/how-to/security/firewalls/
# https://documentation.ubuntu.com/server/how-to/security/openssh-server/
set -Eeuo pipefail

# Метаданные скрипта
SCRIPT_VERSION="1.3.0"

# Цветовые коды
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    local title="$1"
    local width=50
    local padding=$(( (width - ${#title}) / 2 ))
    echo
    echo -e "${BLUE}┌$( printf '─%.0s' $(seq 1 $width) )┐${NC}"
    echo -e "${BLUE}│$( printf ' %.0s' $(seq 1 $padding) )${CYAN}$title$( printf ' %.0s' $(seq 1 $(( width - padding - ${#title} )) ) )${BLUE}│${NC}"
    echo -e "${BLUE}└$( printf '─%.0s' $(seq 1 $width) )┘${NC}"
    echo
}

print_step() {
    echo -e "${YELLOW}➜${NC} $1"
}

print_success() {
    echo -e "${GREEN}✔${NC} $1"
}

print_error() {
    echo -e "${RED}✘${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

confirm() {
    local answer
    read -r -p "$1 [y/N]: " answer || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
}

# Константы
BACKUP_DIR="/root/config_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/system_setup.log"
MIN_FREE_SPACE_KB=2097152  # 2GB в килобайтах
VLESS_SYSCTL_CONFIG="${VLESS_SYSCTL_CONFIG:-/etc/sysctl.d/90-server-scripts-vless-tcp.conf}"
VLESS_LEGACY_CONFIG="${VLESS_LEGACY_CONFIG:-/etc/sysctl.d/99-xanmod-vless-tcp.conf}"
VLESS_MODULE_CONFIG="${VLESS_MODULE_CONFIG:-/etc/modules-load.d/90-server-scripts-bbr.conf}"
VLESS_BACKUP_DIR="${VLESS_BACKUP_DIR:-/var/backups/server-scripts/vless-tcp}"

# Функция логирования с цветным выводом
log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    case "$level" in
        "INFO") local color=$GREEN ;;
        "WARNING") local color=$YELLOW ;;
        "ERROR") local color=$RED ;;
        *) local color=$NC ;;
    esac
    echo -e "${timestamp} [${color}${level}${NC}] $*"
    echo "${timestamp} [${level}] $*" >> "$LOG_FILE"
}

ROLLBACK_ACTIVE=0
ROLLBACK_KIND=""
UFW_WAS_ACTIVE=0
AUTHORIZED_KEYS_EXISTED=0

# Восстановление выполняется только для текущей транзакции UFW или SSH.
rollback() {
    local rc="${1:-1}"
    trap - ERR
    (( ROLLBACK_ACTIVE == 1 )) || return "$rc"
    if (( rc == 0 )); then
        log "WARNING" "Изменения ${ROLLBACK_KIND} не подтверждены. Восстанавливаем исходную конфигурацию."
    else
        log "ERROR" "Ошибка во время настройки ${ROLLBACK_KIND}. Восстанавливаем исходную конфигурацию."
    fi
    case "$ROLLBACK_KIND" in
        ufw)
            if [[ -d "$BACKUP_DIR/ufw" ]]; then
                rm -rf /etc/ufw
                cp -a "$BACKUP_DIR/ufw" /etc/ufw
                if (( UFW_WAS_ACTIVE == 1 )); then ufw --force enable >/dev/null 2>&1 || true; else ufw --force disable >/dev/null 2>&1 || true; fi
            fi
            ;;
        ssh)
            if [[ -f "$BACKUP_DIR/sshd_config" ]]; then cp -a "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config; fi
            if [[ -f "$BACKUP_DIR/00-server-scripts.conf" ]]; then
                cp -a "$BACKUP_DIR/00-server-scripts.conf" /etc/ssh/sshd_config.d/00-server-scripts.conf
            else
                rm -f /etc/ssh/sshd_config.d/00-server-scripts.conf
            fi
            if (( AUTHORIZED_KEYS_EXISTED == 1 )) && [[ -f "$BACKUP_DIR/authorized_keys" ]]; then
                cp -a "$BACKUP_DIR/authorized_keys" /root/.ssh/authorized_keys
            else
                rm -f /root/.ssh/authorized_keys
            fi
            sshd -t >/dev/null 2>&1 && systemctl reload ssh >/dev/null 2>&1 || true
            ;;
    esac
    ROLLBACK_ACTIVE=0
    ROLLBACK_KIND=""
    trap transaction_error ERR
    return "$rc"
}

transaction_error() { local rc=$?; rollback "$rc"; exit "$rc"; }
trap transaction_error ERR

# Проверка свободного места на диске
check_free_space() {
    local free_space_kb
    free_space_kb=$(df -k --output=avail "$PWD" | tail -n1)
    if [ "$free_space_kb" -lt "$MIN_FREE_SPACE_KB" ]; then
        log "ERROR" "Недостаточно свободного места на диске. Требуется минимум $((MIN_FREE_SPACE_KB / 1024)) MB."
        exit 1
    fi
}

initialize_script() {
    if (( EUID != 0 )); then
        echo "Этот скрипт должен быть запущен с правами root" >&2
        exit 1
    fi
    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")"
    log "INFO" "Проверка свободного места на диске..."
    check_free_space
}

# Создание резервных копий
backup_file() {
    local src="$1"
    if [ -f "$src" ]; then
        # Проверяем, что директория для бэкапа существует
        if [ ! -d "$BACKUP_DIR" ]; then
            mkdir -p "$BACKUP_DIR"
            log "INFO" "Создана директория для резервных копий: $BACKUP_DIR"
        fi
        
        # Копируем файл
        cp "$src" "$BACKUP_DIR/" || { log "ERROR" "Не удалось создать резервную копию: $src"; exit 1; }
        log "INFO" "Создана резервная копия файла: $src"
    else
        log "WARNING" "Файл не найден для резервного копирования: $src"
    fi
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

valid_ip_or_cidr() {
    local value="$1" address prefix octet
    local -a octets
    [[ -n "$value" && "$value" != *[[:space:]]* ]] || return 1
    if [[ "$value" == *:* ]]; then
        command -v python3 >/dev/null 2>&1 || return 1
        python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$value" >/dev/null 2>&1
        return
    fi
    address="${value%%/*}"
    if [[ "$value" == */* ]]; then
        prefix="${value##*/}"
        [[ "$prefix" =~ ^[0-9]+$ ]] && (( 10#$prefix <= 32 )) || return 1
    fi
    IFS=. read -r -a octets <<< "$address"
    ((${#octets[@]} == 4)) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] && (( 10#$octet <= 255 )) || return 1
    done
}

detect_ssh_port() {
    local port connection="${SSH_CONNECTION:-}"
    if [[ -n "$connection" ]]; then
        port="${connection##* }"
        if valid_port "$port"; then printf '%s\n' "$port"; return 0; fi
    fi
    port="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')"
    valid_port "${port:-}" && printf '%s\n' "$port" || printf '22\n'
}

current_ssh_client_ip() {
    local connection="${SSH_CONNECTION:-}" client
    [[ -n "$connection" ]] || return 0
    client="${connection%% *}"
    valid_ip_or_cidr "$client" && printf '%s\n' "$client" || true
}

render_ssh_dropin() {
    local tcp_forwarding="${1:-no}"
    case "$tcp_forwarding" in yes|local|remote|no) ;; *) return 2 ;; esac
    cat <<EOF
# Managed by Server_scripts ubuntu_pre_install.sh
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding $tcp_forwarding
LoginGraceTime 30
EOF
}

package_is_installed() {
    local status
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null || true)
    [[ "$status" == ii* ]]
}

first_output_line() {
    local output
    output=$("$@" 2>&1) || return 1
    printf '%s\n' "${output%%$'\n'*}"
}

package_version_line() {
    case "$1" in
        curl) first_output_line curl --version ;;
        wget) first_output_line wget --version ;;
        git) first_output_line git --version ;;
        openssh-server) first_output_line sshd -V ;;
        mtr|mtr-tiny) first_output_line mtr --version ;;
        *) return 1 ;;
    esac
}

pin_dnscrypt_installer_snapshot() {
    local installer="$1" commit="$2"
    [[ -f "$installer" && "$commit" =~ ^[0-9a-f]{40}$ ]] || return 2
    sed -i "s#https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/main/#https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/${commit}/#g" "$installer"
    ! grep -q 'https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/main/' "$installer"
}

normalize_dnscrypt_manager_entrypoint() {
    local main_script="$1" candidate line replaced=0
    local expected='SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"'
    [[ -f "$main_script" ]] || return 2
    if grep -Fq 'source_path=$(readlink -f "$1")' "$main_script" || \
        grep -Fq 'SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"' "$main_script"; then
        return 0
    fi
    candidate=$(mktemp "${main_script}.candidate.XXXXXX")
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == "$expected" ]]; then
            printf '%s\n' 'SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"' \
                'SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"' >> "$candidate"
            ((replaced += 1))
        else
            printf '%s\n' "$line" >> "$candidate"
        fi
    done < "$main_script"
    if (( replaced != 1 )) || ! bash -n "$candidate"; then
        rm -f -- "$candidate"
        return 1
    fi
    chmod --reference="$main_script" "$candidate"
    mv -f -- "$candidate" "$main_script"
}

# Установка зависимостей и обновление системы
install_dependencies_and_update_system() {
    log "INFO" "Установка зависимостей и обновление системы..."
    print_header "Установка зависимых пакетов и обновление системы"
    
    # Только серверные инструменты. Декоративные neofetch/fastfetch намеренно
    # не устанавливаются: на минимальном образе они могут тянуть GUI-зависимости.
    local mtr_package="mtr"
    if package_is_installed mtr-tiny; then
        mtr_package="mtr-tiny"
    fi
    local base_packages=(
        curl wget git mc
        net-tools nmap tcpdump iotop
        unzip tar vim tmux screen
        rsync ncdu dnsutils
        whois ufw openssh-server
        "$mtr_package" htop
    )
    
    # Обновление списка пакетов
    print_step "Обновление списков пакетов..."
    apt-get update
    
    # Проверка наличия пакетов и установка недостающих
    print_step "Проверка наличия зависимостей..."
    local packages_to_install=()
    
    for package in "${base_packages[@]}"; do
        if ! package_is_installed "$package"; then
            packages_to_install+=("$package")
        fi
    done
    
    # Если есть пакеты для установки
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        local install_plan install_removals
        print_step "Предварительная проверка плана установки..."
        install_plan=$(apt-get -s install -- "${packages_to_install[@]}")
        printf '%s\n' "$install_plan"
        install_removals=$(sed -n 's/^Remv \([^ ]*\).*/\1/p' <<< "$install_plan")
        if [[ -n "$install_removals" ]]; then
            print_error "Установка требует удаления пакетов; операция остановлена."
            log "ERROR" "План установки требует удаления: ${install_removals//$'\n'/, }"
            return 1
        fi
        print_step "Установка недостающих пакетов: ${packages_to_install[*]}"
        apt-get install -y "${packages_to_install[@]}"
        print_success "Зависимости установлены."
        log "INFO" "Установлены пакеты: ${packages_to_install[*]}"
    else
        print_success "Все необходимые зависимости уже установлены."
        log "INFO" "Все необходимые зависимости уже установлены."
    fi
    
    # Обновление системы
    print_step "Обновление системы..."
    apt-get upgrade --with-new-pkgs --no-remove -y
    log "INFO" "Система обновлена."
    
    # Очистка системы после обновления
    print_step "Очистка системы после обновления..."
    
    # Запоминаем свободное место до очистки
    local free_space_before free_space_after
    free_space_before=$(df -h / | awk 'NR==2 {print $4}')
    
    # Удаление устаревших пакетов
    print_step "Предварительный просмотр autoremove..."
    local autoremove_plan removals
    autoremove_plan=$(apt-get -s autoremove)
    printf '%s\n' "$autoremove_plan"
    removals=$(sed -n 's/^Remv \([^ ]*\).*/\1/p' <<< "$autoremove_plan")
    if grep -Eq '^(linux-(image|headers|modules)|linux-xanmod|grub|systemd|openssh-server|xray)' <<< "$removals"; then
        print_warning "autoremove предлагает удалить защищённый пакет; операция пропущена."
    elif [[ -n "$removals" ]] && confirm "Применить показанный autoremove?"; then
        apt-get autoremove -y
    else
        print_step "autoremove пропущен."
    fi
    
    # Очистка архивов пакетов
    print_step "Очистка устаревших архивов пакетов..."
    apt-get autoclean
    
    # Проверка свободного места после очистки
    free_space_after=$(df -h / | awk 'NR==2 {print $4}')
    
    print_success "Система успешно обновлена и очищена."
    log "INFO" "Система успешно обновлена и очищена. Свободно места: $free_space_after (было: $free_space_before)"
    
    # Вывод версий важных компонентов
    print_step "Проверка установленных версий..."
    
    # Основные пакеты, версии которых стоит проверить
    local key_packages=("curl" "wget" "git" "openssh-server" "$mtr_package")
    
    echo -e "\n${CYAN}Версии ключевых компонентов:${NC}"
    for pkg in "${key_packages[@]}"; do
        local version
        if version=$(package_version_line "$pkg"); then
            echo -e "${GREEN}✓${NC} $pkg: $version"
        else
            echo -e "${RED}✘${NC} $pkg: не установлен"
        fi
    done
    
    echo 
    return 0
}
# Установка DNSCrypt Manager через внешний скрипт
install_dnscrypt() {
    log "INFO" "Установка DNSCrypt Manager..."
    print_header "Установка DNSCrypt Manager"
    
    print_step "DNSCrypt-proxy обеспечивает шифрование DNS-запросов"
    print_step "и защиту от прослушивания и подмены DNS-ответов."
    echo
    
    # Проверяем наличие curl
    if ! command -v curl &> /dev/null; then
        log "ERROR" "curl не найден. Пожалуйста, установите curl сначала."
        print_error "Требуется установить зависимости (curl) перед установкой DNSCrypt."
        return 1
    fi
    # Resolve current main once, then download the installer from that exact snapshot.
    local dnscrypt_api="https://api.github.com/repos/gopnikgame/Installer_dnscypt"
    local dnscrypt_commit response
    response=$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 30 \
        -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$dnscrypt_api/commits/main") || {
        print_error "Не удалось определить свежий commit DNSCrypt installer."
        return 1
    }
    dnscrypt_commit=$(sed -n 's/^[[:space:]]*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' <<< "$response" | head -n 1)
    [[ "$dnscrypt_commit" =~ ^[0-9a-f]{40}$ ]] || {
        print_error "GitHub API вернул некорректный commit DNSCrypt installer."
        return 1
    }
    local dnscrypt_install_url="https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/${dnscrypt_commit}/quick_install.sh"
    
    print_step "Загрузка скрипта установки DNSCrypt..."
    
    # Создаем временную директорию
    local temp_dir
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/dnscrypt-install.XXXXXX")
    local install_script="$temp_dir/dnscrypt_install.sh"
    
    # Скачиваем скрипт
    if curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 60 "$dnscrypt_install_url" -o "$install_script"; then
        log "INFO" "Скрипт установки успешно загружен."
        print_success "Скрипт установки загружен."
    else
        log "ERROR" "Не удалось загрузить скрипт установки DNSCrypt."
        print_error "Ошибка загрузки скрипта. Проверьте подключение к интернету."
        rm -rf -- "$temp_dir"
        return 1
    fi

    if ! pin_dnscrypt_installer_snapshot "$install_script" "$dnscrypt_commit"; then
        print_error "Не удалось зафиксировать зависимости DNSCrypt installer на commit ${dnscrypt_commit}."
        rm -rf -- "$temp_dir"
        return 1
    fi
    if ! bash -n "$install_script"; then
        print_error "DNSCrypt installer не прошёл bash -n."
        rm -rf -- "$temp_dir"
        return 1
    fi
    log "INFO" "DNSCrypt installer получен из commit ${dnscrypt_commit}."
    
    # Делаем скрипт исполняемым
    chmod +x "$install_script"
    
    print_step "Запуск скрипта установки DNSCrypt..."
    echo
    
    # Запускаем скрипт установки
    if bash "$install_script" && normalize_dnscrypt_manager_entrypoint /usr/local/dnscrypt-scripts/main.sh; then
        log "INFO" "DNSCrypt Manager успешно установлен из commit ${dnscrypt_commit}."
        print_success "DNSCrypt Manager установлен. Сам DNSCrypt-proxy настраивается через dnscrypt_manager."
    else
        log "ERROR" "Ошибка при установке DNSCrypt Manager."
        print_error "Произошла ошибка при установке DNSCrypt Manager."
        rm -rf -- "$temp_dir"
        return 1
    fi
    
    # Очищаем временные файлы
    rm -rf -- "$temp_dir"
    
    echo
    print_step "Запустите dnscrypt_manager для установки и настройки DNSCrypt-proxy."
    
    return 0
}

# Настройка файрволла (UFW)
configure_firewall() {
    command -v ufw >/dev/null || { print_error "UFW не установлен."; return 1; }
    command -v sshd >/dev/null || { print_error "sshd не найден: сначала установите OpenSSH Server."; return 1; }

    local ssh_port client_ip open_http restrict_ssh custom_ports restrict_custom_ports value port ip firewall_mode
    local -a ssh_allowed_ips=() custom_port_list=() custom_ip_list=()
    ssh_port="$(detect_ssh_port)"
    client_ip="$(current_ssh_client_ip)"
    print_header "Безопасный план UFW"
    echo -e "${CYAN}Фактический порт sshd:${NC} $ssh_port"
    [[ -z "$client_ip" ]] || echo -e "${CYAN}Адрес текущей SSH-сессии:${NC} $client_ip"
    echo
    echo -e "${CYAN}Текущие правила UFW:${NC}"
    ufw status verbose || true
    echo
    ufw status numbered || true
    echo
    echo "1) Сохранить существующие правила и добавить новые"
    echo "2) Удалить существующие правила и создать набор с нуля"
    echo "0) Отмена"
    read -r -p "Режим настройки UFW [0-2]: " firewall_mode
    case "$firewall_mode" in
        1) print_step "Существующие правила будут сохранены." ;;
        2) print_warning "Все существующие правила UFW будут удалены после резервного копирования." ;;
        0|'') print_step "Настройка UFW отменена."; return 0 ;;
        *) print_error "Неверный режим UFW."; return 1 ;;
    esac

    read -r -p "Открыть HTTP 80/tcp? [y/N]: " open_http
    read -r -p "Ограничить SSH списком IP/CIDR? [y/N]: " restrict_ssh
    if [[ "$restrict_ssh" =~ ^[Yy]$ ]]; then
        [[ -z "$client_ip" ]] || { ssh_allowed_ips+=("$client_ip"); print_step "Текущий адрес $client_ip добавлен автоматически."; }
        while true; do
            read -r -p "IP или CIDR для SSH (Enter — закончить): " value
            [[ -n "$value" ]] || break
            if valid_ip_or_cidr "$value"; then ssh_allowed_ips+=("$value"); else print_error "Некорректный IP/CIDR."; fi
        done
        ((${#ssh_allowed_ips[@]} > 0)) || { print_error "Нельзя включить ограничение SSH с пустым списком."; return 1; }
    fi

    read -r -p "Добавить пользовательские TCP-порты? [y/N]: " custom_ports
    if [[ "$custom_ports" =~ ^[Yy]$ ]]; then
        while true; do
            read -r -p "TCP-порт (Enter — закончить): " value
            [[ -n "$value" ]] || break
            if valid_port "$value"; then custom_port_list+=("$value"); else print_error "Порт должен быть 1–65535."; fi
        done
        if ((${#custom_port_list[@]} > 0)); then
            read -r -p "Ограничить эти порты списком IP/CIDR? [y/N]: " restrict_custom_ports
            if [[ "$restrict_custom_ports" =~ ^[Yy]$ ]]; then
                while true; do
                    read -r -p "IP или CIDR (Enter — закончить): " value
                    [[ -n "$value" ]] || break
                    if valid_ip_or_cidr "$value"; then custom_ip_list+=("$value"); else print_error "Некорректный IP/CIDR."; fi
                done
                ((${#custom_ip_list[@]} > 0)) || { print_error "Ограничение с пустым списком запрещено."; return 1; }
            fi
        fi
    fi

    echo
    if [[ "$firewall_mode" == 2 ]]; then
        print_warning "Существующие правила будут заменены. Сначала создаётся полная копия /etc/ufw."
    else
        print_step "Новые разрешения будут добавлены к существующим правилам."
    fi
    read -r -p "Применить показанный план? [y/N]: " value
    [[ "$value" =~ ^[Yy]$ ]] || { print_step "Настройка отменена."; return 0; }

    rm -rf "$BACKUP_DIR/ufw"
    cp -a /etc/ufw "$BACKUP_DIR/ufw"
    LC_ALL=C ufw status | grep -q '^Status: active' && UFW_WAS_ACTIVE=1 || UFW_WAS_ACTIVE=0
    ROLLBACK_KIND=ufw; ROLLBACK_ACTIVE=1
    if [[ "$firewall_mode" == 2 ]]; then
        ufw --force disable >/dev/null 2>&1 || true
        ufw --force reset >/dev/null
        ufw default deny incoming
        ufw default allow outgoing
    fi
    ufw allow 443/tcp
    if [[ "$open_http" =~ ^[Yy]$ ]]; then ufw allow 80/tcp; fi
    if [[ "$restrict_ssh" =~ ^[Yy]$ ]]; then
        for ip in "${ssh_allowed_ips[@]}"; do ufw allow proto tcp from "$ip" to any port "$ssh_port"; done
    else
        ufw allow "$ssh_port/tcp"
    fi
    for port in "${custom_port_list[@]}"; do
        if ((${#custom_ip_list[@]} > 0)); then
            for ip in "${custom_ip_list[@]}"; do ufw allow proto tcp from "$ip" to any port "$port"; done
        else
            ufw allow "$port/tcp"
        fi
    done
    # Replace mode disables UFW before reset, so it must always be enabled again
    # for the mandatory second-session check, regardless of its initial state.
    if [[ "$firewall_mode" == 2 ]] || (( UFW_WAS_ACTIVE == 0 )); then
        ufw --dry-run enable >/dev/null
        ufw --force enable
    fi
    ufw status numbered

    print_warning "Не закрывайте эту сессию. Откройте вторую SSH-сессию и проверьте вход."
    if ! read -r -p "Вторая SSH-сессия успешно подключилась? [y/N]: " value; then
        value=""
    fi
    if [[ "$value" =~ ^[Yy]$ ]]; then
        ROLLBACK_ACTIVE=0; ROLLBACK_KIND=""
        log "INFO" "UFW применён и подтверждён второй SSH-сессией. Резервная копия: $BACKUP_DIR/ufw"
        print_success "UFW применён безопасно."
    else
        rollback 0
        print_error "Новые правила отменены; восстановлена прежняя конфигурация UFW."
    fi
}



# Смена пароля root
change_root_password() {
    log "INFO" "Смена пароля пользователя root..."
    
    # Проверка, что команда passwd доступна
    if ! command -v passwd &> /dev/null; then
        log "ERROR" "Команда passwd не найдена. Невозможно сменить пароль."
        return 1
    fi
    
    echo -e "${YELLOW}=== Смена пароля пользователя root ===${NC}"
    echo "ВНИМАНИЕ: Пароль не будет отображаться при вводе."
    echo "Если вы планируете использовать только SSH-ключи, пароль можно сделать сложным."

    # Запрашиваем новый пароль
    local password_changed=0
    local attempt=1
    local max_attempts=3

    while [ $password_changed -eq 0 ] && [ $attempt -le $max_attempts ]; do
        echo ""
        echo "Попытка $attempt из $max_attempts:"
        
        # Используем временный файл для смены пароля
        temp_file=$(mktemp)
        chmod 600 "$temp_file"
        
        read -s -p "Введите новый пароль: " password
        echo ""
        read -s -p "Повторите новый пароль: " password_confirm
        echo ""
        
        if [ "$password" != "$password_confirm" ]; then
            log "WARNING" "Пароли не совпадают. Попробуйте снова."
            attempt=$((attempt+1))
            continue
        fi
        
        if [ -z "$password" ]; then
            log "WARNING" "Пароль не может быть пустым. Попробуйте снова."
            attempt=$((attempt+1))
            continue
        fi
        
        # Проверка сложности пароля
        if [ ${#password} -lt 8 ]; then
            echo -e "${YELLOW}Предупреждение: Пароль короче 8 символов.${NC}"
            read -p "Продолжить со слабым паролем? (y/n): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                attempt=$((attempt+1))
                continue
            fi
        fi
        
        # Меняем пароль
        echo "root:$password" | chpasswd 2> "$temp_file"
        
        if [ $? -eq 0 ]; then
            log "INFO" "Пароль пользователя root успешно изменен."
            password_changed=1
        else
            log "ERROR" "Ошибка при смене пароля: $(cat "$temp_file")"
            attempt=$((attempt+1))
        fi
        
        rm -f "$temp_file"
    done
    
    if [ $password_changed -eq 0 ]; then
        log "ERROR" "Не удалось сменить пароль после $max_attempts попыток."
        return 1
    fi
    
    return 0
}


# Настройка SSH
configure_ssh() {
    log "INFO" "Настройка безопасности SSH..."

    # Проверка наличия службы SSH
    if ! command -v sshd >/dev/null 2>&1; then
        log "INFO" "Служба SSH не найдена. Установка OpenSSH..."
        apt-get install -y openssh-server
    fi

    if [[ -f /root/.ssh/authorized_keys ]]; then
        AUTHORIZED_KEYS_EXISTED=1
        cp -a /root/.ssh/authorized_keys "$BACKUP_DIR/authorized_keys"
    else
        AUTHORIZED_KEYS_EXISTED=0
        rm -f "$BACKUP_DIR/authorized_keys"
    fi

    # Создание директории .ssh и файла authorized_keys
    if [ ! -d "/root/.ssh" ]; then
        log "INFO" "Создание директории /root/.ssh..."
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
    fi

    if [ ! -f "/root/.ssh/authorized_keys" ]; then
        log "INFO" "Создание файла /root/.ssh/authorized_keys..."
        touch /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
    fi

    # Проверка наличия публичного ключа в authorized_keys
    if [ -s "/root/.ssh/authorized_keys" ]; then
        log "INFO" "Публичный ключ уже настроен в /root/.ssh/authorized_keys. Пропускаем шаг добавления ключа."
    else
        log "INFO" "Для продолжения настройки SSH требуется ваш публичный ключ."
        log "INFO" "Публичный ключ обычно находится в файле ~/.ssh/id_rsa.pub или ~/.ssh/id_ed25519.pub."
        log "INFO" "Пример публичного ключа:"
        log "INFO" "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEArV1... user@hostname"
        read -p "Введите ваш публичный ключ SSH: " public_key

        local key_file
        key_file="$(mktemp)"
        chmod 0600 "$key_file"
        printf '%s\n' "$public_key" > "$key_file"
        if ! ssh-keygen -l -f "$key_file" >/dev/null 2>&1; then
            rm -f "$key_file"
            log "ERROR" "OpenSSH не распознал публичный ключ."
            return 1
        fi
        rm -f "$key_file"
        printf '%s\n' "$public_key" >> /root/.ssh/authorized_keys
        log "INFO" "Публичный ключ успешно добавлен в /root/.ssh/authorized_keys."
    fi

    chown root:root /root/.ssh /root/.ssh/authorized_keys
    chmod 0700 /root/.ssh
    chmod 0600 /root/.ssh/authorized_keys
    ssh-keygen -l -f /root/.ssh/authorized_keys >/dev/null 2>&1 || {
        print_error "В authorized_keys нет ключа, распознаваемого OpenSSH. Отключение пароля отменено."
        return 1
    }

    local tcp_forwarding_choice tcp_forwarding_mode
    print_header "SSH TCP FORWARDING"
    echo "1) Разрешить все туннели (yes): ssh -L, ssh -R и ssh -D"
    echo "2) Разрешить локальные туннели (local): ssh -L и ssh -D; запретить ssh -R"
    echo "3) Запретить все TCP-туннели (no)"
    echo
    while true; do
        read -r -p "Выберите режим AllowTcpForwarding [1-3, Enter=2]: " tcp_forwarding_choice
        case "${tcp_forwarding_choice:-2}" in
            1) tcp_forwarding_mode="yes"; break ;;
            2) tcp_forwarding_mode="local"; break ;;
            3) tcp_forwarding_mode="no"; break ;;
            *) print_error "Введите 1, 2 или 3." ;;
        esac
    done
    print_step "Будет применено: AllowTcpForwarding $tcp_forwarding_mode"

    mkdir -p /etc/ssh/sshd_config.d
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
    if [[ -f /etc/ssh/sshd_config.d/00-server-scripts.conf ]]; then
        cp -a /etc/ssh/sshd_config.d/00-server-scripts.conf "$BACKUP_DIR/00-server-scripts.conf"
    else
        rm -f "$BACKUP_DIR/00-server-scripts.conf"
    fi
    ROLLBACK_KIND=ssh; ROLLBACK_ACTIVE=1

    render_ssh_dropin "$tcp_forwarding_mode" > /etc/ssh/sshd_config.d/00-server-scripts.conf
    chmod 0644 /etc/ssh/sshd_config.d/00-server-scripts.conf
    sshd -t

    local effective
    effective="$(sshd -T)"
    grep -q '^permitrootlogin without-password$\|^permitrootlogin prohibit-password$' <<< "$effective"
    grep -q '^pubkeyauthentication yes$' <<< "$effective"
    grep -q '^passwordauthentication no$' <<< "$effective"
    grep -q '^kbdinteractiveauthentication no$' <<< "$effective"
    grep -q "^allowtcpforwarding $tcp_forwarding_mode$" <<< "$effective"
    systemctl reload ssh
    systemctl is-active --quiet ssh

    print_warning "Не закрывайте текущую сессию. Откройте вторую SSH-сессию тем же ключом."
    local confirmed
    if ! read -r -p "Вход по ключу во второй сессии успешен? [y/N]: " confirmed; then
        confirmed=""
    fi
    if [[ "$confirmed" =~ ^[Yy]$ ]]; then
        ROLLBACK_ACTIVE=0; ROLLBACK_KIND=""
        log "INFO" "Конфигурация SSH проверена sshd -t, перезагружена и подтверждена второй сессией."
        print_success "SSH настроен безопасно. Резервная копия: $BACKUP_DIR"
    else
        rollback 0
        print_error "Новая конфигурация SSH отменена; восстановлена предыдущая."
    fi
}

# Профиль VLESS/REALITY с большим количеством TCP-соединений.
vless_buffer_limit_for_ram() {
    local ram_mb="$1"
    # MemTotal is lower than nominal VM RAM because firmware/kernel reserve memory.
    if (( ram_mb < 768 )); then printf '%s\n' 8388608
    elif (( ram_mb < 3584 )); then printf '%s\n' 16777216
    elif (( ram_mb < 7680 )); then printf '%s\n' 33554432
    else printf '%s\n' 67108864
    fi
}

vless_max_current_or() {
    local key="$1" wanted="$2" current
    current=$(sysctl -n "$key" 2>/dev/null || echo 0)
    [[ "$current" =~ ^[0-9]+$ ]] || current=0
    (( current > wanted )) && printf '%s\n' "$current" || printf '%s\n' "$wanted"
}

vless_local_port_range() {
    local low high
    read -r low high < <(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || printf '32768 60999\n')
    [[ "$low" =~ ^[0-9]+$ ]] || low=32768
    [[ "$high" =~ ^[0-9]+$ ]] || high=60999
    (( low > 10240 )) && low=10240
    (( high < 65535 )) && high=65535
    printf '%s %s\n' "$low" "$high"
}

vless_kernel_label() {
    if [[ "$(uname -r)" == *xanmod* ]]; then
        printf 'XanMod; используется реализация BBR из загруженной сборки XanMod\n'
    else
        printf 'Ubuntu/Linux generic; используется BBR из загруженного ядра\n'
    fi
}

ensure_running_kernel_bbr() {
    modprobe tcp_bbr 2>/dev/null || true
    sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr
}

render_vless_high_connection_profile() {
    local ram_mb="$1" buffer somax synbacklog port_range
    buffer=$(vless_buffer_limit_for_ram "$ram_mb")
    somax=$(vless_max_current_or net.core.somaxconn 16384)
    synbacklog=$(vless_max_current_or net.ipv4.tcp_max_syn_backlog 16384)
    port_range=$(vless_local_port_range)
    cat <<EOF
# Server_scripts: VLESS/REALITY High Connection
# Generated: $(date -Is)
# BBR implementation is supplied by the currently running kernel.
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

vless_profile_keys() {
    printf '%s\n' net.core.default_qdisc net.ipv4.tcp_congestion_control \
        net.ipv4.tcp_mtu_probing net.ipv4.tcp_syncookies net.core.somaxconn \
        net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range \
        net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem
}

snapshot_vless_runtime() {
    local target="$1" key value
    : > "$target"
    while IFS= read -r key; do
        value=$(sysctl -n "$key" 2>/dev/null) || continue
        printf '%s=%s\n' "$key" "$value" >> "$target"
    done < <(vless_profile_keys)
    chmod 0600 "$target"
}

validate_vless_profile() {
    local file="$1" key
    while IFS='=' read -r key _; do
        [[ "$key" =~ ^[[:space:]]*# || -z "${key// }" ]] && continue
        key="${key//[[:space:]]/}"
        sysctl -n "$key" >/dev/null 2>&1 || { print_error "Ядро не поддерживает sysctl: $key"; return 1; }
    done < "$file"
}

show_vless_tcp_status() {
    print_header "VLESS/REALITY HIGH CONNECTION"
    printf 'Ядро:                 %s\n' "$(uname -r)"
    printf 'Реализация BBR:       %s\n' "$(vless_kernel_label)"
    printf 'Доступные алгоритмы:  %s\n' "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)"
    printf 'Активный алгоритм:    %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    printf 'Qdisc по умолчанию:   %s\n' "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
    printf 'SOMAXCONN:             %s\n' "$(sysctl -n net.core.somaxconn 2>/dev/null || echo unknown)"
    printf 'SYN backlog:           %s\n' "$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null || echo unknown)"
    printf 'Локальные TCP-порты:  %s\n' "$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo unknown)"
    printf 'Профиль:               %s\n' "$([[ -f "$VLESS_SYSCTL_CONFIG" ]] && echo установлен || echo не-установлен)"
    if systemctl cat xray.service >/dev/null 2>&1; then
        printf 'Xray LimitNOFILE:      %s\n' "$(systemctl show xray.service -p LimitNOFILE --value 2>/dev/null || echo unknown)"
    fi
    printf '\nСокеты:\n'; ss -s 2>/dev/null || true
    printf '\nSYN-RECV: %s; TIME-WAIT: %s\n' \
        "$(ss -Hnt state syn-recv 2>/dev/null | wc -l | tr -d ' ')" \
        "$(ss -Hnt state time-wait 2>/dev/null | wc -l | tr -d ' ')"
}

apply_vless_tcp_profile() {
    local ram_mb temporary module_temporary stamp backup runtime_backup had_current=0 had_legacy=0 had_module=0
    ensure_running_kernel_bbr || { print_error "Загруженное ядро не предоставляет алгоритм bbr."; return 1; }
    ram_mb=$(awk '/MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
    temporary=$(mktemp)
    render_vless_high_connection_profile "$ram_mb" > "$temporary"
    validate_vless_profile "$temporary" || { rm -f "$temporary"; return 1; }
    print_header "ПЛАН VLESS/REALITY HIGH CONNECTION"
    printf 'Ядро: %s\n' "$(vless_kernel_label)"
    cat "$temporary"
    confirm "Применить профиль?" || { rm -f "$temporary"; return 0; }

    stamp=$(date +%Y%m%d-%H%M%S)
    backup="$VLESS_BACKUP_DIR/$stamp"
    mkdir -p "$backup"
    chmod 0700 "$VLESS_BACKUP_DIR" "$backup"
    runtime_backup="$backup/runtime.conf"
    snapshot_vless_runtime "$runtime_backup"
    if [[ -e "$VLESS_SYSCTL_CONFIG" ]]; then cp -a "$VLESS_SYSCTL_CONFIG" "$backup/profile.conf"; had_current=1; fi
    if [[ -e "$VLESS_LEGACY_CONFIG" ]]; then cp -a "$VLESS_LEGACY_CONFIG" "$backup/legacy.conf"; had_legacy=1; fi
    if [[ -e "$VLESS_MODULE_CONFIG" ]]; then cp -a "$VLESS_MODULE_CONFIG" "$backup/module.conf"; had_module=1; fi
    printf '%s %s %s\n' "$had_current" "$had_legacy" "$had_module" > "$backup/state"

    install -m 0644 "$temporary" "$VLESS_SYSCTL_CONFIG"
    module_temporary=$(mktemp)
    printf 'tcp_bbr\n' > "$module_temporary"
    install -m 0644 "$module_temporary" "$VLESS_MODULE_CONFIG"
    rm -f "$module_temporary"
    rm -f "$temporary" "$VLESS_LEGACY_CONFIG"
    if ! sysctl -p "$VLESS_SYSCTL_CONFIG" >> "$LOG_FILE" 2>&1; then
        print_error "Ядро отклонило профиль; выполняется откат."
        restore_vless_tcp_backup "$backup"
        return 1
    fi
    [[ "$(sysctl -n net.ipv4.tcp_congestion_control)" == bbr ]] || { restore_vless_tcp_backup "$backup"; print_error "BBR не активировался; профиль отменён."; return 1; }
    log "INFO" "VLESS/REALITY High Connection применён. Резервная копия: $backup"
    print_success "Профиль применён. Резервная копия: $backup"
    show_vless_tcp_status
}

restore_vless_tcp_backup() {
    local backup="$1" had_current had_legacy had_module
    [[ -f "$backup/state" && -f "$backup/runtime.conf" ]] || { print_error "Некорректная резервная копия: $backup"; return 1; }
    read -r had_current had_legacy had_module < "$backup/state"
    if (( had_current == 1 )); then cp -a "$backup/profile.conf" "$VLESS_SYSCTL_CONFIG"; else rm -f "$VLESS_SYSCTL_CONFIG"; fi
    if (( had_legacy == 1 )); then cp -a "$backup/legacy.conf" "$VLESS_LEGACY_CONFIG"; else rm -f "$VLESS_LEGACY_CONFIG"; fi
    if (( had_module == 1 )); then cp -a "$backup/module.conf" "$VLESS_MODULE_CONFIG"; else rm -f "$VLESS_MODULE_CONFIG"; fi
    sysctl -p "$backup/runtime.conf" >> "$LOG_FILE" 2>&1
}

rollback_vless_tcp_profile() {
    local backup
    backup=$(find "$VLESS_BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -name '20??????-??????' 2>/dev/null | sort -r | head -n 1 || true)
    [[ -n "$backup" ]] || { print_warning "Резервные копии профиля не найдены."; return 0; }
    printf 'Будет восстановлена копия: %s\n' "$backup"
    confirm "Выполнить откат?" || return 0
    restore_vless_tcp_backup "$backup"
    mv "$backup" "$backup.restored"
    print_success "Профиль и runtime-параметры восстановлены."
    show_vless_tcp_status
}

apply_system_tweaks() {
    local choice
    while true; do
        print_header "СЕТЕВОЙ ПРОФИЛЬ VLESS/REALITY"
        echo "1) Применить High Connection профиль (BBR обязателен)"
        echo "2) Показать текущие параметры и нагрузку"
        echo "3) Откатить последнее применение"
        echo "0) Вернуться"
        read -r -p "Выберите действие [0-3]: " choice
        case "$choice" in
            1) apply_vless_tcp_profile ;;
            2) show_vless_tcp_status ;;
            3) rollback_vless_tcp_profile ;;
            0|'') return 0 ;;
            *) print_error "Введите 0, 1, 2 или 3." ;;
        esac
        echo
        read -r -p "Нажмите Enter для продолжения..." || return 0
    done
}

# Проверка статуса IPv6
check_ipv6_status() {
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" -eq 0 ]; then
        return 0  # IPv6 включен
    else
        return 1  # IPv6 выключен
    fi
}

# Включение IPv6
enable_ipv6() {
    log "INFO" "Включение IPv6..."
    
    if check_ipv6_status; then
        log "INFO" "IPv6 уже включен."
        print_success "IPv6 уже включен."
        return 0
    fi

    print_step "Включение IPv6..."
    interface_name=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)

    # Создаем резервную копию sysctl.conf
    backup_file "/etc/sysctl.conf"

    # Удаляем старые настройки IPv6
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    sed -i "/net.ipv6.conf.$interface_name.disable_ipv6/d" /etc/sysctl.conf

    # Добавляем новые настройки для включения IPv6
    echo "# Включение IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.$interface_name.disable_ipv6 = 0" >> /etc/sysctl.conf

    # Применяем изменения
    sysctl -p > /dev/null 2>&1

    log "INFO" "IPv6 успешно включен."
    print_success "IPv6 успешно включен."
    
    # Информация о сетевых интерфейсах с IPv6
    print_step "Проверка конфигурации IPv6..."
    ip -6 addr show | grep -v "scope host" || echo "IPv6 адреса пока не назначены."
    
    log "INFO" "Рекомендуется перезагрузить систему для полного применения изменений."
    print_step "Рекомендуется перезагрузить систему для полного применения изменений."
    
    return 0
}

# Отключение IPv6
disable_ipv6() {
    log "INFO" "Отключение IPv6..."
    
    if ! check_ipv6_status; then
        log "INFO" "IPv6 уже отключен."
        print_success "IPv6 уже отключен."
        return 0
    fi

    print_step "Отключение IPv6..."
    interface_name=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)

    # Создаем резервную копию sysctl.conf
    backup_file "/etc/sysctl.conf"

    # Удаляем старые настройки IPv6
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    sed -i "/net.ipv6.conf.$interface_name.disable_ipv6/d" /etc/sysctl.conf

    # Добавляем новые настройки для отключения IPv6
    echo "# Отключение IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.$interface_name.disable_ipv6 = 1" >> /etc/sysctl.conf

    # Применяем изменения
    sysctl -p > /dev/null 2>&1

    log "INFO" "IPv6 успешно отключен."
    print_success "IPv6 успешно отключен."
    
    log "INFO" "Рекомендуется перезагрузить систему для полного применения изменений."
    print_step "Рекомендуется перезагрузить систему для полного применения изменений."
    
    return 0
}

# Управление IPv6
manage_ipv6() {
    while true; do
        print_header "Управление IPv6"
        
        # Проверяем текущий статус IPv6
        if check_ipv6_status; then
            echo -e "Текущий статус: ${GREEN}IPv6 включен${NC}"
            echo
            echo -e "1) ${YELLOW}Отключить IPv6${NC}"
        else
            echo -e "Текущий статус: ${RED}IPv6 отключен${NC}"
            echo
            echo -e "1) ${GREEN}Включить IPv6${NC}"
        fi
        
        echo -e "0) ${BLUE}Вернуться в предыдущее меню${NC}"
        echo
        
        read -p "Выберите действие [0-1]: " choice
        
        case $choice in
            0)
                return 0
                ;;
            1)
                if check_ipv6_status; then
                    disable_ipv6
                else
                    enable_ipv6
                fi
                ;;
            *)
                print_error "Неверный выбор"
                ;;
        esac
        
        echo
        read -p "Нажмите Enter для продолжения..."
    done
}


# Функция перезагрузки
reboot_system() {
    log "INFO" "Подготовка к перезагрузке системы..."
    
    # Проверка, запущен ли скрипт в интерактивном режиме
    if tty -s; then
        echo -e "${YELLOW}=== Перезагрузка системы ===${NC}"
        echo "Все несохраненные данные будут потеряны."
        read -p "Вы уверены, что хотите перезагрузить систему сейчас? (y/n): " confirm
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            log "INFO" "Выполняется перезагрузка..."
            print_success "Перезагрузка системы..."
            shutdown -r now
        else
            log "INFO" "Перезагрузка отменена пользователем."
            print_step "Перезагрузка отменена."
        fi
    else
        log "WARNING" "Скрипт запущен в неинтерактивном режиме. Перезагрузка не может быть выполнена."
        print_error "Невозможно выполнить перезагрузку в неинтерактивном режиме."
    fi
}


# Главное меню
show_menu() {
    while true; do
        print_header "НАСТРОЙКА UBUNTU v${SCRIPT_VERSION}"
        echo -e "${YELLOW}Выберите действие:${NC}"
        echo
        
        local i=1
        
        # Выводим пункты меню
        echo -e "$i) ${GREEN}Установить зависимости и обновить систему${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Установить DNSCrypt Manager${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Настроить файрволл (UFW)${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Сменить пароль root${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Настроить SSH${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Применить системные твики${NC}"
        ((i++))
        echo -e "$i) ${YELLOW}Управление IPv6${NC}"
        ((i++))
        echo -e "$i) ${YELLOW}Перезагрузить систему${NC}"
        ((i++))
        echo -e "0) ${RED}Выход${NC}"
        echo
        
        read -p "Выберите опцию [0-$((i-1))]: " choice
        echo

        case $choice in
            0)
                print_success "До свидания!"
                exit 0
                ;;
            1)
                install_dependencies_and_update_system
                ;;
            2)
                install_dnscrypt
                ;;
            3)
                configure_firewall
                ;;
            4)
                change_root_password
                ;;
            5)
                configure_ssh
                ;;
            6)
                apply_system_tweaks
                ;;
            7)
                manage_ipv6
                ;;
            8)
                reboot_system
                ;;
            *)
                print_error "Неверный выбор"
                ;;
        esac
        
        echo
        read -p "Нажмите Enter для продолжения..."
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    initialize_script
    show_menu
fi
