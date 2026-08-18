#!/usr/bin/env bash
# Official references checked 2026-08-14:
# https://documentation.ubuntu.com/server/how-to/security/firewalls/
# https://documentation.ubuntu.com/server/how-to/security/openssh-server/
set -Eeuo pipefail

# Метаданные скрипта
SCRIPT_VERSION="1.2.0"

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
    log "ERROR" "Ошибка во время настройки ${ROLLBACK_KIND}. Восстанавливаем исходную конфигурацию."
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
    cat <<'EOF'
# Managed by Server_scripts ubuntu_pre_install.sh
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
AllowAgentForwarding no
AllowTcpForwarding no
LoginGraceTime 30
EOF
}

# Установка зависимостей и обновление системы
install_dependencies_and_update_system() {
    log "INFO" "Установка зависимостей и обновление системы..."
    print_header "Установка зависимых пакетов и обновление системы"
    
    # Базовый список пакетов (без neofetch/fastfetch)
    local base_packages=(
        curl wget git mc
        net-tools nmap tcpdump iotop
        unzip tar vim tmux screen
        rsync ncdu dnsutils
        whois ufw openssh-server
        mtr htop
    )
    
    # Определяем, какой пакет для информации о системе доступен
    local system_info_package=""
    
    # Проверяем, доступен ли fastfetch в репозиториях
    if apt-cache show fastfetch &>/dev/null; then
        system_info_package="fastfetch"
        log "INFO" "Найден пакет fastfetch в репозиториях"
    # Если fastfetch нет, проверяем neofetch
    elif apt-cache show neofetch &>/dev/null; then
        system_info_package="neofetch"
        log "INFO" "Найден пакет neofetch в репозиториях"
    else
        log "WARNING" "Ни fastfetch, ни neofetch не доступны для установки. Пропускаем."
    fi
    
    # Формируем финальный список пакетов
    local required_packages=("${base_packages[@]}")
    if [ -n "$system_info_package" ]; then
        required_packages+=("$system_info_package")
    fi
    
    # Обновление списка пакетов
    print_step "Обновление списков пакетов..."
    apt-get update
    
    # Проверка наличия пакетов и установка недостающих
    print_step "Проверка наличия зависимостей..."
    local packages_to_install=()
    
    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            packages_to_install+=("$package")
        fi
    done
    
    # Если есть пакеты для установки
    if [ ${#packages_to_install[@]} -gt 0 ]; then
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
    local key_packages=("curl" "wget" "git" "openssh-server" "mtr")
    
    echo -e "\n${CYAN}Версии ключевых компонентов:${NC}"
    for pkg in "${key_packages[@]}"; do
        if command -v "$pkg" &> /dev/null; then
            local version
            version=$("$pkg" --version 2>&1 | head -n 1)
            echo -e "${GREEN}✓${NC} $pkg: $version"
        else
            echo -e "${RED}✘${NC} $pkg: не установлен"
        fi
    done
    
    # Проверяем установленный пакет для информации о системе
    if [ -n "$system_info_package" ]; then
        if command -v "$system_info_package" &> /dev/null; then
            local info_version
            info_version=$("$system_info_package" --version 2>&1 | head -n 1)
            echo -e "${GREEN}✓${NC} $system_info_package: $info_version"
        fi
    fi
    
    echo 
    return 0
}
# Установка DNSCrypt через внешний скрипт
install_dnscrypt() {
    log "INFO" "Установка DNSCrypt-proxy..."
    print_header "Установка DNSCrypt-proxy"
    
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
    if bash "$install_script"; then
        log "INFO" "DNSCrypt-proxy успешно установлен."
        print_success "DNSCrypt-proxy успешно установлен и настроен."
    else
        log "ERROR" "Ошибка при установке DNSCrypt-proxy."
        print_error "Произошла ошибка при установке DNSCrypt."
        rm -rf -- "$temp_dir"
        return 1
    fi
    
    # Очищаем временные файлы
    rm -rf -- "$temp_dir"
    
    echo
    print_step "Дальнейшая настройка DNS будет выполняться через DNSCrypt-proxy."
    
    return 0
}

# Настройка файрволла (UFW)
configure_firewall() {
    command -v ufw >/dev/null || { print_error "UFW не установлен."; return 1; }
    command -v sshd >/dev/null || { print_error "sshd не найден: сначала установите OpenSSH Server."; return 1; }

    local ssh_port client_ip open_http restrict_ssh custom_ports restrict_custom_ports value port ip
    local -a ssh_allowed_ips=() custom_port_list=() custom_ip_list=()
    ssh_port="$(detect_ssh_port)"
    client_ip="$(current_ssh_client_ip)"
    print_header "Безопасный план UFW"
    echo -e "${CYAN}Фактический порт sshd:${NC} $ssh_port"
    [[ -z "$client_ip" ]] || echo -e "${CYAN}Адрес текущей SSH-сессии:${NC} $client_ip"
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

    echo; print_warning "Существующие правила будут заменены. Сначала создаётся полная копия /etc/ufw."
    read -r -p "Применить показанный план? [y/N]: " value
    [[ "$value" =~ ^[Yy]$ ]] || { print_step "Настройка отменена."; return 0; }

    rm -rf "$BACKUP_DIR/ufw"
    cp -a /etc/ufw "$BACKUP_DIR/ufw"
    LC_ALL=C ufw status | grep -q '^Status: active' && UFW_WAS_ACTIVE=1 || UFW_WAS_ACTIVE=0
    ROLLBACK_KIND=ufw; ROLLBACK_ACTIVE=1
    ufw --force disable >/dev/null 2>&1 || true
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
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
    ufw --dry-run enable >/dev/null
    ufw --force enable
    ufw status numbered

    print_warning "Не закрывайте эту сессию. Откройте вторую SSH-сессию и проверьте вход."
    read -r -p "Вторая SSH-сессия успешно подключилась? [y/N]: " value
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

    mkdir -p /etc/ssh/sshd_config.d
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
    if [[ -f /etc/ssh/sshd_config.d/00-server-scripts.conf ]]; then
        cp -a /etc/ssh/sshd_config.d/00-server-scripts.conf "$BACKUP_DIR/00-server-scripts.conf"
    else
        rm -f "$BACKUP_DIR/00-server-scripts.conf"
    fi
    ROLLBACK_KIND=ssh; ROLLBACK_ACTIVE=1

    render_ssh_dropin > /etc/ssh/sshd_config.d/00-server-scripts.conf
    chmod 0644 /etc/ssh/sshd_config.d/00-server-scripts.conf
    sshd -t

    local effective
    effective="$(sshd -T)"
    grep -q '^permitrootlogin without-password$\|^permitrootlogin prohibit-password$' <<< "$effective"
    grep -q '^pubkeyauthentication yes$' <<< "$effective"
    grep -q '^passwordauthentication no$' <<< "$effective"
    grep -q '^kbdinteractiveauthentication no$' <<< "$effective"
    systemctl reload ssh
    systemctl is-active --quiet ssh

    print_warning "Не закрывайте текущую сессию. Откройте вторую SSH-сессию тем же ключом."
    local confirmed
    read -r -p "Вход по ключу во второй сессии успешен? [y/N]: " confirmed
    if [[ "$confirmed" =~ ^[Yy]$ ]]; then
        ROLLBACK_ACTIVE=0; ROLLBACK_KIND=""
        log "INFO" "Конфигурация SSH проверена sshd -t, перезагружена и подтверждена второй сессией."
        print_success "SSH настроен безопасно. Резервная копия: $BACKUP_DIR"
    else
        rollback 0
        print_error "Новая конфигурация SSH отменена; восстановлена предыдущая."
    fi
}

# Системные твики
apply_system_tweaks() {
    log "INFO" "Применение системных твиков..."

    # Оптимизация TCP/IP стека
    cat >> /etc/sysctl.conf << EOF
# Оптимизация сети
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_max_tw_buckets = 720000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
EOF
    sysctl -p
    log "INFO" "Системные твики применены."
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
        echo -e "$i) ${GREEN}Установить DNSCrypt-proxy${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Настроить файрволл (UFW)${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Сменить пароль root${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Настроить SSH${NC}"
        ((i++))
        echo -e "$i) ${GREEN}Применить системные твики${NC}"
        ((i++))
        echo -e "$i) ${YELLOW}Выполнить все задачи автоматически${NC}"
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
                install_dependencies_and_update_system
                install_dnscrypt
                configure_firewall
                change_root_password
                configure_ssh
                apply_system_tweaks
                ;;
            8)
                manage_ipv6
                ;;
            9)
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
