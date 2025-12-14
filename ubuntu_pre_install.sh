#!/bin/bash
set -e

# Метаданные скрипта
SCRIPT_VERSION="1.1.1"
SCRIPT_DATE="2025-05-14 14:30:00"
SCRIPT_AUTHOR="gopnikgame"

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

# Константы
BACKUP_DIR="/root/config_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/system_setup.log"
MIN_FREE_SPACE_KB=2097152  # 2GB в килобайтах

# Создаем директорию для резервных копий и логов
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Функция логирования с цветным выводом
log() {
    local level="$1"
    shift
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    case "$level" in
        "INFO") local color=$GREEN ;;
        "WARNING") local color=$YELLOW ;;
        "ERROR") local color=$RED ;;
        *) local color=$NC ;;
    esac
    echo -e "${timestamp} [${color}${level}${NC}] $*"
    echo "${timestamp} [${level}] $*" >> "$LOG_FILE"
}

# Функция отката изменений
rollback() {
    log "ERROR" "Произошла ошибка. Выполняется откат изменений..."
    exit 1
}

# Установка обработчика ошибок
trap rollback ERR

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    log "ERROR" "Этот скрипт должен быть запущен с правами root"
    exit 1
fi

# Проверка свободного места на диске
check_free_space() {
    local free_space_kb=$(df -k --output=avail "$PWD" | tail -n1)
    if [ "$free_space_kb" -lt "$MIN_FREE_SPACE_KB" ]; then
        log "ERROR" "Недостаточно свободного места на диске. Требуется минимум $((MIN_FREE_SPACE_KB / 1024)) MB."
        exit 1
    fi
}

log "INFO" "Проверка свободного места на диске..."
check_free_space

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

# Установка зависимостей и обновление системы
install_dependencies_and_update_system() {
    log "INFO" "Установка зависимостей и обновление системы..."
    print_header "Установка зависимых пакетов и обновление системы"
    
    # Список необходимых пакетов
    local required_packages=(
        curl wget git htop neofetch mc
        net-tools nmap tcpdump iotop
        unzip tar vim tmux screen
        rsync ncdu dnsutils
        whois ufw openssh-server
        mtr
    )
    
    # Обновление списка пакетов
    print_step "Обновление списков пакетов..."
    apt update
    
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
        apt install -y "${packages_to_install[@]}"
        print_success "Зависимости установлены."
        log "INFO" "Установлены пакеты: ${packages_to_install[*]}"
    else
        print_success "Все необходимые зависимости уже установлены."
        log "INFO" "Все необходимые зависимости уже установлены."
    fi
    
    # Обновление системы
    print_step "Обновление системы..."
    apt upgrade -y
    apt dist-upgrade -y
    log "INFO" "Система обновлена."
    
    # Очистка системы после обновления
    print_step "Очистка системы после обновления..."
    
    # Запоминаем свободное место до очистки
    local free_space_before=$(df -h / | awk 'NR==2 {print $4}')
    
    # Удаление устаревших пакетов
    print_step "Удаление неиспользуемых пакетов..."
    apt autoremove -y
    
    # Очистка архивов пакетов
    print_step "Очистка устаревших архивов пакетов..."
    apt autoclean
    
    # Проверка свободного места после очистки
    local free_space_after=$(df -h / | awk 'NR==2 {print $4}')
    
    print_success "Система успешно обновлена и очищена."
    log "INFO" "Система успешно обновлена и очищена. Свободно места: $free_space_after (было: $free_space_before)"
    
    # Вывод версий важных компонентов
    print_step "Проверка установленных версий..."
    
    # Основные пакеты, версии которых стоит проверить
    local key_packages=("curl" "wget" "git" "openssh-server" "mtr")
    
    echo -e "\n${CYAN}Версии ключевых компонентов:${NC}"
    for pkg in "${key_packages[@]}"; do
        if command -v "$pkg" &> /dev/null; then
            local version=$($pkg --version 2>&1 | head -n 1)
            echo -e "${GREEN}✓${NC} $pkg: $version"
        else
            echo -e "${RED}✘${NC} $pkg: не установлен"
        fi
    done
    
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
    
    # URL скрипта установки
    local DNSCRYPT_INSTALL_URL="https://raw.githubusercontent.com/gopnikgame/Installer_dnscypt/main/quick_install.sh"
    
    print_step "Загрузка скрипта установки DNSCrypt..."
    
    # Создаем временную директорию
    local temp_dir=$(mktemp -d)
    local install_script="$temp_dir/dnscrypt_install.sh"
    
    # Скачиваем скрипт
    if curl -fsSL "$DNSCRYPT_INSTALL_URL" -o "$install_script"; then
        log "INFO" "Скрипт установки успешно загружен."
        print_success "Скрипт установки загружен."
    else
        log "ERROR" "Не удалось загрузить скрипт установки DNSCrypt."
        print_error "Ошибка загрузки скрипта. Проверьте подключение к интернету."
        rm -rf "$temp_dir"
        return 1
    fi
    
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
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Очищаем временные файлы
    rm -rf "$temp_dir"
    
    echo
    print_step "Дальнейшая настройка DNS будет выполняться через DNSCrypt-proxy."
    
    return 0
}

# Настройка файрволла (UFW)
configure_firewall() {
    log "INFO" "Настройка UFW..."

    # Сброс существующих правил UFW
    log "INFO" "Сброс существующих правил UFW..."
    print_step "Сброс правил UFW..."
    
    # Проверка статуса UFW
    if ufw status | grep -q "Status: active"; then
        log "INFO" "UFW активен, отключаем перед сбросом правил..."
        yes | ufw disable >/dev/null 2>&1
    fi
    
    # Сброс всех правил
    log "INFO" "Сброс правил UFW до настроек по умолчанию..."
    ufw --force reset >/dev/null 2>&1
    print_success "Правила UFW сброшены"
    
    # Создание резервной копии конфигурации UFW
    if [ -d "/etc/ufw" ]; then
        for ufw_config in /etc/ufw/user*.rules; do
            if [ -f "$ufw_config" ]; then
                backup_file "$ufw_config"
            fi
        done
        if [ -f "/etc/ufw/ufw.conf" ]; then
            backup_file "/etc/ufw/ufw.conf"
        fi
    fi

    # Блокировка IP-адресов из AS61280 (IPv4 и IPv6)
    log "INFO" "Получение списка IP-адресов для блокировки (AS61280)..."
    blocked_ips=$(whois -h whois.radb.net -- '-i origin AS61280' | grep -E '^route|^route6' | awk '{print $2}')
    if [ -z "$blocked_ips" ]; then
        log "WARNING" "Не удалось получить IP-адреса для блокировки."
    else
        log "INFO" "Блокировка IP-адресов из AS61280..."
        for ip in $blocked_ips; do
            ufw deny from "$ip" to any
            log "INFO" "Заблокирован IP-адрес: $ip"
        done
    fi

    # Основные правила UFW
    ufw default deny incoming
    ufw default allow outgoing
    
    # Порт 443 (HTTPS) открыт по умолчанию
    ufw allow 443/tcp
    log "INFO" "Открыт порт 443 (HTTPS)"
    
    # Спрашиваем пользователя о порте 80 (HTTP)
    echo -e "\n${YELLOW}=== Настройка порта 80 (HTTP) ===${NC}"
    read -p "Открыть порт 80 (HTTP)? [y/n]: " open_http
    if [[ "$open_http" =~ ^[Yy]$ ]]; then
        ufw allow 80/tcp
        log "INFO" "Открыт порт 80 (HTTP)"
    else
        log "INFO" "Порт 80 (HTTP) не будет открыт"
    fi
    
    # Настройка порта SSH
    echo -e "\n${YELLOW}=== Настройка порта SSH ===${NC}"
    local ssh_port=22
    read -p "Введите порт SSH [по умолчанию 22]: " custom_ssh_port
    
    # Проверка введенного порта
    if [ -n "$custom_ssh_port" ]; then
        if [[ "$custom_ssh_port" =~ ^[0-9]+$ ]] && [ "$custom_ssh_port" -ge 1 ] && [ "$custom_ssh_port" -le 65535 ]; then
            ssh_port=$custom_ssh_port
            log "INFO" "Установлен кастомный порт SSH: $ssh_port"
        else
            log "WARNING" "Некорректный порт. Используется порт по умолчанию: 22"
            print_error "Некорректный порт. Используется порт 22"
            ssh_port=22
        fi
    else
        log "INFO" "Используется порт SSH по умолчанию: 22"
    fi
    
    echo -e "${CYAN}Порт SSH:${NC} $ssh_port"
    
    # Настройка доступа к SSH
    echo -e "\n${YELLOW}=== Настройка доступа к SSH (порт $ssh_port) ===${NC}"
    read -p "Настроить SSH только для определенных IP-адресов? [y/n]: " restrict_ssh
    if [[ "$restrict_ssh" =~ ^[Yy]$ ]]; then
        log "INFO" "Настройка доступа к SSH для определенных IP-адресов"
        ssh_allowed_ips=()
        
        echo "Введите IP-адреса для доступа к SSH (оставьте поле пустым и нажмите Enter для завершения):"
        while true; do
            # Отображаем текущий список IP-адресов
            if [ ${#ssh_allowed_ips[@]} -gt 0 ]; then
                echo -e "${CYAN}Добавленные IP-адреса: ${ssh_allowed_ips[*]}${NC}"
            fi
            
            read -p "IP-адрес для SSH: " ip_addr
            
            # Проверка, пустой ли ввод
            if [ -z "$ip_addr" ]; then
                if [ ${#ssh_allowed_ips[@]} -eq 0 ]; then
                    # Список пуст, просто выходим
                    log "INFO" "IP-адреса для SSH не указаны, порт $ssh_port будет открыт для всех"
                    ufw allow $ssh_port/tcp
                    break
                else
                    # Список не пуст, спрашиваем о завершении
                    read -p "Вы закончили вводить IP-адреса? [y/n]: " done_adding
                    if [[ "$done_adding" =~ ^[Yy]$ ]]; then
                        break
                    fi
                fi
            elif [[ "$ip_addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                # Базовая валидация IP-адреса
                ssh_allowed_ips+=("$ip_addr")
                log "INFO" "Добавлен IP-адрес для SSH: $ip_addr"
            else
                print_error "Некорректный формат IP-адреса"
            fi
        done
        
        # Применяем правила для SSH если есть IP-адреса
        if [ ${#ssh_allowed_ips[@]} -gt 0 ]; then
            log "INFO" "Настройка правил SSH для указанных IP-адресов (порт $ssh_port)"
            for ip in "${ssh_allowed_ips[@]}"; do
                ufw allow from "$ip" to any port $ssh_port proto tcp
                log "INFO" "Разрешен доступ к SSH (порт $ssh_port) для IP: $ip"
            done
        fi
    else
        # Открываем SSH для всех
        ufw allow $ssh_port/tcp
        log "INFO" "Порт $ssh_port (SSH) открыт для всех"
    fi
    
    # Настройка пользовательских портов
    echo -e "\n${YELLOW}=== Настройка пользовательских портов ===${NC}"
    read -p "Настроить дополнительные порты? [y/n]: " custom_ports
    if [[ "$custom_ports" =~ ^[Yy]$ ]]; then
        log "INFO" "Настройка дополнительных портов"
        custom_port_list=()
        
        echo "Введите номера портов для открытия (оставьте поле пустым и нажмите Enter для завершения):"
        while true; do
            # Отображаем текущий список портов
            if [ ${#custom_port_list[@]} -gt 0 ]; then
                echo -e "${CYAN}Добавленные порты: ${custom_port_list[*]}${NC}"
            fi
            
            read -p "Номер порта: " port_num
            
            # Проверка, пустой ли ввод
            if [ -z "$port_num" ]; then
                if [ ${#custom_port_list[@]} -eq 0 ]; then
                    # Список пуст, просто выходим
                    log "INFO" "Дополнительные порты не указаны"
                    break
                else
                    # Список не пуст, спрашиваем о завершении
                    read -p "Вы закончили вводить порты? [y/n]: " done_ports
                    if [[ "$done_ports" =~ ^[Yy]$ ]]; then
                        break
                    fi
                fi
            elif [[ "$port_num" =~ ^[0-9]+$ ]] && [ "$port_num" -ge 1 ] && [ "$port_num" -le 65535 ]; then
                # Валидный номер порта
                custom_port_list+=("$port_num")
                log "INFO" "Добавлен порт: $port_num"
            else
                print_error "Некорректный номер порта (должен быть от 1 до 65535)"
            fi
        done
        
        # Если есть порты для настройки
        if [ ${#custom_port_list[@]} -gt 0 ]; then
            # Спрашиваем о настройке доступа по IP
            echo -e "\n${YELLOW}Настройка доступа к пользовательским портам${NC}"
            read -p "Ограничить доступ к пользовательским портам по IP? [y/n]: " restrict_custom_ports
            
            if [[ "$restrict_custom_ports" =~ ^[Yy]$ ]]; then
                # Ограничение по IP
                custom_ip_list=()
                
                echo "Введите IP-адреса для доступа к пользовательским портам (оставьте поле пустым для завершения):"
                while true; do
                    # Отображаем текущий список IP
                    if [ ${#custom_ip_list[@]} -gt 0 ]; then
                        echo -e "${CYAN}Добавленные IP-адреса: ${custom_ip_list[*]}${NC}"
                    fi
                    
                    read -p "IP-адрес: " custom_ip
                    
                    # Проверка, пустой ли ввод
                    if [ -z "$custom_ip" ]; then
                        if [ ${#custom_ip_list[@]} -eq 0 ]; then
                            # Список пуст, выходим и будем открывать порты для всех
                            log "INFO" "IP-адреса для пользовательских портов не указаны, порты будут открыты для всех"
                            for port in "${custom_port_list[@]}"; do
                                ufw allow "$port/tcp"
                                log "INFO" "Открыт порт $port/tcp для всех"
                            done
                            break
                        else
                            # Список не пуст, спрашиваем о завершении
                            read -p "Вы закончили вводить IP-адреса? [y/n]: " done_ips
                            if [[ "$done_ips" =~ ^[Yy]$ ]]; then
                                # Применяем правила для каждого порта и IP
                                for port in "${custom_port_list[@]}"; do
                                    for ip in "${custom_ip_list[@]}"; do
                                        ufw allow from "$ip" to any port "$port" proto tcp
                                        log "INFO" "Разрешен доступ к порту $port/tcp для IP: $ip"
                                    done
                                done
                                break
                            fi
                        fi
                    elif [[ "$custom_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                        # Валидный IP
                        custom_ip_list+=("$custom_ip")
                        log "INFO" "Добавлен IP-адрес для пользовательских портов: $custom_ip"
                    else
                        print_error "Некорректный формат IP-адреса"
                    fi
                done
            else
                # Открываем порты для всех
                for port in "${custom_port_list[@]}"; do
                    ufw allow "$port/tcp"
                    log "INFO" "Открыт порт $port/tcp для всех"
                done
            fi
        fi
    fi

    # Активация UFW
    echo -e "\n${YELLOW}=== Активация файрволла UFW ===${NC}"
    print_step "Активация UFW..."
    yes | ufw enable
    log "INFO" "UFW успешно настроен и активирован."
    print_success "UFW успешно настроен."
    
    # Вывод статуса UFW
    echo -e "\n${YELLOW}=== Текущие правила UFW ===${NC}"
    ufw status numbered
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
    if ! systemctl is-active --quiet ssh; then
        log "INFO" "Служба SSH не найдена. Установка OpenSSH..."
        apt install -y openssh-server
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

        # Проверка валидности публичного ключа
        if [[ -z "$public_key" || ! "$public_key" =~ ^ssh-(rsa|ed25519|ecdsa) ]]; then
            log "ERROR" "Некорректный публичный ключ. Убедитесь, что вы ввели его правильно."
            exit 1
        fi

        # Добавление публичного ключа в authorized_keys
        echo "$public_key" >> /root/.ssh/authorized_keys
        log "INFO" "Публичный ключ успешно добавлен в /root/.ssh/authorized_keys."
    fi

    # Настройка параметров SSH
    update_ssh_config() {
        local key="$1"
        local value="$2"
        if ! grep -q "^$key" /etc/ssh/sshd_config; then
            echo "$key $value" >> /etc/ssh/sshd_config
        else
            sed -i "s/^$key.*/$key $value/" /etc/ssh/sshd_config
        fi
    }

    update_ssh_config "PermitRootLogin" "prohibit-password"
    update_ssh_config "PasswordAuthentication" "no"
    update_ssh_config "X11Forwarding" "no"
    update_ssh_config "MaxAuthTries" "3"
    update_ssh_config "Protocol" "2"
    update_ssh_config "AllowAgentForwarding" "no"
    update_ssh_config "AllowTcpForwarding" "no"
    update_ssh_config "LoginGraceTime" "30"

    # Перезапуск службы SSH
    systemctl restart ssh
    log "INFO" "Служба SSH перезапущена. Парольная аутентификация отключена."
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

# Запуск главного меню
show_menu

# Финальная информация
log "INFO" "=== Установка завершена ==="
log "INFO" "Backup directory: $BACKUP_DIR"
log "INFO" "Log file: $LOG_FILE"

# Запрос на перезагрузку
if tty -s; then
    read -p "Перезагрузить систему сейчас? (y/n): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        log "INFO" "Выполняется перезагрузка..."
        shutdown -r now
    else
        log "WARNING" "Перезагрузка отложена. Рекомендуется перезагрузить систему позже."
    fi
else
    log "INFO" "Скрипт запущен в неинтерактивном режиме. Перезагрузка не выполняется."
fi