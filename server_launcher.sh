#!/bin/bash

# Version: 1.0.3
# Author: gopnikgame
# Created: 2025-02-20 10:31:01
# Last Modified: 2025-02-20 17:40:36
# Current User: gopnikgame

# Цветовые коды
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Константы
SCRIPT_DIR="/root/server-scripts"
MODULES_DIR="/usr/local/server-scripts/modules"
LOG_DIR="/var/log/server-scripts"
GITHUB_RAW="https://raw.githubusercontent.com/gopnikgame/Server_scripts/main"
SCRIPT_VERSION="1.0.3"
SCRIPT_NAME="server_launcher.sh"

# Массив модулей с версиями
declare -A MODULES=(
    ["ubuntu_pre_install.sh"]="Первоначальная настройка Ubuntu 24.04"
    ["install_xanmod.sh"]="Установка XanMod Kernel с BBR3"
    ["bbr_info.sh"]="Проверка и настройка конфигурации BBR"
)

# Функция логирования
log() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [$1] $2"
    echo -e "${timestamp} [$1] $2" >> "$LOG_DIR/server-scripts.log"
}

# Создание необходимых директорий
create_directories() {
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$MODULES_DIR"
    mkdir -p "$LOG_DIR"
    chmod 755 "$SCRIPT_DIR"
    chmod 755 "$MODULES_DIR"
    chmod 755 "$LOG_DIR"
}

# Проверка и загрузка модулей
check_and_download_modules() {
    local missing_modules=0
    local force_update=${1:-false}
    
    echo -e "${YELLOW}Проверка и загрузка модулей...${NC}"
    for module in "${!MODULES[@]}"; do
        if [ ! -f "$MODULES_DIR/$module" ] || [ "$force_update" = true ]; then
            echo -ne "${BLUE}Загрузка модуля ${module}... ${NC}"
            if wget -q "$GITHUB_RAW/$module" -O "$MODULES_DIR/$module.tmp"; then
                mv "$MODULES_DIR/$module.tmp" "$MODULES_DIR/$module"
                chmod +x "$MODULES_DIR/$module"
                echo -e "${GREEN}[OK]${NC}"
            else
                rm -f "$MODULES_DIR/$module.tmp"
                echo -e "${RED}[ОШИБКА]${NC}"
                ((missing_modules++))
            fi
        fi
    done
    
    return $missing_modules
}

# Проверка root прав
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Этот скрипт должен быть запущен с правами root${NC}"
        exit 1
    fi
}

# Проверка зависимостей
check_dependencies() {
    local deps=("wget" "curl" "sysctl" "modinfo" "grep")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW}Установка необходимых зависимостей: ${missing_deps[*]}${NC}"
        if [ -f /etc/debian_version ]; then
            apt-get update -qq
            apt-get install -y "${missing_deps[@]}" procps
        elif [ -f /etc/redhat-release ]; then
            yum install -y "${missing_deps[@]}" procps-ng
        else
            echo -e "${RED}Неподдерживаемый дистрибутив${NC}"
            exit 1
        fi
    fi
}

# Функция самообновления
self_update() {
    echo -e "${YELLOW}Проверка обновлений...${NC}"
    
    # Загрузка новой версии
    if wget -q "$GITHUB_RAW/$SCRIPT_NAME" -O "/tmp/$SCRIPT_NAME.tmp"; then
        # Сравнение версий
        local new_version=$(grep "# Version:" "/tmp/$SCRIPT_NAME.tmp" | awk '{print $3}')
        if [ "$new_version" != "$SCRIPT_VERSION" ]; then
            echo -e "${GREEN}Доступна новая версия ($new_version)! Обновление...${NC}"
            mv "/tmp/$SCRIPT_NAME.tmp" "$SCRIPT_DIR/$SCRIPT_NAME"
            chmod +x "$SCRIPT_DIR/$SCRIPT_NAME"
            echo -e "${GREEN}Скрипт успешно обновлен до версии $new_version${NC}"
            # Перезапуск скрипта
            exec "$SCRIPT_DIR/$SCRIPT_NAME"
        else
            echo -e "${GREEN}У вас установлена последняя версия${NC}"
            rm -f "/tmp/$SCRIPT_NAME.tmp"
        fi
    else
        echo -e "${RED}Ошибка проверки обновлений${NC}"
    fi
}

# Показать главное меню
show_main_menu() {
    clear
    echo -e "${BLUE}=== Server Scripts Manager v${SCRIPT_VERSION} ===${NC}"
    echo -e "${YELLOW}Выберите действие:${NC}"
    echo
    local i=1
    
    # Вывод доступных модулей
    for module in "${!MODULES[@]}"; do
        echo -e "$i) ${GREEN}${MODULES[$module]}${NC}"
        ((i++))
    done
    
    # Системные опции
    echo -e "$i) ${YELLOW}Обновить все модули${NC}"
    ((i++))
    echo -e "$i) ${YELLOW}Обновить launcher${NC}"
    ((i++))
    echo -e "0) ${RED}Выход${NC}"
    echo
    
    read -p "Выберите опцию [0-$((i-1))]: " choice
    
    case $choice in
        0)
            echo -e "${YELLOW}До свидания!${NC}"
            exit 0
            ;;
        $((i-1)))
            self_update
            ;;
        $((i-2)))
            check_and_download_modules true
            ;;
        *)
            if [ $choice -gt 0 ] && [ $choice -lt $((i-2)) ]; then
                local module_name=(${!MODULES[@]})
                run_module "${module_name[$((choice-1))]}"
            else
                echo -e "${RED}Неверный выбор${NC}"
            fi
            ;;
    esac
    
    # Пауза перед возвратом в меню
    echo
    read -p "Нажмите Enter для продолжения..."
    show_main_menu
}

# Запуск выбранного модуля
run_module() {
    local module_name=$1
    if [ -f "$MODULES_DIR/$module_name" ]; then
        echo -e "${YELLOW}Запуск модуля: $module_name${NC}"
        bash "$MODULES_DIR/$module_name"
        return $?
    else
        echo -e "${RED}Модуль $module_name не найден${NC}"
        return 1
    fi
}

# Установка скрипта
install_script() {
    # Создание директорий
    create_directories
    
    # Копирование скрипта
    if [ ! -f "$SCRIPT_DIR/$SCRIPT_NAME" ]; then
        cp "$0" "$SCRIPT_DIR/$SCRIPT_NAME"
        chmod +x "$SCRIPT_DIR/$SCRIPT_NAME"
    fi
    
    # Создание символической ссылки
    if [ ! -L "/usr/local/bin/$SCRIPT_NAME" ]; then
        ln -s "$SCRIPT_DIR/$SCRIPT_NAME" "/usr/local/bin/$SCRIPT_NAME"
    fi
    
    # Загрузка модулей
    check_and_download_modules
}

# Основная функция
main() {
    # Проверки
    check_root
    check_dependencies
    
    # Если скрипт запущен напрямую из curl
    if [ ! -f "$SCRIPT_DIR/$SCRIPT_NAME" ]; then
        echo -e "${YELLOW}Первый запуск - установка скрипта...${NC}"
        install_script
    fi
    
    # Показ меню
    show_main_menu
}

# Запуск основной функции
main "$@"