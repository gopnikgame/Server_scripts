#!/bin/bash

# Version: 1.0.0
# Author: gopnikgame
# Created: 2025-02-20 20:00:00
# Last Modified: 2025-02-20 20:00:00
# Description: Swap file management module

set -Eeuo pipefail

# Цветовые коды
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Константы
SWAPFILE="${SWAPFILE:-/swapfile}"
LOG_FILE="${LOG_FILE:-/var/log/system_setup.log}"
FSTAB_FILE="${FSTAB_FILE:-/etc/fstab}"

# Функции для красивого вывода
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

# Функция логирования
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

is_swap_active() {
    swapon --noheadings --raw --output=NAME 2>/dev/null | grep -Fxq -- "$SWAPFILE"
}

fstab_has_swap() {
    awk -v path="$SWAPFILE" '$1 == path && $3 == "swap" {found=1} END {exit !found}' "$FSTAB_FILE"
}

ensure_fstab_entry() {
    fstab_has_swap || printf '%s none swap sw 0 0\n' "$SWAPFILE" >> "$FSTAB_FILE"
}

# Проверка root прав
check_root() {
    if [ "$EUID" -ne 0 ]; then
  log "ERROR" "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
}

# Функция управления файлом подкачки (swap)
manage_swap() {
    check_root

    while true; do
        print_header "Управление файлом подкачки (Swap)"
        
        # Проверяем текущее состояние swap
        local current_swap_size=0 file_size_bytes
        local swap_enabled=false
        local swap_file_exists=false
        
        if [ -f "$SWAPFILE" ]; then
      swap_file_exists=true
      file_size_bytes=$(stat -c%s "$SWAPFILE" 2>/dev/null || echo "0")
      current_swap_size=$((file_size_bytes / 1024 / 1024))
  fi
        
    if is_swap_active; then
   swap_enabled=true
        fi
        
 # Получаем общую информацию о swap в системе
        local total_swap_mb=0
        if command -v free &> /dev/null; then
  total_swap_mb=$(free -m | awk '/Swap:/ {print $2}')
        fi

        # Выводим текущее состояние
        echo -e "${CYAN}Текущее состояние:${NC}"
     echo "----------------------------------------"
        if [ "$swap_enabled" = true ]; then
echo -e "Статус:   ${GREEN}Включен${NC}"
 echo -e "Размер файла:        ${GREEN}${current_swap_size} MB${NC}"
            echo -e "Путь к файлу:        ${BLUE}${SWAPFILE}${NC}"
        elif [ "$swap_file_exists" = true ]; then
            echo -e "Статус:              ${YELLOW}Отключен (файл существует)${NC}"
            echo -e "Размер файла:        ${YELLOW}${current_swap_size} MB${NC}"
    else
 echo -e "Статус:   ${RED}Не настроен${NC}"
        fi
        
        if [ "$total_swap_mb" -gt 0 ]; then
            echo -e "Всего swap в системе: ${BLUE}${total_swap_mb} MB${NC}"
        fi
    echo "----------------------------------------"
        echo
      
        # Показываем подробную информацию о swap, если он активен
        if [ "$swap_enabled" = true ]; then
  echo -e "${CYAN}Подробная информация:${NC}"
  swapon --show 2>/dev/null || echo "Информация недоступна"
       echo
        fi
        
   # Рекомендации по размеру
      local total_ram_mb=0
        if command -v free &> /dev/null; then
            total_ram_mb=$(free -m | awk '/Mem:/ {print $2}')
        fi
        
 local recommended_swap=2048
      if [ "$total_ram_mb" -gt 0 ]; then
   if [ "$total_ram_mb" -le 2048 ]; then
    recommended_swap=$((total_ram_mb * 2))
    elif [ "$total_ram_mb" -le 8192 ]; then
      recommended_swap=$total_ram_mb
            else
      recommended_swap=$((total_ram_mb / 2))
            fi
            
     echo -e "${YELLOW}ℹ️  Информация о системе:${NC}"
      echo "Оперативная память: ${total_ram_mb} MB"
      echo "Рекомендуемый размер swap: ${recommended_swap} MB"
    echo
        fi
   
        # Меню действий
        echo -e "${YELLOW}Доступные действия:${NC}"
   
        if [ "$swap_enabled" = true ]; then
        echo "1. Изменить размер swap"
     echo "2. Отключить swap"
        elif [ "$swap_file_exists" = true ]; then
            echo "1. Включить swap"
    echo "2. Изменить размер и включить swap"
   echo "3. Удалить файл swap"
     else
   echo "1. Создать и включить swap"
  fi
        
   echo "0. Вернуться в главное меню"
        echo
        
        read -p "Выберите действие: " choice
        echo
        
        case $choice in
  0)
      return 0
      ;;
   1)
           if [ "$swap_enabled" = true ]; then
        # Изменить размер активного swap
    change_swap_size "$current_swap_size" "$recommended_swap"
    elif [ "$swap_file_exists" = true ]; then
       # Включить существующий swap
enable_existing_swap
         else
         # Создать новый swap
                    create_new_swap "$recommended_swap"
      fi
        ;;
      2)
       if [ "$swap_enabled" = true ]; then
          # Отключить swap
      disable_swap false
      elif [ "$swap_file_exists" = true ]; then
      # Изменить размер неактивного swap
       change_swap_size "$current_swap_size" "$recommended_swap"
      else
  print_error "Неверный выбор"
                fi
             ;;
   3)
     if [ "$swap_file_exists" = true ] && [ "$swap_enabled" = false ]; then
        # Удалить файл swap
    disable_swap true
  else
            print_error "Неверный выбор"
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

# Функция создания нового swap
create_new_swap() {
    local recommended_size="$1"
    
  print_step "Создание файла подкачки"
    echo -e "${CYAN}Рекомендуемый размер: ${recommended_size} MB${NC}"
    echo -e "${YELLOW}Примеры ввода:${NC}"
    echo "  512    - для 512 MB"
    echo "  1024   - для 1 GB"
    echo "  2048   - для 2 GB"
    echo "  4096   - для 4 GB"
    echo
    
    local swap_size
    while true; do
        read -p "Введите размер swap в MB [${recommended_size}]: " input_size
     swap_size="${input_size:-$recommended_size}"
    
        # Проверка корректности ввода
        if [[ "$swap_size" =~ ^[0-9]+$ ]] && [ "$swap_size" -gt 0 ]; then
            # Проверка свободного места на диске
            local available_space_mb
            available_space_mb=$(df -m / | awk 'NR==2 {print $4}')
          
     if [ "$swap_size" -gt "$available_space_mb" ]; then
       print_error "Недостаточно свободного места. Доступно: ${available_space_mb} MB"
      read -p "Введите меньший размер или нажмите Ctrl+C для отмены: "
 continue
   fi
   
            # Предупреждение для очень больших файлов
  if [ "$swap_size" -gt 16384 ]; then
      echo -e "${YELLOW}⚠ Внимание: Вы указали размер больше 16 GB${NC}"
     read -p "Продолжить? [y/N]: " confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      continue
            fi
          fi
        
        break
        else
      print_error "Некорректный ввод. Введите число больше 0"
fi
    done
    
    log "INFO" "Создание файла подкачки размером ${swap_size} MB..."
    print_step "Создание файла подкачки размером ${swap_size} MB..."
    
    # Создание swap файла
    if ! fallocate -l "${swap_size}M" "$SWAPFILE" 2>/dev/null; then
        # Если fallocate не поддерживается, используем dd
        log "WARNING" "fallocate не поддерживается, используем dd (это может занять время)..."
        print_step "Создание файла с помощью dd (это может занять время)..."
        if ! dd if=/dev/zero of="$SWAPFILE" bs=1M count="$swap_size" status=progress 2>&1 | tee -a "$LOG_FILE"; then
            log "ERROR" "Ошибка при создании файла подкачки"
       print_error "Ошибка при создании файла подкачки"
        return 1
        fi
    fi
    
    # Установка правильных прав доступа
    chmod 600 "$SWAPFILE"
    log "INFO" "Установлены права доступа 600 для $SWAPFILE"
    
    # Форматирование как swap
    print_step "Форматирование файла как swap..."
    if ! mkswap "$SWAPFILE" 2>&1 | tee -a "$LOG_FILE"; then
  log "ERROR" "Ошибка при форматировании swap"
  print_error "Ошибка при форматировании swap"
        rm -f "$SWAPFILE"
        return 1
    fi
    
    # Включение swap
    print_step "Активация swap..."
    if ! swapon "$SWAPFILE" 2>&1 | tee -a "$LOG_FILE"; then
 log "ERROR" "Ошибка при активации swap"
  print_error "Ошибка при активации swap"
        return 1
    fi
    
    # Добавление в fstab для автоматического монтирования
    if ! fstab_has_swap; then
        print_step "Добавление записи в /etc/fstab..."
        ensure_fstab_entry
        log "INFO" "Добавлена запись в /etc/fstab"
    fi
    
    log "INFO" "Файл подкачки успешно создан и активирован"
    print_success "Swap успешно создан и активирован (${swap_size} MB)"
    
    # Показываем текущее состояние
    echo
    print_step "Текущее состояние swap:"
    swapon --show
    echo
    free -h | grep -E "Swap|Mem"
    
    return 0
}

# Функция включения существующего swap
enable_existing_swap() {
    log "INFO" "Активация существующего файла подкачки..."
    print_step "Активация существующего файла подкачки..."
    
    # Проверка прав доступа
    chmod 600 "$SWAPFILE"
    
    # Активация swap
    if ! swapon "$SWAPFILE" 2>&1 | tee -a "$LOG_FILE"; then
  log "ERROR" "Ошибка при активации swap"
        print_error "Ошибка при активации swap. Возможно, файл поврежден."
    
        read -p "Пересоздать файл подкачки? [y/N]: " recreate
      if [[ "$recreate" =~ ^[Yy]$ ]]; then
            local file_size_mb
            file_size_mb=$(stat -c%s "$SWAPFILE" 2>/dev/null || echo "2147483648")
            file_size_mb=$((file_size_mb / 1024 / 1024))
            rm -f -- "$SWAPFILE"
          create_new_swap "$file_size_mb"
        fi
        return 1
    fi
    
    # Добавление в fstab если отсутствует
    if ! fstab_has_swap; then
        print_step "Добавление записи в /etc/fstab..."
        ensure_fstab_entry
 log "INFO" "Добавлена запись в /etc/fstab"
    fi
    
    log "INFO" "Файл подкачки успешно активирован"
    print_success "Swap успешно активирован"
    
    # Показываем текущее состояние
    echo
    print_step "Текущее состояние swap:"
    swapon --show
    
    return 0
}

# Функция изменения размера swap
change_swap_size() {
    local current_size="$1"
    local recommended_size="$2"
    
    print_step "Изменение размера файла подкачки"
    echo -e "${CYAN}Текущий размер: ${current_size} MB${NC}"
    echo -e "${CYAN}Рекомендуемый размер: ${recommended_size} MB${NC}"
    echo -e "${YELLOW}Примеры ввода:${NC}"
    echo "  512    - для 512 MB"
    echo "  1024   - для 1 GB"
    echo "  2048   - для 2 GB"
    echo "  4096   - для 4 GB"
echo
    
    local new_size
    while true; do
        read -p "Введите новый размер swap в MB [${recommended_size}]: " input_size
      new_size="${input_size:-$recommended_size}"
        
        # Проверка корректности ввода
     if [[ "$new_size" =~ ^[0-9]+$ ]] && [ "$new_size" -gt 0 ]; then
            # Проверка, не совпадает ли с текущим размером
            if [ "$new_size" -eq "$current_size" ]; then
           print_error "Указанный размер совпадает с текущим"
         read -p "Введите другой размер или нажмите Ctrl+C для отмены: "
     continue
        fi
        
            # Проверка свободного места
            local available_space_mb required_space
            available_space_mb=$(df -m / | awk 'NR==2 {print $4}')
            required_space=$((new_size - current_size))
      
     if [ "$required_space" -gt 0 ] && [ "$required_space" -gt "$available_space_mb" ]; then
    print_error "Недостаточно свободного места. Доступно: ${available_space_mb} MB"
       read -p "Введите меньший размер или нажмите Ctrl+C для отмены: "
                continue
       fi
   
            break
      else
        print_error "Некорректный ввод. Введите число больше 0"
        fi
    done
    
    log "INFO" "Изменение размера swap с ${current_size} MB на ${new_size} MB..."
    
    # Отключаем swap если он активен
    local was_active=false backup_file="${SWAPFILE}.server-scripts-backup"
    if is_swap_active; then
        was_active=true
        print_step "Отключение текущего swap..."
        if ! swapoff "$SWAPFILE" 2>&1 | tee -a "$LOG_FILE"; then
            print_error "Не удалось отключить старый swap; файл оставлен без изменений"
            return 1
        fi
    fi

    rm -f -- "$backup_file"
    mv -- "$SWAPFILE" "$backup_file"
    if create_new_swap "$new_size"; then
        rm -f -- "$backup_file"
        return 0
    fi

    print_error "Новый swap не активирован; восстанавливаем прежний файл"
    rm -f -- "$SWAPFILE"
    mv -- "$backup_file" "$SWAPFILE"
    if [[ "$was_active" == true ]]; then swapon "$SWAPFILE" || true; fi
    return 1
}

# Функция отключения swap
disable_swap() {
    local delete_file="${1:-false}"
    
    log "INFO" "Отключение файла подкачки..."
    
    # Отключаем swap если он активен
  if is_swap_active; then
        print_step "Отключение swap..."
      if ! swapoff "$SWAPFILE" 2>&1 | tee -a "$LOG_FILE"; then
          log "ERROR" "Ошибка при отключении swap"
        print_error "Ошибка при отключении swap"
       return 1
  fi
        log "INFO" "Swap успешно отключен"
        print_success "Swap отключен"
    fi

    # Удаляем из fstab
    if fstab_has_swap; then
        print_step "Удаление записи из /etc/fstab..."
        sed -i "\|^${SWAPFILE//|/\\|}[[:space:]]|d" "$FSTAB_FILE"
     log "INFO" "Запись удалена из /etc/fstab"
        print_success "Запись удалена из /etc/fstab"
    fi
    
    # Удаляем файл если требуется
    if [ "$delete_file" = true ] && [ -f "$SWAPFILE" ]; then
        echo -e "${YELLOW}⚠ Внимание: Файл подкачки будет безвозвратно удален${NC}"
        read -p "Вы уверены? [y/N]: " confirm
  
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
  print_step "Удаление файла подкачки..."
      rm -f "$SWAPFILE"
            log "INFO" "Файл подкачки удален"
   print_success "Файл подкачки удален"
else
   log "INFO" "Удаление файла отменено пользователем"
       print_step "Файл подкачки сохранен (отключен)"
        fi
    fi
    
    # Показываем текущее состояние
    echo
    print_step "Текущее состояние swap:"
    if swapon --noheadings --raw --output=NAME 2>/dev/null | grep -q .; then
  swapon --show
    else
echo "Swap не активен"
    fi
    
    return 0
}

# Главная функция
main() {
    print_header "УПРАВЛЕНИЕ SWAP v1.0.0"
    manage_swap
}

# Запуск главной функции
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
