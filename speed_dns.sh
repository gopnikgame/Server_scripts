#!/bin/bash

# Функция для проверки существования команды
_exists() {
    command -v "$1" &>/dev/null
}

# Функции для цветного вывода
_red() {
    echo -e "\033[31m$1\033[0m"
}

_green() {
    echo -e "\033[32m$1\033[0m"
}

_yellow() {
    echo -e "\033[33m$1\033[0m"
}

_cyan() {
    echo -e "\033[1;36m$1\033[0m"
}

# Функция для автоматической установки необходимых утилит
install_required_tools() {
    local tool="$1"
    local pkg="$2"
    
    if ! _exists "$tool"; then
        echo " $(_yellow "Утилита $tool не найдена. Установка $pkg..."))"
        
        # Определяем пакетный менеджер
        if _exists "apt-get"; then
            apt-get update -qq && apt-get install -y "$pkg"
        elif _exists "yum"; then
            yum install -y "$pkg"
        elif _exists "dnf"; then
            dnf install -y "$pkg"
        elif _exists "zypper"; then
            zypper install -y "$pkg"
        elif _exists "apk"; then
            apk add "$pkg"
        else
            echo " $(_red "Не удалось определить пакетный менеджер. Установите $pkg вручную.")"
            return 1
        fi
        
        # Проверяем, установился ли пакет
        if _exists "$tool"; then
            echo " $(_green "✓ $tool успешно установлен.")"
        else
            echo " $(_red "✗ Не удалось установить $tool. Попробуйте установить вручную.")"
            return 1
        fi
    fi
    
    return 0
}

# Проверка DNS-утечки
check_dns_leak() {
    echo
    echo " $(_cyan "=== Проверка DNS-утечки (аналог BrowserLeaks) ===")"
    
    # Проверяем наличие утилит
    install_required_tools "curl" "curl"
    install_required_tools "jq" "jq"
    install_required_tools "dig" "dnsutils"
    
    # Проверка через ipleak.net
    echo
    echo " $(_yellow "● IP и Провайдер:")"
    
    # Запрашиваем данные с ipleak.net
    local ip_data
    ip_data=$(curl --fail --silent --show-error --connect-timeout 5 --max-time 15 "https://ipleak.net/json/" 2>/dev/null || true)
    
    if [ -n "$ip_data" ]; then
        if _exists "jq"; then
            echo "$ip_data" | jq -r '"   IP: \(.ip)\n   Страна: \(.country_name)\n   Провайдер: \(.isp)"' 2>/dev/null
        else
            # Если jq не установлен или не работает, используем grep/sed
            echo "   IP: $(echo "$ip_data" | grep -o '"ip":"[^"]*' | sed 's/"ip":"//')"
            echo "   Страна: $(echo "$ip_data" | grep -o '"country_name":"[^"]*' | sed 's/"country_name":"//')"
            echo "   Провайдер: $(echo "$ip_data" | grep -o '"isp":"[^"]*' | sed 's/"isp":"//')"
        fi
    else
        echo " $(_red "   Не удалось получить данные с ipleak.net")"
    fi
    
    # Проверка DNS-серверов
    echo
    echo " $(_yellow "● DNS-серверы:")"
    
    if _exists "dig"; then
        local dns_ip
        dns_ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null)
        if [ -n "$dns_ip" ]; then
            echo "   DNS определяет ваш IP как: $dns_ip"
        else
            echo " $(_red "   Не удалось определить DNS IP")"
        fi
    fi
    
    echo "   Используемые DNS-серверы системой:"
    if [ -f "/etc/resolv.conf" ]; then
        grep nameserver /etc/resolv.conf | sed 's/nameserver/   /'
    else
        echo " $(_red "   Не удалось найти файл /etc/resolv.conf")"
    fi
    
    # Дополнительная проверка через systemd-resolved, если доступно
    if _exists "resolvectl"; then
        echo
        echo "   Настройки systemd-resolved:"
        resolvectl status | grep "DNS Server" | sed 's/^/   /' || true
    fi
}

# Тест DNS-серверов
run_dns_test() {
    echo
    echo " ⌛ Тестирование DNS-серверов..."
    
    # Массив DNS-серверов для проверки
    declare -A dns_servers
    dns_servers["Google"]="8.8.8.8"
    dns_servers["Cloudflare"]="1.1.1.1"
    dns_servers["AdGuard"]="94.140.14.14"
    dns_servers["Quad9"]="9.9.9.9"
    dns_servers["OpenDNS"]="208.67.222.222"
    dns_servers["NextDNS"]="45.90.28.0"
    dns_servers["UncensoredDNS"]="91.239.100.100"
    
    # Сайты для проверки DNS
    local test_domains=("google.com" "yandex.ru" "cloudflare.com")
    
    echo
    printf " %-18s %-20s %-10s\n" "DNS Сервер" "Провайдер" "Время (мс)"
    echo " -------------------------------------------------"
    
    # Установка и определение доступной утилиты для проверки DNS
    local dns_tool=""
    
    # Пытаемся установить dig если нет ни dig, ни nslookup
    if ! _exists "dig" && ! _exists "nslookup"; then
        install_required_tools "dig" "dnsutils"
    fi
    
    # Проверяем доступные инструменты
    if _exists "dig"; then
        dns_tool="dig"
    elif _exists "nslookup"; then
        dns_tool="nslookup"
    else
        echo " $(_red "Ошибка: Не найдены утилиты dig или nslookup и не удалось их установить.")"
        return 1
    fi
    
    for provider in "${!dns_servers[@]}"; do
        local server=${dns_servers[$provider]}
        local total_time=0
        local count=0
        local start_time result end_time query_time
        
        for domain in "${test_domains[@]}"; do
            if [ "$dns_tool" = "dig" ]; then
                # Используем dig с увеличенным таймаутом
                start_time=$(date +%s%N)
                result=$(dig "@$server" "$domain" +short +time=2 +retry=1 2>/dev/null)
                end_time=$(date +%s%N)
                
                if [ -n "$result" ]; then
                    # Расчет времени в миллисекундах (ms)
                    query_time=$(( (end_time - start_time) / 1000000 ))
                    total_time=$((total_time + query_time))
                    count=$((count + 1))
                fi
            else
                # Используем nslookup с таймером
                start_time=$(date +%s%N)
                result=$(nslookup -timeout=2 "$domain" "$server" 2>/dev/null)
                end_time=$(date +%s%N)
                
                # Проверяем, что запрос был успешным
                if echo "$result" | grep -q "Address:" && ! echo "$result" | grep -q "server can't find"; then
                    # Расчет времени в миллисекундах (ms)
                    query_time=$(( (end_time - start_time) / 1000000 ))
                    total_time=$((total_time + query_time))
                    count=$((count + 1))
                fi
            fi
        done
        
        if [[ $count -gt 0 ]]; then
            local avg_time=$((total_time / count))
            
            # Цветовое отображение в зависимости от скорости
            if [[ $avg_time -lt 30 ]]; then
                printf " %-18s %-20s $(_green "%-10s")\n" "$server" "$provider" "${avg_time} мс"
            elif [[ $avg_time -lt 60 ]]; then
                printf " %-18s %-20s $(_yellow "%-10s")\n" "$server" "$provider" "${avg_time} мс"
            else
                printf " %-18s %-20s $(_red "%-10s")\n" "$server" "$provider" "${avg_time} мс"
            fi
        else
            printf " %-18s %-20s $(_red "%-10s")\n" "$server" "$provider" "ошибка"
        fi
    done
    echo
}

run_traceroute() {
    echo
    echo " ⌛ Проверка маршрута к популярным DNS-серверам..."
    
    # Установка утилиты трассировки если отсутствует
    if ! _exists "traceroute" && ! _exists "tracepath"; then
        if ! install_required_tools "traceroute" "traceroute"; then
            install_required_tools "tracepath" "iputils-tracepath"
        fi
    fi
    
    # Проверяем наличие команды traceroute или tracepath
    if _exists "traceroute"; then
        local cmd="traceroute"
    elif _exists "tracepath"; then
        local cmd="tracepath"
    else
        echo " $(_red "Ошибка: Не удалось установить traceroute/tracepath!")"
        return 1
    fi
    
    # Ассоциативный массив DNS-серверов (в bash 4.0+)
    declare -A dns_servers=(
        ["Google"]="8.8.8.8"
        ["Cloudflare"]="1.1.1.1"
        ["AdGuard"]="94.140.14.14"
        ["Quad9"]="9.9.9.9"
        ["OpenDNS"]="208.67.222.222"
        ["NextDNS"]="45.90.28.0"
        ["UncensoredDNS"]="91.239.100.100"
    )
    
    # Для совместимости с bash < 4.0 можно использовать два массива:
    # dns_names=("Google" "Cloudflare" ...)
    # dns_ips=("8.8.8.8" "1.1.1.1" ...)
    
    for dns_name in "${!dns_servers[@]}"; do
        local target=${dns_servers[$dns_name]}
        echo
        echo " $(_yellow "★") Маршрут к $dns_name DNS (${target}):"
        
        # Ограничиваем трассировку 10 хопами для ускорения
        if [[ "$cmd" == "traceroute" ]]; then
            "$cmd" -m 10 -w 2 "$target" 2>&1 | grep -Fv '* * *' | head -n 15
        else
            "$cmd" -m 10 "$target" 2>&1 | grep -Fv '(mtu' | grep -Fv 'no reply' | head -n 15
        fi
    done
    echo
}

# Генерация отчета
generate_report() {
    echo
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                   ОТЧЁТ О ПРОВЕРКЕ DNS И СЕТИ                    ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo
    echo "$(_yellow "▶") Дата проверки: $(date '+%d.%m.%Y %H:%M:%S')"
    echo
    echo "$(_yellow "▶") Информация о системе:"
    echo "   Хост: $(hostname)"
    if _exists "lsb_release"; then
        echo "   ОС: $(lsb_release -ds 2>/dev/null)"
    elif [ -f "/etc/os-release" ]; then
        echo "   ОС: $(grep -oP '(?<=^PRETTY_NAME=).+' /etc/os-release | tr -d '"')"
    fi
    echo
    echo "$(_yellow "▶") Текущие настройки DNS:"
    if [ -f "/etc/resolv.conf" ]; then
        grep nameserver /etc/resolv.conf | sed 's/nameserver/   Nameserver:/'
    fi
    
    # Проверка расширенных настроек resolved.conf, если доступны
    if [ -f "/etc/systemd/resolved.conf" ] && command -v resolvectl &>/dev/null; then
        echo
        echo "$(_yellow "▶") Расширенные настройки DNS (systemd-resolved):"
        echo "   Серверы DNS:"
        resolvectl dns 2>/dev/null | grep -v "Link " | sed 's/^/   /'
        
        # Проверка статуса DNSSEC
        local dnssec_status
        dnssec_status=$(resolvectl status 2>/dev/null | grep "DNSSEC setting" | sed 's/^[[:space:]]*//' || true)
        if [ -n "$dnssec_status" ]; then
            echo "   $dnssec_status"
        fi
        
        # Проверка статуса кеширования
        if grep -q "^Cache=yes" /etc/systemd/resolved.conf 2>/dev/null; then
            echo "   Кеширование DNS: Включено"
        elif grep -q "^Cache=no" /etc/systemd/resolved.conf 2>/dev/null; then
            echo "   Кеширование DNS: Отключено"
        fi
    fi
    
    # Запуск проверки DNS утечек
    check_dns_leak
    
    echo
    echo "$(_yellow "▶") Результаты тестирования DNS:"
    echo "   $(_green "< 30 мс") - отличное время отклика"
    echo "   $(_yellow "30-60 мс") - хорошее время отклика"
    echo "   $(_red "> 60 мс") - медленное время отклика"
    
    # Запуск теста DNS
    run_dns_test
    
    # Запуск трассировки
    run_traceroute
    
    echo
    echo "$(_yellow "▶") РЕКОМЕНДАЦИИ:"
    echo "   1. DNS-серверы с временем отклика менее 30 мс обеспечат наилучшую производительность при веб-серфинге."
    echo "   2. При выборе DNS-сервера учитывайте не только скорость, но и приватность, фильтрацию контента."
    echo "   3. Для улучшения производительности можно настроить использование нескольких DNS-серверов."
    echo "   4. Трассировка показывает количество переходов до целевых серверов - меньшее количество обычно означает более быстрое соединение."
    echo "   5. Если ваш реальный IP отличается от IP, определяемого через DNS, возможна DNS-утечка."
    echo
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                          КОНЕЦ ОТЧЁТА                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
}

# Главная функция
main() {
    # Проверка наличия root-прав
    if [ "$(id -u)" -ne 0 ]; then
        echo " $(_red "Скрипт должен быть запущен с привилегиями root или sudo!")"
        exit 1
    fi
    
    # Запуск отчета
    generate_report
}

# Запуск скрипта
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
