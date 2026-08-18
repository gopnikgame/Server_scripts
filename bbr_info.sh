#!/bin/bash

# Version: 2.0.0
# Description: Read-only XanMod/BBR/VLESS TCP status monitor

set -u

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
readonly PROFILE_FILE="/etc/sysctl.d/99-xanmod-vless-tcp.conf"

value_or_unknown() {
    sysctl -n "$1" 2>/dev/null || printf 'unknown\n'
}

show_status() {
    clear
    printf '%b=== XanMod / BBR / VLESS TCP ===%b\n\n' "$BLUE" "$NC"
    printf 'Ядро:                    %s\n' "$(uname -r)"
    printf 'Доступные алгоритмы:     %s\n' "$(value_or_unknown net.ipv4.tcp_available_congestion_control)"
    printf 'Активный алгоритм:       %s\n' "$(value_or_unknown net.ipv4.tcp_congestion_control)"
    printf 'Qdisc по умолчанию:      %s\n' "$(value_or_unknown net.core.default_qdisc)"
    printf 'MTU probing:             %s\n' "$(value_or_unknown net.ipv4.tcp_mtu_probing)"
    printf 'SOMAXCONN:               %s\n' "$(value_or_unknown net.core.somaxconn)"
    printf 'SYN backlog:             %s\n' "$(value_or_unknown net.ipv4.tcp_max_syn_backlog)"
    printf 'Xray service:            %s\n' "$(systemctl is-active xray 2>/dev/null || echo не-найден)"
    printf 'Профиль VLESS TCP:       %s\n' "$([[ -f "$PROFILE_FILE" ]] && echo установлен || echo не-установлен)"
    printf '\n%bСокеты:%b\n' "$YELLOW" "$NC"
    ss -s 2>/dev/null || printf 'Команда ss недоступна\n'
    printf '\n%bОчереди интерфейсов:%b\n' "$YELLOW" "$NC"
    tc -s qdisc show 2>/dev/null || printf 'Команда tc недоступна\n'
    printf '\n'
    if [[ "$(uname -r)" == *xanmod* ]] &&
       [[ "$(value_or_unknown net.ipv4.tcp_congestion_control)" == bbr ]] &&
       [[ "$(value_or_unknown net.core.default_qdisc)" == fq ]]; then
        printf '%bXanMod + BBR + fq активны.%b\n' "$GREEN" "$NC"
    else
        printf '%bКонфигурация не полностью соответствует VLESS TCP Stable.%b\n' "$YELLOW" "$NC"
    fi
}

main_menu() {
    while true; do
        show_status
        printf '\n1) Обновить сведения\n'
        printf '2) Открыть установщик и настройку профиля\n'
        printf '0) Выход\n\n'
        read -rp 'Выберите действие: ' choice
        case "$choice" in
            1) ;;
            2)
                local installer
                installer="$(dirname "${BASH_SOURCE[0]}")/install_xanmod.sh"
                if [[ -x "$installer" ]]; then
                    "$installer"
                elif [[ -f "$installer" ]]; then
                    bash "$installer"
                else
                    printf 'install_xanmod.sh не найден рядом с монитором.\n'
                    read -rp 'Нажмите Enter...' _
                fi
                ;;
            0) break ;;
            *) sleep 1 ;;
        esac
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main_menu "$@"
fi
