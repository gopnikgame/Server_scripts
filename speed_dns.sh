#!/usr/bin/env bash

# Version: 2.0.0
# Description: DNS configuration, performance and DNSSEC diagnostics for Ubuntu

set -Eeuo pipefail

SCRIPT_VERSION='2.0.0'
DNS_TIMEOUT="${DNS_TIMEOUT:-2}"
DNS_TRIES="${DNS_TRIES:-1}"
TRACE_MAX_HOPS="${TRACE_MAX_HOPS:-10}"
readonly SCRIPT_VERSION DNS_TIMEOUT DNS_TRIES TRACE_MAX_HOPS

DNS_NAMES=(Google Cloudflare AdGuard Quad9 OpenDNS NextDNS UncensoredDNS)
DNS_ADDRESSES=(8.8.8.8 1.1.1.1 94.140.14.14 9.9.9.9 208.67.222.222 45.90.28.0 91.239.100.100)
TEST_DOMAINS=(cloudflare.com google.com example.com)
readonly DNS_NAMES DNS_ADDRESSES TEST_DOMAINS

if [[ -t 1 ]]; then
    RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[1;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi
readonly RED GREEN YELLOW CYAN NC

_exists() { command -v "$1" >/dev/null 2>&1; }
_red() { printf '%b%s%b\n' "$RED" "$1" "$NC"; }
_green() { printf '%b%s%b\n' "$GREEN" "$1" "$NC"; }
_yellow() { printf '%b%s%b\n' "$YELLOW" "$1" "$NC"; }
_cyan() { printf '%b%s%b\n' "$CYAN" "$1" "$NC"; }

section() {
    printf '\n%b=== %s ===%b\n\n' "$CYAN" "$1" "$NC"
}

confirm() {
    local answer
    read -r -p "$1 [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

install_ubuntu_packages() {
    local packages=("$@")
    (( EUID == 0 )) || {
        _red 'Для установки недостающих пакетов запустите модуль от root.'
        return 1
    }
    confirm "Установить недостающие пакеты: ${packages[*]}?" || return 1
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
}

ensure_dig() {
    _exists dig && return 0
    _exists apt-get || { _red 'Не найден dig; поддерживается автоматическая установка только на Ubuntu/Debian.'; return 1; }
    install_ubuntu_packages dnsutils && _exists dig
}

ensure_trace_tool() {
    if _exists tracepath || _exists traceroute; then return 0; fi
    _exists apt-get || { _red 'Не найден tracepath/traceroute.'; return 1; }
    install_ubuntu_packages iputils-tracepath && _exists tracepath
}

validate_settings() {
    [[ "$DNS_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { _red 'DNS_TIMEOUT должен быть положительным целым числом.'; return 1; }
    [[ "$DNS_TRIES" =~ ^[1-9][0-9]*$ ]] || { _red 'DNS_TRIES должен быть положительным целым числом.'; return 1; }
    [[ "$TRACE_MAX_HOPS" =~ ^[1-9][0-9]*$ ]] || { _red 'TRACE_MAX_HOPS должен быть положительным целым числом.'; return 1; }
}

dig_query() {
    local server="$1" domain="$2" transport="${3:-udp}"
    local -a args=("$domain" A "+time=$DNS_TIMEOUT" "+tries=$DNS_TRIES" +noall +comments +answer +stats)
    [[ -n "$server" ]] && args=("@$server" "${args[@]}")
    [[ "$transport" == tcp ]] && args+=(+tcp)
    dig "${args[@]}" 2>/dev/null
}

parse_query_time() {
    awk '/^;; Query time:/ { print $4; exit }'
}

query_succeeded() {
    awk '
        /status: NOERROR/ { valid_status=1 }
        /ANSWER: [1-9][0-9]*/ { has_answer=1 }
        END { exit !(valid_status && has_answer) }
    '
}

query_status() {
    sed -n 's/^;; ->>HEADER<<- .*status: \([^,]*\),.*/\1/p' | head -n 1
}

resolver_exit_ip() {
    ensure_dig >/dev/null || return 1
    dig whoami.akamai.net A +short "+time=$DNS_TIMEOUT" "+tries=$DNS_TRIES" 2>/dev/null | awk 'NF {print; exit}'
}

public_exit_ip() {
    _exists curl || return 1
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null
}

show_system_dns() {
    section 'Текущая конфигурация DNS'
    printf 'Хост: %s\n' "$(hostname)"
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf 'ОС: %s\n' "${PRETTY_NAME:-не определена}"
    fi
    printf 'resolv.conf: %s\n' "$(readlink -f /etc/resolv.conf 2>/dev/null || printf '/etc/resolv.conf')"
    awk '$1 == "nameserver" { printf "  nameserver: %s\n", $2 }' /etc/resolv.conf 2>/dev/null || true

    if _exists resolvectl; then
        echo
        echo 'Фактические DNS-серверы systemd-resolved:'
        resolvectl dns 2>/dev/null | sed 's/^/  /' || true
        resolvectl domain 2>/dev/null | sed 's/^/  /' || true
        echo
        resolvectl status --no-pager 2>/dev/null | \
            awk '/DNSOverTLS setting:|DNSSEC setting:|Current DNS Server:|DNS Servers:/ {sub(/^[[:space:]]+/, ""); print "  " $0}' || true
    fi

    if ensure_dig; then
        local output status latency
        output=$(dig_query '' cloudflare.com udp || true)
        status=$(printf '%s\n' "$output" | query_status)
        latency=$(printf '%s\n' "$output" | parse_query_time)
        printf '\nСистемное разрешение cloudflare.com: %s, %s мс\n' "${status:-ошибка}" "${latency:--}"
    fi
}

show_egress_context() {
    section 'Контекст выхода DNS'
    local public_ip='' resolver_ip=''
    public_ip=$(public_exit_ip || true)
    resolver_ip=$(resolver_exit_ip || true)
    printf 'Публичный IP сервера: %s\n' "${public_ip:-не определён}"
    printf 'IP рекурсивного резолвера по whoami.akamai.net: %s\n' "${resolver_ip:-не определён}"
    echo
    echo 'Это серверная диагностика, а не браузерный DNS leak test.'
    echo 'Разные IP обычно означают использование внешнего рекурсивного резолвера;'
    echo 'совпадение IP само по себе не доказывает утечку.'
}

benchmark_resolvers() {
    ensure_dig || return 1
    section 'Сравнение публичных DNS-резолверов'
    printf '%-17s %-15s %9s %9s %9s %8s\n' 'Провайдер' 'Адрес' 'Среднее' 'Мин.' 'Макс.' 'Успех'
    printf '%-17s %-15s %9s %9s %9s %8s\n' '-----------------' '---------------' '---------' '---------' '---------' '--------'

    local index domain output time success total min max average
    local best_name='' best_address='' best_average=999999
    for index in "${!DNS_NAMES[@]}"; do
        success=0; total=0; min=999999; max=0
        for domain in "${TEST_DOMAINS[@]}"; do
            output=$(dig_query "${DNS_ADDRESSES[$index]}" "$domain" udp || true)
            if printf '%s\n' "$output" | query_succeeded; then
                time=$(printf '%s\n' "$output" | parse_query_time)
                if [[ "$time" =~ ^[0-9]+$ ]]; then
                    (( success += 1, total += time ))
                    (( time < min )) && min=$time
                    (( time > max )) && max=$time
                fi
            fi
        done
        if (( success > 0 )); then
            average=$((total / success))
            printf '%-17s %-15s %7d ms %7d ms %7d ms %5d/%d\n' \
                "${DNS_NAMES[$index]}" "${DNS_ADDRESSES[$index]}" "$average" "$min" "$max" "$success" "${#TEST_DOMAINS[@]}"
            if (( success == ${#TEST_DOMAINS[@]} && average < best_average )); then
                best_name="${DNS_NAMES[$index]}"
                best_address="${DNS_ADDRESSES[$index]}"
                best_average=$average
            fi
        else
            printf '%-17s %-15s %9s %9s %9s %8s\n' \
                "${DNS_NAMES[$index]}" "${DNS_ADDRESSES[$index]}" 'ошибка' '-' '-' "0/${#TEST_DOMAINS[@]}"
        fi
    done
    echo
    if [[ -n "$best_name" ]]; then
        _green "Лучший полный результат: $best_name ($best_address), в среднем ${best_average} мс."
    fi
    echo 'Время берётся из поля Query time утилиты dig; запуск процесса в замер не входит.'
    echo 'Частичный успех явно показан и не считается полноценным результатом.'
}

tcp_reachability() {
    ensure_dig || return 1
    section 'Доступность DNS по TCP/53'
    local index output latency
    printf '%-17s %-15s %12s\n' 'Провайдер' 'Адрес' 'TCP'
    for index in "${!DNS_NAMES[@]}"; do
        output=$(dig_query "${DNS_ADDRESSES[$index]}" cloudflare.com tcp || true)
        if printf '%s\n' "$output" | query_succeeded; then
            latency=$(printf '%s\n' "$output" | parse_query_time)
            printf '%-17s %-15s %9s ms\n' "${DNS_NAMES[$index]}" "${DNS_ADDRESSES[$index]}" "${latency:--}"
        else
            printf '%-17s %-15s %12s\n' "${DNS_NAMES[$index]}" "${DNS_ADDRESSES[$index]}" 'недоступен'
        fi
    done
}

dnssec_status_for() {
    local server="$1" output status positive_output positive_status
    local -a common=(A +dnssec "+time=$DNS_TIMEOUT" "+tries=$DNS_TRIES" +noall +comments +stats)
    local -a positive_args=(cloudflare.com "${common[@]}") invalid_args=(dnssec-failed.org "${common[@]}")
    if [[ -n "$server" ]]; then
        positive_args=("@$server" "${positive_args[@]}")
        invalid_args=("@$server" "${invalid_args[@]}")
    fi
    positive_output=$(dig "${positive_args[@]}" 2>/dev/null || true)
    positive_status=$(printf '%s\n' "$positive_output" | query_status)
    [[ "$positive_status" == NOERROR ]] || { printf 'нет корректного контрольного ответа'; return 0; }
    output=$(dig "${invalid_args[@]}" 2>/dev/null || true)
    status=$(printf '%s\n' "$output" | query_status)
    case "$status" in
        SERVFAIL) printf 'проверяет DNSSEC' ;;
        NOERROR) printf 'не проверяет DNSSEC' ;;
        '') printf 'нет ответа' ;;
        *) printf 'неопределённо (%s)' "$status" ;;
    esac
}

check_dnssec() {
    ensure_dig || return 1
    section 'Проверка валидации DNSSEC'
    printf '%-17s %-15s %s\n' 'Резолвер' 'Адрес' 'Результат'
    printf '%-17s %-15s %s\n' 'Системный' '-' "$(dnssec_status_for '')"
    local index
    for index in "${!DNS_NAMES[@]}"; do
        printf '%-17s %-15s %s\n' "${DNS_NAMES[$index]}" "${DNS_ADDRESSES[$index]}" \
            "$(dnssec_status_for "${DNS_ADDRESSES[$index]}")"
    done
    echo
    echo 'Проверка использует домен с намеренно повреждённой DNSSEC-подписью:'
    echo 'валидирующий резолвер должен вернуть SERVFAIL.'
}

trace_resolvers() {
    ensure_trace_tool || return 1
    section 'Маршруты к DNS-серверам'
    local index target
    for index in "${!DNS_NAMES[@]}"; do
        target="${DNS_ADDRESSES[$index]}"
        printf '\n%s (%s):\n' "${DNS_NAMES[$index]}" "$target"
        if _exists tracepath; then
            timeout 25 tracepath -n -m "$TRACE_MAX_HOPS" "$target" 2>&1 || _yellow '  Маршрут не завершён в пределах лимита.'
        else
            timeout 25 traceroute -n -m "$TRACE_MAX_HOPS" -w 2 "$target" 2>&1 || _yellow '  Маршрут не завершён в пределах лимита.'
        fi
    done
}

full_report() {
    printf '\nDNS И СЕТЕВОЙ ОТЧЁТ v%s — %s\n' "$SCRIPT_VERSION" "$(date '+%d.%m.%Y %H:%M:%S')"
    show_system_dns
    show_egress_context
    benchmark_resolvers
    tcp_reachability
    check_dnssec
}

usage() {
    cat <<'USAGE'
Использование: speed_dns.sh [--all|--system|--benchmark|--tcp|--dnssec|--trace]
Без аргументов открывается интерактивное меню.
USAGE
}

interactive_menu() {
    while true; do
        section "DNS DIAGNOSTICS v$SCRIPT_VERSION"
        echo '1. Полный отчёт (без трассировки)'
        echo '2. Текущая конфигурация и контекст выхода DNS'
        echo '3. Сравнить скорость публичных DNS'
        echo '4. Проверить TCP/53'
        echo '5. Проверить DNSSEC'
        echo '6. Выполнить трассировку'
        echo '0. Вернуться в главное меню'
        local choice
        read -r -p 'Выберите действие: ' choice
        case "$choice" in
            1) full_report ;;
            2) show_system_dns; show_egress_context ;;
            3) benchmark_resolvers ;;
            4) tcp_reachability ;;
            5) check_dnssec ;;
            6) trace_resolvers ;;
            0) return 0 ;;
            *) _red 'Неверный выбор.' ;;
        esac
        echo
        read -r -p 'Нажмите Enter для продолжения...'
    done
}

main() {
    validate_settings
    case "${1:-}" in
        '') interactive_menu ;;
        --all) full_report ;;
        --system) show_system_dns; show_egress_context ;;
        --benchmark) benchmark_resolvers ;;
        --tcp) tcp_reachability ;;
        --dnssec) check_dnssec ;;
        --trace) trace_resolvers ;;
        -h|--help) usage ;;
        *) usage >&2; return 2 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
