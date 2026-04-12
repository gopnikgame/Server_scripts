#!/bin/bash

# Version: 1.2.0
# Author: gopnikgame
# Created: 2025-07-22 14:00:00
# Last Modified: 2025-07-22 16:00:00
# Description: Server proxy configuration module
#              Modes: direct HTTP proxy, SSH tunnel + Privoxy, VPN system proxy, Xray VLESS
#              Includes: connectivity diagnostics and mode recommendation wizard
# Repository: https://github.com/gopnikgame/Server_scripts

set -euo pipefail

# Цветовые коды
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Константы
PROXY_ENV_FILE="/etc/environment"
PROXY_APT_CONF="/etc/apt/apt.conf.d/99proxy"
PROXY_PROFILE="/etc/profile.d/proxy.sh"
PRIVOXY_CONF="/etc/privoxy/config"
SSH_TUNNEL_SERVICE="/etc/systemd/system/ssh-tunnel-proxy.service"
PROXY_STATE_FILE="/etc/server-scripts/proxy.conf"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
LOG_FILE="/var/log/server-scripts/setup_proxy.log"

# ─── Утилиты вывода ────────────────────────────────────────────────────────────

log() {
    echo -e "\033[1;34m[$(date '+%Y-%m-%d %H:%M:%S')]\033[0m - $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ОШИБКА] - $1${NC}" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[УСПЕХ] - $1${NC}" | tee -a "$LOG_FILE"
}

print_header() {
    local title="$1"
    local width=50
    local padding=$(( (width - ${#title}) / 2 ))
    echo
    echo -e "${BLUE}┌$( printf '─%.0s' $(seq 1 $width) )┐${NC}"
    echo -e "${BLUE}│$( printf ' %.0s' $(seq 1 $padding) )${CYAN}${title}$( printf ' %.0s' $(seq 1 $(( width - padding - ${#title} )) ) )${BLUE}│${NC}"
    echo -e "${BLUE}└$( printf '─%.0s' $(seq 1 $width) )┘${NC}"
    echo
}

# ─── Вспомогательные функции ───────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Скрипт должен быть запущен с правами root"
        exit 1
    fi
}

# Запись прокси в /etc/environment, /etc/profile.d/proxy.sh, /etc/apt/apt.conf.d/99proxy
apply_proxy() {
    local proxy_url="$1"
    local no_proxy="localhost,127.0.0.1,::1"

    # /etc/environment — сохраняется между перезагрузками
    sed -i '/^http_proxy\|^https_proxy\|^HTTP_PROXY\|^HTTPS_PROXY\|^no_proxy\|^NO_PROXY/d' \
        "$PROXY_ENV_FILE" 2>/dev/null || true
    printf '\nhttp_proxy="%s"\nhttps_proxy="%s"\nHTTP_PROXY="%s"\nHTTPS_PROXY="%s"\nno_proxy="%s"\nNO_PROXY="%s"\n' \
        "$proxy_url" "$proxy_url" "$proxy_url" "$proxy_url" "$no_proxy" "$no_proxy" \
        >> "$PROXY_ENV_FILE"

    # /etc/profile.d/proxy.sh — экспорт в shell сессии
    cat > "$PROXY_PROFILE" <<EOF
export http_proxy="$proxy_url"
export https_proxy="$proxy_url"
export HTTP_PROXY="$proxy_url"
export HTTPS_PROXY="$proxy_url"
export no_proxy="$no_proxy"
export NO_PROXY="$no_proxy"
EOF
    chmod +x "$PROXY_PROFILE"

    # APT — для apt-get / apt
    mkdir -p /etc/apt/apt.conf.d
    cat > "$PROXY_APT_CONF" <<EOF
Acquire::http::Proxy "$proxy_url";
Acquire::https::Proxy "$proxy_url";
EOF

    log_success "Системный прокси применён: $proxy_url"
}

# Удаление всех системных настроек прокси
remove_proxy() {
    sed -i '/^http_proxy\|^https_proxy\|^HTTP_PROXY\|^HTTPS_PROXY\|^no_proxy\|^NO_PROXY/d' \
        "$PROXY_ENV_FILE" 2>/dev/null || true
    rm -f "$PROXY_PROFILE"
    rm -f "$PROXY_APT_CONF"
    log_success "Системные настройки прокси удалены"
}

# Проверка доступности прокси
test_proxy() {
    local proxy_url="$1"
    log "Тестирование прокси: $proxy_url"
    # Пробуем xanmod (основная задача), затем google как запасной
    if curl -sfI --connect-timeout 10 --max-time 15 \
            --proxy "$proxy_url" "http://deb.xanmod.org" &>/dev/null; then
        log_success "Прокси работает (deb.xanmod.org доступен)"
        return 0
    fi
    if curl -sfI --connect-timeout 10 --max-time 15 \
            --proxy "$proxy_url" "http://google.com" &>/dev/null; then
        log_success "Прокси работает (google.com доступен)"
        return 0
    fi
    log_error "Прокси не отвечает"
    return 1
}

# Сохранение состояния для отображения статуса
save_proxy_state() {
    mkdir -p "$(dirname "$PROXY_STATE_FILE")"
    cat > "$PROXY_STATE_FILE" <<EOF
PROXY_MODE="$1"
PROXY_URL="$2"
PROXY_DETAILS="${3:-}"
PROXY_CONFIGURED="$(date '+%Y-%m-%d %H:%M:%S')"
EOF
}

# ─── URL утилиты и парсинг VLESS ──────────────────────────────────────────────

url_decode() {
    python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()), end='')" 2>/dev/null || cat
}

get_qparam() {
    local key="$1" query="$2"
    printf '%s' "$query" | tr '&' '\n' | { grep -m1 "^${key}=" || true; } | cut -d= -f2- | url_decode
}

# Парсинг VLESS ссылки → глобальные переменные VLESS_*
parse_vless_link() {
    local link="$1"
    local body="${link#vless://}"

    # remark после #
    local remark_raw=""
    if [[ "$body" == *"#"* ]]; then
        remark_raw="${body##*#}"
        body="${body%#*}"
    fi

    # query string после ?
    local query=""
    if [[ "$body" == *"?"* ]]; then
        query="${body##*?}"
        body="${body%%\?*}"
    fi

    VLESS_UUID="${body%%@*}"
    local hostport="${body#*@}"

    # IPv6 [::1]:port
    if [[ "$hostport" =~ ^\[([^\]]+)\]:([0-9]+)$ ]]; then
        VLESS_HOST="${BASH_REMATCH[1]}"
        VLESS_PORT="${BASH_REMATCH[2]}"
    else
        VLESS_HOST="${hostport%:*}"
        VLESS_PORT="${hostport##*:}"
    fi

    VLESS_SECURITY="$(get_qparam security "$query")"
    VLESS_NETWORK="$(get_qparam type     "$query")"
    VLESS_FLOW="$(get_qparam flow        "$query")"
    VLESS_SNI="$(get_qparam sni          "$query")"
    VLESS_FP="$(get_qparam fp            "$query")"
    VLESS_PBK="$(get_qparam pbk          "$query")"
    VLESS_SID="$(get_qparam sid          "$query")"
    VLESS_SPX="$(get_qparam spx          "$query")"
    VLESS_HOST_HEADER="$(get_qparam host "$query")"
    VLESS_PATH="$(get_qparam path        "$query")"
    VLESS_REMARK="$(printf '%s' "$remark_raw" | url_decode)"

    VLESS_SECURITY="${VLESS_SECURITY:-none}"
    VLESS_NETWORK="${VLESS_NETWORK:-tcp}"
    VLESS_FP="${VLESS_FP:-chrome}"
    VLESS_PATH="${VLESS_PATH:-/}"
    VLESS_SPX="${VLESS_SPX:-/}"
    VLESS_REMARK="${VLESS_REMARK:-xray-proxy}"
}

# ─── Установка Xray-core ───────────────────────────────────────────────────────

install_xray() {
    if command -v xray &>/dev/null; then
        local ver
        ver=$(xray version 2>/dev/null | head -1 || echo "неизвестна")
        log_success "Xray уже установлен: $ver"
        return 0
    fi

    log "Установка Xray-core..."
    apt-get install -y curl unzip -qq 2>/dev/null || true

    # Официальный инсталлятор
    if curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh \
            -o /tmp/xray-install.sh 2>/dev/null && bash /tmp/xray-install.sh install 2>>"$LOG_FILE"; then
        rm -f /tmp/xray-install.sh
        log_success "Xray установлен через официальный инсталлятор"
        return 0
    fi
    rm -f /tmp/xray-install.sh

    # Резервный вариант: прямая загрузка через GitHub API
    log "Попытка прямой загрузки с GitHub Releases..."
    local api_url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local download_url
    download_url=$(curl -sfL "$api_url" 2>/dev/null | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(next((a['browser_download_url'] for a in d['assets'] if 'linux-64.zip' in a['name'] and 'dgst' not in a['name']), ''))" \
        2>/dev/null || true)

    if [[ -n "$download_url" ]]; then
        local tmp
        tmp=$(mktemp -d)
        if curl -fSL --progress-bar "$download_url" -o "$tmp/xray.zip" 2>>"$LOG_FILE"; then
            unzip -q "$tmp/xray.zip" -d "$tmp"
            install -m 755 "$tmp/xray" /usr/local/bin/xray
            mkdir -p "$XRAY_CONFIG_DIR" /var/log/xray
            rm -rf "$tmp"

            cat > /etc/systemd/system/xray.service <<'XSVC'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
XSVC
            systemctl daemon-reload
            log_success "Xray установлен из GitHub Releases"
            return 0
        fi
        rm -rf "$tmp"
    fi

    log_error "Не удалось установить Xray автоматически"
    echo
    echo -e "${YELLOW}Установите Xray вручную:${NC}"
    echo -e "  ${CYAN}https://github.com/XTLS/Xray-core/releases${NC}"
    echo -e "Распакуйте binary в ${CYAN}/usr/local/bin/xray${NC}, затем повторите."
    return 1
}

# Генерация config.json из переменных VLESS_* через Python (корректный JSON, без heredoc-инъекций)
generate_xray_config() {
    mkdir -p "$XRAY_CONFIG_DIR" /var/log/xray
    log "Генерация конфигурации Xray..."

    local gen_result=0
    VLESS_UUID="$VLESS_UUID" \
    VLESS_HOST="$VLESS_HOST" \
    VLESS_PORT="$VLESS_PORT" \
    VLESS_SECURITY="$VLESS_SECURITY" \
    VLESS_NETWORK="$VLESS_NETWORK" \
    VLESS_FLOW="$VLESS_FLOW" \
    VLESS_SNI="$VLESS_SNI" \
    VLESS_FP="$VLESS_FP" \
    VLESS_PBK="$VLESS_PBK" \
    VLESS_SID="$VLESS_SID" \
    VLESS_SPX="$VLESS_SPX" \
    VLESS_HOST_HEADER="$VLESS_HOST_HEADER" \
    VLESS_PATH="$VLESS_PATH" \
    XRAY_CFG="${XRAY_CONFIG_DIR}/config.json" \
    python3 <<'PYEOF' || gen_result=$?
import json, os

uuid     = os.environ["VLESS_UUID"]
host     = os.environ["VLESS_HOST"]
port     = int(os.environ["VLESS_PORT"])
security = os.environ.get("VLESS_SECURITY", "none")
network  = os.environ.get("VLESS_NETWORK",  "tcp")
flow     = os.environ.get("VLESS_FLOW",     "")
sni      = os.environ.get("VLESS_SNI",      "")
fp       = os.environ.get("VLESS_FP",       "chrome") or "chrome"
pbk      = os.environ.get("VLESS_PBK",      "")
sid      = os.environ.get("VLESS_SID",      "")
spx      = os.environ.get("VLESS_SPX",      "/") or "/"
ws_host  = os.environ.get("VLESS_HOST_HEADER", "") or sni
ws_path  = os.environ.get("VLESS_PATH",     "/") or "/"
cfg_file = os.environ["XRAY_CFG"]

user = {"id": uuid, "encryption": "none"}
if flow:
    user["flow"] = flow

stream = {"network": network}
if security == "reality":
    stream["security"] = "reality"
    stream["realitySettings"] = {
        "serverName": sni, "fingerprint": fp,
        "publicKey": pbk, "shortId": sid, "spiderX": spx
    }
elif security == "tls":
    stream["security"] = "tls"
    stream["tlsSettings"] = {"serverName": sni, "allowInsecure": False}
else:
    stream["security"] = "none"

if network == "ws":
    stream["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
elif network == "grpc":
    stream["grpcSettings"] = {"serviceName": ws_path}

config = {
    "log": {
        "loglevel": "warning",
        "error": "/var/log/xray/error.log",
        "access": "/var/log/xray/access.log"
    },
    "inbounds": [
        {"tag": "socks", "port": 10808, "listen": "127.0.0.1",
         "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
        {"tag": "http",  "port": 10809, "listen": "127.0.0.1",
         "protocol": "http"}
    ],
    "outbounds": [
        {"tag": "proxy", "protocol": "vless",
         "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
         "streamSettings": stream},
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block",  "protocol": "blackhole", "settings": {}}
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]
    }
}

with open(cfg_file, "w") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
PYEOF

    if [ $gen_result -ne 0 ]; then
        log_error "Ошибка генерации конфигурации"
        return 1
    fi
    log_success "Конфигурация записана: ${XRAY_CONFIG_DIR}/config.json"
}

# ─── Режим 4: Xray VLESS ───────────────────────────────────────────────────────

configure_xray_vless() {
    print_header "XRAY VLESS ПРОКСИ"
    echo -e "${YELLOW}Схема:${NC} VLESS ссылка → Xray (локально) → HTTP прокси 127.0.0.1:10809"
    echo -e "${YELLOW}Поддерживаются:${NC} REALITY+TCP, TLS+TCP, TLS+WS, TLS+gRPC, none+WS"
    echo
    echo -e "${YELLOW}Пример (REALITY):${NC}"
    echo -e "  ${CYAN}vless://uuid@host:443?security=reality&sni=example.com&pbk=...&sid=...&fp=chrome&flow=xtls-rprx-vision&type=tcp#имя${NC}"
    echo

    read -rp "Вставьте VLESS ссылку: " vless_link

    if [[ -z "$vless_link" ]]; then
        log_error "Ссылка не может быть пустой"
        return 1
    fi
    if ! [[ "$vless_link" =~ ^vless:// ]]; then
        log_error "Неверный формат. Ссылка должна начинаться с vless://"
        return 1
    fi

    parse_vless_link "$vless_link"

    if [[ -z "$VLESS_UUID" || -z "$VLESS_HOST" || -z "$VLESS_PORT" ]]; then
        log_error "Не удалось распознать UUID, хост или порт из ссылки"
        return 1
    fi

    echo
    echo -e "${CYAN}─── Распознанные параметры ──────────────────────${NC}"
    echo -e "  Сервер:       ${GREEN}${VLESS_HOST}:${VLESS_PORT}${NC}"
    echo -e "  UUID:         ${GREEN}${VLESS_UUID}${NC}"
    echo -e "  Безопасность: ${GREEN}${VLESS_SECURITY^^}${NC}"
    echo -e "  Транспорт:    ${GREEN}${VLESS_NETWORK^^}${NC}"
    [[ -n "$VLESS_FLOW" ]]   && echo -e "  Flow:         ${GREEN}${VLESS_FLOW}${NC}"
    [[ -n "$VLESS_SNI" ]]    && echo -e "  SNI:          ${GREEN}${VLESS_SNI}${NC}"
    [[ -n "$VLESS_PBK" ]]    && echo -e "  PublicKey:    ${GREEN}${VLESS_PBK:0:24}...${NC}"
    [[ -n "$VLESS_REMARK" ]] && echo -e "  Название:     ${GREEN}${VLESS_REMARK}${NC}"
    echo
    echo -e "${YELLOW}Несколько серверов (балансировка): после настройки отредактируйте${NC}"
    echo -e "  ${CYAN}${XRAY_CONFIG_DIR}/config.json${NC}  — добавьте outbounds и balancer"
    echo

    read -rp "Параметры верны? Продолжить установку? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log "Установка отменена"
        return 0
    fi

    echo
    if ! install_xray; then
        return 1
    fi

    if ! generate_xray_config; then
        return 1
    fi

    systemctl enable xray 2>>"$LOG_FILE"
    systemctl restart xray
    sleep 3

    local proxy_url="http://127.0.0.1:10809"

    if systemctl is-active xray &>/dev/null; then
        log_success "Xray запущен"
        apply_proxy "$proxy_url"
        save_proxy_state "xray+vless" "$proxy_url" "${VLESS_REMARK} (${VLESS_HOST}:${VLESS_PORT})"
        echo
        echo -e "${GREEN}✔ Xray VLESS настроен и запущен${NC}"
        echo -e "  Системный HTTP прокси: ${CYAN}${proxy_url}${NC}"
        echo -e "  SOCKS5:                ${CYAN}socks5://127.0.0.1:10808${NC}"
        echo
        log "Тест подключения через VLESS..."
        if test_proxy "$proxy_url"; then
            echo -e "${GREEN}✔ Подключение через VLESS работает${NC}"
        else
            echo -e "${YELLOW}⚠ Тест не прошёл. Проверьте параметры или доступность сервера.${NC}"
            echo -e "  ${CYAN}journalctl -u xray -n 30${NC}"
            echo -e "  ${CYAN}cat /var/log/xray/error.log${NC}"
        fi
        echo
        echo -e "${YELLOW}Для применения в текущей SSH-сессии:${NC}"
        echo -e "${CYAN}  source /etc/profile.d/proxy.sh${NC}"
    else
        log_error "Xray не запустился"
        echo
        echo -e "${YELLOW}Диагностика:${NC}"
        echo -e "  ${CYAN}journalctl -u xray -n 30${NC}"
        echo -e "  ${CYAN}cat /var/log/xray/error.log${NC}"
        echo -e "  ${CYAN}xray -test -config ${XRAY_CONFIG_DIR}/config.json${NC}"
    fi
}

# ─── Статус ────────────────────────────────────────────────────────────────────

show_status() {
    print_header "ТЕКУЩИЙ СТАТУС ПРОКСИ"

    local proxy_url="" proxy_mode="не настроен" configured_at="" proxy_details=""

    if [ -f "$PROXY_STATE_FILE" ]; then
        # shellcheck source=/dev/null
        source "$PROXY_STATE_FILE"
        proxy_url="${PROXY_URL:-}"
        proxy_mode="${PROXY_MODE:-}"
        configured_at="${PROXY_CONFIGURED:-}"
        proxy_details="${PROXY_DETAILS:-}"
    elif [ -f "$PROXY_PROFILE" ]; then
        proxy_url=$(grep "^export http_proxy=" "$PROXY_PROFILE" 2>/dev/null | cut -d'"' -f2 || true)
        proxy_mode="http"
    fi

    if [ -n "$proxy_url" ]; then
        echo -e "Статус:        ${GREEN}Активен${NC}"
        echo -e "Режим:         ${CYAN}${proxy_mode}${NC}"
        echo -e "Адрес прокси:  ${CYAN}${proxy_url}${NC}"
        [ -n "$proxy_details" ] && echo -e "Детали:        ${CYAN}${proxy_details}${NC}"
        [ -n "$configured_at" ] && echo -e "Настроен:      ${CYAN}${configured_at}${NC}"
    else
        echo -e "Статус:        ${YELLOW}Не настроен${NC}"
    fi

    echo
    echo -e "APT прокси:    $( [ -f "$PROXY_APT_CONF" ]  && echo "${GREEN}Настроен${NC}"     || echo "${YELLOW}Нет${NC}" )"
    echo -e "Shell профиль: $( [ -f "$PROXY_PROFILE" ]   && echo "${GREEN}${PROXY_PROFILE}${NC}" || echo "${YELLOW}Нет${NC}" )"

    if systemctl list-unit-files ssh-tunnel-proxy.service &>/dev/null 2>&1; then
        if systemctl is-active ssh-tunnel-proxy.service &>/dev/null 2>&1; then
            echo -e "SSH-туннель:   ${GREEN}Активен${NC}"
        else
            echo -e "SSH-туннель:   ${YELLOW}Настроен, не запущен${NC}"
        fi
    else
        echo -e "SSH-туннель:   ${YELLOW}Не настроен${NC}"
    fi

    if command -v privoxy &>/dev/null; then
        if systemctl is-active privoxy &>/dev/null 2>&1; then
            echo -e "Privoxy:       ${GREEN}Запущен${NC}"
        else
            echo -e "Privoxy:       ${YELLOW}Установлен, не запущен${NC}"
        fi
    else
        echo -e "Privoxy:       ${YELLOW}Не установлен${NC}"
    fi

    if command -v xray &>/dev/null; then
        if systemctl is-active xray &>/dev/null 2>&1; then
            local xver
            xver=$(xray version 2>/dev/null | head -1 || echo "xray")
            echo -e "Xray:          ${GREEN}Запущен (${xver})${NC}"
        else
            echo -e "Xray:          ${YELLOW}Установлен, не запущен${NC}"
        fi
    else
        echo -e "Xray:          ${YELLOW}Не установлен${NC}"
    fi
    echo
}

# ─── Диагностика и подбор режима ──────────────────────────────────────────────

diagnose_and_guide() {
    print_header "ДИАГНОСТИКА И ПОДБОР РЕЖИМА"
    echo -e "${YELLOW}Проверяем, что именно блокируется, и подбираем решение.${NC}"
    echo

    # ── Шаг 1: базовый интернет ─────────────────────────────────────────────
    echo -e "${CYAN}━━━ Шаг 1: Базовый интернет ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local base_ok=false
    if curl -sfI --connect-timeout 6 "http://example.com" &>/dev/null; then
        echo -e "  Базовый интернет:  ${GREEN}✔ Работает${NC}"
        base_ok=true
    else
        echo -e "  Базовый интернет:  ${RED}✘ Нет соединения${NC}"
    fi
    echo

    if ! $base_ok; then
        echo -e "${RED}Интернет недоступен. Прокси здесь не поможет.${NC}"
        echo -e "${YELLOW}Проверьте:${NC}"
        echo -e "  ${CYAN}ip route${NC}          — таблица маршрутов"
        echo -e "  ${CYAN}ping 8.8.8.8${NC}      — доступность внешних IP"
        echo -e "  ${CYAN}resolvectl status${NC} — состояние DNS"
        return 0
    fi

    # ── Шаг 2: проверка ключевых ресурсов ───────────────────────────────────
    echo -e "${CYAN}━━━ Шаг 2: Проверка ключевых ресурсов ━━━━━━━━━━━━━━${NC}"
    echo

    local -a check_hosts=(
        "deb.xanmod.org|XanMod репозиторий"
        "github.com|GitHub"
        "raw.githubusercontent.com|GitHub Raw"
        "api.github.com|GitHub API"
        "registry-1.docker.io|Docker Hub"
    )

    local -a blocked=()
    for item in "${check_hosts[@]}"; do
        local h="${item%%|*}" lbl="${item##*|}"
        printf "  %-38s" "$lbl:"
        if curl -sfI --connect-timeout 6 "https://$h" &>/dev/null; then
            echo -e "${GREEN}✔ Доступен${NC}"
        else
            echo -e "${RED}✘ Заблокирован${NC}"
            blocked+=("$h")
        fi
    done
    echo

    if [[ ${#blocked[@]} -eq 0 ]]; then
        echo -e "${GREEN}✔ Все ресурсы доступны. Прокси не требуется.${NC}"
        echo -e "${YELLOW}Если установка всё равно не проходит — проблема не в блокировках.${NC}"
        echo
        echo -e "${CYAN}Типичные причины (не блокировки):${NC}"
        echo -e "  • Неверный URL в источнике пакетов — ${CYAN}cat /etc/apt/sources.list.d/*.list${NC}"
        echo -e "  • Нехватка места           — ${CYAN}df -h${NC}"
        echo -e "  • Повреждённый кеш apt     — ${CYAN}apt-get clean && apt-get update${NC}"
        return 0
    fi

    echo -e "${YELLOW}Заблокированы: ${blocked[*]}${NC}"
    echo

    # ── Шаг 3: выбор инструмента ────────────────────────────────────────────
    echo -e "${CYAN}━━━ Шаг 3: Что у вас есть? ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo -e "  ${CYAN}a)${NC} VLESS ссылка (vless://...) — от своего Xray/XTLS сервера"
    echo -e "  ${CYAN}b)${NC} SSH-доступ к серверу за пределами блокировок"
    echo -e "  ${CYAN}c)${NC} VPN-клиент с локальным HTTP прокси (Clash, Mihomo, V2Ray...)"
    echo -e "  ${CYAN}d)${NC} Готовый HTTP прокси (адрес:порт)"
    echo -e "  ${CYAN}e)${NC} Ничего из перечисленного"
    echo
    read -rp "Ваш вариант [a/b/c/d/e]: " tool_choice
    echo

    case "${tool_choice,,}" in
        a)
            echo -e "${GREEN}▶ Рекомендуется: Режим 4 — Xray VLESS${NC}"
            echo
            echo -e "${CYAN}Как это работает:${NC}"
            echo -e "  VLESS ссылка → Xray-core (локально) → HTTP :10809 → системный прокси"
            echo
            echo -e "${YELLOW}Пошаговый план:${NC}"
            echo -e "  1. Выбрать ${CYAN}4) Xray VLESS${NC} в меню"
            echo -e "  2. Вставить VLESS ссылку — скрипт сам установит Xray и пропишет прокси"
            echo -e "  3. Выполнить нужную установку (${CYAN}apt install${NC}, ${CYAN}./install_xanmod.sh${NC} и т.д.)"
            echo -e "  4. После завершения — ${CYAN}7) Отключить прокси${NC} (если прокси больше не нужен)"
            echo
            read -rp "Настроить Xray VLESS прямо сейчас? [Y/n]: " go
            [[ ! "${go}" =~ ^[Nn]$ ]] && configure_xray_vless
            ;;
        b)
            echo -e "${GREEN}▶ Рекомендуется: Режим 2 — SSH туннель + Privoxy${NC}"
            echo
            echo -e "${CYAN}Как это работает:${NC}"
            echo -e "  SSH -D (SOCKS5 туннель) → Privoxy (SOCKS5 → HTTP) → системный прокси"
            echo
            echo -e "${YELLOW}Требования:${NC}"
            echo -e "  • SSH ключ без пароля (настройте заранее):"
            echo -e "    ${CYAN}ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519${NC}"
            echo -e "    ${CYAN}ssh-copy-id -p <PORT> user@your-server${NC}"
            echo
            echo -e "${YELLOW}Пошаговый план:${NC}"
            echo -e "  1. Выбрать ${CYAN}2) SSH туннель + Privoxy${NC} в меню"
            echo -e "  2. Ввести user / host / port — скрипт создаст systemd-сервис"
            echo -e "  3. Запустить нужную установку"
            echo -e "  4. После завершения — ${CYAN}7) Отключить прокси${NC}"
            echo
            read -rp "Настроить SSH + Privoxy прямо сейчас? [Y/n]: " go
            [[ ! "${go}" =~ ^[Nn]$ ]] && configure_ssh_privoxy
            ;;
        c)
            echo -e "${GREEN}▶ Рекомендуется: Режим 3 — VPN системный прокси${NC}"
            echo
            echo -e "${CYAN}Типичные адреса HTTP прокси VPN-клиентов:${NC}"
            echo -e "  Clash / Mihomo:  ${CYAN}http://127.0.0.1:7890${NC}"
            echo -e "  Xray / V2Ray:    ${CYAN}http://127.0.0.1:10809${NC}"
            echo -e "  Sing-box:        ${CYAN}http://127.0.0.1:2080${NC}"
            echo -e "  3proxy / Squid:  ${CYAN}http://127.0.0.1:3128${NC}"
            echo
            echo -e "${YELLOW}Пошаговый план:${NC}"
            echo -e "  1. Убедитесь, что VPN-клиент запущен и слушает нужный порт"
            echo -e "  2. Выбрать ${CYAN}3) VPN системный прокси${NC} в меню, ввести адрес"
            echo -e "  3. Запустить нужную установку"
            echo
            read -rp "Настроить VPN прокси прямо сейчас? [Y/n]: " go
            [[ ! "${go}" =~ ^[Nn]$ ]] && configure_vpn_proxy
            ;;
        d)
            echo -e "${GREEN}▶ Рекомендуется: Режим 1 — HTTP прокси${NC}"
            echo
            echo -e "${YELLOW}Пошаговый план:${NC}"
            echo -e "  1. Выбрать ${CYAN}1) HTTP прокси${NC} в меню, ввести адрес"
            echo -e "  2. Скрипт протестирует подключение и пропишет системный прокси"
            echo
            read -rp "Настроить HTTP прокси прямо сейчас? [Y/n]: " go
            [[ ! "${go}" =~ ^[Nn]$ ]] && configure_http_proxy
            ;;
        e)
            echo -e "${YELLOW}━━━ Как получить доступ к заблокированным ресурсам ━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo
            echo -e "  ${CYAN}Вариант 1 — Cloudflare WARP (бесплатно):${NC}"
            echo -e "    curl -fsSL https://pkg.cloudflareclient.com/install.sh | bash"
            echo -e "    warp-cli registration new"
            echo -e "    warp-cli mode proxy && warp-cli connect"
            echo -e "    → HTTP прокси будет доступен на ${CYAN}http://127.0.0.1:40001${NC}"
            echo -e "    → Затем выбрать ${CYAN}3) VPN системный прокси${NC}, адрес: http://127.0.0.1:40001"
            echo
            echo -e "  ${CYAN}Вариант 2 — Арендовать VPS за рубежом (€3–5/мес):${NC}"
            echo -e "    DigitalOcean, Hetzner, Vultr, Linode, BuyVM"
            echo -e "    → Поднять Xray-server → получить VLESS ссылку → вернуться к варианту (a)"
            echo
            echo -e "  ${CYAN}Вариант 3 — Установить Xray-server на существующем VPS:${NC}"
            echo -e "    bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
            echo -e "    Документация: ${CYAN}https://xtls.github.io${NC}"
            echo
            ;;
        *)
            echo -e "${RED}✘ Неверный выбор${NC}"
            ;;
    esac
}

# ─── Режим 1: прямой HTTP прокси ───────────────────────────────────────────────

configure_http_proxy() {
    print_header "ПРЯМОЙ HTTP ПРОКСИ"
    echo -e "${YELLOW}Формат:${NC}"
    echo -e "  ${CYAN}http://host:port${NC}"
    echo -e "  ${CYAN}http://user:pass@host:port${NC}"
    echo

    read -rp "Адрес прокси: " proxy_url

    if [[ -z "$proxy_url" ]]; then
        log_error "Адрес прокси не может быть пустым"
        return 1
    fi
    if ! [[ "$proxy_url" =~ ^https?:// ]]; then
        log_error "Неверный формат. Пример: http://1.2.3.4:3128"
        return 1
    fi

    echo
    if test_proxy "$proxy_url"; then
        apply_proxy "$proxy_url"
        save_proxy_state "http" "$proxy_url"
        echo
        echo -e "${GREEN}✔ HTTP прокси настроен и протестирован${NC}"
    else
        echo
        read -rp "Прокси не отвечает. Сохранить настройки всё равно? [y/N]: " force
        if [[ "$force" =~ ^[Yy]$ ]]; then
            apply_proxy "$proxy_url"
            save_proxy_state "http" "$proxy_url"
            echo -e "${YELLOW}⚠ Прокси настроен без подтверждения доступности${NC}"
        else
            log "Настройка прокси отменена"
            return 0
        fi
    fi

    echo
    echo -e "${YELLOW}Для применения в текущей SSH-сессии:${NC}"
    echo -e "${CYAN}  source /etc/profile.d/proxy.sh${NC}"
}

# ─── Режим 2: SSH туннель + Privoxy ────────────────────────────────────────────

configure_ssh_privoxy() {
    print_header "SSH ТУННЕЛЬ + PRIVOXY"
    echo -e "${YELLOW}Схема:${NC} ssh -D <socks_port> user@host  →  Privoxy  →  системный HTTP прокси"
    echo -e "${YELLOW}Требование:${NC} SSH-ключ без пароля на удалённом сервере"
    echo

    # Зависимости
    log "Установка Privoxy и openssh-client..."
    apt-get update -qq
    if ! apt-get install -y privoxy openssh-client; then
        log_error "Ошибка установки зависимостей"
        return 1
    fi
    log_success "Зависимости установлены"

    # Параметры
    echo
    echo -e "${CYAN}─── Параметры SSH туннеля ───────────────────────${NC}"
    read -rp "SSH пользователь: " ssh_user
    read -rp "SSH хост (IP или домен): " ssh_host
    read -rp "SSH порт [22]: " ssh_port
    ssh_port=${ssh_port:-22}
    read -rp "Локальный SOCKS5 порт [1080]: " socks_port
    socks_port=${socks_port:-1080}
    read -rp "Локальный HTTP порт Privoxy [8118]: " privoxy_port
    privoxy_port=${privoxy_port:-8118}

    if [[ -z "$ssh_user" || -z "$ssh_host" ]]; then
        log_error "SSH пользователь и хост обязательны"
        return 1
    fi
    if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
        log_error "Некорректный SSH порт: $ssh_port"
        return 1
    fi

    local proxy_url="http://127.0.0.1:${privoxy_port}"

    # systemd сервис SSH туннеля
    log "Создание systemd сервиса SSH туннеля..."
    cat > "$SSH_TUNNEL_SERVICE" <<EOF
[Unit]
Description=SSH SOCKS5 Proxy Tunnel (${ssh_user}@${ssh_host}:${ssh_port})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/ssh \\
    -N \\
    -D 127.0.0.1:${socks_port} \\
    -p ${ssh_port} \\
    -o StrictHostKeyChecking=accept-new \\
    -o ServerAliveInterval=30 \\
    -o ServerAliveCountMax=3 \\
    -o ExitOnForwardFailure=yes \\
    -o ConnectTimeout=15 \\
    ${ssh_user}@${ssh_host}
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Конфигурация Privoxy (минимальная, только SOCKS5→HTTP)
    log "Настройка Privoxy..."
    if [ ! -f "${PRIVOXY_CONF}.orig" ]; then
        cp "$PRIVOXY_CONF" "${PRIVOXY_CONF}.orig"
        log "Оригинальный конфиг сохранён: ${PRIVOXY_CONF}.orig"
    fi

    cat > "$PRIVOXY_CONF" <<EOF
# Managed by setup_proxy.sh — restore with: cp ${PRIVOXY_CONF}.orig ${PRIVOXY_CONF}
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
logfile logfile

# Слушаем HTTP запросы локально
listen-address  127.0.0.1:${privoxy_port}

# Перенаправляем всё в SOCKS5 туннель
forward-socks5  /  127.0.0.1:${socks_port}  .

# Отключаем фильтрацию (режим чистого прокси)
toggle                          1
enable-remote-toggle            0
enable-remote-http-toggle       0
enable-edit-actions             0
enforce-blocks                  0
buffer-limit                    4096
forwarded-connect-retries       3
accept-intercepted-requests     0
split-large-forms               0
keep-alive-timeout              5
tolerate-pipelining             1
socket-timeout                  300

actionsfile match-all.action
actionsfile default.action
actionsfile user.action
filterfile default.filter
EOF

    systemctl daemon-reload
    systemctl enable ssh-tunnel-proxy.service
    systemctl enable privoxy

    # Инструкция по SSH ключам
    echo
    echo -e "${YELLOW}━━━ SSH ключ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Для беспарольного подключения к ${CYAN}${ssh_host}${NC}:"
    echo -e "  ${CYAN}ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ''${NC}  ← если ключа ещё нет"
    echo -e "  ${CYAN}ssh-copy-id -p ${ssh_port} ${ssh_user}@${ssh_host}${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    read -rp "SSH ключ настроен, запустить туннель сейчас? [y/N]: " start_now

    if [[ "$start_now" =~ ^[Yy]$ ]]; then
        log "Запуск SSH туннеля..."
        systemctl start ssh-tunnel-proxy.service
        sleep 4

        if systemctl is-active ssh-tunnel-proxy.service &>/dev/null; then
            log_success "SSH туннель запущен (SOCKS5 → 127.0.0.1:${socks_port})"

            log "Запуск Privoxy..."
            systemctl restart privoxy
            sleep 2

            if systemctl is-active privoxy &>/dev/null; then
                log_success "Privoxy запущен (HTTP → 127.0.0.1:${privoxy_port})"
                apply_proxy "$proxy_url"
                save_proxy_state "ssh+privoxy" "$proxy_url" "${ssh_user}@${ssh_host}:${ssh_port}"
                echo
                echo -e "${GREEN}✔ SSH туннель + Privoxy настроены и запущены${NC}"
                echo -e "  Системный прокси: ${CYAN}${proxy_url}${NC}"
                echo
                echo -e "${YELLOW}Для применения в текущей SSH-сессии:${NC}"
                echo -e "${CYAN}  source /etc/profile.d/proxy.sh${NC}"
            else
                log_error "Ошибка запуска Privoxy"
                echo -e "${YELLOW}Диагностика: ${CYAN}journalctl -u privoxy -n 30${NC}"
            fi
        else
            log_error "SSH туннель не запустился. Проверьте SSH ключи и доступность хоста."
            echo
            echo -e "${YELLOW}Диагностика:${NC}"
            echo -e "  ${CYAN}journalctl -u ssh-tunnel-proxy.service -n 30${NC}"
            echo -e "  ${CYAN}ssh -v -N -D 127.0.0.1:${socks_port} -p ${ssh_port} ${ssh_user}@${ssh_host}${NC}"
            save_proxy_state "ssh+privoxy" "$proxy_url" "${ssh_user}@${ssh_host}:${ssh_port}"
        fi
    else
        save_proxy_state "ssh+privoxy" "$proxy_url" "${ssh_user}@${ssh_host}:${ssh_port}"
        echo
        echo -e "${YELLOW}Сервисы настроены. Запуск вручную:${NC}"
        echo -e "  ${CYAN}systemctl start ssh-tunnel-proxy.service${NC}"
        echo -e "  ${CYAN}systemctl start privoxy${NC}"
        echo
        echo -e "${YELLOW}Затем применить прокси повторно запустите этот скрипт${NC}"
        echo -e "${YELLOW}или выполните вручную:${NC}"
        echo -e "  ${CYAN}export http_proxy=\"${proxy_url}\" https_proxy=\"${proxy_url}\"${NC}"
    fi
}

# ─── Режим 3: VPN системный прокси ─────────────────────────────────────────────

configure_vpn_proxy() {
    print_header "VPN СИСТЕМНЫЙ ПРОКСИ"
    echo -e "${YELLOW}VPN клиенты, открывающие локальный HTTP прокси:${NC}"
    echo -e "  Clash / Mihomo  ${CYAN}http://127.0.0.1:7890${NC}"
    echo -e "  OpenVPN + Squid ${CYAN}http://127.0.0.1:8080${NC}"
    echo -e "  3proxy          ${CYAN}http://127.0.0.1:3128${NC}"
    echo -e "  Xray / V2Ray    ${CYAN}http://127.0.0.1:10809${NC}"
    echo

    read -rp "Адрес прокси VPN: " proxy_url

    if [[ -z "$proxy_url" ]]; then
        log_error "Адрес прокси не может быть пустым"
        return 1
    fi
    if ! [[ "$proxy_url" =~ ^https?:// ]]; then
        log_error "Неверный формат. Пример: http://127.0.0.1:7890"
        return 1
    fi

    echo
    if test_proxy "$proxy_url"; then
        apply_proxy "$proxy_url"
        save_proxy_state "vpn" "$proxy_url"
        echo
        echo -e "${GREEN}✔ VPN прокси настроен и протестирован${NC}"
    else
        echo
        read -rp "Прокси не отвечает (VPN отключён?). Сохранить настройки? [y/N]: " force
        if [[ "$force" =~ ^[Yy]$ ]]; then
            apply_proxy "$proxy_url"
            save_proxy_state "vpn" "$proxy_url"
            echo -e "${YELLOW}⚠ Прокси настроен. Убедитесь, что VPN активен перед использованием.${NC}"
        else
            log "Настройка отменена"
            return 0
        fi
    fi

    echo
    echo -e "${YELLOW}Для применения в текущей SSH-сессии:${NC}"
    echo -e "${CYAN}  source /etc/profile.d/proxy.sh${NC}"
}

# ─── Отключение ────────────────────────────────────────────────────────────────

disable_proxy() {
    print_header "ОТКЛЮЧЕНИЕ ПРОКСИ"

    remove_proxy

    if systemctl list-unit-files ssh-tunnel-proxy.service &>/dev/null 2>&1; then
        systemctl stop ssh-tunnel-proxy.service 2>/dev/null || true
        systemctl disable ssh-tunnel-proxy.service 2>/dev/null || true
        rm -f "$SSH_TUNNEL_SERVICE"
        systemctl daemon-reload
        log_success "SSH туннель остановлен и удалён"
    fi

    if command -v privoxy &>/dev/null; then
        systemctl stop privoxy 2>/dev/null || true
        systemctl disable privoxy 2>/dev/null || true
        if [ -f "${PRIVOXY_CONF}.orig" ]; then
            cp "${PRIVOXY_CONF}.orig" "$PRIVOXY_CONF"
            log_success "Конфигурация Privoxy восстановлена"
        fi
        log_success "Privoxy остановлен"
    fi

    if command -v xray &>/dev/null; then
        systemctl stop xray 2>/dev/null || true
        systemctl disable xray 2>/dev/null || true
        log_success "Xray остановлен"
    fi

    rm -f "$PROXY_STATE_FILE"

    echo
    echo -e "${GREEN}✔ Все настройки прокси удалены${NC}"
    echo -e "${YELLOW}Для текущей сессии:${NC}"
    echo -e "${CYAN}  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY${NC}"
}

# ─── Главное меню ──────────────────────────────────────────────────────────────

show_menu() {
    while true; do
        print_header "НАСТРОЙКА ПРОКСИ v1.2.0"
        show_status

        echo -e "${YELLOW}Выберите режим:${NC}"
        echo
        echo -e "1) ${GREEN}HTTP прокси${NC}              — прямой HTTP/HTTPS прокси"
        echo -e "2) ${GREEN}SSH туннель + Privoxy${NC}    — SOCKS5 через SSH → HTTP (обход блокировок)"
        echo -e "3) ${GREEN}VPN системный прокси${NC}     — HTTP прокси от VPN клиента (Clash, Mihomo...)"
        echo -e "4) ${GREEN}Xray VLESS${NC}               — VLESS ссылка (REALITY / TLS / WS / gRPC)"
        echo -e "5) ${CYAN}Диагностика${NC}              — что делать, если что-то не устанавливается"
        echo -e "6) ${YELLOW}Обновить статус${NC}"
        echo -e "7) ${RED}Отключить прокси${NC}         — удалить все настройки и остановить сервисы"
        echo -e "0) ${RED}Выход${NC}"
        echo

        read -rp "Выберите опцию [0-7]: " choice
        echo

        case $choice in
            1) configure_http_proxy ;;
            2) configure_ssh_privoxy ;;
            3) configure_vpn_proxy ;;
            4) configure_xray_vless ;;
            5) diagnose_and_guide ;;
            6) continue ;;
            7) disable_proxy ;;
            0) exit 0 ;;
            *) echo -e "${RED}✘ Неверный выбор${NC}" ;;
        esac

        echo
        read -rp "Нажмите Enter для продолжения..."
    done
}

# ─── Точка входа ───────────────────────────────────────────────────────────────

mkdir -p "$(dirname "$LOG_FILE")"
check_root
show_menu
