#!/usr/bin/env bash

# Version: 2.0.0
# Description: Temporary proxy server/client session manager for Ubuntu 24.04

set -Eeuo pipefail

SCRIPT_VERSION='2.0.0'
STATE_ROOT="${PROXY_STATE_ROOT:-/etc/server-scripts/proxy-sessions}"
CONFIG_ROOT="${PROXY_CONFIG_ROOT:-/etc/server-scripts-proxy}"
SERVER_STATE="$STATE_ROOT/server.env"
CLIENT_STATE="$STATE_ROOT/client.env"
SERVER_CONFIG="$CONFIG_ROOT/server.json"
CLIENT_CONFIG="$CONFIG_ROOT/client.json"
CLIENT_BACKUP="$STATE_ROOT/client-backup"
LOG_FILE="${PROXY_LOG_FILE:-/var/log/server-scripts/setup_proxy.log}"
PROXY_ENV_FILE="${PROXY_ENV_FILE:-/etc/environment}"
PROXY_APT_CONF="${PROXY_APT_CONF:-/etc/apt/apt.conf.d/99server-scripts-proxy}"
PROXY_PROFILE="${PROXY_PROFILE:-/etc/profile.d/server-scripts-proxy.sh}"
SERVER_UNIT="${SERVER_UNIT:-/etc/systemd/system/server-scripts-proxy-server.service}"
CLIENT_UNIT="${CLIENT_UNIT:-/etc/systemd/system/server-scripts-proxy-client.service}"
SSH_UNIT="${SSH_UNIT:-/etc/systemd/system/server-scripts-proxy-ssh.service}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_DROPIN="${SSHD_DROPIN:-/etc/ssh/sshd_config.d/10-server-scripts-proxy.conf}"
SSHD_BACKUP="${SSHD_BACKUP:-$STATE_ROOT/sshd_config.backup}"
EXPIRE_SERVICE="${EXPIRE_SERVICE:-/etc/systemd/system/server-scripts-proxy-expire.service}"
EXPIRE_TIMER="${EXPIRE_TIMER:-/etc/systemd/system/server-scripts-proxy-expire.timer}"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PROXY_USER="${PROXY_USER:-server-scripts-proxy}"
readonly SCRIPT_VERSION STATE_ROOT CONFIG_ROOT SERVER_STATE CLIENT_STATE SERVER_CONFIG CLIENT_CONFIG CLIENT_BACKUP LOG_FILE
readonly PROXY_ENV_FILE PROXY_APT_CONF PROXY_PROFILE SERVER_UNIT CLIENT_UNIT SSH_UNIT EXPIRE_SERVICE EXPIRE_TIMER
readonly SSHD_CONFIG SSHD_DROPIN SSHD_BACKUP
readonly XRAY_BIN PYTHON_BIN PROXY_USER

if [[ -t 1 ]]; then
    RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
fi
readonly RED GREEN YELLOW BLUE CYAN NC

print_header() { printf '\n%b========== %s ==========%b\n\n' "$BLUE" "$1" "$NC"; }
print_step() { printf '%b➜%b %s\n' "$YELLOW" "$NC" "$1"; }
print_success() { printf '%b✔%b %s\n' "$GREEN" "$NC" "$1"; }
print_error() { printf '%b✘%b %s\n' "$RED" "$NC" "$1" >&2; }
print_secret() { { printf '%b\n' "$1" > /dev/tty; } 2>/dev/null || printf '%s\n' '[Секрет скрыт: требуется интерактивный TTY]' >&2; }
confirm() { local answer; read -r -p "$1 [y/N]: " answer; [[ "$answer" =~ ^[Yy]$ ]]; }

log() {
    local level="$1"; shift
    install -d -m 0750 -- "$(dirname -- "$LOG_FILE")"
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" >> "$LOG_FILE"
}

check_root() { (( EUID == 0 )) || { print_error 'Скрипт должен быть запущен от root'; return 1; }; }
shell_quote() { printf '%q' "$1"; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

validate_paths() {
    local path
    for path in "$STATE_ROOT" "$CONFIG_ROOT" "$LOG_FILE" "$SERVER_UNIT" "$CLIENT_UNIT" "$SSH_UNIT" "$EXPIRE_SERVICE" "$EXPIRE_TIMER" "$SSHD_CONFIG" "$SSHD_DROPIN" "$SSHD_BACKUP"; do
        [[ "$path" == /* && "$path" != / && $(realpath -m -- "$path") == "$path" ]] || {
            print_error "Недопустимый путь: $path"; return 1;
        }
    done
}

validate_proxy_url() {
    PROXY_URL_TO_VALIDATE="$1" "$PYTHON_BIN" <<'PY'
import os, sys, urllib.parse
value = os.environ['PROXY_URL_TO_VALIDATE']
if any(ord(ch) < 32 or ord(ch) == 127 for ch in value): sys.exit(1)
p = urllib.parse.urlsplit(value)
try: port = p.port
except ValueError: sys.exit(1)
if p.scheme not in {'http', 'https', 'socks5h'} or not p.hostname or port is None: sys.exit(1)
if not 1 <= port <= 65535 or p.path not in {'', '/'} or p.query or p.fragment: sys.exit(1)
PY
}

validate_host() {
    HOST_TO_VALIDATE="$1" "$PYTHON_BIN" <<'PY'
import ipaddress, os, re, sys
v=os.environ['HOST_TO_VALIDATE']
try: ipaddress.ip_address(v); sys.exit(0)
except ValueError: pass
if len(v)>253 or not re.fullmatch(r'(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', v): sys.exit(1)
PY
}

validate_ipv4_cidr() {
    CIDR_TO_VALIDATE="$1" "$PYTHON_BIN" <<'PY'
import ipaddress, os, sys
try: n=ipaddress.ip_network(os.environ['CIDR_TO_VALIDATE'], strict=False)
except ValueError: sys.exit(1)
sys.exit(0 if n.version == 4 else 1)
PY
}

create_session_id() { printf '%s-%s' "$(date '+%Y%m%d%H%M%S')" "$(openssl rand -hex 4)"; }
random_secret() { openssl rand -base64 24 | tr -d '\n' | tr '/+' '_-'; }
random_port() {
    local port
    for _ in {1..100}; do
        port=$((20000 + RANDOM % 30000))
        if ! ss -H -lnt "sport = :$port" 2>/dev/null | grep -q .; then printf '%s\n' "$port"; return 0; fi
    done
    return 1
}

wait_for_listener() {
    local unit="$1" port="$2" attempts="${3:-30}"
    local attempt
    for ((attempt=0; attempt<attempts; attempt++)); do
        systemctl is-active --quiet "$unit" || return 1
        ss -H -lnt "sport = :$port" 2>/dev/null | grep -q . && return 0
        sleep 0.5
    done
    return 1
}

save_state() {
    local file="$1"; shift
    local temp key value
    install -d -m 0700 -- "$STATE_ROOT"
    temp=$(mktemp "$STATE_ROOT/.state.XXXXXX") || return 1
    while (( $# >= 2 )); do
        key="$1"; value="$2"; shift 2
        [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || { rm -f -- "$temp"; return 1; }
        printf '%s=%q\n' "$key" "$value" >> "$temp"
    done
    chmod 0600 -- "$temp"
    mv -f -- "$temp" "$file"
}

load_state() {
    local file="$1"
    [[ -f "$file" && ! -L "$file" && $(stat -c %a -- "$file") == 600 ]] || return 1
    # State is generated by save_state and writable only by root.
    # shellcheck disable=SC1090
    source "$file"
}

# Backward-compatible helper retained for fixture consumers.
save_proxy_state() {
    local mode="$1" url="$2" details="${3:-}"
    save_state "$CLIENT_STATE" PROXY_MODE "$mode" PROXY_URL "$url" PROXY_DETAILS "$details" PROXY_CONFIGURED "$(date --iso-8601=seconds)"
}

encode_bundle() {
    B_MODE="$1" B_HOST="$2" B_PORT="$3" B_USER="$4" B_PASS="$5" B_SESSION="$6" B_EXPIRES="$7" \
    "$PYTHON_BIN" <<'PY'
import base64, json, os
obj={'version':1,'role':'server','mode':os.environ['B_MODE'],'host':os.environ['B_HOST'],
     'port':int(os.environ['B_PORT']),'username':os.environ['B_USER'],'password':os.environ['B_PASS'],
     'sessionId':os.environ['B_SESSION'],'expiresAt':os.environ['B_EXPIRES']}
raw=json.dumps(obj,separators=(',',':')).encode()
print('server-scripts-proxy://v1/'+base64.urlsafe_b64encode(raw).decode().rstrip('='))
PY
}

decode_bundle() {
    local bundle="$1"
    mapfile -d '' -t BUNDLE_FIELDS < <(BUNDLE="$bundle" "$PYTHON_BIN" <<'PY'
import base64, ipaddress, json, os, re, sys
prefix='server-scripts-proxy://v1/'
value=os.environ['BUNDLE']
if not value.startswith(prefix): sys.exit(2)
try:
    data=value[len(prefix):]; data += '='*((4-len(data)%4)%4)
    obj=json.loads(base64.urlsafe_b64decode(data).decode())
except Exception: sys.exit(2)
required={'version','role','mode','host','port','username','password','sessionId','expiresAt'}
if set(obj) != required or obj['version'] != 1 or obj['role'] != 'server' or obj['mode'] not in {'http','socks5'}: sys.exit(2)
if not isinstance(obj['port'],int) or not 1 <= obj['port'] <= 65535: sys.exit(2)
for key in ('host','username','password','sessionId','expiresAt'):
    if not isinstance(obj[key],str) or not obj[key] or any(ord(c)<32 or ord(c)==127 for c in obj[key]): sys.exit(2)
if len(obj['host'])>253 or not re.fullmatch(r'[A-Za-z0-9.:-]+',obj['host']): sys.exit(2)
for key in ('mode','host','port','username','password','sessionId','expiresAt'):
    sys.stdout.write(str(obj[key])+'\0')
PY
    ) || return 1
    (( ${#BUNDLE_FIELDS[@]} == 7 )) || return 1
    BUNDLE_MODE=${BUNDLE_FIELDS[0]}; BUNDLE_HOST=${BUNDLE_FIELDS[1]}; BUNDLE_PORT=${BUNDLE_FIELDS[2]}
    BUNDLE_USER=${BUNDLE_FIELDS[3]}; BUNDLE_PASS=${BUNDLE_FIELDS[4]}; BUNDLE_SESSION=${BUNDLE_FIELDS[5]}; BUNDLE_EXPIRES=${BUNDLE_FIELDS[6]}
}

ensure_packages() {
    local -a packages=(ca-certificates curl openssl python3 unzip)
    local command
    for command in curl openssl "$PYTHON_BIN" unzip sha256sum ss; do
        command -v "$command" >/dev/null 2>&1 || {
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" iproute2
            break
        }
    done
}

install_xray_binary() {
    [[ -x "$XRAY_BIN" ]] && { "$XRAY_BIN" version >/dev/null 2>&1; return; }
    ensure_packages
    local machine asset tmp expected actual
    machine=$(uname -m)
    case "$machine" in
        x86_64) asset='Xray-linux-64.zip' ;;
        aarch64|arm64) asset='Xray-linux-arm64-v8a.zip' ;;
        *) print_error "Архитектура Xray не поддерживается: $machine"; return 1 ;;
    esac
    tmp=$(mktemp -d /tmp/setup-proxy-xray.XXXXXX) || return 1
    if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors \
        "https://github.com/XTLS/Xray-core/releases/latest/download/$asset" -o "$tmp/xray.zip" \
        || ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 3 --retry-all-errors \
        "https://github.com/XTLS/Xray-core/releases/latest/download/$asset.dgst" -o "$tmp/xray.zip.dgst"; then
        rm -rf -- "$tmp"; return 1
    fi
    expected=$(awk -F '= ' '/SHA2-256|SHA256|256=/ {print $NF; exit}' "$tmp/xray.zip.dgst" | tr -d '[:space:]')
    actual=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
    [[ "$expected" =~ ^[0-9A-Fa-f]{64}$ && "${expected,,}" == "$actual" ]] || { rm -rf -- "$tmp"; print_error 'SHA-256 Xray не совпал'; return 1; }
    unzip -Z1 "$tmp/xray.zip" | grep -qx xray || { rm -rf -- "$tmp"; return 1; }
    unzip -p "$tmp/xray.zip" xray > "$tmp/xray"
    chmod 0755 "$tmp/xray"; "$tmp/xray" version >/dev/null
    install -m 0755 -- "$tmp/xray" "$XRAY_BIN"
    rm -rf -- "$tmp"
}

ensure_proxy_user() {
    if ! id "$PROXY_USER" >/dev/null 2>&1; then
        useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home "$PROXY_USER"
    fi
}

write_xray_unit() {
    local unit="$1" description="$2" config="$3" candidate
    candidate=$(mktemp /tmp/setup-proxy-unit.XXXXXX.service)
    cat > "$candidate" <<EOF
[Unit]
Description=$description
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$PROXY_USER
Group=$PROXY_USER
ExecStart=$XRAY_BIN run -c $config
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF
    systemd-analyze verify "$candidate" >/dev/null
    install -m 0644 -- "$candidate" "$unit"
    rm -f -- "$candidate"
}

generate_server_config() {
    local mode="$1" port="$2" username="$3" password="$4"
    MODE="$mode" PORT="$port" USERNAME="$username" PASSWORD="$password" OUTPUT="$SERVER_CONFIG" "$PYTHON_BIN" <<'PY'
import json, os
mode=os.environ['MODE']; port=int(os.environ['PORT']); user=os.environ['USERNAME']; password=os.environ['PASSWORD']
if mode=='http': settings={'accounts':[{'user':user,'pass':password}]}
elif mode=='socks5': settings={'auth':'password','accounts':[{'user':user,'pass':password}],'udp':False}
else: raise SystemExit(2)
cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'0.0.0.0','port':port,'protocol':'socks' if mode=='socks5' else 'http','settings':settings,'tag':'temporary-in'}],
     'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'blocked'}]}
with open(os.environ['OUTPUT'],'w') as f: json.dump(cfg,f,separators=(',',':'))
PY
}

generate_socks_client_config() {
    local host="$1" port="$2" username="$3" password="$4" local_port="$5"
    HOST="$host" PORT="$port" USERNAME="$username" PASSWORD="$password" LOCAL_PORT="$local_port" OUTPUT="$CLIENT_CONFIG" "$PYTHON_BIN" <<'PY'
import json, os
cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':int(os.environ['LOCAL_PORT']),'protocol':'http','settings':{},'tag':'local-http'}],
     'outbounds':[{'protocol':'socks','tag':'proxy','settings':{'servers':[{'address':os.environ['HOST'],'port':int(os.environ['PORT']),'users':[{'user':os.environ['USERNAME'],'pass':os.environ['PASSWORD']}]}]}}]}
server=cfg['outbounds'][0]['settings']['servers'][0]
if not os.environ['USERNAME'] and not os.environ['PASSWORD']: server.pop('users')
with open(os.environ['OUTPUT'],'w') as f: json.dump(cfg,f,separators=(',',':'))
PY
}

validate_private_key_path() {
    local path="$1" mode
    [[ "$path" =~ ^/[A-Za-z0-9._/-]+$ && -f "$path" && ! -L "$path" ]] || return 1
    mode=$(stat -c '%a' -- "$path")
    (( (8#$mode & 077) == 0 ))
}

write_ssh_client_unit() {
    local host="$1" ssh_port="$2" user="$3" key_file="$4" socks_port="$5" candidate
    validate_host "$host" && valid_port "$ssh_port" && validate_username "$user" && validate_private_key_path "$key_file" && valid_port "$socks_port" || return 2
    candidate=$(mktemp /tmp/setup-proxy-ssh-unit.XXXXXX.service)
    cat > "$candidate" <<EOF
[Unit]
Description=Temporary SSH SOCKS client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -N -D 127.0.0.1:$socks_port -p $ssh_port -i $key_file -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$STATE_ROOT/ssh_known_hosts $user@$host
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_ROOT

[Install]
WantedBy=multi-user.target
EOF
    systemd-analyze verify "$candidate" >/dev/null
    install -m 0644 -- "$candidate" "$SSH_UNIT"
    rm -f -- "$candidate"
}

client_connect_ssh_socks() {
    local host="$1" ssh_port="$2" user="$3" key_file="$4" local_socks_port="${5:-10808}" proxy_url
    [[ ! -e "$CLIENT_STATE" ]] || { print_error 'Клиентская сессия уже существует; сначала отключите её'; return 1; }
    if ! validate_host "$host" || ! valid_port "$ssh_port" || ! validate_username "$user" || ! validate_private_key_path "$key_file"; then
        print_error 'Проверьте host/port/user; нужен приватный ключ с правами 0600 и безопасным абсолютным путём'; return 2
    fi
    valid_port "$local_socks_port" || return 2
    install -d -m 0700 -- "$STATE_ROOT"
    write_ssh_client_unit "$host" "$ssh_port" "$user" "$key_file" "$local_socks_port"
    systemctl daemon-reload; systemctl enable --now "$(basename -- "$SSH_UNIT")" >/dev/null
    if ! wait_for_listener "$(basename -- "$SSH_UNIT")" "$local_socks_port"; then
        client_remove || true; print_error 'SSH SOCKS-туннель не запустился'; return 1
    fi
    proxy_url="socks5h://127.0.0.1:$local_socks_port"
    if ! test_http_proxy "$proxy_url"; then client_remove || true; print_error 'Доступ через SSH SOCKS не подтверждён'; return 1; fi
    apply_system_proxy "$proxy_url"
    save_state "$CLIENT_STATE" ROLE client SESSION_ID "$(create_session_id)" MODE ssh-socks PROXY_URL "$proxy_url" DETAILS "$user@$host:$ssh_port" CONFIGURED_AT "$(date --iso-8601=seconds)"
    print_success 'SSH SOCKS-клиент подключён напрямую через socks5h'
    print_secret "Для текущего терминала: source $PROXY_PROFILE"
}

url_decode() { VALUE_TO_DECODE="$1" "$PYTHON_BIN" -c 'import os,urllib.parse; print(urllib.parse.unquote(os.environ["VALUE_TO_DECODE"]))'; }
get_qparam() { local value; value=$(printf '%s' "$VLESS_QUERY" | tr '&' '\n' | awk -F= -v key="$1" '$1==key {sub(/^[^=]*=/,""); print; exit}'); url_decode "$value"; }

parse_vless_link() {
    local link="$1" body authority query remark_raw hostport
    body=${link#vless://}; remark_raw=''; [[ "$body" == *#* ]] && { remark_raw=${body#*#}; body=${body%%#*}; }
    query=''; [[ "$body" == *\?* ]] && { query=${body#*\?}; body=${body%%\?*}; }
    VLESS_UUID=${body%%@*}; authority=${body#*@}; [[ "$authority" != "$body" ]] || return 1
    hostport=$authority
    if [[ "$hostport" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then VLESS_HOST=${BASH_REMATCH[1]}; VLESS_PORT=${BASH_REMATCH[2]}
    else VLESS_HOST=${hostport%:*}; VLESS_PORT=${hostport##*:}; fi
    VLESS_QUERY=$query
    VLESS_SECURITY=$(get_qparam security); VLESS_NETWORK=$(get_qparam type); VLESS_FLOW=$(get_qparam flow)
    VLESS_SNI=$(get_qparam sni); VLESS_FP=$(get_qparam fp); VLESS_PBK=$(get_qparam pbk); VLESS_SID=$(get_qparam sid)
    VLESS_SPX=$(get_qparam spx); VLESS_HOST_HEADER=$(get_qparam host); VLESS_PATH=$(get_qparam path)
    VLESS_SECURITY=${VLESS_SECURITY:-none}; VLESS_NETWORK=${VLESS_NETWORK:-tcp}; VLESS_FP=${VLESS_FP:-chrome}
    VLESS_PATH=${VLESS_PATH:-/}; VLESS_SPX=${VLESS_SPX:-/}; VLESS_REMARK=$(url_decode "$remark_raw"); VLESS_REMARK=${VLESS_REMARK:-temporary-vless}
}

validate_vless_params() {
    [[ "$VLESS_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || return 1
    validate_host "$VLESS_HOST" || return 1; valid_port "$VLESS_PORT" || return 1
    [[ "$VLESS_SECURITY" =~ ^(none|tls|reality)$ && "$VLESS_NETWORK" =~ ^(tcp|raw|ws|grpc)$ ]] || return 1
    [[ "$VLESS_SECURITY" != reality || ( -n "$VLESS_SNI" && -n "$VLESS_PBK" ) ]] || return 1
    [[ "$VLESS_SECURITY" != tls || -n "$VLESS_SNI" ]] || return 1
}

generate_vless_client_config() {
    local local_port="$1"
    VLESS_UUID="$VLESS_UUID" VLESS_HOST="$VLESS_HOST" VLESS_PORT="$VLESS_PORT" VLESS_SECURITY="$VLESS_SECURITY" \
    VLESS_NETWORK="$VLESS_NETWORK" VLESS_FLOW="$VLESS_FLOW" VLESS_SNI="$VLESS_SNI" VLESS_FP="$VLESS_FP" VLESS_PBK="$VLESS_PBK" \
    VLESS_SID="$VLESS_SID" VLESS_SPX="$VLESS_SPX" VLESS_HOST_HEADER="$VLESS_HOST_HEADER" VLESS_PATH="$VLESS_PATH" \
    LOCAL_PORT="$local_port" OUTPUT="$CLIENT_CONFIG" "$PYTHON_BIN" <<'PY'
import json,os
u=os.environ
stream={'network':'tcp' if u['VLESS_NETWORK']=='raw' else u['VLESS_NETWORK'],'security':u['VLESS_SECURITY']}
if u['VLESS_SECURITY']=='reality': stream['realitySettings']={'serverName':u['VLESS_SNI'],'fingerprint':u['VLESS_FP'],'publicKey':u['VLESS_PBK'],'shortId':u['VLESS_SID'],'spiderX':u['VLESS_SPX']}
elif u['VLESS_SECURITY']=='tls': stream['tlsSettings']={'serverName':u['VLESS_SNI'],'fingerprint':u['VLESS_FP'],'allowInsecure':False}
if u['VLESS_NETWORK']=='ws': stream['wsSettings']={'path':u['VLESS_PATH'],'headers':{'Host':u['VLESS_HOST_HEADER'] or u['VLESS_SNI']}}
elif u['VLESS_NETWORK']=='grpc': stream['grpcSettings']={'serviceName':u['VLESS_PATH'].lstrip('/')}
user={'id':u['VLESS_UUID'],'encryption':'none'}
if u['VLESS_FLOW']: user['flow']=u['VLESS_FLOW']
cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':int(u['LOCAL_PORT']),'protocol':'http','settings':{},'tag':'local-http'}],
 'outbounds':[{'protocol':'vless','tag':'proxy','settings':{'vnext':[{'address':u['VLESS_HOST'],'port':int(u['VLESS_PORT']),'users':[user]}]},'streamSettings':stream}]}
with open(u['OUTPUT'],'w') as f: json.dump(cfg,f,separators=(',',':'))
PY
}

backup_client_proxy_files() {
    rm -rf -- "$CLIENT_BACKUP"
    install -d -m 0700 -- "$CLIENT_BACKUP"
    local index=0 file
    for file in "$PROXY_ENV_FILE" "$PROXY_APT_CONF" "$PROXY_PROFILE"; do
        [[ ! -L "$file" && ( ! -e "$file" || -f "$file" ) ]] || { print_error "Proxy target должен быть обычным файлом: $file"; return 1; }
        if [[ -e "$file" ]]; then cp -a -- "$file" "$CLIENT_BACKUP/file.$index"; else : > "$CLIENT_BACKUP/absent.$index"; fi
        ((index += 1))
    done
}

apply_system_proxy() {
    local proxy_url="$1" temp
    validate_proxy_url "$proxy_url" || return 1
    backup_client_proxy_files
    temp=$(mktemp "$(dirname -- "$PROXY_ENV_FILE")/.environment.proxy.XXXXXX")
    ENV_FILE="$PROXY_ENV_FILE" PROXY_URL_VALUE="$proxy_url" "$PYTHON_BIN" <<'PY' > "$temp"
import os
keys={'http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','all_proxy','ALL_PROXY','no_proxy','NO_PROXY'}
try: lines=open(os.environ['ENV_FILE']).read().splitlines()
except FileNotFoundError: lines=[]
for line in lines:
    if line.split('=',1)[0].strip() not in keys: print(line)
p=os.environ['PROXY_URL_VALUE'].replace('\\','\\\\').replace('"','\\"')
n='localhost,127.0.0.1,::1'
for key in ('http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY'): print(f'{key}="{p}"')
for key in ('all_proxy','ALL_PROXY'): print(f'{key}="{p}"')
for key in ('no_proxy','NO_PROXY'): print(f'{key}="{n}"')
PY
    chmod 0600 "$temp"; mv -f -- "$temp" "$PROXY_ENV_FILE"
    install -m 0600 /dev/null "$PROXY_PROFILE"
    printf 'export http_proxy=%q\nexport https_proxy=%q\nexport HTTP_PROXY=%q\nexport HTTPS_PROXY=%q\n' "$proxy_url" "$proxy_url" "$proxy_url" "$proxy_url" > "$PROXY_PROFILE"
    printf 'export all_proxy=%q\nexport ALL_PROXY=%q\n' "$proxy_url" "$proxy_url" >> "$PROXY_PROFILE"
    printf 'export no_proxy=%q\nexport NO_PROXY=%q\n' 'localhost,127.0.0.1,::1' 'localhost,127.0.0.1,::1' >> "$PROXY_PROFILE"
    chmod 0600 "$PROXY_PROFILE"
    printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "%s";\n' "${proxy_url//"/\\"}" "${proxy_url//"/\\"}" > "$PROXY_APT_CONF"
    chmod 0600 "$PROXY_APT_CONF"
}

restore_client_proxy_files() {
    [[ -d "$CLIENT_BACKUP" ]] || return 0
    local index path
    local -a paths=("$PROXY_ENV_FILE" "$PROXY_APT_CONF" "$PROXY_PROFILE")
    for index in 0 1 2; do
        path=${paths[$index]}
        if [[ -e "$CLIENT_BACKUP/file.$index" ]]; then rm -f -- "$path"; cp -a -- "$CLIENT_BACKUP/file.$index" "$path"
        else rm -f -- "$path"; fi
    done
    rm -rf -- "$CLIENT_BACKUP"
}

test_http_proxy() {
    local proxy_url="$1"
    curl --fail --silent --show-error --location --proxy "$proxy_url" --connect-timeout 10 --max-time 30 https://api.ipify.org >/dev/null
}

url_with_credentials() {
    URL_SCHEME="$1" URL_HOST="$2" URL_PORT="$3" URL_USER="$4" URL_PASS="$5" "$PYTHON_BIN" <<'PY'
import os,urllib.parse
q=lambda s: urllib.parse.quote(s,safe='')
print(f"{os.environ['URL_SCHEME']}://{q(os.environ['URL_USER'])}:{q(os.environ['URL_PASS'])}@{os.environ['URL_HOST']}:{os.environ['URL_PORT']}")
PY
}

manage_ufw_add() {
    local cidr="$1" port="$2"
    UFW_RULE_CREATED=0
    if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
        if ufw status | awk -v cidr="$cidr" -v port="$port/tcp" 'index($0,cidr) && index($0,port) {found=1} END {exit !found}'; then
            print_step 'Подходящее UFW-правило уже существует; оно не будет принадлежать сессии'
        else
            ufw allow from "$cidr" to any port "$port" proto tcp comment 'server-scripts temporary proxy'
            UFW_RULE_CREATED=1
        fi
    else
        print_error 'UFW не активен: сервис защищён паролем, но доступен со всех маршрутизируемых адресов'
    fi
}

manage_ufw_delete() {
    local cidr="$1" port="$2" created="$3"
    [[ "$created" == 1 ]] || return 0
    ufw --force delete allow from "$cidr" to any port "$port" proto tcp >/dev/null 2>&1 || true
}

ssh_service_name() {
    if systemctl cat ssh.service >/dev/null 2>&1; then printf '%s\n' ssh.service
    elif systemctl cat sshd.service >/dev/null 2>&1; then printf '%s\n' sshd.service
    else return 1
    fi
}

validate_ssh_user() {
    validate_username "$1" && getent passwd "$1" >/dev/null
}

validate_username() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

sshd_effective_value() {
    local user="$1" address="$2" host="$3" key="$4"
    address=$(cidr_probe_address "$address") || return 1
    sshd -T -C "user=$user,addr=$address,host=$host" 2>/dev/null | awk -v wanted="$key" '$1==wanted && !found {print $2; found=1}'
}

cidr_probe_address() {
    CIDR_PROBE_VALUE="$1" "$PYTHON_BIN" <<'PY'
import ipaddress, os
value=os.environ['CIDR_PROBE_VALUE']
if '/' not in value:
    print(ipaddress.ip_address(value)); raise SystemExit
network=ipaddress.ip_network(value, strict=False)
if network.num_addresses > 2: print(network.network_address + 1)
else: print(network.network_address)
PY
}

sshd_forwarding_allowed() {
    local user="$1" address="$2" host="$3" allow disable
    allow=$(sshd_effective_value "$user" "$address" "$host" allowtcpforwarding)
    disable=$(sshd_effective_value "$user" "$address" "$host" disableforwarding)
    [[ "$allow" =~ ^(yes|all|local)$ && "$disable" == no ]]
}

reload_sshd_checked() {
    local service
    sshd -t -f "$SSHD_CONFIG"
    service=$(ssh_service_name) || { print_error 'Не найден systemd-сервис OpenSSH'; return 1; }
    systemctl reload "$service"
    systemctl is-active --quiet "$service"
}

enable_temporary_ssh_forwarding() {
    local user="$1" address="$2" host="$3" backup_created=0 temp
    SSHD_CHANGED=0
    sshd_forwarding_allowed "$user" "$address" "$host" && return 0
    [[ -f "$SSHD_CONFIG" && ! -L "$SSHD_CONFIG" ]] || { print_error 'Основной sshd_config не найден или является ссылкой'; return 1; }
    install -d -m 0755 -- "$(dirname -- "$SSHD_DROPIN")"

    # Ubuntu normally includes this directory near the beginning. If an older
    # config does not, prepend one line and retain an exact root-only backup.
    if ! awk 'tolower($1)=="include" && $2 ~ /sshd_config\.d\/\*\.conf/ {found=1} END {exit !found}' "$SSHD_CONFIG"; then
        cp -a -- "$SSHD_CONFIG" "$SSHD_BACKUP"
        chmod 0600 "$SSHD_BACKUP"
        temp=$(mktemp "$(dirname -- "$SSHD_CONFIG")/.sshd_config.proxy.XXXXXX")
        printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > "$temp"
        cat -- "$SSHD_CONFIG" >> "$temp"
        chmod --reference="$SSHD_CONFIG" "$temp"
        chown --reference="$SSHD_CONFIG" "$temp"
        mv -f -- "$temp" "$SSHD_CONFIG"
        backup_created=1
    fi

    temp=$(mktemp "$(dirname -- "$SSHD_DROPIN")/.proxy-forwarding.XXXXXX")
    cat > "$temp" <<EOF
# Temporary rule owned by Server_scripts setup_proxy.sh
Match User $user Address $address
    DisableForwarding no
    AllowTcpForwarding local
    PermitOpen any
Match all
EOF
    chmod 0644 "$temp"; mv -f -- "$temp" "$SSHD_DROPIN"
    if ! reload_sshd_checked || ! sshd_forwarding_allowed "$user" "$address" "$host"; then
        rm -f -- "$SSHD_DROPIN"
        if (( backup_created )); then cp -a -- "$SSHD_BACKUP" "$SSHD_CONFIG"; rm -f -- "$SSHD_BACKUP"; fi
        reload_sshd_checked || true
        print_error 'Не удалось безопасно разрешить SSH TCP-forwarding для выбранного пользователя'
        return 1
    fi
    SSHD_CHANGED=1
}

restore_temporary_ssh_forwarding() {
    local changed="${1:-0}"
    [[ "$changed" == 1 ]] || return 0
    rm -f -- "$SSHD_DROPIN"
    if [[ -f "$SSHD_BACKUP" && ! -L "$SSHD_BACKUP" ]]; then
        cp -a -- "$SSHD_BACKUP" "$SSHD_CONFIG"
        rm -f -- "$SSHD_BACKUP"
    fi
    reload_sshd_checked
}

create_expiry_units() {
    local session="$1" minutes="$2" script_path
    script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
    cat > "$EXPIRE_SERVICE" <<EOF
[Unit]
Description=Remove expired temporary proxy server

[Service]
Type=oneshot
ExecStart=/usr/bin/bash $script_path --server-remove $session
EOF
    cat > "$EXPIRE_TIMER" <<EOF
[Unit]
Description=Expire temporary proxy server session

[Timer]
OnActiveSec=${minutes}min
AccuracySec=1min
Unit=$(basename -- "$EXPIRE_SERVICE")

[Install]
WantedBy=timers.target
EOF
    systemd-analyze verify "$EXPIRE_SERVICE" "$EXPIRE_TIMER" >/dev/null
    systemctl daemon-reload
    systemctl enable --now "$(basename -- "$EXPIRE_TIMER")" >/dev/null
}

server_create() {
    local mode="$1" host="$2" port="$3" client_cidr="$4" ttl="$5" ssh_user="${6:-}"
    [[ "$mode" =~ ^(http|socks5|ssh-socks)$ ]] || return 2
    validate_host "$host"; valid_port "$port"; validate_ipv4_cidr "$client_cidr"; [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl >= 10 && ttl <= 1440 )) || return 2
    [[ ! -e "$SERVER_STATE" ]] || { print_error 'Серверная сессия уже существует; сначала удалите её'; return 1; }
    install -d -m 0700 -- "$STATE_ROOT"
    local session username password expires bundle
    session=$(create_session_id)
    expires=$(date --date="+$ttl minutes" --iso-8601=seconds)
    if [[ "$mode" == ssh-socks ]]; then
        validate_ssh_user "$ssh_user" || { print_error 'Указанный SSH-пользователь не существует или имеет недопустимое имя'; return 2; }
        command -v sshd >/dev/null || { print_error 'OpenSSH server не установлен'; return 1; }
        ss -H -lnt "sport = :$port" | grep -q . || { print_error "SSH не слушает порт $port"; return 1; }
        enable_temporary_ssh_forwarding "$ssh_user" "$client_cidr" "$host"
        if ! save_state "$SERVER_STATE" ROLE server SESSION_ID "$session" MODE "$mode" HOST "$host" PORT "$port" SSH_USER "$ssh_user" CLIENT_CIDR "$client_cidr" SSHD_CHANGED "$SSHD_CHANGED" EXPIRES_AT "$expires"; then
            restore_temporary_ssh_forwarding "$SSHD_CHANGED" || true
            return 1
        fi
        if ! create_expiry_units "$session" "$ttl"; then server_remove "$session" || true; return 1; fi
        log INFO "Создана SSH SOCKS-сессия $session user=$ssh_user expires=$expires"
        print_success "SSH SOCKS разрешён для $ssh_user с $client_cidr до $expires"
        print_secret "${YELLOW}Данные подключения:${NC}\nХост: ${CYAN}${host}${NC}\nSSH-порт: ${CYAN}${port}${NC}\nПользователь: ${CYAN}${ssh_user}${NC}\nSession ID: ${CYAN}${session}${NC}"
        return 0
    fi
    install_xray_binary; ensure_proxy_user; install -d -o root -g "$PROXY_USER" -m 0750 -- "$CONFIG_ROOT"
    username="tmp_$(openssl rand -hex 4)"; password=$(random_secret)
    generate_server_config "$mode" "$port" "$username" "$password"
    chown root:"$PROXY_USER" "$SERVER_CONFIG"; chmod 0640 "$SERVER_CONFIG"
    "$XRAY_BIN" run -test -c "$SERVER_CONFIG" >/dev/null
    write_xray_unit "$SERVER_UNIT" "Temporary $mode proxy server" "$SERVER_CONFIG"
    manage_ufw_add "$client_cidr" "$port"
    if ! save_state "$SERVER_STATE" ROLE server SESSION_ID "$session" MODE "$mode" HOST "$host" PORT "$port" USERNAME "$username" PASSWORD "$password" CLIENT_CIDR "$client_cidr" UFW_RULE_CREATED "$UFW_RULE_CREATED" EXPIRES_AT "$expires"; then
        manage_ufw_delete "$client_cidr" "$port" "$UFW_RULE_CREATED"
        rm -f -- "$SERVER_UNIT" "$SERVER_CONFIG"
        return 1
    fi
    systemctl daemon-reload; systemctl enable --now "$(basename -- "$SERVER_UNIT")" >/dev/null
    if ! wait_for_listener "$(basename -- "$SERVER_UNIT")" "$port"; then
        server_remove "$session" || true; print_error 'Серверный proxy не запустился'; return 1
    fi
    if ! create_expiry_units "$session" "$ttl"; then
        server_remove "$session" || true
        print_error 'Не удалось создать таймер автоудаления; серверная сессия отменена'
        return 1
    fi
    bundle=$(encode_bundle "$mode" "$host" "$port" "$username" "$password" "$session" "$expires")
    log INFO "Создана серверная proxy-сессия $session mode=$mode port=$port expires=$expires"
    print_success "Временный $mode proxy запущен до $expires"
    print_secret "${YELLOW}Пакет подключения (не сохраняйте в логах):${NC}\n${CYAN}${bundle}${NC}"
}

server_remove() {
    local expected_session="${1:-}" current_session='' cidr='' port='' created=0 sshd_changed=0
    if load_state "$SERVER_STATE"; then
        current_session=${SESSION_ID:-}; cidr=${CLIENT_CIDR:-}; port=${PORT:-}; created=${UFW_RULE_CREATED:-0}; sshd_changed=${SSHD_CHANGED:-0}
        [[ -z "$expected_session" || "$expected_session" == "$current_session" ]] || { print_error 'Session ID не совпадает; удаление отменено'; return 1; }
    elif [[ -n "$expected_session" ]]; then return 0; fi
    systemctl disable --now "$(basename -- "$EXPIRE_TIMER")" >/dev/null 2>&1 || true
    systemctl disable --now "$(basename -- "$SERVER_UNIT")" >/dev/null 2>&1 || true
    [[ -n "$cidr" && -n "$port" ]] && manage_ufw_delete "$cidr" "$port" "$created"
    restore_temporary_ssh_forwarding "$sshd_changed"
    rm -f -- "$SERVER_UNIT" "$EXPIRE_SERVICE" "$EXPIRE_TIMER" "$SERVER_CONFIG" "$SERVER_STATE"
    rmdir -- "$CONFIG_ROOT" 2>/dev/null || true
    systemctl daemon-reload
    log INFO "Удалена серверная proxy-сессия ${current_session:-unknown}"
    print_success 'Серверная proxy-сессия удалена'
}

start_xray_client() {
    ensure_proxy_user; install -d -o root -g "$PROXY_USER" -m 0750 -- "$CONFIG_ROOT"
    chown root:"$PROXY_USER" "$CLIENT_CONFIG"; chmod 0640 "$CLIENT_CONFIG"
    "$XRAY_BIN" run -test -c "$CLIENT_CONFIG" >/dev/null
    write_xray_unit "$CLIENT_UNIT" 'Temporary proxy client' "$CLIENT_CONFIG"
    systemctl daemon-reload; systemctl enable --now "$(basename -- "$CLIENT_UNIT")" >/dev/null
    systemctl is-active --quiet "$(basename -- "$CLIENT_UNIT")"
}

client_connect_bundle() {
    local bundle="$1" local_port="${2:-10809}" proxy_url details
    [[ ! -e "$CLIENT_STATE" ]] || { print_error 'Клиентская сессия уже существует; сначала отключите её'; return 1; }
    decode_bundle "$bundle" || { print_error 'Пакет подключения повреждён или имеет неподдерживаемый формат'; return 1; }
    valid_port "$local_port" || return 2; install -d -m 0700 -- "$STATE_ROOT"
    if [[ "$BUNDLE_MODE" == http ]]; then
        proxy_url=$(url_with_credentials http "$BUNDLE_HOST" "$BUNDLE_PORT" "$BUNDLE_USER" "$BUNDLE_PASS")
        details="server-session=$BUNDLE_SESSION expires=$BUNDLE_EXPIRES"
    else
        install_xray_binary
        generate_socks_client_config "$BUNDLE_HOST" "$BUNDLE_PORT" "$BUNDLE_USER" "$BUNDLE_PASS" "$local_port"
        start_xray_client || { client_remove || true; return 1; }
        proxy_url="http://127.0.0.1:$local_port"; details="server-session=$BUNDLE_SESSION expires=$BUNDLE_EXPIRES"
    fi
    if ! test_http_proxy "$proxy_url"; then client_remove || true; print_error 'Проверка доступа через proxy не прошла'; return 1; fi
    apply_system_proxy "$proxy_url"
    save_state "$CLIENT_STATE" ROLE client SESSION_ID "$(create_session_id)" MODE "$BUNDLE_MODE" PROXY_URL "$proxy_url" DETAILS "$details" CONFIGURED_AT "$(date --iso-8601=seconds)"
    print_success "Клиент подключён через $BUNDLE_MODE"
    print_secret "Для текущего терминала: source $PROXY_PROFILE"
}

client_connect_vless() {
    local link="$1" local_port="${2:-10809}" proxy_url
    [[ ! -e "$CLIENT_STATE" ]] || { print_error 'Клиентская сессия уже существует; сначала отключите её'; return 1; }
    [[ "$link" == vless://* ]] || return 2
    parse_vless_link "$link"; validate_vless_params || { print_error 'VLESS-ссылка не прошла проверку'; return 1; }
    valid_port "$local_port"; install_xray_binary; install -d -m 0700 -- "$STATE_ROOT"
    generate_vless_client_config "$local_port"; start_xray_client || { client_remove || true; return 1; }
    proxy_url="http://127.0.0.1:$local_port"
    if ! test_http_proxy "$proxy_url"; then client_remove || true; print_error 'VLESS-клиент запущен, но доступ через него не подтверждён'; return 1; fi
    apply_system_proxy "$proxy_url"
    save_state "$CLIENT_STATE" ROLE client SESSION_ID "$(create_session_id)" MODE vless PROXY_URL "$proxy_url" DETAILS "$VLESS_REMARK" CONFIGURED_AT "$(date --iso-8601=seconds)"
    print_success 'VLESS-клиент подключён; серверная инфраструктура не изменялась'
    print_secret "Для текущего терминала: source $PROXY_PROFILE"
}

client_connect_http_url() {
    local proxy_url="$1"
    [[ ! -e "$CLIENT_STATE" ]] || { print_error 'Клиентская сессия уже существует'; return 1; }
    validate_proxy_url "$proxy_url" || return 2
    test_http_proxy "$proxy_url" || { print_error 'HTTP proxy не отвечает'; return 1; }
    apply_system_proxy "$proxy_url"
    save_state "$CLIENT_STATE" ROLE client SESSION_ID "$(create_session_id)" MODE http PROXY_URL "$proxy_url" DETAILS direct CONFIGURED_AT "$(date --iso-8601=seconds)"
}

client_remove() {
    systemctl disable --now "$(basename -- "$SSH_UNIT")" >/dev/null 2>&1 || true
    systemctl disable --now "$(basename -- "$CLIENT_UNIT")" >/dev/null 2>&1 || true
    rm -f -- "$SSH_UNIT" "$CLIENT_UNIT" "$CLIENT_CONFIG" "$STATE_ROOT/ssh_known_hosts"
    rmdir -- "$CONFIG_ROOT" 2>/dev/null || true
    systemctl daemon-reload
    restore_client_proxy_files || true
    rm -f -- "$CLIENT_STATE"
    log INFO 'Клиентская proxy-сессия удалена'
    print_success 'Клиентское подключение удалено, исходные proxy-файлы восстановлены'
    print_secret 'Для текущего терминала: unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY'
}

show_status() {
    print_header 'СОСТОЯНИЕ ВРЕМЕННОГО ДОСТУПА'
    if load_state "$SERVER_STATE"; then
        printf 'Сервер: mode=%s, session=%s, %s:%s, expires=%s\n' "${MODE:-?}" "${SESSION_ID:-?}" "${HOST:-?}" "${PORT:-?}" "${EXPIRES_AT:-?}"
        systemctl is-active "$(basename -- "$SERVER_UNIT")" 2>/dev/null || true
    else echo 'Серверная сессия: отсутствует'; fi
    if load_state "$CLIENT_STATE"; then
        printf 'Клиент: mode=%s, session=%s, proxy=%s\n' "${MODE:-?}" "${SESSION_ID:-?}" "${PROXY_URL:-?}"
        if [[ "${MODE:-}" == ssh-socks ]]; then systemctl is-active "$(basename -- "$SSH_UNIT")" 2>/dev/null || true
        elif [[ "${MODE:-}" =~ ^(socks5|vless)$ ]]; then systemctl is-active "$(basename -- "$CLIENT_UNIT")" 2>/dev/null || true
        fi
    else echo 'Клиентская сессия: отсутствует'; fi
}

interactive_server_create() {
    local mode host port cidr ttl ssh_user=''
    echo '1. HTTP proxy'; echo '2. SOCKS5 proxy'; echo '3. SSH SOCKS (временное разрешение forwarding)'; read -r -p 'Тип сервиса [1-3]: ' mode
    case "$mode" in 1) mode=http ;; 2) mode=socks5 ;; 3) mode=ssh-socks ;; *) print_error 'Неверный выбор'; return 1 ;; esac
    host=$(curl --fail --silent --show-error --connect-timeout 5 --max-time 15 https://api.ipify.org 2>/dev/null || true)
    read -r -p "Публичный IP/домен сервера [$host]: " input; host=${input:-$host}
    if [[ "$mode" == ssh-socks ]]; then
        port=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}'); port=${port:-22}
        read -r -p "SSH-порт [$port]: " input; port=${input:-$port}
        read -r -p "SSH-пользователь [${SUDO_USER:-root}]: " ssh_user; ssh_user=${ssh_user:-${SUDO_USER:-root}}
    else
        port=$(random_port); read -r -p "Порт [$port]: " input; port=${input:-$port}
    fi
    read -r -p 'Разрешённый IPv4/CIDR клиента (например 203.0.113.10/32): ' cidr
    read -r -p 'Время жизни в минутах [120]: ' ttl; ttl=${ttl:-120}
    server_create "$mode" "$host" "$port" "$cidr" "$ttl" "$ssh_user"
}

interactive_client_connect() {
    local choice value port host ssh_port ssh_user key_file socks_port
    echo '1. Пакет HTTP/SOCKS5'; echo '2. Готовая VLESS-ссылка (только клиент)'; echo '3. Готовый HTTP proxy URL'; echo '4. SSH SOCKS'
    read -r -p 'Тип подключения [1-4]: ' choice
    case "$choice" in
        1) read -r -p 'Вставьте пакет подключения: ' value; read -r -p 'Локальный HTTP порт [10809]: ' port; client_connect_bundle "$value" "${port:-10809}" ;;
        2) read -r -p 'Вставьте vless:// ссылку: ' value; read -r -p 'Локальный HTTP порт [10809]: ' port; client_connect_vless "$value" "${port:-10809}" ;;
        3) read -r -p 'HTTP proxy URL: ' value; client_connect_http_url "$value" ;;
        4)
            read -r -p 'SSH host/IP: ' host; read -r -p 'SSH-порт [22]: ' ssh_port; ssh_port=${ssh_port:-22}
            read -r -p 'SSH-пользователь [root]: ' ssh_user; ssh_user=${ssh_user:-root}
            read -r -p 'Абсолютный путь к приватному ключу: ' key_file
            read -r -p 'Локальный SOCKS5-порт [10808]: ' socks_port; socks_port=${socks_port:-10808}
            client_connect_ssh_socks "$host" "$ssh_port" "$ssh_user" "$key_file" "$socks_port"
            ;;
        *) print_error 'Неверный выбор' ;;
    esac
}

show_menu() {
    while true; do
        print_header "TEMPORARY PROXY MANAGER v$SCRIPT_VERSION"
        echo '1. Создать временный proxy-сервер'; echo '2. Подключить proxy-клиент'; echo '3. Показать состояние'
        echo '4. Удалить клиентское подключение'; echo '5. Удалить серверный сервис'; echo '6. Проверить текущий proxy'; echo '0. Выход'
        local choice proxy_url
        read -r -p 'Выберите действие [0-6]: ' choice
        case "$choice" in
            1) interactive_server_create ;;
            2) interactive_client_connect ;;
            3) show_status ;;
            4) client_remove ;;
            5) server_remove ;;
            6) if load_state "$CLIENT_STATE"; then proxy_url=${PROXY_URL:-}; if test_http_proxy "$proxy_url"; then print_success 'Proxy работает'; else print_error 'Proxy не отвечает'; fi; else print_error 'Клиент не настроен'; fi ;;
            0) return 0 ;;
            *) print_error 'Неверный выбор' ;;
        esac
        echo; read -r -p 'Нажмите Enter для продолжения...'
    done
}

usage() {
    cat <<'EOF'
Использование: setup_proxy.sh [--status|--server-remove [SESSION_ID]|--client-remove]
Без аргументов открывается интерактивное меню.
EOF
}

main() {
    check_root; validate_paths; ensure_packages
    install -d -m 0700 -- "$STATE_ROOT"; install -d -m 0750 -- "$(dirname -- "$LOG_FILE")"; touch "$LOG_FILE"; chmod 0600 "$LOG_FILE"
    case "${1:-}" in
        '') show_menu ;;
        --status) show_status ;;
        --server-remove) server_remove "${2:-}" ;;
        --client-remove) client_remove ;;
        -h|--help) usage ;;
        *) usage >&2; return 2 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
