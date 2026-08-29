# Server Scripts Manager

[Русский](README.md) · [English](README_EN.md)

Набор интерактивных Bash-модулей для первоначальной настройки и обслуживания серверов на Ubuntu 24.04 LTS. Launcher при каждом обычном запуске проверяет `main`, загружает launcher и модули одним согласованным snapshot, выполняет `bash -n` и активирует обновление целиком только после успешной проверки.

![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

## Быстрый запуск

Запускайте от `root`. Команды сначала сохраняют файл, а затем выполняют его — без `curl | bash`.

### curl

```bash
curl -fL --retry 3 -o server_launcher.sh \
  https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh \
  && bash server_launcher.sh
```

### wget

```bash
wget --https-only -O server_launcher.sh \
  https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh \
  && bash server_launcher.sh
```

[Скачать launcher напрямую](https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh)

> Если GitHub недоступен на целевом сервере, сначала используйте `setup_proxy.sh` через другой доступный сервер или существующее SSH/VLESS-подключение.

## Модули

| Модуль | Назначение |
|---|---|
| `ubuntu_pre_install.sh` | Стартовая настройка Ubuntu: пакеты, SSH, UFW, DNSCrypt, IPv6 |
| `setup_proxy.sh` | Временные HTTP/SOCKS5-серверы и клиенты HTTP, SOCKS5, SSH SOCKS, VLESS |
| `install_xanmod.sh` | XanMod LTS, проверка загрузки и TCP-профиль для VLESS/REALITY |
| `bbr_info.sh` | Диагностика BBR, qdisc, Xray и сетевых лимитов |
| `snapfile.sh` | Создание, изменение и удаление swap-файла |
| `speed_dns.sh` | Проверка скорости DNS, DNSSEC, TCP/53 и маршрутов |
| `auto_update_vps.sh` | Безопасное обновление APT и расписание через systemd timer |

## Proxy Manager

Один `setup_proxy.sh` используется в двух ролях:

- на доступном сервере временно поднимает HTTP/SOCKS5 либо разрешает SSH TCP-forwarding выбранному пользователю и CIDR;
- на заблокированной машине подключает выданный пакет, готовый HTTP proxy, SSH SOCKS или существующую `vless://` ссылку;
- при удалении убирает только собственные units, правила и конфиги, восстанавливая исходные proxy-файлы.

VLESS поддерживается только как клиент. Модуль не создаёт, не меняет и не удаляет VLESS-серверы. WireGuard намеренно не включён: необходимые сценарии уже покрывают HTTP, SOCKS5 и SSH SOCKS.

## Обновление launcher

```bash
server_launcher.sh --status       # локальное состояние snapshot
server_launcher.sh --refresh      # получить свежий snapshot main и выйти
server_launcher.sh --no-refresh   # открыть меню без сетевой проверки
```

Обычный запуск `server_launcher.sh` также проверяет обновления. При недоступности `raw.githubusercontent.com` launcher использует архив `codeload.github.com` того же commit SHA. Можно закрепить конкретный полный SHA:

```bash
SERVER_SCRIPTS_COMMIT=<40-символьный-SHA> server_launcher.sh --refresh
```

## Безопасность и откат

- Требуются Ubuntu 24.04 LTS, root-доступ и резервный консольный доступ для изменений SSH, UFW или ядра.
- SSH-конфигурация проверяется через `sshd -t`; UFW и системные файлы сохраняются до изменения.
- Xray загружается из официального release, сверяется по SHA-256 и проверяется до запуска.
- Proxy-секреты показываются только в интерактивном TTY и хранятся в файлах с ограниченными правами.
- Установка ядра не удаляет рабочее Ubuntu-ядро; перезагрузка выполняется отдельно и явно.

## Полезные команды

```bash
tail -f /var/log/server-scripts/server-scripts.log
tail -f /var/log/server-scripts/setup_proxy.log
journalctl -u server-scripts-proxy-server.service -f
journalctl -u server-scripts-proxy-client.service -f
journalctl -u server-scripts-update.service -f
```

## Проверка репозитория

```bash
bash .codex/skills/linux-server-script-engineer/scripts/self-test.sh
bash .codex/skills/linux-server-script-engineer/scripts/audit-shell-project.sh .
bash tests/test_setup_proxy.sh
```

Live-сценарии в `tests/live_test_*.sh` предназначены только для одноразовой Ubuntu VM с консолью и snapshot.

## Лицензия

[MIT](LICENSE) · [GitHub Issues](https://github.com/gopnikgame/Server_scripts/issues)
