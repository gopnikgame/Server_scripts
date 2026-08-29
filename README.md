# 🚀 Server Scripts Manager

![Launcher](https://img.shields.io/badge/launcher-v2.0.2-blue)
![Proxy](https://img.shields.io/badge/proxy--manager-v2.0.0-blueviolet)
![Updated](https://img.shields.io/badge/updated-2026--08--29-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange)

Модульный комплекс bash-скриптов для первоначальной настройки и оптимизации Ubuntu 24.04 серверов.  
При каждом запуске launcher определяет свежий commit ветки `main`, загружает
сам launcher и все модули из единого snapshot, проверяет их через `bash -n`,
создаёт резервную копию и только после этого активирует комплект целиком.
Если `raw.githubusercontent.com` недоступен, весь комплект загружается одним
архивом через официальный `codeload.github.com` с тем же commit SHA. Перед
извлечением проверяются пути, типы файлов и наличие всех ожидаемых скриптов.

## ⚡ Быстрый старт

```bash
wget -qO server_launcher.sh https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh \
  && chmod +x server_launcher.sh && sudo ./server_launcher.sh
```

> **Заблокирован GitHub?** — сначала настройте прокси вручную, см. раздел [«Что делать, если что-то не устанавливается»](#-что-делать-если-что-то-не-устанавливается).

---

## 📦 Модули

| # | Модуль | Назначение |
|---|--------|-----------|
| 1 | `ubuntu_pre_install.sh` | Первоначальная настройка Ubuntu 24.04 |
| 2 | `setup_proxy.sh` | Временные proxy-серверы и подключения (HTTP / SOCKS5 / SSH SOCKS / VLESS-клиент) |
| 3 | `install_xanmod.sh` | Установка XanMod Kernel с BBR3 |
| 4 | `bbr_info.sh` | Проверка и настройка конфигурации BBR |
| 5 | `snapfile.sh` | Управление файлом подкачки (Swap) |
| 6 | `speed_dns.sh` | Тестирование DNS-серверов |
| 7 | `auto_update_vps.sh` | Автоматическое обновление VPS |

---

## 🧠 Навык Codex для серверных скриптов

В репозитории находится `.codex/skills/linux-server-script-engineer` —
repo-local навык для аудита, отладки, безопасной доработки и живого тестирования
Bash-инсталляторов, systemd, APT, сети, SSH и firewall. Он включает тематические
reference-файлы и read-only аудиторы с выводом `PASS/WARN/FAIL/SKIP`.

Быстрая локальная проверка навыка:

```bash
bash .codex/skills/linux-server-script-engineer/scripts/self-test.sh
bash .codex/skills/linux-server-script-engineer/scripts/audit-shell-project.sh .
```

Предупреждения аудитора являются поводом для ручной проверки, а не
автоматически подтверждёнными дефектами. Сам навык не изменяет сервер.

---

### 1 · Ubuntu Pre-Install

Первоначальная настройка сервера «с нуля»:

- Установка базовых пакетов
- **DNS**: DNSCrypt-proxy (DoH/DoT + DNSSEC)
- **UFW**: фактический порт текущего `sshd`, 443 и интерактивно выбранные порты
- **SSH**: только ключевая аутентификация, таймаут 30 с, максимум 3 попытки
- Смена пароля root через системный `passwd` без хранения пароля скриптом
- Транзакционное управление IPv6 с сохранением состояния после настройки сети

UFW настраивается транзакционно: исходный `/etc/ufw` копируется **до** сброса,
порт SSH определяется из `sshd -T`, адрес текущей SSH-сессии сохраняется в
разрешённом списке, а новые правила подтверждаются входом во второй сессии.
При отрицательном ответе или ошибке восстанавливается прежний firewall.

SSH настраивается отдельным drop-in-файлом, публичный ключ проверяется через
`ssh-keygen`, а конфигурация — через `sshd -t` до `systemctl reload ssh`.
Отключение парольного входа сохраняется только после успешного входа по ключу
во второй SSH-сессии; иначе выполняется откат.

IPv6 хранится в `/etc/sysctl.d/90-server-scripts-ipv6.conf`. Отдельный oneshot
unit повторно применяет состояние после `network-online.target`, поскольку
netplan/systemd-networkd может позднее включить link-local IPv6 на интерфейсе.
Старые строки `disable_ipv6` мигрируются из `/etc/sysctl.conf` только после
показа плана и с побайтно проверяемой резервной копией.

Проверено 2026-08-28 на Ubuntu 24.04.4 KVM: включение и отключение IPv6
пережили reboot, `eth0` и `lo` получили ожидаемое состояние, последовательный
откат восстановил исходный `/etc/sysctl.conf`, IPv6 и SSH. Смена пароля через
`passwd` проверена на временной учётной записи без изменения пароля root.
UFW и SSH ранее прошли отдельные live-тесты со второй SSH-сессией и откатом на
этой же VM с доступной консолью Proxmox.

---

### 2 · Proxy Manager

Один модуль используется с двух сторон: на доступном сервере он временно поднимает
сервис, а на машине с блокировкой подключает его как системный proxy для `apt`,
`curl`, `wget`, Git и других инструментов. Исходные proxy-файлы сохраняются и
восстанавливаются при отключении.

**Режимы:**

| Роль | Возможности |
|------|-------------|
| Сервер | Временный HTTP или SOCKS5 с логином/паролем, UFW-доступом только от выбранного CIDR и таймером удаления |
| Сервер SSH SOCKS | Проверка `sshd -T`; при необходимости временное разрешение local TCP-forwarding только выбранному SSH-пользователю и адресу |
| Клиент | Пакет подключения HTTP/SOCKS5, готовый HTTP URL, SSH SOCKS через `socks5h`, существующая `vless://` ссылка |
| Управление | Статус, проверка трафика, отдельное удаление клиентской и серверной сессий |

**VLESS поддерживается только на клиенте:** REALITY+TCP, TLS+TCP/WS/gRPC. Модуль
никогда не создаёт, не изменяет и не удаляет VLESS-серверы.

Версия `2.0.0` загружает официальный release-архив Xray
и соответствующий `.dgst`, проверяет SHA-256 и только затем устанавливает бинарный
файл. Новый конфиг сначала проходит `xray run -test`, предыдущий конфиг сохраняется
для rollback. VLESS UUID и реквизиты HTTP-прокси полностью показываются в
интерактивном терминале для копирования, но не записываются в общий лог; файлы с
реквизитами создаются с правами `0600`, Xray-конфиг — `0640`.

На Ubuntu 24.04 проверены ShellCheck, HTTP и SOCKS5 серверы, UFW rollback,
SSH-forwarding enable/rollback, SSH SOCKS с реальным HTTPS-запросом и удаление
временных systemd-сервисов. Конкретную VLESS-ссылку следует проверять отдельно,
так как серверная VLESS-инфраструктура намеренно находится вне управления модуля.

---

### 3 · XanMod Kernel для VLESS TCP

Интерактивный установщик XanMod и устойчивого сетевого профиля для серверов,
на которых Xray использует VLESS RAW/TCP с TLS или REALITY.

Меню позволяет без длинных команд:

1. Выполнить диагностику ОС, codename, psABI, памяти, `/boot`, загрузчика,
   Secure Boot и DKMS без изменения системы.
2. Настроить временный HTTP/HTTPS-прокси и установить доступный пакет XanMod.
3. Применить профиль `VLESS TCP Stable` после загрузки нового ядра.
4. Проверить XanMod, BBR, `fq`, Xray и состояние сокетов.
5. Откатить только сетевой профиль из резервной копии.
6. Показать план аварийной загрузки прежнего ядра без автоматического удаления
   пакетов.

Установщик получает список пакетов из APT, а не хранит номера веток ядра в
коде. Для сервера по умолчанию рекомендуется доступный LTS-пакет, совместимый
с psABI процессора. Старое ядро не удаляется, GRUB не устанавливается
принудительно, перезагрузка выполняется только после явного подтверждения.

Профиль `VLESS TCP Stable` включает:

- реализацию BBR, которую предоставляет текущее загруженное ядро, и `fq`;
- `tcp_mtu_probing=1` для обнаруженных MTU black holes;
- запас очередей новых подключений до 16384 без уменьшения более высоких
  существующих значений;
- расширенный диапазон локальных портов для исходящих соединений Xray;
- верхние границы TCP autotuning 8/16/32/64 МиБ в зависимости от RAM.

Профиль намеренно не меняет глобальные keepalive, TIME_WAIT, FIN timeout, ECN,
TCP Fast Open, busy polling и начальные буферы каждого сокета.
Обе точки входа используют `/etc/sysctl.d/90-server-scripts-vless-tcp.conf`;
старый `99-xanmod-vless-tcp.conf` мигрируется с резервной копией и может быть
восстановлен штатным откатом.

> **Требуется тестирование на живой системе.** Синтаксис и логика выбора
> проверяются автоматически, но установка ядра, загрузка, DKMS, работа Xray,
> сетевой профиль и откат должны быть проверены на тестовом VPS с доступной
> консолью провайдера до массового применения.

Проверено 2026-08-28 на тестовой KVM/Proxmox VM с Ubuntu 24.04.4 Noble,
x86-64-v2 и UEFI/GRUB: установка свежего XanMod LTS 6.18, повторные загрузки,
постоянство и транзакционный откат BBR + `fq`, сохранение Ubuntu-ядра и
реальная разовая аварийная загрузка `6.8.0-138-generic` прошли успешно.
Secure Boot был обнаружен диагностикой и отключён на одноразовом стенде до
установки; загрузка XanMod с включённым Secure Boot, DKMS и реальная
VLESS-нагрузка не проверялись.

---

### 4 · BBR Monitor

Интерактивная диагностика без скрытого применения sysctl:

- текущее ядро, BBR и qdisc;
- MTU probing и очереди подключений;
- состояние Xray, сокетов и qdisc интерфейсов;
- переход в основное меню установки и настройки XanMod.

---

### 5 · Swap Manager

- Интерактивное создание, включение, отключение, изменение размера и удаление swap-файла
- Атомарное обновление `/etc/fstab` без дублирования записей
- Резервная копия `fstab` перед каждой операцией и автоматический откат при ошибке
- Проверка типа файла, сигнатуры swap и запаса свободного места
- Проверка сохранения конфигурации после перезагрузки

---

### 6 · DNS Speed Test

- Интерактивные независимые проверки конфигурации, скорости, TCP/53, DNSSEC и маршрутов
- Стабильный порядок публичных резолверов и выбор лучшего полного результата
- Замер по `Query time` из `dig` на трёх доменах с явным количеством успешных запросов
- Сопоставление публичного IP сервера с адресом выхода системного рекурсивного резолвера
- DNSSEC-проверка с корректным доменом и доменом с намеренно повреждённой подписью
- Серверная диагностика не выдаётся за браузерный DNS leak test

---

### 7 · Auto Update VPS

- полностью интерактивное меню без обязательных ключей командной строки;
- предварительный план APT и отдельное подтверждение установки;
- обычное и расширенное обновление с запретом удаления пакетов;
- защита пакетов ядер XanMod/Ubuntu, GRUB, systemd, SSH, сети и Xray;
- снимок списка пакетов, удержаний, текущего ядра и `/boot` перед установкой;
- проверка `dpkg`, SSH, Xray, маршрута, DNS и failed units после установки;
- расписание systemd: ежедневное, еженедельное или ежемесячное;
- безопасный режим расписания по умолчанию только проверяет обновления.
- мастер миграции отключает старый cron и удаляет глобальный legacy-файл APT
  с `force-yes`, предварительно сохраняя их резервные копии.

`autoremove` доступен только как просмотр плана. Автоматические удаление ядер
и перезагрузка исключены; перезагрузка выполняется отдельным пунктом меню с
подтверждением. Журнал расписания хранится в journald.

Проверено 2026-08-28 на тестовой KVM/Proxmox VM с Ubuntu 24.04.4: preview и
установка 14 обновлений без удаления пакетов, пакетный snapshot, postflight,
повторная загрузка XanMod, systemd timer в режиме проверки, journal,
транзакционный rollback ошибочной конфигурации timer, legacy-миграция и
блокировка удаления Ubuntu-ядер в `autoremove` прошли успешно. Сохранение
активного Xray и плановая установка непустого набора обновлений через timer
на этом стенде не проверялись.

---

## 🔥 Что делать, если что-то не устанавливается

Некоторые ресурсы (GitHub, `deb.xanmod.org`, Docker Hub) могут быть заблокированы.  
Запустите `setup_proxy.sh` на доступном сервере и выберите создание временного
сервиса. На заблокированной машине запустите тот же модуль и выберите подключение.

### Логический маршрут

```
sudo ./server_launcher.sh
         │
         ▼
   Пункт 2 → setup_proxy.sh
         │
         ▼
   1) Создать временный proxy-сервер
         │
         ├─ Нет интернета вообще? ──► ip route / ping 8.8.8.8 / resolvectl status
         │
         ├─ Всё доступно? ──────────► Прокси не нужен → см. "Типичные ошибки" ниже
         │
         └─ Ресурсы заблокированы?
                    │
                    ├─ Доступный второй сервер? ───► HTTP или SOCKS5 server
                    │                                → скопировать пакет подключения
                    │
                    ├─ Есть SSH-доступ? ───────────► SSH SOCKS server
                    │                                → при запрете временно разрешит forwarding
                    │                                → на клиенте указать host/user/key
                    │
                    ├─ Есть VLESS ссылка? ─────────► Клиент → существующая vless://
                    │                                сервер VLESS не изменяется
                    │
                    └─ Есть готовый HTTP proxy? ───► Клиент → HTTP proxy URL
```

### Применение прокси к текущей SSH-сессии

```bash
source /etc/profile.d/server-scripts-proxy.sh
```

### Отключение прокси после установки

```bash
# Через меню: пункт 4) Удалить клиентское подключение

# Для текущей сессии вручную:
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY
```

### Типичные ошибки (не блокировки)

| Симптом | Команда |
|---------|---------|
| `E: Unable to fetch` | `apt-get clean && apt-get update` |
| `No space left on device` | `df -h` |
| `GPG error` | `ls /etc/apt/trusted.gpg.d/` |
| Неверный sources.list | `cat /etc/apt/sources.list.d/*.list` |

---

## 🗂️ Структура файловой системы

```
/root/server-scripts/                         # Launcher
/usr/local/server-scripts/modules/            # Загруженные модули
/var/lib/server-scripts/snapshot.env           # SHA и версия активного snapshot
/var/backups/server-scripts/launcher/          # Резервные копии обновлений launcher
/usr/local/etc/xray/config.json               # Конфигурация Xray
/etc/server-scripts/proxy.conf                # Состояние прокси
/etc/profile.d/proxy.sh                       # Экспорт переменных прокси
/etc/apt/apt.conf.d/99proxy                   # APT прокси
/etc/systemd/system/ssh-tunnel-proxy.service  # SSH туннель (если настроен)
/var/log/server-scripts/                      # Логи launcher и модулей
/var/log/xray/                                # Логи Xray
/etc/server-scripts-update.conf               # Конфигурация расписания обновлений
/etc/systemd/system/server-scripts-update.*   # Служба и таймер обновлений
```

---

## 📋 Требования

- Ubuntu 24.04 LTS
- Root-доступ
- Минимум 5 ГБ свободного места
- Интернет (или настроенный прокси)

---

## 🛡️ Безопасность

**SSH:**
- Только ключевая аутентификация (`PasswordAuthentication no`)
- `LoginGraceTime 30`, `MaxAuthTries 3`
- Кастомный порт (задаётся при установке)

**UFW:**
- `Deny incoming` / `Allow outgoing` по умолчанию
- Открыты: фактический порт SSH, 443 и выбранные в интерактивном меню порты

**DNS:**
- DNSCrypt-proxy: DoH + DoT + DNSSEC
- Кеширование, защита от DNS-утечек

**Прокси:**
- Модуль управляет только собственными `server-scripts-proxy-*` units и файлами
- HTTP/SOCKS5 ограничиваются выбранным client CIDR через UFW
- SSH forwarding разрешается только выбранным user/address и откатывается при удалении
- Исходные `/etc/environment`, APT и profile-файлы восстанавливаются из root-only backup

---

## 📝 Логи

```bash
# Launcher
tail -f /var/log/server-scripts/server-scripts.log

# Proxy Manager
tail -f /var/log/server-scripts/setup_proxy.log

# Временный Xray server/client
journalctl -u server-scripts-proxy-server.service -f
journalctl -u server-scripts-proxy-client.service -f
journalctl -u xray -f

# SSH туннель
journalctl -u ssh-tunnel-proxy.service -f

# Автообновление
journalctl -u server-scripts-update.service -f
```

---

## 🔄 Обновление

```bash
sudo server_launcher.sh
# → при старте проверяется весь snapshot launcher + модули
# → «Проверить и обновить весь snapshot» — повторить проверку вручную

sudo server_launcher.sh --status       # локальное состояние без сетевой проверки
sudo server_launcher.sh --refresh      # обновить snapshot и завершить работу
sudo server_launcher.sh --no-refresh   # открыть меню без автоматического обновления

# Аварийно установить конкретный опубликованный snapshot без discovery API:
sudo SERVER_SCRIPTS_COMMIT=<полный-SHA-40-символов> server_launcher.sh --refresh
```

---

## 🆘 Диагностика

```bash
# Сеть
ip route
ping 8.8.8.8

# DNS
resolvectl status

# BBR
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc

# Xray — тест конфига
xray -test -config /usr/local/etc/xray/config.json

# SSH туннель
journalctl -u ssh-tunnel-proxy.service -n 30

# Автообновление
cat /etc/server-scripts-update.conf
systemctl list-timers server-scripts-update.timer
```

---

## 📜 Лицензия

MIT License © 2025 [gopnikgame](https://github.com/gopnikgame)

## 🤝 Поддержка

[GitHub Issues](https://github.com/gopnikgame/Server_scripts/issues)

---

**Launcher:** v2.0.2 · **Proxy Manager:** v2.0.0 · **Дата:** 2026-08-29 · **Автор:** gopnikgame
