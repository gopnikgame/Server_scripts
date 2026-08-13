# 🚀 Server Scripts Manager

![Launcher](https://img.shields.io/badge/launcher-v1.0.7-blue)
![Proxy](https://img.shields.io/badge/proxy--manager-v1.2.0-blueviolet)
![Updated](https://img.shields.io/badge/updated-2026--08--14-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange)

Модульный комплекс bash-скриптов для первоначальной настройки и оптимизации Ubuntu 24.04 серверов.  
Все модули загружаются автоматически с GitHub и запускаются через единое интерактивное меню.

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
| 2 | `setup_proxy.sh` | Настройка прокси (HTTP / SSH+Privoxy / VPN / VLESS) |
| 3 | `install_xanmod.sh` | Установка XanMod Kernel с BBR3 |
| 4 | `bbr_info.sh` | Проверка и настройка конфигурации BBR |
| 5 | `snapfile.sh` | Управление файлом подкачки (Swap) |
| 6 | `speed_dns.sh` | Тестирование DNS-серверов |
| 7 | `auto_update_vps.sh` | Автоматическое обновление VPS |

---

### 1 · Ubuntu Pre-Install

Первоначальная настройка сервера «с нуля»:

- Установка базовых пакетов
- **DNS**: DNSCrypt-proxy (DoH/DoT + DNSSEC)
- **UFW**: SSH-порт на выбор (22 или кастомный), 80, 443
- **SSH**: только ключевая аутентификация, таймаут 30 с, максимум 3 попытки
- Управление IPv6

---

### 2 · Proxy Manager

Настройка системного прокси для всех операций (`apt`, `curl`, `wget` и т.д.).  
Прокси прописывается в `/etc/environment`, `/etc/profile.d/proxy.sh` и `/etc/apt/apt.conf.d/99proxy`.

**Режимы:**

| Пункт меню | Режим | Схема |
|-----------|-------|-------|
| 1 | HTTP прокси | Прямое подключение к HTTP/HTTPS прокси |
| 2 | SSH + Privoxy | `ssh -D` (SOCKS5) → Privoxy → HTTP системный прокси |
| 3 | VPN системный прокси | HTTP прокси от работающего VPN-клиента (Clash, Mihomo...) |
| 4 | **Xray VLESS** | Вставить `vless://...` → Xray-core локально → HTTP `:10809` |
| 5 | **Диагностика** | Проверяет блокировки и рекомендует нужный режим |
| 6 | Обновить статус | Перечитать статус сервисов |
| 7 | Отключить прокси | Удалить все настройки, остановить сервисы |

**VLESS поддерживает:** REALITY+TCP, TLS+TCP/WS/gRPC, автоустановку `xray-core`.

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

- BBR (BBRv3 в загруженном XanMod) и `fq`;
- `tcp_mtu_probing=1` для обнаруженных MTU black holes;
- умеренный запас очередей новых подключений без уменьшения более высоких
  существующих значений;
- верхние границы TCP autotuning 8/16/32 МиБ в зависимости от RAM.

Профиль намеренно не меняет глобальные keepalive, TIME_WAIT, FIN timeout, ECN,
TCP Fast Open, busy polling и начальные буферы каждого сокета.

> **Требуется тестирование на живой системе.** Синтаксис и логика выбора
> проверяются автоматически, но установка ядра, загрузка, DKMS, работа Xray,
> сетевой профиль и откат должны быть проверены на тестовом VPS с доступной
> консолью провайдера до массового применения.

---

### 4 · BBR Monitor

Интерактивная диагностика без скрытого применения sysctl:

- текущее ядро, BBR и qdisc;
- MTU probing и очереди подключений;
- состояние Xray, сокетов и qdisc интерфейсов;
- переход в основное меню установки и настройки XanMod.

---

### 5 · Swap Manager

- Автоматический расчёт размера
- Создание / удаление swap
- Настройка `vm.swappiness`

---

### 6 · DNS Speed Test

- Сравнительный замер задержки резолверов
- Проверка DNS-утечек
- Трассировка маршрутов

---

### 7 · Auto Update VPS

- Расписание: еженедельно / ежемесячно
- Автоперезагрузка (опционально)
- Защита конфигурационных файлов
- Детальное логирование

---

## 🔥 Что делать, если что-то не устанавливается

Некоторые ресурсы (GitHub, `deb.xanmod.org`, Docker Hub) могут быть заблокированы.  
Запустите **встроенный диагностический мастер**: `setup_proxy.sh` → пункт **5 · Диагностика**.

### Логический маршрут

```
sudo ./server_launcher.sh
         │
         ▼
   Пункт 2 → setup_proxy.sh
         │
         ▼
   5) Диагностика
         │
         ├─ Нет интернета вообще? ──► ip route / ping 8.8.8.8 / resolvectl status
         │
         ├─ Всё доступно? ──────────► Прокси не нужен → см. "Типичные ошибки" ниже
         │
         └─ Ресурсы заблокированы?
                    │
                    ├─ Есть VLESS ссылка? ─────────► 4) Xray VLESS
                    │                                   вставить vless://... → готово
                    │
                    ├─ Есть SSH-сервер за рубежом? ─► 2) SSH + Privoxy
                    │                                   ssh-copy-id → ввести host/user
                    │
                    ├─ Работает VPN с HTTP прокси? ─► 3) VPN системный прокси
                    │                                   указать адрес (:7890, :10809...)
                    │
                    ├─ Есть HTTP прокси? ──────────► 1) HTTP прокси
                    │                                   указать адрес:порт
                    │
                    └─ Ничего нет?
                               │
                               ├─ Cloudflare WARP (бесплатно):
                               │    curl -fsSL https://pkg.cloudflareclient.com/install.sh | bash
                               │    warp-cli registration new
                               │    warp-cli mode proxy && warp-cli connect
                               │    → прокси: http://127.0.0.1:40001
                               │    → затем пункт 3) VPN системный прокси
                               │
                               └─ Арендовать VPS (€3–5/мес):
                                    DigitalOcean / Hetzner / Vultr / BuyVM
                                    → поднять Xray-server → получить VLESS ссылку
                                    → пункт 4) Xray VLESS
```

### Применение прокси к текущей SSH-сессии

```bash
source /etc/profile.d/proxy.sh
```

### Отключение прокси после установки

```bash
# Через меню: пункт 7) Отключить прокси

# Для текущей сессии вручную:
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
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
/usr/local/etc/xray/config.json               # Конфигурация Xray
/etc/server-scripts/proxy.conf                # Состояние прокси
/etc/profile.d/proxy.sh                       # Экспорт переменных прокси
/etc/apt/apt.conf.d/99proxy                   # APT прокси
/etc/systemd/system/ssh-tunnel-proxy.service  # SSH туннель (если настроен)
/var/log/server-scripts/                      # Логи launcher и модулей
/var/log/xray/                                # Логи Xray
/etc/auto_update_vps.conf                     # Конфигурация автообновления
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
- Открыты: выбранный SSH-порт, 80, 443

**DNS:**
- DNSCrypt-proxy: DoH + DoT + DNSSEC
- Кеширование, защита от DNS-утечек

**Прокси:**
- Все настройки изолированы, полностью удаляются через пункт «Отключить прокси»
- Оригинальный конфиг Privoxy сохраняется в `/etc/privoxy/config.orig`

---

## 📝 Логи

```bash
# Launcher
tail -f /var/log/server-scripts/server-scripts.log

# Proxy Manager
tail -f /var/log/server-scripts/setup_proxy.log

# Xray
tail -f /var/log/xray/error.log
journalctl -u xray -f

# SSH туннель
journalctl -u ssh-tunnel-proxy.service -f

# Автообновление
tail -f /var/log/auto_update_vps.log
```

---

## 🔄 Обновление

```bash
sudo server_launcher.sh
# → «Обновить все модули»  — перезагрузить модули с GitHub
# → «Обновить launcher»    — обновить сам менеджер
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
cat /etc/auto_update_vps.conf
```

---

## 📜 Лицензия

MIT License © 2025 [gopnikgame](https://github.com/gopnikgame)

## 🤝 Поддержка

[GitHub Issues](https://github.com/gopnikgame/Server_scripts/issues)

---

**Launcher:** v1.0.7 · **Proxy Manager:** v1.2.0 · **Дата:** 2026-08-14 · **Автор:** gopnikgame
