# Коллекция Серверных Скриптов

![Версия](https://img.shields.io/badge/версия-1.0.0-blue)
![Лицензия](https://img.shields.io/badge/лицензия-MIT-green)

Коллекция скриптов для оптимизации сервера, ориентированная на оптимизацию ядра Linux и мониторинг производительности сети, специально разработанная для систем Debian/Ubuntu с ядром XanMod и контролем перегрузки BBR3.

## 📚 Содержание

- [install_xanmod.sh](install_xanmod.sh) - Автоматическая установка ядра XanMod с оптимизацией BBR3
- [bbr_info.sh](bbr_info.sh) - Инструмент проверки и мониторинга конфигурации BBR

## 🚀 Возможности

### Скрипт установки ядра XanMod
- Автоматическая установка ядра XanMod с поддержкой BBR3
- Оптимизация под конкретный CPU (x64v1-v4)
- Поддержка различных вариантов ядра:
  - Стандартное
  - Edge (Новейшее)
  - RT (Реального времени)
  - LTS (Долгосрочной поддержки)
- Автоматическая настройка системы для оптимальной производительности сети
- Пост-установочная конфигурация BBR3

### Скрипт BBR Info
- Комплексная проверка конфигурации BBR
- Мониторинг состояний BBR в реальном времени
- Проверка настроек сетевых буферов
- Анализ активных соединений
- Автоматическое разрешение зависимостей
- Проверка совместимости системы

## 🔧 Требования

- Операционная система: Debian или Ubuntu
- Архитектура: x86_64
- Права суперпользователя (sudo)
- Минимум 2ГБ свободного места на диске
- Активное интернет-соединение

## 📥 Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/gopnikgame/Server_scripts.git
cd Server_scripts
```

2. Сделайте скрипты исполняемыми:
```bash
chmod +x install_xanmod.sh bbr_info.sh
```

## 🎮 Использование

### Установка ядра XanMod:
```bash
sudo ./install_xanmod.sh
```

### Проверка конфигурации BBR:
```bash
sudo ./bbr_info.sh
```

## 📋 Подробности функций

### Скрипт установки XanMod
- Автоматическое определение уровня оптимизации CPU
- Безопасная установка с возможностью отката
- Автоматическая настройка GRUB
- Оптимизированные сетевые настройки
- Завершение настройки после перезагрузки
- Подробное логирование

### Скрипт BBR Info
- Проверка версии BBR
- Проверка планировщика очереди
- Анализ сетевых буферов
- Мониторинг статуса ECN
- Отслеживание состояния активных соединений
- Автоматическое управление зависимостями

## 🔍 Пример вывода

```plaintext
[2025-02-17 05:06:03] - Проверка конфигурации BBR...
Текущий алгоритм управления перегрузкой: bbr
Версия BBR: 3
Планировщик очереди: fq_pie
Статус ECN: включен

Сетевые настройки:
-----------------
Размеры буферов:
- Чтение: 67108864
- Запись: 67108864
- Чтение по умолчанию: 1048576
- Запись по умолчанию: 1048576
```

## ⚙️ Параметры конфигурации

Скрипты автоматически настраивают следующие параметры:

### Оптимизация сети
- Контроль перегрузки TCP BBR3
- Дисциплина очереди FQ-PIE
- Оптимизированные размеры буферов
- ECN (Explicit Congestion Notification)
- TCP Fast Open
- Различные оптимизации TCP

### Настройки ядра
- Оптимизация для высокопроизводительных сетей
- Конфигурация с низкой задержкой
- Оптимизация управления памятью
- Настройка сетевого стека

## 🛟 Устранение неполадок

При возникновении проблем:

1. Проверьте логи:
   - Установка XanMod: `/var/log/xanmod_install.log`
   - Системные логи: `journalctl -xe`

2. Частые проблемы:
   - "Команда не найдена": Сначала запустите `check_dependencies`
   - "BBR не активен": Убедитесь в правильности установки ядра
   - "Неверная конфигурация": Проверьте настройки sysctl

## 📝 Лицензия

Этот проект лицензирован под MIT License - подробности см. в файле LICENSE.

## 👤 Автор

- **gopnikgame**
- Создано: 2025-02-17 05:06:03

## 🤝 Участие в разработке

Приветствуются вклады, сообщения о проблемах и запросы новых функций. Не стесняйтесь проверять страницу issues, если хотите внести свой вклад.

## 📮 Поддержка

Для получения поддержки создайте issue в репозитории GitHub или свяжитесь с автором.