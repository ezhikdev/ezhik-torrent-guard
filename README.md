# EzhikLB

**EzhikLB (Ezhik Load Balancer)** — лёгкая панель управления L4-балансировкой TCP- и UDP-трафика на Linux. Панель хранит профили, настройки и ревизии, а агенты на нодах применяют их через IPVS непосредственно в ядре Linux.

> Текущая версия: **0.1.0-alpha.7**. Проект активно разрабатывается. Перед установкой на рабочий шлюз обязательно проверьте нужные сценарии на тестовом VPS.

## Возможности

- балансировка TCP, UDP или обоих протоколов одновременно;
- несколько backend-серверов с настраиваемыми весами;
- планировщики IPVS `wrr` и `rr`;
- Affinity (IPVS persistence) с интервалами от 15 минут до 24 часов и своим значением;
- ICMP health-check с интервалом, таймаутом и порогами отключения/возврата;
- переиспользуемые профили и назначение одного профиля нескольким нодам;
- неизменяемые ревизии, просмотр истории и откат конфигурации;
- роли установки «Панель», «Нода» и «Панель + Нода»;
- отдельные учётные данные и ротация токена каждой удалённой ноды;
- статистика IPVS по соединениям, пакетам и трафику;
- обновление с сохранением конфигурации и базы данных;
- перенос конфигурации со старого `Ezhik UDP`, если она найдена установщиком.

## Как это работает

```text
Браузер → Панель EzhikLB → желаемая конфигурация
                           ↓
                       Агент ноды
                           ↓
                         IPVS
                           ↓
                 TCP/UDP backend-серверы
```

Панель не проксирует пользовательский трафик. После применения конфигурации пакеты обрабатываются IPVS в ядре Linux, поэтому userspace не выбирает backend для каждого нового соединения.

## Требования

- Debian или Ubuntu;
- архитектура `amd64`;
- права `root` или доступ к `sudo`;
- публичный либо маршрутизируемый IPv4 на ноде;
- для удалённых нод — доступ к URL панели;
- для рабочей удалённой установки — HTTPS на панели.

Установщик сам установит необходимые пакеты, подключит модули IPVS, применит sysctl-параметры и создаст службы systemd.

## Быстрая установка

Все команды установки ниже выполняются **одной строкой**. Версия закреплена намеренно: для другого релиза замените `0.1.0-alpha.7` во всей строке.

### Панель + локальная нода

Рекомендуемый вариант для первой тестовой установки:

```bash
ezhik_tmp=$(mktemp -d) && cd "$ezhik_tmp" && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && sha256sum -c ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && tar -xzf ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && sudo EZHIKLB_ROLE=panel-node ./install.sh
```

### Только панель

```bash
ezhik_tmp=$(mktemp -d) && cd "$ezhik_tmp" && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && sha256sum -c ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && tar -xzf ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && sudo EZHIKLB_ROLE=panel ./install.sh
```

### Только удалённая нода

Сначала создайте ноду в панели. Она один раз покажет `NODE_ID`, токен и готовую команду — лучше использовать именно её. Общий шаблон:

```bash
ezhik_tmp=$(mktemp -d) && cd "$ezhik_tmp" && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && sha256sum -c ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && tar -xzf ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && sudo EZHIKLB_ROLE=node EZHIKLB_PANEL_URL="https://panel.example.com" EZHIKLB_NODE_ID="NODE_ID" EZHIKLB_AGENT_TOKEN="AGENT_TOKEN" ./install.sh
```

Токен ноды является секретом. Не публикуйте его в issue, скриншотах и логах рабочего сервера. При утечке выполните ротацию токена в панели.

### Тестовая удалённая нода без HTTPS

Обычный HTTP допустим только на одноразовом тестовом VPS в изолированной или доверенной сети. Для такого теста к команде установки добавляется `EZHIKLB_ALLOW_INSECURE=1`:

```bash
sudo EZHIKLB_ROLE=node EZHIKLB_PANEL_URL="http://IP_ПАНЕЛИ:8080" EZHIKLB_NODE_ID="NODE_ID" EZHIKLB_AGENT_TOKEN="AGENT_TOKEN" EZHIKLB_ALLOW_INSECURE=1 ./install.sh
```

В рабочей установке удалённые ноды должны обращаться к панели по HTTPS: иначе токен и конфигурация передаются по сети без шифрования.

## Вход в панель

По умолчанию панель слушает только `127.0.0.1:8080` и не выставляется напрямую в интернет. Для первого входа создайте SSH-туннель **со своего компьютера**:

```bash
ssh -L 8080:127.0.0.1:8080 root@IP_СЕРВЕРА
```

Пока SSH-подключение открыто, перейдите в браузере на <http://127.0.0.1:8080>.

Посмотреть административный токен на сервере:

```bash
sudo sed -n 's/^EZHIKLB_ADMIN_TOKEN=//p' /etc/ezhiklb/ezhiklb.env
```

Для постоянного внешнего доступа установите перед панелью Caddy, Nginx или другой reverse proxy с действующим HTTPS-сертификатом. Не открывайте панель в интернет по обычному HTTP.

## Обновление без потери настроек

При обнаружении установленной версии скрипт сохраняет роль, конфигурацию, базу данных и токены. Перед заменой файлов он также создаёт резервную копию в `/var/backups/ezhiklb` и при ошибке пытается вернуть предыдущую версию.

Обновление до `alpha.7` одной строкой:

```bash
ezhik_tmp=$(mktemp -d) && cd "$ezhik_tmp" && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && curl -fLO https://github.com/ezhikdev/ezhiklb/releases/download/v0.1.0-alpha.7/ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && sha256sum -c ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz.sha256 && tar -xzf ezhiklb_0.1.0-alpha.7_linux_amd64.tar.gz && sudo ./install.sh
```

Для автоматического подтверждения обновления можно добавить `EZHIKLB_YES=1` перед `./install.sh`.

## Первая настройка

1. Откройте раздел профилей и создайте либо отредактируйте профиль.
2. Добавьте запись, укажите входной адрес и порт.
3. Выберите TCP, UDP или оба протокола.
4. Добавьте один или несколько выходов в формате `IP:порт`.
5. Укажите веса backend-серверов. При весах `1` и `1` трафик распределяется примерно поровну, при `2` и `1` — примерно как `66%` и `33%`.
6. При необходимости включите Affinity и ICMP health-check.
7. Сохраните запись и опубликуйте новую ревизию профиля.
8. Назначьте профиль нужным нодам и дождитесь статуса «Применено».

## Affinity

Affinity закрепляет IP клиента за выбранным backend на заданное время. Это особенно важно для VPN и других stateful UDP-сервисов: после паузы трафик возвращается на тот же сервер, а сессия не ломается из-за выбора другого backend.

| Сценарий | Начальное значение |
| --- | ---: |
| Короткий UDP-трафик | 15–30 минут |
| VPN и продолжительные сессии | 1–5 часов |
| Строго постоянный backend | до 24 часов |

Для VPN разумная начальная настройка — **3 часа (10800 секунд)**. Записи Affinity хранятся ядром и обычно не дают заметной нагрузки даже при тысячах клиентов. Однако при CGNAT один общий публичный IP может закрепить за одним backend сразу группу пользователей.

## ICMP health-check

Health-check периодически отправляет ICMP-запросы на IP backend-серверов. После заданного количества неудачных проверок сервер исключается из выдачи, а после серии успешных — возвращается.

Успешный ICMP подтверждает доступность хоста, но не гарантирует работу конкретного TCP- или UDP-порта. Если backend блокирует ping, разрешите ICMP в firewall либо отключите health-check для такого сценария.

## Полезные команды

Выполняйте команды только для установленных на сервере компонентов.

### Версия и состояние служб

```bash
sudo cat /etc/ezhiklb/version
```

```bash
sudo systemctl status ezhiklb ezhiklb-agent --no-pager -l
```

```bash
sudo systemctl restart ezhiklb ezhiklb-agent
```

### Логи

Последние 100 строк:

```bash
sudo journalctl -u ezhiklb -u ezhiklb-agent -n 100 --no-pager -l
```

Логи в реальном времени:

```bash
sudo journalctl -u ezhiklb -u ezhiklb-agent -f
```

### Проверка панели и агента

```bash
curl -fsS http://127.0.0.1:8080/healthz && echo
```

```bash
sudo cat /var/lib/ezhiklb-agent/state.json
```

### Проверка IPVS

Текущая конфигурация:

```bash
sudo ipvsadm -Ln
```

Счётчики пакетов и трафика:

```bash
sudo ipvsadm -Ln --stats
```

Активные соединения:

```bash
sudo ipvsadm -Lnc
```

Таймауты IPVS:

```bash
sudo ipvsadm -Ln --timeout
```

### Сеть и NAT

```bash
sudo conntrack -L -p udp 2>/dev/null | head -n 50
```

```bash
sudo iptables -t nat -S | grep -E 'EZHIK|IPVS|MASQUERADE'
```

## Резервная копия

Создать ручной архив настроек и состояния одной строкой:

```bash
sudo tar -czf "/root/ezhiklb-backup-$(date +%Y%m%d-%H%M%S).tar.gz" /etc/ezhiklb /var/lib/ezhiklb /var/lib/ezhiklb-agent
```

Основные пути:

| Путь | Назначение |
| --- | --- |
| `/opt/ezhiklb` | бинарные файлы |
| `/usr/share/ezhiklb/web` | собранная web-панель |
| `/etc/ezhiklb` | конфигурация и переменные окружения |
| `/var/lib/ezhiklb` | база данных панели |
| `/var/lib/ezhiklb-agent` | применённое состояние агента |
| `/var/backups/ezhiklb` | резервные копии установщика |
| `/etc/systemd/system/ezhiklb.service` | служба панели |
| `/etc/systemd/system/ezhiklb-agent.service` | служба агента |

## Если конфигурация не применяется

Проверьте по порядку:

```bash
sudo systemctl status ezhiklb ezhiklb-agent --no-pager -l
```

```bash
sudo journalctl -u ezhiklb-agent -n 200 --no-pager -l
```

```bash
sudo cat /var/lib/ezhiklb-agent/state.json
```

```bash
sudo ipvsadm -Ln && sudo ipvsadm -Ln --stats
```

На удалённой ноде дополнительно проверьте доступность URL панели, правильность `NODE_ID`, токена и HTTPS-сертификата. Перед публикацией диагностического вывода удалите из него секреты.

## Остановка и повторный запуск

Временно остановить компоненты без удаления данных:

```bash
sudo systemctl disable --now ezhiklb ezhiklb-agent
```

Запустить снова:

```bash
sudo systemctl enable --now ezhiklb ezhiklb-agent
```

## Выпуск релиза

GitHub Actions устанавливает зависимости, запускает Go-тесты, собирает web-интерфейс и два Linux-бинарника, создаёт архив `amd64`, checksum и GitHub Release при отправке тега вида `v*`.

После отправки изменений в `main` релиз `alpha.7` запускается одной строкой:

```bash
git tag v0.1.0-alpha.7 && git push origin main --tags
```

## Структура репозитория

| Каталог | Назначение |
| --- | --- |
| `cmd/ezhiklb` | панель и API |
| `cmd/ezhiklb-agent` | привилегированный агент ноды |
| `internal/domain` | модель конфигурации и валидация |
| `internal/store` | SQLite, профили и ревизии |
| `internal/api` | HTTP API и аутентификация |
| `internal/agent` | применение IPVS, firewall и health-check |
| `web` | панель на React и TypeScript |
| `scripts` | установщик и системная интеграция |
| `.github/workflows` | тестирование и сборка релизов |
| `docs` | архитектура, план и сценарии тестирования |

## Статус проекта

`alpha.7` предназначена для тестирования панели, локальной ноды и первых удалённых нод. Условия перехода к beta-версии перечислены в [`docs/ROADMAP.md`](docs/ROADMAP.md), а рекомендуемый порядок проверки релиза — в [`docs/TESTING.md`](docs/TESTING.md).

При создании issue приложите версию, роль установки, состояние systemd, журнал агента и вывод `ipvsadm`, предварительно удалив токены и другие секреты.

## Лицензия

Лицензия проекта пока не выбрана. До появления файла `LICENSE` условия использования и распространения необходимо согласовывать с владельцем репозитория.
