# 🦔 Ezhik Torrent Guard

Автоматическая защита Xray / Remnawave exit-нод от BitTorrent abuse и
исходящего сканирования портов.

```text
Developer : ezhikdev
Telegram  : @ezhikdev
GitHub    : https://github.com/ezhikdev
Version   : 1.2.3
```

Guard связывает сетевое нарушение с точным числовым ID авторизованного клиента
Xray и применяет санкцию только к его подписке через Remnawave API. Общий
ingress-IP пользователя для блокировки не используется.

## Возможности

- обнаружение BitTorrent через Suricata 8.0.6 и strict nDPI 4.14;
- точная корреляция `Xray request → client ID → outbound socket → nDPI alert`;
- обнаружение TCP/UDP-сканирования публичных IPv4-адресов;
- учёт обращений к закрытым портам по access-событиям Xray;
- независимые режимы наблюдения и блокировки для Torrent Guard и Port Guard;
- временное отключение клиента с автоматическим восстановлением;
- бессрочное отключение с последующей ручной разблокировкой в Remnawave Panel;
- список клиентов, которых Guard никогда не отключает;
- русскоязычные Telegram-уведомления и текстовые отчёты об инцидентах;
- обработка сетевой метаинформации в RAM без записи PCAP и payload на диск;
- готовые runtime-пакеты для Ubuntu 22.04 и 24.04 без компиляции на сервере.

> Текущая версия детекторов работает с IPv4. Подробнее об ограничениях — в
> разделе [Ограничения](#ограничения).

## Как работает защита

### BitTorrent

```text
Xray / RemnaNode
       │ authenticated request
       ├───────────────┐
       │               │
       │        outbound socket
       │               │
       └──── exact attribution ──── Suricata + strict nDPI
                                      │
                               BitTorrent alert
                                      │
                               Remnawave API
```

Санкция создаётся только после однозначного сопоставления strict-nDPI alert с
реальным outbound-сокетом Xray и ID клиента.

### Сканирование портов

Port Guard анализирует уже существующие access-события Xray. Для каждого
клиента в RAM поддерживаются отдельные скользящие окна. Попытка учитывается
сразу после принятия запроса Xray, поэтому удалённый порт не обязан быть открыт.

Триггеры по умолчанию:

- `20` разных портов одного IP за `60` секунд;
- `16` адресов одной `/24`, `50` разных портов и `100` уникальных назначений
  внутри этой подсети за `60` секунд.

Повтор одного назначения не увеличивает счётчик. Обычное большое количество
HTTPS/QUIC-соединений только к порту `443` не достигает порога разнообразия
портов. После события действует cooldown `300` секунд для подавления повторных
уведомлений по тому же клиенту.

Случайный fan-out по множеству несвязанных IP не считается сканированием сам по
себе: такой профиль характерен для BitTorrent peer/DHT traffic и без анализа
протокола неоднозначен. Его классифицирует отдельный strict nDPI Torrent Guard.

Режимы Port Guard:

| Режим | Обнаружение | Отчёт и Telegram | Блокировка клиента |
|---|---:|---:|---:|
| `OBSERVE` | Да | Да | Нет |
| `LIVE` | Да | Да | Да |
| `DISABLED` | Нет | Нет | Нет |

При бессрочной санкции Guard подтверждает `DISABLED` через Remnawave API и
забывает локальную санкцию. Администратор может затем вручную включить клиента
в Remnawave Panel без доступа к ноде.

Подробное техническое описание:
[`docs/HOSTER_PORT_SCAN_PROTECTION_RU.md`](docs/HOSTER_PORT_SCAN_PROTECTION_RU.md).

## Требования

- Ubuntu 22.04 или 24.04;
- x86_64 / amd64;
- установленный и работающий Docker;
- RemnaNode container, обычно `remnanode`;
- Remnawave Panel API key;
- Xray access/info logs в RAM.

Для неподдерживаемой версии Ubuntu или при отсутствии release-runtime installer
может перейти к сборке Suricata и nDPI из исходников.

## Настройка Xray

В профиле Xray, используемом RemnaNode, должны быть включены оба журнала:

```json
"log": {
  "access": "/dev/shm/xray-access.log",
  "error": "/dev/shm/xray-info.log",
  "loglevel": "info"
}
```

Без `access` и `info` Guard не сможет надёжно связать сетевое событие с
пользователем. Подробности: [`docs/XRAY_LOGGING.md`](docs/XRAY_LOGGING.md).

## Установка и обновление

Запускать от `root`:

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/install.sh | bash
```

Installer запросит:

1. адрес Remnawave Panel и API key;
2. защищённые numeric client IDs;
3. длительность Torrent freeze;
4. режим Torrent Guard `DRY RUN` или `LIVE`;
5. включение Port Guard;
6. длительность port-scan блокировки (`0` — бессрочно);
7. режим Port Guard `OBSERVE` или `LIVE`;
8. необязательные Telegram bot token и numeric chat ID администратора.

Повторный запуск той же команды обновляет установленную версию и сохраняет
текущие настройки. Если версия уже актуальна, installer может выполнить repair
или reconfiguration.

## Проверка работы

Статус компонентов:

```bash
systemctl status ezhik-suricata --no-pager
systemctl status ezhik-torrent-guard --no-pager
systemctl status ezhik-ram-log-guard --no-pager
```

Журнал Guard в реальном времени:

```bash
journalctl -fu ezhik-torrent-guard
```

Последние события обнаружения и действий:

```bash
journalctl -u ezhik-torrent-guard --since "1 hour ago" --no-pager | \
  grep -E "BT EXACT|SCAN DETECTED|WOULD_|ACTION QUEUED|FROZEN|BLOCKED|UNFROZEN|TELEGRAM"
```

Текущая конфигурация Port Guard:

```bash
grep -E '^EZHIK_SCAN_(ENABLED|DRY_RUN|BLOCK_SECONDS|WINDOW_SECONDS|VERTICAL_PORTS|SUBNET_(HOSTS|PORTS|ENDPOINTS)|COOLDOWN_SECONDS)=' \
  /etc/ezhik-torrent-guard/settings.env
```

Примеры событий:

```text
[BT EXACT] client=12345 sockets=1 ...
[FROZEN] client=12345 duration=15m reason=bittorrent ...
[SCAN DETECTED] client=12345 reason=vertical-port-scan action=WOULD_BLOCK ...
[BLOCKED] client=12345 duration=permanent manual_unblock=remnawave-panel
```

## Аварийное управление Port Guard

Настройки находятся в:

```text
/etc/ezhik-torrent-guard/settings.env
```

Команды ниже меняют только детектор сканирования. Torrent Guard продолжит
работать в своём текущем режиме.

### Срочно перевести Port Guard в OBSERVE

Обнаружение и уведомления продолжатся, но новые блокировки за сканирование
применяться не будут:

```bash
sed -i \
  -e 's/^EZHIK_SCAN_ENABLED=.*/EZHIK_SCAN_ENABLED=1/' \
  -e 's/^EZHIK_SCAN_DRY_RUN=.*/EZHIK_SCAN_DRY_RUN=1/' \
  /etc/ezhik-torrent-guard/settings.env
chmod 600 /etc/ezhik-torrent-guard/settings.env
systemctl restart ezhik-torrent-guard
```

Проверка:

```bash
journalctl -u ezhik-torrent-guard -n 30 --no-pager
```

В заголовке запуска должно быть:

```text
Port-scan protection: OBSERVE
```

### Полностью отключить только Port Guard

Torrent detection и его санкции останутся активны:

```bash
sed -i 's/^EZHIK_SCAN_ENABLED=.*/EZHIK_SCAN_ENABLED=0/' \
  /etc/ezhik-torrent-guard/settings.env
chmod 600 /etc/ezhik-torrent-guard/settings.env
systemctl restart ezhik-torrent-guard
```

В журнале должно быть:

```text
Port-scan protection: DISABLED
```

### Вернуть Port Guard в LIVE

```bash
sed -i \
  -e 's/^EZHIK_SCAN_ENABLED=.*/EZHIK_SCAN_ENABLED=1/' \
  -e 's/^EZHIK_SCAN_DRY_RUN=.*/EZHIK_SCAN_DRY_RUN=0/' \
  /etc/ezhik-torrent-guard/settings.env
chmod 600 /etc/ezhik-torrent-guard/settings.env
systemctl restart ezhik-torrent-guard
```

В журнале должно быть:

```text
Port-scan protection: LIVE REMNAWAVE
```

### Экстренно остановить весь Guard

Останавливает и Torrent Guard, и Port Guard. Xray/RemnaNode продолжает работать:

```bash
systemctl stop ezhik-torrent-guard
```

Вернуть защиту:

```bash
systemctl start ezhik-torrent-guard
```

> Остановка сервиса или перевод в `OBSERVE` не разблокирует клиентов, санкции к
> которым уже были применены. Временные санкции продолжат обработку после
> запуска Guard; бессрочно отключённого клиента можно включить вручную в
> Remnawave Panel.

## Защищённые клиенты

Во время установки можно указать numeric client IDs, которые Guard никогда не
будет отключать:

```text
123,456,789
```

Чтобы временно запретить автоматический unfreeze конкретного клиента:

```bash
echo 12345 >> /etc/ezhik-torrent-guard/hold.txt
```

## Файлы и журналы

```text
/opt/ezhik-torrent-guard/                    приложение
/etc/ezhik-torrent-guard/settings.env        рабочие настройки
/etc/ezhik-torrent-guard/api.env             Remnawave API credentials
/etc/ezhik-torrent-guard/telegram.env        Telegram credentials
/etc/ezhik-torrent-guard/hold.txt            запрет auto-unfreeze
/var/lib/ezhik-torrent-guard/                 sanction state и incident reports
/var/log/ezhik-torrent-guard-install.log      журнал установки
```

Файлы с credentials создаются с правами `0600` и не входят в репозиторий.

## Приватность и безопасность

- Xray access/info и Suricata fast log находятся в `/dev/shm`;
- EVE и PCAP logging отключены;
- packet payload в incident report не сохраняется;
- raw connection metadata очищается из RAM по TTL;
- хранится не более 100 port-scan отчётов с правами `0600`;
- Telegram token не передаётся через systemd `EnvironmentFile` и не выводится
  в журнал;
- перед санкцией проверяются numeric ID, UUID и текущий статус клиента;
- Guard не добавляет правила `iptables` и не использует inline `NFQUEUE`.

## Удаление

Обычное удаление с сохранением конфигурации и sanction state:

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/uninstall.sh | bash
```

Полное удаление:

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/uninstall.sh \
  -o /tmp/ezhik-tg-uninstall.sh
bash /tmp/ezhik-tg-uninstall.sh --purge
```

Uninstaller не продолжит обычное удаление при активной локальной санкции, чтобы
не оставить подписку отключённой навсегда. Принудительный `--force` следует
использовать только при осознанном ручном восстановлении.

## Ограничения

- анализируются публичные IPv4 TCP/UDP destinations;
- IPv6 и ICMP пока не анализируются;
- процессы, запущенные непосредственно на VPS, нельзя связать с клиентом
  Remnawave;
- трафик по отдельному маршруту в обход Xray не может быть атрибутирован VPN-ID;
- Port Guard является поведенческой, а не inline-защитой: первые запросы проходят
  до достижения порога;
- любой поведенческий детектор требует первоначальной проверки в `OBSERVE` на
  реальной нагрузке конкретной ноды.

Проект не гарантирует обнаружение всех будущих вариантов протоколов или полное
отсутствие ложных срабатываний. Перед включением `LIVE` рекомендуется проверить
обычный браузинг, видео, игры и контролируемый тест собственной инфраструктуры.
