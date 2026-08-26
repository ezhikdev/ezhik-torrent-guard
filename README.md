# 🦔 Ezhik Torrent Guard

> Автоматическая защита Xray / Remnawave exit-нод от BitTorrent abuse и исходящего сканирования портов.

```text
Developer : ezhikdev
Telegram  : @ezhikdev
GitHub    : https://github.com/ezhikdev
```

Ezhik Torrent Guard пассивно обнаруживает BitTorrent-трафик и аномальное сканирование портов на exit-сервере, связывает **реальный outbound socket Xray** с аутентифицированным пользователем Remnawave и отключает точную подписку через Remnawave API.

## Как это работает

```text
Client → Xray / RemnaNode → Internet
               │
               └── passive AF_PACKET copy
                           ↓
                  Suricata + strict nDPI
                           ↓
                       exact socket
                           ↓
                     Torrent Guard
                           ↓
                    Remnawave API
                           ↓
              freeze → 15 min → unfreeze
```

По умолчанию санкция срабатывает на **первом exact strict-nDPI BitTorrent socket**, который удалось однозначно связать с authenticated client ID Xray.

Guard **не банит source IP** и не использует общий IP ingress для определения пользователя.

## Особенности v1.2.0

- пассивный `AF_PACKET`, без inline/NFQUEUE;
- не добавляет правила `iptables`;
- outbound-only BPF-фильтр для уменьшения нагрузки;
- Suricata 8.0.6 + nDPI 4.14;
- strict BitTorrent heuristic для устранения известного ложного срабатывания на Roblox UDP;
- точная корреляция `Xray request-id → authenticated client → real outbound socket → nDPI alert`;
- freeze через Remnawave API и автоматический unfreeze;
- длительность freeze настраивается при установке;
- protected client IDs задаются при установке;
- минимальное persistent state хранит только информацию, необходимую для последующего unfreeze;
- raw connection metadata обрабатывается в RAM и автоматически очищается;
- Suricata EVE и PCAP logging отключаются;
- защита от накопления stale `tail` readers после restart Guard.
- RAM-only port-scan detector поверх уже атрибутированных Xray sockets;
- отдельные режимы port-scan `OBSERVE` и `LIVE`;
- временная или постоянная (`0` минут) блокировка за сканирование;
- постоянная блокировка забывается после подтверждённого disable и снимается вручную в Remnawave Panel;
- Telegram-уведомление с `.txt` incident report и ограниченная локальная ротация отчётов.

> **Ограничение v1.2.0:** детекторы настроены на IPv4. IPv6 — отдельная будущая задача.

## Защита от сканирования портов

Port-scan detector не запускает второй DPI и не анализирует payload. Он получает
только outbound sockets, которые `guard.py` уже однозначно связал с numeric
client ID Xray, и поддерживает ограниченные TTL-счётчики в RAM.

Триггеры по умолчанию:

- `20` разных портов одного IP за `60` секунд;
- `16` адресов одной `/24` и `50` разных портов за `60` секунд;
- `100` уникальных `IP:port` и `50` разных портов за `15` секунд.

Большое число HTTPS/QUIC-соединений только к `443` не достигает порога
разнообразия портов. После события для клиента действует cooldown `300` секунд,
чтобы один инцидент не создавал поток одинаковых уведомлений.

В `OBSERVE` Guard только пишет `[SCAN DETECTED]`, сохраняет incident report и
отправляет Telegram-уведомление. В `LIVE` он ставит disable в безопасную очередь
Remnawave. При длительности `0` после подтверждённого `DISABLED` локальное
состояние удаляется: последующая разблокировка выполняется вручную в панели.

## Оптимизация runtime

- reader отбрасывает ненужные Xray- и Suricata-строки до декодирования и очереди;
- разбор timestamp кэширует epoch текущей секунды;
- TTL-state удаляется через expiry queues без полного обхода всех живых socket ownership records;
- nDPI включает только `NDPI_PROTOCOL_BITTORRENT`, который используется единственным Suricata-правилом.

В `[STATS]` поля `filtered_info`, `filtered_access` и `dropped` показывают число строк, отфильтрованных до очереди, и событий, потерянных из-за переполнения очереди.

## Требования

Production-tested вариант рассчитан на:

- Ubuntu 22.04 / 24.04;
- x86_64 / amd64;
- установленный и работающий Docker;
- RemnaNode container (обычно `remnanode`);
- Remnawave Panel API key;
- Xray profile с RAM-only access/info logs.

На Ubuntu 22.04 и 24.04 установщик скачивает готовый проверенный runtime из GitHub Release. Поэтому на сервере пользователя не запускается тяжёлая компиляция Suricata и nDPI. Для другой версии Ubuntu или при отсутствии подходящего release-asset автоматически используется сборка из исходников.

Release-runtime собирается для универсального CPU baseline `x86-64`; host-specific `-march=native` принудительно отключён, поэтому пакет не зависит от модели процессора GitHub runner или пользовательского сервера.

Режим локальной сборки можно выбрать переменной окружения:

```bash
EZHIK_BUILD_MODE=eco bash install.sh       # 1 job, минимальная нагрузка
EZHIK_BUILD_MODE=balanced bash install.sh  # до 4 jobs, режим по умолчанию
EZHIK_BUILD_MODE=fast bash install.sh      # все доступные CPU
EZHIK_FORCE_SOURCE=1 bash install.sh       # принудительно собирать из исходников
```

## Обязательная настройка Xray

В профиле Xray, используемом RemnaNode, нужны:

```json
"log": {
  "access": "/dev/shm/xray-access.log",
  "error": "/dev/shm/xray-info.log",
  "loglevel": "info"
}
```

Без `access` + `info` Guard не сможет построить exact attribution пользователя.

Подробнее: [`docs/XRAY_LOGGING.md`](docs/XRAY_LOGGING.md).

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/install.sh | bash
```

Installer интерактивно спросит:

1. домен или URL Remnawave Panel;
2. API key — ввод скрытый;
3. protected numeric client IDs, если нужны;
4. длительность freeze (по умолчанию 15 минут);
5. запускать torrent enforcement сразу в `LIVE` или оставить `DRY RUN`;
6. включить ли port-scan detector;
7. длительность блокировки за сканирование (`0` — до ручной разблокировки);
8. port-scan режим `OBSERVE` или `LIVE`;
9. опциональные Telegram bot token и numeric admin chat ID.

Пример:

```text
============================================================
                   EZHIK TORRENT GUARD
============================================================

 Torrent protection for Xray + Remnawave

 Developer : ezhikdev
 Telegram  : @ezhikdev
 GitHub    : https://github.com/ezhikdev

============================================================

Remnawave panel domain or URL: panel.example.com
Remnawave API key: ********
Protected Remnawave client IDs, comma-separated (optional):
Freeze duration in minutes [15]:
Enable LIVE Remnawave enforcement after install? [Y/n]:
Enable port-scan detection? [Y/n]:
Port-scan block duration in minutes (0 = permanent) [60]:
Enable LIVE port-scan enforcement after install? [y/N]:
Telegram bot token (optional; Enter keeps/disables): ********
Telegram admin chat ID (optional): 123456789
```

Installer сам определяет WAN interface и WAN IPv4. IP-адрес конкретного сервера в исходниках не зашит.

При повторном запуске installer сравнивает установленный `/opt/ezhik-torrent-guard/VERSION` с `VERSION` репозитория:

- более старая версия — предлагает обновление с сохранением текущих настроек;
- та же версия — сообщает, что установлена последняя версия, и предлагает repair/reconfigure;
- более новая версия — отказывается выполнять неявный downgrade.

## Сборка готовых runtime-пакетов

Workflow `.github/workflows/runtime-release.yml` собирает отдельные пакеты на официальных GitHub runners Ubuntu 22.04 и 24.04 с ограничением в два build jobs. Собственный сервер для сборки не нужен.

Для теста откройте в GitHub вкладку **Actions**, выберите **Build runtime and release** и нажмите **Run workflow**. Будут выполнены source checks, две сборки и две runtime-проверки; результат останется временным Actions Artifact и не будет опубликован.

Для публикации:

```bash
git tag v1.2.0
git push origin v1.2.0
```

Значение тега должно точно соответствовать корневому `VERSION` с префиксом `v`. После успешных build/verify jobs workflow создаст GitHub Release и приложит оба runtime-пакета, SHA-256 и manifests. Для следующего релиза сначала измените `VERSION`, например на `1.0.3`, затем создайте тег `v1.0.3`.

## Что устанавливается

```text
/opt/ezhik-torrent-guard/
/etc/ezhik-torrent-guard/
/var/lib/ezhik-torrent-guard/
/opt/ezhik-suricata-8.0.6/

/etc/systemd/system/ezhik-suricata.service
/etc/systemd/system/ezhik-torrent-guard.service
/etc/systemd/system/ezhik-ram-log-guard.service
```

API credentials сохраняются локально в:

```text
/etc/ezhik-torrent-guard/api.env
```

с правами `0600`. Они не входят в репозиторий. Runtime-настройки находятся отдельно в `settings.env`, поэтому API token не требуется передавать через systemd EnvironmentFile.

## Проверка работы

```bash
systemctl status ezhik-suricata
systemctl status ezhik-torrent-guard
systemctl status ezhik-ram-log-guard
```

Live log Guard:

```bash
journalctl -fu ezhik-torrent-guard
```

При exact detection:

```text
[BT EXACT] client=12345 sockets=1 ...
[ACTION QUEUED] client=12345 action=freeze
[FROZEN] client=12345 duration=15m ...
```

После истечения срока:

```text
[UNFROZEN] client=12345 status=ACTIVE
```

В `DRY RUN` вместо API action:

```text
[WOULD_FREEZE] client=12345 ...
```

Port-scan наблюдение:

```text
[SCAN DETECTED] client=12345 reason=vertical-port-scan ... action=WOULD_BLOCK
[TELEGRAM SENT] client=12345 file=port-scan-...txt
```

Постоянная live-блокировка:

```text
[ACTION QUEUED] client=12345 action=freeze reason=port-scan duration=permanent
[BLOCKED] client=12345 duration=permanent manual_unblock=remnawave-panel
```

## Protected clients

Во время установки можно указать client IDs, которые Guard **никогда не будет отключать**:

```text
123,456,789
```

Значения универсальные — никакой конкретный admin ID в public repository не зашит.

## Admin hold

Чтобы временно запретить автоматический unfreeze конкретного client ID:

```bash
echo 12345 >> /etc/ezhik-torrent-guard/hold.txt
```

Guard не будет force-enable пользователя из hold-файла.

## Privacy

Raw connection metadata требуется для кратковременной exact correlation, но проект рассчитан на обработку этих данных **в RAM**:

```text
Xray access    → container /dev/shm/xray-access.log
Xray info      → container /dev/shm/xray-info.log
Suricata fast  → host /dev/shm/ezhik-suricata-fast.log
EVE            → disabled
PCAP logging   → disabled
```

На диск сохраняется минимальное sanction state, необходимое для безопасного автоматического unfreeze после restart:

```text
client_id
uuid
disabled_at
unfreeze_at
next_retry_at
reason
```

История peer IP / remote ports / visited domains в sanction state не сохраняется.

Для подтверждённых port-scan событий отдельно сохраняется не более 100 текстовых
incident reports в `/var/lib/ezhik-torrent-guard/incidents/` с правами `0600`.
Каждый файл содержит агрегированные счётчики и не более 100 sample endpoints;
payload пакетов не сохраняется. Telegram token находится в отдельном
`/etc/ezhik-torrent-guard/telegram.env` с правами `0600` и не передаётся через
systemd EnvironmentFile.

## Безопасность действий Remnawave

Перед freeze Guard:

- resolve numeric client ID → Remnawave UUID;
- проверяет совпадение client ID;
- требует текущий `ACTIVE` status;
- только после успешного `disable` создаёт локальную sanction.

Перед unfreeze Guard повторно проверяет UUID и status. Если подписка была отключена не Guard'ом или состояние изменилось вручную, Guard не должен слепо force-enable пользователя.

## Удаление

Скачать и запустить uninstaller:

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/uninstall.sh | bash
```

По умолчанию конфиг и sanction state сохраняются.

Полное удаление:

```bash
curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/uninstall.sh -o /tmp/ezhik-tg-uninstall.sh
bash /tmp/ezhik-tg-uninstall.sh --purge
```

Uninstaller откажется останавливаться при активной локальной sanction, чтобы случайно не оставить подписку замороженной навсегда. `--force` существует только для осознанного ручного восстановления.

## Структура репозитория

```text
ezhik-torrent-guard/
├── install.sh
├── uninstall.sh
├── README.md
├── VERSION
├── RUNTIME.env
├── .github/
│   └── workflows/
│       └── runtime-release.yml
├── src/
│   ├── guard.py
│   ├── remnawave_actions.py
│   ├── scan_detector.py
│   └── telegram_notifier.py
├── suricata/
│   └── ezhik-torrent-only.rules
├── scripts/
│   ├── ezhik-ram-log-guard.sh
│   ├── ezhik-torrent-guard-cleanup.sh
│   ├── build-runtime.sh
│   ├── create-release-manifest.py
│   ├── patch_ndpi_strict.py
│   ├── patch_suricata_ndpi.py
│   ├── render_suricata_config.py
│   └── verify-runtime.py
├── systemd/
│   ├── ezhik-suricata.service.template
│   ├── ezhik-torrent-guard.service
│   ├── ezhik-torrent-guard-cleanup.conf
│   └── ezhik-ram-log-guard.service
├── tests/
│   ├── test_scan_detector.py
│   └── test_remnawave_actions.py
└── docs/
    └── XRAY_LOGGING.md
```

## Disclaimer

Torrent/DPI и поведенческий port-scan detection не могут гарантировать распознавание абсолютно каждого нарушения без ложных срабатываний. Port-scan защита не является inline firewall: несколько первых соединений успеют выйти до достижения порога и применения Remnawave disable. Перед массовым rollout рекомендуется поставить новую версию на одну exit-ноду, оставить port-scan в `OBSERVE` и проверить игры, видео, браузинг и контролируемый скан собственной тестовой системы.
