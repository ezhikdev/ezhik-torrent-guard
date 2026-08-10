# 🦔 Ezhik Torrent Guard

> Автоматическая защита Xray / Remnawave exit-нод от BitTorrent abuse.

```text
Developer : ezhikdev
Telegram  : @ezhikdev
GitHub    : https://github.com/ezhikdev
```

Ezhik Torrent Guard пассивно обнаруживает BitTorrent-трафик на exit-сервере, связывает **реальный outbound socket Xray** с аутентифицированным пользователем Remnawave и временно отключает точную подписку через Remnawave API.

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

## Особенности v1.0.0

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

> **Ограничение v1.0.0:** детектор настроен на IPv4. IPv6 — отдельная будущая задача.

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

Первичная установка компилирует pinned nDPI и Suricata из исходников, поэтому занимает несколько минут.

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
5. запускать сразу в `LIVE` или оставить `DRY RUN`.

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
```

Installer сам определяет WAN interface и WAN IPv4. IP-адрес конкретного сервера в исходниках не зашит.

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

На диск сохраняется только минимальное sanction state, необходимое для безопасного автоматического unfreeze после restart:

```text
client_id
uuid
disabled_at
unfreeze_at
next_retry_at
reason
```

История peer IP / remote ports / visited domains в sanction state не сохраняется.

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
├── src/
│   ├── guard.py
│   └── remnawave_actions.py
├── suricata/
│   └── ezhik-torrent-only.rules
├── scripts/
│   ├── ezhik-ram-log-guard.sh
│   ├── ezhik-torrent-guard-cleanup.sh
│   ├── patch_ndpi_strict.py
│   ├── patch_suricata_ndpi.py
│   └── render_suricata_config.py
├── systemd/
│   ├── ezhik-suricata.service.template
│   ├── ezhik-torrent-guard.service
│   ├── ezhik-torrent-guard-cleanup.conf
│   └── ezhik-ram-log-guard.service
└── docs/
    └── XRAY_LOGGING.md
```

## Disclaimer

Torrent/DPI detection не может гарантировать распознавание абсолютно каждого клиента, будущей обфускации или каждого варианта протокола. Перед массовым rollout рекомендуется сначала поставить новую версию на одну exit-ноду и проверить `DRY RUN` на своей тестовой подписке.
