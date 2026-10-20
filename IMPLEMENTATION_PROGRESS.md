# Ezhik Guard 2.1 — прогресс реализации (для продолжения в новой сессии)

> Последнее обновление: 2026-10-17. Читать целиком перед продолжением работы.
> Секреты (пароли, токены) в этот файл НЕ записывать.

## 0. Как продолжить

1. Прочитать разделы 1 (ТЗ), 3 (что сделано), 5 (что осталось) и 6 (окружение).
2. Не переделывать то, что отмечено как сделанное и протестированное.
3. Следующий шаг — раздел 5, первый невыполненный пункт.
4. После каждого крупного шага обновлять этот файл.

## 1. Исходное ТЗ (дословно)

Нужно реализовать крупное обновление **Ezhik Guard**, расширив существующую панель и агентов. Сначала изучи архитектуру проекта, затем интегрируй новые функции в существующий интерфейс. Детали реализации и структуру модулей определяй самостоятельно.

### 1. HTTPS для центральной панели
- Добавить настройку собственного домена с проверкой DNS A/AAAA и доступности.
- Автоматизировать получение и продление SSL-сертификатов Let's Encrypt.
- Обеспечить работу панели, API и WebSocket через HTTPS.
- Предусмотреть безопасный переход с IP на домен без потери доступа.

### 2. Централизованный Firewall Manager
- Глобальные правила для всех нод с индивидуальными переопределениями.
- По умолчанию разрешены TCP 22, 80, 443; остальные входящие соединения запрещены, кроме необходимых для работы сервисов.
- Автоматически обнаруживать порты Xray/Remnanode и определять, какие должны быть публичными, внутренними или доступны только по белому списку.
- Поддержать TCP/UDP, диапазоны портов, IPv4/IPv6, IP/CIDR и пользовательские правила.
- Автоматически разрешать необходимые соединения панели и агентов.
- Учитывать Docker, nftables/iptables и существующие правила.
- Обязательны резервное копирование, защита от потери SSH/связи и автоматический rollback.

### 3. Nginx Manager
Добавить индивидуальный выбор режима для каждой ноды:

**Direct Xray:** Nginx не занимает VPN-порт, подключения поступают непосредственно в Xray, TLS обрабатывается Xray. Существующие конфигурации сохраняются.

**Nginx Frontend:** Nginx принимает HTTP/HTTPS на 80/443, выполняет 301-редирект на HTTPS, обслуживает TLS 1.2/1.3, сертификаты, сайт-заглушку и маршрутизирует поддерживаемые HTTP/gRPC-транспорты к Xray.

Для gRPC TLS завершается на Nginx, внутреннее соединение Nginx → Xray работает без дополнительного TLS.

(так же включить BBR)

Реализовать:
- Централизованное управление маршрутами с индивидуальными настройками нод.
- Настройку публичного порта, транспорта, `path` / `serviceName`, внутреннего адреса и порта Xray.
- Несколько маршрутов на одной ноде, возможность их включения, изменения и удаления.
- Автоматическую генерацию Nginx-конфигураций (`grpc_pass` для gRPC).
- Проверку совместимости транспортов: REALITY/RAW нельзя направлять через обычный HTTP location.
- Безопасное переключение режимов с проверкой портов, конфигураций и rollback.

**Пример маршрута:**
- Публичный порт: `443`
- Транспорт: `gRPC`
- `serviceName`: `cdn-service`
- Внутренний Xray: `127.0.0.1:10443`
- TLS: Nginx

Nginx должен направлять `/cdn-service/Tun` на внутренний Xray, остальные запросы — на сайт-заглушку.

Учитывать Docker-сети: `127.0.0.1` допустим только при соответствующей сетевой архитектуре.

Если возможно через поддерживаемые механизмы Remnawave, синхронизировать `listen`, `port`, `security: none` и `grpcSettings.serviceName` с Xray. Не изменять управляемые Remnawave конфигурации напрямую в обход панели и не нарушать действующие подписки.

### 4. Управление сайтом-заглушкой
- Добавить загрузку сайта через ZIP (HTML, CSS, JS, изображения, assets) в центральной панели.
- Поддержать общий сайт для всех нод и индивидуальные сайты для отдельных нод.
- Реализовать централизованное распространение, обновление и синхронизацию сайта на выбранные ноды с отображением статусов.
- Добавить кнопку **«Предпросмотр сайта»**, открывающую загруженную заглушку по адресу `https://домен-панели/site-mask/`.
- Предпросмотр должен полностью отображать сайт со всеми стилями, изображениями, JavaScript и переходами между страницами, максимально соответствуя отображению на реальной ноде.
- Обеспечить корректную работу относительных и абсолютных путей к ресурсам, включая сайты, рассчитанные на размещение в корне домена `/`.
- Предусмотреть просмотр общего сайта и индивидуальной заглушки каждой ноды, желательно без необходимости предварительного распространения.
- Обеспечить безопасную распаковку ZIP, изоляцию загруженного контента от административной части панели и корректную раздачу статических файлов через Nginx.
- Предусмотреть возможность обновления заглушки с предварительным просмотром новой версии перед её публикацией.

### 5. Интеграция и надёжность
- Сохранить стиль и архитектуру существующей панели.
- Все операции выполнять через агентов с проверками, журналированием и понятными статусами.
- Перед применением изменений создавать резервные копии, проверять конфигурации и доступность сервисов.
- При ошибках автоматически восстанавливать прежнее рабочее состояние.
- Сохранить совместимость с Remnawave 3.4.4, существующими нодами, конфигурациями и всеми модулями Ezhik Guard.
- Не перезаписывать пользовательские настройки без разрешения.
- Предусмотреть безопасное массовое применение настроек на несколько нод.

### 6. Тестирование
**Все реальные интеграционные тесты проводить на тестовом сервере. Данные находятся в `TEST-SERVER.txt`. Рабочие серверы не трогать. Секретные данные не выводить в логи и отчёты.**

Проверить чистую установку, миграции, SSL панели, Nginx/Xray, маршрутизацию gRPC, firewall, Docker, синхронизацию агентов, переключение режимов, rollback и отсутствие регрессий в Torrent Guard, Port Guard и SSL Manager.

Использовать тестовые сценарии, включая намеренно неправильные конфигурации, чтобы проверить восстановление после ошибок. Для внешних сервисов, например Let's Encrypt, учитывать реальные условия проверки и не выдавать имитацию за успешный интеграционный тест.

**Главный приоритет:** полностью работающая функциональность, безопасность, совместимость и удобное централизованное управление.

Работай самостоятельно, принимай технические решения, исправляй обнаруженные ошибки и выполняй тесты. Не ограничивайся созданием интерфейса. В конце предоставь краткий отчёт: что реализовано, что протестировано, какие ограничения остались.

### Дополнительные указания пользователя
- Сборку готовить на ПК чисто для загрузки на GitHub через браузер: папка `D:\Projects\Ezhik VPN\Torrent Guard - upload\partN`, < 100 файлов в части, без node_modules/__pycache__/dist/TEST-SERVER.txt/ABUSE/base-skills (см. память `clean-github-upload`). Релизы не публиковать без подтверждения пользователя.
- Тестовая VM (из TEST-SERVER.txt) — отдельная, root. Пользователь разрешил делать на ней что угодно («нода отключена от всего»). На ней стоит старая EzhikLB-нода (haproxy 103.112.71.102:2301/2305, IPVS, fail2ban) — firewall не должен ломать работающие службы (политика по умолчанию «существующие службы открыты»).

## 2. Архитектура (кратко, что уже было в 2.0)

- `panel/ezhik_panel` — FastAPI + SQLite; два порта: UI (8443) и API агентов (8444, собственный CA, пиннинг).
- `agent/ezhik_agent` — stdlib Python на ноде; long-poll `/agent/v1/sync`, реконсайлер шагов (`reconcile()` в main.py), отчёт `report()`.
- `web/` — Preact + Vite UI. `scripts/build_release.py` → `dist/ezhik-guard.tar.gz`.
- Конфиг ноды строит `NodeService.desired_config()`; generation = sha конфигурации.

## 3. Сделано в 2.1 (код написан)

### Агент (`agent/ezhik_agent/`)
- `ports.py` — слушающие сокеты (`ss`), роли (ssh/xray/nginx/remnanode/docker/ipvs/other), IPVS из `/proc/net/ip_vs`; UDP-сокеты Xray из эфемерного диапазона отбрасываются (фикс: только role=xray).
- `firewall.py` — своя таблица `inet ezhik_guard` (input policy drop, established, lo, ICMP/ND, SSH anti-lockout, правила; forward — фильтр DNAT в docker0/br-*), атомарное `nft -f`, `nft -c` проверка, dead-man через `systemd-run --on-active=Ns` (+ threading fallback), проверка связи с панелью (`/agent/v1/ping`), rollback.
- `nginx.py` — режимы direct/frontend, генерация конфига `/etc/nginx/conf.d/ezhik-guard.conf` (gRPC `grpc_pass`, ws/httpupgrade, xhttp, 301 с 80, TLS1.2/1.3, сайт-заглушка), проверки: транспорт, порты заняты (не nginx), чужие конфиги на портах, сеть контейнера (127.0.0.1 только при host), отключение стокового default site с восстановлением, `nginx -t`, reload, probe 443 и gRPC, rollback; при direct — удаление своего конфига и остановка nginx, если ставили мы.
- `site.py` — заглушка: releases/<ver> + symlink current, встроенная страница, безопасная распаковка tar.
- `netopt.py` — BBR (sysctl.d + modules-load, восстановление прежних значений).
- `main.py` — новые шаги reconcile: site → nginx → bbr → firewall; отчёт: ports, nginx, firewall, bbr, site; `panel_reachable()`; `panel_ports()` (порты панели на этой же машине из panel.env и `/var/lib/ezhik-guard/panel/listeners.json`).

### Панель (`panel/ezhik_panel/`)
- `db.py` миграция 2: nodes.nginx/firewall/bbr/site_id/remnawave_node; таблицы sites, site_versions.
- `firewall.py` — глобальная политика (по умолчанию TCP 22/80/443, enabled_default=False), override ноды, `plan()` (порты из отчёта + inbound'ы Remnawave + Nginx + порты панели; whitelist для API RemnaNode = IP панели Remnawave + remnanode_sources); не включается, пока агент не прислал порты.
- `nginx_routes.py` — валидация маршрутов, `check_routes()` против activeInbounds Remnawave (транспорт, security none, serviceName/path, listen, конфликт публичного порта, сеть Docker), `snippet()`, `patch_profile()` (меняет только один inbound).
- `remnawave.py` — `nodes()`, `match_node()`, `config_profile()`, `update_config_profile()` (PATCH /api/config-profiles).
- `sites.py` — ZIP: лимиты, whitelist расширений, запрет `..`/абсолютных/symlink, zip-bomb, снятие общей папки, index.html обязателен; версии (draft/publish), bundle tar.gz для агентов, preview-токены HMAC, `rewrite()` абсолютных путей в HTML/CSS.
- `panel_domain.py` — проверка DNS A/AAAA vs адреса сервера, HTTP/HTTPS-доступность, HTTP-приложение порта 80 (ACME HTTP-01 + 301), `Listeners` (динамические uvicorn на 80/443; 8443 всегда работает), `listeners.json`.
- `acme.py` — `challenges(order, kind)` поддерживает http-01.
- `certificates.py` — провайдер `http01` (HTTP01), `_issue_http01`, общий `_finalize`.
- `settings_service.py` — firewall(), network() (bbr_default), panel: domain, domain_cert_id, http_port, https_port.
- `main.py` — Listeners, SiteService, preview.key, ssl_contexts (горячая замена cert на всех портах), авто-переключение UI на сертификат домена, фоновый кэш Remnawave (`refresh_remnawave`, каждые 120 с).
- `nodes.py` — desired_config: nginx, site, bbr, firewall; public(): nginx/firewall/bbr/site + detail: firewall plan, ports, remnawave, route_checks; update_node: nginx, firewall, bbr, site_id, remnawave_node.
- `app.py` — API: `/api/settings/firewall|network`, `/api/remnawave/refresh`, `/api/nodes/{id}/nginx/remnawave-sync` (preview + confirm), `/api/sites*` (upload multipart, publish, preview, delete), `/api/nodes/{id}/site-preview`, `/site-mask/` (с сессией → редирект на токен), `/site-mask/{token}/{path}` (CSP sandbox, rewrite), `/api/system/domain*` (status, check, apply, reset); агент: `/agent/v1/ping`, `/agent/v1/site/{id}/{ver}.tar.gz`.

### Тесты
- `tests/agent/test_firewall_nginx.py` (11) и `tests/panel/test_sites_firewall.py` (16) — проходят. Все старые тесты тоже проходят.

## 4. Протестировано на VM (реально)
- Чистая установка панели 2.1.0 настоящим `install.sh --bundle` от root на Ubuntu 22.04 — OK (панель на 103.112.71.52:8443/8444).
- Запущен контейнер `remnanode` (teddysun/xray, network host): grpc-in 127.0.0.1:10443 serviceName cdn-service security none (client id ...0a01 email 101), ws-in 127.0.0.1:10444 /ws (…0a02, email 102), reality-in 0.0.0.0:9443 (…0a03, pbk 5TiApiqixtj7D64FWuyQxJl0drThleaCreWr4qw3BQY, sid a1b2, sni www.microsoft.com). Конфиг: `/opt/xray-test/config.json`.

### Пройдено на VM (2.1.0 → 2.1.2), реально
- Агент установлен командой из панели (нода на той же VM, id в /root/.eg-nid), обновления агента кнопкой «Обновить все» 2.1.0→2.1.1→2.1.2 — OK.
- Firewall: классификация портов (панель 8443/8444, haproxy 2301/2305 TCP + IPVS UDP, docker 8088, xray 9443, python 9999); применение; проверка из контейнера (вход через docker0, не lo): 22/8443/8444/9443/2301/2305 открыты, 9999/8088/12345 закрыты; откат при verify=False — таблица восстановлена; dead-man: процесс убит после применения → systemd timer через 40 с вернул прежнюю таблицу; выключение — таблица удалена, порты снова открыты. ВНИМАНИЕ: проверка портов с ПК пользователя бесполезна (его трафик идёт через прокси, «открыто» всё).
- Найдено/исправлено: nft 1.0.2 не принимает `oifname { "docker0", "br-*" }` (wildcard в анонимном множестве) → отдельные правила; `nft -c` поймал ошибку до применения.
- Найдено/исправлено: панель не сохраняла новые поля отчёта (ports/nginx/firewall/bbr/site) — добавлены в record_report.
- HTTPS панели: домен 103-112-71-52.sslip.io, проверка DNS; LE staging → затем боевой LE (issuer YE2) через HTTP-01 порта 80 панели; UI автоматически переключился на сертификат; curl без -k: 200; http→301; доступ по IP сохраняется; порт 443 для UI включается/выключается на лету (listeners.json).
- Найдено/исправлено: PUT /api/settings/panel не пропускал http_port/https_port.
- Сертификат ноды 103-112-71-102.sslip.io — боевой LE через HTTP-01; wildcard через http01 корректно отклоняется.
- Nginx frontend: первый запуск дал 500 (агент с UMask=0077 создал /var/www 0700) → агент сам откатил конфигурацию; исправлено (`site._public_dir` 0755). После фикса: 443→200, grpc cdn-service HTTP 200, ws upstream ok.
- E2E: xray-клиент (контейнер xclient, socks 10808 gRPC / 10809 WS) → TLS на Nginx → Xray → интернет: оба транспорта работают, в access-логе email 101/102 (атрибуция работает за Nginx); заглушка, 301, TLS1.2 ок, TLS1.1 отклоняется.

## 5. Осталось сделать (по порядку)
1. (сделано)
2. (сделано)
3. (сделано, 2.1.3) Nginx негативные сценарии на VM: чужой конфиг на 443 → отказ, наш конфиг не изменён; маршрут на 9443 (xray) → отказ; REALITY/tcp → 400 от API; frontend→direct (nginx остановлен, 80/443 свободны, default site восстановлен) → снова frontend (gRPC и WS туннели работают, 443→200, 80→301); firewall (массово) вкл → 80/443 открыты автоматически, 9999 закрыт; выкл → таблица удалена.
4. (сделано) HTTPS панели. Не забыть: при http_port=0 продление по HTTP-01 не пройдёт — показать предупреждение в UI.
5. (сделано, 2.1.3) BBR на VM: cubic/fq_codel → вкл (bbr/fq, sysctl.d) → выкл (восстановлено cubic/fq_codel, файл удалён) → наследование глобальной → глобально вкл.
6. (сделано, 2.1.5) Сайт-заглушка: скрипт site_e2e.py (42 проверки, ALL PASS) + browser_e2e.py (Chromium/Playwright на VM, ALL PASS): вредоносные ZIP отклоняются; черновик/публикация; предпросмотр /site-mask/ (CSS, img, ES-модули, fetch, JS-созданные img, переходы), изоляция (нет cookies/API панели/localStorage); доставка на ноду и отдача Nginx; индивидуальный сайт ноды, возврат к общему, удаление → встроенная.
   Исправлено: версии сайтов в одну секунду конфликтовали (UNIQUE + перезапись каталога) → глобально уникальные версии; в предпросмотре добавлен CORS `*` (opaque origin ломал module/fetch/шрифты), JS-shim для абсолютных URL в рантайме и переписывание `import "/..."` в JS.
7. (сделано, 2.1.8) Реальный Remnawave 3.4.4 (/opt/remnawave, docker compose, 127.0.0.1:3000) + RemnaNode remnawave/node:3.4.2 (/opt/remnanode, host, порт 2222) на VM. Секреты: /root/.rw-admin, .rw-token, .rw-node-secret (не выводить). Профиль EG-Test (grpc-in/ws-in/reality-in), squad EG-Test, пользователи eg_grpc/eg_ws/eg_reality (id 2/3/4, vlessUuid = UUID xclient). Фейковый контейнер переименован в xray-fake (остановлен).
   rw_sync.py — ALL PASS: проверки маршрутов (serviceName/listen), предпросмотр не меняет профиль, REALITY отклоняется, применение меняет только grpc-in, RemnaNode применяет, gRPC-туннель заработал, WS работает, подписки отдаются, аудит.
   Исправлено: Remnawave 3.x рвёт соединения без X-Forwarded-For/Proto → клиент добавляет их для http://-адресов; процесс `rw-node` (RemnaNode 3.4) → роль remnanode; firewall: протоколы по транспорту inbound (raw/grpc/ws → только TCP), upstream-порты маршрутов Nginx — «внутренний (за Nginx)», закрыты по умолчанию; patch_profile отказывает для REALITY/другого транспорта (было: 500/порча inbound).
8. (сделано; скриншоты Chromium на VM проверены) UI (web/): страница «Firewall» (глобальные правила, авто-политики, белый список, BBR по умолчанию), на странице ноды — секции Firewall (обнаруженные порты/политики/override), Nginx (режим, маршруты, проверки Remnawave, синхронизация), BBR, сайт; страница «Сайты» (загрузка, версии, предпросмотр, публикация, статусы нод); Настройки → Панель: мастер домена. Массовые действия: firewall вкл/выкл, BBR.
9. (сделано) Регрессия на реальном стеке (regress.py): Torrent Guard — реальный BitTorrent-handshake клиента eg_ws через WS/Nginx → событие, заморозка (DISABLED в Remnawave), туннель заблокирован, gRPC-пользователь не затронут, «Снять» из панели → ACTIVE, туннель снова работает; Port Guard — скан 70 портов IP (portquiz.net) клиентом eg_grpc → «Перебор портов одного IP», режим наблюдения, без блокировки; SSL — сертификат ноды установлен, Nginx отдаёт LE-сертификат.
   Обновление 2.0.1 (релиз с GitHub) → 2.1 в systemd-контейнере (egup.sh): user_version 1→2, данные сохранены, новые API работают, Traceback нет. Юнит-тесты и на Python 3.12 (docker python:3.12-slim на VM) — OK.
10. (сделано) README (разделы 2.1), code-map.md переписан под 2.x, VERSION 2.1.0, сборка, папка загрузки `Torrent Guard - upload/part1` (33 изменённых/новых файла относительно GitHub main; устаревших файлов на GitHub нет). IMPLEMENTATION_PROGRESS.md в загрузку НЕ входит (содержит данные тестового стенда).
   Финальный прогон на сборке 2.1.0 (final.sh, лог /root/final.log на VM) — ВСЁ ПРОШЛО: юнит-тесты 3.10 и 3.12, nginx_neg, fw_nginx, bbr, site_e2e (2 прогона), browser_e2e, rw_break+rw_sync, regress. Traceback в панели после исправлений — 0.
   СТАТУС: ТЗ выполнено. Осталось только по решению пользователя: загрузить part1 на GitHub и опубликовать тег v2.1.0 (без подтверждения не публиковать).

### Сделано в сессии 3 (2026-10-17)
- Сверка: страницы Firewall.tsx, Sites.tsx, NodeNetwork.tsx (карточки Firewall/Nginx/Сеть и сайт) уже были написаны.
- Добавлено: массовые действия `firewall_enabled`, `bbr` (`NodeService.bulk`, кнопки в bulkbar Nodes.tsx); мастер домена панели (`DomainCard` в Settings → Панель: проверка DNS/HTTP/HTTPS, HTTP-01/DNS-01, 443, редирект 80, агенты по домену, предупреждение о продлении при выключенном 80, сброс на IP).
- ВАЖНО (указание пользователя): на ПК — только код и сборка; ВСЕ тесты (в т.ч. юнит) запускать на тестовой VM (`/root/src`, python панели `/opt/ezhik-guard/panel/venv/bin/python`).
- 2.1.3 установлена на VM, юнит-тесты на VM: агент 36 OK, панель 70 OK.

## 6. Окружение и инструменты
- Тестовая VM: см. `TEST-SERVER.txt` (root). IP: 103.112.71.52 (ens3, маршрут по умолчанию) и 103.112.71.102 (ens3:0). Ubuntu 22.04, Docker, nft 1.0.2, ephemeral range 10000-65535, BBR уже включён.
- Панель на VM: https://103.112.71.52:8443 (логин admin; пароль выдан установщиком — можно сбросить `bash /root/install.sh --reset-password`).
- SSH-хелпер (локально; старый venv+rssh.py лежат в scratchpad сессии 55470267-…, их можно переиспользовать, скопировав `r`): `C:/Users/Ezhik/AppData/Local/Temp/claude/d--Projects-Ezhik-VPN-Torrent-Guard/<session>/scratchpad/r` — `r run '<cmd>' [--timeout N]`, `r put LOCAL REMOTE` (пути на сервере — относительные от /root, т.к. Git Bash портит `/root/...`), основан на `rssh.py` + paramiko в `scratchpad/venv`. В новой сессии scratchpad другой — пересоздать: venv с paramiko и rssh.py (читает IP/Port/Login/Password из TEST-SERVER.txt).
- Локальные тесты: `python -m unittest discover -s tests/agent -t tests/agent` и `-s tests/panel -t tests/panel` (панельным нужны зависимости panel/requirements.txt).
- Сборка: `python scripts/build_release.py [--skip-web]` (web: `cd web && npm run build`).

## 7. Известные проблемы / решения
- Git Bash переписывает аргументы `/root/...` → использовать относительные пути или `MSYS_NO_PATHCONV=1`.
- Не использовать `pkill -f <шаблон>`, совпадающий с командой самой SSH-сессии (убивает её).
- Python-патчи через heredoc с тройными кавычками ломаются в bash — писать скрипт в файл.
- Панель и Nginx-frontend на одной машине конкурируют за порт 80 (HTTP-01 панели). Для такой схемы — DNS-01 или выпуск до включения frontend. Задокументировать.

## 8. После релиза v2.1.0 (2026-10-17, вечер)
- Пользователь опубликовал v2.1.0. Сообщил: на его ноде LT-1 обновление агента со старой версии на 2.1.0 «откатено» (дважды).
  Воспроизвести НЕ удалось: (1) чистый systemd-контейнер 2.0.1 панель+агент → панель 2.1.0 → агент 2.1.0 OK; (2) нода VM (Docker, RemnaNode, Suricata) откачена на 2.0.1 со «старым» state → обновление до 2.1.1 OK; опубликованный бандл = локальной сборке; все модули импортируются на Python 3.10/3.12.
  Откат = OnFailure после 5 стартов за 300 с (новый агент падает при запуске). Нужен журнал агента с LT-1 (запрошен у пользователя).
- Баг UI: модальные окна (новое правило firewall) рисовались внутри карточки и уходили под соседние → Modal через createPortal в body (ui.tsx). Проверено в Chromium. Версия 2.1.1 на VM; папка загрузки part1: VERSION, code-map.md, web/src/components/ui.tsx.
- Внимание: не импортировать `ezhik_agent.__main__` в проверках — он запускает агента.
- ПРИЧИНА отката найдена по логам US-1 (Ubuntu 24.04, systemd 255): выход 75 после активации → «Triggering OnFailure» → rollback-служба (код из previous = 2.0.1) возвращает старую версию. В systemd ≥ 254 RestartMode=normal проводит каждый авто-рестарт через failed. Баг ещё из 2.0; на 22.04 (systemd 249) не проявлялся.
  Исправлено в 2.1.2: юнит SuccessExitStatus=75 + RestartMode=direct; updater.rollback() при ExecMainStatus=75 только перезапускает; панель в событии «откатено» (from < 2.1.2, откат < 30 с) даёт команду drop-in; uninstall снимает nftables-таблицу, Nginx→direct, BBR, сайт, drop-in. Тест tests/agent/test_updater.py.
  Проверено в systemd-контейнере Ubuntu 24.04 (noble_up.sh): A — баг воспроизведён на 2.0.1; B — drop-in → обновление до 2.1.2 OK; C — restart_agent без отката; D — SIGKILL без отката; E — uninstall чистит.
  Ноды на 2.0.x–2.1.1 с Ubuntu 24.04 требуют ОДНОРАЗОВОГО drop-in (старый код делает активацию и откат — новым релизом не обойти). Папка загрузки part1: README, VERSION 2.1.2, uninstall/units/updater.py, code-map, nodes.py, test_updater.py.

## 9. Ezhik Guard 2.2 — Vision + TLS Fallback (2026-10-18)
- Третий режим Nginx "vision": Xray (inbound Remnawave) на 0.0.0.0:443 VLESS RAW+TLS+xtls-rprx-vision, fallbacks → Nginx 127.0.0.1:8001 (HTTP/1.1) / 8002 (h2c), PROXY protocol; маршруты 443 (gRPC/WS/XHTTP) — locations в fallback-сервере; другие порты — TLS в Nginx; 80 → 301.
- Панель: nginx_routes.validate_vision/vision_conflicts/check_vision/patch_vision; API /api/nodes/{id}/nginx/vision-sync (preview / confirm / confirm+when_ready; kv vision_sync:<node>, hook в record_report); update_node отказывает при REALITY/не-VLESS/не-RAW/другом inbound на 443. Сайты и firewall поддерживают режим (uses_nginx; 443 в vision — порт Xray).
- Агент: NginxManager._vision (сертификат в контейнере, сеть host, порты, foreign configs) → render_vision → _install (общий с frontend, откат) → пробы h1/h2c; vision_e2e (Xray :443 как браузер); push-отчёт (body.push) при готовности → sync стартует сразу.
- Remnawave 3.4.4: flow для VLESS raw+tls по умолчанию xtls-rprx-vision (get-vless-flow.ts); certificateFile читается в контейнере RemnaNode, если на панели файла нет.
- E2E vision_e2e.py — 38/38 ALL PASS (реальные Remnawave+RemnaNode, xclient: Vision 10810, gRPC 10808, WS 10809, REALITY 10811). Простой 443 при переключении ≈10 с. Регрессия final.sh на 2.2.0 — всё OK (firewall-блок требовал восстановить override tcp/9999 closed, стёртый моим downgrade-тестом).
- Стенд: цель REALITY изменена на www.apple.com (www.microsoft.com несовместим с REALITY здесь — проверено чистым Xray). Профиль EG-Test: добавлен vision-in (127.0.0.1:10445 без TLS в исходном состоянии), пользователь eg_vision (…0a04, id 5). Сертификат ноды ставится в Docker-контейнер.
- Папка загрузки part1: README, VERSION 2.2.0, agent main/nginx, code-map, panel app/nginx_routes/nodes, тесты, web NodeNetwork/Sites.
- 2.2.2: общий inbound профиля (активен и на других нодах) больше не блокирует Vision-sync — check_vision кладёт его в warnings (не problems), can_sync=true; UI показывает предупреждение и список затронутых нод в окне подтверждения. Папка загрузки part1: VERSION, IMPLEMENTATION_PROGRESS, code-map, panel app/nginx_routes, test_sites_firewall, web NodeNetwork.
