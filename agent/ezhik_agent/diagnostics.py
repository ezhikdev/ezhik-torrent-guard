"""Self-checks shown on the node page with concrete fix hints."""

import shutil
import time

from . import legacy, paths, suricata, system
from .util import run


def check(checks, cid, title, status, message, hint=""):
    checks.append({"id": cid, "title": title, "status": status, "message": message, "hint": hint})


def run_all(agent):
    checks = []
    desired = agent.desired or {}
    det = desired.get("detector") or {}
    container = agent.detector.config.container or det.get("container") or "remnanode"
    torrent = bool((det.get("torrent") or {}).get("enabled"))
    scan = bool((det.get("scan") or {}).get("enabled"))

    osr = system.os_release()
    supported = osr["id"] == "ubuntu" and osr["version"] in ("22.04", "24.04", "26.04")
    check(checks, "os", "Операционная система", "ok" if supported else "warn",
          osr["pretty"], "" if supported else "Протестированы Ubuntu 22.04 и 24.04 LTS (amd64).")

    if not system.docker_available():
        check(checks, "docker", "Docker", "fail", "Docker недоступен",
              "Агент читает логи Xray через docker exec. Установите/запустите Docker.")
    else:
        check(checks, "docker", "Docker", "ok", f"Docker {system.docker_version()}")
        state = system.container_state(container)
        if not state:
            found = system.detect_remnanode_container()
            check(checks, "container", "Контейнер RemnaNode", "fail", f"Контейнер {container} не найден",
                  f"Укажите имя контейнера в настройках ноды{' (найден: ' + found + ')' if found else ''}.")
        elif state["status"] != "running":
            check(checks, "container", "Контейнер RemnaNode", "fail", f"{container}: {state['status']}",
                  "Запустите контейнер RemnaNode.")
        else:
            check(checks, "container", "Контейнер RemnaNode", "ok", f"{container} · {state['image']}")
            if system.xray_logs_present(container):
                sizes = system.container_files_sizes(container, [paths.XRAY_ACCESS_LOG, paths.XRAY_INFO_LOG])
                ages = agent.detector.snapshot()["last_line_age"]
                stale = agent.detector.running and (ages.get("access") is None or ages["access"] > 600)
                check(checks, "xray_logs", "Логи Xray в RAM", "warn" if stale else "ok",
                      "Файлы есть" + (", но новых строк нет более 10 минут" if stale else "")
                      + f" (access {sizes.get(paths.XRAY_ACCESS_LOG, 0)//1024} КБ, info {sizes.get(paths.XRAY_INFO_LOG, 0)//1024} КБ)",
                      "Проверьте loglevel=info в профиле Xray." if stale else "")
                if agent.detector.running and ages.get("info") is None and ages.get("access") is not None:
                    check(checks, "xray_loglevel", "Уровень логирования Xray", "fail",
                          "Info-лог не содержит запросов", 'Задайте "loglevel": "info" в профиле Xray.')
            else:
                check(checks, "xray_logs", "Логи Xray в RAM", "fail" if (torrent or scan) else "warn",
                      "Нет /dev/shm/xray-access.log и /dev/shm/xray-info.log в контейнере",
                      'В профиле Xray (Remnawave → Config Profiles) задайте "log": {"access": '
                      '"/dev/shm/xray-access.log", "error": "/dev/shm/xray-info.log", "loglevel": "info"}.')

    wan_if, wan_ip = agent.wan
    check(checks, "wan", "Внешний интерфейс", "ok" if wan_ip else "fail",
          f"{wan_if or '?'} / {wan_ip or '?'}", "" if wan_ip else "Не удалось определить IPv4 маршрут по умолчанию.")

    engine = desired.get("runtime")
    if torrent:
        if engine and suricata.is_installed(engine):
            active = system.unit_active(paths.SURICATA_UNIT)
            check(checks, "suricata", "Сенсор Suricata + nDPI", "ok" if active else "fail",
                  f"{engine['engine_id']}: {'активен' if active else 'не запущен'}",
                  "" if active else system.unit_failure_hint(paths.SURICATA_UNIT))
        else:
            check(checks, "suricata", "Сенсор Suricata + nDPI", "warn", "Runtime ещё не установлен",
                  "Агент установит его автоматически; смотрите статус компонента suricata.")
    else:
        check(checks, "suricata", "Сенсор Suricata + nDPI", "ok", "Не требуется: защита от торрентов выключена")

    if torrent and not system.package_installed("python3-yaml"):
        check(checks, "yaml", "python3-yaml", "warn", "Пакет не установлен", "Будет установлен автоматически.")

    usage = shutil.disk_usage(str(paths.ROOT))
    free_gb = usage.free / 1024 ** 3
    check(checks, "disk", "Свободное место", "ok" if free_gb > 1 else "warn", f"{free_gb:.1f} ГБ свободно",
          "" if free_gb > 1 else "Для runtime нужно ~200 МБ, для обновлений apt — больше.")

    ntp = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10)
    synced = ntp.stdout.strip() == "yes"
    check(checks, "time", "Синхронизация времени", "ok" if synced else "warn",
          "NTP синхронизирован" if synced else "NTP не синхронизирован",
          "" if synced else "Включите systemd-timesyncd: время событий и сертификатов зависит от часов.")

    found = legacy.detect()
    check(checks, "legacy", "Старые версии", "warn" if found["present"] else "ok",
          ("Найдены компоненты Torrent Guard " + (found.get("version") or "1.x")) if found["present"] else "Не обнаружены",
          "Будут удалены автоматически." if found["present"] else "")

    stock = system.unit_state("suricata.service")
    if stock.get("ActiveState") == "active":
        check(checks, "stock_suricata", "Системный suricata.service", "warn", "Запущен штатный Suricata",
              "Он не мешает работе, но расходует ресурсы. Отключите, если не используете.")

    cert = agent.state.get("cert") or {}
    if cert.get("error"):
        check(checks, "cert", "Сертификат", "fail", cert["error"], "Проверьте путь назначения и контейнер.")
    elif cert.get("id"):
        check(checks, "cert", "Сертификат", "ok", f"Установлен, действует до {cert.get('not_after')}")

    return {"checks": checks, "at": time.time()}
