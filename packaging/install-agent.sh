#!/usr/bin/env bash
# Ezhik Guard node agent installer. Served by the panel; placeholders are
# filled in per request. Usage (copy the exact command from the panel):
#   curl -fsSL --pinnedpubkey 'sha256//...' -k https://PANEL:8444/install.sh | sudo bash -s -- --token TOKEN
set -Eeuo pipefail

PANEL_URL="@@PANEL_URL@@"
PIN="@@PIN@@"
AGENT_VERSION="@@VERSION@@"
read -r -d '' CA_PEM <<'__CA__' || true
@@CA_PEM@@
__CA__

APP_DIR=/opt/ezhik-guard/agent
CONFIG_DIR=/etc/ezhik-guard/agent
STATE_DIR=/var/lib/ezhik-guard/agent
LOG=/var/log/ezhik-guard-agent-install.log
TOKEN=""
NAME=""
FORCE_REGISTER=0

c_info() { printf '\033[1;36m[ezhik]\033[0m %s\n' "$*"; }
c_ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()    { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; [ -s "$LOG" ] && { echo "--- последние строки $LOG ---" >&2; tail -n 25 "$LOG" >&2; }; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --force-register) FORCE_REGISTER=1; shift ;;
    -h|--help) echo "usage: install.sh --token TOKEN [--name NAME] [--force-register]"; exit 0 ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done

[ "${EUID:-$(id -u)}" -eq 0 ] || die "Запустите установку от root (sudo)."
: >"$LOG"; chmod 600 "$LOG"

cat <<'BANNER'
============================================================
              EZHIK GUARD · установка агента ноды
============================================================
BANNER

[ -r /etc/os-release ] || die "Не удалось определить ОС."
. /etc/os-release
[ "${ID:-}" = "ubuntu" ] || die "Поддерживается Ubuntu (обнаружено: ${PRETTY_NAME:-unknown})."
case "${VERSION_ID:-}" in
  22.04|24.04) c_ok "ОС: ${PRETTY_NAME}" ;;
  *) c_warn "Ubuntu ${VERSION_ID} не тестировалась; будет выбран совместимый runtime." ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) c_warn "Архитектура $(uname -m): защита от торрентов (Suricata runtime) доступна только для amd64." ;;
esac

apt_install() {
  local missing=() pkg
  for pkg in "$@"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || missing+=("$pkg")
  done
  [ ${#missing[@]} -eq 0 ] && return 0
  c_info "Установка пакетов: ${missing[*]}"
  env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=300 update >>"$LOG" 2>&1 || true
  env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends "${missing[@]}" >>"$LOG" 2>&1 \
    || die "apt-get install ${missing[*]} завершился ошибкой"
}

apt_install python3 ca-certificates curl openssl iproute2 zstd python3-yaml

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  c_ok "Docker доступен"
else
  c_warn "Docker недоступен: агент установится, но защита заработает после запуска RemnaNode."
fi

WORK="$(mktemp -d /tmp/ezhik-agent.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
printf '%s\n' "$CA_PEM" >"$WORK/ca.pem"

fetch() {
  curl -fsSL --retry 3 --connect-timeout 15 --pinnedpubkey "$PIN" -k "$PANEL_URL$1" -o "$2" >>"$LOG" 2>&1
}

c_info "Загрузка агента $AGENT_VERSION с панели"
fetch /agent/v1/bootstrap/agent.sha256 "$WORK/agent.sha256" || die "Панель $PANEL_URL недоступна (проверьте порт и фаервол)."
fetch /agent/v1/bootstrap/agent.tar.gz "$WORK/agent.tar.gz" || die "Не удалось скачать пакет агента."
EXPECTED="$(awk '{print $1}' "$WORK/agent.sha256")"
VERSION="$(awk '{print $2}' "$WORK/agent.sha256")"
ACTUAL="$(sha256sum "$WORK/agent.tar.gz" | awk '{print $1}')"
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "Контрольная сумма пакета агента не совпадает."
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.]+)?$ ]] || die "Некорректная версия агента: $VERSION"
if tar -tzf "$WORK/agent.tar.gz" | grep -qE '(^/|(^|/)\.\.(/|$))'; then die "Небезопасные пути в архиве."; fi

install -d -m 0755 "$APP_DIR/releases"
install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR"
RELEASE="$APP_DIR/releases/$VERSION"
rm -rf "$RELEASE.tmp"; mkdir -p "$RELEASE.tmp"
tar -xzf "$WORK/agent.tar.gz" -C "$RELEASE.tmp" --no-same-owner
python3 -m compileall -q "$RELEASE.tmp/ezhik_agent" >>"$LOG" 2>&1 || die "Агент не компилируется системным Python $(python3 -V 2>&1)."
rm -rf "$RELEASE"; mv "$RELEASE.tmp" "$RELEASE"
if [ -L "$APP_DIR/current" ] && [ "$(readlink -f "$APP_DIR/current")" != "$RELEASE" ]; then
  ln -sfn "$(readlink "$APP_DIR/current")" "$APP_DIR/previous"
fi
ln -sfn "releases/$VERSION" "$APP_DIR/current"
c_ok "Агент $VERSION распакован"

export PYTHONPATH="$APP_DIR/current"
if [ -s "$CONFIG_DIR/agent.json" ] && [ "$FORCE_REGISTER" -eq 0 ]; then
  c_ok "Нода уже зарегистрирована — регистрационные данные сохранены (обновление)."
else
  [ -n "$TOKEN" ] || die "Нужен --token (скопируйте команду установки из панели)."
  REG_ARGS=(register --panel "$PANEL_URL" --token "$TOKEN" --ca-file "$WORK/ca.pem")
  [ -n "$NAME" ] && REG_ARGS+=(--name "$NAME")
  [ "$FORCE_REGISTER" -eq 1 ] && REG_ARGS+=(--force)
  python3 -m ezhik_agent "${REG_ARGS[@]}" 2>>"$LOG" || die "Регистрация отклонена панелью (токен устарел или уже использован?)."
  c_ok "Нода зарегистрирована в панели"
fi

python3 -c 'from ezhik_agent import units; units.sync()' >>"$LOG" 2>&1 || die "Не удалось записать systemd-юниты."
systemctl daemon-reload
systemctl enable ezhik-guard-agent.service >>"$LOG" 2>&1
MARK="$(date +%s)"
systemctl restart ezhik-guard-agent.service

c_info "Ожидание первой синхронизации с панелью..."
for _ in $(seq 1 60); do
  if [ -s "$STATE_DIR/desired.json" ] && [ "$(stat -c %Y "$STATE_DIR/desired.json")" -ge "$MARK" ]; then
    c_ok "Конфигурация получена от панели"
    break
  fi
  if ! systemctl is-active --quiet ezhik-guard-agent.service; then
    journalctl -u ezhik-guard-agent.service -n 30 --no-pager >&2 || true
    die "Агент не запустился."
  fi
  sleep 1
done
[ -s "$STATE_DIR/desired.json" ] || c_warn "Агент работает, но ещё не получил конфигурацию; проверьте связь с панелью."

cat <<DONE

============================================================
 Ezhik Guard agent $VERSION установлен
============================================================
 Панель     : $PANEL_URL
 Сервис     : ezhik-guard-agent (systemctl status ezhik-guard-agent)
 Журнал     : journalctl -fu ezhik-guard-agent

 Если на сервере была старая версия Torrent Guard, агент сам
 удалит её компоненты (конфигурация сохраняется в архив
 /var/backups/ezhik-guard/agent) и передаст панели активные
 блокировки. Дальнейшая настройка — в веб-интерфейсе панели.
============================================================
DONE
