#!/usr/bin/env bash
# Ezhik Guard — universal panel installer / updater.
#
# The command never changes between releases:
#   bash <(curl -fsSL https://raw.githubusercontent.com/ezhikdev/ezhik-torrent-guard/main/install.sh)
#
# It always installs the latest GitHub release (or --version X.Y.Z), keeps the
# database and settings on update, and rolls back if the new panel fails its
# health check. Nodes are added from the web interface afterwards.
set -Eeuo pipefail

REPO="${EZHIK_REPO:-ezhikdev/ezhik-torrent-guard}"
ASSET="ezhik-guard.tar.gz"
BASE=/opt/ezhik-guard/panel
CONFIG_DIR=/etc/ezhik-guard/panel
DATA_DIR=/var/lib/ezhik-guard/panel
ENV_FILE="$CONFIG_DIR/panel.env"
SERVICE_USER=ezhik-guard
LOG=/var/log/ezhik-guard-install.log

REQUESTED_VERSION=""
BUNDLE=""
ASSUME_YES=0
MODE="install"
WEB_PORT=""
AGENT_PORT=""
PUBLIC_HOST=""
WITH_NODE=0
NODE_NAME=""

c_info() { printf '\033[1;36m[ezhik]\033[0m %s\n' "$*"; }
c_ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()    { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; [ -s "$LOG" ] && { echo "--- $LOG ---" >&2; tail -n 30 "$LOG" >&2; }; exit 1; }

usage() {
  cat <<'USAGE'
Ezhik Guard installer

  install.sh                      install or update the panel (latest release)
  install.sh --version 2.0.0      install a specific release
  install.sh --bundle FILE        install from a local ezhik-guard.tar.gz
  install.sh --with-node [NAME]   also protect this server (install the node agent)
  install.sh --reset-password     print a new password for the admin user
  install.sh --uninstall          remove the panel (keeps /var/lib backup unless --purge)

Options: --yes, --web-port N, --agent-port N, --public-host HOST, --purge
USAGE
}

PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) REQUESTED_VERSION="${2#v}"; shift 2 ;;
    --bundle) BUNDLE="$2"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --agent-port) AGENT_PORT="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    --with-node) WITH_NODE=1; if [ -n "${2:-}" ] && [ "${2#--}" = "$2" ]; then NODE_NAME="$2"; shift; fi; shift ;;
    --reset-password) MODE="reset-password"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --purge) PURGE=1; shift ;;
    --update) MODE="update"; ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1 (см. --help)" ;;
  esac
done

[ "${EUID:-$(id -u)}" -eq 0 ] || die "Запустите от root: sudo bash install.sh"
mkdir -p "$(dirname "$LOG")"; : >"$LOG"; chmod 600 "$LOG"

ask() {  # ask "question" default -> echo answer
  local answer
  if [ "$ASSUME_YES" -eq 1 ] || [ ! -r /dev/tty ]; then printf '%s' "$2"; return; fi
  printf '%s [%s]: ' "$1" "$2" >/dev/tty
  IFS= read -r answer </dev/tty || answer=""
  printf '%s' "${answer:-$2}"
}

confirm() {
  local answer
  if [ "$ASSUME_YES" -eq 1 ] || [ ! -r /dev/tty ]; then return 0; fi
  printf '%s [Y/n]: ' "$1" >/dev/tty
  IFS= read -r answer </dev/tty || answer=""
  case "${answer:-y}" in y|Y|yes|д|Д|да) return 0 ;; *) return 1 ;; esac
}

panel_py() {
  sudo -u "$SERVICE_USER" env EZHIK_PANEL_ENV="$ENV_FILE" PYTHONPATH="$BASE/current/panel" \
    "$BASE/venv/bin/python" -m ezhik_panel "$@"
}

# ------------------------------------------------------------------ modes

if [ "$MODE" = "reset-password" ]; then
  [ -x "$BASE/venv/bin/python" ] || die "Панель не установлена."
  PASSWORD="$(panel_py admin --username admin --reset)" || die "Не удалось сбросить пароль."
  echo "Логин: admin"
  echo "Новый пароль: $PASSWORD"
  exit 0
fi

if [ "$MODE" = "uninstall" ]; then
  c_info "Удаление панели Ezhik Guard"
  systemctl disable --now ezhik-guard-panel.service ezhik-guard-panel-update.path >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/ezhik-guard-panel.service /etc/systemd/system/ezhik-guard-panel-update.path \
        /etc/systemd/system/ezhik-guard-panel-update.service
  systemctl daemon-reload
  if [ -d "$DATA_DIR" ] && [ "$PURGE" -eq 0 ]; then
    mkdir -p /var/backups/ezhik-guard
    BACKUP="/var/backups/ezhik-guard/panel-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$BACKUP" -C / "${DATA_DIR#/}" "${CONFIG_DIR#/}" 2>/dev/null || true
    chmod 600 "$BACKUP"
    c_ok "Резервная копия базы и настроек: $BACKUP"
  fi
  rm -rf "$BASE" "$DATA_DIR" "$CONFIG_DIR"
  rmdir /opt/ezhik-guard /etc/ezhik-guard /var/lib/ezhik-guard 2>/dev/null || true
  c_ok "Панель удалена. Агенты на нодах продолжают работать автономно; удалите их из панели заранее или командой"
  echo "      sudo PYTHONPATH=/opt/ezhik-guard/agent/current python3 -m ezhik_agent uninstall"
  exit 0
fi

cat <<'BANNER'
============================================================
     EZHIK GUARD · защита VPN-нод · панель управления
     Torrent / P2P / port-scan protection + SSL manager
============================================================
BANNER

[ -r /etc/os-release ] || die "Не удалось определить ОС."
# Read os-release in a subshell: it defines VERSION, ID etc. that must not
# leak into the installer's own variables.
OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
OS_PRETTY="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
case "$OS_ID" in
  ubuntu) ;;
  debian) c_warn "Debian не входит в список протестированных ОС панели." ;;
  *) die "Поддерживается Ubuntu 22.04/24.04 (обнаружено $OS_PRETTY)." ;;
esac
c_ok "ОС: $OS_PRETTY"

# ----------------------------------------------------------- dependencies

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

PYV="$(python3 -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || echo "")"
apt_install ca-certificates curl openssl tar python3 sudo
PYV="$(python3 -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "Нужен Python >= 3.10 (найден $PYV)."
# Ubuntu splits venv/ensurepip into a versioned package (python3.12-venv on 24.04).
if ! python3 -c 'import ensurepip, venv' >/dev/null 2>&1; then
  apt_install "python${PYV}-venv" || apt_install python3-venv
fi

# --------------------------------------------------------------- bundle

WORK="$(mktemp -d /tmp/ezhik-guard-install.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$BUNDLE" ]; then
  [ -f "$BUNDLE" ] || die "Файл $BUNDLE не найден."
  cp "$BUNDLE" "$WORK/$ASSET"
  if [ -f "$BUNDLE.sha256" ]; then
    (cd "$WORK" && awk -v f="$ASSET" '{print $1"  "f}' "$BUNDLE.sha256" | sha256sum -c - >>"$LOG" 2>&1) \
      || die "Контрольная сумма $BUNDLE не совпадает."
  fi
else
  if [ -n "$REQUESTED_VERSION" ]; then
    URL="https://github.com/$REPO/releases/download/v$REQUESTED_VERSION/$ASSET"
  else
    URL="https://github.com/$REPO/releases/latest/download/$ASSET"
  fi
  c_info "Загрузка $URL"
  curl -fsSL --retry 3 --connect-timeout 20 "$URL" -o "$WORK/$ASSET" >>"$LOG" 2>&1 || die "Не удалось скачать релиз."
  curl -fsSL --retry 3 --connect-timeout 20 "$URL.sha256" -o "$WORK/$ASSET.sha256" >>"$LOG" 2>&1 || die "Не удалось скачать контрольную сумму."
  (cd "$WORK" && awk -v f="$ASSET" '{print $1"  "f}' "$ASSET.sha256" | sha256sum -c - >>"$LOG" 2>&1) \
    || die "Контрольная сумма релиза не совпадает."
fi
if tar -tzf "$WORK/$ASSET" | grep -qE '(^/|(^|/)\.\.(/|$))'; then die "Небезопасные пути в архиве релиза."; fi
mkdir -p "$WORK/x"
tar -xzf "$WORK/$ASSET" -C "$WORK/x" --no-same-owner
SRC="$WORK/x/ezhik-guard"
[ -f "$SRC/VERSION" ] && [ -d "$SRC/panel/ezhik_panel" ] && [ -f "$SRC/web/index.html" ] || die "Архив релиза повреждён."
NEW_VERSION="$(tr -d '[:space:]' <"$SRC/VERSION")"
OLD_VERSION=""
[ -f "$BASE/current/VERSION" ] && OLD_VERSION="$(tr -d '[:space:]' <"$BASE/current/VERSION")"

if [ -n "$OLD_VERSION" ]; then
  if [ "$OLD_VERSION" = "$NEW_VERSION" ] && [ "$MODE" != "update" ]; then
    c_ok "Установлена актуальная версия $NEW_VERSION"
    confirm "Переустановить (repair)?" || exit 0
  else
    c_info "Обновление панели: $OLD_VERSION → $NEW_VERSION"
    confirm "Продолжить?" || exit 0
  fi
fi

# --------------------------------------------------------- legacy notice

if [ -d /opt/ezhik-torrent-guard ] || [ -f /etc/systemd/system/ezhik-torrent-guard.service ]; then
  c_warn "На этом сервере стоит Torrent Guard 1.x. Он будет полностью удалён автоматически,"
  c_warn "когда вы подключите этот сервер как ноду (--with-node или кнопка «Добавить ноду»)."
fi

# --------------------------------------------------------- user and dirs

id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -m 0755 /opt/ezhik-guard "$BASE" "$BASE/releases"
install -d -m 0750 -o root -g "$SERVICE_USER" /etc/ezhik-guard "$CONFIG_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
chmod 0755 /etc/ezhik-guard

port_free() {
  ! ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .
}

if [ ! -f "$ENV_FILE" ]; then
  DEFAULT_HOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
  PUBLIC_IP="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_IP" ] && DEFAULT_HOST="$PUBLIC_IP"
  PUBLIC_HOST="${PUBLIC_HOST:-$(ask 'Адрес панели для подключения нод (IP или домен)' "$DEFAULT_HOST")}"
  [ -n "$PUBLIC_HOST" ] || die "Нужен адрес панели."
  WEB_PORT="${WEB_PORT:-$(ask 'Порт веб-интерфейса (HTTPS)' 8443)}"
  AGENT_PORT="${AGENT_PORT:-$(ask 'Порт API для агентов нод (HTTPS)' 8444)}"
  for p in "$WEB_PORT" "$AGENT_PORT"; do
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "Некорректный порт: $p"
    port_free "$p" || die "Порт $p уже занят. Укажите другой (--web-port / --agent-port)."
  done
  [ "$WEB_PORT" != "$AGENT_PORT" ] || die "Порты веб-интерфейса и агентов должны различаться."
  umask 027
  cat >"$ENV_FILE" <<ENV
# Ezhik Guard panel
EZHIK_WEB_HOST=0.0.0.0
EZHIK_WEB_PORT=$WEB_PORT
EZHIK_AGENT_HOST=0.0.0.0
EZHIK_AGENT_PORT=$AGENT_PORT
EZHIK_PUBLIC_HOST=$PUBLIC_HOST
EZHIK_DATA_DIR=$DATA_DIR
EZHIK_CONFIG_DIR=$CONFIG_DIR
EZHIK_INSTALL_DIR=$BASE/current
ENV
  chown root:"$SERVICE_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"
  umask 022
fi
WEB_PORT="$(sed -n 's/^EZHIK_WEB_PORT=//p' "$ENV_FILE")"
AGENT_PORT="$(sed -n 's/^EZHIK_AGENT_PORT=//p' "$ENV_FILE")"
PUBLIC_HOST="$(sed -n 's/^EZHIK_PUBLIC_HOST=//p' "$ENV_FILE")"

# ------------------------------------------------------------- release

RELEASE="$BASE/releases/$NEW_VERSION"
rm -rf "$RELEASE.tmp"
cp -a "$SRC" "$RELEASE.tmp"
chown -R root:root "$RELEASE.tmp"
chmod -R u=rwX,go=rX "$RELEASE.tmp"
rm -rf "$RELEASE"; mv "$RELEASE.tmp" "$RELEASE"

# Python environment (rebuilt when the system Python changes, e.g. 22.04 -> 24.04).
VENV="$BASE/venv"
if [ -x "$VENV/bin/python" ] && [ "$("$VENV/bin/python" -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null)" != "$PYV" ]; then
  c_info "Системный Python изменился — пересоздаю окружение"
  rm -rf "$VENV"
fi
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" >>"$LOG" 2>&1 || die "Не удалось создать venv (python3 -m venv)."
fi
c_info "Установка Python-зависимостей панели"
PIP_ARGS=(-m pip install --disable-pip-version-check --no-input -q)
if [ -d "$RELEASE/wheels" ] && ls "$RELEASE/wheels"/*.whl >/dev/null 2>&1; then
  PIP_ARGS+=(--no-index --find-links "$RELEASE/wheels")
fi
"$VENV/bin/python" "${PIP_ARGS[@]}" -r "$RELEASE/panel/requirements.txt" >>"$LOG" 2>&1 \
  || "$VENV/bin/python" -m pip install --disable-pip-version-check --no-input -q -r "$RELEASE/panel/requirements.txt" >>"$LOG" 2>&1 \
  || die "pip install завершился ошибкой."
"$VENV/bin/python" -c 'import fastapi, uvicorn, cryptography, httpx, dns' >>"$LOG" 2>&1 || die "Зависимости панели не импортируются."

PREVIOUS=""
[ -L "$BASE/current" ] && PREVIOUS="$(readlink "$BASE/current")"
ln -sfn "releases/$NEW_VERSION" "$BASE/current"

# --------------------------------------------------------------- systemd

cat >/etc/systemd/system/ezhik-guard-panel.service <<UNIT
[Unit]
Description=Ezhik Guard panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
Environment=EZHIK_PANEL_ENV=$ENV_FILE
Environment=PYTHONPATH=$BASE/current/panel
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=$BASE/current
ExecStart=$VENV/bin/python -m ezhik_panel run
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/ezhik-guard-panel-update.path <<UNIT
[Unit]
Description=Ezhik Guard panel update request watcher

[Path]
PathChanged=$DATA_DIR/update-request.json

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/ezhik-guard-panel-update.service <<UNIT
[Unit]
Description=Ezhik Guard panel self-update

[Service]
Type=oneshot
ExecStart=/bin/bash $BASE/current/packaging/panel-update.sh
UNIT

systemctl daemon-reload
systemctl enable ezhik-guard-panel.service ezhik-guard-panel-update.path >>"$LOG" 2>&1
systemctl restart ezhik-guard-panel.service
systemctl restart ezhik-guard-panel-update.path >>"$LOG" 2>&1 || true

c_info "Проверка запуска панели"
HEALTHY=0
for _ in $(seq 1 40); do
  if curl -fsSk --max-time 3 "https://127.0.0.1:$WEB_PORT/healthz" >/dev/null 2>&1; then HEALTHY=1; break; fi
  sleep 1
done
if [ "$HEALTHY" -ne 1 ]; then
  journalctl -u ezhik-guard-panel.service -n 40 --no-pager >>"$LOG" 2>&1 || true
  if [ -n "$PREVIOUS" ]; then
    c_warn "Новая версия не запустилась — возвращаю $PREVIOUS"
    ln -sfn "$PREVIOUS" "$BASE/current"
    systemctl restart ezhik-guard-panel.service || true
  fi
  die "Панель не ответила на /healthz. Журнал: journalctl -u ezhik-guard-panel"
fi
c_ok "Панель $NEW_VERSION работает"

# Keep the two newest releases plus the active one.
ls -1dt "$BASE"/releases/*/ 2>/dev/null | tail -n +4 | while read -r old; do
  [ "$(readlink -f "$BASE/current")" = "$(readlink -f "$old")" ] || rm -rf "$old"
done

PASSWORD=""
if ! panel_py has-admin >/dev/null 2>&1; then
  PASSWORD="$(panel_py admin --username admin)" || die "Не удалось создать администратора."
fi

if [ "$WITH_NODE" -eq 1 ]; then
  c_info "Подключение этого сервера как ноды"
  CMD="$(panel_py create-node --name "${NODE_NAME:-$(hostname -s)}" 2>>"$LOG")" || die "Не удалось создать ноду."
  bash -c "$CMD" || c_warn "Установка агента на этом сервере завершилась с ошибкой (см. выше)."
fi

FPR="$(panel_py info 2>/dev/null | sed -n 's/^ca_fingerprint=//p')"
cat <<DONE

============================================================
 Ezhik Guard $NEW_VERSION готов
============================================================
 Веб-интерфейс : https://$PUBLIC_HOST:$WEB_PORT
DONE
if [ -n "$PASSWORD" ]; then
  cat <<DONE
 Логин         : admin
 Пароль        : $PASSWORD   (смените в «Настройки → Безопасность»)
DONE
fi
cat <<DONE
 API агентов   : https://$PUBLIC_HOST:$AGENT_PORT
 CA панели     : ${FPR:0:16}…

 Сертификат веб-интерфейса самоподписанный — браузер покажет
 предупреждение. Выпустите сертификат во вкладке «Сертификаты»
 и назначьте его панели в «Настройки → Панель».

 Обновление    : кнопка в «Настройки → Обновления» или повтор этой команды
 Сброс пароля  : bash <(curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh) --reset-password
 Журнал        : journalctl -fu ezhik-guard-panel
============================================================
DONE
