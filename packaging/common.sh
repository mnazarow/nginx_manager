#!/usr/bin/env bash
# shellcheck disable=SC2034  # переменные используются в install.sh / update.sh / uninstall.sh
# Общие функции скриптов установки/обновления/удаления Nginx Manager.

APP_NAME="nginx-manager"
INSTALL_DIR="/opt/nginx-manager"
CONF_DIR="/etc/nginx-manager"
DATA_DIR="/var/lib/nginx-manager"
LOG_FILE="/var/log/nginx-manager-setup.log"
UNIT_FILE="/etc/systemd/system/nginx-manager.service"
NGINX_CONF="/etc/nginx/nginx.conf"
MANAGED_DIR="/etc/nginx/nginx-manager"

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_B=""; C_0=""
fi

log()   { printf '%s\n' "$*" >>"$LOG_FILE" 2>/dev/null || true; }
step()  { printf '%s==>%s %s%s%s\n' "$C_BLU" "$C_0" "$C_B" "$*" "$C_0"; log "==> $*"; }
info()  { printf '    %s\n' "$*"; log "    $*"; }
ok()    { printf '    %s✓%s %s\n' "$C_GRN" "$C_0" "$*"; log "    OK $*"; }
warn()  { printf '    %s!%s %s\n' "$C_YEL" "$C_0" "$*" >&2; log "    WARN $*"; }
fail()  { printf '%s✗ %s%s\n' "$C_RED" "$*" "$C_0" >&2; log "FAIL $*"; exit 1; }

# Выполнить команду с записью вывода в журнал; при ошибке — показать хвост вывода
run() {
  log "+ $*"
  local out rc
  out=$("$@" 2>&1); rc=$?
  printf '%s\n' "$out" >>"$LOG_FILE" 2>/dev/null || true
  if [ $rc -ne 0 ]; then
    printf '%s    команда завершилась с кодом %s: %s%s\n' "$C_RED" "$rc" "$*" "$C_0" >&2
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/      /' >&2
  fi
  return $rc
}

retry() {  # retry <попыток> <команда...>
  local n=$1; shift; local i=1
  while true; do
    "$@" && return 0
    [ $i -ge "$n" ] && return 1
    warn "попытка $i не удалась, повтор через $((i * 5)) с…"; sleep $((i * 5)); i=$((i + 1))
  done
}

require_root() { [ "$(id -u)" -eq 0 ] || fail "Запустите от root: sudo $0 $*"; }

confirm() {  # confirm "вопрос" -> 0/1 ; учитывает ASSUME_YES
  [ "${ASSUME_YES:-0}" = 1 ] && return 0
  [ -t 0 ] || return 1
  local a; printf '%s [y/N]: ' "$1"; read -r a
  case "$a" in y|Y|yes|Yes|да|Да|д|Д) return 0 ;; *) return 1 ;; esac
}

detect_os() {
  [ -r /etc/os-release ] || fail "Не удалось определить ОС (/etc/os-release отсутствует)"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"; OS_LIKE="${ID_LIKE:-}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
  OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) PKG=apt ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) PKG=dnf; command -v dnf >/dev/null 2>&1 || PKG=yum ;;
    *" suse "*|*" opensuse "*|*" sles "*) PKG=zypper ;;
    *) PKG=unknown ;;
  esac
  OS_MAJOR="${OS_VER%%.*}"
}

has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive run apt-get install -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
    dnf) run dnf install -y -q "$@" ;;
    yum) run yum install -y -q "$@" ;;
    zypper) run zypper --non-interactive install "$@" ;;
    *) return 1 ;;
  esac
}

pkg_installed() {
  case "$PKG" in
    apt) dpkg -s "$1" >/dev/null 2>&1 ;;
    dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

find_python() {  # выбрать интерпретатор Python >= 3.9
  local c
  for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null 2>&1; then
      if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        command -v "$c"; return 0
      fi
    fi
  done
  return 1
}

panel_port() {
  local p
  p=$(grep -E '^(NM_)?BIND_PORT=' "$CONF_DIR/panel.conf" 2>/dev/null | tail -1 | cut -d= -f2)
  echo "${p:-8088}"
}

wait_healthy() {  # wait_healthy <порт> <секунд>
  local port=$1 t=${2:-40} i=0
  while [ $i -lt "$t" ]; do
    if curl -fsS --max-time 2 --noproxy '*' "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}

server_ips() {
  { ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1; } | head -5
}

service_start() {
  if has_systemd; then
    run systemctl daemon-reload
    run systemctl enable --now nginx-manager.service
  else
    warn "systemd не обнаружен (контейнер?) — сервис запускается в фоне без автозапуска"
    pkill -f "$INSTALL_DIR/venv/bin/python -m app.main" 2>/dev/null || true
    cd "$INSTALL_DIR" || return 1
    if setsid -f true 2>/dev/null; then
      setsid -f nohup "$INSTALL_DIR/venv/bin/python" -m app.main >>/var/log/nginx-manager.log 2>&1 </dev/null
    else
      nohup "$INSTALL_DIR/venv/bin/python" -m app.main >>/var/log/nginx-manager.log 2>&1 </dev/null &
      disown 2>/dev/null || true
    fi
    cd - >/dev/null || true
  fi
}

service_stop() {
  if has_systemd; then
    systemctl stop nginx-manager.service 2>/dev/null || true
  else
    pkill -f "$INSTALL_DIR/venv/bin/python -m app.main" 2>/dev/null || true
  fi
  sleep 1
}

installed_version() { cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo "нет"; }
