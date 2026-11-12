#!/usr/bin/env bash
# =============================================================================
#  Nginx Manager — автоматическое обновление
#
#  sudo ./update.sh                         обновить из каталога, где лежит этот скрипт
#  sudo ./update.sh --source /tmp/nm-1.1.0  обновить из распакованного архива новой версии
#  sudo ./update.sh --archive nm-1.1.0.tar.gz
#
#  Порядок: резервная копия (БД + настройки + код) → остановка → замена кода → зависимости →
#           миграция БД → запуск → проверка → применение конфигурации. При сбое — автоматический откат.
# =============================================================================
set -uo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=packaging/common.sh
. "$SELF_DIR/packaging/common.sh"

SRC=""; ARCHIVE=""; DO_BACKUP=1; DO_APPLY=1; ASSUME_YES=0; FORCE=0; WHEELS_DIR=""
usage() {
  cat <<EOF
Использование: sudo $0 [параметры]
  --source DIR      каталог с новой версией (по умолчанию — каталог скрипта)
  --archive FILE    архив .tar.gz с новой версией
  --wheels DIR      офлайн-установка зависимостей из каталога wheel-файлов
  --no-backup       не создавать резервную копию (не рекомендуется)
  --no-apply        не переприменять конфигурацию nginx после обновления
  --with-geoip      установить поддержку GeoIP (пакет maxminddb), если её ещё нет
  --force           обновить, даже если версия не новее
  -y, --yes         не задавать вопросов
EOF
}
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SRC="$2"; shift ;;
    --archive) ARCHIVE="$2"; shift ;;
    --wheels) WHEELS_DIR="$2"; shift ;;
    --no-backup) DO_BACKUP=0 ;;
    --no-apply) DO_APPLY=0 ;;
    --with-geoip) WITH_GEOIP=1 ;;
    --force) FORCE=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "Неизвестный параметр: $1" ;;
  esac
  shift
done
require_root "$@"
umask 022
log "=== update $(date -Is) ==="
[ -d "$INSTALL_DIR/app" ] || fail "Nginx Manager не установлен ($INSTALL_DIR). Используйте install.sh"

if [ -n "$ARCHIVE" ]; then
  [ -f "$ARCHIVE" ] || fail "Архив не найден: $ARCHIVE"
  TMP=$(mktemp -d); tar -xzf "$ARCHIVE" -C "$TMP" || fail "Не удалось распаковать $ARCHIVE"
  SRC="$(dirname "$(find "$TMP" -maxdepth 3 -name VERSION -type f | head -1)")"
  [ -d "$SRC/app" ] || fail "В архиве нет каталога app/"
fi
SRC="${SRC:-$SELF_DIR}"
SRC="$(cd "$SRC" && pwd)"
[ -f "$SRC/VERSION" ] && [ -d "$SRC/app" ] || fail "В $SRC нет новой версии (нужны VERSION и app/)"

OLD="$(installed_version)"; NEW="$(cat "$SRC/VERSION")"
printf '\n%sОбновление Nginx Manager: %s → %s%s\n\n' "$C_B" "$OLD" "$NEW" "$C_0"
if [ "$SRC" = "$INSTALL_DIR" ]; then
  info "Источник совпадает с установленным каталогом — будут переустановлены зависимости и перезапущен сервис"
elif [ "$FORCE" = 0 ] && [ "$(printf '%s\n%s\n' "$OLD" "$NEW" | sort -V | tail -1)" = "$OLD" ] && [ "$OLD" != "$NEW" ]; then
  fail "Устанавливаемая версия $NEW не новее текущей $OLD (используйте --force)"
fi
detect_os
PORT="$(panel_port)"
TS="$(date +%Y%m%d-%H%M%S)"
CODE_BACKUP="$DATA_DIR/backups/code-$OLD-$TS.tar.gz"

# -----------------------------------------------------------------------------
if [ "$DO_BACKUP" = 1 ]; then
  step "Резервное копирование"
  mkdir -p "$DATA_DIR/backups"
  if /usr/local/bin/nmctl backup >>"$LOG_FILE" 2>&1; then ok "копия базы и настроек: $DATA_DIR/backups"; else warn "nmctl backup не выполнен — копируется файл БД"; cp -a "$DATA_DIR/nginx-manager.db" "$DATA_DIR/backups/nginx-manager-$TS-preupdate.db" 2>/dev/null || true; fi
  tar -czf "$CODE_BACKUP" -C "$INSTALL_DIR" --exclude=venv --exclude='__pycache__' . 2>>"$LOG_FILE" || fail "не удалось сохранить код текущей версии"
  ok "копия кода: $CODE_BACKUP"
  cp -a "$NGINX_CONF" "$DATA_DIR/backups/nginx.conf-$TS" 2>/dev/null || true
fi

rollback() {
  warn "ОТКАТ к версии $OLD"
  service_stop
  if [ -f "$CODE_BACKUP" ]; then
    for d in app web docs tools packaging; do rm -rf "${INSTALL_DIR:?}/$d"; done
    tar -xzf "$CODE_BACKUP" -C "$INSTALL_DIR" && ok "код версии $OLD восстановлен"
    "$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt" >>"$LOG_FILE" 2>&1 || true
  fi
  service_start
  wait_healthy "$PORT" 40 && ok "сервис версии $OLD работает" || warn "сервис не отвечает — см. journalctl -u nginx-manager"
  fail "Обновление не выполнено. Подробности: $LOG_FILE"
}

# -----------------------------------------------------------------------------
step "Остановка сервиса"
service_stop
ok "остановлен"

step "Замена кода"
if [ "$SRC" != "$INSTALL_DIR" ]; then
  for d in app web docs tools packaging; do
    rm -rf "${INSTALL_DIR:?}/$d"
    [ -d "$SRC/$d" ] && cp -a "$SRC/$d" "$INSTALL_DIR/$d"
  done
  for f in VERSION requirements.txt requirements-optional.txt install.sh update.sh uninstall.sh README.md LICENSE; do
    [ -f "$SRC/$f" ] && cp -a "$SRC/$f" "$INSTALL_DIR/$f"
  done
  chmod 755 "$INSTALL_DIR"/*.sh
fi
find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
ok "файлы версии $NEW скопированы"

step "Зависимости Python"
PIP_OPTS="-q --disable-pip-version-check"
[ -n "$WHEELS_DIR" ] && PIP_OPTS="$PIP_OPTS --no-index --find-links $WHEELS_DIR"
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
  PY="$(find_python)" || rollback
  run "$PY" -m venv "$INSTALL_DIR/venv" || rollback
fi
retry 3 run "$INSTALL_DIR/venv/bin/pip" install $PIP_OPTS --upgrade -r "$INSTALL_DIR/requirements.txt" || rollback
if [ "${WITH_GEOIP:-0}" = 1 ] || "$INSTALL_DIR/venv/bin/python" -c 'import maxminddb' 2>/dev/null \
    || ls "${DATA_DIR:-/var/lib/nginx-manager}"/geoip/*.mmdb >/dev/null 2>&1; then
  run "$INSTALL_DIR/venv/bin/pip" install $PIP_OPTS --upgrade -r "$INSTALL_DIR/requirements-optional.txt" || true
fi
"$INSTALL_DIR/venv/bin/python" -c 'import fastapi, uvicorn, psutil, pydantic' 2>>"$LOG_FILE" || rollback
ok "зависимости обновлены"

step "Системные файлы"
install -m 0755 "$INSTALL_DIR/packaging/nmctl" /usr/local/bin/nmctl
install -m 0644 "$INSTALL_DIR/packaging/logrotate" /etc/logrotate.d/nginx-manager
if has_systemd; then
  install -m 0644 "$INSTALL_DIR/packaging/nginx-manager.service" "$UNIT_FILE"
  mkdir -p /etc/systemd/system/nginx.service.d
  install -m 0644 "$INSTALL_DIR/packaging/nginx-limits.conf" /etc/systemd/system/nginx.service.d/nginx-manager.conf
  systemctl daemon-reload
fi
ok "юнит systemd, nmctl, logrotate обновлены"

step "Миграция базы данных"
if "$INSTALL_DIR/venv/bin/python" -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from app.config import settings
from app.db import Database
db = Database(settings.db_path)
print('схема БД версии', db.schema_version)
" >>"$LOG_FILE" 2>&1; then ok "схема БД актуальна"; else rollback; fi

step "Запуск"
service_start
wait_healthy "$PORT" 60 || rollback
ok "панель версии $NEW работает"

if [ "$DO_APPLY" = 1 ]; then
  step "Применение конфигурации (генератор новой версии)"
  if /usr/local/bin/nmctl apply -m "Обновление до $NEW" >>"$LOG_FILE" 2>&1; then
    ok "конфигурация nginx перегенерирована и применена"
  else
    warn "конфигурация не применена — nginx продолжает работать с предыдущей. Подробности: nmctl apply"
  fi
fi

step "Проверка"
/usr/local/bin/nmctl diag --problems 2>>"$LOG_FILE" | tail -n 25 || true
printf '\n%s%sОбновление до %s завершено.%s Резервная копия кода: %s\n\n' "$C_GRN" "$C_B" "$NEW" "$C_0" "$CODE_BACKUP"
exit 0
