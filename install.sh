#!/usr/bin/env bash
# =============================================================================
#  Nginx Manager — полностью автоматическая установка
#
#  Поддерживаемые ОС: Debian 11/12/13, Ubuntu 20.04/22.04/24.04+,
#                     RHEL/Rocky/AlmaLinux/Oracle 8/9/10, CentOS Stream, Fedora.
#
#  Быстрый старт:      sudo ./install.sh
#  Без вопросов:       sudo ./install.sh --yes --admin-password 'S3cure!pass' --le-email admin@example.com
#  Справка:            ./install.sh --help
#
#  Повторный запуск безопасен: работает как «восстановление» — данные и настройки сохраняются.
# =============================================================================
set -uo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=packaging/common.sh
. "$SRC_DIR/packaging/common.sh"

BIND_HOST="0.0.0.0"
BIND_PORT="8088"
ADMIN_USER="admin"
ADMIN_PASS=""
LE_EMAIL=""
NGINX_REPO="distro"        # distro | stable | mainline
OPEN_FIREWALL=1
OPEN_PANEL_PORT=0
WITH_GEOIP=0
WHEELS_DIR=""
SKIP_APPLY=0
SKIP_START=0
ASSUME_YES=0
PYTHON_BIN=""

usage() {
  cat <<EOF
Использование: sudo $0 [параметры]

  --port N              порт веб-панели (по умолчанию 8088)
  --bind ADDR           адрес панели: 0.0.0.0 (все) или 127.0.0.1 (только локально / через домен панели)
  --admin-user NAME     имя администратора (по умолчанию admin)
  --admin-password PW   пароль администратора (по умолчанию генерируется случайный)
  --le-email EMAIL      e-mail для Let's Encrypt
  --nginx-repo REPO     distro (по умолчанию) | stable | mainline — пакеты nginx.org
  --no-firewall         не открывать порты 80/443 в ufw/firewalld
  --open-panel-port     открыть порт панели в firewall (по умолчанию закрыт)
  --with-geoip          установить поддержку GeoIP (пакет maxminddb)
  --wheels DIR          офлайн-установка Python-зависимостей из каталога с wheel-файлами
  --python PATH         использовать указанный интерпретатор Python (>= 3.9)
  --no-apply            не применять конфигурацию nginx при установке
  --no-start            не запускать сервис
  -y, --yes             не задавать вопросов
  -h, --help            эта справка
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port) BIND_PORT="$2"; shift ;;
    --bind) BIND_HOST="$2"; shift ;;
    --admin-user) ADMIN_USER="$2"; shift ;;
    --admin-password) ADMIN_PASS="$2"; shift ;;
    --le-email) LE_EMAIL="$2"; shift ;;
    --nginx-repo) NGINX_REPO="$2"; shift ;;
    --no-firewall) OPEN_FIREWALL=0 ;;
    --open-panel-port) OPEN_PANEL_PORT=1 ;;
    --with-geoip) WITH_GEOIP=1 ;;
    --wheels) WHEELS_DIR="$2"; shift ;;
    --python) PYTHON_BIN="$2"; shift ;;
    --no-apply) SKIP_APPLY=1 ;;
    --no-start) SKIP_START=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "Неизвестный параметр: $1" ;;
  esac
  shift
done

require_root "$@"
umask 022
: >"$LOG_FILE" 2>/dev/null || LOG_FILE=/tmp/nginx-manager-setup.log
log "=== install $(date -Is) ==="
VERSION_NEW="$(cat "$SRC_DIR/VERSION" 2>/dev/null || echo dev)"
printf '\n%sNginx Manager %s — установка%s\n' "$C_B" "$VERSION_NEW" "$C_0"
printf 'Журнал установки: %s\n\n' "$LOG_FILE"

case "$BIND_PORT" in ''|*[!0-9]*) fail "Неверный порт: $BIND_PORT" ;; esac
[ "$BIND_PORT" -ge 1 ] && [ "$BIND_PORT" -le 65535 ] || fail "Порт вне диапазона: $BIND_PORT"
case "$NGINX_REPO" in distro|stable|mainline) ;; *) fail "--nginx-repo: distro | stable | mainline" ;; esac

# -----------------------------------------------------------------------------
step "Проверка системы"
detect_os
info "ОС: $OS_NAME (менеджер пакетов: $PKG)"
[ "$PKG" != unknown ] || fail "Неподдерживаемая ОС. Нужны Debian/Ubuntu или RHEL-совместимая система."
ARCH="$(uname -m)"; info "Архитектура: $ARCH"
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
[ "$MEM_MB" -lt 400 ] && warn "Мало памяти (${MEM_MB} МБ): рекомендуется не менее 512 МБ"
FREE_MB=$(df -Pm / | awk 'NR==2 {print $4}')
[ "${FREE_MB:-0}" -lt 500 ] && fail "Недостаточно места на диске: ${FREE_MB} МБ свободно, нужно не менее 500 МБ"
if [ -d "$INSTALL_DIR" ]; then
  info "Обнаружена установленная версия $(installed_version) — будет выполнено восстановление/переустановка с сохранением данных"
fi
# Конфликт порта панели
if command -v ss >/dev/null 2>&1 && ss -ltnH "sport = :$BIND_PORT" 2>/dev/null | grep -q .; then
  if ! ss -ltnpH "sport = :$BIND_PORT" 2>/dev/null | grep -q "python"; then
    fail "Порт $BIND_PORT уже занят другой программой: $(ss -ltnpH "sport = :$BIND_PORT" | head -1). Укажите другой: --port N"
  fi
fi
ok "система подходит"

# -----------------------------------------------------------------------------
step "Установка пакетов"
add_nginx_org_repo() {
  local branch="$1"
  case "$PKG" in
    apt)
      pkg_install curl gnupg2 ca-certificates lsb-release || return 1
      local distro="debian"; case " $OS_ID $OS_LIKE " in *" ubuntu "*) distro="ubuntu" ;; esac
      local path="packages"; [ "$branch" = mainline ] && path="packages/mainline"
      run curl -fsSL https://nginx.org/keys/nginx_signing.key -o /tmp/nginx_signing.key || return 1
      gpg --dearmor </tmp/nginx_signing.key >/usr/share/keyrings/nginx-archive-keyring.gpg 2>>"$LOG_FILE" || return 1
      echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/$path/$distro ${OS_CODENAME} nginx" \
        >/etc/apt/sources.list.d/nginx.list
      printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n' >/etc/apt/preferences.d/99nginx
      ;;
    dnf|yum)
      local os="centos"; [ "$OS_ID" = fedora ] && { warn "Для Fedora используется пакет nginx дистрибутива"; return 1; }
      cat >/etc/yum.repos.d/nginx.repo <<REPO
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/$os/\$releasever/\$basearch/
gpgcheck=1
enabled=$([ "$branch" = stable ] && echo 1 || echo 0)
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
skip_if_unavailable=1

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/$os/\$releasever/\$basearch/
gpgcheck=1
enabled=$([ "$branch" = mainline ] && echo 1 || echo 0)
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
skip_if_unavailable=1
REPO
      ;;
    *) return 1 ;;
  esac
}

case "$PKG" in
  apt)
    retry 3 run apt-get update -q || fail "apt-get update не выполнен — проверьте сеть и источники пакетов"
    if [ "$NGINX_REPO" != distro ]; then
      if add_nginx_org_repo "$NGINX_REPO"; then retry 3 run apt-get update -q; ok "подключён репозиторий nginx.org ($NGINX_REPO)"
      else warn "не удалось подключить nginx.org — будет установлен nginx из дистрибутива"; NGINX_REPO=distro; fi
    fi
    BASE_PKGS="nginx openssl curl ca-certificates logrotate python3 python3-venv python3-pip iproute2 procps"
    retry 2 pkg_install $BASE_PKGS || fail "не удалось установить пакеты: $BASE_PKGS"
    if [ "$NGINX_REPO" = distro ]; then
      pkg_install libnginx-mod-stream || warn "пакет libnginx-mod-stream недоступен — TCP/UDP-потоки будут отключены"
    fi
    pkg_install certbot || warn "certbot не установлен — выпуск Let's Encrypt будет недоступен"
    ;;
  dnf|yum)
    if [ "$OS_ID" != fedora ] && ! pkg_installed epel-release && ! pkg_installed "oracle-epel-release-el$OS_MAJOR"; then
      # EPEL (certbot): в Rocky/Alma — пакет epel-release, в Oracle Linux — oracle-epel-release-elN,
      # в RHEL пакета в репозиториях нет — ставим из Fedora Project
      case "$OS_ID" in
        ol) pkg_install "oracle-epel-release-el$OS_MAJOR" ;;
        *) pkg_install epel-release || pkg_install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$OS_MAJOR.noarch.rpm" ;;
      esac || warn "EPEL недоступен (certbot может не установиться)"
    fi
    if [ "$NGINX_REPO" != distro ]; then
      if add_nginx_org_repo "$NGINX_REPO"; then ok "подключён репозиторий nginx.org ($NGINX_REPO)"
      else NGINX_REPO=distro; fi
    fi
    BASE_PKGS="nginx openssl curl ca-certificates logrotate python3 iproute procps-ng"
    retry 2 pkg_install $BASE_PKGS || fail "не удалось установить пакеты: $BASE_PKGS"
    if [ "$NGINX_REPO" = distro ]; then
      pkg_install nginx-mod-stream || warn "nginx-mod-stream недоступен — TCP/UDP-потоки будут отключены"
    fi
    if ! find_python >/dev/null; then
      info "Python 3 старше 3.9 — устанавливаем python3.11/python39"
      pkg_install python3.11 || pkg_install python39 || fail "не удалось установить Python >= 3.9"
    fi
    pkg_install certbot || warn "certbot не установлен — выпуск Let's Encrypt будет недоступен"
    ;;
  zypper)
    retry 2 pkg_install nginx openssl curl logrotate python3 python3-pip iproute2 || fail "не удалось установить пакеты"
    pkg_install python3-certbot certbot || warn "certbot не установлен"
    ;;
esac
command -v nginx >/dev/null 2>&1 || [ -x /usr/sbin/nginx ] || fail "nginx не установлен"
ok "nginx: $(nginx -v 2>&1 | sed 's/^nginx version: //')"
if command -v certbot >/dev/null 2>&1 && certbot --version >/dev/null 2>&1; then ok "certbot: $(certbot --version 2>&1 | head -1)"
else warn "certbot не работает — выпуск Let's Encrypt будет недоступен (Диагностика предложит установку)"; fi

# -----------------------------------------------------------------------------
step "Python-окружение"
if [ -z "$PYTHON_BIN" ]; then PYTHON_BIN="$(find_python)" || fail "Не найден Python >= 3.9"; fi
info "интерпретатор: $PYTHON_BIN ($("$PYTHON_BIN" -V 2>&1))"
mkdir -p "$INSTALL_DIR"
# копирование кода (venv и данные не трогаем)
if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
  for d in app web docs tools packaging; do
    rm -rf "${INSTALL_DIR:?}/$d"
    [ -d "$SRC_DIR/$d" ] && cp -a "$SRC_DIR/$d" "$INSTALL_DIR/$d"
  done
  for f in VERSION requirements.txt requirements-optional.txt install.sh update.sh uninstall.sh README.md LICENSE; do
    [ -f "$SRC_DIR/$f" ] && cp -a "$SRC_DIR/$f" "$INSTALL_DIR/$f"
  done
fi
find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
chmod 755 "$INSTALL_DIR"/*.sh 2>/dev/null || true
if [ ! -x "$INSTALL_DIR/venv/bin/python" ] || ! "$INSTALL_DIR/venv/bin/python" -c 'import sys' 2>/dev/null; then
  rm -rf "$INSTALL_DIR/venv"
  run "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv" || fail "не удалось создать venv (Debian/Ubuntu: apt install python3-venv)"
fi
PIP="$INSTALL_DIR/venv/bin/pip"
PIP_OPTS="-q --disable-pip-version-check"
if [ -n "$WHEELS_DIR" ]; then
  PIP_OPTS="$PIP_OPTS --no-index --find-links $WHEELS_DIR"
else
  retry 2 run "$PIP" install $PIP_OPTS --upgrade pip wheel || warn "не удалось обновить pip"
fi
retry 3 run "$PIP" install $PIP_OPTS -r "$INSTALL_DIR/requirements.txt" || fail "не удалось установить Python-зависимости (см. $LOG_FILE). Для офлайн-установки используйте --wheels"
# база GeoIP уже есть (переустановка, перенос) — без пакета maxminddb перестали бы работать статистика по странам
# и доступ к сайтам по странам, поэтому ставим его сами
if [ "$WITH_GEOIP" = 0 ] && ls "$DATA_DIR"/geoip/*.mmdb >/dev/null 2>&1; then
  info "найдена база GeoIP в $DATA_DIR/geoip — будет установлен пакет maxminddb"
  WITH_GEOIP=1
fi
if [ "$WITH_GEOIP" = 1 ]; then
  run "$PIP" install $PIP_OPTS -r "$INSTALL_DIR/requirements-optional.txt" && ok "maxminddb установлен" || warn "maxminddb не установлен"
fi
"$INSTALL_DIR/venv/bin/python" -c 'import fastapi, uvicorn, psutil, pydantic' 2>>"$LOG_FILE" || fail "зависимости не импортируются"
ok "зависимости установлены"

# -----------------------------------------------------------------------------
step "Каталоги и конфигурация"
mkdir -p "$CONF_DIR" "$DATA_DIR"/{backups,certs,acme/.well-known/acme-challenge,geoip} "$MANAGED_DIR" /var/cache/nginx/nginx-manager /var/log/nginx
chmod 700 "$CONF_DIR" "$DATA_DIR/certs" "$DATA_DIR/backups"
chmod 711 "$DATA_DIR"
chmod -R 755 "$DATA_DIR/acme"
if [ ! -f "$CONF_DIR/panel.conf" ]; then
  cat >"$CONF_DIR/panel.conf" <<EOF
# Nginx Manager — параметры запуска сервиса (после изменения: systemctl restart nginx-manager)
# Остальные настройки — в веб-панели.
NM_BIND_HOST=$BIND_HOST
NM_BIND_PORT=$BIND_PORT
NM_DATA_DIR=$DATA_DIR
NM_NGINX_CONF=$NGINX_CONF
NM_MANAGED_DIR=$MANAGED_DIR
NM_LOG_DIR=/var/log/nginx
NM_CACHE_DIR=/var/cache/nginx/nginx-manager
NM_STUB_STATUS_PORT=8089
NM_LOG_LEVEL=info
# HTTPS для самой панели (необязательно; удобнее — домен панели через nginx):
# NM_TLS_CERT=/path/fullchain.pem
# NM_TLS_KEY=/path/privkey.pem
# Доверенные прокси для определения IP клиента панели:
NM_TRUST_PROXY=127.0.0.1,::1
EOF
  chmod 600 "$CONF_DIR/panel.conf"
  ok "создан $CONF_DIR/panel.conf"
else
  info "$CONF_DIR/panel.conf сохранён без изменений"
  BIND_PORT="$(panel_port)"
fi
# Пользователь воркеров nginx — права на кэш
NGX_USER="$(id -u www-data >/dev/null 2>&1 && echo www-data || (id -u nginx >/dev/null 2>&1 && echo nginx || echo nobody))"
chown "$NGX_USER" /var/cache/nginx/nginx-manager 2>/dev/null || true
# Резервная копия исходного nginx.conf (один раз)
if [ -f "$NGINX_CONF" ] && [ ! -f "$NGINX_CONF.nm-orig" ] && ! grep -q "NGINX-MANAGER" "$NGINX_CONF"; then
  cp -a "$NGINX_CONF" "$NGINX_CONF.nm-orig"
  ok "исходный nginx.conf сохранён в $NGINX_CONF.nm-orig"
fi
install -m 0755 "$INSTALL_DIR/packaging/nmctl" /usr/local/bin/nmctl
install -m 0644 "$INSTALL_DIR/packaging/logrotate" /etc/logrotate.d/nginx-manager
if has_systemd; then
  install -m 0644 "$INSTALL_DIR/packaging/nginx-manager.service" "$UNIT_FILE"
  mkdir -p /etc/systemd/system/nginx.service.d
  install -m 0644 "$INSTALL_DIR/packaging/nginx-limits.conf" /etc/systemd/system/nginx.service.d/nginx-manager.conf
  run systemctl daemon-reload
fi
ok "nmctl, logrotate, systemd-юнит установлены"

# -----------------------------------------------------------------------------
step "Безопасность ОС (firewall, SELinux)"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
  info "SELinux в режиме Enforcing — настройка политик"
  run setsebool -P httpd_can_network_connect 1 && ok "httpd_can_network_connect=on (nginx может подключаться к бэкендам)"
  command -v semanage >/dev/null 2>&1 || pkg_install policycoreutils-python-utils || true
  if command -v semanage >/dev/null 2>&1; then
    semanage port -a -t http_port_t -p tcp 8089 2>/dev/null || semanage port -m -t http_port_t -p tcp 8089 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_content_t "$DATA_DIR/acme(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t cert_t "$DATA_DIR/certs(/.*)?" 2>/dev/null || true
    restorecon -R "$DATA_DIR" "$MANAGED_DIR" /var/cache/nginx 2>/dev/null || true
    ok "метки SELinux для каталогов и порта stub_status"
  else
    warn "semanage недоступен — при ошибках Permission denied смотрите «Диагностику»"
  fi
fi
if [ "$OPEN_FIREWALL" = 1 ]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    run ufw allow 80/tcp; run ufw allow 443/tcp; run ufw allow 443/udp
    [ "$OPEN_PANEL_PORT" = 1 ] && run ufw allow "$BIND_PORT/tcp"
    ok "ufw: открыты 80, 443$([ "$OPEN_PANEL_PORT" = 1 ] && echo ", $BIND_PORT")"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    run firewall-cmd --permanent --add-service=http; run firewall-cmd --permanent --add-service=https
    run firewall-cmd --permanent --add-port=443/udp
    [ "$OPEN_PANEL_PORT" = 1 ] && run firewall-cmd --permanent --add-port="$BIND_PORT/tcp"
    run firewall-cmd --reload
    ok "firewalld: открыты http, https$([ "$OPEN_PANEL_PORT" = 1 ] && echo ", $BIND_PORT/tcp")"
  else
    info "активный ufw/firewalld не найден — проверьте правила облачного провайдера (порты 80, 443)"
  fi
fi
# Конфликтующие веб-серверы
for svc in apache2 httpd lighttpd caddy; do
  if has_systemd && systemctl is-active --quiet "$svc" 2>/dev/null; then
    warn "работает $svc — он может занимать порты 80/443"
    if confirm "    Остановить и отключить $svc?"; then run systemctl disable --now "$svc" && ok "$svc остановлен"; fi
  fi
done

# -----------------------------------------------------------------------------
step "Инициализация базы и администратора"
NMCTL="/usr/local/bin/nmctl"
if ! "$NMCTL" user list 2>>"$LOG_FILE" | grep -q .; then
  GENERATED=0
  if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS="$(tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 14)$(tr -dc '2-9' </dev/urandom | head -c 2)!"
    GENERATED=1
  fi
  run "$NMCTL" user add "$ADMIN_USER" --role admin --password "$ADMIN_PASS" || fail "не удалось создать администратора (пароль: ≥ 8 символов, разные регистры/цифры)"
  ( umask 077
    printf 'URL: http://%s:%s/\nЛогин: %s\nПароль: %s\n' "$(server_ips | head -1)" "$BIND_PORT" "$ADMIN_USER" "$ADMIN_PASS" >/root/nginx-manager-credentials.txt )
  ok "создан администратор $ADMIN_USER (данные для входа: /root/nginx-manager-credentials.txt)"
else
  info "пользователи уже существуют — пропуск"; GENERATED=2
fi
if [ -n "$LE_EMAIL" ]; then
  "$INSTALL_DIR/venv/bin/python" - "$LE_EMAIL" <<'PY' 2>>"$LOG_FILE" && ok "e-mail Let's Encrypt: $LE_EMAIL"
import sys
sys.path.insert(0, "/opt/nginx-manager")
from app.config import settings
from app.db import Database
db = Database(settings.db_path)
p = db.kv_get("panel_settings", {}) or {}
p["letsencrypt_email"] = sys.argv[1]
db.kv_set("panel_settings", p)
PY
fi

# -----------------------------------------------------------------------------
if [ "$SKIP_APPLY" = 0 ]; then
  step "Применение конфигурации nginx"
  if has_systemd; then systemctl enable nginx >/dev/null 2>&1 || true; fi
  if "$NMCTL" apply -m "Установка Nginx Manager $VERSION_NEW" >>"$LOG_FILE" 2>&1; then
    ok "nginx работает под управлением панели (исходная конфигурация: $NGINX_CONF.nm-orig)"
  else
    warn "конфигурация не применена. Вывод:"
    "$NMCTL" apply -m "повтор" 2>&1 | tail -n 12 | sed 's/^/      /'
    warn "nginx оставлен с прежней конфигурацией. Откройте панель → «Диагностика»."
  fi
fi

if [ "$SKIP_START" = 0 ]; then
  step "Запуск сервиса"
  service_start
  if wait_healthy "$BIND_PORT" 40; then ok "панель отвечает на порту $BIND_PORT"
  else
    warn "панель не ответила за 40 с. Журнал: journalctl -u nginx-manager -n 50"
    has_systemd && journalctl -u nginx-manager -n 20 --no-pager 2>/dev/null | sed 's/^/      /'
  fi
fi

# -----------------------------------------------------------------------------
step "Проверка (nmctl diag --problems)"
"$NMCTL" diag --problems 2>>"$LOG_FILE" | tail -n 40 || true

printf '\n%s%sУстановка завершена.%s\n\n' "$C_GRN" "$C_B" "$C_0"
printf '  Веб-панель:  '
if [ "$BIND_HOST" = "127.0.0.1" ]; then
  printf 'http://127.0.0.1:%s/  (только локально; SSH-туннель: ssh -L %s:127.0.0.1:%s root@сервер)\n' "$BIND_PORT" "$BIND_PORT" "$BIND_PORT"
else
  for ip in $(server_ips); do printf 'http://%s:%s/  ' "$ip" "$BIND_PORT"; done; echo
fi
if [ "${GENERATED:-2}" != 2 ]; then
  printf '  Логин:       %s\n' "$ADMIN_USER"
  printf '  Пароль:      %s%s%s\n' "$C_B" "$ADMIN_PASS" "$C_0"
  [ "$GENERATED" = 1 ] && printf '               (сгенерирован; сохранён в /root/nginx-manager-credentials.txt)\n'
fi
cat <<EOF

  Дальше:
    1. Войдите в панель и смените пароль (Мой профиль), включите 2FA.
    2. Добавьте сайт (Сайты → Добавить), выпустите сертификат Let's Encrypt.
    3. Для доступа к панели по HTTPS задайте домен панели (Настройки панели → Сеть).

  Консоль:       nmctl status | nmctl diag | nmctl apply | nmctl --help
  Документация:  $INSTALL_DIR/docs/ (и раздел «Документация» в панели)
  Обновление:    sudo $INSTALL_DIR/update.sh --source <каталог новой версии>
  Удаление:      sudo $INSTALL_DIR/uninstall.sh

EOF
exit 0
