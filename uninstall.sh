#!/usr/bin/env bash
# =============================================================================
#  Nginx Manager — удаление
#
#  sudo ./uninstall.sh                 удалить сервис, восстановить исходный nginx.conf, данные сохранить
#  sudo ./uninstall.sh --purge -y      удалить всё, включая базу, статистику, сертификаты панели
#
#  Сайты продолжают работать до момента восстановления исходной конфигурации nginx.
#  Если хотите сохранить текущие сайты в nginx без панели — используйте --keep-nginx-config.
# =============================================================================
set -uo pipefail
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SELF_DIR/packaging/common.sh" ]; then . "$SELF_DIR/packaging/common.sh"
elif [ -f /opt/nginx-manager/packaging/common.sh ]; then . /opt/nginx-manager/packaging/common.sh
else echo "common.sh не найден"; exit 1; fi

PURGE=0; KEEP_NGINX=0; REMOVE_NGINX=0; REMOVE_LE=0; DO_BACKUP=1; ASSUME_YES=0
usage() {
  cat <<EOF
Использование: sudo $0 [параметры]
  --purge               удалить также данные (БД, статистику, резервные копии, загруженные сертификаты), журналы nm-*.log
  --keep-nginx-config   оставить nginx работать с текущей сгенерированной конфигурацией (сайты продолжат работать)
                        — файлы будут скопированы в /etc/nginx/conf.d и отвязаны от панели
  --remove-nginx        удалить сам пакет nginx
  --remove-le-certs     удалить сертификаты Let's Encrypt, выпущенные панелью (certbot delete nm-*)
  --no-backup           не сохранять финальную резервную копию
  -y, --yes             не задавать вопросов
EOF
}
while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1 ;;
    --keep-nginx-config) KEEP_NGINX=1 ;;
    --remove-nginx) REMOVE_NGINX=1 ;;
    --remove-le-certs) REMOVE_LE=1 ;;
    --no-backup) DO_BACKUP=0 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "Неизвестный параметр: $1" ;;
  esac
  shift
done
require_root "$@"
log "=== uninstall $(date -Is) ==="
detect_os
printf '\n%sУдаление Nginx Manager %s%s\n' "$C_B" "$(installed_version)" "$C_0"
printf '  • сервис, nmctl, юнит systemd, logrotate — будут удалены\n'
if [ "$KEEP_NGINX" = 1 ]; then printf '  • nginx продолжит работать с текущими сайтами (конфигурация будет «заморожена»)\n'
else printf '  • nginx.conf будет восстановлен из %s.nm-orig (сайты панели перестанут обслуживаться)\n' "$NGINX_CONF"; fi
[ "$PURGE" = 1 ] && printf '  • %sданные панели будут удалены безвозвратно%s\n' "$C_RED" "$C_0" || printf '  • данные сохранятся в %s\n' "$DATA_DIR"
echo
confirm "Продолжить?" || { echo "Отменено."; exit 1; }

TS="$(date +%Y%m%d-%H%M%S)"
# сначала останавливаем сервис: иначе база меняется во время архивации и копия получается несогласованной
step "Остановка сервиса"
service_stop
ok "сервис остановлен"

if [ "$DO_BACKUP" = 1 ] && [ -d "$DATA_DIR" ]; then
  step "Финальная резервная копия"
  F="/root/nginx-manager-final-backup-$TS.tar.gz"
  [ -x /usr/local/bin/nmctl ] && /usr/local/bin/nmctl backup >>"$LOG_FILE" 2>&1 || true
  # в копии хеши паролей и закрытые ключи — файл доступен только root, даже если архивация прошла с ошибкой
  ( umask 077; tar -czf "$F" -C / "${DATA_DIR#/}" "${CONF_DIR#/}" "${MANAGED_DIR#/}" "${NGINX_CONF#/}" 2>>"$LOG_FILE" )
  rc=$?
  chmod 600 "$F" 2>/dev/null || true
  if [ "$rc" = 0 ]; then ok "$F"; else warn "резервная копия создана с предупреждениями ($F, подробности в $LOG_FILE)"; fi
fi

step "Удаление сервиса"
if has_systemd; then
  systemctl disable nginx-manager.service >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE" /etc/systemd/system/nginx.service.d/nginx-manager.conf
  rmdir /etc/systemd/system/nginx.service.d 2>/dev/null || true
  systemctl daemon-reload
fi
ok "сервис удалён"

step "Конфигурация nginx"
NGINX_BIN="$(command -v nginx || echo /usr/sbin/nginx)"
reload_nginx() {
  if has_systemd && systemctl is-active --quiet nginx; then systemctl reload nginx; else "$NGINX_BIN" -s reload 2>/dev/null || "$NGINX_BIN"; fi
}
if [ "$KEEP_NGINX" = 1 ]; then
  if [ -d "$MANAGED_DIR/live" ]; then
    FROZEN="/etc/nginx/nginx-manager-frozen"
    rm -rf "$FROZEN"; cp -aL "$MANAGED_DIR/live" "$FROZEN"
    sed -i "s#$MANAGED_DIR/live#$FROZEN#g" "$NGINX_CONF" "$FROZEN"/*/*.conf 2>/dev/null
    sed -i '/NGINX-MANAGER: managed file/d' "$NGINX_CONF"
    if "$NGINX_BIN" -t >>"$LOG_FILE" 2>&1; then reload_nginx; ok "конфигурация заморожена в $FROZEN, сайты продолжают работать"
    else warn "проверка nginx -t не пройдена — см. $LOG_FILE"; fi
  fi
else
  if [ -f "$NGINX_CONF.nm-orig" ]; then
    cp -a "$NGINX_CONF" "$NGINX_CONF.nm-last" 2>/dev/null || true
    cp -a "$NGINX_CONF.nm-orig" "$NGINX_CONF"
    if "$NGINX_BIN" -t >>"$LOG_FILE" 2>&1; then
      reload_nginx >>"$LOG_FILE" 2>&1 || true
      rm -f "$NGINX_CONF.nm-orig"
      ok "восстановлен исходный nginx.conf (последняя версия панели: $NGINX_CONF.nm-last)"
    else
      warn "исходный nginx.conf не проходит проверку (возможно, ссылается на удалённые файлы)."
      warn "Оставлена конфигурация панели; исходная — в $NGINX_CONF.nm-orig. Исправьте вручную и выполните nginx -t."
      cp -a "$NGINX_CONF.nm-last" "$NGINX_CONF"
      KEEP_MANAGED=1
    fi
  else
    warn "резервная копия исходного nginx.conf не найдена — конфигурация не изменена"
    KEEP_MANAGED=1
  fi
  if [ "${KEEP_MANAGED:-0}" = 0 ]; then rm -rf "$MANAGED_DIR"; ok "удалён $MANAGED_DIR"; fi
fi

if [ "$REMOVE_LE" = 1 ] && command -v certbot >/dev/null 2>&1; then
  step "Сертификаты Let's Encrypt"
  for d in /etc/letsencrypt/live/nm-*; do
    [ -d "$d" ] || continue
    n="$(basename "$d")"; certbot delete --cert-name "$n" --non-interactive >>"$LOG_FILE" 2>&1 && ok "удалён $n"
  done
fi

step "Файлы программы"
rm -f /usr/local/bin/nmctl /etc/logrotate.d/nginx-manager
rm -rf "$INSTALL_DIR"
ok "удалены $INSTALL_DIR, nmctl, logrotate"

if [ "$PURGE" = 1 ]; then
  step "Данные"
  if [ "$KEEP_NGINX" = 1 ] || [ "${KEEP_MANAGED:-0}" = 1 ]; then
    # nginx продолжает использовать сертификаты и каталог ACME — их не удаляем
    find "$DATA_DIR" -mindepth 1 -maxdepth 1 ! -name certs ! -name acme -exec rm -rf {} + 2>/dev/null || true
    warn "сохранены $DATA_DIR/certs и $DATA_DIR/acme — они используются текущей конфигурацией nginx"
    rm -rf "$CONF_DIR"
  else
    rm -rf "$DATA_DIR" "$CONF_DIR"
  fi
  rm -rf /var/cache/nginx/nginx-manager
  rm -f /var/log/nginx/nm-*.log* /var/log/nginx-manager.log /root/nginx-manager-credentials.txt
  ok "данные, настройки, кэш и журналы панели удалены"
else
  info "данные сохранены: $DATA_DIR, $CONF_DIR (повторная установка подхватит их)"
fi

if [ "$REMOVE_NGINX" = 1 ]; then
  step "Удаление nginx"
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive run apt-get remove -y nginx nginx-common libnginx-mod-stream ;;
    dnf|yum) run "$PKG" remove -y nginx nginx-mod-stream ;;
  esac
  ok "nginx удалён"
fi

printf '\n%s%sNginx Manager удалён.%s\n\n' "$C_GRN" "$C_B" "$C_0"
exit 0
