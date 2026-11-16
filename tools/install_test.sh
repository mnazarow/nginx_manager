#!/bin/bash
# Проверка установки, обновления и удаления на чистой системе в контейнере Docker.
#
#   tools/install_test.sh ubuntu:22.04                       установка этой версии → сайт → проверка браузера → удаление
#   tools/install_test.sh debian:12 nginx-manager-2.3.0.tar.gz   установка старой версии → сайт → обновление до этой
#
# Образ — любой поддерживаемой ОС (ubuntu:22.04, ubuntu:24.04, debian:12, rockylinux:9, almalinux:9, fedora:40…).
# В контейнере нет systemd: панель запускается в фоне — так и задумано для проверки. Переменные https_proxy и
# http_proxy передаются в контейнер, если заданы; NM_TEST_CA=файл.crt — сертификат прокси с перехватом TLS (будет
# добавлен в доверенные в контейнере). Журнал — в stdout; код возврата 0, если все шаги прошли.
set -u
IMAGE="${1:?образ Docker, например ubuntu:22.04}"
OLD="${2:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/new"
(cd "$SRC" && git ls-files -co --exclude-standard | tar -cf - -T -) | tar -xf - -C "$WORK/new"
if [ -n "$OLD" ]; then cp "$OLD" "$WORK/old.tar.gz"; fi
if [ -n "${NM_TEST_CA:-}" ]; then cp "$NM_TEST_CA" "$WORK/ca.crt"; fi

cat >"$WORK/run.sh" <<'EOF'
#!/bin/bash
set -u
fail() { echo "ОШИБКА: $*"; exit 1; }
export DEBIAN_FRONTEND=noninteractive no_proxy=127.0.0.1,localhost NO_PROXY=127.0.0.1,localhost
if [ -f /t/ca.crt ]; then
  if [ -d /usr/local/share/ca-certificates ]; then
    cp /t/ca.crt /usr/local/share/ca-certificates/nm-test.crt && update-ca-certificates >/dev/null 2>&1
    B=/etc/ssl/certs/ca-certificates.crt
  else
    cp /t/ca.crt /etc/pki/ca-trust/source/anchors/nm-test.crt && update-ca-trust
    B=/etc/pki/tls/certs/ca-bundle.crt
  fi
  export PIP_CERT=$B REQUESTS_CA_BUNDLE=$B SSL_CERT_FILE=$B
fi
if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null && apt-get install -y -qq curl python3 >/dev/null
elif command -v dnf >/dev/null; then dnf install -y -q curl python3 tar gzip >/dev/null; fi
login() { curl -s -c /tmp/c -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin12345!"}' http://127.0.0.1:8088/api/auth/login >/dev/null; }
if [ -f /t/old.tar.gz ]; then
  mkdir -p /root/old && tar xzf /t/old.tar.gz -C /root/old --strip-components=1
  cd /root/old && ./install.sh -y --no-firewall --admin-password 'Admin12345!' >/root/install.log 2>&1 \
    || { tail -30 /root/install.log; fail "установка старой версии"; }
  echo "установлена $(curl -s http://127.0.0.1:8088/api/version)"
else
  cd /t/new && ./install.sh -y --no-firewall --admin-password 'Admin12345!' >/root/install.log 2>&1 \
    || { tail -30 /root/install.log; fail "установка"; }
  grep -E "✓|!" /root/install.log | head -20
fi
login
python3 -m http.server 8081 --bind 127.0.0.1 --directory /root >/dev/null 2>&1 &
curl -s -b /tmp/c -H 'X-NM-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{"name":"Проверка","domains":["t.test"],"backends":[{"address":"127.0.0.1","port":8081}]}' \
  'http://127.0.0.1:8088/api/sites?apply=1' | grep -q '"id"' || fail "сайт не создан"
code=$(curl -s -o /dev/null -w "%{http_code}" -H 'Host: t.test' http://127.0.0.1/)
echo "сайт через nginx: $code"; [ "$code" = 200 ] || fail "сайт не отвечает"
if [ -f /t/old.tar.gz ]; then
  cd /t/new && ./update.sh -y >/root/update.log 2>&1 || { tail -30 /root/update.log; fail "обновление"; }
  grep -E "✓|!|завершено" /root/update.log | head -20
  sleep 2; login
  code=$(curl -s -o /dev/null -w "%{http_code}" -H 'Host: t.test' http://127.0.0.1/)
  echo "после обновления: $(curl -s http://127.0.0.1:8088/api/version), сайт через nginx: $code"
  [ "$code" = 200 ] || fail "сайт не отвечает после обновления"
fi
echo "nginx -t: $(nginx -t 2>&1 | grep -c '\[warn\]') предупреждений"
/usr/local/bin/nmctl diag -p 2>&1 | grep -E "^\s+!|✗|Итого"
/opt/nginx-manager/uninstall.sh -y >/root/uninstall.log 2>&1 || { tail -20 /root/uninstall.log; fail "удаление"; }
grep -E "✓|!|      " /root/uninstall.log | head -12
[ ! -d /opt/nginx-manager ] || fail "каталог программы не удалён"
echo "ГОТОВО"
EOF

docker run --rm ${https_proxy:+-e https_proxy="$https_proxy"} ${http_proxy:+-e http_proxy="$http_proxy"} \
  -v "$WORK:/t" "$IMAGE" bash /t/run.sh
