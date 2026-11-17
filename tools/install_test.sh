#!/bin/bash
# Проверка установки, обновления и удаления на чистой системе в контейнере Docker.
#
#   tools/install_test.sh ubuntu:22.04                       установка этой версии → сайт → проверка браузера → удаление
#   tools/install_test.sh debian:12 nginx-manager-2.3.0.tar.gz   установка старой версии → сайт → обновление до этой
#
# Образ — любой поддерживаемой ОС (ubuntu:22.04, ubuntu:24.04, debian:12, rockylinux:9, almalinux:9, fedora:40…).
#
#   tools/install_test.sh --emulate rocky:9 [старая.tar.gz]   ЭМУЛЯЦИЯ: образ Ubuntu (NM_TEST_IMAGE, по умолчанию
#       nm-test/noble:prep) с /etc/os-release другой ОС, а для RHEL-совместимых — с dnf и rpm, которые ставят пакеты
#       Ubuntu (nginx-mod-stream → libnginx-mod-stream и т. п.). Проверяет ветки установщика для этой ОС (выбор
#       пакетного менеджера, EPEL, имена пакетов, срок поддержки ОС), когда зеркала дистрибутива недоступны. Сами
#       пакеты и сборка nginx при этом — Ubuntu; это не замена проверки на настоящей системе.
#       Варианты: debian:12, debian:13, rocky:9, rocky:10, almalinux:9, almalinux:10, rhel:9, ol:9, centos-stream:10.
# В контейнере нет systemd: панель запускается в фоне — так и задумано для проверки. Переменные https_proxy и
# http_proxy передаются в контейнер, если заданы; NM_TEST_CA=файл.crt — сертификат прокси с перехватом TLS (будет
# добавлен в доверенные в контейнере). Журнал — в stdout; код возврата 0, если все шаги прошли.
set -u
EMU=""
if [ "${1:-}" = "--emulate" ]; then EMU="${2:?ОС для эмуляции, например rocky:9}"; shift 2; set -- "${NM_TEST_IMAGE:-nm-test/noble:prep}" "$@"; fi
IMAGE="${1:?образ Docker, например ubuntu:22.04}"
OLD="${2:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/new"
(cd "$SRC" && git ls-files -co --exclude-standard | tar -cf - -T -) | tar -xf - -C "$WORK/new"
if [ -n "$OLD" ]; then cp "$OLD" "$WORK/old.tar.gz"; fi
if [ -n "${NM_TEST_CA:-}" ]; then cp "$NM_TEST_CA" "$WORK/ca.crt"; fi

echo "$EMU" >"$WORK/emulate"
cat >"$WORK/emu.sh" <<'EMUEOF'
#!/bin/bash
# Эмуляция другой ОС в образе Ubuntu: /etc/os-release и (для RHEL-совместимых) dnf/rpm поверх apt.
EMU="$(cat /t/emulate)"
[ -n "$EMU" ] || exit 0
BASE="$(. /etc/os-release; echo "$PRETTY_NAME")"
rm -f /etc/os-release  # в Ubuntu это ссылка на /usr/lib/os-release — пишем отдельный файл
os() { printf 'NAME="%s"\nVERSION_ID="%s"\nID=%s\nID_LIKE="%s"\nPRETTY_NAME="%s"\nVERSION_CODENAME=%s\n' "$@" >/etc/os-release; }
case "$EMU" in
  debian:12) os "Debian GNU/Linux" 12 debian "" "Debian GNU/Linux 12 (bookworm)" bookworm ;;
  debian:13) os "Debian GNU/Linux" 13 debian "" "Debian GNU/Linux 13 (trixie)" trixie ;;
  rocky:9) os "Rocky Linux" 9.6 rocky "rhel centos fedora" "Rocky Linux 9.6 (Blue Onyx)" "" ;;
  rocky:10) os "Rocky Linux" 10.0 rocky "rhel centos fedora" "Rocky Linux 10.0 (Red Quartz)" "" ;;
  almalinux:9) os "AlmaLinux" 9.6 almalinux "rhel centos fedora" "AlmaLinux 9.6 (Sage Margay)" "" ;;
  almalinux:10) os "AlmaLinux" 10.0 almalinux "rhel centos fedora" "AlmaLinux 10.0 (Purple Lion)" "" ;;
  rhel:9) os "Red Hat Enterprise Linux" 9.6 rhel "fedora" "Red Hat Enterprise Linux 9.6 (Plow)" "" ;;
  ol:9) os "Oracle Linux Server" 9.6 ol "fedora" "Oracle Linux Server 9.6" "" ;;
  centos-stream:10) os "CentOS Stream" 10 centos "rhel fedora" "CentOS Stream 10 (Coughlan)" "" ;;
  *) echo "ОШИБКА: неизвестная ОС для эмуляции: $EMU"; exit 1 ;;
esac
echo "ЭМУЛЯЦИЯ: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2) поверх $BASE"
case "$EMU" in debian:*) exit 0 ;; esac
# dnf/rpm → apt: имена пакетов RHEL заменяются ближайшими пакетами Ubuntu, EPEL пропускается
cat >/usr/local/bin/emu-map <<'MAP'
#!/bin/bash
for p in "$@"; do case "$p" in
  -*) ;;
  epel-release|oracle-epel-release-el*|https://*|*.rpm) echo "эмуляция: $p пропущен" >&2 ;;
  nginx-mod-stream) echo libnginx-mod-stream ;;
  nginx-mod-modsecurity) echo libnginx-mod-http-modsecurity ;;
  procps-ng) echo procps ;;
  iproute) echo iproute2 ;;
  python3) echo python3; echo python3-venv; echo python3-pip ;;
  python3.11|python39) echo "эмуляция: $p недоступен" >&2; echo __missing__ ;;
  *) echo "$p" ;;
esac; done
MAP
cat >/usr/local/bin/dnf <<'DNF'
#!/bin/bash
echo "dnf $*" >>/root/emu-dnf.log
cmd="$1"; shift
case "$cmd" in
  install|remove)
    mapfile -t pk < <(/usr/local/bin/emu-map "$@" 2>>/root/emu-dnf.log)
    for p in "${pk[@]}"; do [ "$p" = __missing__ ] && exit 1; done
    [ ${#pk[@]} -eq 0 ] && exit 0
    exec env DEBIAN_FRONTEND=noninteractive apt-get "$cmd" -y -q -o Dpkg::Options::=--force-confold "${pk[@]}" ;;
  *) exit 0 ;;
esac
DNF
cat >/usr/local/bin/rpm <<'RPM'
#!/bin/bash
[ "$1" = -q ] || exit 1
shift
for p in "$@"; do n="$(/usr/local/bin/emu-map "$p" 2>/dev/null | head -1)"; dpkg -s "${n:-$p}" >/dev/null 2>&1 || exit 1; done
RPM
chmod +x /usr/local/bin/emu-map /usr/local/bin/dnf /usr/local/bin/rpm
EMUEOF

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
# прокси без обычного HTTP (только CONNECT): источники пакетов — по HTTPS
if [ -n "${https_proxy:-}" ] && [ -d /etc/apt ]; then
  sed -i 's#http://\([a-z.]*\.ubuntu\.com\)#https://\1#g; s#http://deb\.debian\.org#https://deb.debian.org#g' \
    /etc/apt/sources.list /etc/apt/sources.list.d/*.sources 2>/dev/null
  unset http_proxy
fi
if command -v apt-get >/dev/null; then apt-get update -qq >/dev/null && apt-get install -y -qq curl python3 >/dev/null
elif command -v dnf >/dev/null; then dnf install -y -q curl python3 tar gzip >/dev/null; fi
bash /t/emu.sh || exit 1
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
if [ -s /root/emu-dnf.log ]; then echo "вызовы dnf (эмуляция):"; sed 's/^/  /' /root/emu-dnf.log | sort -u | head -20; fi
/opt/nginx-manager/uninstall.sh -y >/root/uninstall.log 2>&1 || { tail -20 /root/uninstall.log; fail "удаление"; }
grep -E "✓|!|      " /root/uninstall.log | head -12
[ ! -d /opt/nginx-manager ] || fail "каталог программы не удалён"
echo "ГОТОВО"
EOF

docker run --rm ${https_proxy:+-e https_proxy="$https_proxy"} ${http_proxy:+-e http_proxy="$http_proxy"} \
  -v "$WORK:/t" "$IMAGE" bash /t/run.sh
