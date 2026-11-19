"""nmctl — консольная утилита администрирования Nginx Manager.

Примеры:
    nmctl status                      состояние сервиса и nginx
    nmctl apply -m "комментарий"      применить конфигурацию из БД
    nmctl test                        проверить конфигурацию (nginx -t)
    nmctl diag                        полная диагностика в терминале
    nmctl user list | add | passwd | reset-2fa | disable | enable | delete
    nmctl allowlist clear             снять ограничение доступа к панели по IP
    nmctl backup                      резервная копия БД и настроек
    nmctl restore <файл.db[.gz|.enc]> восстановить базу из копии (текущая сохраняется)
    nmctl export > settings.json      экспорт настроек
    nmctl import settings.json        импорт настроек
    nmctl versions                    история применённых конфигураций
    nmctl rollback <id>               откат к версии
    nmctl sites                       список сайтов
    nmctl vulns status                базы защиты: источники, число записей, карта путей эксплойтов
    nmctl vulns update                обновить базу уязвимостей (и правила OWASP CRS, если источник — GitHub)
    nmctl vulns search ТЕКСТ          поиск по базе уязвимостей; nmctl vulns show CVE — карточка
    nmctl deps                        системные пакеты и модули nginx для включённых функций (--packages apt|dnf)
    nmctl os                          срок поддержки ОС (обновления безопасности), --json
    nmctl peers                       другие серверы: связь, блокировки, доверенные адреса, синхронизация сайтов
    nmctl transfer --to web-2 --sites 1,3   перенести сайты с сертификатами на другой сервер (--all, --tag)
    nmctl settings backup [-o DIR]    копия всех настроек (пароль — NM_BACKUP_PASSWORD или --password-file)
    nmctl settings inspect ФАЙЛ       что в копии настроек
    nmctl settings restore ФАЙЛ [--sections sites,certificates] [--no-apply]   восстановить настройки
    nmctl settings remote s3://бакет/префикс/ --endpoint URL   копии настроек в хранилище
    nmctl settings restore s3://бакет/префикс/latest --endpoint URL   новый сервер — прямо из хранилища
    nmctl lists keygen -o ключ.txt    ключи подписи списков адресов (Ed25519): закрытый — в файл, открытый — на экран
    nmctl lists sign СПИСОК --key ключ.txt   подписать список адресов (рядом появится СПИСОК.sig)
    nmctl lists verify СПИСОК --pub ed25519:…   проверить подпись списка
"""
from __future__ import annotations

import argparse
import asyncio
import os
import getpass
import json
import sys
import time
from pathlib import Path

C = {"ok": "\033[32m", "warn": "\033[33m", "fail": "\033[31m", "info": "\033[36m", "skip": "\033[90m",
     "b": "\033[1m", "r": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}
ICON = {"ok": "✓", "warn": "!", "fail": "✗", "info": "i", "skip": "-"}


def _db():
    from .config import settings
    from .db import Database
    settings.ensure_dirs()
    return Database(settings.db_path)


def _manager(db):
    from .nginx.manager import NginxManager
    return NginxManager(db)


def cmd_status(a) -> int:
    from .config import VERSION, settings
    from .utils import has_systemd, run
    db = _db()
    m = _manager(db)
    st = m.status()
    print(f"{C['b']}Nginx Manager {VERSION}{C['r']}")
    if has_systemd():
        code, _ = run(["systemctl", "is-active", "--quiet", "nginx-manager"])
        print(f"  Сервис панели:   {'активен' if code == 0 else 'не запущен'}")
    print(f"  Адрес панели:    http://{settings.bind_host}:{settings.bind_port}/")
    print(f"  База данных:     {settings.db_path}")
    print(f"  Nginx:           {st['version']} — " + (f"{C['ok']}работает{C['r']} (PID {st.get('pid')}, "
                                                     f"воркеров {st.get('workers')})" if st["running"] else
                                                     f"{C['fail']}остановлен{C['r']}"))
    print(f"  nginx.conf:      {'под управлением панели' if st['managed'] else C['warn'] + 'НЕ под управлением' + C['r']}")
    last = m.last_applied()
    if last:
        print(f"  Версия конфиг.:  #{last['id']} от {time.strftime('%Y-%m-%d %H:%M', time.localtime(last['ts']))} "
              f"({last['username']})")
    pend = m.pending()
    print(f"  Неприменённое:   {'да (' + str(len(pend.get('changed', []))) + ' файлов)' if pend.get('pending') else 'нет'}")
    print(f"  Сайтов:          {db.scalar('SELECT COUNT(*) FROM sites')}, потоков: "
          f"{db.scalar('SELECT COUNT(*) FROM streams')}, сертификатов: {db.scalar('SELECT COUNT(*) FROM certificates')}")
    return 0


def cmd_apply(a) -> int:
    from .nginx.manager import ApplyError
    db = _db()
    m = _manager(db)
    try:
        res = m.apply_sync(m.load_state(), "cli", a.message or "nmctl apply", "cli")
    except ApplyError as e:
        print(f"{C['fail']}✗ {e}{C['r']}")
        for err in e.errors:
            print(f"  [{err['level']}] {err['message']} ({err.get('file')}:{err.get('line')})")
            if err.get("hint"):
                print(f"    → {err['hint']}")
        if e.output and not e.errors:
            print(e.output)
        return 1
    print(f"{C['ok']}✓ Применена версия {res['version']} за {res['duration']} с{C['r']}")
    for w in res["warnings"]:
        print(f"  {C['warn']}! {w}{C['r']}")
    return 0


def cmd_test(a) -> int:
    m = _manager(_db())
    ok, out = m.test_config()
    print(out.strip())
    return 0 if ok else 1


def cmd_diag(a) -> int:
    from fastapi import FastAPI  # noqa: F401  (проверка окружения)
    from .core import App

    async def go():
        app = App()
        app.stats.reload_geoip()
        app.refresh_runtime_maps()
        st = app.stats
        await asyncio.to_thread(st.system.sample)
        # в консольном режиме сборщик не запущен — подготовим разовые данные
        s = await st.stub.fetch()
        if s:
            s.update(rps=0.0, cps=0.0, dropped=s["accepts"] - s["handled"])
            st.stub.samples.append(s)
        for t in st.tailers:
            t.status = "ok" if t.path.exists() else "файл не найден"
            t.lines_total = -1
            # позиция чтения — из сохранённого сервисом состояния (иначе отставание = весь размер файла)
            try:
                saved = app.db.kv_get(f"tail:{t.name}") or {}
                stt = os.stat(t.path)
                t.pos = saved.get("pos", stt.st_size) if saved.get("ino") == stt.st_ino else stt.st_size
            except OSError:
                pass
        return await app.diag.run_all()
    res = asyncio.run(go())
    group = None
    for r in res["results"]:
        if a.problems and r["status"] in ("ok", "info", "skip"):
            continue
        if r["group"] != group:
            group = r["group"]
            print(f"\n{C['b']}{group}{C['r']}")
        s = r["status"]
        print(f"  {C[s]}{ICON[s]}{C['r']} {r['title']}: {r['message']}")
        if r["hint"] and s in ("warn", "fail"):
            for line in r["hint"].splitlines():
                print(f"      → {line}")
        if r.get("fix") and s in ("warn", "fail"):
            print(f"      {C['info']}исправление в панели: «{r['fix_label']}»{C['r']}")
    s = res["summary"]
    print(f"\nИтого: {C['ok']}{s['ok']} ок{C['r']}, {C['warn']}{s['warn']} предупр.{C['r']}, "
          f"{C['fail']}{s['fail']} ошибок{C['r']}, {s['info']} инфо ({res['duration']} с)")
    return 1 if s["fail"] else 0


def cmd_user(a) -> int:
    from .auth import AuthService
    from .models import PanelSettings
    db = _db()
    auth = AuthService(db, lambda: PanelSettings.model_validate(db.kv_get("panel_settings", {})))
    if a.action == "list":
        for u in auth.users():
            flags = []
            if u["disabled"]:
                flags.append("отключён")
            if u["totp_enabled"]:
                flags.append("2FA")
            print(f"{u['id']:>3}  {u['username']:<20} {u['role']:<9} {' '.join(flags)}")
        return 0
    if not a.username:
        print("Укажите имя пользователя")
        return 2
    u = db.one("SELECT * FROM users WHERE username=?", (a.username,))
    if a.action == "add":
        pw = a.password or getpass.getpass("Пароль: ")
        try:
            auth.create_user(a.username, pw, a.role)
        except ValueError as e:
            print(f"{C['fail']}{e}{C['r']}")
            return 1
        print(f"Пользователь {a.username} ({a.role}) создан")
        return 0
    if not u:
        print(f"{C['fail']}Пользователь {a.username} не найден{C['r']}")
        return 1
    if a.action == "passwd":
        pw = a.password or getpass.getpass("Новый пароль: ")
        try:
            auth.set_password(u["id"], pw)
        except ValueError as e:
            print(f"{C['fail']}{e}{C['r']}")
            return 1
        db.execute("UPDATE users SET disabled=0 WHERE id=?", (u["id"],))
        print("Пароль изменён, все сессии пользователя завершены")
    elif a.action == "reset-2fa":
        db.execute("UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (u["id"],))
        print("2FA отключена")
    elif a.action in ("disable", "enable"):
        db.execute("UPDATE users SET disabled=? WHERE id=?", (1 if a.action == "disable" else 0, u["id"]))
        print("Готово")
    elif a.action == "role":
        db.execute("UPDATE users SET role=? WHERE id=?", (a.role, u["id"]))
        print(f"Роль: {a.role}")
    elif a.action == "delete":
        db.execute("DELETE FROM users WHERE id=?", (u["id"],))
        print("Удалён")
    db.audit("cli", "local", f"cli_user_{a.action}", a.username)
    return 0


def cmd_allowlist(a) -> int:
    db = _db()
    p = db.kv_get("panel_settings", {})
    if a.action == "show":
        print("\n".join(p.get("panel_allow", [])) or "(доступ с любых IP)")
        return 0
    p["panel_allow"] = []
    db.kv_set("panel_settings", p)
    db.audit("cli", "local", "cli_allowlist_clear")
    print("Ограничение доступа по IP снято. Перезапустите сервис: systemctl restart nginx-manager")
    return 0


def cmd_backup(a) -> int:
    from .core import App
    from .services.backup import db_backup, prune_backups
    app = App()
    p = db_backup(app, "cli")
    print(f"Резервная копия: {p}")
    removed = prune_backups(app.panel().backup_keep, app.panel().backup_keep_update)
    if removed:
        print(f"Удалено старых копий: {len(removed)}")
    return 0


def _service_active() -> bool:
    import shutil
    import subprocess
    if not shutil.which("systemctl"):
        return False
    return subprocess.run(["systemctl", "is-active", "--quiet", "nginx-manager"], check=False,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _panel_answers() -> bool:
    """Отвечает ли панель на своём порту (запущена не как сервис systemd — тогда менять базу под ней нельзя)."""
    import ssl
    import urllib.request
    from .config import settings
    host = settings.bind_host if settings.bind_host not in ("", "0.0.0.0", "::") else "127.0.0.1"
    host = f"[{host}]" if ":" in host else host
    scheme = "https" if settings.tls_cert and settings.tls_key else "http"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    try:
        with opener.open(f"{scheme}://{host}:{settings.bind_port}/healthz", timeout=3) as r:
            return b'"ok"' in r.read(300)
    except Exception:  # noqa: BLE001 — нет ответа: панель не запущена
        return False


def _prepare_restore_file(path: str) -> Path:
    """Файл копии → несжатая незашифрованная база в каталоге копий (.enc расшифровывается, .gz распаковывается)."""
    import gzip
    import shutil
    from .config import settings
    from .services.backup import _decrypt
    src = Path(path).expanduser().resolve()
    if not src.is_file():
        raise ValueError(f"Файл не найден: {src}")
    work = src
    tmp = []
    try:
        if work.name.endswith(".enc"):
            pw = os.environ.get("NM_BACKUP_PASS") or getpass.getpass("Пароль шифрования копии: ")
            dst = settings.backups_dir / work.name
            if dst != work:
                shutil.copyfile(work, dst)
                tmp.append(dst)
            work = _decrypt(dst, pw)
        if work.name.endswith(".gz"):
            out = settings.backups_dir / work.name[:-3]
            try:
                with gzip.open(work, "rb") as fi, open(out, "wb") as fo:
                    shutil.copyfileobj(fi, fo, 1 << 20)
            except (OSError, EOFError) as e:
                out.unlink(missing_ok=True)
                raise ValueError(f"Не удалось распаковать {work.name}: {e}") from e
            out.chmod(0o600)
            if work.parent == settings.backups_dir and work != src:
                tmp.append(work)
            work = out
    finally:
        for t in tmp:
            t.unlink(missing_ok=True)
    return work


def cmd_restore(a) -> int:
    """Восстановить базу из копии. Сервис запущен — копия ставится в очередь и сервис перезапускается (замена
    файла — при старте); остановлен — файл заменяется сразу, итог запишется в журнал при следующем запуске."""
    from .config import settings
    from .core import App
    from .services.backup import (RESTORE_LAST, _read_json, apply_pending_restore, inspect_db, restore_pending,
                                  schedule_restore)
    settings.ensure_dirs()
    if restore_pending() is not None:
        print(f"{C['warn']}! Восстановление уже запланировано и ждёт перезапуска сервиса.{C['r']} "
              "Перезапустите сервис: systemctl restart nginx-manager")
        return 1
    active = _service_active()
    if not active and _panel_answers():
        print(f"{C['fail']}✗ Панель работает, но не как сервис systemd — заменить базу под ней нельзя.{C['r']} "
              "Восстановите копию из интерфейса («Копии и импорт» → «Восстановить») или остановите панель и "
              "повторите команду.", file=sys.stderr)
        return 1
    src = _prepare_restore_file(a.file)
    info = inspect_db(src)
    fmt = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"  # noqa: E731
    print(f"{C['b']}Копия {src.name}{C['r']}: {info['size'] / 1048576:.1f} МБ, данные по {fmt(info['data_until'])}, "
          f"схема {info['schema']}" + (f" (будет обновлена до {info['schema_current']})"
                                      if info["schema"] < info["schema_current"] else ""))
    print(f"  сайтов {info['sites']}, потоков {info['streams']}, сертификатов {info['certificates']}; "
          f"администраторы: {', '.join(info['admins'])}")
    print("  Текущая база будет сохранена (before-restore); пользователи, пароли, настройки, журналы и статистика "
          "станут такими, как в копии.")
    if not a.yes:
        if not sys.stdin.isatty():
            print("Подтвердите ключом --yes", file=sys.stderr)
            return 1
        if input("Восстановить? [y/N] ").strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено")
            return 1
    app = App()
    res = schedule_restore(app, src, "nmctl", "local")
    app.db.close()  # замена файла базы — без открытых соединений этого процесса
    print(f"Текущая база сохранена: {settings.backups_dir / res['safety']}")
    t0 = time.time()
    if active:
        import subprocess
        print("Перезапуск сервиса nginx-manager…")
        subprocess.run(["systemctl", "restart", "nginx-manager"], check=False)
        while time.time() - t0 < 90:
            last = _read_json(settings.data_dir / RESTORE_LAST)
            if restore_pending() is None and last and last.get("done_at", 0) >= t0 - 1:
                break
            time.sleep(1)
        last = _read_json(settings.data_dir / RESTORE_LAST)
        if not last or last.get("done_at", 0) < t0 - 1:
            print(f"{C['warn']}! Сервис не подтвердил восстановление за 90 с — смотрите journalctl -u nginx-manager"
                  f"{C['r']}")
            return 1
    else:
        last = apply_pending_restore()
    if last and last.get("ok"):
        print(f"{C['ok']}✓ База восстановлена из {src.name}.{C['r']} Проверьте «Неприменённые изменения» в панели "
              "(или nmctl apply), если настройки копии отличаются от работающих.")
        return 0
    print(f"{C['fail']}✗ Восстановление не выполнено: {(last or {}).get('error')}{C['r']}", file=sys.stderr)
    return 1


def cmd_export(a) -> int:
    from .core import App
    from .services.backup import export_config
    print(json.dumps(export_config(App(), include_users=a.users), ensure_ascii=False, indent=2))
    return 0


def cmd_import(a) -> int:
    from .core import App
    from .services.backup import db_backup, import_config
    app = App()
    with open(a.file, encoding="utf-8") as f:
        data = json.load(f)
    db_backup(app, "before-import")
    print(import_config(app, data, a.mode))
    print("Импорт завершён. Примените конфигурацию: nmctl apply")
    return 0


def cmd_versions(a) -> int:
    db = _db()
    for r in db.query("SELECT id, ts, username, source, status, comment FROM config_versions ORDER BY id DESC "
                      "LIMIT ?", (a.limit,)):
        st = C["ok"] if r["status"] == "applied" else C["fail"]
        print(f"#{r['id']:<5} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))}  {st}{r['status']:<8}"
              f"{C['r']} {r['username'] or '':<10} {r['source']:<9} {r['comment'] or ''}")
    return 0


def cmd_rollback(a) -> int:
    from .nginx.generator import State
    db = _db()
    m = _manager(db)
    r = db.one("SELECT state FROM config_versions WHERE id=?", (a.id,))
    if not r:
        print("Версия не найдена")
        return 1
    st = json.loads(r["state"])
    m.restore_state_to_db(st)
    res = m.apply_sync(State.from_json(st), "cli", f"Откат к версии {a.id}", "rollback")
    print(f"{C['ok']}✓ Откат выполнен, новая версия {res['version']}{C['r']}")
    return 0


def cmd_sites(a) -> int:
    db = _db()
    for r in db.query("SELECT id, name, enabled, data FROM sites ORDER BY id"):
        d = json.loads(r["data"])
        print(f"{r['id']:>3} {'●' if r['enabled'] else '○'} {r['name']:<28} {', '.join(d.get('domains', []))[:60]}")
    return 0


def cmd_vulns(a) -> int:
    from .core import App
    from .protection.vulndb import SOURCES
    app = App()
    db = app.protection.vulndb
    if a.action == "update":
        res = asyncio.run(db.update(force=True, user="nmctl"))
        a.action = "status"
        if not res.get("ok") or not (res.get("map") or {}).get("ok", True) or \
                not (res.get("crs") or {}).get("ok", True):
            cmd_vulns(a)
            return 1
    if a.action == "status":
        s = db.summary()
        mp = app.db.kv_get("vulndb_map", {}) or {}
        print(f"{C['b']}База уязвимостей{C['r']} ({'обновляется' if s['enabled'] else 'обновление выключено'}): "
              f"всего {s['total']}, эксплуатируемых {s['kev']} (+{s['kev_week']} за неделю), "
              f"атаковали ваши сайты: {s['seen']}")
        print(f"Карта путей эксплойтов: {mp.get('entries', 0)} путей, {mp.get('cves', 0)} уязвимостей, "
              f"режим «{s['mode']}»")
        order = ["kev", "nuclei", "templates", "cvelist", "epss", "exploitdb", "crs"]
        for k, st in sorted(s["sources"].items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99):
            title = SOURCES.get(k, ("nuclei-templates: шаблоны", ""))[0]
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(st["updated"])) if st.get("updated") else "ещё нет"
            mark = "fail" if st.get("error") else "ok" if st.get("ok") else "skip"
            line = f"{C[mark]}{ICON[mark]}{C['r']} {title:<36} {str(st.get('count') or st.get('tag') or ''):>7}  {when}"
            print(line + (f"  {st['error'][:120]}" if st.get("error") else ""))
        return 1 if any((v or {}).get("error") for v in s["sources"].values()) else 0
    if a.action == "show":
        if not a.query:
            raise ValueError("укажите номер CVE: nmctl vulns show CVE-2021-44228")
        v = db.get(a.query)
        if not v:
            raise ValueError(f"{a.query.upper()}: нет в базе")
        print(f"{C['b']}{v['cve']}{C['r']} {v['name']}")
        for label, val in (("Продукт", f"{v['vendor']} {v['product']}".strip()),
                           ("CVSS", f"{v['cvss'] or '—'} {v['cvss_vector']}".strip()),
                           ("EPSS", f"{v['epss'] * 100:.1f}%" if v["epss"] else "—"),
                           ("CISA KEV", f"добавлена {v['kev_added']}, срок {v['kev_due'] or '—'}" if v["kev"] else "нет"),
                           ("Вымогатели", "да" if v["ransomware"] else "нет"), ("Тип", v["cwe"] or "—"),
                           ("Затронутые версии", v["affected"] or "—"),
                           ("Эксплойты Exploit-DB", ", ".join(f"EDB-{x}" for x in v["exploits"]) or "—"),
                           ("Пути эксплойта", ", ".join(v["paths"]) or "—"),
                           ("В фильтре путей", "исключена" if v["excluded"] else "да" if v["active"] else "нет"),
                           ("Попыток на сайтах", sum(h["n"] for h in v["hits"]))):
            print(f"  {label + ':':<22} {val}")
        if v["description"]:
            print(f"  {v['description'][:600]}")
        return 0
    r = db.search(q=a.query or "", flt=a.filter, sort=a.sort, limit=a.limit)
    for v in r["rows"]:
        flags = ("KEV " if v["kev"] else "") + ("путь " if v["active"] else "") + ("R " if v["ransomware"] else "")
        print(f"{v['cve']:<16} {str(v['cvss'] or ''):>4}  {flags:<14} {(v['vendor'] + ' ' + v['product']).strip()[:30]:<30} "
              f"{v['name'][:70]}")
    print(f"Найдено: {r['total']}" + (f", показано {len(r['rows'])}" if r["total"] > len(r["rows"]) else ""))
    return 0


def cmd_deps(a) -> int:
    """Пакеты и модули для функций панели: что есть, чего не хватает; --packages apt|dnf — список для установки."""
    from .services.deps import missing_packages, report
    db = _db()
    items = report(db, _manager(db))
    if a.packages:
        for name in missing_packages(items, a.packages):
            print(name)
        return 0
    if a.json:
        print(json.dumps(items, ensure_ascii=False, indent=1))
        return 0
    for x in items:
        st = "ok" if x["ok"] else ("fail" if x["required"] else "warn")
        pk = ", ".join(x["apt"] or x["dnf"]) if not x["ok"] else ""
        print(f"  {C[st]}{ICON[st]}{C['r']} {x['title']}: {x['why']}" + (f" — пакеты: {pk}" if pk else ""))
    return 0 if all(x["ok"] for x in items) else 2


def cmd_lists(a) -> int:
    """Подпись списков адресов по ссылке (Ed25519): ключи, подпись, проверка. Работает и без установленной панели."""
    from .services import ed25519 as E
    if a.action == "keygen":
        secret, public = E.keygen()
        text = "ed25519-secret:" + __import__("base64").b64encode(secret).decode() + "\n"
        if a.output:
            out = Path(a.output)
            if out.exists():
                raise ValueError(f"{out} уже есть — не перезаписываю")
            fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            print(f"Закрытый ключ: {out} (храните его там, где готовится список; на серверы панели он не нужен)")
        else:
            print("Закрытый ключ (сохраните в файл с правами 600):", text.strip())
        print("Открытый ключ (поле «Открытый ключ подписи» у списка):", E.format_public(public))
        return 0
    if not a.file:
        raise ValueError("Укажите файл списка")
    data = Path(a.file).read_bytes()
    if a.action == "sign":
        if not a.key:
            raise ValueError("Укажите --key ФАЙЛ закрытого ключа (nmctl lists keygen или openssl genpkey -algorithm "
                             "ed25519)")
        secret = E.parse_secret(Path(a.key).read_text())
        sig = E.sign(secret, data)
        out = Path(a.file + ".sig")
        out.write_text(__import__("base64").b64encode(sig).decode() + "\n")
        print(f"Подпись: {out}; открытый ключ: {E.format_public(E.public_key(secret))}")
        return 0
    if not a.pub:
        raise ValueError("Укажите --pub открытый ключ (ed25519:…)")
    sig = Path(a.sig or a.file + ".sig").read_bytes()
    ok = E.verify_any(E.parse_publics(a.pub), data, E.parse_signature(sig if len(sig) == 64 else sig.strip()))
    print(f"{C['ok']}✓ подпись верна{C['r']}" if ok else f"{C['fail']}✗ подпись не совпадает{C['r']}")
    return 0 if ok else 1


def cmd_os(a) -> int:
    """Срок поддержки ОС: 0 — поддерживается, 1 — поддержка закончилась, 2 — заканчивается в ближайшие полгода."""
    from .services import osinfo
    r = osinfo.check()
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        st = {"ok": "ok", "soon": "warn", "eol": "fail"}.get(r["level"], "info")
        print(f"  {C[st]}{ICON[st]}{C['r']} {r['message']}")
    return {"eol": 1, "soon": 2}.get(r["level"], 0)


def _peer(db, name: str):
    from .models import PanelSettings
    peers = PanelSettings.model_validate(db.kv_get("panel_settings", {})).peers
    m = [p for p in peers if p.id == name or p.name == name] or \
        [p for p in peers if p.name.lower().startswith(name.lower())]
    if len(m) != 1:
        raise ValueError(f"Сервер «{name}» не найден" if not m else
                         f"«{name}» подходит к нескольким серверам: {', '.join(p.name for p in m)}")
    return m[0]


def cmd_peers(a) -> int:
    """Другие серверы: проверка связи и состояние обмена."""
    from .models import PanelSettings
    from .services.peers import _err, call, instance_id
    db = _db()
    ps = PanelSettings.model_validate(db.kv_get("panel_settings", {}))
    st = db.kv_get("peers_status", {}) or {}
    print(f"{C['b']}Этот сервер:{C['r']} {ps.peer_name or os.uname().nodename} ({instance_id(db)})")
    if not ps.peers:
        print("  Других серверов нет — добавьте их в «Настройки панели → Другие серверы»")
        return 0
    bad = 0
    for p in ps.peers:
        x = st.get(p.id) or {}
        try:
            code, d = call(p, "GET", "/sync/hello", None, ps.peers_verify_tls, timeout=10)
            link = f"{C['ok']}✓{C['r']} {d.get('name')} {d.get('version')}, токен «{d.get('role')}»" if code == 200 \
                else f"{C['fail']}✗{C['r']} {_err(code, d)}"
            bad += code != 200
        except Exception as e:  # noqa: BLE001
            link, bad = f"{C['fail']}✗{C['r']} нет связи: {e}", bad + 1
        what = [w for w, on in (("блокировки", p.bans), ("доверенные", p.trusted), ("защита", p.protection),
                                ("сайты" + (f" [{p.sites_tag}]" if p.sites_tag else ""), p.sites)) if on]
        print(f"  {C['b']}{p.name}{C['r']} {p.url}{'' if p.enabled else ' (выключен)'}\n    связь: {link}\n"
              f"    обмен: {', '.join(what) or '—'}")
        if p.sites and x.get("sites_at"):
            print(f"    сайты: версия {x.get('sites_version')}, {x.get('sites_sent', 0)} сайтов"
                  + (f" — {x['sites_error'] or x.get('sites_note')}" if x.get("sites_error") or x.get("sites_note")
                     else ""))
    return 1 if bad else 0


def cmd_transfer(a) -> int:
    """Перенести сайты с сертификатами на другой сервер (как «Перенести сайты…» в панели)."""
    from .models import PanelSettings
    from .services import transfer as TF
    from .services.peers import _err, call, instance_id
    db = _db()
    peer = _peer(db, a.to)
    ps = PanelSettings.model_validate(db.kv_get("panel_settings", {}))
    rows = db.query("SELECT id, data FROM sites ORDER BY id")
    if a.all:
        ids = [r["id"] for r in rows]
    elif a.tag:
        ids = [r["id"] for r in rows if a.tag in (json.loads(r["data"]).get("tags") or [])]
    else:
        ids = [int(x) for x in a.sites.replace(" ", "").split(",") if x]
    if not ids:
        raise ValueError("Не выбраны сайты: --sites 1,3, --tag метка или --all")
    payload = TF.build(db, ids, not a.no_certs)
    origin = {"id": instance_id(db), "name": ps.peer_name or os.uname().nodename}
    print(f"Перенос на «{peer.name}»: сайтов {len(payload['sites'])}, сертификатов {len(payload['certs'])}…")
    code, d = call(peer, "POST", "/sync/sites", {"origin": origin, **payload, "overwrite": a.overwrite,
                                                 "apply": not a.no_apply}, ps.peers_verify_tls, timeout=180)
    if code == 404:
        raise ValueError("на сервере старая версия Nginx Manager (перенос сайтов — с версии 2.6)")
    if code != 200:
        raise ValueError(_err(code, d))
    if payload["certs"]:
        TF.remember(db, peer.id, payload["certs"])
    s = d.get("sites") or {}
    words = {"created": "создан", "updated": "обновлён", "skipped": "пропущен", "error": "ошибка"}
    for it in s.get("items", []):
        st = {"created": "ok", "updated": "ok", "skipped": "warn"}.get(it["action"], "fail")
        print(f"  {C[st]}{ICON[st]}{C['r']} {it['name']} — {words.get(it['action'], it['action'])}"
              + (f": {'; '.join(it['notes'])}" if it.get("notes") else ""))
    c = d.get("certs") or {}
    print(f"Сертификаты: новых {c.get('created', 0)}, обновлено {c.get('updated', 0)}"
          + (f"; ошибки: {'; '.join(c['errors'])}" if c.get("errors") else ""))
    if d.get("applied"):
        print(f"{C['ok']}✓{C['r']} конфигурация применена на «{d.get('name')}» (версия {d['applied']})")
    elif d.get("apply_error"):
        print(f"{C['warn']}!{C['r']} не применено: {d['apply_error']}")
    db.event("info", "peers", f"Сайты отправлены на сервер «{peer.name}» из консоли (nmctl): {len(ids)}")
    return 0 if not s.get("skipped") and not c.get("errors") else 2


def _backup_password(a) -> str:
    if getattr(a, "password_file", ""):
        return Path(a.password_file).read_text().strip()
    return os.environ.get("NM_BACKUP_PASSWORD") or os.environ.get("NM_BACKUP_PASS", "")


class _CliApp:
    """Минимальное «приложение» для восстановления настроек из консоли (без фоновых задач панели)."""

    def __init__(self, db):
        from .models import PanelSettings
        from .services.certs import CertificateService
        self.db = db
        self._panel = None
        self.certs = CertificateService(db, lambda: PanelSettings.model_validate(db.kv_get("panel_settings", {})))
        self.protection = type("P", (), {"_settings": None})()
        self.bans = type("B", (), {"dirty": False})()

    def touch(self):
        pass

    def refresh_runtime_maps(self):
        pass


def _s3_from_url(a, db, url: str):
    """s3://бакет/префикс/[имя|latest] → (клиент, префикс, имя или ''). Адрес и ключи — из --endpoint и
    NM_S3_ACCESS_KEY / NM_S3_SECRET_KEY (новый сервер) или из настроек панели, если бакет — её хранилище."""
    import urllib.parse
    from .models import PanelSettings
    from .services.s3 import S3Client
    u = urllib.parse.urlparse(url)
    if u.scheme != "s3" or not u.netloc:
        raise ValueError("Адрес копии в хранилище — s3://бакет/префикс/имя-файла (или …/latest)")
    bucket, rest = u.netloc, u.path.lstrip("/")
    name = ""
    if rest.endswith(".settings.tar.gz") or rest.endswith(".settings.tar.gz.enc") or rest.endswith("/latest") \
            or rest == "latest":
        prefix, _, name = rest.rpartition("/")
        prefix = prefix + "/" if prefix else ""
    else:
        prefix = rest if not rest or rest.endswith("/") else rest + "/"
    ak, sk = os.environ.get("NM_S3_ACCESS_KEY", ""), os.environ.get("NM_S3_SECRET_KEY", "")
    endpoint = a.endpoint or os.environ.get("NM_S3_ENDPOINT", "")
    region = a.region or os.environ.get("NM_S3_REGION", "")
    path_style = not a.virtual_host
    if not endpoint:
        ps = PanelSettings.model_validate(db.kv_get("panel_settings", {}))
        if ps.sb_s3 and ps.sb_s3_bucket == bucket:
            endpoint, region, ak, sk, path_style = (ps.sb_s3_endpoint, ps.sb_s3_region, ak or ps.sb_s3_access_key,
                                                    sk or ps.sb_s3_secret_key, ps.sb_s3_path_style)
        elif ps.s3_endpoint and ps.s3_bucket == bucket:
            endpoint, region, ak, sk, path_style = (ps.s3_endpoint, ps.s3_region, ak or ps.s3_access_key,
                                                    sk or ps.s3_secret_key, ps.s3_path_style)
        else:
            raise ValueError("Укажите --endpoint (адрес хранилища) — этот бакет не настроен в панели")
    if not ak and sys.stdin.isatty():
        ak = input("Access key ID: ").strip()
    if not sk and sys.stdin.isatty():
        sk = getpass.getpass("Secret access key: ")
    if not ak or not sk:
        raise ValueError("Ключи хранилища — переменные NM_S3_ACCESS_KEY и NM_S3_SECRET_KEY")
    return S3Client(endpoint, region or "us-east-1", bucket, ak, sk, path_style), prefix, name


def _s3_settings_list(cl, prefix: str):
    return sorted((o for o in cl.list(prefix) if ".settings.tar.gz" in o["key"] and "/" not in o["key"][len(prefix):]),
                  key=lambda o: o["key"])


def _s3_fetch(a, db, url: str) -> Path:
    from .config import settings
    cl, prefix, name = _s3_from_url(a, db, url)
    if not name or name == "latest":
        objs = _s3_settings_list(cl, prefix)
        if not objs:
            raise ValueError(f"В s3://{cl.bucket}/{prefix} нет копий настроек")
        name = objs[-1]["key"][len(prefix):]
    if not name.startswith("nginx-manager-"):
        raise ValueError("Это не копия настроек Nginx Manager")
    settings.ensure_dirs()
    dest = settings.backups_dir / name
    cl.get_to_file(prefix + name, dest)
    dest.chmod(0o600)
    print(f"{C['ok']}✓{C['r']} скачана {name} ({dest.stat().st_size // 1024} КБ) → {dest}")
    return dest


def cmd_settings(a) -> int:
    """Копия всех настроек: backup | inspect | restore | remote | fetch."""
    from .services import settings_backup as SB
    db = _db()
    password = _backup_password(a)
    if a.action == "remote":
        if not a.file:
            raise ValueError("Укажите s3://бакет/префикс/")
        cl, prefix, _ = _s3_from_url(a, db, a.file)
        objs = _s3_settings_list(cl, prefix)
        for o in objs:
            print(f"  {o['key'][len(prefix):]:<64} {o.get('size', 0) // 1024:>6} КБ  {o.get('last_modified', '')}")
        print(f"копий настроек: {len(objs)} (s3://{cl.bucket}/{prefix})")
        return 0
    if a.action == "fetch":
        if not a.file:
            raise ValueError("Укажите s3://бакет/префикс/имя-файла или …/latest")
        _s3_fetch(a, db, a.file)
        return 0
    if a.action == "backup":
        app = _CliApp(db)
        p = SB.create(app, "cli", None, password, dest_dir=Path(a.output) if a.output else None)
        print(f"{C['ok']}✓{C['r']} {p} ({p.stat().st_size // 1024} КБ" + (", зашифрована)" if password else ")"))
        if not password:
            print(f"{C['warn']}!{C['r']} без пароля: в файле открыто лежат ключи сертификатов и пароли интеграций "
                  "(задайте NM_BACKUP_PASSWORD или --password-file)")
        return 0
    if not a.file:
        raise ValueError("Укажите файл копии")
    path = _s3_fetch(a, db, a.file) if a.file.startswith("s3://") else Path(a.file)
    if path.name.endswith(".enc") and not password and sys.stdin.isatty():
        password = getpass.getpass("Пароль копии: ")
    if a.action == "inspect":
        info = SB.inspect(path, password)
        mf = info["manifest"]
        print(f"Копия {path.name}: версия {mf['version']}, сервер {mf['host']}, "
              f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(mf['created_at']))}")
        for sec in info["sections"]:
            print(f"  {sec['id']:<13} {sec['count']:>5}  {sec['title']}")
        for w in info["warnings"]:
            print(f"  {C['warn']}!{C['r']} {w}")
        return 0
    sections = [x for x in a.sections.split(",") if x] if a.sections else list(SB.SECTIONS)
    app = _CliApp(db)
    safety = SB.create(app, "before-settings-restore")
    res = SB.restore(app, path, sections, password, "nmctl")
    print(f"{C['ok']}✓{C['r']} восстановлено: {', '.join(res['sections'])}; прежние настройки — {safety.name}")
    for n in res["notes"]:
        print(f"  {C['warn']}!{C['r']} {n}")
    rc = 0
    if res["nginx"] and not a.no_apply:
        from .nginx.manager import ApplyError
        try:
            m = _manager(db)
            r = m.apply_sync(m.load_state(), "cli", f"Восстановление настроек из {path.name}", "restore")
            print(f"{C['ok']}✓{C['r']} конфигурация применена (версия {r['version']})")
        except ApplyError as e:
            SB.restore(app, safety, sections, "", "nmctl")
            print(f"{C['fail']}✗{C['r']} nginx не принял конфигурацию — настройки возвращены: {e}")
            rc = 1
    from .utils import has_systemd, run
    if has_systemd():
        run(["systemctl", "restart", "nginx-manager"], timeout=60)
        print("панель перезапущена, чтобы перечитать настройки")
    else:
        print("перезапустите панель, чтобы она перечитала настройки")
    return rc


def main(argv=None) -> int:
    import os
    os.umask(0o022)
    ap = argparse.ArgumentParser(prog="nmctl", description="Администрирование Nginx Manager")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="состояние")
    p = sub.add_parser("apply", help="применить конфигурацию")
    p.add_argument("-m", "--message", default="")
    sub.add_parser("test", help="nginx -t")
    p = sub.add_parser("diag", help="диагностика")
    p.add_argument("-p", "--problems", action="store_true", help="только проблемы")
    p = sub.add_parser("user", help="пользователи")
    p.add_argument("action", choices=["list", "add", "passwd", "reset-2fa", "disable", "enable", "role", "delete"])
    p.add_argument("username", nargs="?")
    p.add_argument("--role", default="admin", choices=["admin", "operator", "viewer"])
    p.add_argument("--password", default="")
    p = sub.add_parser("allowlist", help="доступ к панели по IP")
    p.add_argument("action", choices=["show", "clear"])
    sub.add_parser("backup", help="резервная копия")
    p = sub.add_parser("restore", help="восстановить базу из копии")
    p.add_argument("file", help="файл копии: .db, .db.gz или .db.gz.enc (пароль — запрос или NM_BACKUP_PASS)")
    p.add_argument("-y", "--yes", action="store_true", help="не спрашивать подтверждение")
    p = sub.add_parser("export", help="экспорт настроек в JSON")
    p.add_argument("--users", action="store_true")
    p = sub.add_parser("import", help="импорт настроек из JSON")
    p.add_argument("file")
    p.add_argument("--mode", default="replace", choices=["replace", "merge"])
    p = sub.add_parser("versions", help="история конфигураций")
    p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("rollback", help="откат к версии")
    p.add_argument("id", type=int)
    sub.add_parser("sites", help="список сайтов")
    p = sub.add_parser("vulns", help="база уязвимостей и обновление баз защиты")
    p.add_argument("action", choices=["status", "update", "search", "show"])
    p.add_argument("query", nargs="?", default="", help="текст поиска или номер CVE")
    p.add_argument("--filter", default="", choices=["", "kev", "patched", "covered", "uncovered", "seen", "exploit",
                                                     "ransomware", "critical", "epss"])
    p.add_argument("--sort", default="kev", choices=["kev", "new", "cvss", "epss", "seen", "cve"])
    p.add_argument("--limit", type=int, default=30)
    p = sub.add_parser("deps", help="системные пакеты и модули nginx для функций панели")
    p.add_argument("--packages", default="", choices=["", "apt", "dnf", "yum"],
                   help="вывести недостающие пакеты для пакетного менеджера (по одному в строке)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("os", help="срок поддержки ОС")
    p.add_argument("--json", action="store_true")
    sub.add_parser("peers", help="другие серверы: связь и обмен")
    p = sub.add_parser("settings", help="копия всех настроек и восстановление")
    p.add_argument("action", choices=["backup", "inspect", "restore", "remote", "fetch"])
    p.add_argument("file", nargs="?", default="", help="файл копии или s3://бакет/префикс/имя (…/latest — последняя)")
    p.add_argument("--endpoint", default="", help="адрес S3-хранилища (или NM_S3_ENDPOINT); ключи — NM_S3_ACCESS_KEY, "
                                                  "NM_S3_SECRET_KEY")
    p.add_argument("--region", default="", help="регион хранилища (или NM_S3_REGION)")
    p.add_argument("--virtual-host", action="store_true", help="адресация virtual-hosted вместо path-style")
    p.add_argument("-o", "--output", default="", help="каталог для копии (по умолчанию — каталог копий панели)")
    p.add_argument("--password-file", default="", help="файл с паролем копии (или переменная NM_BACKUP_PASSWORD)")
    p.add_argument("--sections", default="", help="разделы через запятую: " + ", ".join(
        ["sites", "streams", "certificates", "dns", "global", "panel", "protection", "alerts", "users", "bans",
         "secrets"]))
    p.add_argument("--no-apply", action="store_true", help="не применять конфигурацию nginx")
    p = sub.add_parser("lists", help="подпись списков адресов по ссылке (Ed25519)")
    p.add_argument("action", choices=["keygen", "sign", "verify"])
    p.add_argument("file", nargs="?", default="", help="файл списка адресов")
    p.add_argument("-o", "--output", default="", help="keygen: файл для закрытого ключа")
    p.add_argument("--key", default="", help="sign: файл закрытого ключа")
    p.add_argument("--pub", default="", help="verify: открытый ключ ed25519:…")
    p.add_argument("--sig", default="", help="verify: файл подписи (по умолчанию СПИСОК.sig)")
    p = sub.add_parser("transfer", help="перенести сайты с сертификатами на другой сервер")
    p.add_argument("--to", required=True, help="сервер: название (или его начало) либо ID из «Другие серверы»")
    p.add_argument("--sites", default="", help="номера сайтов через запятую")
    p.add_argument("--tag", default="", help="все сайты с этой меткой")
    p.add_argument("--all", action="store_true", help="все сайты")
    p.add_argument("--no-certs", action="store_true", help="без сертификатов")
    p.add_argument("--overwrite", action="store_true", help="заменить сайты с теми же доменами")
    p.add_argument("--no-apply", action="store_true", help="не применять конфигурацию на получателе")
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 0
    cmd = {"status": cmd_status, "apply": cmd_apply, "test": cmd_test, "diag": cmd_diag, "user": cmd_user,
           "allowlist": cmd_allowlist, "backup": cmd_backup, "restore": cmd_restore, "export": cmd_export,
           "import": cmd_import,
           "versions": cmd_versions, "rollback": cmd_rollback, "sites": cmd_sites, "vulns": cmd_vulns,
           "deps": cmd_deps, "os": cmd_os, "peers": cmd_peers, "transfer": cmd_transfer,
           "settings": cmd_settings, "lists": cmd_lists}[a.cmd]
    from .nginx.manager import ApplyError
    try:
        return cmd(a)
    except ApplyError as e:  # понятное сообщение вместо трассировки
        print(f"{C['fail']}✗ {e}{C['r']}", file=sys.stderr)
        if e.output:
            print(e.output.strip()[-3000:], file=sys.stderr)
        return 1
    except (ValueError, OSError) as e:  # в т.ч. ошибки JSON и проверки данных, нет файла, нет прав
        print(f"{C['fail']}✗ {e}{C['r']}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
