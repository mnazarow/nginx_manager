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
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 0
    cmd = {"status": cmd_status, "apply": cmd_apply, "test": cmd_test, "diag": cmd_diag, "user": cmd_user,
           "allowlist": cmd_allowlist, "backup": cmd_backup, "restore": cmd_restore, "export": cmd_export,
           "import": cmd_import,
           "versions": cmd_versions, "rollback": cmd_rollback, "sites": cmd_sites}[a.cmd]
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
