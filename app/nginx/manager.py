"""Управление nginx: определение возможностей, применение конфигурации с проверкой,
атомарное переключение версий, откат, управление процессом."""
from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import pwd
import grp
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from ..config import settings
from ..db import Database
from ..models import GlobalSettings, PanelSettings, Site, Stream
from ..utils import atomic_write, has_systemd, run, sha256, which
from .generator import MARKER, CertInfo, ConfigError, Generator, NginxCaps, Paths, State

log = logging.getLogger("nm.nginx")

ERR_RE = re.compile(r"\[(emerg|alert|crit|error|warn)\]\s+(.*?)(?:\s+in\s+(/\S+?):(\d+))?\s*$")


class ApplyError(Exception):
    def __init__(self, message: str, output: str = "", errors: Optional[List[dict]] = None,
                 site_id: Optional[int] = None):
        super().__init__(message)
        self.output = output
        self.errors = errors or []
        self.site_id = site_id


class NginxManager:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.lock = asyncio.Lock()
        self._caps: Optional[NginxCaps] = None
        self._caps_ts = 0.0
        self._last_test: Tuple[float, bool, str] = (0.0, True, "")
        self.binary = settings.nginx_bin or which("nginx") or "/usr/sbin/nginx"

    # =====================================================================
    #  Возможности nginx
    # =====================================================================
    def version_output(self) -> str:
        return run([self.binary, "-V"], timeout=10)[1]

    def caps(self, refresh: bool = False) -> NginxCaps:
        if self._caps and not refresh and time.time() - self._caps_ts < 300:
            return self._caps
        out = self.version_output()
        caps = NginxCaps()
        m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", out)
        if m:
            caps.version = tuple(int(x) for x in m.groups())  # type: ignore[assignment]
        caps.modules = set(re.findall(r"--with-(\w+?)_module", out))
        for incdir in ("/etc/nginx/modules-enabled", "/usr/share/nginx/modules"):
            if Path(incdir).is_dir() and any(Path(incdir).glob("*.conf")):
                caps.module_includes.append(f"{incdir}/*.conf")
        stream_builtin = re.search(r"--with-stream(\s|$)", out) is not None
        if stream_builtin:
            caps.stream_available = True
        else:
            loaded = False
            for incdir in ("/etc/nginx/modules-enabled", "/usr/share/nginx/modules"):
                for f in Path(incdir).glob("*.conf") if Path(incdir).is_dir() else []:
                    try:
                        if "ngx_stream_module" in f.read_text():
                            loaded = True
                    except OSError:
                        pass
            if loaded:
                caps.stream_available = True
            else:
                mp = re.search(r"--modules-path=(\S+)", out)
                cands = [Path(mp.group(1)) / "ngx_stream_module.so"] if mp else []
                cands += [Path("/usr/lib/nginx/modules/ngx_stream_module.so"),
                          Path("/usr/lib64/nginx/modules/ngx_stream_module.so")]
                so = next((c for c in cands if c.exists()), None)
                caps.stream_available = so is not None
                caps.stream_load = str(so) if so else ""
        pm = re.search(r"--pid-path=(\S+)", out)
        caps.pid_path = pm.group(1) if pm else "/run/nginx.pid"
        cm = re.search(r"--conf-path=(\S+)", out)
        conf_dir = Path(cm.group(1)).parent if cm else Path("/etc/nginx")
        caps.mime_types = str(conf_dir / "mime.types")
        for u in ("www-data", "nginx", "http", "nobody"):
            try:
                pwd.getpwnam(u)
                caps.default_user = u
                break
            except KeyError:
                continue
        try:
            caps.ipv6 = Path("/proc/net/if_inet6").stat().st_size > 0
        except OSError:
            caps.ipv6 = False
        for ca in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                   "/etc/ssl/ca-bundle.pem"):
            if Path(ca).exists():
                caps.ca_bundle = ca
                break
        self._caps, self._caps_ts = caps, time.time()
        return caps

    def info(self) -> Dict[str, Any]:
        out = self.version_output()
        caps = self.caps(refresh=True)
        m = re.search(r"configure arguments: (.*)", out)
        return {
            "binary": self.binary,
            "version": ".".join(map(str, caps.version)),
            "version_full": out.splitlines()[0] if out else "",
            "openssl": (re.search(r"built with (OpenSSL [^\s]+|LibreSSL [^\s]+|BoringSSL)", out) or [None, ""])[1]
            if out else "",
            "modules": sorted(caps.modules),
            "stream": caps.stream_available,
            "http3": caps.http3,
            "http2_directive": caps.http2_directive,
            "reject_handshake": caps.reject_handshake,
            "configure": m.group(1) if m else "",
            "pid_path": caps.pid_path,
            "user": caps.default_user,
            "ipv6": caps.ipv6,
        }

    # =====================================================================
    #  Состояние из БД
    # =====================================================================
    def load_state(self) -> State:
        sites = [(r["id"], Site.model_validate(json.loads(r["data"])))
                 for r in self.db.query("SELECT id, data FROM sites ORDER BY id")]
        streams = [(r["id"], Stream.model_validate(json.loads(r["data"])))
                   for r in self.db.query("SELECT id, data FROM streams ORDER BY id")]
        glob = GlobalSettings.model_validate(self.db.kv_get("global_settings", {}))
        panel = PanelSettings.model_validate(self.db.kv_get("panel_settings", {}))
        certs = {}
        for r in self.db.query("SELECT id, cert_path, key_path, status FROM certificates"):
            ok = r["status"] == "valid" and Path(r["cert_path"]).exists() and Path(r["key_path"]).exists()
            certs[r["id"]] = CertInfo(r["id"], r["cert_path"], r["key_path"], ok)
        return State(sites, streams, glob, panel, certs)

    def paths(self, include_root: str) -> Paths:
        return Paths(include_root=include_root, live_root=str(settings.live_dir),
                     acme_webroot=str(settings.acme_webroot), log_dir=str(settings.log_dir),
                     cache_dir=str(settings.cache_dir), stub_status_port=settings.stub_status_port,
                     panel_port=settings.bind_port, data_dir=str(settings.data_dir))

    def render(self, state: State, include_root: Optional[str] = None) -> Tuple[Dict[str, str], List[str]]:
        gen = Generator(state, self.caps(), self.paths(include_root or str(settings.live_dir)))
        files = gen.render()
        return files, gen.warnings

    @staticmethod
    def checksum(files: Dict[str, str]) -> str:
        return sha256(json.dumps(files, sort_keys=True, ensure_ascii=False))

    # =====================================================================
    #  Версии
    # =====================================================================
    def last_applied(self) -> Optional[Dict[str, Any]]:
        return self.db.one("SELECT * FROM config_versions WHERE status='applied' ORDER BY id DESC LIMIT 1")

    def pending(self) -> Dict[str, Any]:
        """Есть ли неприменённые изменения (сравнение рендера БД с последней применённой версией)."""
        try:
            files, warnings = self.render(self.load_state())
        except (ConfigError, ValueError) as e:
            return {"pending": True, "error": str(e), "changed": []}
        last = self.last_applied()
        if not last:
            return {"pending": True, "changed": sorted(files), "warnings": warnings}
        old = json.loads(last["files"])
        changed = sorted(k for k in set(files) | set(old) if files.get(k) != old.get(k))
        return {"pending": bool(changed), "changed": changed, "warnings": warnings, "version": last["id"]}

    def diff(self, old: Dict[str, str], new: Dict[str, str]) -> List[Dict[str, Any]]:
        out = []
        for name in sorted(set(old) | set(new)):
            a, b = old.get(name), new.get(name)
            if a == b or name.endswith(".keep"):
                continue
            status = "added" if a is None else "removed" if b is None else "modified"
            lines = list(difflib.unified_diff((a or "").splitlines(), (b or "").splitlines(),
                                              fromfile=f"a/{name}", tofile=f"b/{name}", lineterm="", n=3))
            out.append({"file": name, "status": status, "diff": "\n".join(lines),
                        "added": sum(1 for x in lines if x.startswith("+") and not x.startswith("+++")),
                        "removed": sum(1 for x in lines if x.startswith("-") and not x.startswith("---"))})
        return out

    def pending_diff(self) -> List[Dict[str, Any]]:
        files, _ = self.render(self.load_state())
        last = self.last_applied()
        return self.diff(json.loads(last["files"]) if last else {}, files)

    # =====================================================================
    #  Проверка и применение
    # =====================================================================
    def test_config(self, conf: Optional[Path] = None) -> Tuple[bool, str]:
        cmd = [self.binary, "-t"]
        if conf:
            cmd += ["-c", str(conf)]
        code, out = run(cmd, timeout=60)
        if conf is None:
            self._last_test = (time.time(), code == 0, out)
        return code == 0, out

    def parse_errors(self, output: str, files: Dict[str, str], root: str) -> List[dict]:
        errors = []
        for line in output.splitlines():
            m = ERR_RE.search(line)
            if not m:
                continue
            level, msg, path, lineno = m.group(1), m.group(2), m.group(3), m.group(4)
            item: Dict[str, Any] = {"level": level, "message": msg, "file": path, "line": int(lineno or 0)}
            if path and path.startswith(root):
                rel = path[len(root):].lstrip("/")
                item["file"] = rel
                sm = re.match(r"(sites|streams)/(?:site|stream)-(\d+)-", rel)
                if sm:
                    item["kind"] = "site" if sm.group(1) == "sites" else "stream"
                    item["object_id"] = int(sm.group(2))
                content = files.get(rel, "")
                if content and lineno:
                    ls = content.splitlines()
                    n = int(lineno)
                    item["context"] = [{"n": i + 1, "text": ls[i], "error": i + 1 == n}
                                       for i in range(max(0, n - 4), min(len(ls), n + 3))]
            item["hint"] = explain_nginx_error(msg)
            errors.append(item)
        return errors

    def _prepare_dirs(self, state: State, user: str) -> None:
        try:
            pw = pwd.getpwnam(user)
            uid, gid = pw.pw_uid, pw.pw_gid
        except KeyError:
            uid = gid = -1
        settings.cache_dir.mkdir(parents=True, exist_ok=True)
        for z in state.glob.cache_zones:
            d = settings.cache_dir / z.name
            d.mkdir(parents=True, exist_ok=True)
            if uid >= 0:
                os.chown(d, uid, gid)
        if uid >= 0:
            os.chown(settings.cache_dir, uid, gid)
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        for f in (settings.access_log, settings.error_log, settings.stream_log):
            if not f.exists():
                f.touch()
                os.chmod(f, 0o640)
        if state.glob.ssl_dhparam and not (settings.certs_dir / "dhparam.pem").exists():
            (settings.certs_dir / "dhparam.pem").write_text(FFDHE2048)

    def _write_tree(self, root: Path, files: Dict[str, str], group: str) -> None:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            gid = -1
        root.mkdir(parents=True, exist_ok=True)
        for d in (settings.managed_dir, settings.versions_dir, root):
            os.chmod(d, 0o755)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            os.chmod(p.parent, 0o755)
            if rel.startswith("auth/"):
                atomic_write(p, content, 0o640)
                if gid >= 0:
                    os.chown(p, 0, gid)
            else:
                atomic_write(p, content, 0o644)

    def _switch_live(self, target: Path) -> Optional[str]:
        live = settings.live_dir
        prev = os.readlink(live) if live.is_symlink() else None
        if live.exists() and not live.is_symlink():
            shutil.move(str(live), str(live) + f".old-{int(time.time())}")
        tmp = live.with_name(".live.tmp")
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(str(target), tmp)
        os.replace(tmp, live)
        return prev

    def _restore_live(self, prev: Optional[str]) -> None:
        if prev:
            tmp = settings.live_dir.with_name(".live.tmp")
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            os.symlink(prev, tmp)
            os.replace(tmp, settings.live_dir)

    def fix_permissions(self, user: str) -> List[str]:
        """Права на каталоги конфигурации, страницы, ACME и кэш, чтобы воркеры nginx могли их читать."""
        fixed = []
        try:
            gid = grp.getgrnam(user).gr_gid
        except KeyError:
            gid = -1
        for d in (settings.managed_dir, settings.versions_dir):
            if d.is_dir() and (d.stat().st_mode & 0o755) != 0o755:
                os.chmod(d, 0o755)
                fixed.append(str(d))
        if settings.versions_dir.is_dir():
            for vd in settings.versions_dir.iterdir():
                for path in [vd] + list(vd.rglob("*")):
                    try:
                        st = path.stat()
                        if path.is_dir():
                            want = 0o755
                        elif "/auth/" in str(path):
                            want = 0o640
                            if gid >= 0 and st.st_gid != gid:
                                os.chown(path, 0, gid)
                        else:
                            want = 0o644
                        if st.st_mode & 0o777 != want:
                            os.chmod(path, want)
                            fixed.append(str(path))
                    except OSError:
                        continue
        settings.ensure_dirs()
        return fixed

    def unreadable_paths(self, user: str) -> List[str]:
        """Пути, которые не сможет прочитать пользователь воркеров nginx."""
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            return []
        groups = {g.gr_gid for g in grp.getgrall() if user in g.gr_mem} | {pw.pw_gid}

        def can(path: Path, bits: int) -> bool:
            try:
                st = path.stat()
            except OSError:
                return True
            if st.st_uid == pw.pw_uid:
                return bool(st.st_mode & (bits << 6))
            if st.st_gid in groups:
                return bool(st.st_mode & (bits << 3))
            return bool(st.st_mode & bits)
        bad = []
        live = settings.live_dir
        targets = [live / "pages" / "error-502.html", settings.acme_webroot / ".well-known" / "acme-challenge"]
        targets += list((live / "auth").glob("*.htpasswd")) if (live / "auth").is_dir() else []
        for t in targets:
            p = Path(os.path.realpath(t))
            chain = [p] + list(p.parents)
            for c in reversed(chain[1:]):
                if not can(c, 1):
                    bad.append(f"{c} (нет права прохода)")
                    break
            else:
                if p.exists() and not can(p, 4 if p.is_file() else 5):
                    bad.append(f"{p} (нет права чтения)")
        return sorted(set(bad))

    def ensure_original_backup(self) -> None:
        conf = settings.nginx_conf
        backup = conf.with_name(conf.name + ".nm-orig")
        try:
            if conf.exists() and not backup.exists() and MARKER not in conf.read_text():
                shutil.copy2(conf, backup)
                log.info("Сохранена исходная конфигурация nginx: %s", backup)
        except OSError as e:
            log.warning("Не удалось сохранить исходную конфигурацию: %s", e)

    def apply_sync(self, state: State, username: str = "system", comment: str = "",
                   source: str = "user") -> Dict[str, Any]:
        """Полный цикл применения. Бросает ApplyError с понятным описанием проблемы."""
        t0 = time.time()
        caps = self.caps(refresh=True)
        tag = time.strftime("%Y%m%d-%H%M%S") + f"-{int(t0 * 1000) % 1000:03d}"
        vdir = settings.versions_dir / tag
        try:
            staged_files, warnings = self.render(state, include_root=str(vdir))
            live_files, _ = self.render(state, include_root=str(settings.live_dir))
        except ConfigError as e:
            raise ApplyError(str(e), site_id=e.site_id)
        user = state.glob.user or caps.default_user
        self.ensure_original_backup()
        self._prepare_dirs(state, user)
        self._write_tree(vdir, {k: v for k, v in staged_files.items() if k != "nginx.conf"}, user)
        staged_main = vdir / "nginx.conf"
        atomic_write(staged_main, staged_files["nginx.conf"])
        # 1) проверка во «временном» каталоге — работающий nginx не затрагивается
        ok, out = self.test_config(staged_main)
        if not ok:
            errors = self.parse_errors(out, staged_files, str(vdir))
            shutil.rmtree(vdir, ignore_errors=True)
            self._save_version(state, live_files, username, comment, source, "failed", out)
            raise ApplyError("Конфигурация не прошла проверку nginx -t", out, errors,
                             site_id=next((e.get("object_id") for e in errors if e.get("kind") == "site"), None))
        # 2) переключение
        conf = settings.nginx_conf
        old_main = conf.read_text() if conf.exists() else None
        prev = self._switch_live(vdir)
        atomic_write(conf, live_files["nginx.conf"])
        ok, out2 = self.test_config()
        if not ok:
            self._rollback_files(prev, old_main)
            raise ApplyError("Итоговая конфигурация не прошла проверку — изменения отменены", out2,
                             self.parse_errors(out2, live_files, str(settings.live_dir)))
        # 3) перезагрузка
        rok, rout = self.reload_or_start()
        if not rok:
            self._rollback_files(prev, old_main)
            self.reload_or_start()
            raise ApplyError("nginx не смог перечитать конфигурацию — восстановлена предыдущая версия", rout)
        time.sleep(0.6)
        if not self.is_running():
            self._rollback_files(prev, old_main)
            self.reload_or_start()
            raise ApplyError("nginx остановился после перезагрузки — восстановлена предыдущая версия",
                             "\n".join(self.recent_error_log(30)))
        vid = self._save_version(state, live_files, username, comment, source, "applied", out + rout)
        self._cleanup_versions(keep=10)
        self.db.kv_set("applied_version", vid)
        return {"version": vid, "warnings": warnings, "duration": round(time.time() - t0, 2), "output": out}

    def _rollback_files(self, prev: Optional[str], old_main: Optional[str]) -> None:
        self._restore_live(prev)
        if old_main is not None:
            atomic_write(settings.nginx_conf, old_main)

    def _save_version(self, state: State, files: Dict[str, str], username: str, comment: str,
                      source: str, status: str, output: str) -> int:
        return self.db.execute(
            "INSERT INTO config_versions(ts,username,comment,source,status,files,state,output,checksum) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (time.time(), username, comment, source, status, json.dumps(files, ensure_ascii=False),
             json.dumps(state.to_json(), ensure_ascii=False), output[-20000:], self.checksum(files)))

    def _cleanup_versions(self, keep: int = 10) -> None:
        d = settings.versions_dir
        if not d.is_dir():
            return
        current = os.path.realpath(settings.live_dir)
        dirs = sorted((p for p in d.iterdir() if p.is_dir()), key=lambda p: p.name)
        for p in dirs[:-keep]:
            if os.path.realpath(p) != current:
                shutil.rmtree(p, ignore_errors=True)
        # ограничим историю в БД (последние 500 версий)
        self.db.execute("DELETE FROM config_versions WHERE id NOT IN "
                        "(SELECT id FROM config_versions ORDER BY id DESC LIMIT 500)")

    async def apply(self, state: Optional[State] = None, username: str = "system", comment: str = "",
                    source: str = "user") -> Dict[str, Any]:
        async with self.lock:
            st = state or self.load_state()
            res = await asyncio.to_thread(self.apply_sync, st, username, comment, source)
            self.db.event("info", "config", f"Конфигурация применена (версия {res['version']})",
                          {"user": username, "source": source, "comment": comment})
            return res

    def restore_state_to_db(self, state_json: dict) -> None:
        now = time.time()
        with self.db.transaction() as c:
            c.execute("DELETE FROM sites")
            for s in state_json.get("sites", []):
                c.execute("INSERT INTO sites(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (s["id"], s["data"]["name"], int(s["data"].get("enabled", True)),
                           json.dumps(s["data"], ensure_ascii=False), now, now))
            c.execute("DELETE FROM streams")
            for s in state_json.get("streams", []):
                c.execute("INSERT INTO streams(id,name,enabled,data,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (s["id"], s["data"]["name"], int(s["data"].get("enabled", True)),
                           json.dumps(s["data"], ensure_ascii=False), now, now))
            c.execute("INSERT INTO kv(key,value) VALUES('global_settings',?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (json.dumps(state_json.get("global", {}), ensure_ascii=False),))

    # =====================================================================
    #  Процесс nginx
    # =====================================================================
    def master_process(self) -> Optional[psutil.Process]:
        try:
            pid = int(Path(self.caps().pid_path).read_text().strip())
            p = psutil.Process(pid)
            if "nginx" in p.name():
                return p
        except (OSError, ValueError, psutil.Error):
            pass
        for p in psutil.process_iter(["name", "cmdline", "ppid"]):
            try:
                if p.info["name"] == "nginx" and "master process" in " ".join(p.info["cmdline"] or []):
                    return p
            except psutil.Error:
                continue
        return None

    def is_running(self) -> bool:
        return self.master_process() is not None

    def status(self) -> Dict[str, Any]:
        m = self.master_process()
        caps = self.caps()
        res: Dict[str, Any] = {"running": m is not None, "version": ".".join(map(str, caps.version)),
                               "binary": self.binary}
        if m:
            try:
                children = m.children()
                res.update(pid=m.pid, started=m.create_time(), uptime=time.time() - m.create_time(),
                           workers=len(children),
                           rss=sum(c.memory_info().rss for c in children) + m.memory_info().rss)
            except psutil.Error:
                pass
        ts, ok, out = self._last_test
        res["config_test"] = {"ts": ts, "ok": ok, "output": out}
        res["managed"] = self.is_managed()
        return res

    def is_managed(self) -> bool:
        try:
            return MARKER in settings.nginx_conf.read_text()
        except OSError:
            return False

    def _systemctl(self, action: str) -> Tuple[int, str]:
        return run(["systemctl", action, "nginx"], timeout=60)

    def reload_or_start(self) -> Tuple[bool, str]:
        if self.is_running():
            if has_systemd() and run(["systemctl", "is-active", "--quiet", "nginx"])[0] == 0:
                code, out = self._systemctl("reload")
            else:
                code, out = run([self.binary, "-s", "reload"], timeout=60)
            return code == 0, out
        return self.start()

    def start(self) -> Tuple[bool, str]:
        if has_systemd():
            code, out = self._systemctl("start")
        else:
            code, out = run([self.binary], timeout=60)
        time.sleep(0.5)
        return code == 0 and self.is_running(), out

    def stop(self) -> Tuple[bool, str]:
        if has_systemd():
            code, out = self._systemctl("stop")
        else:
            code, out = run([self.binary, "-s", "quit"], timeout=60)
        return code == 0, out

    def restart(self) -> Tuple[bool, str]:
        if has_systemd():
            code, out = self._systemctl("restart")
            time.sleep(0.5)
            return code == 0, out
        self.stop()
        for _ in range(20):
            if not self.is_running():
                break
            time.sleep(0.25)
        return self.start()

    def reopen_logs(self) -> Tuple[bool, str]:
        code, out = run([self.binary, "-s", "reopen"], timeout=30)
        return code == 0, out

    def recent_error_log(self, n: int = 50) -> List[str]:
        from ..utils import tail_lines
        return tail_lines(settings.error_log, n)

    def dump_config(self) -> str:
        return run([self.binary, "-T"], timeout=60)[1]


# =============================================================================
def explain_nginx_error(msg: str) -> str:
    """Человеческое пояснение типовых ошибок nginx -t."""
    rules = [
        (r"unknown directive \"(\w+)\"", "Неизвестная директива «{0}». Опечатка или модуль не установлен "
                                         "(например, для stream нужен пакет libnginx-mod-stream)."),
        (r"cannot load certificate.*No such file", "Файл сертификата не найден. Выпустите сертификат заново "
                                                   "или проверьте путь на странице «Сертификаты»."),
        (r"cannot load certificate key", "Не удаётся загрузить закрытый ключ: файла нет или он не "
                                         "соответствует формату PEM."),
        (r"key values mismatch", "Закрытый ключ не соответствует сертификату."),
        (r"bind\(\) to .* failed \(98", "Порт уже занят другой программой (Apache, другой nginx...). "
                                        "См. «Диагностика → Порты»."),
        (r"host not found in upstream \"([^\"]+)\"", "Не удаётся разрешить имя бэкенда «{0}» через DNS. "
                                                     "Используйте IP или проверьте /etc/hosts и DNS."),
        (r"duplicate location \"([^\"]+)\"", "Локация «{0}» описана дважды (возможно, в своих директивах)."),
        (r"could not build server_names_hash", "Увеличьте server_names_hash_bucket_size в глобальных настройках."),
        (r"\"(\w+)\" directive is duplicate", "Директива «{0}» указана дважды — проверьте свои директивы."),
        (r"\"(\w+)\" directive is not allowed here", "Директива «{0}» недопустима в этом месте конфигурации."),
        (r"invalid number of arguments in \"(\w+)\"", "Неверное число аргументов у директивы «{0}»."),
        (r"unexpected \"[}{;]\"", "Синтаксическая ошибка: лишняя или пропущенная скобка/точка с запятой "
                                  "в своих директивах."),
        (r"conflicting server name \"([^\"]+)\"", "Домен «{0}» указан в нескольких сайтах на одном порту — "
                                                  "nginx будет использовать только первый."),
        (r"duplicate listen options", "Разные параметры listen для одного адреса:порта у разных сайтов."),
        (r"a duplicate default server", "Несколько серверов по умолчанию на одном порту."),
        (r"no \"ssl_certificate\" is defined", "Для HTTPS-блока не указан сертификат."),
        (r"open\(\) \"([^\"]+)\" failed \(13", "Нет прав на файл «{0}» (или блокирует SELinux)."),
        (r"open\(\) \"([^\"]+)\" failed \(2", "Файл «{0}» не существует."),
        (r"zero size shared memory zone \"(\w+)\"", "Зона «{0}» используется, но не объявлена."),
        (r"limit_req_zone .* is already bound", "Конфликт зон ограничения частоты."),
        (r"unknown \"(\w+)\" variable", "Неизвестная переменная ${0}."),
        (r"pcre2?_compile\(\) failed: (.*)", "Ошибка в регулярном выражении: {0}"),
    ]
    for pat, text in rules:
        m = re.search(pat, msg)
        if m:
            try:
                return text.format(*m.groups())
            except IndexError:
                return text
    return ""


FFDHE2048 = """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""
