"""Сбор статистики в нетиповых ситуациях: ротация и усечение журналов на ходу, удаление файла, обрыв строки,
продолжение с сохранённой позиции после перезапуска, огромный накопившийся хвост; журнал ошибок и потоков;
сбой записи в базу; stub_status с мусором и сбросом счётчиков; системные метрики при недоступном nginx;
поиск со спецсимволами и неверными числами; очистка истории."""
from __future__ import annotations

import asyncio
import json
import os
import time
from types import SimpleNamespace

import pytest

from app.db import Database
from app.models import PanelSettings
from app.stats import collector as C
from app.stats.collector import Aggregator, LogTailer, StubPoller, SystemPoller
from app.stats.parsing import GeoIP, classify_ua, parse_error, parse_stream, referer_domain
from app.stats.service import StatsService
from tests.test_collector import line


# =============================================================================
#  Чтение журнала на ходу
# =============================================================================
async def _until(cond, timeout=3.0):
    t0 = time.monotonic()
    while not cond():
        if time.monotonic() - t0 > timeout:
            raise AssertionError("не дождались")
        await asyncio.sleep(0.01)


def test_tailer_rotation_truncate_delete_resume(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    log = tmp_path / "access.log"
    log.write_text("старое 1\nстарое 2\n")  # было до запуска панели: при первом запуске не читается
    got = []

    async def main():
        t = LogTailer(log, "acc", db, got.extend, interval=0.01)
        task = asyncio.create_task(t.run())
        await _until(lambda: t.status == "ok")
        with open(log, "a") as f:
            f.write("a\nb")  # «b» без перевода строки — ждёт продолжения
            f.flush()
            await _until(lambda: got == ["a"])
            f.write("c\n")
        await _until(lambda: got == ["a", "bc"])
        # logrotate copytruncate: файл усечён на месте
        with open(log, "r+") as f:
            f.truncate(0)
        await asyncio.sleep(0.05)
        with open(log, "a") as f:
            f.write("после усечения\n")
        await _until(lambda: got[-1] == "после усечения")
        # logrotate create: старый файл переименован (в нём дописана строка), создан новый
        with open(log, "a") as f:
            f.write("хвост старого\n")
        os.rename(log, tmp_path / "access.log.1")
        await asyncio.sleep(0.03)
        log.write_text("новый файл\n")
        await _until(lambda: got[-1] == "новый файл")
        assert "хвост старого" in got
        # файл удалён и долго не появляется
        log.unlink()
        await _until(lambda: "удалён" in t.status or t.status == "файл не найден")
        log.write_text("вернулся\n")
        await _until(lambda: got[-1] == "вернулся")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return t
    t = asyncio.run(main())
    assert "старое 1" not in got and t.lines_total == len(got)
    saved = db.kv_get("tail:acc")
    assert saved["pos"] == log.stat().st_size and saved["ino"] == log.stat().st_ino
    info = t.info()
    assert info["lag_bytes"] == 0 and info["lines"] == len(got)

    # перезапуск панели: продолжение с сохранённой позиции, строки за время простоя не теряются
    with open(log, "a") as f:
        f.write("пока панель стояла\n")
    got2 = []

    async def again():
        t2 = LogTailer(log, "acc", db, got2.extend, interval=0.01)
        task = asyncio.create_task(t2.run())
        await _until(lambda: got2 == ["пока панель стояла"])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(again())


def test_tailer_skips_huge_backlog_and_bad_handler(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    log = tmp_path / "a.log"
    log.write_text("x\n")
    db.kv_set("tail:big", {"ino": log.stat().st_ino, "pos": 1})
    with open(log, "r+b") as f:  # разреженный файл 300 МБ: панель стояла долго
        f.truncate(300 * 1024 * 1024)
    t = LogTailer(log, "big", db, lambda lines: None)
    assert t._open(from_start=False) and t.pos == 300 * 1024 * 1024  # не «догоняем» 300 МБ
    # сохранённая позиция за концом файла (файл заменён) — читаем новый с начала только при первом запуске
    db.kv_set("tail:big2", {"ino": log.stat().st_ino, "pos": 10 ** 12})
    t2 = LogTailer(log, "big2", db, lambda lines: None)
    t2._open(from_start=True)
    assert t2.pos == 0
    t3 = LogTailer(tmp_path / "нет.log", "none", db, lambda x: None)
    assert not t3._open(True) and t3.status == "файл не найден" and t3._read() is False
    assert t3.info()["size"] == 0


# =============================================================================
#  Журналы ошибок и потоков
# =============================================================================
ERR = ('2026/11/24 10:00:{s:02d} [error] 123#123: *45 connect() failed (111: Connection refused) while connecting '
       'to upstream, client: 203.0.113.5, server: shop.test, request: "GET /a HTTP/1.1", upstream: '
       '"http://10.0.0.1:8080/a", host: "shop.test"')


def test_ingest_errors_and_streams(tmp_path):
    db = Database(str(tmp_path / "s.db"))
    agg = Aggregator(db, lambda: PanelSettings(), GeoIP())
    agg.domain_map = {"shop.test": "3"}
    agg.stream_port_map = {(5432, "TCP"): "7", (53, "UDP"): "8"}
    agg.ingest_errors([ERR.format(s=1), ERR.format(s=2).replace("server: shop.test", "server: other.test")
                       .replace('host: "shop.test"', 'host: "x.test"'), "мусор", "",
                       '2026/13/45 99:99:99 [crit] 1#1: странная дата',
                       ERR.format(s=3).replace("http://10.0.0.1:8080/a", "http://[::1:bad")])
    assert agg.err_seq == 4 and agg.passive_upstream["10.0.0.1:8080"] == 2
    sites = {e["site"] for _, e in agg.err_live}
    assert sites == {"3", ""} and len(agg.errors_since(2)) == 2 and agg.errors_since(10) == []
    def s(**kw):
        return json.dumps({"t": f"{time.time():.3f}", "ip": "198.51.100.1", "port": 5432, "s": "200",
                           "bs": "100", "br": "50", "dur": "1.5", **kw})
    agg.ingest_stream([s(), s(s="502"), s(proto="UDP", port=53), s(port=9999), "не json", "", "[1,2]"])
    rows = next(iter(agg.stream_min.values()))
    assert rows["7"] == [2, 100, 200, 3.0, 1] and rows["8"][0] == 1 and rows["port:9999"][0] == 1
    agg.flush(force=True)
    assert {r["stream"] for r in db.query("SELECT stream FROM stream_minute")} == {"7", "8", "port:9999"}
    assert db.scalar("SELECT COUNT(*) FROM errors") == 4


def test_parse_stream_and_error_edges():
    assert parse_stream("[1]") is None or parse_stream("[1]")["port"] == 0
    r = parse_stream('{"port": "x", "s": null, "dur": "nan"}')
    assert r["port"] == 0 and r["status"] == 0 and r["ts"] > 0
    e = parse_error('2026/11/24 10:00:00 [warn] 1#1: *1 an upstream response is buffered to a temporary file '
                    '/var/cache/x while reading upstream, client: 1.2.3.4, server: , request: "GET /a\\"b HTTP/1.1"')
    assert e["category"] == "buffered_to_file" and e["server"] == "" and e["request"] == 'GET /a\\"b HTTP/1.1'
    assert parse_error("2026/11/24 10:00:00 [emerg] 1#1: что-то\n")["category"] == "config"
    assert parse_error("2026/11/24 10:00:00 [notice] 1#1: signal process started")["category"] == "other"


@pytest.mark.parametrize("ua,expect", [
    ("", ("Пусто", "Неизвестно", "Неизвестно", True)),
    ("-", ("Пусто", "Неизвестно", "Неизвестно", True)),
    ("Microsoft-CryptoAPI/10.0", ("Другой", "Другая", "Компьютер", False)),
    ("Microsoft Office/16.0 (Microsoft Outlook 16.0.1; Pro)", ("Другой", "Другая", "Компьютер", False)),
    ("MyShop/3.1 (iOS 17.2; iPhone15,2)", ("Другой", "iOS", "Мобильный", False)),
    ("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/120 Safari/537.36", ("Chrome", "ChromeOS", "Компьютер",
                                                                           False)),
    ("Mozilla/5.0 (Linux; Android 13; SM-X700) Chrome/120 Safari/537.36", ("Chrome", "Android", "Планшет", False)),
    ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", ("ahrefsbot", "Другая", "Бот", True)),
    ("python-requests/2.31", ("python-requests", "Другая", "Бот", True)),
    ("Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/121.0", ("Firefox", "Windows", "Компьютер", False)),
    ("Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", ("Internet Explorer", "Windows", "Компьютер",
                                                                        False)),
    ("Mozilla/5.0 (Macintosh) AppleWebKit/605 Version/17 Safari/605", ("Safari", "macOS", "Компьютер", False)),
    ("Mozilla/5.0 YaBrowser/24.1 Chrome/120 Safari/537.36 Windows", ("Яндекс.Браузер", "Windows", "Компьютер",
                                                                     False)),
])
def test_classify_ua(ua, expect):
    assert classify_ua(ua) == expect


def test_referer_and_geoip(tmp_path):
    assert referer_domain("", "a") == "" and referer_domain("-", "a") == ""
    assert referer_domain("https://a.test/x", "a.test") == "" and referer_domain("http://[::1", "a") == ""
    assert referer_domain("https://Google.com/", "a") == "google.com" and referer_domain("/relative", "a") == ""
    g = GeoIP()
    g.load(str(tmp_path / "нет.mmdb"), str(tmp_path))
    assert g.reader is None and g.error and g.country("8.8.8.8") == ""
    (tmp_path / "broken.mmdb").write_bytes(b"not a db")
    g.load(str(tmp_path / "broken.mmdb"), str(tmp_path))
    assert g.reader is None and g.country("8.8.8.8") == ""


# =============================================================================
#  Агрегаты: поздние строки, сбой базы, окна
# =============================================================================
def test_aggregator_late_lines_and_db_failure(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "a.db"))
    agg = Aggregator(db, lambda: PanelSettings(store_requests=True), GeoIP())
    now = time.time()
    agg.ingest_access([line(now - 5), line(now - 4, status=502), line(now - 3600, uri="/old"),  # час назад
                       line(now + 3600, uri="/future"), line(now - 4.5)])
    assert agg.parsed == 5
    w = agg.window(10, "*", int(now) + 1)
    assert w["req"] == 3 and w["err5_pct"] > 0
    assert agg.window(10, "999", int(now) + 1)["req"] == 0 and agg.per_site_now(10)["1"]["rps"] > 0
    rt = agg.realtime(30, "1")
    assert sum(rt["req"]) == 3 and len(rt["ts"]) == 30
    assert [x["seq"] for x in agg.live_since(3)] == [4, 5] and agg.live_since(99) == []
    # запись в базу не удалась (диск полон) — данные отбрасываются, цикл не падает
    calls = []

    def broken(*a):
        calls.append(a[0][:20])
        raise OSError("database or disk is full")
    monkeypatch.setattr(db, "executemany", broken)
    agg.ingest_errors([ERR.format(s=1)])
    agg.ipdeny[(int(now) // 60 * 60, "1", "203.0.113.1")] = [3, "/x", ""]
    agg.flush(force=True)
    assert agg.req_buffer == [] and agg.err_buffer == [] and agg.ipdeny == {} and len(calls) == 3
    monkeypatch.undo()
    # минуты записаны, поздняя строка за час до этого — тоже (отдельная минута); строка «из будущего» ждёт
    # своей минуты в памяти
    assert db.scalar("SELECT SUM(req) FROM stats_minute WHERE site='*'") == 4 and all(k > now - 60 for k in agg.mins)
    summ = agg.recent_minutes_summary(120, "*")
    assert summ["totals"]["req"] == 5 and summ["totals"]["s5"] == 1 and summ["totals"]["uniq"] == 1


def test_aggregator_merges_minute_written_twice(tmp_path):
    db = Database(str(tmp_path / "m.db"))
    agg = Aggregator(db, lambda: PanelSettings(), GeoIP())
    t = (int(time.time()) // 60 - 3) * 60 + 5
    agg.ingest_access([line(t), line(t + 1)])
    agg.flush(force=True)
    agg.ingest_access([line(t + 2, status=500)])  # строка той же минуты пришла позже (буфер nginx)
    agg.flush(force=True)
    r = db.one("SELECT req, s5 FROM stats_minute WHERE ts=? AND site='1'", (t // 60 * 60,))
    assert dict(r) == {"req": 3, "s5": 1}


# =============================================================================
#  stub_status и системные метрики
# =============================================================================
STUB = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nActive connections: 5 \nserver accepts handled requests\n"
        b" {a} {a} {r} \nReading: 0 Writing: 1 Waiting: 4 \n")


def test_stub_poller_garbage_and_counter_reset():
    responses = [STUB.replace(b"{a}", b"100").replace(b"{r}", b"1000"),
                 STUB.replace(b"{a}", b"110").replace(b"{r}", b"1100"),
                 STUB.replace(b"{a}", b"3").replace(b"{r}", b"5"),  # nginx перезапущен — счётчики с нуля
                 b"HTTP/1.1 404 Not Found\r\n\r\n<html>nope</html>", b""]

    async def handler(r, w):
        await r.read(100)
        w.write(responses.pop(0))
        await w.drain()
        w.close()

    async def main():
        srv = await asyncio.start_server(handler, "127.0.0.1", 0)
        p = StubPoller(srv.sockets[0].getsockname()[1])
        real = asyncio.sleep
        n = [0]

        async def fast(s):
            n[0] += 1
            if n[0] > 5:
                raise asyncio.CancelledError()
            await real(0.01)
        C.asyncio.sleep, orig = fast, C.asyncio.sleep
        try:
            with pytest.raises(asyncio.CancelledError):
                await p.run()
        finally:
            C.asyncio.sleep = orig
        srv.close()
        return p
    p = asyncio.run(main())
    s = list(p.samples)
    assert [x["requests"] for x in s] == [1000, 1100, 5]
    assert s[0]["rps"] == 0 and s[1]["rps"] > 0 and s[2]["rps"] == 0 and s[2]["dropped"] == 0
    assert p.error  # мусорный ответ записан как ошибка, последний снимок остаётся
    latest = p.latest()
    assert latest["ok"] and latest["active"] == 5
    p.samples[-1]["ts"] -= 60
    assert p.latest()["ok"] is False
    closed = StubPoller(1)
    assert asyncio.run(closed.fetch()) is None and "Error" in closed.error


def test_system_poller_with_dying_nginx(tmp_path):
    class Proc:
        def __init__(self, pid, die=False):
            self.pid, self.die = pid, die

        def children(self):
            return [Proc(11), Proc(12, die=True)]

        def cpu_percent(self, i=None):
            return 1.0

        def memory_info(self):
            if self.die:
                raise ProcessLookupError()
            return SimpleNamespace(rss=1000)

        def num_fds(self):
            return 7
    masters = iter([Proc(10), None, Proc(10)])
    sp = SystemPoller(lambda: next(masters), tmp_path / "нет-каталога")
    a = sp.sample()
    assert a["nginx_workers"] == 2 and a["nginx_rss"] == 2000 and a["net_rx"] == 0 and a["disk_log"] == a["disk"]
    b = sp.sample()  # nginx остановлен
    assert b["nginx_workers"] == 0 and b["nginx_rss"] == 0
    sp.sample()
    avg = sp.minute_avg(0, time.time() + 1)
    assert avg["nginx_workers"] == 2 and sp.minute_avg(0, 1) is None and sp.latest() is sp.samples[-1]


# =============================================================================
#  История и поиск
# =============================================================================
@pytest.fixture()
def stats(tmp_path):
    db = Database(str(tmp_path / "st.db"))
    ps = PanelSettings(store_requests=True)
    object.__setattr__(ps, "requests_max_rows", 1000)  # в настройках минимум 10 000 — для теста меньше
    s = StatsService.__new__(StatsService)
    s.db, s.get_panel = db, lambda: ps
    s.agg = Aggregator(db, lambda: ps, GeoIP())
    s.started = time.time()
    s.stub = StubPoller(1)
    s.system = SystemPoller(lambda: None, tmp_path)
    s.tailers = []
    return s


def test_search_special_chars_and_bad_numbers(stats):
    now = time.time()
    stats.agg.ingest_access([line(now - 5, uri="/sale/100%_off"), line(now - 5, uri="/sale/100xyoff"),
                             line(now - 4, uri="/a\\b", ua="Bot_1"), line(now - 3, uri="/x", host="a_b.test")])
    stats.agg.flush(force=True)
    def uris(**f):
        return [r["uri"] for r in stats.search_requests(f)["items"]]
    assert uris(uri="100%_off") == ["/sale/100%_off"]  # «%» и «_» — обычные символы
    assert uris(uri="\\") == ["/a\\b"] and len(uris(ua="Bot_")) == 1 and uris(host="a_b") == ["/x"]
    assert uris(status="2xx", sort="rt") and uris(status="abc") and uris(status="x5x")
    for bad in ({"start": "вчера"}, {"end": "nan"}, {"min_rt": "inf"}):
        with pytest.raises(ValueError, match="Параметр"):
            stats.search_requests(bad)
    stats.agg.ingest_errors([ERR.format(s=1), ERR.format(s=2).replace("Connection refused", "50%_done")])
    stats.agg.flush(force=True)
    r = stats.search_errors({"q": "50%_"})
    assert r["total"] == 1 and r["categories"] if "categories" in r else r["total"] == 1
    assert stats.search_errors({"q": "%"})["total"] == 1
    with pytest.raises(ValueError):
        stats.search_errors({"start": "x"})


def test_cleanup_and_history(stats):
    db = stats.db
    old = time.time() - 400 * 86400
    rows = [(old if i < 1100 else time.time(), "1", "h", "ip", "GET", "/", "", 200, 1, 0.1, None, "", "", "", "",
             "", "", "", "") for i in range(1500)]
    db.executemany("INSERT INTO requests(ts,site,host,ip,method,uri,proto,status,bytes,rt,urt,upstream,ustatus,ref,"
                   "ua,cache,tls,country,rid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    db.event("info", "x", "старое")
    db.execute("UPDATE events SET ts=?", (old,))
    res = stats.cleanup()
    assert res["requests"] == 1100 and res["events"] >= 1 and db.scalar("SELECT COUNT(*) FROM requests") == 400
    # переполнение: больше requests_max_rows — удаляются самые старые
    db.executemany("INSERT INTO requests(ts,site,host,ip,method,uri,proto,status,bytes,rt,urt,upstream,ustatus,ref,"
                   "ua,cache,tls,country,rid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   [(time.time(),) + r[1:] for r in rows[:700]])
    res = stats.cleanup()
    assert res["requests_overflow"] == 100 and db.scalar("SELECT COUNT(*) FROM requests") == 1000
    # пустая история: ряды, сводка, сравнение сайтов
    now = time.time()
    ts = stats.timeseries(now - 86400 * 7, now, "*")  # неделя — из часовой таблицы
    assert isinstance(ts, dict)
    assert stats.timeseries(now - 600, now - 600, "*") is not None  # нулевой интервал
    s = stats.summary(now - 3600, now, "*", exact_uniq=True)
    assert s["requests"] == 0 and stats.compare_sites(now - 3600, now) == []
    assert stats.tops(now - 3600, now, "*", "uri") == [] and stats.system_series(now - 3600, now) is not None
