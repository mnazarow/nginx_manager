// Дашборд реального времени.
import { api, live } from '../api.js';
import { h, mount, kpi, card, fmtNum, fmtBps, fmtMs, fmtPct, fmtInt, fmtBytes, fmtDur, fmtAgo, sparkline, icon, badge, table,
  stateBadge, hbars, fmtCompact } from '../ui.js';
import { timeChart, setData, chartCard, statusColors, seriesColor, destroyAll, segBar } from '../charts.js';
import { hintKpi, insightsCard, loadCatalog } from '../advice.js';

const WINDOW = 300;

export async function render(root) {
  const charts = [];
  const [rt, ov, sysSeries] = await Promise.all([
    api('/stats/realtime', { query: { seconds: WINDOW } }), api('/overview'),
    api('/stats/system', { query: { from: Date.now() / 1000 - WINDOW } })]);
  const sc = statusColors();

  // ---- KPI ----
  const k = {
    rps: kpi('Запросов в секунду', '—', { tip: 'Среднее за последние 10 секунд (из журнала) и общий поток по stub_status' }),
    bw: kpi('Исходящий трафик', '—', { tip: 'Байты ответов клиентам, среднее за 10 секунд' }),
    conn: kpi('Активные соединения', '—', { tip: 'stub_status: все открытые клиентские соединения' }),
    err: kpi('Ошибки 5xx', '—', { tip: 'Доля ответов 5xx за последнюю минуту' }),
    lat: kpi('Время ответа p95', '—', { tip: '95% запросов за минуту обслужены быстрее этого времени' }),
    be: kpi('Бэкенды', '—', { tip: 'Активные проверки доступности' }),
  };

  // ---- Графики ----
  const cReq = chartCard('Запросы по классам ответов', { sub: 'запросов/с, последние 5 минут' });
  const cConn = chartCard('Соединения', { sub: 'по данным stub_status' });
  const cBw = chartCard('Трафик', { sub: 'бит/с' });
  const cLat = chartCard('Время ответа', { sub: 'перцентили за секунду' });

  const sitesBox = h('div', {});
  const sysBox = h('div', {});
  const certBox = h('div', {});
  const evBox = h('div', {});
  const sumBox = h('div', {});
  const insBox = h('div', {});

  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Обзор'), h('p', {}, 'Работа nginx и всех сайтов в реальном времени. Данные обновляются каждую секунду.')),
      h('div', { class: 'row' }, h('a', { class: 'btn', href: '#/analytics' }, icon('chart'), 'Аналитика'), h('a', { class: 'btn', href: '#/requests' }, icon('list'), 'Живой журнал'))),
    h('div', { class: 'grid g6' }, Object.values(k)),
    insBox,
    h('div', { class: 'grid g2 mt' }, cReq.el, cConn.el, cBw.el, cLat.el),
    h('div', { class: 'grid g3 mt' },
      h('div', { class: 'span2' }, card('Сайты', sitesBox, { flush: true, sub: 'нагрузка за последние 10 с', actions: h('a', { class: 'btn sm', href: '#/sites' }, 'Все сайты') })),
      h('div', { class: 'col', style: { gap: '16px' } }, card('Сервер', sysBox), card('Сертификаты', certBox, { actions: h('a', { class: 'btn sm', href: '#/certs' }, 'Открыть') }))),
    h('div', { class: 'grid g2 mt' }, card('Последние 24 часа', sumBox), card('События', evBox, { flush: true, actions: h('a', { class: 'btn sm', href: '#/events' }, 'Все') })));

  const reqSeries = [
    { label: '2xx', color: sc.s2, fill: true, first: true }, { label: '3xx', color: sc.s3, fill: true },
    { label: '4xx', color: sc.s4, fill: true }, { label: '5xx', color: sc.s5, fill: true }];
  const chReq = timeChart(cReq.canvas, reqSeries, { stacked: true, yFmt: (v) => fmtNum(v, 1), legendEl: cReq.legendEl });
  const connSeries = [{ label: 'Активные', color: seriesColor(0) }, { label: 'Чтение', color: seriesColor(1) },
    { label: 'Запись', color: seriesColor(2) }, { label: 'Ожидание (keepalive)', color: seriesColor(3) }];
  const chConn = timeChart(cConn.canvas, connSeries, { yFmt: (v) => fmtInt(v), legendEl: cConn.legendEl });
  const bwSeries = [{ label: 'Исходящий', color: seriesColor(0), fill: true }, { label: 'Входящий', color: seriesColor(1) }];
  const chBw = timeChart(cBw.canvas, bwSeries, { yFmt: fmtBps, legendEl: cBw.legendEl });
  const latSeries = [{ label: 'p50', color: seriesColor(0) }, { label: 'p95', color: seriesColor(1) }, { label: 'p99', color: seriesColor(2) }];
  const chLat = timeChart(cLat.canvas, latSeries, { yFmt: fmtMs, legendEl: cLat.legendEl });
  charts.push(chReq, chConn, chBw, chLat);

  // ---- Наполнение историей ----
  const n = rt.ts.length - 3;
  const R = { ts: rt.ts.slice(0, n), s2: rt.s2.slice(0, n), s3: rt.s3.slice(0, n), s4: rt.s4.slice(0, n), s5: rt.s5.slice(0, n),
    out: rt.bout.slice(0, n).map(b => b * 8), inn: rt.bin.slice(0, n).map(b => b * 8),
    p50: rt.p50.slice(0, n), p95: rt.p95.slice(0, n), p99: rt.p99.slice(0, n) };
  const C = { ts: [], a: [], r: [], w: [], k: [] };
  sysSeries.ts.forEach((t, i) => { if (sysSeries.conn_active[i] != null) { C.ts.push(Math.round(t)); C.a.push(sysSeries.conn_active[i]); C.r.push(sysSeries.conn_reading[i]); C.w.push(sysSeries.conn_writing[i]); C.k.push(sysSeries.conn_waiting[i]); } });
  const draw = () => {
    setData(chReq, R.ts, [R.s2, R.s3, R.s4, R.s5]);
    setData(chBw, R.ts, [R.out, R.inn]);
    setData(chLat, R.ts, [R.p50, R.p95, R.p99]);
    setData(chConn, C.ts, [C.a, C.r, C.w, C.k]);
  };
  draw();

  const siteNames = Object.fromEntries(ov.sites.map(s => [String(s.id), s.name]));
  const spark = {};
  const push = (arr, v, max = WINDOW) => { arr.push(v); if (arr.length > max) arr.shift(); };

  function onTick(m) {
    const w = m.now;
    const i = R.ts.indexOf(w.ts);
    const vals = [w.s2, w.s3, w.s4, w.s5, w.bout * 8, w.bin * 8, w.p50, w.p95, w.p99];
    const keys = ['s2', 's3', 's4', 's5', 'out', 'inn', 'p50', 'p95', 'p99'];
    if (i >= 0) keys.forEach((kk, j) => { R[kk][i] = vals[j]; });
    else if (!R.ts.length || w.ts > R.ts[R.ts.length - 1]) { push(R.ts, w.ts); keys.forEach((kk, j) => push(R[kk], vals[j])); }
    if (m.stub && m.stub.ok) {
      const t = Math.round(m.stub.ts);
      if (!C.ts.length || t > C.ts[C.ts.length - 1]) {
        push(C.ts, t, 150); push(C.a, m.stub.active, 150); push(C.r, m.stub.reading, 150); push(C.w, m.stub.writing, 150); push(C.k, m.stub.waiting, 150);
      }
    }
    draw();
    const w10 = m.w10, w60 = m.w60;
    k.rps.set(fmtNum(w10.rps, 1), '', m.stub.ok ? `всего по nginx: ${fmtNum(m.stub.rps, 1)}/с` : 'stub_status недоступен');
    hintKpi(k.rps, 'rps', w10.rps, { text: fmtNum(w10.rps, 1) + ' rps' });
    k.bw.set(fmtBps(w10.bps_out).split(' ')[0], fmtBps(w10.bps_out).split(' ')[1], `входящий ${fmtBps(w10.bps_in)}`);
    hintKpi(k.bw, 'bandwidth', w10.bps_out, { text: fmtBps(w10.bps_out) });
    k.conn.set(m.stub.ok ? fmtInt(m.stub.active) : '—', '', m.stub.ok ? `чтение ${m.stub.reading} · запись ${m.stub.writing} · ожид. ${m.stub.waiting}` : '');
    hintKpi(k.conn, 'connections', m.stub.ok ? m.stub.active : null, { text: m.stub.ok ? fmtInt(m.stub.active) : '—' });
    k.err.set(fmtNum(w60.err5_pct, 2), '%', `${fmtInt(w60.s5)} из ${fmtInt(w60.req)} за минуту · 4xx ${fmtPct(w60.err4_pct)}`,
      w60.err5_pct >= 5 && w60.req >= 20 ? 'bad' : w60.err5_pct >= 1 ? 'warn' : '');
    hintKpi(k.err, 'err5', w60.err5_pct, { req: w60.req, text: fmtPct(w60.err5_pct, 2) });
    const p95 = fmtMs(w60.p95).split(' ');
    k.lat.set(p95[0], p95[1] || '', `среднее ${fmtMs(w60.rt_avg)} · бэкенд ${fmtMs(w60.urt_avg)}`);
    hintKpi(k.lat, 'p95', w60.p95, { req: w60.req, text: fmtMs(w60.p95) });
    // сайты
    for (const [sid, v] of Object.entries(m.sites || {})) { spark[sid] ||= []; push(spark[sid], v.rps, 60); }
    for (const s of ov.sites) { const v = (m.sites || {})[String(s.id)]; if (!v) { spark[s.id] ||= []; push(spark[s.id], 0, 60); } else Object.assign(s, { rps: v.rps, bps: v.bps, err5_pct: v.err5_pct, rt_avg: v.rt_avg }); }
    drawSites();
    drawSys(m.system);
  }

  function drawSites() {
    mount(sitesBox, table([
      { title: 'Сайт', render: (s) => h('div', {}, h('a', { href: `#/sites?edit=${s.id}` }, s.name), h('div', { class: 'muted small ellipsis', style: { maxWidth: '260px' } }, s.domains.join(', '))) },
      { title: '', render: (s) => h('div', { class: 'row', style: { gap: '4px' } }, !s.enabled ? badge('выкл') : null, s.ssl ? badge('HTTPS', 'good') : null, s.maintenance ? badge('обслуживание', 'warn') : null) },
      { title: 'Бэкенды', render: (s) => h('span', { class: 'health-dots' }, (s.health || []).map(t => h('span', { class: 'dot ' + (t.state === 'up' ? 'good' : t.state === 'down' ? 'bad' : ''), title: `${t.addr}: ${t.state}${t.error ? ' — ' + t.error : ''}` }))) },
      { title: 'Запросов/с', num: true, render: (s) => fmtNum(s.rps, 1) },
      { title: 'Динамика (10 мин)', render: (s) => h('div', { style: { width: '120px' } }, sparkline(spark[s.id] || [0], { hgt: 24 })) },
      { title: 'Трафик', num: true, render: (s) => fmtBps(s.bps) },
      { title: '5xx', num: true, render: (s) => h('span', { class: s.err5_pct >= 5 ? 'status-5' : '' }, fmtPct(s.err5_pct)) },
      { title: 'Ответ', num: true, render: (s) => fmtMs(s.rt_avg) },
    ], ov.sites.filter(s => s.enabled), { empty: 'Сайтов пока нет — добавьте первый на странице «Сайты»', onRow: (s) => { location.hash = `#/sites?edit=${s.id}`; } }));
  }

  function drawSys(s) {
    if (!s || !s.ts) return;
    const bar = (label, v, extra) => h('div', { class: 'mb', style: { marginBottom: '10px' } },
      h('div', { class: 'row between small' }, h('span', { class: 'ink2' }, label), h('span', { class: 'num' }, fmtPct(v, 0), extra ? h('span', { class: 'muted' }, ' · ' + extra) : null)),
      h('div', { class: 'progress ' + (v > 90 ? 'bad' : v > 75 ? 'warn' : '') }, h('div', { style: { width: Math.min(100, v) + '%' } })));
    mount(sysBox, bar('CPU', s.cpu, `load ${fmtNum(s.load1, 2)} / ${s.cpus} ядер`), bar('Память', s.mem, `${fmtBytes(s.mem_used)} из ${fmtBytes(s.mem_total)}`),
      bar('Диск /', s.disk, `свободно ${fmtBytes(s.disk_free)}`),
      h('div', { class: 'kv small' }, h('dt', {}, 'Сеть'), h('dd', { class: 'num' }, `↓ ${fmtBps(s.net_rx)} · ↑ ${fmtBps(s.net_tx)}`),
        h('dt', {}, 'Процессы nginx'), h('dd', { class: 'num' }, `${s.nginx_workers} воркеров · ${fmtBytes(s.nginx_rss)} · CPU ${fmtNum(s.nginx_cpu, 1)}%`)));
  }

  // ---- Статичные блоки ----
  const up = ov.health.filter(t => t.state === 'up').length, down = ov.health.filter(t => t.state === 'down').length;
  k.be.set(`${up}`, ` / ${ov.health.filter(t => t.state !== 'disabled').length}`, down ? h('span', { class: 'status-5' }, `недоступно: ${down}`) : 'все доступны');
  k.be.title = 'Доступно / всего проверяемых серверов';
  hintKpi(k.be, 'backends_down', down, { text: `недоступно: ${down}` });
  const certs = ov.certs.slice().sort((a, b) => (a.days_left ?? 1e9) - (b.days_left ?? 1e9)).slice(0, 5);
  mount(certBox, certs.length ? certs.map(c => h('div', { class: 'row between', style: { padding: '5px 0' } },
    h('span', { class: 'ellipsis', style: { maxWidth: '60%' } }, c.name),
    c.status !== 'valid' ? stateBadge(c.status) : badge(`${Math.floor(c.days_left)} дн.`, c.days_left < 7 ? 'bad' : c.days_left < 21 ? 'warn' : 'good'))) : h('div', { class: 'muted' }, 'Сертификатов нет'));
  mount(evBox, ov.events.length ? h('div', {}, ov.events.slice(0, 8).map(e => h('div', { class: 'row nowrap', style: { padding: '8px 16px', borderBottom: '1px solid var(--line)', alignItems: 'flex-start' } },
    h('span', { class: 'dot ' + (e.level === 'error' ? 'bad' : e.level === 'warning' ? 'warn' : 'good'), style: { marginTop: '6px' } }),
    h('div', { class: 'grow' }, h('div', { class: 'small' }, e.message), h('div', { class: 'muted small' }, fmtAgo(e.ts), ' · ', e.source))))) : h('div', { class: 'empty' }, 'Событий нет'));
  const s24 = ov.summary_24h;
  mount(sumBox, h('div', { class: 'grid g3', style: { gap: '12px' } },
    h('div', {}, h('div', { class: 'muted small' }, 'Запросов'), h('div', { style: { fontSize: '20px', fontWeight: 600 } }, fmtCompact(s24.requests))),
    h('div', {}, h('div', { class: 'muted small' }, 'Передано'), h('div', { style: { fontSize: '20px', fontWeight: 600 } }, fmtBytes(s24.bytes_out))),
    h('div', {}, h('div', { class: 'muted small' }, 'Уникальных IP (≈)'), h('div', { style: { fontSize: '20px', fontWeight: 600 } }, fmtCompact(s24.uniq)))),
  h('div', { class: 'mt' }, h('div', { class: 'small ink2 mb', style: { marginBottom: '6px' } }, 'Классы ответов'),
    segBar([{ label: '2xx', value: s24.status['2xx'], color: sc.s2 }, { label: '3xx', value: s24.status['3xx'], color: sc.s3 },
      { label: '4xx', value: s24.status['4xx'], color: sc.s4 }, { label: '5xx', value: s24.status['5xx'], color: sc.s5 }], fmtCompact)),
  h('div', { class: 'grid g2 mt', style: { gap: '12px' } },
    h('div', {}, h('div', { class: 'small ink2', style: { marginBottom: '4px' } }, 'Время ответа'),
      h('div', { class: 'kv small' }, h('dt', {}, 'среднее'), h('dd', { class: 'num' }, fmtMs(s24.rt_avg)), h('dt', {}, 'p95'), h('dd', { class: 'num' }, fmtMs(s24.p95)),
        h('dt', {}, 'p99'), h('dd', { class: 'num' }, fmtMs(s24.p99)), h('dt', {}, 'кэш HIT'), h('dd', { class: 'num' }, fmtPct(s24.hit_ratio)))),
    h('div', {}, h('div', { class: 'small ink2', style: { marginBottom: '4px' } }, 'Частые ошибки nginx'),
      Object.keys(s24.errors).length ? hbars(Object.entries(s24.errors).slice(0, 4).map(([kk, v]) => ({ label: v.title, value: v.count, title: v.hint })), { color: 'var(--s2)' })
        : h('div', { class: 'muted small' }, 'нет'))));
  drawSites();
  const snap = ov.snapshot; snap.now.ts = -1; onTick(snap);

  const off = live.on('tick', onTick);
  // встроенный анализ последних 15 минут (обновляется раз в 30 секунд)
  let insTimer = null;
  const loadIns = async () => {
    try {
      const to = Date.now() / 1000;
      const res = await api('/insights', { query: { from: to - 900, to }, silent: true });
      mount(insBox, h('div', { class: 'mt' }, insightsCard(res, { limit: 4, onChange: loadIns })));
    } catch { /* анализ необязателен для дашборда */ }
    insTimer = setTimeout(loadIns, 30000);
  };
  loadCatalog().then(loadIns);
  return () => { off(); clearTimeout(insTimer); destroyAll(charts); };
}
