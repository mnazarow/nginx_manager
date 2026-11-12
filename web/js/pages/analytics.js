// Аналитика за произвольный период: динамика, распределения, топы, сравнение сайтов.
import { api } from '../api.js';
import { h, mount, kpi, card, fmtNum, fmtBps, fmtMs, fmtPct, fmtInt, fmtBytes, fmtCompact, fmtDate, table, tabs, hbars, segmented,
  icon, loading, statusClass } from '../ui.js';
import { timeChart, setData, chartCard, statusColors, seriesColor, destroyAll, barChart, segBar } from '../charts.js';
import { ctx } from '../app.js';

const RANGES = [['900', '15 мин'], ['3600', '1 час'], ['21600', '6 часов'], ['86400', '24 часа'], ['604800', '7 дней'], ['2592000', '30 дней'], ['7776000', '90 дней']];

export async function render(root) {
  const charts = [];
  const sites = await api('/sites');
  const st = { range: ctx.params.range || '3600', site: ctx.params.site || '*', from: null, to: null, topKind: 'uri' };
  const body = h('div', {});
  const fromInp = h('input', { type: 'datetime-local', style: { width: '200px' } });
  const toInp = h('input', { type: 'datetime-local', style: { width: '200px' } });
  const custom = h('div', { class: 'row hidden' }, fromInp, '—', toInp, h('button', { class: 'btn sm', onclick: () => {
    if (!fromInp.value || !toInp.value) return;
    st.from = new Date(fromInp.value).getTime() / 1000; st.to = new Date(toInp.value).getTime() / 1000; load();
  } }, 'Показать'));
  const siteSel = h('select', { onchange: (e) => { st.site = e.target.value; load(); } }, h('option', { value: '*' }, 'Все сайты'),
    sites.map(s => h('option', { value: String(s.id), selected: String(s.id) === st.site }, s.name)));
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Аналитика'), h('p', {}, 'История трафика, ошибок и производительности. До 48 часов — поминутная детализация, дальше — почасовая.'))),
    h('div', { class: 'toolbar' }, segmented([...RANGES, ['custom', 'Период…']], st.range, (v) => {
      st.range = v; custom.classList.toggle('hidden', v !== 'custom'); if (v !== 'custom') { st.from = st.to = null; load(); }
    }), custom, siteSel, h('button', { class: 'btn sm', onclick: () => load() }, icon('refresh'), 'Обновить')),
    body);

  async function load() {
    const to = st.to || Date.now() / 1000;
    const from = st.from || to - +st.range;
    const q = { from, to, site: st.site };
    body.style.opacity = '.55';
    const [ts, sum, cmp, streams] = await Promise.all([api('/stats/timeseries', { query: { ...q, points: 200 } }), api('/stats/summary', { query: q }),
      st.site === '*' ? api('/stats/sites', { query: { from, to } }) : Promise.resolve([]), api('/stats/streams', { query: { from, to } })]);
    body.style.opacity = '1';
    destroyAll(charts);
    const span = to - from;
    const xFmt = span > 2 * 86400 ? (t) => new Date(t * 1000).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' }) + (span < 10 * 86400 ? ' ' + new Date(t * 1000).getHours() + 'ч' : '')
      : (t) => new Date(t * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    const sc = statusColors();
    const kp = [
      kpi('Запросов', fmtCompact(sum.requests), { foot: `${fmtNum(sum.rps, 2)} в секунду` }),
      kpi('Передано', fmtBytes(sum.bytes_out), { foot: `принято ${fmtBytes(sum.bytes_in)}` }),
      kpi('Ошибки 5xx', fmtPct(sum.err5_pct, 2), { foot: `4xx: ${fmtPct(sum.err4_pct)}`, cls: sum.err5_pct > 5 ? 'bad' : sum.err5_pct > 1 ? 'warn' : '' }),
      kpi('Время ответа p95', fmtMs(sum.p95), { foot: `p50 ${fmtMs(sum.p50)} · p99 ${fmtMs(sum.p99)}` }),
      kpi('Уникальных IP', fmtCompact(sum.uniq), { foot: sum.uniq_exact ? 'точно, по журналу запросов' : 'оценка (сумма почасовых)', tip: 'Точный подсчёт возможен, пока период покрыт журналом запросов' }),
      kpi('Кэш (HIT)', fmtPct(sum.hit_ratio), { foot: `боты: ${fmtPct(sum.requests ? sum.bots / sum.requests * 100 : 0)} запросов` }),
    ];
    const cReq = chartCard('Запросы по классам ответов', { sub: `шаг ${ts.step >= 3600 ? ts.step / 3600 + ' ч' : ts.step / 60 + ' мин'}, запросов за шаг` });
    const cBw = chartCard('Трафик', { sub: 'средняя скорость, бит/с' });
    const cLat = chartCard('Время ответа', { sub: 'перцентили и среднее время бэкенда' });
    const cUniq = chartCard('Уникальные посетители (IP)', { sub: 'за шаг' });
    const cErr = chartCard('Доля ошибок 5xx', { sub: '% ответов' });
    const cNg = chartCard('Ошибки в журнале nginx', { sub: 'записей за шаг' });
    const hist = h('canvas');
    const topBox = h('div', {});
    const topCard = card('Топ-списки', topBox, { flush: true });
    const kinds = [['uri', 'URI'], ['ip', 'IP-адреса'], ['referer', 'Источники'], ['ua', 'User-Agent'], ['host', 'Хосты'], ['upstream', 'Бэкенды'],
      ['e4xx', 'Ошибки 4xx'], ['e5xx', 'Ошибки 5xx'], ['slow', 'Медленные']];
    const drawTop = async () => {
      mount(topBox, h('div', { style: { padding: '0 16px' } }, tabs(kinds.map(([id, label]) => ({ id, label })), st.topKind, (k) => { st.topKind = k; drawTop(); })), loading());
      const rows = await api('/stats/top', { query: { ...q, kind: st.topKind, limit: 50 } });
      const max = Math.max(...rows.map(r => r.count), 1);
      const link = (r) => {
        const k = st.topKind;
        if (k === 'ip') return h('a', { href: `#/requests?ip=${encodeURIComponent(r.key)}` }, r.key);
        if (k === 'uri' || k === 'slow') return h('a', { href: `#/requests?uri=${encodeURIComponent(r.key)}` }, r.key);
        if (k === 'e4xx' || k === 'e5xx') { const [code, ...p] = r.key.split(' '); return h('a', { href: `#/requests?status=${code}&uri=${encodeURIComponent(p.join(' '))}` }, h('span', { class: statusClass(code) }, code), ' ', p.join(' ')); }
        return r.key;
      };
      mount(topBox, h('div', { style: { padding: '0 16px' } }, tabs(kinds.map(([id, label]) => ({ id, label })), st.topKind, (k) => { st.topKind = k; drawTop(); })),
        table([
          { title: '#', render: (r) => rows.indexOf(r) + 1, width: '40px' },
          { title: kinds.find(x => x[0] === st.topKind)[1], cls: 'bar-cell', render: (r) => [h('div', { class: 'bar', style: { width: (r.count / max * 100) + '%' } }), h('span', { class: 'ellipsis', style: { maxWidth: '640px', display: 'inline-block', verticalAlign: 'bottom' }, title: r.key }, link(r))] },
          { title: 'Запросов', num: true, render: (r) => fmtInt(r.count) },
          { title: 'Доля', num: true, render: (r) => fmtPct(sum.requests ? r.count / sum.requests * 100 : 0) },
          ['uri', 'ip', 'host'].includes(st.topKind) ? { title: 'Трафик', num: true, render: (r) => fmtBytes(r.bytes) } : null,
          st.topKind === 'slow' ? { title: 'Среднее время', num: true, render: (r) => fmtMs(r.avg_ms) } : null,
        ].filter(Boolean), rows, { cls: 'compact', empty: 'Нет данных за период' }));
    };
    const dist = (title, obj, opts = {}) => {
      const items = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, opts.limit || 8).map(([k, v]) => ({ label: opts.lbl ? opts.lbl(k) : k, value: v }));
      return card(title, hbars(items, { valueFmt: (v) => `${fmtCompact(v)} · ${fmtPct(sum.requests ? v / sum.requests * 100 : 0)}`, color: opts.color }));
    };
    const codesBox = card('Коды ответов', h('div', {}, segBar([{ label: '2xx', value: sum.status['2xx'], color: sc.s2 }, { label: '3xx', value: sum.status['3xx'], color: sc.s3 },
      { label: '4xx', value: sum.status['4xx'], color: sc.s4 }, { label: '5xx', value: sum.status['5xx'], color: sc.s5 }], fmtCompact),
    h('div', { class: 'mt' }, hbars(Object.entries(sum.codes).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => ({ label: h('span', { class: statusClass(k) }, k + ' ' + (HTTP[k] || '')), value: v })),
      { valueFmt: fmtCompact }))));
    const topDims = await Promise.all(['browser', 'os', 'device', 'country'].map(k => api('/stats/top', { query: { ...q, kind: k, limit: 8 } })));
    const dimCard = (title, rows) => card(title, hbars(rows.map(r => ({ label: r.key || '—', value: r.count })), { valueFmt: (v) => `${fmtCompact(v)} · ${fmtPct(sum.requests ? v / sum.requests * 100 : 0)}` }));
    const errs = Object.entries(sum.errors || {});
    mount(body,
      h('div', { class: 'grid g6' }, kp),
      h('div', { class: 'grid g2 mt' }, cReq.el, cBw.el, cLat.el, cUniq.el, cErr.el, cNg.el),
      h('div', { class: 'grid g3 mt' }, codesBox, card('Распределение времени ответа', h('div', { class: 'chart-box short' }, hist)),
        card('Ошибки nginx за период', errs.length ? h('div', {}, errs.slice(0, 8).map(([k, v]) => h('div', { style: { padding: '6px 0', borderBottom: '1px solid var(--line)' } },
          h('div', { class: 'row between' }, h('b', { class: 'small' }, v.title), h('span', { class: 'num small' }, fmtInt(v.count))),
          v.hint ? h('div', { class: 'muted small' }, v.hint) : null))) : h('div', { class: 'muted' }, 'Ошибок нет'))),
      h('div', { class: 'grid g4 mt' }, dist('Методы', sum.methods), dist('Протоколы', sum.proto), dist('Версии TLS', sum.tls, { lbl: (k) => k || 'без TLS' }),
        dist('Кэш', sum.cache), dimCard('Браузеры', topDims[0]), dimCard('ОС', topDims[1]), dimCard('Устройства', topDims[2]),
        topDims[3].length ? dimCard('Страны', topDims[3]) : card('Страны', h('div', { class: 'muted small' }, 'GeoIP не настроен. См. Документация → Мониторинг → GeoIP.'))),
      h('div', { class: 'mt' }, topCard),
      cmp.length ? h('div', { class: 'mt' }, card('Сравнение сайтов', table([
        { title: 'Сайт', render: (r) => sites.find(s => String(s.id) === r.site)?.name || (r.site === '-' ? 'Неизвестные домены' : r.site === 'panel' ? 'Панель' : r.site) },
        { title: 'Запросов', num: true, render: (r) => fmtInt(r.req) }, { title: 'Доля', num: true, render: (r) => fmtPct(sum.requests ? r.req / sum.requests * 100 : 0) },
        { title: 'Трафик', num: true, render: (r) => fmtBytes(r.bout) }, { title: '4xx', num: true, render: (r) => fmtInt(r.s4) },
        { title: '5xx', num: true, render: (r) => h('span', { class: r.err5_pct > 5 ? 'status-5' : '' }, `${fmtInt(r.s5)} (${fmtPct(r.err5_pct)})`) },
        { title: 'Ср. время', num: true, render: (r) => fmtMs(r.rt_avg) },
      ], cmp, { onRow: (r) => { if (sites.find(s => String(s.id) === r.site)) { st.site = r.site; siteSel.value = r.site; load(); } } }), { flush: true, sub: 'щелчок по строке — подробности по сайту' })) : null,
      streams.totals.length ? h('div', { class: 'mt' }, card('TCP/UDP-потоки', table([
        { title: 'Поток', render: (r) => r.stream }, { title: 'Сессий', num: true, render: (r) => fmtInt(r.sessions) },
        { title: 'Принято', num: true, render: (r) => fmtBytes(r.bin) }, { title: 'Отдано', num: true, render: (r) => fmtBytes(r.bout) },
        { title: 'Ср. длительность', num: true, render: (r) => fmtNum(r.sessions ? r.dur / r.sessions : 0, 1) + ' с' }, { title: 'Ошибок', num: true, render: (r) => fmtInt(r.errors) },
      ], streams.totals), { flush: true })) : null);
    const step = ts.step;
    const mk = (cc, series, opts) => { const c = timeChart(cc.canvas, series, { xFmt, tipTitle: (t) => fmtDate(t) + (step >= 3600 ? '' : ''), maxTicks: 8, ...opts, legendEl: cc.legendEl }); charts.push(c); return c; };
    setData(mk(cReq, [{ label: '2xx', color: sc.s2, fill: true }, { label: '3xx', color: sc.s3, fill: true }, { label: '4xx', color: sc.s4, fill: true }, { label: '5xx', color: sc.s5, fill: true }],
      { stacked: true, type: 'bar', yFmt: fmtCompact }), ts.ts, [ts.s2, ts.s3, ts.s4, ts.s5]);
    setData(mk(cBw, [{ label: 'Исходящий', color: seriesColor(0), fill: true }, { label: 'Входящий', color: seriesColor(1) }], { yFmt: fmtBps }), ts.ts, [ts.bps_out, ts.bps_in]);
    setData(mk(cLat, [{ label: 'p50', color: seriesColor(0) }, { label: 'p90', color: seriesColor(1) }, { label: 'p99', color: seriesColor(2) }, { label: 'бэкенд (ср.)', color: seriesColor(3) }],
      { yFmt: fmtMs }), ts.ts, [ts.p50, ts.p90, ts.p99, ts.urt_avg]);
    setData(mk(cUniq, [{ label: 'IP', color: seriesColor(0), fill: true }], { yFmt: fmtCompact }), ts.ts, [ts.uniq]);
    setData(mk(cErr, [{ label: '5xx, %', color: sc.s5, fill: true }], { yFmt: (v) => fmtNum(v, 1) + '%' }), ts.ts, [ts.err_pct]);
    setData(mk(cNg, [{ label: 'ошибки', color: seriesColor(1) }], { type: 'bar', yFmt: fmtCompact }), ts.ts, [ts.errors]);
    charts.push(barChart(hist, sum.hist.labels, sum.hist.values, { fmt: fmtCompact, label: 'запросов' }));
    drawTop();
  }
  await load();
  return () => destroyAll(charts);
}

const HTTP = { 200: 'OK', 201: 'Created', 204: 'No Content', 206: 'Partial', 301: 'Moved', 302: 'Found', 304: 'Not Modified', 307: 'Temp Redirect',
  308: 'Perm Redirect', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 408: 'Timeout',
  413: 'Too Large', 429: 'Too Many', 444: 'Closed', 499: 'Client Closed', 500: 'Server Error', 502: 'Bad Gateway', 503: 'Unavailable', 504: 'Gateway Timeout' };
