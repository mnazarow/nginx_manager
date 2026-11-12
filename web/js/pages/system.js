// Сервер: ресурсы ОС, процессы nginx, управление nginx, информация о сборке.
import { api, live } from '../api.js';
import { h, mount, icon, badge, card, segmented, fmtNum, fmtBps, fmtBytes, fmtPct, fmtDur, toast, confirmDlg, modal, loading, kpi } from '../ui.js';
import { timeChart, setData, chartCard, seriesColor, destroyAll } from '../charts.js';
import { can, refreshState } from '../app.js';

export async function render(root) {
  const charts = [];
  let range = '600';
  const body = h('div', {});
  const infoBox = h('div', {});
  const kp = h('div', { class: 'grid g6 mb' });
  const ctl = (action, label, ic, danger) => can('operator') ? h('button', { class: 'btn' + (danger ? ' danger' : ''), onclick: async () => {
    if (danger && !await confirmDlg(`Выполнить «${label}»? Все сайты будут недоступны, пока nginx не запущен.`, { danger: true, ok: label })) return;
    try { const r = await api(`/nginx/${action}`, { method: 'POST' }); toast((r.output || '').trim() || 'Выполнено', 'good', label); } finally { refreshState(); loadInfo(); }
  } }, icon(ic), label) : null;
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Сервер и nginx'), h('p', {}, 'Ресурсы операционной системы и процессов nginx, управление службой.')),
      h('div', { class: 'row' }, ctl('reload', 'Перечитать (reload)', 'refresh'), ctl('restart', 'Перезапустить', 'power'), ctl('reopen', 'Переоткрыть журналы', 'file'),
        ctl('start', 'Запустить', 'play'), ctl('stop', 'Остановить', 'x', true))),
    kp,
    h('div', { class: 'toolbar' }, segmented([['600', '10 минут'], ['3600', '1 час'], ['86400', '24 часа'], ['604800', '7 дней'], ['2592000', '30 дней']], range, (v) => { range = v; load(); })),
    body, h('div', { class: 'mt' }, infoBox));

  async function load() {
    const r = await api('/stats/system', { query: { from: Date.now() / 1000 - +range } });
    destroyAll(charts);
    const c = [chartCard('CPU', { sub: '% загрузки' }), chartCard('Память и диск', { sub: '% использования' }), chartCard('Load average', { sub: '1 мин' }),
      chartCard('Сеть', { sub: 'бит/с' }), chartCard('Дисковый ввод-вывод', { sub: 'байт/с' }), chartCard('Соединения nginx', { sub: 'stub_status' }),
      chartCard('Память процессов nginx', { sub: 'RSS' }), chartCard('CPU процессов nginx', { sub: '% одного ядра' })];
    mount(body, h('div', { class: 'grid g2' }, c.map(x => x.el)));
    const span = +range;
    const xFmt = span > 86400 ? (t) => new Date(t * 1000).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' }) : undefined;
    const mk = (i, series, yFmt, opts = {}) => { const ch = timeChart(c[i].canvas, series, { yFmt, xFmt, seconds: span <= 600, legendEl: c[i].legendEl, ...opts }); charts.push(ch); return ch; };
    const pct = (v) => fmtNum(v, 0) + '%';
    setData(mk(0, [{ label: 'CPU', color: seriesColor(0), fill: true }], pct, { suggestedMax: 100 }), r.ts, [r.cpu]);
    setData(mk(1, [{ label: 'Память', color: seriesColor(0) }, { label: 'Диск /', color: seriesColor(1) }], pct, { suggestedMax: 100 }), r.ts, [r.mem, r.disk]);
    setData(mk(2, [{ label: 'load1', color: seriesColor(0), fill: true }], (v) => fmtNum(v, 2)), r.ts, [r.load1]);
    setData(mk(3, [{ label: 'Приём', color: seriesColor(0), fill: true }, { label: 'Передача', color: seriesColor(1) }], fmtBps), r.ts, [r.net_rx, r.net_tx]);
    setData(mk(4, [{ label: 'Чтение', color: seriesColor(0) }, { label: 'Запись', color: seriesColor(1) }], (v) => fmtBytes(v) + '/с'), r.ts, [r.disk_r, r.disk_w]);
    setData(mk(5, [{ label: 'Активные', color: seriesColor(0) }, { label: 'Чтение', color: seriesColor(1) }, { label: 'Запись', color: seriesColor(2) }, { label: 'Ожидание', color: seriesColor(3) }],
      (v) => fmtNum(v, 0)), r.ts, [r.conn_active, r.conn_reading, r.conn_writing, r.conn_waiting]);
    setData(mk(6, [{ label: 'RSS', color: seriesColor(0), fill: true }], (v) => fmtBytes(v)), r.ts, [r.nginx_rss]);
    setData(mk(7, [{ label: 'CPU', color: seriesColor(0), fill: true }], pct), r.ts, [r.nginx_cpu]);
  }
  async function loadInfo() {
    const [info, col] = await Promise.all([api('/nginx/info'), api('/diagnostics/collector')]);
    const s = info.status;
    mount(infoBox, h('div', { class: 'grid g2' },
      card('Сборка nginx', h('div', { class: 'col' },
        h('dl', { class: 'kv' }, h('dt', {}, 'Версия'), h('dd', {}, info.version_full), h('dt', {}, 'Библиотека TLS'), h('dd', {}, info.openssl || '—'),
          h('dt', {}, 'Исполняемый файл'), h('dd', { class: 'mono' }, info.binary), h('dt', {}, 'PID-файл'), h('dd', { class: 'mono' }, info.pid_path),
          h('dt', {}, 'Пользователь воркеров'), h('dd', {}, info.user), h('dt', {}, 'Состояние'), h('dd', {}, s.running ? `работает ${fmtDur(s.uptime)}, PID ${s.pid}, воркеров ${s.workers}` : 'остановлен'),
          h('dt', {}, 'Возможности'), h('dd', { class: 'row', style: { gap: '4px' } }, badge('stream ' + (info.stream ? '✓' : '✗'), info.stream ? 'good' : 'bad'),
            badge('HTTP/2', 'good'), badge('HTTP/3 ' + (info.http3 ? '✓' : '✗'), info.http3 ? 'good' : ''), badge('reject_handshake ' + (info.reject_handshake ? '✓' : '✗'), info.reject_handshake ? 'good' : ''),
            badge('IPv6 ' + (info.ipv6 ? '✓' : '✗'), info.ipv6 ? 'good' : ''))),
        h('details', {}, h('summary', { class: 'small' }, `Модули (${info.modules.length})`), h('div', { class: 'mt-s' }, info.modules.map(m => h('span', { class: 'tag' }, m)))),
        h('details', {}, h('summary', { class: 'small' }, 'Параметры сборки (configure)'), h('pre', { class: 'code mt-s', style: { whiteSpace: 'pre-wrap' } }, info.configure.split(' --').join('\n--'))),
        can('admin') ? h('div', {}, h('button', { class: 'btn sm', onclick: async () => {
          const body = h('div', {}, loading()); modal({ title: 'nginx -T (полная конфигурация)', size: 'xl', body });
          const t = await api('/config/dump'); mount(body, h('pre', { class: 'code', style: { maxHeight: '72vh' } }, t));
        } }, icon('file'), 'Показать nginx -T')) : null)),
      card('Сборщик статистики', h('div', { class: 'col' },
        h('dl', { class: 'kv' }, h('dt', {}, 'Обработано строк'), h('dd', {}, fmtNum(col.parsed)), h('dt', {}, 'Ошибок разбора'), h('dd', {}, fmtNum(col.parse_errors)),
          h('dt', {}, 'stub_status'), h('dd', {}, col.stub.ok ? 'работает' : col.stub.error), h('dt', {}, 'GeoIP'), h('dd', {}, col.geoip.enabled ? col.geoip.path : col.geoip.error),
          h('dt', {}, 'Время работы панели'), h('dd', {}, fmtDur(col.uptime))),
        h('table', { class: 't compact' }, h('thead', {}, h('tr', {}, ['Журнал', 'Состояние', 'Размер', 'Отставание', 'Строк'].map(x => h('th', {}, x)))),
          h('tbody', {}, col.tailers.map(t => h('tr', {}, h('td', { class: 'mono small' }, t.path), h('td', {}, t.status === 'ok' ? badge('ok', 'good') : badge(t.status, 'warn')),
            h('td', { class: 'num' }, fmtBytes(t.size)), h('td', { class: 'num' }, fmtBytes(t.lag_bytes)), h('td', { class: 'num' }, fmtNum(t.lines))))))))));
  }
  await Promise.all([load(), loadInfo()]);
  const off = live.on('tick', (m) => {
    const s = m.system; if (!s || !s.ts) return;
    mount(kp, kpi('CPU', fmtPct(s.cpu, 0), { foot: `${s.cpus} ядер, load ${fmtNum(s.load1, 2)}` }), kpi('Память', fmtPct(s.mem, 0), { foot: `${fmtBytes(s.mem_used)} / ${fmtBytes(s.mem_total)}` }),
      kpi('Диск /', fmtPct(s.disk, 0), { foot: `свободно ${fmtBytes(s.disk_free)}` }), kpi('Сеть ↓', fmtBps(s.net_rx), { foot: `↑ ${fmtBps(s.net_tx)}` }),
      kpi('Nginx RSS', fmtBytes(s.nginx_rss), { foot: `${s.nginx_workers} воркеров, ${s.nginx_fds} дескрипторов` }), kpi('Nginx CPU', fmtPct(s.nginx_cpu), { foot: 'сумма по процессам' }));
  });
  return () => { off(); destroyAll(charts); };
}
