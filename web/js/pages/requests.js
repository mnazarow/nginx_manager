// Журнал запросов: живой поток и поиск по истории.
import { api, live } from '../api.js';
import { h, mount, icon, badge, table, tabs, modal, fmtBytes, fmtMs, fmtDate, fmtTime, fmtInt, statusClass, debounce, loading, copyBtn, downloadText } from '../ui.js';
import { ctx, can } from '../app.js';
import { banDialog } from './bans.js';

export async function render(root) {
  const sites = await api('/sites');
  const names = Object.fromEntries(sites.map(s => [String(s.id), s.name]));
  names['-'] = 'неизвестный домен'; names.panel = 'панель';
  let mode = (ctx.params.ip || ctx.params.uri || ctx.params.status) ? 'search' : 'live';
  const body = h('div', {});
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Журнал запросов'),
      h('p', {}, 'Каждый запрос через nginx: кто, куда, с каким результатом и за сколько. Живой поток показывает запросы с задержкой 1–2 секунды.'))),
    tabs([{ id: 'live', label: 'В реальном времени' }, { id: 'search', label: 'Поиск по истории' }], mode, (m) => { mode = m; draw(); }),
    body);
  let cleanup = null;
  const draw = () => { if (cleanup) cleanup(); cleanup = mode === 'live' ? liveView(body, sites, names) : searchView(body, sites, names); };
  draw();
  return () => { if (cleanup) cleanup(); };
}

function siteSelect(sites, value, onchange) {
  return h('select', { onchange: (e) => onchange(e.target.value) }, h('option', { value: '' }, 'Все сайты'),
    sites.map(s => h('option', { value: String(s.id), selected: String(s.id) === value }, s.name)));
}

const cols = (names) => [
  { title: 'Время', render: (r) => h('span', { class: 'num small' }, fmtTime(r.ts)) },
  { title: 'Код', render: (r) => h('b', { class: statusClass(r.s ?? r.status) }, r.s ?? r.status) },
  { title: 'Метод', render: (r) => h('span', { class: 'small' }, r.m ?? r.method) },
  { title: 'Хост / URI', render: (r) => h('div', { class: 'ellipsis', style: { maxWidth: '520px' }, title: (r.host || '') + (r.u ?? r.uri) },
    h('span', { class: 'muted small' }, r.host), ' ', h('span', { class: 'mono' }, r.u ?? r.uri)) },
  { title: 'Клиент', render: (r) => h('span', { class: 'mono small' }, r.ip, (r.cc ?? r.country) ? h('span', { class: 'muted' }, ' ' + (r.cc ?? r.country)) : null, r.bot ? ' 🤖' : '') },
  { title: 'Размер', num: true, render: (r) => fmtBytes(r.b ?? r.bytes) },
  { title: 'Время', num: true, render: (r) => { const ms = (r.rt) * 1000; return h('span', { class: ms > 1000 ? 'status-4' : '' }, fmtMs(ms)); } },
  { title: 'Бэкенд', render: (r) => h('span', { class: 'mono small muted' }, r.up ?? r.upstream ?? '') },
  { title: 'Кэш', render: (r) => (r.cache) ? badge(r.cache, r.cache === 'HIT' ? 'good' : '') : '' },
];

function details(r, names) {
  const g = (a, b) => r[a] ?? r[b];
  modal({ title: `${g('m', 'method')} ${g('u', 'uri')}`, size: 'lg', body: h('div', { class: 'col' },
    h('dl', { class: 'kv' },
      h('dt', {}, 'Время'), h('dd', {}, fmtDate(r.ts, { sec: true, year: true })),
      h('dt', {}, 'Сайт'), h('dd', {}, names[r.site] || r.site),
      h('dt', {}, 'Хост'), h('dd', {}, r.host),
      h('dt', {}, 'Статус'), h('dd', {}, h('b', { class: statusClass(g('s', 'status')) }, g('s', 'status'))),
      h('dt', {}, 'Протокол'), h('dd', {}, (g('proto', 'proto') || '') + (r.tls ? ' / ' + r.tls : '')),
      h('dt', {}, 'Клиент'), h('dd', {}, h('a', { href: `#/requests?ip=${encodeURIComponent(r.ip)}` }, r.ip), (g('cc', 'country')) ? ' (' + g('cc', 'country') + ')' : ''),
      h('dt', {}, 'Ответ'), h('dd', {}, fmtBytes(g('b', 'bytes'))),
      h('dt', {}, 'Время nginx'), h('dd', {}, fmtMs(r.rt * 1000)),
      h('dt', {}, 'Время бэкенда'), h('dd', {}, r.urt != null ? fmtMs(r.urt * 1000) : '—'),
      h('dt', {}, 'Бэкенд'), h('dd', {}, (g('up', 'upstream') || '—') + (g('us', 'ustatus') ? ` → ${g('us', 'ustatus')}` : '')),
      h('dt', {}, 'Кэш'), h('dd', {}, r.cache || '—'),
      h('dt', {}, 'Referer'), h('dd', { class: 'small' }, r.ref || '—'),
      h('dt', {}, 'User-Agent'), h('dd', { class: 'small' }, r.ua || '—'),
      h('dt', {}, 'X-Request-ID'), h('dd', { class: 'mono small' }, r.rid || '—', r.rid ? copyBtn(r.rid) : null)),
    h('div', { class: 'alert small' }, 'X-Request-ID передаётся бэкенду в заголовке — по нему можно найти этот запрос в журналах приложения.'),
    can('operator') && r.ip ? h('div', { class: 'row' },
      h('a', { class: 'btn sm', href: `#/requests?ip=${encodeURIComponent(r.ip)}` }, icon('list'), 'Все запросы с этого IP'),
      h('button', { class: 'btn sm danger', onclick: () => banDialog(r.ip, { reason: `${g('m', 'method')} ${String(g('u', 'uri')).slice(0, 120)} → ${g('s', 'status')}` }) }, icon('ban'), 'Заблокировать IP')) : null) });
}

function liveView(box, sites, names) {
  const f = { site: '', status: '', ip: '', q: '', min_rt: '', hide_bots: false };
  let paused = false, rows = [], count = 0;
  const tbody = h('div', {});
  const counter = h('span', { class: 'muted small' });
  const send = () => live.send('live', { on: !paused, filter: { ...f, site: f.site || '*' } });
  const upd = debounce(() => { rows = []; drawRows(); send(); }, 300);
  const pauseBtn = h('button', { class: 'btn', onclick: () => { paused = !paused; mount(pauseBtn, icon(paused ? 'play' : 'pause'), paused ? 'Продолжить' : 'Пауза'); send(); } }, icon('pause'), 'Пауза');
  mount(box,
    h('div', { class: 'toolbar' },
      siteSelect(sites, '', (v) => { f.site = v; upd(); }),
      h('select', { onchange: (e) => { f.status = e.target.value; upd(); } }, ['', '2xx', '3xx', '4xx', '5xx', '404', '429', '499', '502', '504'].map(s => h('option', { value: s }, s || 'Все коды'))),
      h('input', { type: 'search', placeholder: 'IP', style: { width: '140px' }, oninput: (e) => { f.ip = e.target.value.trim(); upd(); } }),
      h('input', { type: 'search', placeholder: 'Текст в URI, хосте, User-Agent', oninput: (e) => { f.q = e.target.value.trim(); upd(); } }),
      h('input', { type: 'number', placeholder: 'от мс', style: { width: '100px' }, oninput: (e) => { f.min_rt = e.target.value; upd(); } }),
      h('label', { class: 'switch small' }, h('input', { type: 'checkbox', onchange: (e) => { f.hide_bots = e.target.checked; upd(); } }), h('span', { class: 'track' }), 'Скрыть ботов'),
      pauseBtn, h('button', { class: 'btn', onclick: () => { rows = []; drawRows(); } }, 'Очистить'), counter),
    h('div', { class: 'card' }, tbody));
  function drawRows() {
    mount(tbody, rows.length ? table(cols(names), rows, { onRow: (r) => details(r, names), cls: 'compact' }) : h('div', { class: 'empty' }, paused ? 'На паузе' : 'Ожидание запросов…'));
    counter.textContent = `получено: ${fmtInt(count)}, показано последних ${rows.length}`;
  }
  drawRows();
  const off = live.on('requests', (m) => {
    if (paused) return;
    count += m.items.length;
    rows = m.items.slice().reverse().concat(rows).slice(0, 300);
    drawRows();
  });
  send();
  return () => { off(); live.send('live', { on: false }); };
}

function searchView(box, sites, names) {
  const p = ctx.params;
  const f = { site: p.site || '', status: p.status || '', ip: p.ip || '', uri: p.uri || '', method: '', host: '', ua: '', upstream: '', min_rt: '', rid: '', sort: '', start: '', end: '' };
  let offset = 0;
  const limit = 100;
  const res = h('div', {});
  const inp = (key, ph, w = '160px', type = 'search') => h('input', { type, placeholder: ph, value: f[key], style: { width: w }, oninput: (e) => { f[key] = e.target.value.trim(); } });
  const run = async () => {
    mount(res, loading());
    const q = { ...f, limit, offset };
    if (f.start) q.start = new Date(f.start).getTime() / 1000;
    if (f.end) q.end = new Date(f.end).getTime() / 1000;
    const r = await api('/requests', { query: q });
    mount(res, h('div', { class: 'card' }, table(cols(names).map((c, i) => i === 0 ? { ...c, render: (x) => h('span', { class: 'num small' }, fmtDate(x.ts, { sec: true })) } : c), r.items,
      { onRow: (x) => details(x, names), cls: 'compact', empty: 'Ничего не найдено. Журнал хранится ограниченное время (см. Настройки панели → Статистика).' })),
    h('div', { class: 'row mt' }, h('span', { class: 'muted small' }, `Найдено: ${r.total >= 100000 ? 'более 100 000' : fmtInt(r.total)}`), h('span', { class: 'grow' }),
      h('button', { class: 'btn sm', disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - limit); run(); } }, '← Назад'),
      h('span', { class: 'small' }, `${offset + 1}–${offset + r.items.length}`),
      h('button', { class: 'btn sm', disabled: r.items.length < limit, onclick: () => { offset += limit; run(); } }, 'Вперёд →'),
      h('button', { class: 'btn sm', onclick: () => downloadText('requests.csv', toCsv(r.items), 'text/csv') }, icon('download'), 'CSV')));
  };
  mount(box,
    h('div', { class: 'card mb' }, h('div', { class: 'card-body' }, h('div', { class: 'toolbar', style: { marginBottom: 0 } },
      siteSelect(sites, f.site, (v) => { f.site = v; }),
      h('select', { onchange: (e) => { f.status = e.target.value; } }, ['', '2xx', '3xx', '4xx', '5xx', '400', '401', '403', '404', '429', '499', '500', '502', '503', '504'].map(s => h('option', { value: s, selected: s === f.status }, s || 'Все коды'))),
      h('select', { onchange: (e) => { f.method = e.target.value; } }, ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map(s => h('option', { value: s }, s || 'Все методы'))),
      inp('ip', 'IP-адрес', '140px'), inp('uri', 'URI содержит', '200px'), inp('host', 'Хост', '150px'), inp('ua', 'User-Agent', '150px'),
      inp('upstream', 'Бэкенд', '130px'), inp('min_rt', 'от, мс', '90px', 'number'), inp('rid', 'X-Request-ID', '160px'),
      h('input', { type: 'datetime-local', title: 'С', onchange: (e) => { f.start = e.target.value; } }),
      h('input', { type: 'datetime-local', title: 'По', onchange: (e) => { f.end = e.target.value; } }),
      h('select', { onchange: (e) => { f.sort = e.target.value; } }, [['', 'Сначала новые'], ['rt', 'Сначала медленные'], ['bytes', 'Сначала большие']].map(([v, l]) => h('option', { value: v }, l))),
      h('button', { class: 'btn primary', onclick: () => { offset = 0; run(); } }, icon('search'), 'Найти')))),
    res);
  run();
  return () => {};
}

function toCsv(items) {
  const keys = ['ts', 'site', 'host', 'ip', 'method', 'uri', 'status', 'bytes', 'rt', 'urt', 'upstream', 'ustatus', 'ref', 'ua', 'cache', 'tls', 'country', 'rid'];
  const esc = (v) => { v = v == null ? '' : String(v); return /[",\n;]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return keys.join(',') + '\n' + items.map(r => keys.map(k => esc(k === 'ts' ? new Date(r.ts * 1000).toISOString() : r[k])).join(',')).join('\n');
}
