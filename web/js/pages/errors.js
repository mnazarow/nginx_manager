// Журнал ошибок nginx: классификация, рекомендации, живой поток, поиск.
import { api, live } from '../api.js';
import { h, mount, icon, badge, table, tabs, segmented, fmtDate, fmtInt, loading, modal } from '../ui.js';

const LVL = { emerg: 'bad', alert: 'bad', crit: 'bad', error: 'bad', warn: 'warn', notice: 'info', info: '', debug: '' };

export async function render(root) {
  const sites = await api('/sites');
  const names = Object.fromEntries(sites.map(s => [String(s.id), s.name]));
  const st = { range: '86400', level: '', category: '', site: '', q: '', mode: 'list' };
  const sumBox = h('div', {});
  const listBox = h('div', {});
  let liveOff = null;
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Журнал ошибок nginx'),
      h('p', {}, 'Ошибки автоматически классифицируются, к каждой категории дано объяснение причины и что сделать.')),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: raw }, icon('file'), 'Исходный файл журнала'))),
    h('div', { class: 'toolbar' }, segmented([['3600', '1 час'], ['86400', '24 часа'], ['604800', '7 дней'], ['2592000', '30 дней']], st.range, (v) => { st.range = v; load(); }),
      h('select', { onchange: (e) => { st.level = e.target.value; load(); } }, ['', 'crit', 'error', 'warn', 'notice', 'info'].map(l => h('option', { value: l }, l || 'Все уровни'))),
      h('select', { onchange: (e) => { st.site = e.target.value; load(); } }, h('option', { value: '' }, 'Все сайты'), sites.map(s => h('option', { value: s.id }, s.name))),
      h('input', { type: 'search', placeholder: 'Поиск по тексту, IP, бэкенду…', onkeydown: (e) => { if (e.key === 'Enter') { st.q = e.target.value; load(); } } })),
    sumBox,
    tabs([{ id: 'list', label: 'Записи' }, { id: 'live', label: 'В реальном времени' }], 'list', (m) => { st.mode = m; drawMode(); }),
    listBox);

  async function load() {
    const q = { start: Date.now() / 1000 - +st.range, level: st.level, category: st.category, site: st.site, q: st.q, limit: 200 };
    mount(listBox, loading());
    const r = await api('/errors', { query: q });
    mount(sumBox, r.categories.length ? h('div', { class: 'grid g4 mb' }, r.categories.map(c => h('div', { class: 'card', style: { cursor: 'pointer', outline: st.category === c.category ? '2px solid var(--accent)' : '' },
      onclick: () => { st.category = st.category === c.category ? '' : c.category; load(); }, title: c.hint },
    h('div', { class: 'card-body' }, h('div', { class: 'row between' }, h('b', {}, c.title), badge(fmtInt(c.n), c.level === 'crit' ? 'bad' : c.level === 'error' ? 'bad' : c.level === 'warn' ? 'warn' : '')),
      h('div', { class: 'muted small mt-s', style: { display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' } }, c.hint || ''))))) : h('div', { class: 'alert good mb' }, 'За выбранный период ошибок нет 🎉'));
    if (st.mode === 'list') mount(listBox, h('div', { class: 'card' }, table(cols(names), r.items, { cls: 'compact', onRow: detail, empty: 'Нет записей' })),
      h('div', { class: 'muted small mt-s' }, `Показано ${r.items.length} из ${fmtInt(r.total)}`));
  }
  function drawMode() {
    if (liveOff) { liveOff(); liveOff = null; live.send('errors', { on: false }); }
    if (st.mode === 'list') return load();
    let rows = [];
    const box = h('div', { class: 'card' });
    mount(listBox, box);
    const drawRows = () => mount(box, rows.length ? table(cols(names), rows, { cls: 'compact', onRow: detail }) : h('div', { class: 'empty' }, 'Ожидание новых записей…'));
    drawRows();
    liveOff = live.on('errors', (m) => { rows = m.items.slice().reverse().concat(rows).slice(0, 300); drawRows(); });
    live.send('errors', { on: true });
  }
  await load();
  return () => { if (liveOff) liveOff(); live.send('errors', { on: false }); };
}

const cols = (names) => [
  { title: 'Время', render: (r) => h('span', { class: 'num small nowrap' }, fmtDate(r.ts, { sec: true })) },
  { title: 'Уровень', render: (r) => badge(r.level, LVL[r.level] || '') },
  { title: 'Категория', render: (r) => h('span', { class: 'small' }, r.title || r.category) },
  { title: 'Сообщение', render: (r) => h('div', { class: 'ellipsis small', style: { maxWidth: '520px' }, title: r.message }, r.message) },
  { title: 'Сайт', render: (r) => h('span', { class: 'small' }, names[r.site] || r.server || '') },
  { title: 'Клиент', render: (r) => h('span', { class: 'mono small' }, r.client) },
  { title: 'Бэкенд', render: (r) => h('span', { class: 'mono small muted' }, r.upstream) },
];

function detail(r) {
  modal({ title: r.title || r.category, size: 'lg', body: h('div', { class: 'col' },
    r.hint ? h('div', { class: 'alert warn' }, '💡 ', r.hint) : null,
    h('pre', { class: 'code', style: { whiteSpace: 'pre-wrap' } }, r.message),
    h('dl', { class: 'kv' }, h('dt', {}, 'Время'), h('dd', {}, fmtDate(r.ts, { sec: true, year: true })), h('dt', {}, 'Уровень'), h('dd', {}, r.level),
      h('dt', {}, 'Сервер'), h('dd', {}, r.server || '—'), h('dt', {}, 'Хост'), h('dd', {}, r.host || '—'), h('dt', {}, 'Запрос'), h('dd', { class: 'mono small' }, r.request || '—'),
      h('dt', {}, 'Клиент'), h('dd', {}, r.client ? h('a', { href: `#/requests?ip=${encodeURIComponent(r.client)}` }, r.client) : '—'),
      h('dt', {}, 'Бэкенд'), h('dd', { class: 'mono small' }, r.upstream || '—'))) });
}

async function raw() {
  const t = await api('/errors/raw', { query: { lines: 500 } });
  modal({ title: 'nm-error.log (последние 500 строк)', size: 'xl', body: h('pre', { class: 'code', style: { maxHeight: '70vh' } }, t || '(пусто)') });
}
