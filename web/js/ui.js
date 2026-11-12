// Общие помощники интерфейса: построение DOM, форматирование, уведомления, модальные окна.

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else if (k in el && typeof v !== 'string') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...children) { clear(el); append(el, children); return el; }

// ---------- Иконки (линейные, 24×24) ----------
const P = {
  bulb: 'M9 18h6M10 22h4M12 2a7 7 0 00-4 12.7V17h8v-2.3A7 7 0 0012 2z',
  ban: 'M12 2a10 10 0 100 20 10 10 0 000-20zM4.9 4.9l14.2 14.2',
  dash: 'M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z',
  sites: 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20M12 2a15 15 0 014 10 15 15 0 01-4 10 15 15 0 01-4-10 15 15 0 014-10z',
  stream: 'M4 7h16M4 12h16M4 17h10M17 15l3 2-3 2',
  cert: 'M12 2l7 3v6c0 5-3.5 9-7 11-3.5-2-7-6-7-11V5l7-3zM9 12l2 2 4-4',
  chart: 'M3 3v18h18M7 15l4-4 3 3 6-6',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  alert: 'M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01',
  server: 'M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01',
  stethoscope: 'M22 12h-4l-3 9L9 3l-3 9H2',
  bell: 'M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0',
  sliders: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  history: 'M3 3v5h5M3.05 13A9 9 0 106 5.3L3 8M12 7v5l4 2',
  cpu: 'M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2M6 6h12v12H6zM9 9h6v6H9z',
  users: 'M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8zM23 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  gear: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z',
  book: 'M4 19.5A2.5 2.5 0 016.5 17H20M4 4.5A2.5 2.5 0 016.5 2H20v20H6.5A2.5 2.5 0 014 19.5z',
  backup: 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3',
  plus: 'M12 5v14M5 12h14', edit: 'M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z', trash: 'M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6',
  copy: 'M9 9h11v11H9zM5 15H4V4h11v1', play: 'M5 3l14 9-14 9V3z', pause: 'M6 4h4v16H6zM14 4h4v16h-4z',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0114.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0020.5 15',
  check: 'M20 6L9 17l-5-5', x: 'M18 6L6 18M6 6l12 12', search: 'M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3',
  eye: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 100-6 3 3 0 000 6z', logout: 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9',
  sun: 'M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z', download: 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3',
  upload: 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12', wrench: 'M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.8-3.8a6 6 0 01-7.9 7.9l-6.9 6.9a2.1 2.1 0 01-3-3l6.9-6.9a6 6 0 017.9-7.9z',
  power: 'M18.4 6.6a9 9 0 11-12.8 0M12 2v10', tool: 'M3 21l6-6M14 4l6 6-9 9-6-6z', file: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8zM14 2v6h6',
  user: 'M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z', key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 11-7.8 7.8 5.5 5.5 0 017.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  import: 'M12 3v12M7 10l5 5 5-5M5 21h14', globe: 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2', bolt: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z', lock: 'M5 11h14v10H5zM8 11V7a4 4 0 018 0v4',
};
export function icon(name, cls = '') {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', '1.8'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
  if (cls) s.setAttribute('class', cls);
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', P[name] || P.file);
  s.appendChild(p); return s;
}

// ---------- Форматирование ----------
const nf = new Intl.NumberFormat('ru-RU');
export function fmtNum(n, d = 0) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  return new Intl.NumberFormat('ru-RU', { maximumFractionDigits: d, minimumFractionDigits: 0 }).format(n);
}
export function fmtInt(n) { return n === null || n === undefined ? '—' : nf.format(Math.round(n)); }
export function fmtCompact(n) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  const a = Math.abs(n);
  if (a >= 1e9) return fmtNum(n / 1e9, 1) + ' млрд';
  if (a >= 1e6) return fmtNum(n / 1e6, 1) + ' млн';
  if (a >= 1e4) return fmtNum(n / 1e3, 1) + ' тыс';
  return fmtNum(n, a < 10 ? 1 : 0);
}
export function fmtBytes(b, d = 1) {
  if (b === null || b === undefined || isNaN(b)) return '—';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ']; let i = 0;
  while (Math.abs(b) >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return fmtNum(b, i ? d : 0) + ' ' + u[i];
}
export function fmtBps(bits) {
  if (bits === null || bits === undefined || isNaN(bits)) return '—';
  const u = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с']; let i = 0;
  while (Math.abs(bits) >= 1000 && i < u.length - 1) { bits /= 1000; i++; }
  return fmtNum(bits, bits < 10 && i ? 2 : 1) + ' ' + u[i];
}
export function fmtMs(ms) {
  if (ms === null || ms === undefined || isNaN(ms)) return '—';
  if (ms >= 1000) return fmtNum(ms / 1000, 2) + ' с';
  return fmtNum(ms, ms < 10 ? 1 : 0) + ' мс';
}
export function fmtPct(p, d = 1) { return p === null || p === undefined || isNaN(p) ? '—' : fmtNum(p, d) + '%'; }
export function fmtDate(ts, opts = {}) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: opts.year ? 'numeric' : undefined,
    hour: '2-digit', minute: '2-digit', second: opts.sec ? '2-digit' : undefined });
}
export function fmtTime(ts, sec = true) {
  return new Date(ts * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: sec ? '2-digit' : undefined });
}
export function fmtAgo(ts) {
  if (!ts) return '—';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.round(s) + ' с назад';
  if (s < 3600) return Math.round(s / 60) + ' мин назад';
  if (s < 86400) return Math.round(s / 3600) + ' ч назад';
  return Math.round(s / 86400) + ' дн назад';
}
export function fmtDur(s) {
  s = Math.round(s || 0);
  const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return `${d} д ${hh} ч`;
  if (hh) return `${hh} ч ${m} мин`;
  if (m) return `${m} мин`;
  return `${s} с`;
}
let regionNames = null;
/** Название страны по-русски по коду ISO (RU → Россия); LAN — локальная сеть. */
export function countryName(cc) {
  if (!cc || cc === '--') return '';
  if (cc === 'LAN') return 'локальная сеть';
  try { regionNames = regionNames || new Intl.DisplayNames(['ru'], { type: 'region' }); return regionNames.of(cc) || cc; } catch { return cc; }
}
export function countryTag(cc) { return cc ? h('span', { class: 'tag', title: countryName(cc) }, cc) : null; }
export function statusClass(code) { return 'status-' + String(code)[0]; }

// ---------- Уведомления ----------
export function toast(msg, kind = 'info', title = '', timeout = 5000) {
  let box = $('.toasts');
  if (!box) { box = h('div', { class: 'toasts' }); document.body.appendChild(box); }
  const t = h('div', { class: 'toast ' + kind }, title ? h('b', {}, title) : null, msg);
  box.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, kind === 'bad' ? timeout * 2 : timeout);
  t.addEventListener('click', () => t.remove());
}

// ---------- Модальные окна ----------
export function modal({ title, body, footer, size = '', onClose }) {
  const back = h('div', { class: 'modal-back' });
  const close = () => { back.remove(); document.removeEventListener('keydown', esc); onClose && onClose(); };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  const m = h('div', { class: 'modal ' + size },
    h('div', { class: 'modal-head' }, h('h2', {}, title), h('button', { class: 'btn ghost icon', onclick: close, title: 'Закрыть' }, icon('x'))),
    h('div', { class: 'modal-body' }, body),
    footer ? h('div', { class: 'modal-foot' }, footer) : null);
  back.appendChild(m);
  back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
  document.addEventListener('keydown', esc);
  document.body.appendChild(back);
  return { close, el: m };
}

/** Всплывающая подсказка у элемента: закрывается щелчком вне неё, Esc или повторным щелчком. */
let openPop = null;
export function popover(anchor, content) {
  if (openPop) { const same = openPop.anchor === anchor; openPop.close(); if (same) return null; }
  const el = h('div', { class: 'popover', role: 'dialog' }, content);
  document.body.appendChild(el);
  const place = () => {
    const r = anchor.getBoundingClientRect();
    const w = Math.min(420, window.innerWidth - 16);
    el.style.width = w + 'px';
    let left = Math.min(Math.max(8, r.left + r.width / 2 - w / 2), window.innerWidth - w - 8);
    let top = r.bottom + 8;
    if (top + el.offsetHeight > window.innerHeight - 8 && r.top - el.offsetHeight - 8 > 8) top = r.top - el.offsetHeight - 8;
    el.style.left = left + 'px'; el.style.top = Math.max(8, top) + 'px';
  };
  place();
  const onDoc = (e) => { if (!el.contains(e.target) && e.target !== anchor) close(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const close = () => { el.remove(); document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey);
    window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close); openPop = null; };
  setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', close, true); window.addEventListener('resize', close); }, 0);
  openPop = { anchor, close };
  return openPop;
}

export function confirmDlg(text, { title = 'Подтверждение', ok = 'Да', danger = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const m = modal({
      title, body: h('div', { style: { whiteSpace: 'pre-wrap' } }, text),
      footer: [h('button', { class: 'btn', onclick: () => { done = true; m.close(); resolve(false); } }, 'Отмена'),
        h('button', { class: 'btn ' + (danger ? 'danger solid' : 'primary'), onclick: () => { done = true; m.close(); resolve(true); } }, ok)],
      onClose: () => { if (!done) resolve(false); },
    });
  });
}

export function promptDlg(title, label, value = '', { placeholder = '', textarea = false } = {}) {
  return new Promise((resolve) => {
    const inp = textarea ? h('textarea', { placeholder }, value) : h('input', { type: 'text', value, placeholder });
    let done = false;
    const m = modal({
      title, body: h('div', { class: 'field' }, h('label', {}, label), inp),
      footer: [h('button', { class: 'btn', onclick: () => { done = true; m.close(); resolve(null); } }, 'Отмена'),
        h('button', { class: 'btn primary', onclick: () => { done = true; m.close(); resolve(inp.value); } }, 'OK')],
      onClose: () => { if (!done) resolve(null); },
    });
    setTimeout(() => inp.focus(), 50);
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !textarea) { done = true; m.close(); resolve(inp.value); } });
  });
}

// ---------- Компоненты ----------
export function card(title, body, { sub = '', actions = null, cls = '', flush = false } = {}) {
  return h('div', { class: 'card ' + cls },
    title ? h('div', { class: 'card-head' }, h('div', {}, h('h3', {}, title), sub ? h('div', { class: 'sub' }, sub) : null), actions ? h('div', { class: 'row' }, actions) : null) : null,
    h('div', { class: 'card-body' + (flush ? ' flush' : '') }, body));
}

export function kpi(label, value, { unit = '', foot = '', cls = '', tip = '' } = {}) {
  const v = h('div', { class: 'value num' }, value, unit ? h('small', {}, unit) : null);
  const f = h('div', { class: 'foot' }, foot);
  const el = h('div', { class: 'card kpi ' + cls, title: tip }, h('div', { class: 'label' }, label), v, f);
  el.set = (val, u, ft, c) => { mount(v, val, u ? h('small', {}, u) : null); if (ft !== undefined) mount(f, ft); el.className = 'card kpi ' + (c || ''); };
  return el;
}

export function badge(text, kind = '') { return h('span', { class: 'badge ' + kind }, text); }
export function stateBadge(state) {
  const m = { up: ['доступен', 'good'], down: ['недоступен', 'bad'], unknown: ['проверка…', ''], disabled: ['не проверяется', 'outline'],
    valid: ['действителен', 'good'], expired: ['истёк', 'bad'], error: ['ошибка', 'bad'], pending: ['выпускается', 'info'], missing: ['нет файла', 'bad'],
    applied: ['применена', 'good'], failed: ['ошибка', 'bad'], ok: ['норма', 'good'], firing: ['сработало', 'bad'], pending_alert: ['ожидание', 'warn'],
    resolved: ['восстановлено', 'good'], repeat: ['повтор', 'warn'] };
  const [t, k] = m[state] || [state, ''];
  return badge(t, k);
}

export function table(columns, rows, { onRow, empty = 'Нет данных', cls = '', rowClass } = {}) {
  if (!rows || !rows.length) return h('div', { class: 'empty' }, empty);
  return h('div', { class: 'table-wrap' }, h('table', { class: 't ' + cls },
    h('thead', {}, h('tr', {}, columns.map(c => h('th', { class: c.num ? 'num' : '', style: c.width ? { width: c.width } : null }, c.title)))),
    h('tbody', {}, rows.map(r => h('tr', { class: (onRow ? 'clickable ' : '') + (rowClass ? rowClass(r) : ''), onclick: onRow ? (e) => { if (!e.target.closest('button,a,input,label')) onRow(r); } : null },
      columns.map(c => {
        const v = c.render ? c.render(r) : r[c.key];
        return h('td', { class: (c.num ? 'num ' : '') + (c.cls || '') }, v);
      }))))));
}

export function tabs(items, active, onChange) {
  const bar = h('div', { class: 'tabs' });
  const draw = (cur) => mount(bar, items.map(it => h('button', { class: it.id === cur ? 'active' : '', onclick: () => { draw(it.id); onChange(it.id); } },
    it.label, it.badge ? badge(it.badge, it.badgeKind || '') : null)));
  draw(active);
  return bar;
}

export function segmented(options, value, onChange) {
  const g = h('div', { class: 'btn-group' });
  const draw = (v) => mount(g, options.map(([val, lbl]) => h('button', { class: 'btn sm' + (val === v ? ' active' : ''), onclick: () => { draw(val); onChange(val); } }, lbl)));
  draw(value);
  return g;
}

export function empty(title, text = '', action = null, ic = 'file') {
  return h('div', { class: 'empty' }, icon(ic), h('h3', {}, title), text ? h('div', {}, text) : null, action ? h('div', { class: 'mt' }, action) : null);
}

export function loading(text = 'Загрузка…') { return h('div', { class: 'loading' }, h('span', { class: 'spinner' }), ' ', text); }

export function copyBtn(getText, label = '') {
  return h('button', { class: 'btn sm', title: 'Копировать', onclick: async () => {
    try { await navigator.clipboard.writeText(typeof getText === 'function' ? getText() : getText); toast('Скопировано', 'good'); }
    catch { toast('Не удалось скопировать', 'bad'); }
  } }, icon('copy'), label);
}

// Подсветка синтаксиса конфигурации nginx (без innerHTML для пользовательских данных — экранирование вручную)
export function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
export function highlightNginx(text, errLine = 0) {
  const lines = text.split('\n').map((ln, i) => {
    let out;
    const ci = ln.indexOf('#');
    let code = ln, com = '';
    if (ci >= 0 && !/["'][^"']*#/.test(ln.slice(0, ci + 1))) { code = ln.slice(0, ci); com = ln.slice(ci); }
    // экранируем только то, что важно для текста (&, <, >, ") — без числовых сущностей, чтобы правило для чисел их не задело
    out = code.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
      .replace(/(&quot;.*?&quot;|'[^']*')/g, '<span class="s">$1</span>')
      .replace(/(\$[a-zA-Z_0-9]+)/g, '<span class="v">$1</span>')
      .replace(/^(\s*)([a-z_0-9]+)(?=\s|;|$)/, '$1<span class="k">$2</span>')
      .replace(/\b(\d+(?:ms|s|m|h|d|k|K|M|g|G|r\/s|r\/m)?)\b(?=[;\s])/g, '<span class="n">$1</span>');
    if (com) out += `<span class="c">${esc(com)}</span>`;
    return (i + 1 === errLine) ? `<span class="errline">${out || ' '}</span>` : out;
  });
  return lines.join('\n');
}
export function codeBlock(text, { errLine = 0, maxHeight } = {}) {
  const pre = h('pre', { class: 'code', html: highlightNginx(text || '', errLine) });
  if (maxHeight) pre.style.maxHeight = maxHeight;
  return pre;
}
export function diffBlock(text) {
  const html = (text || '').split('\n').map(l => {
    const e = esc(l);
    if (l.startsWith('+') && !l.startsWith('+++')) return `<span class="add">${e}</span>`;
    if (l.startsWith('-') && !l.startsWith('---')) return `<span class="del">${e}</span>`;
    if (l.startsWith('@@')) return `<span class="hunk">${e}</span>`;
    return e;
  }).join('\n');
  return h('pre', { class: 'code diff', html });
}

export function sparkline(values, { color = 'var(--s1)', w = 120, hgt = 28, fill = true } = {}) {
  const max = Math.max(...values, 1), n = values.length;
  const pts = values.map((v, i) => [n > 1 ? i / (n - 1) * w : 0, hgt - 2 - (v / max) * (hgt - 4)]);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${hgt}`); svg.setAttribute('preserveAspectRatio', 'none');
  svg.setAttribute('width', '100%'); svg.setAttribute('height', hgt);
  svg.innerHTML = (fill ? `<path d="${d} L${w} ${hgt} L0 ${hgt}Z" fill="${color}" opacity=".12"/>` : '') +
    `<path d="${d}" fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
  return svg;
}

export function hbars(items, { valueFmt = fmtInt, labelFmt = (x) => x, max, color } = {}) {
  if (!items.length) return h('div', { class: 'empty small' }, 'Нет данных');
  const m = max || Math.max(...items.map(i => i.value), 1);
  return h('div', { class: 'hbars' }, items.map(it => h('div', { class: 'hb', title: it.title || '' },
    h('div', { class: 'ellipsis' }, labelFmt(it.label)), h('div', { class: 'num ink2' }, valueFmt(it.value), it.extra ? h('span', { class: 'muted small' }, ' ' + it.extra) : null),
    h('div', { class: 'track' }, h('div', { style: { width: (it.value / m * 100).toFixed(1) + '%', background: color || 'var(--s1)' } })))));
}

export function debounce(fn, ms = 300) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

export function downloadText(name, text, type = 'application/json') {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

export function pickFile(accept = '') {
  return new Promise((resolve) => {
    const inp = h('input', { type: 'file', accept, style: { display: 'none' } });
    inp.addEventListener('change', () => { const f = inp.files[0]; if (!f) return resolve(null); const r = new FileReader(); r.onload = () => resolve({ name: f.name, text: r.result }); r.readAsText(f); });
    document.body.appendChild(inp); inp.click(); setTimeout(() => inp.remove(), 60000);
  });
}

export const SITE_TYPES = { proxy: 'Прокси', redirect: 'Редирект', static: 'Статика' };
