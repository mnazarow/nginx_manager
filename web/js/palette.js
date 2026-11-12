// Быстрый поиск по панели (Ctrl+K): разделы, сайты, вкладки настроек, действия, документация, IP и коды ответов.
import { api } from './api.js';
import { h, mount, icon } from './ui.js';
import { ctx, can, NAV, applyDialog, toggleTheme } from './app.js';
import { SCHEMA } from './forms.js';
import { searchDocs } from './docrender.js';
import { openPageHelp } from './help.js';

let el = null;
let cache = null;

async function sources() {
  if (cache && Date.now() - cache.ts < 30000) return cache;
  const [sites, streams] = await Promise.all([api('/sites', { silent: true }).catch(() => []), api('/streams', { silent: true }).catch(() => [])]);
  cache = { ts: Date.now(), sites, streams };
  return cache;
}

function staticItems() {
  const items = [];
  for (const [group, entries] of NAV) {
    for (const [path, label, ic] of entries) items.push({ group: 'Разделы', label, hint: group, icon: ic, go: '#' + path });
  }
  for (const t of SCHEMA?.tabs?.global || []) items.push({ group: 'Настройки nginx', label: t.label, hint: 'Настройки nginx', icon: 'sliders', go: `#/global?tab=${t.id}` });
  for (const t of SCHEMA?.tabs?.panel || []) items.push({ group: 'Настройки панели', label: t.label, hint: 'Настройки панели', icon: 'gear', go: `#/settings?tab=${t.id}` });
  const A = (label, ic, run, role = 'viewer', kw = '') => can(role) && items.push({ group: 'Действия', label, icon: ic, run, kw });
  A('Новый сайт', 'plus', () => { location.hash = '#/sites?new'; }, 'operator', 'добавить создать');
  A('Применить конфигурацию', 'check', () => applyDialog(), 'operator', 'apply reload');
  A('Запустить диагностику', 'stethoscope', () => { location.hash = '#/diagnostics'; }, 'viewer', 'проверка');
  A('Заблокировать IP-адрес', 'ban', () => import('./pages/bans.js').then(m => m.banDialog('')), 'operator', 'бан блокировка');
  A('Тишина оповещений', 'bell', () => import('./pages/alerts.js').then(m => m.silenceDialog()), 'operator', 'mute плановые работы');
  A('Выпустить сертификат', 'cert', () => { location.hash = '#/certs'; }, 'operator', "let's encrypt ssl https");
  A('Справка по этой странице', 'book', () => openPageHelp(ctx.route, ctx.params), 'viewer', 'помощь f1 help');
  A('Сменить тему (светлая / тёмная)', 'moon', () => toggleTheme(), 'viewer', 'dark light');
  return items;
}

function score(item, words) {
  const text = `${item.label} ${item.hint || ''} ${item.kw || ''}`.toLowerCase();
  let s = 0;
  for (const w of words) {
    const i = text.indexOf(w);
    if (i < 0) return -1;
    s += i === 0 ? 30 : text[i - 1] === ' ' ? 15 : 5;
  }
  return s + (item.group === 'Разделы' ? 5 : item.group === 'Действия' ? 4 : 0);
}

export async function openPalette() {
  if (el) { close(); return; }
  document.querySelectorAll('.popover').forEach((p) => p.remove());
  const input = h('input', { type: 'search', placeholder: 'Раздел, сайт, домен, настройка, действие, IP, код ответа или вопрос по документации…', 'aria-label': 'Поиск по панели' });
  const list = h('div', { class: 'pal-list', role: 'listbox' });
  el = h('div', { class: 'pal-back', onmousedown: (e) => { if (e.target === el) close(); } },
    h('div', { class: 'pal', role: 'dialog', 'aria-label': 'Поиск по панели' },
      h('div', { class: 'pal-input' }, icon('search'), input, h('kbd', {}, 'Esc')), list,
      h('div', { class: 'pal-foot' }, h('span', {}, h('kbd', {}, '↑'), h('kbd', {}, '↓'), ' выбор'), h('span', {}, h('kbd', {}, 'Enter'), ' открыть'),
        h('span', {}, h('kbd', {}, 'Ctrl'), h('kbd', {}, 'K'), ' в любом месте панели'))));
  document.body.appendChild(el);
  input.focus();
  const base = staticItems();
  const src = await sources();
  for (const s of src.sites) base.push({ group: 'Сайты', label: s.name, hint: (s.domains || []).join(', '), icon: 'sites', go: `#/sites?edit=${s.id}`, kw: (s.domains || []).join(' ') });
  for (const s of src.streams) base.push({ group: 'Потоки', label: s.name, hint: `порт ${s.listen_port || ''}`, icon: 'stream', go: '#/streams' });
  let shown = [], sel = 0, seq = 0;

  const draw = () => {
    let lastGroup = null;
    mount(list, shown.length ? shown.map((it, i) => {
      const head = it.group !== lastGroup ? h('div', { class: 'pal-group' }, it.group) : null;
      lastGroup = it.group;
      return [head, h('div', { class: 'pal-item' + (i === sel ? ' sel' : ''), role: 'option', 'aria-selected': i === sel,
        onmousemove: () => { if (sel !== i) { sel = i; draw(); } }, onclick: () => choose(it) },
        icon(it.icon || 'list'), h('span', { class: 'pal-label' }, it.label), it.hint ? h('span', { class: 'pal-hint' }, it.hint) : null)];
    }) : h('div', { class: 'pal-empty' }, 'Ничего не найдено'));
    list.querySelector('.pal-item.sel')?.scrollIntoView({ block: 'nearest' });
  };

  const update = async () => {
    const q = input.value.trim().toLowerCase();
    const my = ++seq;
    const words = q.split(/\s+/).filter(Boolean);
    let items;
    if (!words.length) items = base.filter(i => i.group === 'Разделы' || i.group === 'Действия' || i.group === 'Сайты').slice(0, 40);
    else items = base.map(i => [score(i, words), i]).filter(x => x[0] >= 0).sort((a, b) => b[0] - a[0]).map(x => x[1]).slice(0, 30);
    const extra = [];
    const raw = input.value.trim();
    if (/^[0-9a-f:.]+$/i.test(raw) && (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw) || raw.includes(':'))) {
      extra.push({ group: 'IP-адрес', label: `Запросы с адреса ${raw}`, icon: 'list', go: `#/requests?ip=${encodeURIComponent(raw)}` });
      if (can('operator')) extra.push({ group: 'IP-адрес', label: `Заблокировать ${raw}`, icon: 'ban', run: () => import('./pages/bans.js').then(m => m.banDialog(raw)) });
    }
    if (/^[1-5]\d\d$/.test(raw)) {
      extra.push({ group: 'Код ответа', label: `Запросы со статусом ${raw}`, icon: 'list', go: `#/requests?status=${raw}` });
    }
    shown = [...extra, ...items];
    sel = 0;
    draw();
    if (q.length >= 3) {
      const docs = await searchDocs(q, 6).catch(() => []);
      if (my !== seq || !el) return;
      shown = [...shown, ...docs.map(d => ({ group: 'Документация', label: d.title, hint: d.chapter, icon: 'book',
        go: `#/docs?p=${encodeURIComponent(d.name)}` + (d.id ? `&s=${encodeURIComponent(d.id)}` : '') + `&hl=${encodeURIComponent(q)}` }))];
      draw();
    }
  };

  const choose = (it) => {
    close();
    if (it.run) it.run();
    else if (it.go) location.hash = it.go;
  };
  input.addEventListener('input', update);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); draw(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); draw(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (shown[sel]) choose(shown[sel]); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  });
  update();
}

function close() {
  if (el) { el.remove(); el = null; }
}

export function installPalette() {
  document.addEventListener('keydown', (e) => {
    if (!ctx.user) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K' || e.key === 'л' || e.key === 'Л')) { e.preventDefault(); openPalette(); }
    else if (e.key === '/' && !typing && !document.querySelector('.modal-back')) { e.preventDefault(); openPalette(); }
  });
}
