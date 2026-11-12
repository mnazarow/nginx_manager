// Отрисовка документации (Markdown из каталога docs/): якоря разделов, ссылки, изображения, поиск, подсветка.
/* global marked */
import { api } from './api.js';
import { h, modal } from './ui.js';

const cache = new Map();   // name -> markdown
let listCache = null;

/** Якорь раздела как на GitHub: строчные буквы, без знаков препинания, пробелы → дефисы. */
export function slugify(text) {
  return String(text).trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

export async function docList() {
  if (!listCache) listCache = await api('/docs');
  return listCache;
}

export async function docText(name) {
  if (!cache.has(name)) cache.set(name, await api(`/docs/${encodeURIComponent(name)}`));
  return cache.get(name);
}

/** Markdown → DOM: id у заголовков (с суффиксами для повторов), ссылки на главы и разделы внутри панели. */
export function renderMarkdown(md, name, { onNavigate } = {}) {
  const root = h('div', { html: marked.parse(md) });
  root.querySelectorAll('script,iframe,object,embed,style').forEach(e => e.remove());
  const seen = new Map();
  root.querySelectorAll('h1,h2,h3,h4,h5').forEach(el => {
    const base = slugify(el.textContent);
    const n = seen.get(base) || 0;
    seen.set(base, n + 1);
    el.id = n ? `${base}-${n}` : base;
    if (el.tagName !== 'H1') {
      el.appendChild(h('a', { class: 'anchor', href: `#/docs?p=${encodeURIComponent(name)}&s=${encodeURIComponent(el.id)}`, title: 'Ссылка на раздел' }, '#'));
    }
  });
  root.querySelectorAll('img').forEach(img => {
    const src = img.getAttribute('src') || '';
    if (!/^(https?:|data:|\/)/.test(src)) img.src = '/docs-files/' + src;
    img.title = 'Нажмите, чтобы увеличить';
    img.addEventListener('click', () => modal({ title: img.alt || 'Иллюстрация', size: 'xl', body: h('img', { src: img.src, class: 'zoomed', alt: img.alt }) }));
  });
  root.querySelectorAll('a[href]').forEach(a => {
    if (a.classList.contains('anchor')) return;
    const href = a.getAttribute('href') || '';
    const m = /^([\w.-]+\.md)?(?:#(.*))?$/.exec(href);
    if (m && (m[1] || m[2] !== undefined)) {
      const page = m[1] || name;
      const sec = m[2] ? decodeURIComponent(m[2]) : '';
      a.href = `#/docs?p=${encodeURIComponent(page)}` + (sec ? `&s=${encodeURIComponent(sec)}` : '');
      if (onNavigate) a.addEventListener('click', (e) => { e.preventDefault(); onNavigate(page, sec); });
    } else if (/^https?:/.test(href)) { a.target = '_blank'; a.rel = 'noopener'; }
  });
  return root;
}

/** Элемент раздела по id: для якоря параметра (<a id="f-…">) — следующий за ним заголовок. */
export function findSection(root, id) {
  const el = root.querySelector(`[id="${CSS.escape(id)}"]`);
  if (!el || el.tagName !== 'A') return el;
  const block = el.parentElement && el.parentElement.tagName === 'P' && el.parentElement.textContent.trim() === '' ? el.parentElement : el;
  const next = block.nextElementSibling;
  return next && /^H[1-6]$/.test(next.tagName) ? next : block;
}

/** Прокрутить к элементу и повторить после загрузки картинок выше него (иначе они сдвинут раздел вниз). */
export function scrollToStable(el, opts = { block: 'start' }) {
  if (!el) return;
  el.scrollIntoView(opts);
  const root = el.closest('.docs') || document;
  const imgs = [...root.querySelectorAll('img')].filter(i => !i.complete && (i.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING));
  if (!imgs.length) return;
  let moved = false;
  const stop = () => { moved = true; };
  window.addEventListener('wheel', stop, { once: true, passive: true });
  window.addEventListener('touchmove', stop, { once: true, passive: true });
  Promise.race([Promise.all(imgs.map(i => i.decode().catch(() => null))), new Promise(r => setTimeout(r, 4000))])
    .then(() => { if (!moved) el.scrollIntoView({ ...opts, behavior: 'auto' }); });
}

/** Текст заголовка без значка ссылки «#». */
export function headingText(el) {
  return [...el.childNodes].filter(n => !(n.classList && n.classList.contains('anchor'))).map(n => n.textContent).join('').trim();
}

/** Заголовки второго уровня — оглавление главы. */
export function outline(root) {
  return [...root.querySelectorAll('h2')].map(el => ({ id: el.id, text: headingText(el) }));
}

/** Подсветить вхождения слов запроса внутри элемента (без изменения разметки, кроме <mark>). */
export function highlight(root, query) {
  const words = terms(query);
  if (!words.length) return 0;
  const re = new RegExp('(' + words.map(escapeRe).join('|') + ')', 'gi');
  const test = new RegExp(words.map(escapeRe).join('|'), 'i');
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => !n.parentElement || n.parentElement.closest('mark,script,style,.anchor') ? NodeFilter.FILTER_SKIP
      : test.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP,
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  let count = 0;
  for (const node of nodes) {
    re.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0;
    const text = node.nodeValue;
    for (const m of text.matchAll(re)) {
      frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      frag.appendChild(h('mark', { class: 'doc-hl' }, m[0]));
      last = m.index + m[0].length;
      count++;
    }
    frag.appendChild(document.createTextNode(text.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }
  return count;
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function terms(q) { return String(q || '').toLowerCase().split(/\s+/).map(s => s.trim()).filter(s => s.length >= 2).slice(0, 6); }

/** Поиск по всем главам: разделы (h1–h4), где встречаются все слова запроса; сортировка по релевантности. */
let index = null;
export async function searchDocs(query, limit = 60) {
  const words = terms(query);
  if (!words.length) return [];
  if (!index) {
    const list = await docList();
    const texts = await Promise.all(list.map(d => docText(d.name)));
    index = [];
    list.forEach((d, i) => {
      const root = renderMarkdown(texts[i], d.name);
      let cur = { name: d.name, chapter: d.title, id: '', title: d.title, text: '' };
      const push = () => { if (cur.text.trim() || cur.id) index.push(cur); };
      for (const el of root.children) {
        if (/^H[1-4]$/.test(el.tagName)) {
          push();
          cur = { name: d.name, chapter: d.title, id: el.tagName === 'H1' ? '' : el.id, title: headingText(el), text: '' };
        } else {
          cur.text += ' ' + el.textContent.replace(/\s+/g, ' ');
        }
      }
      push();
    });
    index.forEach(s => { s.lt = s.title.toLowerCase(); s.lx = s.text.toLowerCase(); });
  }
  const out = [];
  for (const s of index) {
    let score = 0, ok = true;
    for (const w of words) {
      const inTitle = s.lt.includes(w);
      const pos = s.lx.indexOf(w);
      if (!inTitle && pos < 0) { ok = false; break; }
      score += (inTitle ? 10 : 0) + (pos >= 0 ? 1 + Math.min(5, s.lx.split(w).length - 2) : 0);
    }
    if (!ok) continue;
    const pos = Math.max(0, ...words.map(w => s.lx.indexOf(w)).filter(p => p >= 0).slice(0, 1));
    const start = Math.max(0, pos - 70);
    const snippet = (start ? '…' : '') + s.text.slice(start, start + 220).trim() + (s.text.length > start + 220 ? '…' : '');
    out.push({ ...s, score, snippet });
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}

/** Что открывать в справке для страницы панели: [глава, заголовок раздела]. */
const TAB_HEADINGS = {
  sites: { main: 'Вкладка «Основное»', backends: 'Вкладка «Бэкенды»', ssl: 'Вкладка «SSL / HTTPS»', locations: 'Вкладка «Локации»',
    proxy: 'Вкладка «Проксирование»', cache: 'Вкладка «Кэш»', security: 'Вкладка «Безопасность»', performance: 'Вкладка «Производительность»',
    errors: 'Вкладка «Ошибки и обслуживание»', advanced: 'Вкладка «Дополнительно»' },
};
const PAGE_HELP = {
  '/': ['09-monitoring.md', 'Дашборд (реальное время)'], '/analytics': ['09-monitoring.md', 'Аналитика (история)'],
  '/requests': ['09-monitoring.md', 'Журнал запросов'], '/errors': ['09-monitoring.md', 'Журнал ошибок nginx'],
  '/backends': ['09-monitoring.md', 'Бэкенды'], '/system': ['09-monitoring.md', 'Сервер'],
  '/sites': ['05-sites.md', ''], '/streams': ['06-streams.md', ''], '/certs': ['07-certificates.md', ''],
  '/bans': ['17-bans.md', ''], '/global': ['08-global-settings.md', 'Справочник параметров'],
  '/versions': ['15-backup-versions.md', 'Версии конфигурации'], '/diagnostics': ['10-diagnostics.md', ''],
  '/alerts': ['11-alerts.md', ''], '/events': ['10-diagnostics.md', 'Автоматическое восстановление'],
  '/users': ['12-security.md', 'Пользователи и роли'], '/audit': ['12-security.md', 'Аудит'],
  '/settings': ['13-panel-settings.md', ''], '/backup': ['15-backup-versions.md', 'Резервные копии'],
  '/profile': ['12-security.md', 'Двухфакторная аутентификация (TOTP)'], '/docs': ['01-overview.md', 'Интерфейс'],
};
export function helpFor(route, params = {}) {
  const [page, heading] = PAGE_HELP[route] || ['01-overview.md', ''];
  let sec = heading ? slugify(heading) : '';
  if (route === '/sites' && params.edit && params.tab && TAB_HEADINGS.sites[params.tab]) sec = slugify(TAB_HEADINGS.sites[params.tab]);
  else if (route === '/sites' && params.edit) sec = slugify(TAB_HEADINGS.sites.main);
  else if (route === '/bans' && params.tab === 'countries') sec = slugify('Доступ по странам');
  return { page, sec, tab: (route === '/global' || route === '/settings') ? params.tab || '' : '' };
}
