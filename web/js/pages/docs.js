// Встроенная документация (Markdown из каталога docs/).
/* global marked */
import { api } from '../api.js';
import { h, mount, loading } from '../ui.js';
import { ctx } from '../app.js';

export async function render(root) {
  const list = await api('/docs');
  const name = ctx.params.p || (list[0] && list[0].name);
  const content = h('div', { class: 'docs' }, loading());
  mount(root, h('div', { class: 'docs-layout' },
    h('div', { class: 'card docs-nav' }, h('div', { class: 'card-body' }, h('h4', { class: 'mb' }, 'Документация'),
      list.map(d => h('a', { href: `#/docs?p=${encodeURIComponent(d.name)}`, class: d.name === name ? 'active' : '' }, d.title)))),
    h('div', { class: 'card' }, h('div', { class: 'card-body', style: { padding: '24px 32px' } }, content))));
  if (!name) { mount(content, 'Документация не найдена'); return; }
  const md = await api(`/docs/${encodeURIComponent(name)}`);
  // Документы — локальные файлы из поставки; ссылки на изображения и другие разделы переписываются под панель
  let html = marked.parse(md);
  const tmp = h('div', { html });
  tmp.querySelectorAll('script,iframe,object').forEach(e => e.remove());
  tmp.querySelectorAll('img').forEach(img => { const src = img.getAttribute('src') || ''; if (!/^(https?:|data:|\/)/.test(src)) img.src = '/docs-files/' + src; });
  tmp.querySelectorAll('a').forEach(a => {
    const href = a.getAttribute('href') || '';
    if (/^[\w.-]+\.md(#.*)?$/.test(href)) a.href = `#/docs?p=${encodeURIComponent(href.split('#')[0])}`;
    else if (href.startsWith('#')) { const id = href.slice(1); a.href = '#'; a.onclick = (e) => { e.preventDefault(); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' }); }; }
    else if (/^https?:/.test(href)) { a.target = '_blank'; a.rel = 'noopener'; }
  });
  tmp.querySelectorAll('h1,h2,h3').forEach(el => { el.id = el.textContent.trim().toLowerCase().replace(/[^\wа-яё\s-]/gi, '').replace(/\s+/g, '-'); });
  mount(content, ...tmp.childNodes);
  window.scrollTo(0, 0);
}
