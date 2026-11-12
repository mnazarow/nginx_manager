// Встроенная документация: главы, оглавление, поиск по всем главам, ссылки на разделы, печать.
import { h, mount, icon, loading, debounce } from '../ui.js';
import { ctx } from '../app.js';
import { docList, docText, renderMarkdown, outline, highlight, searchDocs, scrollToStable, findSection } from '../docrender.js';

export async function render(root) {
  const list = await docList();
  const name = ctx.params.p || (list[0] && list[0].name);
  const sec = ctx.params.s || '';
  const query = ctx.params.q || '';
  const hl = ctx.params.hl || '';
  const content = h('div', { class: 'docs' }, loading());
  const search = h('input', { type: 'search', placeholder: 'Поиск по документации…', value: query, 'aria-label': 'Поиск по документации' });
  const chapters = h('div', { class: 'doc-chapters' });
  const pager = h('div', { class: 'doc-pager' });
  const tools = h('div', { class: 'doc-tools' },
    h('button', { class: 'btn sm', onclick: () => window.print(), title: 'Печать или сохранение в PDF' }, icon('file'), 'Печать'));

  mount(root, h('div', { class: 'docs-layout' },
    h('div', { class: 'card docs-nav' }, h('div', { class: 'card-body' }, search, chapters)),
    h('div', { class: 'card docs-main' }, h('div', { class: 'card-body' }, tools, content, pager))));

  const drawChapters = (headings = []) => mount(chapters, list.map(d => [
    h('a', { href: `#/docs?p=${encodeURIComponent(d.name)}`, class: d.name === name && !query ? 'active' : '' }, d.title),
    d.name === name && !query && headings.length ? h('div', { class: 'doc-sub' }, headings.map(x =>
      h('a', { href: `#/docs?p=${encodeURIComponent(name)}&s=${encodeURIComponent(x.id)}`, 'data-id': x.id, onclick: (e) => { e.preventDefault(); goSection(x.id); } }, x.text))) : null,
  ]));

  const goSection = (id) => {
    const el = findSection(content, id);
    if (!el) return;
    scrollToStable(el, { block: 'start' });
    history.replaceState(null, '', `#/docs?p=${encodeURIComponent(name)}&s=${encodeURIComponent(id)}`);
    content.querySelectorAll('.doc-target').forEach(x => x.classList.remove('doc-target'));
    el.classList.add('doc-target');
  };

  // ---- поиск
  const runSearch = async (q) => {
    if (!q.trim()) { location.hash = `#/docs?p=${encodeURIComponent(name)}`; return; }
    history.replaceState(null, '', `#/docs?q=${encodeURIComponent(q)}`);
    drawChapters();
    mount(pager); tools.style.display = 'none';
    mount(content, loading('Поиск…'));
    const res = await searchDocs(q);
    if (search.value !== q) return;
    const groups = {};
    res.forEach(r => (groups[r.name] ||= { chapter: r.chapter, items: [] }).items.push(r));
    const out = h('div', {}, h('h1', {}, `Поиск: «${q}»`),
      h('p', { class: 'muted' }, res.length ? `Найдено разделов: ${res.length}` : 'Ничего не найдено. Попробуйте другое слово или директиву nginx (например, proxy_read_timeout).'),
      Object.entries(groups).map(([n, g]) => h('div', { class: 'doc-results' }, h('h2', {}, g.chapter),
        g.items.map(r => h('a', { class: 'doc-result', href: `#/docs?p=${encodeURIComponent(n)}` + (r.id ? `&s=${encodeURIComponent(r.id)}` : '') + `&hl=${encodeURIComponent(q)}` },
          h('div', { class: 'doc-result-title' }, r.title), h('div', { class: 'doc-result-snippet' }, r.snippet))))));
    highlight(out, q);
    mount(content, out);
  };
  search.addEventListener('input', debounce(() => runSearch(search.value), 300));
  search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { search.value = ''; runSearch(''); } });

  if (query) { drawChapters(); await runSearch(query); return; }
  if (!name) { mount(content, 'Документация не найдена'); return; }

  // ---- глава
  if (!list.some(d => d.name === name)) {
    drawChapters();
    mount(content, h('div', { class: 'empty' }, h('h1', {}, 'Глава не найдена'), h('div', {}, `«${name}» нет в документации — выберите главу в списке.`)));
    return;
  }
  const md = await docText(name);
  const doc = renderMarkdown(md, name);
  const heads = outline(doc);
  drawChapters(heads);
  mount(content, ...doc.childNodes);
  if (hl) {
    const n = highlight(content, hl);
    tools.insertBefore(h('span', { class: 'muted small' }, `Подсвечено совпадений: ${n} `,
      h('a', { href: `#/docs?p=${encodeURIComponent(name)}` + (sec ? `&s=${encodeURIComponent(sec)}` : '') }, 'убрать')), tools.firstChild);
  }
  const i = list.findIndex(d => d.name === name);
  mount(pager,
    i > 0 ? h('a', { class: 'btn', href: `#/docs?p=${encodeURIComponent(list[i - 1].name)}` }, '← ', list[i - 1].title) : h('span'),
    i < list.length - 1 ? h('a', { class: 'btn', href: `#/docs?p=${encodeURIComponent(list[i + 1].name)}` }, list[i + 1].title, ' →') : h('span'));
  if (sec) setTimeout(() => goSection(sec), 30);
  else window.scrollTo(0, 0);

  // подсветка текущего раздела в оглавлении при прокрутке
  const subLinks = () => [...chapters.querySelectorAll('.doc-sub a')];
  const obs = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) subLinks().forEach(a => a.classList.toggle('current', a.dataset.id === e.target.id));
    }
  }, { rootMargin: '-10% 0px -80% 0px' });
  content.querySelectorAll('h2').forEach(el => obs.observe(el));
  return () => obs.disconnect();
}
