// Справка в выдвижной панели: нужный раздел документации рядом с формой, не уходя со страницы.
import { h, mount, icon, loading } from './ui.js';
import { docList, docText, renderMarkdown, slugify, helpFor, scrollToStable, findSection } from './docrender.js';
import { SCHEMA } from './forms.js';

let drawer = null;

function close() {
  if (!drawer) return;
  drawer.remove();
  drawer = null;
  document.removeEventListener('keydown', onKey);
}
function onKey(e) { if (e.key === 'Escape') close(); }

/** Открыть справку: глава name, раздел sec (id заголовка или якоря). */
export async function openHelp(name, sec = '') {
  if (!name) return;
  close();
  const body = h('div', { class: 'docs help-body' }, loading());
  const title = h('div', { class: 'help-title' }, 'Справка');
  const full = h('a', { class: 'btn sm', href: `#/docs?p=${encodeURIComponent(name)}` + (sec ? `&s=${encodeURIComponent(sec)}` : ''), onclick: () => close() },
    icon('book'), 'Открыть в документации');
  drawer = h('aside', { class: 'help-drawer', role: 'dialog', 'aria-label': 'Справка' },
    h('div', { class: 'help-head' }, title, h('span', { class: 'grow' }), full,
      h('button', { class: 'btn ghost icon', title: 'Закрыть (Esc)', onclick: close }, icon('x'))),
    body);
  document.body.appendChild(drawer);
  document.addEventListener('keydown', onKey);
  try {
    const [list, md] = await Promise.all([docList(), docText(name)]);
    const doc = list.find(d => d.name === name);
    title.textContent = doc ? doc.title : name;
    const root = renderMarkdown(md, name, { onNavigate: (p, s) => openHelp(p, s) });
    mount(body, ...root.childNodes);
    const target = sec ? findSection(body, sec) : null;
    if (target) {
      scrollToStable(target, { block: 'start' });
      target.classList.add('doc-target');
    } else body.scrollTop = 0;
  } catch (e) {
    mount(body, h('div', { class: 'alert bad' }, 'Не удалось открыть документацию: ', e.message));
  }
}

/** Справка по текущей странице панели. */
export function openPageHelp(route, params) {
  const { page, sec, tab } = helpFor(route, params);
  let s = sec;
  if (tab) {
    const kind = route === '/global' ? 'global' : 'panel';
    const t = (SCHEMA?.tabs?.[kind] || []).find(x => x.id === tab);
    if (t) s = slugify(t.label);
  }
  return openHelp(page, s);
}
