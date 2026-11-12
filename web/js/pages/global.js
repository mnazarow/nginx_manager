// Глобальные настройки nginx (nginx.conf, уровень http).
import { api } from '../api.js';
import { h, mount, icon, toast, tabs, badge } from '../ui.js';
import { model, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { ctx, can, refreshState, applyDialog } from '../app.js';

export async function render(root) {
  const obj = await api('/settings/global');
  let tab = ctx.params.tab || 'workers', adv = localStorage.getItem('nm-adv') === '1', errors = {}, dirty = false;
  const form = h('div', {});
  const status = h('span', {});
  const tabBar = h('div', {});
  const draw = () => {
    mount(tabBar, tabs(SCHEMA.tabs.global, tab, (t) => { tab = t; draw(); }));
    mount(form);
    renderFields(form, model('global'), obj, { root: obj, tab, advanced: adv, errors, rerender: draw, onChange: () => { dirty = true; mount(status, badge('не сохранено', 'warn')); } });
  };
  const save = async (apply) => {
    try {
      await api('/settings/global', { method: 'PUT', body: obj });
      errors = {}; dirty = false; mount(status, badge('сохранено', 'good'));
      await refreshState();
      if (apply) applyDialog('Глобальные настройки'); else toast('Сохранено. Примените конфигурацию.', 'good');
    } catch (e) { errors = errorsToMap(e); draw(); }
  };
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Настройки nginx'),
      h('p', {}, 'Параметры главного файла nginx.conf и уровня http, действующие для всех сайтов. Значения по умолчанию подходят для большинства серверов; наведите на «i», чтобы увидеть описание и рекомендации.')),
      h('div', { class: 'row' }, status,
        h('label', { class: 'switch small' }, h('input', { type: 'checkbox', checked: adv, onchange: (e) => { adv = e.target.checked; localStorage.setItem('nm-adv', adv ? '1' : '0'); draw(); } }), h('span', { class: 'track' }), 'Расширенные'),
        can('admin') ? h('button', { class: 'btn', onclick: () => save(false) }, 'Сохранить') : null,
        can('admin') ? h('button', { class: 'btn primary', onclick: () => save(true) }, icon('check'), 'Сохранить и применить') : null)),
    !can('admin') ? h('div', { class: 'alert mb' }, 'Изменять глобальные настройки может только администратор.') : null,
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, tabBar, form)));
  draw();
  const before = (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', before);
  return () => window.removeEventListener('beforeunload', before);
}
