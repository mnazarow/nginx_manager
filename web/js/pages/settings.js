// Настройки самой панели.
import { api } from '../api.js';
import { h, mount, icon, toast, tabs, badge } from '../ui.js';
import { model, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { applyDialog } from '../app.js';

export async function render(root, c) {
  const [obj, certs] = await Promise.all([api('/settings/panel'), api('/certs')]);
  let tab = (c && c.params && c.params.tab) || 'stats', errors = {};
  const form = h('div', {});
  const tabBar = h('div', {});
  const draw = () => {
    mount(tabBar, tabs(SCHEMA.tabs.panel, tab, (t) => { tab = t; draw(); }));
    mount(form);
    renderFields(form, model('panel'), obj, { root: obj, tab, advanced: true, errors, certs: certs.items, rerender: draw });
    if (tab === 'network') form.appendChild(h('div', { class: 'alert mt' }, 'Домен панели: nginx будет проксировать его на панель (с WebSocket). Выпустите для него сертификат на странице «Сертификаты», выберите его здесь и примените конфигурацию. После этого порт панели можно закрыть в firewall, а в /etc/nginx-manager/panel.conf указать BIND_HOST=127.0.0.1.'));
    if (tab === 'security') form.appendChild(h('div', { class: 'alert warn mt' }, 'Если вы потеряете доступ из-за списка IP — выполните на сервере: ', h('code', {}, 'nmctl allowlist clear'), '.'));
  };
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Настройки панели'), h('p', {}, 'Хранение статистики, сеть, безопасность доступа, Let\'s Encrypt, мониторинг и резервное копирование.')),
      h('button', { class: 'btn primary', onclick: async () => {
        try {
          const r = await api('/settings/panel', { method: 'PUT', body: obj }); errors = {}; draw();
          toast('Настройки сохранены', 'good');
          if (r.needs_apply) applyDialog('Изменены сетевые настройки панели');
        } catch (e) { errors = errorsToMap(e); draw(); }
      } }, icon('check'), 'Сохранить')),
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, tabBar, form)));
  draw();
}
