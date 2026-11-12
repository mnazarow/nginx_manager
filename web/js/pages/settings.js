// Настройки самой панели.
import { api } from '../api.js';
import { h, mount, icon, toast, tabs, modal, loading } from '../ui.js';
import { model, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { applyDialog } from '../app.js';

export async function render(root, c) {
  const [obj, certs, channels] = await Promise.all([api('/settings/panel'), api('/certs'), api('/alerts/channels').catch(() => [])]);
  let tab = (c && c.params && c.params.tab) || 'stats', errors = {};
  const form = h('div', {});
  const tabBar = h('div', {});
  const draw = () => {
    mount(tabBar, tabs(SCHEMA.tabs.panel, tab, (t) => { tab = t; draw(); }));
    mount(form);
    renderFields(form, model('panel'), obj, { root: obj, tab, advanced: true, errors, certs: certs.items, channels, rerender: draw });
    if (tab === 'network') form.appendChild(h('div', { class: 'alert mt' }, 'Домен панели: nginx будет проксировать его на панель (с WebSocket). Выпустите для него сертификат на странице «Сертификаты», выберите его здесь и примените конфигурацию. После этого порт панели можно закрыть в firewall, а в /etc/nginx-manager/panel.conf указать BIND_HOST=127.0.0.1.'));
    if (tab === 'reports') form.appendChild(h('div', { class: 'row mt', style: { flexWrap: 'wrap' } },
      h('button', { class: 'btn', onclick: () => previewReport(obj.report_period) }, icon('eye'), 'Предпросмотр отчёта'),
      h('button', { class: 'btn', onclick: async () => {
        const r = await api('/reports/send', { method: 'POST', body: { period: obj.report_period, channels: obj.report_channels } });
        const bad = r.results.filter(x => !x.ok);
        toast(bad.length ? `Ошибки: ${bad.map(x => `${x.name || x.id}: ${x.error}`).join('; ')}` : `«${r.title}» отправлен (${r.results.length})`, bad.length ? 'bad' : 'good');
      } }, icon('bell'), 'Отправить сейчас'),
      h('span', { class: 'muted small' }, 'Сначала сохраните настройки, если меняли каналы.')));
    if (tab === 'events') form.prepend(h('div', { class: 'alert mb' }, 'Каждое событие из журнала «События» выбранных источников и уровня приходит отдельным сообщением: сбой продления сертификата, ошибка применения конфигурации, перезапуск nginx сторожем, блокировка входа, вход администратора с нового адреса, сбой фоновой задачи. В отличие от правил оповещений здесь нет порогов — это сообщения о том, что уже произошло. Глобальная «тишина» на время работ глушит и их.'));
    if (tab === 'events') form.appendChild(h('div', { class: 'row mt' },
      h('button', { class: 'btn', onclick: async () => {
        const r = await api('/events/notify-test', { method: 'POST' });
        const bad = r.results.filter(x => !x.ok);
        toast(bad.length ? `Ошибки: ${bad.map(x => `${x.name || x.id}: ${x.error}`).join('; ')}` : `Проверочное уведомление отправлено (${r.results.length})`, bad.length ? 'bad' : 'good');
      } }, icon('bell'), 'Отправить проверочное'),
      h('span', { class: 'muted small' }, 'Сначала сохраните настройки, если меняли каналы.')));
    if (tab === 'security') form.appendChild(h('div', { class: 'alert warn mt' }, 'Если вы потеряете доступ из-за списка IP — выполните на сервере: ', h('code', {}, 'nmctl allowlist clear'), '.'));
  };
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Настройки панели'), h('p', {}, 'Хранение статистики, сеть, безопасность доступа, сертификаты (ACME), мониторинг, отчёты, уведомления о событиях и резервное копирование.')),
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

async function previewReport(period) {
  const body = h('div', {}, loading('Формирование отчёта…'));
  modal({ title: 'Предпросмотр отчёта', size: 'lg', body });
  const r = await api('/reports/preview', { query: { period } });
  mount(body, h('h3', { style: { marginTop: 0 } }, r.title), h('pre', { class: 'code', style: { whiteSpace: 'pre-wrap' } }, r.text));
}
