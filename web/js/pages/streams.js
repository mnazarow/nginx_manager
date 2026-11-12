// TCP/UDP-потоки (модуль stream): проксирование баз данных, почты, игровых серверов и т.п.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, empty, codeBlock, debounce } from '../ui.js';
import { model, defaults, renderFields, errorsToMap } from '../forms.js';
import { ctx, can, refreshState, applyDialog } from '../app.js';

export async function render(root) {
  const list = await api('/streams');
  const caps = ctx.state.caps || {};
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'TCP/UDP-потоки'),
      h('p', {}, 'Проксирование произвольных TCP/UDP-сервисов на уровне L4 (PostgreSQL, MySQL, Redis, SMTP, DNS, игровые серверы). Внешний порт сервера → один или несколько внутренних серверов с балансировкой.')),
      can('operator') ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить поток') : null),
    !caps.stream ? h('div', { class: 'alert warn mb' }, 'Модуль stream недоступен в установленном nginx. Установите libnginx-mod-stream (Debian/Ubuntu) или nginx-mod-stream (RHEL) — кнопка есть в «Диагностике».') : null,
    h('div', { class: 'card' }, list.length ? table([
      { title: 'Название', render: (s) => h('b', {}, s.name) },
      { title: 'Порт', render: (s) => h('code', {}, `${s.data.listen_ip ? s.data.listen_ip + ':' : ''}${s.data.listen_port}/${s.data.protocol === 'both' ? 'tcp+udp' : s.data.protocol}`) },
      { title: 'Серверы', render: (s) => h('div', { class: 'col', style: { gap: '2px' } }, s.data.backends.map(b => {
        const hh = s.health.find(x => x.addr === `${b.address}:${b.port}`);
        return h('div', { class: 'row nowrap small' }, h('span', { class: 'dot ' + (hh?.state === 'up' ? 'good' : hh?.state === 'down' ? 'bad' : '') }), h('code', {}, `${b.address}:${b.port}`));
      })) },
      { title: 'Балансировка', render: (s) => s.data.balancing },
      { title: 'Состояние', render: (s) => s.enabled ? badge('включён', 'good') : badge('выключен') },
      { title: '', render: (s) => can('operator') ? h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end' } },
        h('button', { class: 'btn sm danger', onclick: async () => {
          if (!await confirmDlg(`Удалить поток «${s.name}»?`, { danger: true, ok: 'Удалить' })) return;
          await api(`/streams/${s.id}`, { method: 'DELETE' }); refreshState(); render(root);
        } }, icon('trash'))) : null },
    ], list, { onRow: (s) => edit(s) }) : empty('Потоков нет', 'Например: внешний порт 5432 → PostgreSQL на 10.0.0.10:5432 с белым списком IP.', null, 'stream')));

  function edit(s) {
    const obj = s ? structuredClone(s.data) : { ...defaults(model('stream')), backends: [{ ...defaults(model('backend')), address: '10.0.0.10', port: 5432 }] };
    let errors = {};
    let adv = false;
    const form = h('div', {});
    const prev = h('div', {});
    const preview = debounce(async () => {
      try { const r = await api('/streams/preview', { method: 'POST', body: obj, query: { sid: s ? s.id : 0 }, silent: true }); errors = {}; mount(prev, codeBlock(r.config)); }
      catch (e) { errors = errorsToMap(e); mount(prev, h('div', { class: 'alert bad' }, e.message)); }
    }, 400);
    const draw = () => { mount(form, h('label', { class: 'switch small mb' }, h('input', { type: 'checkbox', checked: adv, onchange: (e) => { adv = e.target.checked; draw(); } }), h('span', { class: 'track' }), 'Расширенные параметры'));
      renderFields(form, model('stream'), obj, { root: obj, advanced: adv, errors, rerender: draw, onChange: preview }); };
    draw(); preview();
    const save = async (apply) => {
      try {
        if (s) await api(`/streams/${s.id}`, { method: 'PUT', body: obj }); else await api('/streams', { method: 'POST', body: obj });
        m.close(); refreshState(); toast('Сохранено', 'good');
        if (apply) applyDialog(`Поток «${obj.name}»`);
        render(root);
      } catch (e) { errors = errorsToMap(e); draw(); }
    };
    const m = modal({ title: s ? `Поток: ${s.name}` : 'Новый поток', size: 'xl',
      body: h('div', { class: 'grid split' }, form, h('div', {}, h('h3', { class: 'mb' }, 'Конфигурация'), prev)),
      footer: can('operator') ? [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn', onclick: () => save(false) }, 'Сохранить'),
        h('button', { class: 'btn primary', onclick: () => save(true) }, 'Сохранить и применить')] : null });
  }
}
