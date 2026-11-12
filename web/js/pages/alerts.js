// Оповещения: правила, каналы уведомлений, история срабатываний.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, tabs, fmtDate, fmtAgo, stateBadge, fmtNum } from '../ui.js';
import { model, defaults, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { can } from '../app.js';

export async function render(root) {
  let tab = 'rules';
  const box = h('div', {});
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Оповещения'),
      h('p', {}, 'Правила проверяются каждые 10 секунд. Срабатывание — когда условие выполняется дольше заданного времени; восстановление тоже сообщается. Каналы: Telegram, Slack, Discord, e-mail, произвольный webhook.'))),
    tabs([{ id: 'rules', label: 'Правила' }, { id: 'channels', label: 'Каналы уведомлений' }, { id: 'events', label: 'История' }], tab, (t) => { tab = t; draw(); }),
    box);
  const draw = () => ({ rules, channels, events }[tab])(box);
  draw();
}

async function rules(box) {
  const [list, channels, sites] = await Promise.all([api('/alerts/rules'), api('/alerts/channels'), api('/sites')]);
  const metricLabel = Object.fromEntries(SCHEMA.models.alert_rule.find(f => f.key === 'metric').options.map(o => [o, SCHEMA.models.alert_rule.find(f => f.key === 'metric').labels[o]]));
  mount(box,
    h('div', { class: 'toolbar' }, can('operator') ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить правило') : null,
      !channels.length ? h('span', { class: 'alert warn small', style: { padding: '5px 10px' } }, 'Нет каналов уведомлений — срабатывания видны только в панели. Добавьте канал на вкладке «Каналы».') : null),
    h('div', { class: 'card' }, table([
      { title: 'Правило', render: (r) => h('div', {}, h('b', {}, r.data.name), h('div', { class: 'muted small' }, `${metricLabel[r.data.metric]} ${r.data.operator} ${r.data.threshold}` +
        (r.data.duration ? `, дольше ${r.data.duration} с` : '') + (r.data.site !== '*' ? ` · сайт ${sites.find(s => String(s.id) === r.data.site)?.name || r.data.site}` : ''))) },
      { title: 'Важность', render: (r) => badge({ info: 'инфо', warning: 'предупреждение', critical: 'критично' }[r.data.severity], r.data.severity === 'critical' ? 'bad' : r.data.severity === 'warning' ? 'warn' : 'info') },
      { title: 'Состояние', render: (r) => !r.data.enabled ? badge('выключено') : r.status.state === 'firing' ? badge('СРАБОТАЛО', 'bad') : r.status.state === 'pending' ? badge('ожидание', 'warn') : badge('норма', 'good') },
      { title: 'Текущее значение', num: true, render: (r) => r.status.value == null ? '—' : fmtNum(r.status.value, 2) },
      { title: 'Каналы', render: (r) => r.data.channels.length ? r.data.channels.map(id => h('span', { class: 'tag' }, channels.find(c => c.id === id)?.data.name || '#' + id)) : h('span', { class: 'muted small' }, 'только панель') },
      { title: '', render: (r) => can('operator') ? h('button', { class: 'btn sm danger', onclick: async () => {
        if (!await confirmDlg(`Удалить правило «${r.data.name}»?`, { danger: true, ok: 'Удалить' })) return;
        await api(`/alerts/rules/${r.id}`, { method: 'DELETE' }); rules(box);
      } }, icon('trash')) : null },
    ], list, { onRow: (r) => edit(r), empty: 'Правил нет' })));

  function edit(r) {
    const obj = r ? structuredClone(r.data) : defaults(model('alert_rule'));
    let errors = {};
    const form = h('div', {});
    const draw = () => { mount(form, h('div', { class: 'alert mb small' }, 'Для долей (%) и времени ответа значение считается по окну усреднения. «Держится не менее» защищает от ложных срабатываний на всплесках.'));
      renderFields(form, model('alert_rule'), obj, { root: obj, advanced: true, errors, channels, sites, rerender: draw }); };
    draw();
    const m = modal({ title: r ? 'Правило' : 'Новое правило', size: 'lg', body: form, footer: can('operator') ? [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
      h('button', { class: 'btn primary', onclick: async () => {
        try { if (r) await api(`/alerts/rules/${r.id}`, { method: 'PUT', body: obj }); else await api('/alerts/rules', { method: 'POST', body: obj }); m.close(); rules(box); }
        catch (e) { errors = errorsToMap(e); draw(); }
      } }, 'Сохранить')] : null });
  }
}

async function channels(box) {
  const list = await api('/alerts/channels');
  const T = { telegram: 'Telegram', webhook: 'Webhook', slack: 'Slack', discord: 'Discord', email: 'E-mail' };
  mount(box,
    h('div', { class: 'toolbar' }, can('admin') ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить канал') : null),
    h('div', { class: 'card' }, table([
      { title: 'Канал', render: (c) => h('b', {}, c.data.name) }, { title: 'Тип', render: (c) => T[c.data.type] },
      { title: 'Состояние', render: (c) => c.data.enabled ? badge('включён', 'good') : badge('выключен') },
      { title: '', render: (c) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        can('operator') ? h('button', { class: 'btn sm', onclick: async () => { await api('/alerts/channels/test', { method: 'POST', body: c.data, query: { cid: c.id } }); toast('Тестовое сообщение отправлено', 'good'); } }, 'Тест') : null,
        can('admin') ? h('button', { class: 'btn sm danger', onclick: async () => { if (!await confirmDlg(`Удалить канал «${c.data.name}»?`, { danger: true, ok: 'Удалить' })) return; await api(`/alerts/channels/${c.id}`, { method: 'DELETE' }); channels(box); } }, icon('trash')) : null) },
    ], list, { onRow: (c) => edit(c), empty: 'Каналов нет' })));

  function edit(c) {
    const obj = c ? structuredClone(c.data) : defaults(model('alert_channel'));
    let errors = {};
    const form = h('div', {});
    const draw = () => { mount(form, obj.type === 'telegram' ? h('div', { class: 'alert small mb' }, '1) Создайте бота у @BotFather и скопируйте токен. 2) Напишите боту любое сообщение (или добавьте его в группу). 3) Chat ID узнайте у @userinfobot или через https://api.telegram.org/bot<токен>/getUpdates.') : null);
      renderFields(form, model('alert_channel'), obj, { root: obj, advanced: true, errors, rerender: draw }); };
    draw();
    const m = modal({ title: c ? 'Канал' : 'Новый канал', size: 'lg', body: form, footer: can('admin') ? [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
      h('button', { class: 'btn', onclick: async () => { try { await api('/alerts/channels/test', { method: 'POST', body: obj, query: { cid: c ? c.id : 0 } }); toast('Отправлено — проверьте получение', 'good'); } catch { /* */ } } }, 'Отправить тест'),
      h('button', { class: 'btn primary', onclick: async () => {
        try { if (c) await api(`/alerts/channels/${c.id}`, { method: 'PUT', body: obj }); else await api('/alerts/channels', { method: 'POST', body: obj }); m.close(); channels(box); }
        catch (e) { errors = errorsToMap(e); draw(); }
      } }, 'Сохранить')] : null });
  }
}

async function events(box) {
  const list = await api('/alerts/events', { query: { limit: 300 } });
  mount(box, h('div', { class: 'card' }, table([
    { title: 'Время', render: (e) => h('span', { class: 'nowrap small' }, fmtDate(e.ts, { sec: true })) },
    { title: 'Правило', render: (e) => h('b', {}, e.rule_name) },
    { title: 'Событие', render: (e) => stateBadge(e.state) },
    { title: 'Сообщение', render: (e) => h('div', { class: 'small', style: { whiteSpace: 'pre-wrap', maxWidth: '560px' } }, e.message) },
    { title: 'Уведомления', render: (e) => h('span', { class: 'small muted' }, e.notified || '—') },
  ], list, { empty: 'Срабатываний не было' })));
}
