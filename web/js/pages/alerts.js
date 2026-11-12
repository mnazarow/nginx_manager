// Оповещения: правила, каналы уведомлений, история срабатываний.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, tabs, fmtDate, fmtAgo, stateBadge, fmtNum } from '../ui.js';
import { model, defaults, renderFields, errorsToMap, SCHEMA } from '../forms.js';
import { can, refreshState } from '../app.js';

const DURS = [[30, '30 минут'], [60, '1 час'], [120, '2 часа'], [240, '4 часа'], [480, '8 часов'], [1440, '1 сутки'], [4320, '3 суток']];
const fmtT = (ts) => new Date(ts * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

export async function render(root) {
  let tab = 'rules';
  const box = h('div', {});
  const silBox = h('div', {});
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Оповещения'),
      h('p', {}, 'Правила проверяются каждые 10 секунд. Срабатывание — когда условие выполняется дольше заданного времени; восстановление тоже сообщается. Каналы: Telegram, Slack, Discord, e-mail, произвольный webhook.')),
      can('operator') ? h('button', { class: 'btn', onclick: () => silenceDialog(loadSil) }, icon('bell'), 'Тишина…') : null),
    silBox,
    tabs([{ id: 'rules', label: 'Правила' }, { id: 'channels', label: 'Каналы уведомлений' }, { id: 'silences', label: 'Тишина' }, { id: 'events', label: 'История' }], tab, (t) => { tab = t; draw(); }),
    box);
  const draw = () => ({ rules, channels, events, silences: (b) => silences(b, loadSil) }[tab])(box);
  async function loadSil() {
    const list = await api('/alerts/silences');
    const active = list.filter(s => s.state === 'active');
    mount(silBox, active.map(s => h('div', { class: 'alert warn mb row', style: { justifyContent: 'space-between' } },
      h('div', {}, h('b', {}, `Тишина до ${fmtT(s.ends_at)}`), ` — ${s.rule_ids.length ? `правил: ${s.rule_ids.length}` : 'все правила'}`,
        s.reason ? ` · ${s.reason}` : '', h('div', { class: 'small' }, `Срабатывания записываются в историю, но уведомления не отправляются. Не отправлено: ${s.suppressed}.`)),
      can('operator') ? h('button', { class: 'btn sm', onclick: async () => { await api(`/alerts/silences/${s.id}`, { method: 'DELETE' }); toast('Тишина завершена', 'good'); refreshState(); loadSil(); if (tab === 'silences') draw(); } }, 'Завершить') : null)));
  }
  loadSil();
  draw();
}

/** Диалог «Тишина»: не отправлять уведомления на время плановых работ (сейчас или по расписанию). */
export async function silenceDialog(onDone) {
  const rulesList = await api('/alerts/rules');
  const dur = h('select', {}, DURS.map(([v, l]) => h('option', { value: v, selected: v === 60 }, l)), h('option', { value: 'custom' }, 'Свой срок…'));
  const custom = h('input', { type: 'number', min: 5, value: 90, style: { display: 'none', width: '120px' } });
  dur.addEventListener('change', () => { custom.style.display = dur.value === 'custom' ? '' : 'none'; });
  const when = h('select', {}, h('option', { value: 'now' }, 'Сейчас'), h('option', { value: 'at' }, 'Запланировать…'));
  const at = h('input', { type: 'datetime-local', style: { display: 'none' } });
  when.addEventListener('change', () => { at.style.display = when.value === 'at' ? '' : 'none'; });
  const scopeAll = h('input', { type: 'radio', name: 'scope', checked: true });
  const scopeSel = h('input', { type: 'radio', name: 'scope' });
  const boxes = rulesList.map(r => ({ id: r.id, el: h('input', { type: 'checkbox' }), name: r.data.name }));
  const ruleBox = h('div', { class: 'col', style: { display: 'none', maxHeight: '180px', overflow: 'auto', paddingLeft: '22px' } },
    boxes.map(b => h('label', { class: 'row small' }, b.el, b.name)));
  scopeAll.addEventListener('change', () => { ruleBox.style.display = 'none'; });
  scopeSel.addEventListener('change', () => { ruleBox.style.display = ''; });
  const reason = h('input', { type: 'text', placeholder: 'Например: обновление базы данных' });
  const err = h('div', {});
  const m = modal({
    title: 'Тишина оповещений', size: 'md',
    body: h('div', { class: 'col' },
      h('p', { class: 'muted small', style: { margin: 0 } }, 'На время работ уведомления в каналы не отправляются. Срабатывания всё равно видны в панели и записываются в историю — после окончания тишины вы увидите, что происходило.'),
      h('div', { class: 'grid g2' },
        h('div', { class: 'field' }, h('label', {}, 'Начало'), when, at),
        h('div', { class: 'field' }, h('label', {}, 'Длительность'), h('div', { class: 'row' }, dur, custom, h('span', { class: 'muted small', style: { display: 'none' } }, 'мин')))),
      h('div', { class: 'field' }, h('label', {}, 'Для каких правил'),
        h('label', { class: 'row small' }, scopeAll, 'Все правила'), h('label', { class: 'row small' }, scopeSel, 'Только выбранные'), ruleBox),
      h('div', { class: 'field' }, h('label', {}, 'Причина'), reason), err),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
      const minutes = dur.value === 'custom' ? Number(custom.value) : Number(dur.value);
      const starts_at = when.value === 'at' && at.value ? new Date(at.value).getTime() / 1000 : null;
      const rule_ids = scopeSel.checked ? boxes.filter(b => b.el.checked).map(b => b.id) : [];
      if (scopeSel.checked && !rule_ids.length) { mount(err, h('div', { class: 'alert bad' }, 'Выберите хотя бы одно правило')); return; }
      try {
        await api('/alerts/silences', { method: 'POST', silent: true, body: { minutes, starts_at, rule_ids, reason: reason.value } });
        m.close(); toast(starts_at ? 'Тишина запланирована' : 'Тишина включена', 'good'); refreshState(); onDone && onDone();
      } catch (e) { mount(err, h('div', { class: 'alert bad' }, e.data?.detail || e.message)); }
    } }, 'Включить тишину')],
  });
}

async function silences(box, reload) {
  const list = await api('/alerts/silences');
  const ST = { active: ['действует', 'warn'], planned: ['запланирована', 'info'], ended: ['завершена', ''] };
  mount(box, h('div', { class: 'card' }, table([
    { title: 'Период', render: (s) => h('span', { class: 'nowrap' }, `${fmtT(s.starts_at)} — ${fmtT(s.ends_at)}`) },
    { title: 'Состояние', render: (s) => badge(...ST[s.state]) },
    { title: 'Правила', render: (s) => s.rule_ids.length ? `выбранные (${s.rule_ids.length})` : 'все' },
    { title: 'Причина', render: (s) => s.reason || h('span', { class: 'muted' }, '—') },
    { title: 'Кто', render: (s) => s.username },
    { title: 'Не отправлено', num: true, render: (s) => String(s.suppressed) },
    { title: '', render: (s) => can('operator') && s.state !== 'ended' ? h('button', { class: 'btn sm', onclick: async () => {
      await api(`/alerts/silences/${s.id}`, { method: 'DELETE' }); refreshState(); reload && reload(); silences(box, reload);
    } }, s.state === 'planned' ? 'Отменить' : 'Завершить') : null },
  ], list, { empty: 'Периодов тишины не было. Кнопка «Тишина…» вверху страницы отключает уведомления на время плановых работ.' })));
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
