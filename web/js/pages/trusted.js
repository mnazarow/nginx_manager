// Доверенные адреса: общий список IP и подсетей, которые никогда не блокируются (блокировки IP, защита от атак,
// ограничения частоты, доступ по странам и по IP на сайтах).
import { api } from '../api.js';
import { h, mount, icon, toast, card, badge, table, modal, fmtDate } from '../ui.js';
import { model, renderFields, errorsToMap } from '../forms.js';
import { can, applyDialog, refreshState } from '../app.js';

/** Разбор «по строке на адрес, комментарий после пробела или #». */
export function parseList(text) {
  return text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(l => {
    const m = l.match(/^(\S+)\s*(?:#\s*)?(.*)$/);
    return { address: m[1].replace(/[,;]$/, ''), comment: (m[2] || '').trim().slice(0, 120) };
  });
}

/** Окно «Добавить списком»: вызывает onAdd(entries). */
export function bulkDialog(onAdd) {
  const ta = h('textarea', { rows: 10, placeholder: '203.0.113.10 офис\n198.51.100.0/24 # VPN\n2001:db8::/48 мониторинг', 'aria-label': 'Адреса по строке' });
  const m = modal({ title: 'Добавить списком', body: h('div', { class: 'col' },
    h('p', { class: 'small muted' }, 'По строке на адрес или подсеть; после адреса через пробел или # — комментарий. Повторы пропускаются.'), ta),
  footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
    h('button', { class: 'btn primary', onclick: () => { const items = parseList(ta.value); if (items.length) onAdd(items); m.close(); } }, icon('plus'), 'Добавить')] });
}

function merge(list, items) {
  const have = new Set(list.map(e => e.address));
  let n = 0;
  for (const it of items) {
    if (!have.has(it.address)) { list.push(it); have.add(it.address); n++; }
  }
  return n;
}

export async function render(root) {
  const d = await api('/trusted');
  const fields = model('panel').filter(f => f.tab === 'trusted');
  const obj = { trusted_ips: d.entries };
  let errors = {};
  let dirty = false;
  const formBox = h('div', {});
  const status = h('span', {});
  const ro = !can('admin');
  const draw = () => {
    mount(formBox);
    renderFields(formBox, fields, obj, { root: obj, tab: 'trusted', advanced: true, errors,
      onChange: () => { dirty = true; mount(status, badge('есть несохранённые изменения', 'warn')); }, rerender: draw });
  };
  const save = async (apply) => {
    try {
      const r = await api('/trusted', { method: 'PUT', body: { entries: obj.trusted_ips } });
      errors = {}; dirty = false;
      mount(status, badge('сохранено', 'good'));
      toast(`Доверенных адресов: ${r.count}` + (r.unbanned ? `; снято блокировок: ${r.unbanned}` : ''), 'good');
      await refreshState();
      if (apply) applyDialog('Доверенные адреса');
      draw();
    } catch (e) { errors = errorsToMap(e); draw(); }
  };
  const addMine = () => {
    const n = merge(obj.trusted_ips, [{ address: d.your_ip, comment: 'мой адрес' }]);
    toast(n ? `Добавлен ${d.your_ip}` : `${d.your_ip} уже в списке`, n ? 'good' : 'info');
    if (n) { dirty = true; mount(status, badge('есть несохранённые изменения', 'warn')); draw(); }
  };
  const addBulk = () => bulkDialog((items) => {
    const n = merge(obj.trusted_ips, items);
    toast(`Добавлено: ${n}` + (items.length > n ? `, повторов: ${items.length - n}` : ''), 'good');
    dirty = true; mount(status, badge('есть несохранённые изменения', 'warn')); draw();
  });

  // проверка адреса
  const ipIn = h('input', { type: 'text', placeholder: '203.0.113.10', value: d.your_ip || '', 'aria-label': 'Проверить адрес' });
  const out = h('div', { class: 'mt' });
  const check = async () => {
    const ip = ipIn.value.trim();
    if (!ip) return;
    try {
      const r = await api('/trusted/check', { query: { ip } });
      mount(out, h('dl', { class: 'facts' },
        h('dt', {}, 'Доверенный'), h('dd', {}, r.trusted ? h('b', { class: 'good-text' }, `да — ${r.trusted.address}${r.trusted.comment ? ' (' + r.trusted.comment + ')' : ''}`)
          : r.always ? h('b', {}, `всегда (${r.always === '127.0.0.1' || r.always === '::1' ? 'сам сервер' : 'доступ к панели'})`) : 'нет'),
        h('dt', {}, 'Блокировка'), h('dd', {}, r.banned ? h('span', { class: 'bad-text' }, `заблокирован (${r.banned.net}): ${r.banned.reason || '—'}${r.banned.expires_at ? ', до ' + fmtDate(r.banned.expires_at) : ', бессрочно'}`) : 'нет'),
        r.sites.length ? [h('dt', {}, 'Сайты с доступом по IP'), h('dd', {}, r.sites.map(s => h('div', {}, `${s.name}: `, s.allowed ? h('span', { class: 'good-text' }, `открыт (${s.by})`) : h('span', { class: 'bad-text' }, 'закрыт'))))] : null));
    } catch (e) { mount(out, h('div', { class: 'alert bad' }, e.data?.detail || e.message)); }
  };

  mount(root,
    h('div', { class: 'page-head' },
      h('div', {}, h('h1', {}, 'Доверенные адреса'),
        h('p', {}, 'IP-адреса и подсети, которые никогда не блокируются: ни вручную, ни автоматически, ни защитой от атак (фильтр запросов, проверка браузера, списки угроз, свои правила), ни ограничениями частоты и доступом по странам. Ваши офисы, VPN, мониторинг, платёжные шлюзы, партнёры.')),
      h('div', { class: 'row' }, status,
        ro ? null : h('button', { class: 'btn', onclick: () => save(false) }, 'Сохранить'),
        ro ? null : h('button', { class: 'btn primary', onclick: () => save(true) }, icon('check'), 'Сохранить и применить'))),
    h('div', { class: 'grid split' },
      card('Список', h('div', {},
        ro ? null : h('div', { class: 'row mb' },
          h('button', { class: 'btn sm', onclick: addMine, disabled: !d.your_ip }, icon('plus'), `Добавить мой адрес${d.your_ip ? ' (' + d.your_ip + ')' : ''}`),
          h('button', { class: 'btn sm', onclick: addBulk }, icon('list'), 'Добавить списком')),
        formBox,
        h('div', { class: 'alert warn mt small' }, 'Доверенный адрес обходит всю защиту. Не добавляйте сети провайдеров и облаков целиком (/8, /16): атака с соседней машины пройдёт без проверок.')),
      { sub: 'изменения действуют после применения конфигурации' }),
      h('div', {},
        card('Проверить адрес', h('div', {},
          h('div', { class: 'row' }, ipIn, h('button', { class: 'btn', onclick: check }, 'Проверить')), out),
        { sub: 'доверенный ли, заблокирован ли, на каких сайтах с доступом по IP открыт' }),
        card('Всегда доверенные', table([{ title: 'Адрес', render: (x) => h('code', {}, x) },
          { title: 'Почему', render: (x) => ['127.0.0.1', '::1'].includes(x) ? 'сам сервер (проверки панели)' : 'доступ к панели только с IP' }], d.always),
        { cls: 'mt', flush: true, sub: 'не нужно добавлять в список' }))));
  draw();
  ipIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') check(); });
  const before = (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', before);
  return () => window.removeEventListener('beforeunload', before);
}
