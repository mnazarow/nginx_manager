// Раздел сайта «Доступ по IP»: свой адрес, добавление списком, проверка адреса по черновику настроек.
import { api } from '../api.js';
import { h, mount, icon, toast, card, table, modal, segmented, fmtInt, fmtAgo, fmtDate, countryName, copyBtn, confirmDlg, qrBlock } from '../ui.js';
import { timeChart, setData, seriesColor } from '../charts.js';
import { expiresSelect } from '../forms.js';
import { bulkDialog } from './trusted.js';

const PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7'];
const LOOPBACK = ['127.0.0.1', '::1'];

/** Адрес → [версия, BigInt] или null. */
function parseIp(s) {
  s = (s || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const p = s.split('.').map(Number);
    if (p.some(x => x > 255)) return null;
    return [4, p.reduce((a, x) => (a << 8n) + BigInt(x), 0n)];
  }
  if (!s.includes(':') || !/^[0-9a-f:]+$/i.test(s)) return null;
  const [l, r = null] = s.split('::');
  if (s.split('::').length > 2) return null;
  const L = l ? l.split(':') : [], R = r ? r.split(':') : [];
  const fill = r === null ? 0 : 8 - L.length - R.length;
  if (fill < 0 || (r === null && L.length !== 8)) return null;
  const parts = [...L, ...Array(fill).fill('0'), ...R];
  if (parts.some(x => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
  return [6, parts.reduce((a, x) => (a << 16n) + BigInt(parseInt(x, 16)), 0n)];
}

/** Входит ли адрес в адрес или подсеть. */
export function ipIn(ip, net) {
  const [base, len] = net.split('/');
  const a = parseIp(ip), b = parseIp(base);
  if (!a || !b || a[0] !== b[0]) return false;
  const bits = a[0] === 4 ? 32 : 128;
  const n = len === undefined ? bits : Number(len);
  const shift = BigInt(bits - n);
  return (a[1] >> shift) === (b[1] >> shift);
}

let cache = null;
async function trustedInfo() {
  if (!cache) cache = api('/trusted', { silent: true }).catch(() => ({ entries: [], your_ip: '' }));
  return cache;
}

/** Панель над полями раздела: добавить свой адрес, списком, проверить адрес. */
export function ipAccessTools(site, { onChange, redraw, readonly, sid, onLink }) {
  const box = h('div', { class: 'ipa-tools mb' });
  const a = site.ip_access;
  trustedInfo().then((t) => {
    const ipIn_ = h('input', { type: 'text', placeholder: '203.0.113.10', value: t.your_ip || '', 'aria-label': 'Адрес для проверки', style: { width: '190px', flex: 'none' } });
    const out = h('span', { class: 'small' });
    const check = () => {
      const ip = ipIn_.value.trim();
      if (!parseIp(ip)) { mount(out, h('span', { class: 'bad-text' }, 'не IP-адрес')); return; }
      const now = Date.now() / 1000;
      const live = (x) => !x.expires || x.expires > now;
      const e = (a.entries || []).find(x => live(x) && ipIn(ip, x.address));
      const tr = a.allow_trusted && [...(t.entries || []), ...(t.received || []).flatMap(r => r.entries)].find(x => live(x) && ipIn(ip, x.address));
      const by = e ? `${e.address}${e.comment ? ' (' + e.comment + ')' : ''}${e.expires ? ', временно' : ''}` : tr ? `доверенные адреса: ${tr.address}`
        : a.allow_private && PRIVATE.some(n => ipIn(ip, n)) ? 'локальные сети' : LOOPBACK.some(n => ipIn(ip, n)) ? 'сам сервер' : '';
      mount(out, !a.enabled ? h('span', { class: 'muted' }, 'ограничение выключено — сайт открыт всем')
        : by ? h('span', { class: 'good-text' }, `пускается: ${by}`) : h('span', { class: 'bad-text' }, 'не пускается'));
    };
    const add = (items) => {
      a.entries = a.entries || [];
      const have = new Set(a.entries.map(x => x.address));
      let n = 0;
      for (const it of items) if (!have.has(it.address)) { a.entries.push(it); have.add(it.address); n++; }
      toast(n ? `Добавлено: ${n}` : 'Эти адреса уже в списке', n ? 'good' : 'info');
      if (n) { onChange(); redraw(); }
    };
    const mine = t.your_ip;
    const mineIn = mine && ((a.entries || []).some(x => ipIn(mine, x.address)) || LOOPBACK.some(n => ipIn(mine, n))
      || (a.allow_private && PRIVATE.some(n => ipIn(mine, n))));
    mount(box,
      a.enabled && mine && !mineIn && !(a.allow_trusted && (t.entries || []).some(x => ipIn(mine, x.address)))
        ? h('div', { class: 'alert warn small mb' }, `Вашего адреса (${mine}) нет в списке — после применения сайт откроется вам, только если вы входите в другой разрешённый адрес.`) : null,
      h('div', { class: 'row', style: { gap: '8px', flexWrap: 'wrap', alignItems: 'center' } },
        readonly ? null : h('button', { class: 'btn sm', type: 'button', disabled: !mine, onclick: () => add([{ address: mine, comment: 'мой адрес' }]) }, icon('plus'), `Добавить мой адрес${mine ? ' (' + mine + ')' : ''}`),
        readonly ? null : h('button', { class: 'btn sm', type: 'button', onclick: () => bulkDialog(add) }, icon('list'), 'Добавить списком'),
        readonly ? null : h('button', { class: 'btn sm', type: 'button', onclick: () => tempDialog(mine, add) }, icon('history'), 'Временный доступ…'),
        readonly || !sid ? null : h('button', { class: 'btn sm', type: 'button', title: 'Ссылка, по которой посетитель сам откроет доступ для своего адреса', onclick: () => linkDialog(sid, a, onLink) }, icon('copy'), 'Ссылка для доступа…'),
        h('span', { class: 'small muted', style: { marginLeft: 'auto' } }, 'Проверить адрес:'), ipIn_,
        h('button', { class: 'btn sm', type: 'button', onclick: check }, 'Проверить'), out));
    ipIn_.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); check(); } });
  });
  return box;
}

/** Окно «Временный доступ»: адрес на N часов (запись удалится сама, конфигурация переприменится). */
export function tempDialog(ip, onAdd) {
  const item = { expires: Math.round(Date.now() / 1000 + 8 * 3600) };
  const addr = h('input', { id: 'nm-temp-addr', type: 'text', value: ip || '', placeholder: '203.0.113.10', 'aria-label': 'Адрес или подсеть' });
  const comment = h('input', { id: 'nm-temp-cmt', type: 'text', value: '', placeholder: 'Подрядчик, проверка, демонстрация', maxlength: 120, 'aria-label': 'Комментарий' });
  const sel = expiresSelect(item, 'expires', 'Срок', () => {});
  sel.id = 'nm-temp-exp';
  const m = modal({ title: 'Временный доступ', body: h('div', { class: 'col' },
    h('p', { class: 'small muted' }, 'Адрес попадёт в список с отметкой срока. Когда срок выйдет, панель уберёт его из списка и переприменит конфигурацию сама — без вашего участия. Не забудьте сохранить и применить изменения сайта.'),
    h('div', { class: 'field' }, h('label', { for: 'nm-temp-addr' }, 'IP-адрес или подсеть'), addr),
    h('div', { class: 'field' }, h('label', { for: 'nm-temp-exp' }, 'На какой срок'), sel),
    h('div', { class: 'field' }, h('label', { for: 'nm-temp-cmt' }, 'Комментарий'), comment)),
  footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'),
    h('button', { class: 'btn primary', onclick: () => {
      const a = addr.value.trim();
      if (!parseIp(a.split('/')[0])) { toast('Укажите IP-адрес или подсеть', 'bad'); return; }
      onAdd([{ address: a, comment: comment.value.trim().slice(0, 120), expires: item.expires }]);
      m.close();
    } }, icon('plus'), 'Добавить')] });
}

let denialsChart = null;

/** Журнал отказов «Доступа по IP»: график по времени и самые частые адреса (кнопка «Разрешить» добавляет адрес). */
export function ipDenialsCard(sid, site, { onChange, redraw, readonly }) {
  let hours = 24;
  const canvas = h('canvas', { role: 'img', 'aria-label': 'Отказы по времени' });
  const chartBox = h('div', { class: 'chart-box', style: { height: '170px' } }, canvas);
  const sum = h('div', { class: 'small muted mb' });
  const list = h('div', {});
  if (denialsChart) { try { denialsChart.destroy(); } catch { /* */ } denialsChart = null; }
  const allow = (ip, temp) => {
    const a = site.ip_access;
    a.entries = a.entries || [];
    if (a.entries.some(x => x.address === ip)) { toast(`${ip} уже в списке`, 'info'); return; }
    a.entries.push({ address: ip, comment: temp ? 'временно (из журнала отказов)' : 'из журнала отказов', expires: temp ? Math.round(Date.now() / 1000 + 8 * 3600) : null });
    toast(`${ip} добавлен${temp ? ' на 8 часов' : ''} — сохраните и примените сайт`, 'good');
    onChange(); redraw();
  };
  const load = async () => {
    let d;
    try { d = await api(`/sites/${sid}/ip-denials`, { query: { hours }, silent: true }); } catch { mount(list, h('div', { class: 'empty' }, 'Нет данных')); return; }
    const step = d.step;
    const fmtX = (ts) => { const t = new Date(ts * 1000); return step >= 86400 ? `${t.getDate()}.${String(t.getMonth() + 1).padStart(2, '0')}` : `${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`; };
    if (!denialsChart) {
      denialsChart = timeChart(canvas, [{ key: 'n', label: 'отказов', color: seriesColor(0) }], { type: 'bar', xFmt: fmtX, yFmt: (v) => fmtInt(v),
        tipTitle: (ts) => step >= 86400 ? fmtDate(ts).split(' ')[0] : `${fmtDate(ts)} — ${fmtDate(ts + step).split(' ').pop()}` });
    } else {
      denialsChart.options.scales.x.ticks.callback = function (v) { return fmtX(+this.getLabelForValue(v)); };
    }
    setData(denialsChart, d.series.map(x => x[0]), [d.series.map(x => x[1])]);
    mount(sum, d.total ? `${fmtInt(d.total)} отказов с ${fmtInt(d.ips)} адресов за ${hours < 48 ? hours + ' ч' : Math.round(hours / 24) + ' дн.'}; интервал столбца — ${step >= 86400 ? 'сутки' : step >= 3600 ? 'час' : '5 минут'}`
      : 'Отказов не было. С паролем (вместо отказа) учитываются запросы без входа.');
    mount(list, table([
      { title: 'Адрес', render: (r) => h('div', {}, h('code', {}, r.ip), h('div', { class: 'small muted' },
        [r.country && r.country !== '--' ? countryName(r.country) : '', r.trusted ? 'доверенный' : ''].filter(Boolean).join(' · ') || '—')) },
      { title: 'Отказов', num: true, render: (r) => fmtInt(r.n) },
      { title: 'Последний путь', render: (r) => h('code', { class: 'small', title: r.uri, style: { wordBreak: 'break-all' } }, r.uri.length > 40 ? r.uri.slice(0, 39) + '…' : r.uri) },
      { title: 'Когда', render: (r) => h('span', { class: 'small', title: fmtDate(r.last), style: { whiteSpace: 'nowrap' } }, fmtAgo(r.last)) },
      { title: '', srTitle: 'Действия', render: (r) => readonly ? null : h('div', { class: 'row', style: { gap: '4px', flexWrap: 'nowrap', justifyContent: 'flex-end' } },
        h('button', { class: 'btn sm', type: 'button', title: 'Добавить адрес в список разрешённых', onclick: () => allow(r.ip, false) }, 'Разрешить'),
        h('button', { class: 'btn sm ghost', type: 'button', title: 'Добавить адрес в список на 8 часов', 'aria-label': `8 ч: разрешить ${r.ip} на 8 часов`, onclick: () => allow(r.ip, true) }, '8 ч')) },
    ], d.top, { empty: 'Отказов не было' }));
  };
  const seg = segmented([[6, '6 ч'], [24, '24 ч'], [168, '7 дн.'], [720, '30 дн.']], hours,
    (v) => { hours = v; if (denialsChart) { denialsChart.destroy(); denialsChart = null; } load(); });
  load();
  return card('Журнал отказов', h('div', {}, sum, chartBox, h('div', { class: 'mt' }, list)),
    { cls: 'mt', sub: 'кто стучался на сайт с неразрешённых адресов (по журналу доступа nginx; хранится столько же, сколько журнал атак)', actions: seg });
}

const OPT = (pairs, val) => pairs.map(([v, t]) => h('option', { value: v, selected: v === val }, t));

/** Окно «Ссылка для доступа»: посетитель откроет её и сам добавит свой адрес на заданный срок. */
export function linkDialog(sid, access, onDone) {
  if (!access.enabled) { toast('Сначала включите «Доступ только с разрешённых адресов», сохраните и примените сайт', 'bad'); return; }
  const hours = h('select', { id: 'nm-link-hours' }, OPT([[1, '1 час'], [4, '4 часа'], [8, '8 часов'], [24, 'сутки'], [72, '3 дня'], [168, 'неделю']], 8));
  const valid = h('select', { id: 'nm-link-valid' }, OPT([[1, '1 час'], [24, 'сутки'], [72, '3 дня'], [168, 'неделю'], [720, '30 дней']], 24));
  const uses = h('select', { id: 'nm-link-uses' }, OPT([[1, 'один раз'], [3, '3 раза'], [10, '10 раз'], [50, '50 раз']], 1));
  const comment = h('input', { id: 'nm-link-cmt', type: 'text', maxlength: 120, placeholder: 'Кому: подрядчик, клиент, сотрудник в командировке' });
  const out = h('div', {});
  const btn = h('button', { class: 'btn primary', onclick: async () => {
    btn.disabled = true;
    try {
      const r = await api(`/sites/${sid}/access-links`, { method: 'POST', body: { hours: +hours.value, valid_hours: +valid.value, uses: +uses.value, comment: comment.value.trim() } });
      let qr = null;
      try { qr = qrBlock(r.url, 4, 'QR-код ссылки'); qr.style.alignSelf = 'flex-start'; } catch { /* без QR */ }
      mount(out, h('div', { class: 'alert good mt col' },
        h('b', {}, 'Ссылка создана — отправьте её получателю. Повторно её показать нельзя (в панели хранится только отпечаток).'),
        h('div', { class: 'row nowrap' }, h('input', { type: 'text', value: r.url, readOnly: true, class: 'code', 'aria-label': 'Ссылка' }), copyBtn(r.url, 'Копировать')),
        qr));
      btn.style.display = 'none';
      if (onDone) onDone();
    } catch (e) { toast(e.data?.detail || e.message, 'bad'); btn.disabled = false; }
  } }, icon('plus'), 'Создать ссылку');
  const m = modal({ title: 'Ссылка для доступа', body: h('div', { class: 'col' },
    h('p', { class: 'small muted' }, 'Получатель откроет ссылку, увидит свой IP-адрес и нажмёт «Открыть доступ» — адрес будет пускаться на выбранный срок без применения конфигурации. Программы предпросмотра ссылок в мессенджерах доступ не «съедят»: он выдаётся только по кнопке.'),
    h('div', { class: 'grid g3' },
      h('div', { class: 'field' }, h('label', { for: 'nm-link-hours' }, 'Доступ на'), hours),
      h('div', { class: 'field' }, h('label', { for: 'nm-link-valid' }, 'Ссылка действует'), valid),
      h('div', { class: 'field' }, h('label', { for: 'nm-link-uses' }, 'Воспользоваться можно'), uses)),
    h('div', { class: 'field' }, h('label', { for: 'nm-link-cmt' }, 'Комментарий'), comment),
    out),
  footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Закрыть'), btn] });
}

const HRS = (x) => x < 1 ? `${Math.round(x * 60)} мин` : x < 48 ? `${x} ч` : `${Math.round(x / 24)} дн.`;

/** Карточка «Ссылки для доступа»: действующие ссылки и адреса, которым доступ выдан по ссылке. */
export function linksCard(sid, { readonly }) {
  const box = h('div', {});
  const el = card('Ссылки для доступа', box, { cls: 'mt', sub: 'посетитель сам открывает доступ для своего адреса; действует сразу, без применения конфигурации' });
  const load = async () => {
    let d;
    try { d = await api(`/sites/${sid}/access-links`, { silent: true }); } catch { mount(box, h('div', { class: 'empty' }, 'Нет данных')); return; }
    const del = async (l) => {
      if (!await confirmDlg(`Отозвать ссылку${l.comment ? ' «' + l.comment + '»' : ''}? Доступ, уже открытый по ней, останется до своего срока.`, { ok: 'Отозвать', danger: true })) return;
      await api(`/sites/${sid}/access-links/${l.id}`, { method: 'DELETE' }); load();
    };
    const revoke = async (g) => {
      if (!await confirmDlg(`Закрыть доступ для ${g.ip} сейчас?`, { ok: 'Закрыть доступ', danger: true })) return;
      const r = await api(`/sites/${sid}/access-grants/${g.id}`, { method: 'DELETE' });
      toast(r.ok ? `Доступ для ${g.ip} закрыт` : 'nginx не перечитал файл доступа', r.ok ? 'good' : 'bad'); load();
    };
    const links = d.links.filter(l => l.state === 'ok');
    mount(box,
      h('h3', { class: 'sub-h', style: { margin: '0 0 6px' } }, `Открыт доступ (${d.grants.length})`),
      table([
        { title: 'Адрес', render: (g) => h('div', {}, h('code', {}, g.ip), g.comment ? h('div', { class: 'small muted' }, g.comment) : null) },
        { title: 'До', render: (g) => h('span', { class: 'small', style: { whiteSpace: 'nowrap' } }, fmtDate(g.expires_at)) },
        { title: 'Открыт', render: (g) => h('span', { class: 'small', title: g.ua || '', style: { whiteSpace: 'nowrap' } }, fmtAgo(g.created_at)) },
        { title: '', srTitle: 'Действия', render: (g) => readonly ? null : h('button', { class: 'btn sm', type: 'button', 'aria-label': `Закрыть доступ для ${g.ip}`, onclick: () => revoke(g) }, 'Закрыть') },
      ], d.grants, { empty: 'Пока никто не открывал доступ по ссылке' }),
      h('h3', { class: 'sub-h', style: { margin: '16px 0 6px' } }, `Действующие ссылки (${links.length})`),
      table([
        { title: 'Комментарий', render: (l) => h('span', {}, l.comment || h('span', { class: 'muted' }, '—'), h('div', { class: 'small muted' }, `создал ${l.created_by || '—'} ${fmtAgo(l.created_at)}`)) },
        { title: 'Доступ на', render: (l) => HRS(l.hours) },
        { title: 'Осталось', num: true, render: (l) => `${l.uses_left} из ${l.uses_total}` },
        { title: 'Действует до', render: (l) => h('span', { class: 'small', style: { whiteSpace: 'nowrap' } }, fmtDate(l.expires_at)) },
        { title: '', srTitle: 'Действия', render: (l) => readonly ? null : h('button', { class: 'btn sm ghost', type: 'button', 'aria-label': `Отозвать ссылку ${l.comment || l.id}`, onclick: () => del(l) }, 'Отозвать') },
      ], links, { empty: 'Ссылок нет — создайте кнопкой «Ссылка для доступа…»' }),
      d.ready ? null : h('div', { class: 'alert warn mt small' }, 'Примените конфигурацию: ссылки заработают после применения.'));
  };
  el.reload = load;
  load();
  return el;
}
