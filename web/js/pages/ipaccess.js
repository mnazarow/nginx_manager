// Раздел сайта «Доступ по IP»: свой адрес, добавление списком, проверка адреса по черновику настроек.
import { api } from '../api.js';
import { h, mount, icon, toast } from '../ui.js';
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
export function ipAccessTools(site, { onChange, redraw, readonly }) {
  const box = h('div', { class: 'ipa-tools mb' });
  const a = site.ip_access;
  trustedInfo().then((t) => {
    const ipIn_ = h('input', { type: 'text', placeholder: '203.0.113.10', value: t.your_ip || '', 'aria-label': 'Адрес для проверки', style: { width: '190px', flex: 'none' } });
    const out = h('span', { class: 'small' });
    const check = () => {
      const ip = ipIn_.value.trim();
      if (!parseIp(ip)) { mount(out, h('span', { class: 'bad-text' }, 'не IP-адрес')); return; }
      const e = (a.entries || []).find(x => ipIn(ip, x.address));
      const tr = a.allow_trusted && (t.entries || []).find(x => ipIn(ip, x.address));
      const by = e ? `${e.address}${e.comment ? ' (' + e.comment + ')' : ''}` : tr ? `доверенные адреса: ${tr.address}`
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
        h('span', { class: 'small muted', style: { marginLeft: 'auto' } }, 'Проверить адрес:'), ipIn_,
        h('button', { class: 'btn sm', type: 'button', onclick: check }, 'Проверить'), out));
    ipIn_.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); check(); } });
  });
  return box;
}
