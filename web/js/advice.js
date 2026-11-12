// Встроенный анализ в интерфейсе: оценка показателей с подсказками и карточки найденных проблем.
import { api } from './api.js';
import { h, mount, icon, badge, toast, popover, fmtAgo, table } from './ui.js';
import { openHelp } from './help.js';
import { can } from './app.js';

let catalog = null;
let loading = null;

export async function loadCatalog(force = false) {
  if (catalog && !force) return catalog;
  if (!loading || force) loading = api('/insights/catalog', { silent: true }).then(c => { catalog = c; return c; }).finally(() => { loading = null; });
  return loading;
}
export const LEVEL_CLASS = { ok: '', info: 'info', warn: 'warn', crit: 'bad' };
export const LEVEL_TEXT = { ok: 'норма', info: 'к сведению', warn: 'внимание', crit: 'проблема' };

/** Уровень показателя по порогам каталога (как на сервере). */
export function levelOf(id, value, req) {
  const m = catalog?.metrics?.[id];
  if (!m || value == null || isNaN(value) || !m.dir || m.warn == null) return 'ok';
  if (m.min_req && req != null && req < m.min_req) return 'ok';
  if (m.dir === 'above') return m.crit != null && value >= m.crit ? 'crit' : value >= m.warn ? 'warn' : 'ok';
  return m.crit != null && value <= m.crit ? 'crit' : value <= m.warn ? 'warn' : 'ok';
}

function fmtThr(m, v) {
  if (v == null) return '—';
  const n = Number.isInteger(v) ? v : Math.round(v * 10) / 10;
  return `${n.toLocaleString('ru-RU')}${m.unit ? ' ' + m.unit : ''}`;
}

/** Содержимое подсказки показателя. */
export function metricHint(id, value, req, valueText) {
  const m = catalog?.metrics?.[id];
  if (!m) return h('div', {}, 'Нет описания');
  const lv = levelOf(id, value, req);
  const few = m.min_req && req != null && req < m.min_req;
  return h('div', { class: 'metric-hint' },
    h('div', { class: 'mh-head' }, h('b', {}, m.label), valueText != null ? h('span', { class: 'mh-val' }, valueText) : null,
      m.dir ? badge(few ? 'мало данных' : LEVEL_TEXT[lv], few ? 'outline' : LEVEL_CLASS[lv] || 'good') : null),
    h('p', {}, m.desc),
    m.dir && m.warn != null ? h('div', { class: 'mh-thr' },
      h('span', {}, h('i', { class: 'dot good' }), 'норма ', m.dir === 'above' ? `< ${fmtThr(m, m.warn)}` : `> ${fmtThr(m, m.warn)}`),
      h('span', {}, h('i', { class: 'dot warn' }), 'внимание ', m.dir === 'above' ? `≥ ${fmtThr(m, m.warn)}` : `≤ ${fmtThr(m, m.warn)}`),
      m.crit != null ? h('span', {}, h('i', { class: 'dot bad' }), 'проблема ', m.dir === 'above' ? `≥ ${fmtThr(m, m.crit)}` : `≤ ${fmtThr(m, m.crit)}`) : null) : null,
    few ? h('p', { class: 'muted small' }, `Оценка выполняется при ${m.min_req} запросах и более.`) : null,
    h('p', { class: 'small' }, h('b', {}, 'Норма. '), m.norm),
    h('p', { class: 'small' }, h('b', {}, lv === 'ok' ? 'Если ухудшится. ' : 'Что сделать. '), m.advice),
    h('details', { class: 'small' }, h('summary', {}, 'Как считается'), h('p', {}, m.how)),
    m.doc?.page ? h('button', { class: 'btn sm', onclick: () => openHelp(m.doc.page, m.doc.section) }, icon('book'), 'Подробнее') : null);
}

/**
 * Подключить оценку и подсказку к карточке показателя (kpi() из ui.js).
 * Повторные вызовы обновляют цвет и значение (на дашборде — каждую секунду).
 */
export function hintKpi(el, id, value, { req, text, keepClass = false } = {}) {
  if (!el) return;
  el._hint = { id, value, req, text };
  if (!el._hintBtn) {
    const btn = h('button', { class: 'kpi-hint', title: 'Что означает показатель и что делать', 'aria-label': 'Подсказка' }, '?');
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const x = el._hint;
      popover(btn, metricHint(x.id, x.value, x.req, x.text));
    });
    el.querySelector('.label')?.appendChild(btn);
    el._hintBtn = btn;
  }
  if (!catalog) { loadCatalog().then(() => hintKpi(el, id, el._hint.value, el._hint)); return; }
  if (keepClass) return;
  const lv = levelOf(id, value, req);
  el.classList.remove('warn', 'bad', 'info');
  if (lv === 'warn') el.classList.add('warn');
  if (lv === 'crit') el.classList.add('bad');
}

// ----------------------------------------------------------------------- находки
const LEVEL_ICON = { crit: 'alert', warn: 'alert', info: 'eye' };

export function findingView(f, { compact = false, onChange } = {}) {
  const det = h('div', { class: 'finding-body' });
  let open = false;
  const toggle = () => {
    open = !open;
    el.classList.toggle('open', open);
    if (open && !det.firstChild) mount(det, details(f, onChange));
  };
  const el = h('div', { class: `finding lv-${f.level}` },
    h('div', { class: 'finding-head', onclick: toggle, role: 'button', tabindex: 0, onkeydown: (e) => { if (e.key === 'Enter') toggle(); } },
      h('span', { class: `finding-ic lv-${f.level}` }, icon(LEVEL_ICON[f.level] || 'alert')),
      h('div', { class: 'grow', style: { minWidth: 0 } },
        h('div', { class: 'finding-title' }, f.title, f.site !== '*' ? h('span', { class: 'tag' }, f.site_name) : null),
        h('div', { class: 'finding-sum' }, f.summary)),
      h('div', { class: 'finding-meta' }, badge(LEVEL_TEXT[f.level], LEVEL_CLASS[f.level]),
        !compact && f.since ? h('div', { class: 'muted small', title: 'Впервые замечено' }, fmtAgo(f.since)) : null),
      h('span', { class: 'finding-chev' }, '›')),
    det);
  return el;
}

function details(f, onChange) {
  const ev = f.evidence;
  return h('div', { class: 'col' },
    h('p', {}, f.what),
    h('div', { class: 'grid g2' },
      f.causes?.length ? h('div', {}, h('h4', {}, 'Вероятные причины'), h('ul', {}, f.causes.map(c => h('li', {}, c)))) : null,
      f.actions?.length ? h('div', {}, h('h4', {}, 'Что сделать'), h('ol', {}, f.actions.map(c => h('li', {}, c)))) : null),
    ev && ev.rows && ev.rows.length ? h('div', {}, h('h4', {}, 'Данные'), table(ev.columns.map((c, i) => ({ title: c, num: i > 0 && typeof ev.rows[0][i] === 'number', render: (r) => r[i] == null ? '—' : typeof r[i] === 'number' ? r[i].toLocaleString('ru-RU') : h('span', { class: i === 0 ? 'mono small' : 'small' }, String(r[i])) })), ev.rows, { cls: 'compact' })) : null,
    h('div', { class: 'muted small' }, h('b', {}, 'Условие: '), f.when, f.custom ? h('div', {}, f.custom) : null),
    h('div', { class: 'row', style: { flexWrap: 'wrap' } },
      (f.links || []).map(l => h('a', { class: 'btn sm', href: l.href + (f.site !== '*' && ['#/analytics', '#/requests'].includes(l.href) ? `?site=${f.site}` : '') }, l.label)),
      f.doc?.page ? h('button', { class: 'btn sm', onclick: () => openHelp(f.doc.page, f.doc.section) }, icon('book'), 'Документация') : null,
      h('span', { class: 'grow' }),
      can('operator') ? h('button', { class: 'btn sm ghost', title: 'Не показывать подсказки этого типа (можно вернуть в «Анализе»)', onclick: async () => {
        await api('/insights/mute', { method: 'POST', body: { id: f.id, mute: !f.muted } });
        toast(f.muted ? 'Подсказка снова показывается' : 'Подсказки этого типа скрыты', 'good');
        onChange && onChange();
      } }, f.muted ? 'Показывать снова' : 'Скрыть этот тип') : null));
}

/** Короткая карточка «Анализ» для дашборда и аналитики. */
export function insightsCard(res, { limit = 4, link = '#/insights', title = 'Анализ и подсказки', onChange } = {}) {
  const c = res.counts || {};
  const items = (res.findings || []).filter(f => f.level !== 'info').slice(0, limit);
  const info = (res.findings || []).filter(f => f.level === 'info').length;
  return h('div', { class: 'card insights-card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h3', {}, title),
      h('div', { class: 'sub' }, c.crit || c.warn ? `проблем: ${c.crit || 0} · требуют внимания: ${c.warn || 0}${info ? ` · к сведению: ${info}` : ''}`
        : info ? `серьёзных проблем нет · к сведению: ${info}` : `проверено сценариев: ${res.checked || 0} — проблем не найдено`)),
      h('a', { class: 'btn sm', href: link }, 'Подробнее')),
    items.length ? h('div', { class: 'card-body flush' }, items.map(f => findingView(f, { compact: true, onChange })))
      : h('div', { class: 'card-body' }, h('div', { class: 'row muted' }, h('span', { class: 'dot good' }), info ? 'Только рекомендации — откройте «Подробнее».' : 'Всё в порядке.')));
}
