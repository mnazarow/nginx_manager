// Защита от атак: аналитика, атакующие адреса, профиль адреса, карточка правила, проверка роботов, глубокая проверка
// (ModSecurity + OWASP CRS), правила ограничения частоты, живая лента.
import { api } from '../api.js';
import { h, mount, icon, toast, modal, loading, card, kpi, badge, table, hbars, fmtInt, fmtNum, fmtDate, fmtAgo, fmtTime,
  fmtDur, fmtBytes, countryTag, countryName, confirmDlg, debounce, segmented, empty, sparkline, copyBtn } from '../ui.js';
import { model, renderFields, errorsToMap } from '../forms.js';
import { timeChart, setData, chartCard, destroyAll, css } from '../charts.js';
import { can, refreshState } from '../app.js';
import { openVuln } from './protection-vulns.js';

// Виды атак в фиксированном порядке категориальной палитры; девятый и далее — нейтральный серый
export const KIND_ORDER = ['waf', 'modsec', 'custom', 'threat', 'fakebot', 'challenge', 'honeypot', 'ratelimit'];
export const kindColor = (k) => KIND_ORDER.includes(k) ? css(`--s${KIND_ORDER.indexOf(k) + 1}`) : css('--muted');
const ACT_KIND = { blocked: 'bad', detected: 'warn', challenged: 'info', banned: 'bad', passed: 'good' };
const ACT_COLOR = { blocked: '--s8', detected: '--s4', challenged: '--s1', banned: '--s7', allowed: '--s3' };
const PERIODS = [['1', 'Час'], ['6', '6 часов'], ['24', 'Сутки'], ['168', 'Неделя'], ['720', 'Месяц']];
const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
const DAYS_FULL = ['понедельник', 'вторник', 'среда', 'четверг', 'пятница', 'суббота', 'воскресенье'];
const RAMP = ['#fde0dd', '#fbb4ae', '#f88b82', '#ee5f55', '#d33c33', '#a82720', '#741812'];
const ramp = () => (document.documentElement.dataset.theme === 'dark' ? [...RAMP].reverse() : RAMP);
const go = (tab, extra = '') => { location.hash = `#/protection?tab=${tab}${extra}`; };
const stepLabel = (s) => s >= 3600 ? `${s / 3600} ч` : `${s / 60} мин`;
// интервал активности: в один день — «09:13–09:57», в разные — с датами
const span = (a, b) => new Date(a * 1000).toDateString() === new Date(b * 1000).toDateString()
  ? `${fmtTime(a, false)}–${fmtTime(b, false)}` : `${fmtDate(a, { short: true })} – ${fmtDate(b, { short: true })}`;

async function saveSettings(obj, msg) {
  await api('/protection/settings', { method: 'PUT', body: obj });
  toast(msg + '. Примените конфигурацию, чтобы изменения попали в nginx.', 'good');
  refreshState();
}

function delta(cur, prev) {
  if (!prev && !cur) return '';
  if (!prev) return 'новое за период';
  const d = (cur - prev) / prev * 100;
  return `${d >= 0 ? '▲' : '▼'} ${fmtNum(Math.abs(d), 0)}% к прошлому периоду`;
}

function siteSelect(sites, value, onChange, label = 'Сайт') {
  return h('select', { 'aria-label': label, style: { width: 'auto', minWidth: '180px' }, onchange: (e) => onChange(e.target.value) },
    h('option', { value: '' }, 'Все сайты'), sites.map(s => h('option', { value: String(s.id), selected: String(s.id) === value }, s.name)));
}

function buckets(since, step) {
  const out = [];
  for (let b = Math.floor(since / step) * step, end = Date.now() / 1000; b <= end; b += step) out.push(b);
  return out;
}

// Ряд «ключ → цвет»: восемь самых крупных — цвета палитры по порядку, остальное — «Прочее» (серый)
function foldSeries(rows, titles, fixedOrder) {
  const tot = {};
  rows.forEach(r => { tot[r.key] = (tot[r.key] || 0) + r.n; });
  let keys = Object.keys(tot).sort((a, b) => tot[b] - tot[a]);
  if (fixedOrder) keys = keys.sort((a, b) => (fixedOrder.indexOf(a) + 99 * (fixedOrder.indexOf(a) < 0)) - (fixedOrder.indexOf(b) + 99 * (fixedOrder.indexOf(b) < 0)));
  const main = keys.slice(0, 7);
  const other = keys.length > 8 ? new Set(keys.slice(7)) : null;
  if (!other && keys.length === 8) main.push(keys[7]);
  const series = main.map((k, i) => ({ key: k, label: titles(k), color: fixedOrder ? kindColor(k) : css(`--s${i + 1}`) }));
  if (other) series.push({ key: '__other', label: `Прочее (${other.size})`, color: css('--muted') });
  return { series, map: (k) => other && other.has(k) ? '__other' : k };
}

function stackedChart(cc, charts, since, step, hours, rows, titles, fixedOrder) {
  if (!rows.length) { cc.canvas.replaceWith(empty('Атак не было', 'За выбранный период защита ничего не отклонила и не записала', null, 'shield')); return; }
  const { series, map } = foldSeries(rows, titles, fixedOrder);
  const labels = buckets(since, step);
  const idx = new Map();
  rows.forEach(r => { const k = `${r.b}|${map(r.key)}`; idx.set(k, (idx.get(k) || 0) + r.n); });
  const ch = timeChart(cc.canvas, series.map(s => ({ label: s.label, color: s.color })), { type: 'bar', stacked: true, legendEl: cc.legendEl, seconds: false,
    xFmt: (ts) => hours > 48 ? fmtDate(ts, { short: true }) : fmtTime(ts, false), yFmt: (v) => fmtInt(v) });
  setData(ch, labels, series.map(s => labels.map(b => idx.get(`${b}|${s.key}`) || 0)));
  charts.push(ch);
}

function heatmap(heat, label = 'Атак') {
  const vals = heat.flat().filter(v => v > 0).sort((a, b) => a - b);
  if (!vals.length) return empty('Нет данных', 'Тепловая карта появится, когда накопится история атак', null, 'chart');
  const max = Math.max(1, vals[Math.min(vals.length - 1, Math.floor(vals.length * 0.97))]);
  const colors = ramp();
  const bin = (v) => Math.max(0, Math.min(colors.length - 1, Math.floor(v / max * (colors.length - 1) + 0.0001)));
  const hour = (x) => String(x).padStart(2, '0') + ':00';
  let peak = null;
  heat.forEach((row, d) => row.forEach((v, hr) => { if (!peak || v > peak.v) peak = { d, hr, v }; }));
  return h('div', {},
    h('div', { class: 'heatmap', role: 'group', 'aria-label': `Тепловая карта: ${label.toLowerCase()} по дням недели и часам` },
      h('span', {}), Array.from({ length: 24 }, (_, i) => h('span', { class: 'hm-h' }, i % 3 === 0 ? String(i) : '')),
      heat.map((row, d) => [h('span', { class: 'hm-d' }, DAYS[d]), row.map((v, hr) => {
        const tip = `${DAYS_FULL[d]}, ${hour(hr)}–${hour((hr + 1) % 24)}: ${fmtInt(v)} ${label.toLowerCase()}`;
        return h('span', { class: 'hm-c' + (v ? '' : ' none'), style: v ? { background: colors[bin(v)] } : null, title: tip, tabindex: 0, role: 'img', 'aria-label': tip });
      })])),
    h('div', { class: 'hm-legend' }, h('span', { class: 'muted small' }, `${label}:`),
      colors.map((col, i) => h('span', { class: 'hm-l' }, h('i', { style: { background: col } }), h('span', { class: 'small' }, (i === colors.length - 1 ? '≥ ' : '') + fmtInt(Math.round(max * i / (colors.length - 1)))))),
      h('span', { class: 'hm-l' }, h('i', { class: 'none' }), h('span', { class: 'small' }, 'нет атак'))),
    peak && peak.v ? h('div', { class: 'small muted mt' }, `Больше всего — ${DAYS_FULL[peak.d]}, ${hour(peak.hr)}: ${fmtInt(peak.v)}`) : null);
}

// ================================================================ Аналитика
export async function analyticsTab(view, { sites, charts, c }) {
  let hours = Number((c.params || {}).hours) || 24;
  let site = (c.params || {}).site || '';
  let dim = 'kind';
  const body = h('div', {});
  const head = () => mount(view, h('div', { class: 'toolbar' },
    segmented(PERIODS, String(hours), (v) => { hours = Number(v); load(); }),
    siteSelect(sites, site, (v) => { site = v; load(); }),
    h('span', { style: { flex: 1 } }),
    h('a', { class: 'btn', href: `/api/protection/events.csv?limit=20000${site ? '&site=' + site : ''}`, download: '' }, icon('download'), 'Журнал атак (CSV)')), body);
  head();
  const load = async () => {
    mount(body, loading());
    destroyAll(charts);
    const d = await api('/protection/analytics', { query: { hours, site } });
    const t = d.totals || {};
    const cat = (k) => d.cat_titles[k] || d.kinds_titles[k] || k;
    const share = d.total_requests ? d.attacks / d.total_requests * 100 : null;
    const dimRows = { kind: d.series.kind, cat: d.series.cat, action: d.series.action, site: d.series.site };
    const titles = {
      kind: (k) => d.kinds_titles[k] || k, cat, action: (k) => ({ blocked: 'заблокировано', detected: 'записано', challenged: 'проверка браузера', banned: 'IP заблокирован', allowed: 'пропущено' })[k] || k,
      site: (k) => (sites.find(s => String(s.id) === k) || {}).name || (k || 'без сайта'),
    };
    const cc = chartCard('Атаки во времени', { sub: `за ${stepLabel(d.step)}`,
      actions: segmented([['kind', 'Механизмы'], ['cat', 'Категории'], ['action', 'Действия'], ['site', 'Сайты']], dim, (v) => { dim = v; drawMain(); }) });
    const drawMain = () => {
      charts.filter(x => x.canvas === cc.canvas).forEach(x => { x.destroy(); charts.splice(charts.indexOf(x), 1); });
      const rows = (dimRows[dim] || []).filter(r => dim !== 'action' || r.key !== 'allowed');
      stackedChart(cc, charts, d.since, d.step, hours, rows.map(r => ({ b: r.b, key: r.key, n: r.n })), titles[dim], dim === 'kind' ? KIND_ORDER : null);
    };
    const shareCard = chartCard('Доля атак в трафике', { sub: 'отражённые и записанные запросы от всех запросов, %', legend: false });
    const uniqCard = chartCard('Атакующих адресов', { sub: `уникальных IP за ${stepLabel(d.step)} (по журналу атак)`, legend: false });
    const ch = d.challenge || {};
    const n = (k) => (ch[k] || {}).n || 0;
    const solvedPct = n('served') ? n('solved') / n('served') * 100 : null;
    const avgSolve = n('solved') ? (ch.solved.ms || 0) / n('solved') / 1000 : null;
    const sv = d.solve || {};
    const ruleTable = d.rules.length ? table([
      { title: 'Правило', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openRule(r.kind, r.rule, { sites }); } }, r.title) },
      { title: 'Категория', render: (r) => h('span', { class: 'small' }, cat(r.cat)) },
      { title: 'Срабатываний', num: true, render: (r) => fmtInt(r.n) },
      { title: 'Адресов', num: true, render: (r) => fmtInt(r.ips) },
      { title: 'Сайтов', num: true, render: (r) => fmtInt(r.sites) },
      { title: 'Блок / запись', render: (r) => h('span', { class: 'small nowrap' }, fmtInt(r.blocked), ' / ', fmtInt(r.detected)) },
      { title: 'Динамика', render: (r) => sparkline(r.spark, { color: kindColor(r.kind), w: 110, hgt: 24 }) },
      { title: 'Последнее', render: (r) => h('span', { class: 'small muted nowrap' }, r.last ? fmtAgo(r.last) : '—') },
    ], d.rules) : empty('Правила не срабатывали', '', null, 'shield');
    const ATT = { blocked: 'заблокировано', detected: 'записано', challenged: 'проверка браузера', banned: 'IP заблокирован' };
    mount(body,
      h('div', { class: 'grid kpi5' },
        kpi('Атак отражено и записано', fmtInt(d.attacks), { foot: delta(d.attacks, d.prev_attacks) || 'за период', cls: d.attacks > d.prev_attacks * 1.5 && d.attacks > 50 ? 'warn' : '' }),
        kpi('Атакующих адресов', fmtInt(d.unique_ips), { foot: delta(d.unique_ips, d.prev_unique_ips) || 'уникальных IP' }),
        kpi('Доля атак в трафике', share == null ? '—' : fmtNum(share, share < 1 ? 2 : 1) + '%', { foot: `из ${fmtInt(d.total_requests)} запросов` }),
        kpi('Пик', fmtInt(d.peak.per_min), { unit: '/мин', foot: d.peak.b ? `в среднем за ${stepLabel(d.step)} с ${fmtDate(d.peak.b, { short: true })}` : 'нет данных' }),
        kpi('Заблокировано', fmtInt(t.blocked || 0), { foot: `записано ${fmtInt(t.detected || 0)}, проверка браузера ${fmtInt(t.challenged || 0)}`, cls: t.blocked ? 'bad' : '' })),
      cc.el,
      h('div', { class: 'grid g2 mt' }, shareCard.el, uniqCard.el),
      card('Атаки по дням недели и часам', heatmap(d.heat), { cls: 'mt', sub: 'не меньше недели истории; местное время сервера' }),
      h('div', { class: 'grid g3 mt' },
        card('Категории атак', hbars(d.categories.map(r => ({ label: cat(r.key), value: r.n })))),
        card('Инструменты атакующих', hbars(d.tools.map(r => ({ label: r.title, value: r.n }))), { sub: 'по User-Agent (журнал атак)' }),
        card('Страны', d.countries.length ? hbars(d.countries.map(r => ({ label: `${r.key} ${countryName(r.key)}`, value: r.n, extra: `${fmtInt(r.ips)} IP` }))) : empty('Нет данных о странах', 'Нужна база GeoIP', null, 'globe'))),
      h('div', { class: 'grid g3 mt' },
        card('Действия', hbars(Object.entries(ATT).filter(([k]) => t[k]).map(([k, l]) => ({ label: l, value: t[k] })))),
        card('Методы', hbars(d.methods.map(r => ({ label: r.key || '—', value: r.n })))),
        card('Коды ответа', hbars(d.statuses.map(r => ({ label: r.key === 0 ? 'закрыто (444)' : String(r.key), value: r.n }))))),
      h('div', { class: 'grid g2 mt' },
        card('Известные уязвимости', (d.vulns || []).length ? table([
          { title: 'CVE', render: (r) => h('a', { href: '#', class: 'nowrap', onclick: (e) => { e.preventDefault(); openVuln(r.cve, { sites }); } }, r.cve) },
          { title: 'Продукт', render: (r) => h('span', { class: 'small' }, r.product || r.name || '—') },
          { title: 'Попыток', num: true, render: (r) => fmtInt(r.n) }, { title: 'Адресов', num: true, render: (r) => fmtInt(r.ips) },
        ], d.vulns) : empty('Попыток не было', 'Пути эксплойтов из базы уязвимостей не запрашивали', null, 'shield'),
        { flush: !!(d.vulns || []).length, sub: d.vulns_total ? `пытались эксплуатировать ${fmtInt(d.vulns_total)} — все на вкладке «Уязвимости»` : 'по карте путей эксплойтов',
          actions: h('a', { class: 'btn sm ghost', href: '#/protection?tab=vulns' }, 'Все уязвимости') }),
        card('Атакуемые сайты', hbars(d.sites.map(r => ({ label: r.name, value: r.n }))), { sub: 'по журналу атак' })),
      h('div', { class: 'grid g2 mt' },
        card('Цели атак', d.paths.length ? table([
          { title: 'Путь', render: (r) => h('code', { class: 'small', style: { wordBreak: 'break-all' } }, r.key || '/') },
          { title: 'Атак', num: true, render: (r) => fmtInt(r.n) }, { title: 'Адресов', num: true, render: (r) => fmtInt(r.ips) },
        ], d.paths) : empty('Нет данных'), { flush: true, sub: 'пути без параметров' }),
        card('Атакуемые домены', (d.hosts || []).length ? hbars(d.hosts.map(r => ({ label: r.key, value: r.n }))) : empty('Нет данных'), { sub: 'заголовок Host запросов атакующих' })),
      card('Эффективность правил', ruleTable, { flush: true, cls: 'mt', sub: 'сколько раз сработало правило, от скольких адресов и на скольких сайтах; щелчок — карточка правила' }),
      h('div', { class: 'grid g3 mt' },
        card('Списки угроз', d.feeds.length ? hbars(d.feeds.map(r => ({ label: r.name, value: r.n }))) : empty('Списки не срабатывали', '', null, 'list')),
        card('Ограничение частоты', d.ratelimit.length ? hbars(d.ratelimit.map(r => ({ label: r.title, value: r.n }))) : empty('Отказов 429 не было', '', null, 'activity')),
        card('Поисковые роботы и боты ИИ', d.bots.length ? table([
          { title: 'Робот', render: (r) => r.name }, { title: 'Настоящих', num: true, render: (r) => fmtInt(r.ok) },
          { title: 'Поддельных', num: true, render: (r) => r.fake ? h('b', { class: 'bad-text' }, fmtInt(r.fake)) : '0' },
        ], d.bots) : empty('Нет данных', 'Включите проверку роботов во вкладке «Роботы»', null, 'globe'), { flush: !!d.bots.length })),
      card('Проверка браузера', h('div', {},
        h('div', { class: 'grid kpi5' },
          kpi('Показана', fmtInt(n('served')), { foot: 'страниц проверки' }),
          kpi('Решена', fmtInt(n('solved')), { foot: solvedPct == null ? '' : `${fmtNum(solvedPct, 0)}% от показанных` }),
          kpi('Неверных решений', fmtInt(n('failed')), { foot: 'подделка или старая страница', cls: n('failed') > n('solved') && n('failed') > 10 ? 'warn' : '' }),
          kpi('Среднее время', avgSolve == null ? '—' : fmtNum(avgSolve, 1), { unit: avgSolve == null ? '' : 'с', foot: 'от показа до пропуска' }),
          kpi('Запросов с пропуском', fmtInt(n('passed')), { foot: 'прошли без повторной проверки' })),
        n('solved') ? h('div', { class: 'mt' }, h('div', { class: 'small muted' }, 'Время прохождения'),
          hbars([['lt1', 'меньше 1 с'], ['1_3', '1–3 с'], ['3_10', '3–10 с'], ['gt10', 'больше 10 с']].map(([k, l]) => ({ label: l, value: sv[k] || 0 })))) : null,
        h('div', { class: 'small muted mt' }, 'Боты без JavaScript страницу получают, но задачу не решают — низкая доля решивших во время атаки нормальна.')), { cls: 'mt' }),
      card('Режим «Под атакой»', d.periods.length ? table([
        { title: 'Сайт', render: (r) => r.name }, { title: 'Включён', render: (r) => h('span', { class: 'nowrap' }, fmtDate(r.start)) },
        { title: 'Выключен', render: (r) => r.end ? h('span', { class: 'nowrap' }, fmtDate(r.end)) : badge('действует', 'warn') },
        { title: 'Длительность', render: (r) => fmtDur(r.duration) },
        { title: 'Кто', render: (r) => r.auto ? badge('автоматика', 'info') : r.who },
        { title: 'Причина', render: (r) => h('span', { class: 'small' }, r.reason || '—') },
      ], d.periods) : empty('Режим не включался', 'За выбранный период проверка браузера для всех не включалась', null, 'shield'), { flush: !!d.periods.length, cls: 'mt' }));
    drawMain();
    const labels = buckets(d.since, d.step);
    const tr = new Map(d.traffic.map(x => [x.b, x.n]));
    const att = new Map();
    (d.series.action || []).forEach(r => { if (r.key !== 'allowed') att.set(r.b, (att.get(r.b) || 0) + r.n); });
    const sch = timeChart(shareCard.canvas, [{ label: 'Доля атак', color: css('--s8'), fill: true }], { seconds: false,
      xFmt: (ts) => hours > 48 ? fmtDate(ts, { short: true }) : fmtTime(ts, false), yFmt: (v) => fmtNum(v, v < 1 ? 2 : 1) + '%' });
    setData(sch, labels, [labels.map(b => tr.get(b) ? (att.get(b) || 0) / tr.get(b) * 100 : (att.get(b) ? 100 : 0))]);
    charts.push(sch);
    const um = new Map(d.uniq_series.map(x => [x.b, x.n]));
    const uch = timeChart(uniqCard.canvas, [{ label: 'Адресов', color: css('--s7'), fill: true }], { seconds: false,
      xFmt: (ts) => hours > 48 ? fmtDate(ts, { short: true }) : fmtTime(ts, false), yFmt: (v) => fmtInt(v) });
    setData(uch, labels, [labels.map(b => um.get(b) || 0)]);
    charts.push(uch);
  };
  await load();
}

// ================================================================ Атакующие
export async function attackersTab(view, { sites, c }) {
  let hours = Number((c.params || {}).hours) || 24;
  let site = '';
  let q = (c.params || {}).q || '';
  let sort = 'score';
  const body = h('div', {});
  const search = h('input', { type: 'search', placeholder: 'IP, страна (RU) или User-Agent', value: q, 'aria-label': 'Поиск атакующих', style: { maxWidth: '280px' },
    oninput: debounce((e) => { q = e.target.value.trim(); load(); }, 400) });
  mount(view, h('div', { class: 'toolbar' },
    segmented(PERIODS, String(hours), (v) => { hours = Number(v); load(); }),
    siteSelect(sites, site, (v) => { site = v; load(); }), search,
    segmented([['score', 'По угрозе'], ['n', 'По числу атак'], ['last', 'Недавние']], sort, (v) => { sort = v; load(); })),
  h('div', { class: 'small muted mb' }, 'Оценка угрозы 0–100: объём атак, разнообразие правил (сканирование), число сайтов, инструмент атаки по User-Agent, попадание в ловушки. Щелчок по адресу — профиль.'),
  body);
  const load = async () => {
    mount(body, loading());
    const rows = await api('/protection/attackers', { query: { hours, site, q, limit: 300 } });
    rows.sort((a, b) => sort === 'n' ? b.n - a.n : sort === 'last' ? b.last - a.last : b.score - a.score || b.n - a.n);
    mount(body, card(`Адреса (${rows.length})`, rows.length ? table([
      { title: 'IP', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openIp(r.ip, { sites }); } }, h('code', {}, r.ip)) },
      { title: '', srTitle: 'Страна', render: (r) => countryTag(r.country) },
      { title: 'Угроза', render: (r) => badge(String(r.score), r.score >= 70 ? 'bad' : r.score >= 40 ? 'warn' : '') },
      { title: 'Атак', num: true, render: (r) => fmtInt(r.n) },
      { title: 'Правил', num: true, render: (r) => fmtInt(r.rules) },
      { title: 'Сайтов', num: true, render: (r) => fmtInt(r.sites) },
      { title: 'Механизмы', render: (r) => h('span', { class: 'small' }, (r.kinds || '').split(',').filter(Boolean).map(k => ({ waf: 'фильтр', modsec: 'ModSecurity', custom: 'свои', threat: 'списки', fakebot: 'робот', challenge: 'проверка', honeypot: 'ловушка', ratelimit: 'частота', hotlink: 'хотлинк', sni: 'SNI' })[k] || k).join(', ')) },
      { title: 'Инструмент', render: (r) => h('span', { class: 'small', title: (r.tools || []).join(', ') }, r.tool_title) },
      { title: 'Активен', render: (r) => h('span', { class: 'small nowrap' }, span(r.first, r.last), h('br'), h('span', { class: 'muted' }, fmtAgo(r.last))) },
      { title: 'Статус', render: (r) => r.banned ? badge('заблокирован', 'bad') : '—' },
      { title: '', srTitle: 'Действия', render: (r) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('button', { class: 'btn sm', onclick: () => openIp(r.ip, { sites }) }, 'Профиль'),
        can('operator') && !r.banned ? h('button', { class: 'btn sm', 'aria-label': `Заблокировать ${r.ip}`, onclick: async () => { if (await banIp(r.ip)) load(); } }, icon('ban')) : null) },
    ], rows) : empty('Атакующих нет', q ? 'Ничего не найдено — измените поиск' : 'За период защита не записала ни одного адреса', null, 'shield'), { flush: !!rows.length }));
  };
  await load();
}

export async function banIp(ip, minutes = 1440) {
  const sel = h('select', { 'aria-label': 'Срок блокировки' }, [['60', '1 час'], ['1440', 'сутки'], ['10080', 'неделя'], ['43200', 'месяц'], ['0', 'бессрочно']].map(([v, l]) => h('option', { value: v, selected: v === String(minutes) }, l)));
  return new Promise((resolve) => {
    const m = modal({ title: `Заблокировать ${ip}`, body: h('div', { class: 'col' }, h('label', { class: 'field' }, h('span', {}, 'Срок'), sel),
      h('div', { class: 'small muted' }, 'Блокировка действует на всех сайтах (раздел «Блокировки IP»), nginx закрывает соединение до любых проверок.')),
    footer: [h('button', { class: 'btn', onclick: () => { m.close(); resolve(false); } }, 'Отмена'), h('button', { class: 'btn danger solid', onclick: async () => {
      await api('/bans', { method: 'POST', body: { nets: [ip], minutes: Number(sel.value) || null, reason: 'Атаки (раздел «Защита от атак»)' } });
      toast(`${ip} заблокирован`, 'good'); m.close(); resolve(true);
    } }, icon('ban'), 'Заблокировать')] });
  });
}

// ---------------------------------------------------------------- профиль адреса
export async function openIp(ip, { sites = [] } = {}) {
  const body = h('div', {}, loading());
  const charts = [];
  const m = modal({ title: `Адрес ${ip}`, size: 'xl', body, onClose: () => destroyAll(charts) });
  const d = await api(`/protection/ip/${encodeURIComponent(ip)}`, { query: { hours: 168 } });
  const s = d.summary || {};
  const cc = chartCard('Атаки за неделю', { sub: `за ${stepLabel(d.step)}, по действиям` });
  const ACT = { blocked: 'заблокировано', detected: 'записано', challenged: 'проверка браузера', banned: 'IP заблокирован', allowed: 'пропущено' };
  const trust = async () => {
    const cfg = await api('/protection/settings');
    const obj = cfg.settings;
    if (obj.bypass_ips.includes(ip)) return toast('Адрес уже доверенный', 'info');
    if (!await confirmDlg(`Добавить ${ip} в доверенные? Защита (фильтр, проверка браузера, списки угроз) перестанет проверять его запросы на всех сайтах.`, { ok: 'Добавить' })) return;
    obj.bypass_ips.push(ip);
    await saveSettings(obj, `${ip} добавлен в доверенные`);
  };
  mount(body,
    h('div', { class: 'row mb', style: { flexWrap: 'wrap', gap: '8px' } },
      countryTag(s.country), s.country ? h('span', {}, countryName(s.country)) : null,
      d.ban ? badge(`заблокирован${d.ban.expires_at ? ' до ' + fmtDate(d.ban.expires_at) : ' бессрочно'}`, 'bad') : badge('не заблокирован'),
      d.trusted ? badge('доверенный', 'good') : null,
      (d.feeds || []).map(f => badge(f.type === 'bot' ? `робот: ${f.name}` : `в списке: ${f.name}`, f.type === 'bot' ? 'good' : 'warn'))),
    h('div', { class: 'grid kpi5' },
      kpi('Угроза', String(d.score), { foot: 'оценка 0–100', cls: d.score >= 70 ? 'bad' : d.score >= 40 ? 'warn' : '' }),
      kpi('Атак за неделю', fmtInt(s.n || 0), { foot: (d.ever || {}).n ? `всего в журнале: ${fmtInt(d.ever.n)}` : '' }),
      kpi('Правил', fmtInt(s.rules || 0), { foot: `сайтов: ${fmtInt(s.sites || 0)}` }),
      kpi('Впервые', (d.ever || {}).first ? fmtAgo(d.ever.first) : '—', { foot: s.last ? `последний раз ${fmtAgo(s.last)}` : '' }),
      kpi('Обычных запросов', d.traffic ? fmtInt(d.traffic.n || 0) : '—', { foot: d.traffic ? `ошибок 4xx/5xx: ${fmtInt(d.traffic.err || 0)}` : 'журнал запросов выключен' })),
    cc.el,
    h('div', { class: 'grid g2 mt' },
      card('Правила', d.rules.length ? table([
        { title: 'Правило', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openRule(r.kind, r.rule, { sites }); } }, r.title) },
        { title: 'Раз', num: true, render: (r) => fmtInt(r.n) }, { title: 'Последний', render: (r) => h('span', { class: 'small muted' }, fmtAgo(r.last)) },
      ], d.rules) : empty('Нет данных'), { flush: !!d.rules.length }),
      card('User-Agent', d.uas.length ? table([
        { title: 'User-Agent', render: (r) => h('span', { class: 'small', style: { wordBreak: 'break-all' } }, r.ua || '(пусто)') },
        { title: 'Инструмент', render: (r) => h('span', { class: 'small' }, r.tool) }, { title: 'Раз', num: true, render: (r) => fmtInt(r.n) },
      ], d.uas) : empty('Нет данных'), { flush: !!d.uas.length })),
    h('div', { class: 'grid g2 mt' },
      card('Запросы', d.paths.length ? table([
        { title: 'Запрос', render: (r) => h('code', { class: 'small', style: { wordBreak: 'break-all' } }, `${r.method} ${r.uri}`) },
        { title: 'Код', render: (r) => r.status || '444' }, { title: 'Раз', num: true, render: (r) => fmtInt(r.n) },
      ], d.paths) : empty('Нет данных'), { flush: !!d.paths.length }),
      card('Сайты', hbars(d.sites.map(r => ({ label: r.name, value: r.n }))))),
    card('Последние события', d.events.length ? table([
      { title: 'Время', render: (r) => h('span', { class: 'nowrap small' }, fmtDate(r.ts)) },
      { title: 'Правило', render: (r) => h('span', { class: 'small' }, r.title || r.rule) },
      { title: 'Действие', render: (r) => badge(ACT[r.action] || r.action, ACT_KIND[r.action]) },
      { title: 'Запрос', render: (r) => h('code', { class: 'small', style: { wordBreak: 'break-all' } }, `${r.method} ${r.uri}`) },
    ], d.events.slice(0, 20)) : empty('Нет событий'), { flush: !!d.events.length, cls: 'mt' }),
    h('div', { class: 'row mt', style: { gap: '8px', flexWrap: 'wrap' } },
      can('operator') && !d.ban ? h('button', { class: 'btn danger', onclick: async () => { if (await banIp(ip)) m.close(); } }, icon('ban'), 'Заблокировать') : null,
      can('operator') && d.ban ? h('button', { class: 'btn', onclick: async () => { await api(`/bans/${d.ban.id}`, { method: 'DELETE' }); toast(`${ip} разблокирован`, 'good'); m.close(); } }, 'Разблокировать') : null,
      can('admin') && !d.trusted ? h('button', { class: 'btn', onclick: trust }, icon('check'), 'В доверенные') : null,
      h('a', { class: 'btn', href: `#/protection?tab=log&ip=${encodeURIComponent(ip)}`, onclick: () => m.close() }, 'Журнал атак'),
      h('a', { class: 'btn', href: `#/requests?ip=${encodeURIComponent(ip)}`, onclick: () => m.close() }, 'Журнал запросов'),
      copyBtn(() => ip, 'Копировать IP')));
  const labels = buckets(d.since, d.step);
  const acts = [...new Set(d.series.map(x => x.action))];
  if (acts.length) {
    const ch = timeChart(cc.canvas, acts.map(a => ({ label: ACT[a] || a, color: css(ACT_COLOR[a] || '--s1') })), { type: 'bar', stacked: true, legendEl: cc.legendEl, seconds: false,
      xFmt: (ts) => fmtDate(ts, { short: true }), yFmt: (v) => fmtInt(v) });
    const idx = new Map(d.series.map(x => [`${x.b}|${x.action}`, x.n]));
    setData(ch, labels, acts.map(a => labels.map(b => idx.get(`${b}|${a}`) || 0)));
    charts.push(ch);
  } else cc.canvas.replaceWith(empty('Нет атак за неделю'));
}

// ---------------------------------------------------------------- карточка правила
export async function openRule(kind, rule, { sites = [] } = {}) {
  const body = h('div', {}, loading());
  const charts = [];
  const m = modal({ title: 'Правило', size: 'xl', body, onClose: () => destroyAll(charts) });
  const d = await api('/protection/rule', { query: { kind, rule, hours: 168 } });
  const meta = d.meta;
  const titleEl = m.el && m.el.querySelector('.modal-head h2, .modal-title');
  if (titleEl) titleEl.textContent = meta.title;
  const t = d.totals || {};
  const cc = chartCard('Срабатывания за неделю', { sub: `за ${stepLabel(d.step)}` });
  const actions = [];
  if (can('admin') && kind === 'waf' && meta.id) {
    actions.push(h('button', { class: 'btn', onclick: async () => {
      if (!await confirmDlg(`Отключить правило «${meta.id}» на всех сайтах? Для одного сайта — «Отключённые правила» на вкладке «Защита от атак» редактора сайта.`, { ok: 'Отключить', danger: true })) return;
      const cfg = await api('/protection/settings');
      const obj = cfg.settings;
      if (!obj.waf_disabled_rules.includes(meta.id)) obj.waf_disabled_rules.push(meta.id);
      await saveSettings(obj, `Правило ${meta.id} отключено`); m.close();
    } }, meta.disabled ? 'Уже отключено' : 'Отключить на всех сайтах'));
  }
  if (can('admin') && kind === 'modsec') {
    const id = Number(rule.split('/')[1]);
    actions.push(h('button', { class: 'btn', onclick: async () => {
      if (!await confirmDlg(`Отключить правило CRS ${id} на всех сайтах?`, { ok: 'Отключить', danger: true })) return;
      const cfg = await api('/protection/settings');
      const obj = cfg.settings;
      if (!obj.modsec_disabled_ids.includes(id)) obj.modsec_disabled_ids.push(id);
      await saveSettings(obj, `Правило CRS ${id} отключено`); m.close();
    } }, 'Отключить правило CRS'));
  }
  if (meta.vuln) actions.unshift(h('button', { class: 'btn primary', onclick: () => { m.close(); openVuln(meta.vuln, { sites }); } }, 'Карточка уязвимости'));
  actions.push(h('a', { class: 'btn', href: `#/protection?tab=log&kind=${kind}&q=${encodeURIComponent(rule)}`, onclick: () => m.close() }, 'Журнал атак'));
  const facts = [
    ['Механизм', meta.kind_title || kind],
    meta.category ? ['Категория', meta.category] : null, meta.crs_group ? ['Группа CRS', meta.crs_group] : null,
    meta.mode ? ['Режим категории', { block: 'блокировать', detect: 'запись', off: 'выключено' }[meta.mode]] : null,
    meta.level ? ['Строгость', String(meta.level)] : null, meta.cve ? ['CVE', meta.cve] : null,
    meta.fields && meta.fields.length ? ['Где ищет', meta.fields.join(', ')] : null,
    ['Идентификатор', h('code', {}, rule)],
  ].filter(Boolean);
  mount(body,
    h('h3', { style: { marginTop: 0 } }, meta.title),
    h('dl', { class: 'facts' }, facts.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
    meta.note ? h('p', { class: 'small' }, meta.note) : null,
    meta.pattern ? h('details', { class: 'mt' }, h('summary', {}, 'Шаблон (регулярное выражение)'), h('pre', { class: 'code small', style: { whiteSpace: 'pre-wrap', wordBreak: 'break-all' } }, meta.pattern)) : null,
    meta.examples && meta.examples.length ? h('div', { class: 'small mt' }, 'Пример атаки: ', h('code', { style: { wordBreak: 'break-all' } }, meta.examples[0])) : null,
    h('div', { class: 'grid kpi5 mt' },
      kpi('Срабатываний', fmtInt(Object.values(t).reduce((a, b) => a + b, 0)), { foot: 'за неделю' }),
      kpi('Заблокировано', fmtInt(t.blocked || 0)), kpi('Записано', fmtInt(t.detected || 0)),
      kpi('Адресов', fmtInt(d.ips.length), { foot: d.ips.length >= 20 ? 'показаны 20 самых активных' : '' }),
      kpi('Сайтов', fmtInt(d.sites.length))),
    cc.el,
    h('div', { class: 'grid g3 mt' },
      card('Адреса', d.ips.length ? table([
        { title: 'IP', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openIp(r.ip, { sites }); } }, h('code', {}, r.ip)) },
        { title: '', srTitle: 'Страна', render: (r) => countryTag(r.country) }, { title: 'Раз', num: true, render: (r) => fmtInt(r.n) },
      ], d.ips) : empty('Нет данных'), { flush: !!d.ips.length }),
      card('Пути', d.paths.length ? hbars(d.paths.map(r => ({ label: r.uri, value: r.n }))) : empty('Нет данных')),
      card('Сайты', hbars(d.sites.map(r => ({ label: r.name, value: r.n }))))),
    d.events.length ? card('Последние срабатывания', table([
      { title: 'Время', render: (r) => h('span', { class: 'nowrap small' }, fmtDate(r.ts)) },
      { title: 'IP', render: (r) => h('code', {}, r.ip) },
      { title: 'Запрос', render: (r) => h('code', { class: 'small', style: { wordBreak: 'break-all' } }, `${r.method} ${r.uri}`) },
      { title: 'Код', render: (r) => r.status || '444' },
    ], d.events.slice(0, 15)), { flush: true, cls: 'mt' }) : null,
    h('div', { class: 'row mt', style: { gap: '8px', flexWrap: 'wrap' } }, actions));
  const labels = buckets(d.since, d.step);
  const acts = [...new Set(d.series.map(x => x.action))];
  if (acts.length) {
    const ACT = { blocked: 'заблокировано', detected: 'записано', challenged: 'проверка браузера', banned: 'IP заблокирован', allowed: 'пропущено' };
    const ch = timeChart(cc.canvas, acts.map(a => ({ label: ACT[a] || a, color: css(ACT_COLOR[a] || '--s1') })), { type: 'bar', stacked: true, legendEl: cc.legendEl, seconds: false,
      xFmt: (ts) => fmtDate(ts, { short: true }), yFmt: (v) => fmtInt(v) });
    const idx = new Map(d.series.map(x => [`${x.b}|${x.action}`, x.n]));
    setData(ch, labels, acts.map(a => labels.map(b => idx.get(`${b}|${a}`) || 0)));
    charts.push(ch);
  } else cc.canvas.replaceWith(empty('Не срабатывало за неделю'));
}

// ================================================================ Живая лента (на «Обзоре»)
export function liveFeed(kinds) {
  const list = h('div', { class: 'live-feed', role: 'log', 'aria-live': 'off', 'aria-label': 'Последние события защиты' });
  let since = Date.now() / 1000 - 600;
  let rows = [];
  let timer = null;
  const ACT = { blocked: 'заблокировано', detected: 'записано', challenged: 'проверка', banned: 'IP заблокирован', allowed: 'пропущено' };
  const draw = () => mount(list, rows.length ? rows.slice(0, 15).map(r => h('div', { class: 'lf-row' },
    h('span', { class: 'muted small nowrap' }, fmtTime(r.ts)),
    badge(ACT[r.action] || r.action, ACT_KIND[r.action]),
    h('span', { class: 'small nowrap' }, kinds[r.kind] || r.kind),
    h('a', { href: '#', class: 'small', onclick: (e) => { e.preventDefault(); openIp(r.ip); } }, h('code', {}, r.ip)), countryTag(r.country),
    h('code', { class: 'small lf-uri' }, `${r.method} ${r.uri}`))) : h('div', { class: 'muted small' }, 'Последние 10 минут тихо — новые события появятся здесь сами.'));
  const tick = async () => {
    if (!list.isConnected) { clearInterval(timer); return; }
    try {
      const fresh = (await api('/protection/live', { query: { since } })).filter(e => !e.test);
      if (fresh.length) { since = fresh[fresh.length - 1].ts; rows = [...fresh.reverse(), ...rows].slice(0, 50); draw(); }
    } catch { /* сеть: следующая попытка через 3 с */ }
  };
  draw();
  tick();
  timer = setInterval(tick, 3000);
  return card('Сейчас', list, { sub: 'живая лента событий защиты, обновляется каждые 3 секунды', cls: 'mt' });
}

// ================================================================ Роботы
export async function botsTab(view, { cfg }) {
  const obj = structuredClone(cfg.settings);
  const status = cfg.feed_status || {};
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'bots', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  let stats = {};
  try { (await api('/protection/analytics', { query: { hours: 24 } })).bots.forEach(b => { stats[b.id] = b; }); } catch { stats = {}; }
  const presetIds = new Set((cfg.bot_presets || []).map(b => b.id));
  const addBot = () => {
    const b = { id: '', name: '', url: '', ua: '', enabled: true };
    let errs = {};
    const fm = h('div', {});
    const draw = () => { mount(fm); renderFields(fm, model('verified_bot'), b, { root: b, errors: errs, rerender: draw }); };
    draw();
    const m = modal({ title: 'Свой проверяемый робот', body: h('div', { class: 'col' }, h('div', { class: 'small muted' }, 'Список адресов: JSON в формате Google ({"prefixes": [{"ipv4Prefix": …}]}) или текст — по подсети в строке. User-Agent — регулярное выражение без учёта регистра.'), fm),
      footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
        try { await saveSettings({ ...obj, verified_bots: [...obj.verified_bots, b] }, 'Робот добавлен'); m.close(); go('bots'); } catch (e) { errs = errorsToMap(e); draw(); }
      } }, icon('check'), 'Добавить')] });
  };
  mount(view,
    h('div', { class: 'alert info mb' }, 'Сканеры и сборщики данных часто называют себя Googlebot, чтобы их не ограничивали. Google, Bing, Apple, DuckDuckGo, OpenAI и Perplexity публикуют адреса своих роботов: панель скачивает их по расписанию списков угроз, а nginx сверяет адрес с User-Agent. Настоящие роботы проходят без проверки браузера даже в режиме «Под атакой». Яндекс адресов не публикует (проверка только через обратный DNS) — его User-Agent не проверяется.'),
    card('Настройки', h('div', {}, form, can('admin') ? h('div', { class: 'row mt' }, h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj, 'Настройки роботов сохранены'); errors = {}; } catch (e) { errors = errorsToMap(e); drawForm(); }
    } }, icon('check'), 'Сохранить')) : null)),
    card('Роботы', table([
      { title: 'Робот', render: (b) => h('span', {}, h('b', {}, b.name), presetIds.has(b.id) ? '' : [' ', badge('свой')]) },
      { title: 'User-Agent', render: (b) => h('code', { class: 'small' }, b.ua) },
      { title: 'Адресов', num: true, render: (b) => { const st = status[`bot:${b.id}`] || {}; return st.count ? fmtInt(st.count) : '—'; } },
      { title: 'Обновлён', render: (b) => { const st = status[`bot:${b.id}`] || {}; return st.error ? h('span', { class: 'bad-text small', title: st.error }, 'ошибка: ' + st.error.slice(0, 60)) : st.updated ? h('span', { class: 'small muted' }, fmtAgo(st.updated)) : h('span', { class: 'small muted' }, 'не загружен'); } },
      { title: 'За сутки: настоящих / поддельных', render: (b) => { const s = stats[b.id]; return s ? h('span', { class: 'small' }, fmtInt(s.ok), ' / ', s.fake ? h('b', { class: 'bad-text' }, fmtInt(s.fake)) : '0') : '—'; } },
      { title: 'Проверять', render: (b) => h('input', { type: 'checkbox', checked: b.enabled, disabled: !can('admin'), 'aria-label': `Проверять ${b.name}`, onchange: async (e) => {
        b.enabled = e.target.checked; await saveSettings(obj, `${b.name}: ${b.enabled ? 'проверяется' : 'не проверяется'}`);
      } }) },
      { title: '', srTitle: 'Действия', render: (b) => can('admin') ? h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('button', { class: 'btn sm', onclick: async () => { const r = await api('/protection/feeds/update', { method: 'POST', body: { id: `bot:${b.id}` } }); const st = (r.feeds || {})[`bot:${b.id}`] || {}; toast(st.ok ? `${b.name}: ${fmtInt(st.count)} адресов` : `${b.name}: ${st.error || 'не обновлён'}`, st.ok ? 'good' : 'bad'); go('bots'); } }, icon('refresh'), 'Обновить'),
        presetIds.has(b.id) ? null : h('button', { class: 'btn sm danger', 'aria-label': `Удалить ${b.name}`, onclick: async () => { obj.verified_bots = obj.verified_bots.filter(x => x !== b); await saveSettings(obj, 'Робот удалён'); go('bots'); } }, icon('trash'))) : null },
    ], obj.verified_bots), { flush: true, cls: 'mt', actions: can('admin') ? h('div', { class: 'row', style: { gap: '6px' } },
      h('button', { class: 'btn', onclick: async () => { const r = await api('/protection/feeds/update', { method: 'POST', body: {} }); toast(`Списки обновлены: ${fmtInt(r.total || 0)} адресов угроз`, r.ok ? 'good' : 'bad'); go('bots'); } }, icon('refresh'), 'Обновить все'),
      h('button', { class: 'btn primary', onclick: addBot }, icon('plus'), 'Свой робот')) : null }));
}

// ================================================================ Глубокая проверка (ModSecurity)
export async function modsecTab(view, { cfg, sites, charts }) {
  const ms = cfg.modsec || {};
  const obj = structuredClone(cfg.settings);
  let errors = {};
  const form = h('div', {});
  const drawForm = () => { mount(form); renderFields(form, model('protection'), obj, { root: obj, tab: 'modsec', advanced: true, errors, rerender: drawForm }); };
  drawForm();
  const ready = ms.module && ms.crs_dir;
  let an = null;
  try { an = await api('/protection/analytics', { query: { hours: 168 } }); } catch { an = null; }
  const msRules = an ? an.rules.filter(r => r.kind === 'modsec') : [];
  const groups = {};
  msRules.forEach(r => { const g = r.rule.split('/')[1].slice(0, 3); groups[g] = (groups[g] || 0) + r.n; });
  const cc = chartCard('Срабатывания ModSecurity за неделю', { sub: an ? `за ${stepLabel(an.step)}` : '', legend: true });
  mount(view,
    h('div', { class: 'alert info mb' }, 'Фильтр запросов панели видит адрес и заголовки. ModSecurity v3 с OWASP Core Rule Set разбирает и тело запроса — формы, JSON, XML, загрузку файлов, — нормализует кодировки и считает «оценку аномальности»: каждое сработавшее правило добавляет баллы, запрос блокируется, когда сумма достигает порога. Работает вместе с фильтром панели: тот отсекает очевидное раньше и дешевле.'),
    h('div', { class: 'grid g3 mb' },
      kpi('Модуль nginx', ms.module ? 'есть' : 'нет', { foot: 'ngx_http_modsecurity_module', cls: ms.module ? 'good' : 'warn' }),
      kpi('OWASP CRS', ms.crs_version || 'не найден', { foot: ms.crs_dir ? `${ms.crs_source === 'github' ? 'выпуск с GitHub' : 'пакет дистрибутива'}${ms.crs_status && ms.crs_status.error ? ' · обновление не удалось' : ''}` : 'пакет modsecurity-crs или выпуск с GitHub', cls: ms.crs_dir ? 'good' : 'warn', tip: [ms.crs_dir, ms.crs_status && ms.crs_status.error].filter(Boolean).join(' — ') }),
      kpi('Журнал аудита', ms.audit_size == null ? '—' : fmtBytes(ms.audit_size), { foot: ms.audit_log || '' })),
    !ready ? card('Установка', h('div', {},
      h('p', {}, 'Debian и Ubuntu — модуль и правила есть в стандартных репозиториях:'),
      h('div', { class: 'row', style: { gap: '8px' } }, h('code', { class: 'code' }, 'sudo ' + (ms.install || 'apt install libnginx-mod-http-modsecurity modsecurity-crs')), copyBtn(() => 'sudo ' + (ms.install || ''), 'Копировать')),
      h('p', { class: 'small muted mt' }, 'RHEL, Rocky, AlmaLinux — пакеты nginx-mod-modsecurity (EPEL или репозиторий nginx) и mod_security_crs. После установки откройте эту вкладку снова и примените конфигурацию.')), { cls: 'mb' }) : null,
    card('Настройки', h('div', {}, form, can('admin') ? h('div', { class: 'row mt' }, h('button', { class: 'btn primary', onclick: async () => {
      try { await saveSettings(obj, 'Настройки глубокой проверки сохранены'); errors = {}; } catch (e) { errors = errorsToMap(e); drawForm(); }
    } }, icon('check'), 'Сохранить')) : null), { sub: 'для одного сайта — вкладка «Защита от атак» в редакторе сайта: режим, исключённые пути, отключённые правила' }),
    an ? cc.el : null,
    h('div', { class: 'grid g2 mt' },
      card('Группы правил CRS', table([
        { title: 'Номера', render: (r) => h('code', {}, r[0] + 'xxx') }, { title: 'Что ловят', render: (r) => r[1] },
        { title: 'Срабатываний за неделю', num: true, render: (r) => fmtInt(groups[r[0]] || 0) },
      ], Object.entries(ms.groups || {}).filter(([k]) => k !== '200')), { flush: true }),
      card('Чаще всего срабатывают', msRules.length ? table([
        { title: 'Правило', render: (r) => h('a', { href: '#', onclick: (e) => { e.preventDefault(); openRule(r.kind, r.rule, { sites }); } }, r.title) },
        { title: 'Раз', num: true, render: (r) => fmtInt(r.n) }, { title: 'Адресов', num: true, render: (r) => fmtInt(r.ips) },
      ], msRules.slice(0, 15)) : empty('Пока не срабатывало', ready ? 'Срабатывания появятся после включения и применения конфигурации' : 'Сначала установите модуль и правила', null, 'shield'), { flush: !!msRules.length, sub: 'ложное срабатывание — откройте правило и отключите его' })));
  if (an && msRules.length) {
    stackedChart(cc, charts, an.since, an.step, 168, (an.series.kind || []).filter(r => r.key === 'modsec').map(r => ({ b: r.b, key: r.key, n: r.n })), (k) => an.kinds_titles[k] || k, KIND_ORDER);
  } else if (an) cc.canvas.replaceWith(empty('Нет срабатываний за неделю'));
}

// ================================================================ Правила ограничения частоты
export function rateRulesCard(cfg, sites, reload) {
  const obj = structuredClone(cfg.settings);
  const list = obj.rate_rules || [];
  const edit = (idx) => {
    const r = idx == null ? { name: '', enabled: true, sites: [], path: '/', methods: [], rate: '60r/m', burst: 10 } : structuredClone(list[idx]);
    let errors = {};
    const form = h('div', {});
    const draw = () => { mount(form); renderFields(form, model('rate_rule').filter(f => f.key !== 'id'), r, { root: r, errors, sites, rerender: draw }); };
    draw();
    const m = modal({ title: idx == null ? 'Новое правило частоты' : `Правило «${r.name}»`, size: 'lg', body: h('div', { class: 'col' },
      h('div', { class: 'small muted' }, 'Каждый адрес отдельно: не больше заданного числа запросов к пути; сверх частоты и запаса — ответ 429. Например: поиск — 30r/m, API — 10r/s, форма заказа — 5r/m.'), form),
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
      const next = structuredClone(list);
      if (idx == null) next.push(r); else next[idx] = r;
      try { await saveSettings({ ...obj, rate_rules: next }, 'Правило частоты сохранено'); m.close(); reload(); } catch (e) { errors = errorsToMap(e); draw(); }
    } }, icon('check'), 'Сохранить')] });
  };
  const siteNames = (ids) => !ids.length ? 'все сайты' : ids.map(id => (sites.find(s => s.id === id) || {}).name || id).join(', ');
  return card(`Правила ограничения частоты (${list.length})`, list.length ? table([
    { title: 'Название', render: (r) => h('span', {}, r.enabled ? '' : badge('выкл'), ' ', h('b', {}, r.name)) },
    { title: 'Запросы', render: (r) => h('span', { class: 'small' }, (r.methods.length ? r.methods.join(', ') : 'любые') + ' ', h('code', {}, r.path)) },
    { title: 'Лимит с IP', render: (r) => h('span', { class: 'nowrap' }, r.rate.replace('r/s', ' в секунду').replace('r/m', ' в минуту'), r.burst ? h('span', { class: 'muted small' }, ` + запас ${r.burst}`) : '') },
    { title: 'Сайты', render: (r) => h('span', { class: 'small' }, siteNames(r.sites)) },
    { title: '', srTitle: 'Действия', render: (r) => can('admin') ? h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
      h('button', { class: 'btn sm', onclick: () => edit(list.indexOf(r)) }, icon('edit'), 'Изменить'),
      h('button', { class: 'btn sm danger', 'aria-label': `Удалить правило ${r.name}`, onclick: async () => {
        if (!await confirmDlg(`Удалить правило «${r.name}»?`, { danger: true, ok: 'Удалить' })) return;
        await saveSettings({ ...obj, rate_rules: list.filter(x => x !== r) }, 'Правило удалено'); reload();
      } }, icon('trash'))) : null },
  ], list) : empty('Правил частоты нет', 'Ограничьте частоту для поиска, API, форм заказа и регистрации — отдельно от общего лимита сайта', can('admin') ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить правило частоты') : null, 'activity'),
  { flush: !!list.length, cls: 'mt', sub: 'как Rate Limiting Rules в Cloudflare и rate-based rules в AWS WAF', actions: can('admin') && list.length ? h('button', { class: 'btn primary', onclick: () => edit(null) }, icon('plus'), 'Добавить') : null });
}
