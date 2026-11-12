// Аналитика: доступность сайтов (SLA, бюджет ошибок) и тепловая карта нагрузки «день недели × час».
import { api } from '../api.js';
import { h, mount, card, fmtInt, fmtNum, fmtMs, fmtCompact, table, segmented, loading, empty, badge } from '../ui.js';

const DAYS = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];
const DAYS_FULL = ['понедельник', 'вторник', 'среда', 'четверг', 'пятница', 'суббота', 'воскресенье'];
// последовательная шкала: один синий тон, 7 ступеней (100 → 700); в тёмной теме — наоборот
const RAMP = ['#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b'];
const isDark = () => document.documentElement.dataset.theme === 'dark';
const ramp = () => (isDark() ? [...RAMP].reverse() : RAMP);

const pct = (v, d = 2) => v == null ? '—' : fmtNum(v, d) + '%';

// ---------------------------------------------------------------- доступность (SLA)
const SLOS = [['99', '99%'], ['99.5', '99,5%'], ['99.9', '99,9%'], ['99.95', '99,95%']];

function dayState(avail, slo) {
  if (avail == null) return 'none';
  if (avail >= slo) return 'ok';
  return avail >= slo - (100 - slo) * 4 ? 'warn' : 'bad';  // немного ниже цели — «внимание», сильно — «нарушение»
}
const STATE_TEXT = { ok: 'цель выполнена', warn: 'немного ниже цели', bad: 'ниже цели', none: 'нет запросов' };

function strip(days, slo) {
  return h('div', { class: 'sla-strip', role: 'img', 'aria-label': 'Доступность по дням' },
    days.map(d => {
      const s = dayState(d.avail, slo);
      const date = new Date(d.ts * 1000).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', weekday: 'short' });
      return h('span', { class: 'sla-day ' + s, tabindex: 0,
        title: `${date}: ${d.avail == null ? 'нет запросов' : pct(d.avail, 3) + ` — ${STATE_TEXT[s]}`}` +
          (d.req ? `\nзапросов ${fmtInt(d.req)}, ошибок 5xx ${fmtInt(d.s5)}` : '') });
    }));
}

function budgetCell(x) {
  if (x.budget_left == null) return h('span', { class: 'muted' }, '—');
  const left = x.budget_left;
  const cls = left <= 0 ? 'bad' : left < 25 ? 'warn' : 'ok';
  return h('div', { class: 'budget', title: `Допустимо ошибок 5xx за 30 дней: ${fmtInt(x.allowed_30)}, было: ${fmtInt(x.s5_30)}` },
    h('div', { class: 'budget-bar' }, h('span', { class: cls, style: { width: Math.max(0, Math.min(100, left)) + '%' } })),
    h('span', { class: 'small' + (left <= 0 ? ' status-5' : '') }, left <= 0 ? 'исчерпан' : `осталось ${fmtNum(left, 0)}%`));
}

export async function renderSla(box) {
  let slo = localStorage.getItem('nm-slo') || '99.9';
  const head = h('div', { class: 'toolbar' });
  const body = h('div', {}, loading());
  mount(box, head, body);
  async function load() {
    mount(head, h('span', { class: 'muted small' }, 'Цель (SLO):'),
      segmented(SLOS, slo, (v) => { slo = v; localStorage.setItem('nm-slo', v); load(); }),
      h('span', { class: 'muted small' }, 'Доступность — доля ответов без ошибок 5xx; дни — по времени сервера.'));
    const r = await api('/stats/sla', { query: { days: 30, slo } });
    const s = +slo;
    if (!r.sites.length) { mount(body, empty('Нет данных', 'Доступность появится, когда через nginx пройдут первые запросы.', null, 'chart')); return; }
    const val = (v) => h('span', { class: v == null ? 'muted' : v >= s ? '' : 'status-5' }, pct(v, v != null && v < 99.99 ? 2 : 3));
    mount(body, h('div', { class: 'card' },
      table([
        { title: 'Сайт', render: (x) => h('div', {}, h('b', {}, x.name), x.site === '*' ? h('div', { class: 'muted small' }, 'все запросы вместе') : null) },
        { title: '24 часа', num: true, render: (x) => val(x.a1) },
        { title: '7 дней', num: true, render: (x) => val(x.a7) },
        { title: '30 дней', num: true, render: (x) => val(x.a30) },
        { title: 'Бюджет ошибок (30 дн.)', render: budgetCell },
        { title: 'По дням (30)', render: (x) => strip(x.days, s) },
        { title: 'Дней ниже цели', num: true, render: (x) => x.breached_days ? h('b', { class: 'status-5' }, x.breached_days) : '0' },
        { title: 'Худший день', render: (x) => x.worst ? h('span', { class: 'small' }, new Date(x.worst.ts * 1000).toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' }), ' · ', pct(x.worst.avail, 2)) : '—' },
      ], r.sites, { rowClass: (x) => x.site === '*' ? 'total' : '' }),
      h('div', { class: 'sla-legend' },
        ['ok', 'warn', 'bad', 'none'].map(k => h('span', {}, h('i', { class: 'sla-day ' + k }), STATE_TEXT[k])),
        h('span', { class: 'muted' }, `Бюджет ошибок: сколько ошибок 5xx ещё можно допустить за 30 дней, не нарушив цель ${slo.replace('.', ',')}%.`))));
  }
  await load();
}

// ---------------------------------------------------------------- тепловая карта
const METRICS = [
  ['req', 'Запросы', (c) => c.n ? c.req / c.n : null, (v) => `${fmtCompact(v)} запросов в час`],
  ['err', 'Ошибки 5xx', (c) => c.req ? c.s5 / c.req * 100 : null, (v) => `${fmtNum(v, 2)}% ответов 5xx`],
  ['rt', 'Время ответа', (c) => c.req ? c.rt / c.req * 1000 : null, (v) => `среднее время ответа ${fmtMs(v)}`],
];

export async function renderHeatmap(box, site) {
  let weeks = localStorage.getItem('nm-hm-weeks') || '4';
  let metric = localStorage.getItem('nm-hm-metric') || 'req';
  const head = h('div', { class: 'toolbar' });
  const body = h('div', {}, loading());
  mount(box, head, body);
  let rows = null;
  async function load() {
    rows = await api('/stats/heatmap', { query: { weeks, site } });
    draw();
  }
  function draw() {
    mount(head, segmented(METRICS.map(([k, l]) => [k, l]), metric, (v) => { metric = v; localStorage.setItem('nm-hm-metric', v); draw(); }),
      segmented([['1', '1 неделя'], ['4', '4 недели'], ['12', '12 недель']], weeks, (v) => { weeks = v; localStorage.setItem('nm-hm-weeks', v); load(); }),
      h('span', { class: 'muted small' }, 'Среднее за час по дням недели, в часовом поясе браузера.'));
    if (!rows.length) { mount(body, empty('Нет данных', 'Почасовая статистика за выбранный период пуста.', null, 'chart')); return; }
    // ячейки: [день][час] → сумма значений и число часов с данными
    const cells = Array.from({ length: 7 }, () => Array.from({ length: 24 }, () => ({ req: 0, s5: 0, rt: 0, n: 0 })));
    for (const [ts, req, s5, rt] of rows) {
      const d = new Date(ts * 1000);
      const c = cells[(d.getDay() + 6) % 7][d.getHours()];
      c.req += req; c.s5 += s5; c.rt += rt; c.n += 1;
    }
    const [, label, valueOf, fmt] = METRICS.find(m => m[0] === metric);
    const vals = cells.flat().map(valueOf).filter(v => v != null).sort((a, b) => a - b);
    // верхняя граница шкалы — 97-й перцентиль: единичный всплеск (нагрузочный тест, атака) не «гасит» остальную карту
    const min = vals.length ? vals[0] : 0;
    const top = vals.length ? vals[vals.length - 1] : 0;
    const max = vals.length ? Math.max(min, vals[Math.min(vals.length - 1, Math.floor(vals.length * 0.97))]) : 0;
    const clipped = top > max * 1.5;
    const colors = ramp();
    const bin = (v) => max === min ? colors.length - 1 : Math.max(0, Math.min(colors.length - 1, Math.floor((v - min) / (max - min) * colors.length)));
    let peak = null, low = null;
    cells.forEach((row, d) => row.forEach((c, hr) => {
      const v = valueOf(c);
      if (v == null) return;
      if (!peak || v > peak.v) peak = { d, hr, v };
      if (!low || v < low.v) low = { d, hr, v };
    }));
    const hour = (x) => String(x).padStart(2, '0') + ':00';
    const grid = h('div', { class: 'heatmap', role: 'grid', 'aria-label': `Тепловая карта: ${label}` },
      h('span', {}), Array.from({ length: 24 }, (_, i) => h('span', { class: 'hm-h' }, i % 3 === 0 ? String(i) : '')),
      cells.map((row, d) => [h('span', { class: 'hm-d' }, DAYS[d]), row.map((c, hr) => {
        const v = valueOf(c);
        const tip = `${DAYS_FULL[d]}, ${hour(hr)}–${hour((hr + 1) % 24)}: ${v == null ? 'нет данных' : fmt(v)}` + (c.n ? ` (часов в выборке: ${c.n})` : '');
        return h('span', { class: 'hm-c' + (v == null ? ' none' : ''), style: v == null ? null : { background: colors[bin(v)] }, title: tip, tabindex: 0, 'aria-label': tip });
      })]));
    const step = (max - min) / colors.length;
    const digits = step < 0.01 ? 3 : step < 0.1 ? 2 : 1;  // шаги легенды должны различаться
    const fv = (v) => metric === 'req' ? fmtCompact(v) : metric === 'err' ? fmtNum(v, digits) + '%' : fmtMs(v);
    const legend = h('div', { class: 'hm-legend' }, h('span', { class: 'muted small' }, label + ':'),
      colors.map((col, i) => h('span', { class: 'hm-l' }, h('i', { style: { background: col } }),
        h('span', { class: 'small' }, (i === 0 ? 'от ' : i === colors.length - 1 && clipped ? '≥ ' : '') + fv(min + step * i)))),
      h('span', { class: 'hm-l' }, h('i', { class: 'none' }), h('span', { class: 'small' }, 'нет данных')));
    mount(body, card(`${label} по дням недели и часам`, h('div', {}, grid, legend,
      peak ? h('div', { class: 'row mt', style: { gap: '18px', flexWrap: 'wrap' } },
        h('span', {}, badge('пик', 'outline'), ' ', `${DAYS_FULL[peak.d]}, ${hour(peak.hr)} — ${fmt(peak.v)}`),
        h('span', {}, badge('минимум', 'outline'), ' ', `${DAYS_FULL[low.d]}, ${hour(low.hr)} — ${fmt(low.v)}`),
        metric === 'req' ? h('span', { class: 'muted small' }, 'Минимум нагрузки — удобное время для работ и перезапусков.') : null) : null),
    { sub: `${rows.length} часов статистики · ${weeks} нед.` }));
  }
  await load();
}
