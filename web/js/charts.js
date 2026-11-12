// Обёртки Chart.js: единый стиль (тонкие линии, «волосяная» сетка, перекрестие, подсказка по всем сериям).
/* global Chart */
import { h, fmtTime, fmtDate } from './ui.js';

export function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
export const SERIES = ['--s1', '--s2', '--s3', '--s4', '--s5', '--s6', '--s7', '--s8'];
export function seriesColor(i) { return css(SERIES[i % SERIES.length]); }
// Классы ответов — статусная палитра (значение «хорошо/плохо»), 3xx — нейтральный синий
export function statusColors() {
  return { s2: '#0ca30c', s3: css('--s1'), s4: '#fab219', s5: '#d03b3b' };
}
export function alpha(hex, a) {
  if (!hex.startsWith('#')) return hex;
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

const crosshair = {
  id: 'nmCrosshair',
  afterDatasetsDraw(chart) {
    const act = chart.tooltip && chart.tooltip.getActiveElements && chart.tooltip.getActiveElements();
    if (!act || !act.length || chart.config.type === 'doughnut') return;
    const x = act[0].element.x, { top, bottom } = chart.chartArea, ctx = chart.ctx;
    ctx.save(); ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom);
    ctx.lineWidth = 1; ctx.strokeStyle = css('--axis'); ctx.stroke(); ctx.restore();
  },
};

let registered = false;
function setup() {
  if (registered || !window.Chart) return;
  registered = true;
  Chart.register(crosshair);
  Chart.defaults.font.family = css('--font') || 'system-ui';
  Chart.defaults.font.size = 11;
  Chart.defaults.animation = false;
  Chart.defaults.maintainAspectRatio = false;
}

export function themeChart(chart) {
  const grid = css('--line'), ink = css('--muted'), axis = css('--axis');
  for (const s of Object.values(chart.options.scales || {})) {
    if (s.grid) { s.grid.color = grid; s.grid.drawTicks = false; }
    if (s.border) s.border.color = axis;
    if (s.ticks) s.ticks.color = ink;
  }
  const tt = chart.options.plugins.tooltip;
  tt.backgroundColor = css('--ink'); tt.titleColor = css('--surface'); tt.bodyColor = css('--surface');
}

/**
 * Временной ряд. series: [{key, label, color, fill, stack, dash}]
 * opts: {yFmt, stacked, type:'line'|'bar', xFmt, min0, legendEl}
 */
export function timeChart(canvas, series, opts = {}) {
  setup();
  const type = opts.type || 'line';
  const datasets = series.map(s => ({
    label: s.label, data: [], borderColor: s.color, backgroundColor: s.fill ? alpha(s.color, opts.stacked ? 0.55 : 0.12) : s.color,
    borderWidth: type === 'bar' ? 0 : 2, pointRadius: 0, pointHoverRadius: 4, pointHitRadius: 12, tension: 0.25,
    fill: s.fill ? (opts.stacked ? (s.first ? 'origin' : '-1') : 'origin') : false, stack: opts.stacked ? 'a' : undefined,
    borderDash: s.dash || undefined, borderRadius: type === 'bar' ? 3 : 0, spanGaps: true,
    barPercentage: 0.9, categoryPercentage: 0.95, hidden: !!s.hidden,
  }));
  if (opts.stacked && type === 'line' && datasets.length) datasets[0].fill = 'origin';
  const xFmt = opts.xFmt || ((ts) => fmtTime(ts, opts.seconds !== false));
  const chart = new Chart(canvas, {
    type, data: { labels: [], datasets },
    options: {
      responsive: true, interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          displayColors: true, boxWidth: 10, boxHeight: 2, usePointStyle: false, padding: 9, cornerRadius: 6,
          callbacks: {
            title: (items) => items.length ? (opts.tipTitle ? opts.tipTitle(+items[0].label) : fmtDate(+items[0].label, { sec: true })) : '',
            label: (it) => ` ${(opts.yFmt || String)(it.parsed.y)}  ${it.dataset.label}`,
          },
          itemSort: (a, b) => a.datasetIndex - b.datasetIndex,
        },
      },
      scales: {
        x: { stacked: !!opts.stacked, grid: { display: false }, border: { display: true },
          ticks: { autoSkip: true, maxTicksLimit: opts.maxTicks || 7, maxRotation: 0, callback(v) { return xFmt(+this.getLabelForValue(v)); } } },
        y: { stacked: !!opts.stacked, beginAtZero: opts.min0 !== false, grid: { display: true }, border: { display: false },
          suggestedMax: opts.suggestedMax, max: opts.max,
          ticks: { maxTicksLimit: 5, callback: (v) => (opts.yFmt || String)(v) } },
      },
    },
  });
  themeChart(chart);
  chart.$series = series;
  if (opts.legendEl) renderLegend(opts.legendEl, series, type === 'bar' || opts.stacked ? 'box' : 'line', chart);
  return chart;
}

export function setData(chart, labels, arrays) {
  chart.data.labels = labels;
  arrays.forEach((a, i) => { if (chart.data.datasets[i]) chart.data.datasets[i].data = a; });
  chart.update('none');
}

export function renderLegend(el, series, kind = 'line', chart = null) {
  if (series.length < 2) { el.innerHTML = ''; return; }
  el.innerHTML = '';
  series.forEach((s, i) => {
    const item = h('span', { style: { cursor: chart ? 'pointer' : 'default', opacity: s.hidden ? .4 : 1 } },
      h('i', { class: kind === 'box' ? 'box' : '', style: { background: s.color } }), s.label);
    if (chart) item.addEventListener('click', () => {
      const meta = chart.getDatasetMeta(i); meta.hidden = !meta.hidden; s.hidden = meta.hidden;
      item.style.opacity = meta.hidden ? .4 : 1; chart.update('none');
    });
    el.appendChild(item);
  });
}

export function barChart(canvas, labels, values, opts = {}) {
  setup();
  const color = opts.color || seriesColor(0);
  const chart = new Chart(canvas, {
    type: 'bar',
    data: { labels, datasets: [{ label: opts.label || '', data: values, backgroundColor: opts.colors || color, borderRadius: 4, borderSkipped: 'start',
      barPercentage: 0.8, categoryPercentage: 0.9, maxBarThickness: 36 }] },
    options: {
      indexAxis: opts.horizontal ? 'y' : 'x', responsive: true,
      plugins: { legend: { display: false }, tooltip: { displayColors: false, padding: 9, cornerRadius: 6,
        callbacks: { label: (it) => ` ${(opts.fmt || String)(it.parsed[opts.horizontal ? 'x' : 'y'])}` } } },
      scales: {
        x: { grid: { display: !!opts.horizontal }, border: { display: !opts.horizontal }, ticks: { maxRotation: 0, autoSkip: true,
          callback: opts.horizontal ? (v) => (opts.fmt || String)(v) : function (v) { const l = this.getLabelForValue(v); return String(l).length > 14 ? String(l).slice(0, 13) + '…' : l; } },
          beginAtZero: true },
        y: { grid: { display: !opts.horizontal }, border: { display: false }, beginAtZero: true,
          ticks: { maxTicksLimit: 5, callback: opts.horizontal ? function (v) { const l = this.getLabelForValue(v); return String(l).length > 22 ? String(l).slice(0, 21) + '…' : l; } : (v) => (opts.fmt || String)(v) } },
      },
    },
  });
  themeChart(chart);
  return chart;
}

export function destroyAll(list) { list.forEach(c => { try { c.destroy(); } catch { /* */ } }); list.length = 0; }

export function chartCard(title, { sub = '', legend = true, cls = 'chart-box', actions = null } = {}) {
  const canvas = h('canvas');
  const legendEl = h('div', { class: 'legend' });
  const el = h('div', { class: 'card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, title), sub ? h('div', { class: 'sub' }, sub) : null), actions),
    legend ? legendEl : null,
    h('div', { class: 'card-body', style: { paddingTop: '6px' } }, h('div', { class: cls }, canvas)));
  return { el, canvas, legendEl };
}

// Сегментированная полоса (доли целого, ≤ 6 частей) с легендой
export function segBar(parts, fmt = String) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return h('div', {},
    h('div', { class: 'seg-bar' }, parts.filter(p => p.value > 0).map(p => h('div', {
      style: { width: (p.value / total * 100) + '%', background: p.color }, title: `${p.label}: ${fmt(p.value)} (${(p.value / total * 100).toFixed(1)}%)` }))),
    h('div', { class: 'legend', style: { padding: '8px 0 0' } }, parts.map(p => h('span', {}, h('i', { class: 'box', style: { background: p.color } }),
      `${p.label} — ${fmt(p.value)} (${(p.value / total * 100).toFixed(1)}%)`))));
}
