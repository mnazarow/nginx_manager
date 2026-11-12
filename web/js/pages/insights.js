// Анализ и подсказки: найденные проблемы по сайтам и серверу, оценка показателей, справочник сценариев.
import { api } from '../api.js';
import { h, mount, icon, badge, kpi, tabs, segmented, loading, empty, fmtNum, fmtMs, fmtPct, fmtInt, debounce } from '../ui.js';
import { ctx } from '../app.js';
import { loadCatalog, findingView, levelOf, metricHint, LEVEL_CLASS, LEVEL_TEXT } from '../advice.js';
import { openHelp } from '../help.js';
import { popover } from '../ui.js';

const RANGES = [['900', '15 мин'], ['3600', '1 час'], ['21600', '6 часов'], ['86400', '24 часа'], ['604800', '7 дней']];

export async function render(root) {
  const [sites, cat] = await Promise.all([api('/sites'), loadCatalog(true)]);
  const st = { range: ctx.params.range || '900', site: ctx.params.site || '*', tab: ctx.params.tab || 'found', q: '', level: '' };
  let res = null, timer = null;
  const kp = h('div', { class: 'grid g4 mb' });
  const tabBar = h('div', {});
  const box = h('div', {});
  const siteSel = h('select', { onchange: (e) => { st.site = e.target.value; load(); } }, h('option', { value: '*' }, 'Все сайты и сервер'),
    sites.map(s => h('option', { value: String(s.id), selected: String(s.id) === st.site }, s.name)));

  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Анализ и подсказки'),
      h('p', {}, `Панель сама проверяет статистику, бэкенды, nginx, сервер, сертификаты и журнал ошибок по ${cat.scenarios.length} сценариям и объясняет, что происходит и что сделать. Щёлкните находку, чтобы раскрыть причины, действия и данные.`)),
      h('button', { class: 'btn', onclick: () => load() }, icon('refresh'), 'Проверить сейчас')),
    h('div', { class: 'toolbar' }, segmented(RANGES, st.range, (v) => { st.range = v; load(); }), siteSel),
    kp, h('div', { class: 'card' }, h('div', { class: 'card-body' }, tabBar, box)));

  async function load() {
    const to = Date.now() / 1000;
    mount(box, loading('Анализ…'));
    res = await api('/insights', { query: { from: to - +st.range, to, site: st.site } });
    draw();
    clearTimeout(timer);
    timer = setTimeout(load, 30000);
  }

  function draw() {
    const c = res.counts;
    mount(kp,
      kpi('Проблемы', fmtInt(c.crit), { cls: c.crit ? 'bad' : '', foot: 'требуют немедленных действий' }),
      kpi('Требуют внимания', fmtInt(c.warn), { cls: c.warn ? 'warn' : '', foot: 'стоит разобраться в ближайшее время' }),
      kpi('К сведению', fmtInt(c.info), { foot: 'рекомендации по улучшению' }),
      kpi('Проверено сценариев', fmtInt(res.checked), { foot: `скрыто типов: ${(cat.muted || []).length}` }));
    mount(tabBar, tabs([
      { id: 'found', label: 'Найдено', badge: (c.crit + c.warn + c.info) || null, badgeKind: c.crit ? 'bad' : c.warn ? 'warn' : '' },
      { id: 'metrics', label: 'Показатели' },
      { id: 'catalog', label: 'Справочник сценариев', badge: cat.scenarios.length },
      { id: 'muted', label: 'Скрытые', badge: res.muted.length || null },
    ], st.tab, (t) => { st.tab = t; draw(); }));
    if (st.tab === 'found') drawFound();
    else if (st.tab === 'metrics') drawMetrics();
    else if (st.tab === 'catalog') drawCatalog();
    else drawMuted();
  }

  function drawFound() {
    const levels = h('div', {}, segmented([['', 'Все'], ['crit', 'Проблемы'], ['warn', 'Внимание'], ['info', 'К сведению']], st.level, (v) => { st.level = v; drawFound(); }));
    const list = res.findings.filter(f => !st.level || f.level === st.level);
    const groups = {};
    list.forEach(f => (groups[f.group] ||= { title: f.group_title, items: [] }).items.push(f));
    mount(box, h('div', { class: 'mb' }, levels),
      list.length ? Object.values(groups).map(g => h('div', { class: 'mb' }, h('h3', { class: 'group-title' }, g.title),
        h('div', { class: 'card flush-list' }, g.items.map(f => findingView(f, { onChange: () => { loadCatalog(true).then(load); } })))))
        : empty(res.findings.length ? 'Нет находок этого уровня' : 'Проблем не найдено',
          `За выбранный период проверено ${res.checked} сценариев. Анализ повторяется автоматически каждые 30 секунд.`, null, 'check'));
  }

  async function drawMetrics() {
    mount(box, loading());
    const to = Date.now() / 1000;
    const q = { from: to - +st.range, to, site: st.site };
    const [sum, health] = await Promise.all([api('/stats/summary', { query: q }), api('/health')]);
    if (st.tab !== 'metrics') return;
    const latest = res.system || {};
    const n = sum.requests;
    const down = health.targets.filter(t => t.state === 'down').length;
    const rows = [
      ['rps', sum.rps, fmtNum(sum.rps, 2) + ' rps', n],
      ['err5', sum.err5_pct, fmtPct(sum.err5_pct, 2), n],
      ['err4', sum.err4_pct, fmtPct(sum.err4_pct, 1), n],
      ['p95', sum.p95, fmtMs(sum.p95), n],
      ['rt_avg', sum.rt_avg, fmtMs(sum.rt_avg), n],
      ['urt_avg', sum.urt_avg, sum.urt_avg ? fmtMs(sum.urt_avg) : '—', n],
      ['hit_ratio', Object.values(sum.cache || {}).reduce((a, b) => a + b, 0) ? sum.hit_ratio : null, Object.keys(sum.cache || {}).length ? fmtPct(sum.hit_ratio) : 'кэш не используется', Object.values(sum.cache || {}).reduce((a, b) => a + b, 0)],
      ['bots', n ? sum.bots / n * 100 : 0, fmtPct(n ? sum.bots / n * 100 : 0), n],
      ['backends_down', down, String(down), null],
      ['cpu', latest.cpu, latest.cpu != null ? fmtPct(latest.cpu, 0) : '—', null],
      ['mem', latest.mem, latest.mem != null ? fmtPct(latest.mem, 0) : '—', null],
      ['disk', latest.disk, latest.disk != null ? fmtPct(latest.disk, 0) : '—', null],
      ['load', latest.load1 != null ? latest.load1 / (latest.cpus || 1) : null, latest.load1 != null ? fmtNum(latest.load1 / (latest.cpus || 1), 2) : '—', null],
    ];
    mount(box, h('p', { class: 'muted small' }, `Значения за выбранный период (${RANGES.find(r => r[0] === st.range)?.[1]}); ресурсы сервера — текущие. Знак «?» — описание показателя, пороги и рекомендации.`),
      h('div', { class: 'table-wrap' }, h('table', { class: 't' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Показатель'), h('th', { class: 'num' }, 'Значение'), h('th', {}, 'Оценка'), h('th', {}, 'Что это значит'), h('th', {}))),
        h('tbody', {}, rows.map(([id, v, txt, req]) => {
          const m = cat.metrics[id];
          const lv = levelOf(id, v, req);
          const few = m.min_req && req != null && req < m.min_req;
          const btn = h('button', { class: 'kpi-hint', onclick: (e) => { e.stopPropagation(); popover(btn, metricHint(id, v, req, txt)); } }, '?');
          return h('tr', {}, h('td', {}, h('b', {}, m.label)), h('td', { class: 'num' }, txt),
            h('td', {}, m.dir ? badge(few ? 'мало данных' : LEVEL_TEXT[lv], few ? 'outline' : LEVEL_CLASS[lv] || 'good') : h('span', { class: 'muted small' }, 'без порогов')),
            h('td', { class: 'small', style: { maxWidth: '520px' } }, lv === 'ok' ? m.desc : m.advice), h('td', {}, btn));
        })))));
  }

  function drawCatalog() {
    const search = h('input', { type: 'search', placeholder: 'Поиск по сценариям: 502, таймаут, кэш, сертификат…', value: st.q, style: { maxWidth: '420px' } });
    const list = h('div', {});
    const firing = new Set(res.findings.map(f => f.id));
    const muted = new Set(cat.muted || []);
    const drawList = () => {
      const q = st.q.toLowerCase();
      const items = cat.scenarios.filter(s => !q || [s.title, s.when, s.what, ...(s.causes || []), ...(s.actions || [])].join(' ').toLowerCase().includes(q));
      const groups = {};
      items.forEach(s => (groups[s.group] ||= { title: s.group_title, items: [] }).items.push(s));
      mount(list, items.length ? Object.values(groups).map(g => h('div', { class: 'mb' }, h('h3', { class: 'group-title' }, `${g.title} (${g.items.length})`),
        g.items.map(s => h('div', { class: 'scenario' },
          h('h4', {}, s.title, firing.has(s.id) ? badge('сейчас найдено', 'bad') : null, muted.has(s.id) ? badge('скрыто', 'outline') : null),
          h('div', { class: 'when' }, 'Когда: ', s.when),
          h('div', { class: 'small' }, s.what),
          s.causes.length || s.actions.length ? h('details', { class: 'small mt' }, h('summary', {}, 'Причины и действия'),
            h('div', { class: 'grid g2 mt' },
              h('div', {}, h('b', {}, 'Вероятные причины'), h('ul', {}, s.causes.map(x => h('li', {}, x)))),
              h('div', {}, h('b', {}, 'Что сделать'), h('ol', {}, s.actions.map(x => h('li', {}, x)))))) : null,
          s.doc?.page ? h('button', { class: 'btn sm ghost mt', onclick: () => openHelp(s.doc.page, s.doc.section) }, icon('book'), 'Документация') : null))))
        : empty('Ничего не найдено', 'Измените запрос.', null, 'search'));
    };
    search.addEventListener('input', debounce(() => { st.q = search.value.trim(); drawList(); }, 200));
    mount(box, h('p', { class: 'muted small' }, 'Все ситуации, которые распознаёт встроенный анализ, с условиями срабатывания. Тот же справочник — в документации, глава 18.'),
      h('div', { class: 'mb' }, search), list);
    drawList();
  }

  function drawMuted() {
    mount(box, res.muted.length || (cat.muted || []).length ? h('div', {},
      h('p', { class: 'muted small' }, 'Скрытые типы подсказок не показываются в «Найдено», на дашборде и в значке меню. Здесь — скрытые находки за период; вернуть тип можно кнопкой в карточке.'),
      res.muted.length ? h('div', { class: 'card flush-list' }, res.muted.map(f => findingView(f, { onChange: () => { loadCatalog(true).then(load); } })))
        : h('div', { class: 'muted' }, `Скрыто типов: ${(cat.muted || []).length}; за выбранный период они не срабатывали.`))
      : empty('Скрытых подсказок нет', 'Любой тип подсказок можно скрыть кнопкой «Скрыть этот тип» в раскрытой карточке.', null, 'eye'));
  }

  await load();
  return () => clearTimeout(timer);
}
