// Состояние бэкендов: активные проверки, задержка, доступность, история.
import { api } from '../api.js';
import { h, mount, icon, badge, stateBadge, fmtMs, fmtAgo, fmtPct, fmtDur, toast, card, kpi, table, segmented, debounce } from '../ui.js';
import { hintKpi } from '../advice.js';

const isProblem = (x) => x.state === 'down' || (x.uptime_pct != null && x.uptime_pct < 99);

function timeline(x) {
  return h('div', { class: 'timeline', style: { width: '200px' }, title: 'Зелёный — успешно, красный — ошибка' },
    Array.from({ length: Math.max(0, 40 - x.history.length) }, () => h('span', { class: 'n' })),
    x.history.slice(-40).map(([ts, ok, ms]) => h('span', { class: ok ? '' : 'f', title: `${new Date(ts * 1000).toLocaleTimeString('ru-RU')}: ${ok ? fmtMs(ms) : 'ошибка'}` })));
}

export async function render(root) {
  const box = h('div', {});
  const kp = h('div', { class: 'grid g4 mb' });
  let timer, last = null, q = '', only = 'all';
  let view = localStorage.getItem('nm-backends-view') || '';
  const search = h('input', { type: 'search', placeholder: 'Сайт, локация, адрес сервера…' });
  search.addEventListener('input', debounce(() => { q = search.value.trim().toLowerCase(); draw(); }, 150));
  const filt = h('span', {});
  const viewSw = h('span', {});
  const count = h('span', { class: 'muted small' });
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Бэкенды'),
      h('p', {}, 'Панель сама опрашивает каждый сервер бэкенда (HTTP-запрос на путь проверки или TCP-подключение). Nginx дополнительно исключает сервер при ошибках (max_fails/fail_timeout) — эти события видны в «Пассивных ошибках».')),
      h('button', { class: 'btn', onclick: async () => { await api('/health/check', { method: 'POST', body: { key: null } }); toast('Проверка выполнена', 'good'); load(); } }, icon('refresh'), 'Проверить все')),
    kp, h('div', { class: 'toolbar' }, search, filt, viewSw, count), box);
  async function load() {
    last = await api('/health');
    draw();
    clearTimeout(timer);
    timer = setTimeout(load, 5000);
  }
  function draw() {
    const r = last;
    const t = r.targets;
    const active = t.filter(x => x.state !== 'disabled');
    const lat = active.filter(x => x.state === 'up').map(x => x.latency_ms);
    const downN = active.filter(x => x.state === 'down').length;
    const avgLat = lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : null;
    const ups = active.filter(x => x.uptime_pct != null).map(x => x.uptime_pct);
    const minUp = ups.length ? Math.min(...ups) : null;
    const K = [kpi('Доступны', String(active.filter(x => x.state === 'up').length), { foot: `из ${active.length} проверяемых` }),
      kpi('Недоступны', String(downN), { foot: 'по активной проверке' }),
      kpi('Средняя задержка', avgLat != null ? fmtMs(avgLat) : '—', { foot: 'время ответа на проверку' }),
      kpi('Худшая доступность', minUp != null ? fmtPct(minUp, 2) : '—', { foot: `пассивных ошибок: ${Object.values(r.passive).reduce((a, b) => a + b, 0)}` })];
    mount(kp, K);
    hintKpi(K[1], 'backends_down', downN, { text: String(downN) });
    hintKpi(K[2], 'backend_latency', avgLat, { text: avgLat != null ? fmtMs(avgLat) : '—' });
    hintKpi(K[3], 'uptime', minUp, { text: minUp != null ? fmtPct(minUp, 2) : '—' });
    const groups = {};
    t.forEach(x => (groups[x.owner] ||= { owner: x.owner, name: x.owner_name, kind: x.owner.split(':')[0], items: [] }).items.push(x));
    const all = Object.values(groups);
    const nProblem = all.filter(g => g.items.some(isProblem)).length;
    // проблемные группы наверх, затем по худшей доступности и имени
    const worst = (g) => Math.min(...g.items.map(x => x.state === 'down' ? -1 : x.uptime_pct ?? 100));
    all.sort((a, b) => worst(a) - worst(b) || a.name.localeCompare(b.name, 'ru'));
    const match = (g) => !q || g.name.toLowerCase().includes(q) || g.items.some(x => `${x.address}:${x.port}`.includes(q));
    const shown = all.filter(g => match(g) && (only === 'all' || g.items.some(isProblem)));
    const mode = view || (all.length > 20 ? 'table' : 'cards');
    mount(filt, segmented([['all', `Все (${all.length})`], ['problems', `С проблемами (${nProblem})`]], only, (v) => { only = v; draw(); }));
    mount(viewSw, segmented([['cards', 'Карточки'], ['table', 'Таблица']], mode, (v) => { view = v; localStorage.setItem('nm-backends-view', v); draw(); }));
    mount(count, shown.length !== all.length ? `показано ${shown.length} из ${all.length}` : '');
    const kindLabel = (g) => g.kind === 'stream' ? 'TCP/UDP-поток' : g.kind === 'loc' ? 'локация с отдельными бэкендами' : 'сайт';
    const cols = [
      { title: 'Сервер', render: (x) => h('div', {}, h('code', {}, `${x.address}:${x.port}`), x.backup ? badge('резерв', 'outline') : null, x.down_cfg ? badge('выключен', 'outline') : null) },
      { title: 'Состояние', render: (x) => h('div', {}, stateBadge(x.state), x.state !== 'disabled' ? h('div', { class: 'muted small' }, 'с ' + fmtAgo(x.since).replace(' назад', '')) : null) },
      { title: 'Проверка', render: (x) => h('span', { class: 'small muted' }, x.type === 'tcp' ? 'TCP' : `${x.scheme.toUpperCase()} ${x.path}`, ` · каждые ${x.interval} с`) },
      { title: 'Задержка', num: true, render: (x) => x.state === 'up' && !x.error ? fmtMs(x.latency_ms) : '—' },
      { title: 'Доступность', num: true, render: (x) => x.uptime_pct == null ? '—' : fmtPct(x.uptime_pct, 2) },
      { title: 'Последние проверки', render: timeline },
      { title: 'Ошибка', render: (x) => x.error ? h('span', { class: 'small status-5' }, x.error) : h('span', { class: 'muted small' }, x.status ? 'HTTP ' + x.status : '') },
      { title: 'Проверено', render: (x) => h('span', { class: 'muted small' }, x.last_check ? fmtAgo(x.last_check) : '—') },
    ];
    let body;
    if (!all.length) body = h('div', { class: 'card' }, h('div', { class: 'empty' }, 'Нет бэкендов. Они появятся после добавления сайтов с типом «Прокси» и применения конфигурации.'));
    else if (!shown.length) body = h('div', { class: 'card' }, h('div', { class: 'empty' }, only === 'problems' && !q ? 'Проблем нет — все серверы отвечают.' : 'Ничего не найдено'));
    else if (mode === 'table') {
      const rows = shown.flatMap(g => g.items.map(x => ({ ...x, _g: g })));
      body = h('div', { class: 'card' }, table([
        { title: 'Сайт / поток', render: (x) => h('div', {}, h('b', {}, x._g.name), h('div', { class: 'muted small' }, kindLabel(x._g))) },
        ...cols.filter(c => c.title !== 'Проверено'),
      ], rows.slice(0, 1000), { rowClass: (x) => isProblem(x) ? 'problem' : '' }),
      rows.length > 1000 ? h('div', { class: 'muted small', style: { padding: '8px 12px' } }, `Показаны первые 1000 серверов из ${rows.length} — уточните поиск.`) : null);
    } else {
      body = shown.slice(0, 200).map(g => h('div', { class: 'card mb' },
        h('div', { class: 'card-head' }, h('div', {}, h('h3', {}, g.name), h('div', { class: 'sub' }, kindLabel(g))),
          h('button', { class: 'btn sm', onclick: async () => { await api('/health/check', { method: 'POST', body: { key: g.owner } }); load(); } }, icon('refresh'), 'Проверить')),
        h('div', { class: 'card-body flush' }, table(cols, g.items))));
    }
    mount(box, body,
      Object.keys(r.passive).length ? card('Пассивные ошибки (из журнала nginx)', table([
        { title: 'Бэкенд', render: (x) => h('code', {}, x[0]) }, { title: 'Ошибок соединения', num: true, render: (x) => x[1] }], Object.entries(r.passive)), { flush: true }) : null);
  }
  await load();
  return () => clearTimeout(timer);
}
