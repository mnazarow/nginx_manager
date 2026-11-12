// Автоматическая диагностика с рекомендациями и исправлениями в один клик.
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, fmtAgo, fmtNum, kpi, confirmDlg } from '../ui.js';
import { can, refreshState } from '../app.js';

const ICON = { ok: '✓', warn: '!', fail: '✕', info: 'i', skip: '–' };

export async function render(root) {
  let data = await api('/diagnostics');
  let onlyProblems = false;
  const head = h('div', {});
  const box = h('div', {});
  const runBtn = h('button', { class: 'btn primary', onclick: () => run() }, icon('refresh'), 'Запустить диагностику');
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Диагностика'),
      h('p', {}, 'Около 40 проверок: nginx и его модули, конфигурация, порты и конфликты, DNS доменов, доступность бэкендов, сертификаты, firewall, SELinux, ресурсы сервера, лимиты, журналы, анализ ошибок и трафика, безопасность. Фоновая проверка выполняется автоматически.')),
      h('div', { class: 'row' }, h('label', { class: 'switch small' }, h('input', { type: 'checkbox', onchange: (e) => { onlyProblems = e.target.checked; draw(); } }), h('span', { class: 'track' }), 'Только проблемы'), runBtn)),
    head, box);

  async function run() {
    runBtn.disabled = true; mount(runBtn, h('span', { class: 'spinner' }), ' Проверка…');
    try { data = await api('/diagnostics/run', { method: 'POST' }); draw(); refreshState(); }
    finally { runBtn.disabled = false; mount(runBtn, icon('refresh'), 'Запустить диагностику'); }
  }
  function draw() {
    const s = data.summary || {};
    mount(head, h('div', { class: 'grid g4 mb' },
      kpi('Ошибки', String(s.fail || 0), { cls: s.fail ? 'bad' : '', foot: 'требуют действий' }),
      kpi('Предупреждения', String(s.warn || 0), { cls: s.warn ? 'warn' : '', foot: 'стоит проверить' }),
      kpi('В порядке', String(s.ok || 0), { foot: 'проверок пройдено' }),
      kpi('Последний запуск', data.ts ? fmtAgo(data.ts) : '—', { foot: data.duration ? `за ${fmtNum(data.duration, 1)} с` + (data.total ? ` · проверок: ${data.total}` : '') : '' })));
    if (!data.results || !data.results.length) { mount(box, h('div', { class: 'card' }, h('div', { class: 'empty' }, 'Диагностика ещё не запускалась', h('div', { class: 'mt' }, h('button', { class: 'btn primary', onclick: run }, 'Запустить'))))); return; }
    const groups = {};
    for (const r of data.results) {
      if (onlyProblems && !['warn', 'fail'].includes(r.status)) continue;
      (groups[r.group] ||= []).push(r);
    }
    const order = (g) => { const st = groups[g].map(r => r.status); return st.includes('fail') ? 0 : st.includes('warn') ? 1 : 2; };
    mount(box, Object.keys(groups).length ? Object.keys(groups).sort((a, b) => order(a) - order(b)).map(g => {
      const items = groups[g];
      // свёрнутая строка «Ещё N проверок» считается за N
      const cnt = (st) => items.filter(x => x.status === st).reduce((a, x) => a + (x.folded || 1), 0);
      const f = cnt('fail'), w = cnt('warn');
      return h('div', { class: 'card mb' }, h('div', { class: 'card-head' }, h('h3', {}, g), h('div', { class: 'row' }, f ? badge(`ошибок: ${f}`, 'bad') : null, w ? badge(`предупреждений: ${w}`, 'warn') : null, !f && !w ? badge('в порядке', 'good') : null)),
        h('div', { class: 'card-body flush', style: { marginTop: '10px' } }, items.map(item)));
    }) : h('div', { class: 'alert good' }, 'Проблем не обнаружено 🎉'));
  }
  function item(r) {
    return h('div', { class: 'diag-item' },
      h('div', { class: 'ic ' + r.status, title: r.status }, ICON[r.status]),
      h('div', {}, h('div', {}, h('b', {}, r.title), r.message ? h('span', { class: 'ink2' }, ' — ', r.message) : null),
        r.hint && r.status !== 'ok' ? h('div', { class: 'hint' }, '💡 ', r.hint) : null,
        r.details ? h('details', {}, h('summary', { class: 'muted' }, 'Подробности'),
          h('pre', { class: 'code mt-s', style: { whiteSpace: 'pre-wrap', maxHeight: '260px' } }, typeof r.details === 'string' ? r.details : JSON.stringify(r.details, null, 2))) : null),
      r.fix && can('operator') && ['warn', 'fail', 'info'].includes(r.status) ? h('button', { class: 'btn sm ' + (r.status === 'fail' ? 'primary' : ''), onclick: (e) => fix(r, e.currentTarget) }, icon('wrench'), r.fix_label || 'Исправить') : h('span'));
  }
  async function fix(r, btn) {
    if (!await confirmDlg(`Выполнить исправление «${r.fix_label}»?\n\n${r.title}: ${r.message}`, { ok: 'Выполнить' })) return;
    btn.disabled = true;
    try {
      const res = await api('/diagnostics/fix', { method: 'POST', body: { action: r.fix, args: r.fix_args || {} } });
      toast(res.ok ? 'Готово' : 'Не удалось', res.ok ? 'good' : 'bad', r.fix_label);
      if (res.output) modal({ title: r.fix_label, size: 'lg', body: h('pre', { class: 'code' }, res.output) });
      await run();
    } catch { btn.disabled = false; }
  }
  draw();
  if (!data.ts || Date.now() / 1000 - data.ts > 300) run();
}
