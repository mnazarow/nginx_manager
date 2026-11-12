// История версий конфигурации: просмотр, сравнение, откат.
import { api } from '../api.js';
import { h, mount, icon, badge, table, modal, fmtDate, confirmDlg, toast, diffBlock, codeBlock, loading, stateBadge, tabs, downloadText } from '../ui.js';
import { can, refreshState } from '../app.js';

const SRC = { user: 'пользователь', cli: 'nmctl', rollback: 'откат', failover: 'автопереключение', certs: 'сертификаты', restore: 'восстановление базы', system: 'система' };

export async function render(root) {
  const list = await api('/config/versions', { query: { limit: 200 } });
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Версии конфигурации'),
      h('p', {}, 'Каждое применение сохраняет полный набор сгенерированных файлов и состояние настроек. Можно сравнить любые версии и откатиться — откат восстанавливает и настройки сайтов в панели.'))),
    h('div', { class: 'card' }, table([
      { title: 'Версия', render: (v) => h('div', { class: 'row nowrap' }, h('b', {}, '#' + v.id), v.current ? badge('текущая', 'good') : null) },
      { title: 'Дата', render: (v) => fmtDate(v.ts, { sec: true, year: true }) },
      { title: 'Результат', render: (v) => stateBadge(v.status) },
      { title: 'Источник', render: (v) => h('span', {}, SRC[v.source] || v.source, h('span', { class: 'muted small' }, v.username ? ' · ' + v.username : '')) },
      { title: 'Комментарий', render: (v) => h('span', { class: 'small' }, v.comment || '') },
      { title: '', render: (v) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('button', { class: 'btn sm', onclick: () => view(v) }, icon('eye'), 'Открыть'),
        can('operator') && v.status === 'applied' && !v.current ? h('button', { class: 'btn sm', onclick: async () => {
          if (!await confirmDlg(`Откатиться к версии #${v.id} от ${fmtDate(v.ts)}?\n\nНастройки сайтов, потоков и глобальные параметры будут восстановлены в состояние этой версии и сразу применены.`, { ok: 'Откатить' })) return;
          const r = await api(`/config/versions/${v.id}/rollback`, { method: 'POST' });
          toast(`Откат выполнен, создана версия #${r.version}`, 'good'); refreshState(); render(root);
        } }, icon('history'), 'Откатить') : null) },
    ], list, { empty: 'Конфигурация ещё ни разу не применялась' })));
}

async function view(v) {
  const body = h('div', {}, loading());
  modal({ title: `Версия #${v.id}`, size: 'xl', body });
  const d = await api(`/config/versions/${v.id}`);
  let mode = 'diff';
  const box = h('div', {});
  const draw = async () => {
    if (mode === 'files') {
      const names = Object.keys(d.files).filter(n => !n.endsWith('.keep') && !n.startsWith('pages/'));
      let cur = names.find(n => n.startsWith('sites/')) || names[0];
      const fileBox = h('div', {});
      const drawFile = () => mount(fileBox, h('div', { class: 'row mb' }, h('code', {}, cur), h('button', { class: 'btn sm', onclick: () => downloadText(cur.split('/').pop(), d.files[cur], 'text/plain') }, icon('download'))), codeBlock(d.files[cur], { maxHeight: '60vh' }));
      mount(box, h('div', { class: 'grid split-nav' },
        h('div', { class: 'col', style: { gap: '2px' } }, names.map(n => h('a', { href: '#', class: 'small mono', onclick: (e) => { e.preventDefault(); cur = n; drawFile(); } }, n))), fileBox));
      drawFile();
    } else if (mode === 'output') {
      mount(box, h('pre', { class: 'code' }, d.output || ''));
    } else {
      mount(box, loading());
      const diff = await api(`/config/versions/${v.id}/diff`, { query: { against: mode === 'current' ? 'current' : 'prev' } });
      mount(box, diff.length ? diff.map(x => h('div', { class: 'mb' }, h('div', { class: 'row', style: { marginBottom: '6px' } }, h('code', {}, x.file), h('span', { class: 'muted small' }, `+${x.added} −${x.removed}`)), diffBlock(x.diff)))
        : h('div', { class: 'empty' }, 'Различий нет'));
    }
  };
  mount(body, h('dl', { class: 'kv mb' }, h('dt', {}, 'Дата'), h('dd', {}, fmtDate(d.ts, { sec: true, year: true })), h('dt', {}, 'Автор'), h('dd', {}, d.username || '—'),
    h('dt', {}, 'Комментарий'), h('dd', {}, d.comment || '—'), h('dt', {}, 'Сайты'), h('dd', {}, d.state_summary.sites.map(s => s.name + (s.enabled ? '' : ' (выкл)')).join(', ') || '—')),
  tabs([{ id: 'diff', label: 'Изменения относительно предыдущей' }, { id: 'current', label: 'Отличия от текущей' }, { id: 'files', label: 'Файлы' }, { id: 'output', label: 'Вывод nginx' }], mode, (m) => { mode = m; draw(); }),
  box);
  draw();
}
