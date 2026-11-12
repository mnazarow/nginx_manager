// Резервные копии, экспорт/импорт настроек.
import { api } from '../api.js';
import { h, mount, icon, toast, table, fmtBytes, fmtDate, confirmDlg, card, pickFile, downloadText } from '../ui.js';
import { refreshState } from '../app.js';

export async function render(root) {
  const box = h('div', {});
  const users = h('input', { type: 'checkbox' });
  const load = async () => {
    const list = await api('/backup/list');
    mount(box, table([
      { title: 'Файл', render: (b) => h('code', {}, b.name) }, { title: 'Тип', render: (b) => b.kind === 'db' ? 'база данных SQLite' : 'настройки JSON' },
      { title: 'Размер', num: true, render: (b) => fmtBytes(b.size) }, { title: 'Создан', render: (b) => fmtDate(b.mtime, { year: true }) },
      { title: '', render: (b) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        h('a', { class: 'btn sm', href: `/api/backup/download/${encodeURIComponent(b.name)}` }, icon('download'), 'Скачать'),
        h('button', { class: 'btn sm danger', onclick: async () => { if (await confirmDlg(`Удалить ${b.name}?`, { danger: true, ok: 'Удалить' })) { await api(`/backup/${encodeURIComponent(b.name)}`, { method: 'DELETE' }); load(); } } }, icon('trash'))) },
    ], list, { empty: 'Копий пока нет' }));
  };
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Резервные копии и импорт'),
      h('p', {}, 'Автоматическая копия создаётся ежедневно (настраивается в «Настройки панели → Резервные копии»). Копии хранятся в /var/lib/nginx-manager/backups.'))),
    h('div', { class: 'grid g3' },
      card('Экспорт настроек', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'JSON-файл со всеми сайтами, потоками, глобальными настройками, правилами оповещений и загруженными сертификатами. Подходит для переноса на другой сервер.'),
        h('label', { class: 'switch small' }, users, h('span', { class: 'track' }), 'Включить пользователей (хеши паролей)'),
        h('button', { class: 'btn', onclick: async () => {
          const r = await api('/backup/export', { query: { users: users.checked ? 1 : '' }, raw: true });
          downloadText(`nginx-manager-export-${new Date().toISOString().slice(0, 10)}.json`, await r.text());
        } }, icon('download'), 'Скачать экспорт'))),
      card('Импорт настроек', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Загрузите файл экспорта. Перед импортом автоматически создаётся резервная копия. После импорта примените конфигурацию.'),
        h('button', { class: 'btn', onclick: async () => {
          const f = await pickFile('.json'); if (!f) return;
          let data; try { data = JSON.parse(f.text); } catch { toast('Файл не является JSON', 'bad'); return; }
          if (!await confirmDlg(`Импортировать «${f.name}»?\nТекущие сайты, потоки и правила будут ЗАМЕНЕНЫ содержимым файла.`, { danger: true, ok: 'Импортировать' })) return;
          const r = await api('/backup/import', { method: 'POST', body: data, query: { mode: 'replace' } });
          toast(`Импортировано: сайтов ${r.stats.sites}, потоков ${r.stats.streams}, сертификатов ${r.stats.certificates}, правил ${r.stats.rules}`, 'good');
          refreshState(); load();
        } }, icon('upload'), 'Выбрать файл…'))),
      card('Резервная копия сейчас', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Полная копия базы данных (включая статистику) и экспорт настроек. Восстановление БД: nmctl или замена файла при остановленном сервисе (см. документацию).'),
        h('button', { class: 'btn primary', onclick: async () => { const r = await api('/backup/create', { method: 'POST' }); toast(`Создана копия ${r.name}`, 'good'); load(); } }, icon('backup'), 'Создать копию')))),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h3', {}, 'Сохранённые копии')), h('div', { class: 'card-body flush' }, box)));
  await load();
}
