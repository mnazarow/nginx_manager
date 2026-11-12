// Резервные копии, экспорт/импорт настроек, выгрузка во внешнее S3-хранилище.
import { api } from '../api.js';
import { h, mount, icon, toast, table, badge, fmtBytes, fmtDate, fmtAgo, confirmDlg, card, pickFile, downloadText, loading } from '../ui.js';
import { refreshState } from '../app.js';

export async function render(root) {
  const box = h('div', {});
  const s3box = h('div', {});
  const users = h('input', { type: 'checkbox' });
  const panel = await api('/settings/panel');
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

  // ---- внешнее хранилище ----
  const loadS3 = async () => {
    if (!panel.s3_enabled) {
      mount(s3box, h('div', { class: 'empty small' }, 'Копии хранятся только на этом сервере — при потере сервера пропадут и они. ',
        h('a', { href: '#/settings?tab=backup' }, 'Включите выгрузку в S3-хранилище'), ' (AWS S3, Yandex Object Storage, VK Cloud, Selectel, MinIO, Cloudflare R2).'));
      return;
    }
    mount(s3box, loading('Список копий в хранилище…'));
    let r;
    try { r = await api('/backup/s3/list', { silent: true }); } catch (e) {
      mount(s3box, h('div', { class: 'alert bad' }, h('b', {}, 'Хранилище недоступно: '), e.message, '. Проверьте настройки и нажмите «Проверить хранилище».'));
      return;
    }
    const last = r.last;
    mount(s3box,
      last ? h('div', { class: 'alert ' + (last.ok ? 'good' : 'bad') + ' mb' }, last.ok
        ? `Последняя выгрузка ${fmtAgo(last.ts)}: ${last.files.length} файл(а), ${fmtBytes(last.files.reduce((a, f) => a + f.size, 0))}.`
        : `Последняя выгрузка ${fmtAgo(last.ts)} не удалась: ${last.error}`) : null,
      table([
        { title: 'Файл в хранилище', render: (o) => h('div', {}, h('code', {}, o.name), o.encrypted ? h('span', { style: { marginLeft: '6px' } }, badge('зашифрован', 'info')) : null) },
        { title: 'Размер', num: true, render: (o) => fmtBytes(o.size) },
        { title: 'Выгружен', render: (o) => o.last_modified ? fmtDate(Date.parse(o.last_modified) / 1000, { year: true }) : '—' },
        { title: '', render: (o) => h('button', { class: 'btn sm', title: 'Скачать на сервер в каталог копий (расшифровать и распаковать)', onclick: async () => {
          const d = await api('/backup/s3/download', { method: 'POST', body: { name: o.name } });
          toast(`Скопировано на сервер: ${d.name}`, 'good'); load();
        } }, icon('download'), 'На сервер') },
      ], r.items, { empty: 'В хранилище пока нет копий' }));
  };
  const s3actions = panel.s3_enabled ? h('div', { class: 'row' },
    h('button', { class: 'btn sm', onclick: async () => {
      const r = await api('/backup/s3/check', { method: 'POST' });
      toast('Хранилище доступно: ' + r.steps.join(', '), 'good');
    } }, icon('check'), 'Проверить хранилище'),
    h('a', { class: 'btn sm', href: '#/settings?tab=backup' }, icon('gear'), 'Настройки')) : null;

  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Резервные копии и импорт'),
      h('p', {}, 'Автоматическая копия создаётся ежедневно (настраивается в «Настройки панели → Резервные копии»). Копии хранятся в /var/lib/nginx-manager/backups' + (panel.s3_enabled ? ` и выгружаются в хранилище ${panel.s3_bucket}.` : '.')))),
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
      card('Резервная копия сейчас', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Полная копия базы данных (включая статистику) и экспорт настроек' + (panel.s3_enabled ? ', сразу выгружается в хранилище.' : '.') + ' Восстановление БД: замена файла при остановленном сервисе (см. документацию).'),
        h('button', { class: 'btn primary', onclick: async (e) => {
          e.target.disabled = true;
          try {
            const r = await api('/backup/create', { method: 'POST' });
            if (r.offsite && !r.offsite.ok) toast(`Копия ${r.name} создана, но не выгружена: ${r.offsite.error}`, 'bad');
            else toast(`Создана копия ${r.name}` + (r.offsite ? ' и выгружена в хранилище' : ''), 'good');
            load(); loadS3();
          } finally { e.target.disabled = false; }
        } }, icon('backup'), 'Создать копию')))),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h3', {}, 'Сохранённые копии на сервере')), h('div', { class: 'card-body flush' }, box)),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h3', {}, 'Внешнее хранилище (S3)'), s3actions), h('div', { class: 'card-body' }, s3box)));
  await load();
  loadS3();
}
