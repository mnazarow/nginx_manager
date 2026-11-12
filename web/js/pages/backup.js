// Резервные копии, экспорт/импорт настроек, выгрузка во внешнее S3-хранилище.
import { api } from '../api.js';
import { h, mount, icon, toast, table, badge, fmtBytes, fmtDate, fmtAgo, confirmDlg, card, pickFile, downloadText, loading, modal } from '../ui.js';
import { refreshState } from '../app.js';

const ROLE = { admin: 'администратор', operator: 'оператор', viewer: 'наблюдатель' };
const KIND = { db: 'база данных SQLite', json: 'настройки JSON', gz: 'база, сжатая gzip', enc: 'зашифрованная копия' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function healthz() {
  const r = await fetch('/healthz', { cache: 'no-store' });
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

/** Ожидание перезапуска панели: опрос /healthz, пока не сменится время запуска, затем перезагрузка страницы. */
async function waitRestart(before) {
  const msg = h('div', { class: 'small ink2', role: 'status' }, 'Панель останавливается…');
  const m = modal({ title: 'Восстановление базы', body: h('div', { class: 'col' }, loading('Панель перезапускается и заменяет файл базы данных…'), msg,
    h('div', { class: 'small ink3' }, 'Обычно это занимает 5–15 секунд. Страница обновится сама; если копия старая, войдите заново с паролем из копии.')) });
  const t0 = Date.now();
  while (Date.now() - t0 < 120000) {
    await sleep(1500);
    try {
      const d = await healthz();
      if (d.started > before) { msg.textContent = 'Готово — обновляю страницу…'; location.hash = '#/backup'; location.reload(); return; }
      msg.textContent = 'Панель ещё завершает работу…';
    } catch { msg.textContent = 'Панель перезапускается…'; }
  }
  m.close();
  toast('Панель не ответила за 2 минуты. Проверьте сервис на сервере: systemctl status nginx-manager и journalctl -u nginx-manager', 'bad', 'Восстановление');
}

/** Проверка копии и подтверждение восстановления. */
async function restoreDlg(name) {
  let info;
  try { info = await api(`/backup/inspect/${encodeURIComponent(name)}`, { silent: true }); } catch (e) {
    modal({ title: 'Эту копию нельзя восстановить', body: h('div', { class: 'alert bad' }, e.message) });
    return;
  }
  const dl = h('dl', { class: 'kv' });
  const add = (k, v) => dl.append(h('dt', {}, k), h('dd', {}, v));
  add('Данные по', info.data_until ? fmtDate(info.data_until, { year: true }) : '—');
  add('Сайтов, потоков', `${info.sites}, ${info.streams}`);
  add('Сертификатов', String(info.certificates));
  add('Пользователи', info.users.map((u) => `${u.username} (${ROLE[u.role] || u.role}${u.disabled ? ', отключён' : ''})`).join(', '));
  add('Схема базы', info.schema < info.schema_current ? `${info.schema} — при запуске будет обновлена до ${info.schema_current}` : String(info.schema));
  add('Размер', fmtBytes(info.size));
  let done = false;
  const go = h('button', { class: 'btn danger solid', onclick: async () => {
    go.disabled = true;
    let before = 0;
    try { before = (await healthz()).started || 0; } catch { /* нет ответа — всё равно попробуем */ }
    let r;
    try { r = await api('/backup/restore', { method: 'POST', body: { name } }); } finally { go.disabled = false; }
    done = true; m.close();
    if (r.restart) waitRestart(before);
    else modal({ title: 'Восстановление запланировано', body: h('div', { class: 'col' }, h('div', { class: 'alert warn' }, 'Панель запущена не как сервис и не может перезапуститься сама. Перезапустите её вручную — база будет заменена при запуске.'), h('div', { class: 'small' }, `Текущая база сохранена как ${r.safety}.`)) });
  } }, icon('history'), 'Восстановить');
  const m = modal({
    title: `Восстановить базу из ${name}?`, size: 'lg',
    body: h('div', { class: 'col' },
      h('div', { class: 'alert good' }, 'Копия проверена: файл цел, это база Nginx Manager, в ней есть администратор.'), dl,
      h('div', { class: 'alert warn' }, h('b', {}, 'Что произойдёт. '),
        'Текущая база будет сохранена как копия «before-restore» — к ней можно вернуться так же. Затем панель перезапустится и заменит базу копией: ',
        'сайты, настройки, пользователи и пароли, ключи API, журналы и статистика станут такими, как в копии; всё, что изменилось после её создания, пропадёт. ',
        'Работающий nginx не трогается: если настройки копии отличаются от него, панель покажет «Неприменённые изменения» — проверьте и примените.')),
    footer: [h('button', { class: 'btn', onclick: () => { done = true; m.close(); } }, 'Отмена'), go],
    onClose: () => { done = true; },
  });
  return done;
}

/** Загрузка файла копии на сервер (потоком, без чтения в память браузера). */
function uploadBackup(onDone) {
  const inp = h('input', { type: 'file', accept: '.db,.gz,.json', style: { display: 'none' } });
  inp.addEventListener('change', async () => {
    const f = inp.files[0]; inp.remove(); if (!f) return;
    toast(`Загрузка ${f.name} (${fmtBytes(f.size)})…`, 'info');
    const res = await fetch(`/api/backup/upload?filename=${encodeURIComponent(f.name)}`, { method: 'POST', body: f, credentials: 'same-origin',
      headers: { 'X-NM-CSRF': '1', 'Content-Type': 'application/octet-stream' } }).catch(() => null);
    if (!res) { toast('Нет связи с сервером панели', 'bad'); return; }
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { toast(d.detail || `Ошибка ${res.status}`, 'bad', 'Копия не загружена'); return; }
    toast(`Загружено: ${d.name}` + (d.info ? '. Кнопка «Восстановить» — в списке копий.' : '. Импортируйте его через «Импорт настроек».'), 'good');
    onDone();
  });
  document.body.appendChild(inp); inp.click();
}

export async function render(root) {
  const box = h('div', {});
  const s3box = h('div', {});
  const users = h('input', { type: 'checkbox' });
  const panel = await api('/settings/panel');
  const restoreBox = h('div', { class: 'card-body', style: { paddingBottom: '0' } });
  const load = async () => {
    const [list, rst] = await Promise.all([api('/backup/list'), api('/backup/restore')]);
    const last = rst.last;
    mount(restoreBox,
      rst.pending ? h('div', { class: 'alert warn mb' }, h('b', {}, 'Запланировано восстановление '), `из ${rst.pending.source} (${rst.pending.user || 'nmctl'}, ${fmtAgo(rst.pending.ts)}) — оно выполнится при перезапуске панели. `,
        h('button', { class: 'btn sm', onclick: async () => { await api('/backup/restore', { method: 'DELETE' }); toast('Восстановление отменено', 'good'); load(); } }, 'Отменить')) : null,
      last && last.done_at > Date.now() / 1000 - 7 * 86400 ? h('div', { class: 'alert ' + (last.ok ? 'good' : 'bad') + ' mb' }, last.ok
        ? `База восстановлена из ${last.source} ${fmtAgo(last.done_at)} (${last.user || 'nmctl'}); прежняя база сохранена как ${last.safety}.`
        : `Восстановление из ${last.source} ${fmtAgo(last.done_at)} не выполнено: ${last.error}. Панель работает с прежней базой.`) : null);
    restoreBox.style.display = restoreBox.childNodes.length ? '' : 'none';
    mount(box, table([
      { title: 'Файл', render: (b) => h('code', {}, b.name) }, { title: 'Тип', render: (b) => KIND[b.kind] || b.kind },
      { title: 'Размер', num: true, render: (b) => fmtBytes(b.size) }, { title: 'Создан', render: (b) => fmtDate(b.mtime, { year: true }) },
      { title: '', render: (b) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        b.kind === 'db' ? h('button', { class: 'btn sm', title: 'Проверить копию и восстановить из неё базу панели', onclick: () => restoreDlg(b.name) }, icon('history'), 'Восстановить') : null,
        h('a', { class: 'btn sm', href: `/api/backup/download/${encodeURIComponent(b.name)}` }, icon('download'), 'Скачать'),
        h('button', { class: 'btn sm danger', 'aria-label': `Удалить ${b.name}`, title: 'Удалить', onclick: async () => { if (await confirmDlg(`Удалить ${b.name}?`, { danger: true, ok: 'Удалить' })) { await api(`/backup/${encodeURIComponent(b.name)}`, { method: 'DELETE' }); load(); } } }, icon('trash'))) },
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
        { title: '', render: (o) => h('button', { class: 'btn sm', title: 'Скачать на сервер в каталог копий (расшифровать и распаковать)', onclick: async (e) => {
          const btn = e.currentTarget; btn.disabled = true;
          try {
            const d = await api('/backup/s3/download', { method: 'POST', body: { name: o.name } });
            toast(`Скопировано на сервер: ${d.name}` + (d.name.endsWith('.db') ? ' — восстановить базу можно кнопкой «Восстановить» в списке копий' : ''), 'good'); load();
          } finally { btn.disabled = false; }
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
      card('Резервная копия сейчас', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Полная копия базы данных (включая статистику) и экспорт настроек' + (panel.s3_enabled ? ', сразу выгружается в хранилище.' : '.') + ' Восстановить базу из копии — кнопка «Восстановить» в списке ниже.'),
        h('button', { class: 'btn primary', onclick: async (e) => {
          e.target.disabled = true;
          try {
            const r = await api('/backup/create', { method: 'POST' });
            if (r.offsite && !r.offsite.ok) toast(`Копия ${r.name} создана, но не выгружена: ${r.offsite.error}`, 'bad');
            else toast(`Создана копия ${r.name}` + (r.offsite ? ' и выгружена в хранилище' : ''), 'good');
            load(); loadS3();
          } finally { e.target.disabled = false; }
        } }, icon('backup'), 'Создать копию')))),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h2', {}, 'Сохранённые копии на сервере'),
      h('button', { class: 'btn sm', title: 'Загрузить на сервер копию базы (.db, .db.gz) или экспорт настроек (.json), например с другого сервера', onclick: () => uploadBackup(load) }, icon('upload'), 'Загрузить копию…')),
    restoreBox, h('div', { class: 'card-body flush' }, box)),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h2', {}, 'Внешнее хранилище (S3)'), s3actions), h('div', { class: 'card-body' }, s3box)));
  await load();
  loadS3();
}
