// Резервные копии, экспорт/импорт настроек, выгрузка во внешнее S3-хранилище.
import { api } from '../api.js';
import { h, mount, icon, toast, table, badge, fmtBytes, fmtDate, fmtAgo, confirmDlg, card, pickFile, downloadText, loading, modal, segmented } from '../ui.js';
import { refreshState } from '../app.js';

const ROLE = { admin: 'администратор', operator: 'оператор', viewer: 'наблюдатель' };
const KIND = { db: 'база данных SQLite', json: 'настройки JSON', gz: 'база, сжатая gzip', enc: 'зашифрованная копия',
  settings: 'копия всех настроек', 'settings-enc': 'копия всех настроек, зашифрована' };
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
function uploadBackup(onDone, onSettings) {
  const inp = h('input', { type: 'file', accept: '.db,.gz,.json,.enc', style: { display: 'none' } });
  inp.addEventListener('change', async () => {
    const f = inp.files[0]; inp.remove(); if (!f) return;
    toast(`Загрузка ${f.name} (${fmtBytes(f.size)})…`, 'info');
    const res = await fetch(`/api/backup/upload?filename=${encodeURIComponent(f.name)}`, { method: 'POST', body: f, credentials: 'same-origin',
      headers: { 'X-NM-CSRF': '1', 'Content-Type': 'application/octet-stream' } }).catch(() => null);
    if (!res) { toast('Нет связи с сервером панели', 'bad'); return; }
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { toast(d.detail || `Ошибка ${res.status}`, 'bad', 'Копия не загружена'); return; }
    if (d.settings) { onDone(); if (onSettings) onSettings(d.name, d.encrypted); return; }
    toast(`Загружено: ${d.name}` + (d.info ? '. Кнопка «Восстановить» — в списке копий.' : '. Импортируйте его через «Импорт настроек».'), 'good');
    onDone();
  });
  document.body.appendChild(inp); inp.click();
}

/** Карточка «Копия всех настроек»: пароль (по желанию) и создание с загрузкой файла. */
function settingsCard(onDone) {
  const pass = h('input', { type: 'password', id: 'nm-sb-pass', autocomplete: 'new-password', placeholder: 'не короче 8 символов' });
  const note = h('div', { class: 'small warning-text' }, 'Без пароля в файле открыто лежат закрытые ключи сертификатов, токены и пароли интеграций — храните его надёжно.');
  pass.addEventListener('input', () => { note.style.display = pass.value ? 'none' : ''; });
  const btn = h('button', { class: 'btn primary', onclick: async () => {
    btn.disabled = true;
    try {
      const r = await api('/backup/settings', { method: 'POST', body: { password: pass.value } });
      const a = h('a', { href: `/api/backup/download/${encodeURIComponent(r.name)}`, download: r.name, style: { display: 'none' } });
      document.body.append(a); a.click(); a.remove();
      toast(`Создана копия ${r.name} (${fmtBytes(r.size)})${r.encrypted ? ', зашифрована' : ''} — файл скачивается`, 'good');
      pass.value = ''; note.style.display = '';
      if (onDone) onDone();
    } catch (e) { toast(e.data?.detail || e.message, 'bad'); } finally { btn.disabled = false; }
  } }, icon('download'), 'Создать и скачать');
  const job = h('div', { class: 'small' });
  const drawJob = (j) => {
    const last = j.last;
    const bad = last ? Object.entries(last.targets || {}).filter(([, v]) => !v.ok) : [];
    const run = h('button', { class: 'btn sm', type: 'button', disabled: !j.targets.length, title: j.targets.length ? 'Создать копию и отправить во все выбранные места сейчас' : 'Места отправки не выбраны', onclick: async () => {
      run.disabled = true;
      try {
        const r = await api('/backup/settings/job', { method: 'POST' });
        toast(r.ok ? `Копия ${r.name} отправлена` : `Не всё отправлено: ${Object.values(r.targets || {}).filter(v => !v.ok).map(v => (v.name ? v.name + ': ' : '') + v.error).join('; ') || r.error}`, r.ok ? 'good' : 'bad');
        drawJob(await api('/backup/settings/job'));
        if (onDone) onDone();
      } catch (e) { toast(e.data?.detail || e.message, 'bad'); } finally { run.disabled = false; }
    } }, icon('upload'), 'Отправить сейчас');
    const verifyBtn = h('button', { class: 'btn sm', type: 'button', title: 'Открыть последнюю копию на сервере и во внешних хранилищах паролем копий и проверить содержимое', onclick: async () => {
      verifyBtn.disabled = true;
      try {
        const r = await api('/backup/settings/verify', { method: 'POST' });
        toast(r.ok ? 'Копии настроек открываются, содержимое в порядке' : `Проблемы: ${r.items.filter(x => !x.ok).map(x => x.where + ': ' + x.problems.join('; ')).join(' · ')}`, r.ok ? 'good' : 'bad');
        drawJob(await api('/backup/settings/job'));
      } catch (e) { toast(e.data?.detail || e.message, 'bad'); } finally { verifyBtn.disabled = false; }
    } }, icon('check'), 'Проверить копии');
    mount(job, h('div', { class: 'sub-h', style: { margin: '6px 0 4px', fontWeight: 600 } }, 'По расписанию'),
      h('div', { class: 'muted' }, j.hours ? `каждые ${j.hours} ч${j.only_changed ? ', если настройки изменились' : ''}` : 'вместе с ежедневной копией базы',
        j.targets.length ? ` → ${j.targets.map(t => t.name).join(', ')}` : ' — во внешние места не отправляется'),
      j.verify ? h('div', { class: j.verify.ok ? 'muted' : 'bad-text' }, `проверка ${fmtAgo(j.verify.at)}: `,
        j.verify.ok ? j.verify.items.map(x => `${x.where} — открывается`).join('; ')
          : j.verify.items.filter(x => !x.ok).map(x => `${x.where}: ${x.problems.join('; ')}`).join('; ')) : null,
      last ? h('div', { class: bad.length || last.ok === false ? 'bad-text' : 'muted' },
        `последняя: ${fmtAgo(last.at)}${last.name ? ' — ' + last.name : ''}`,
        bad.length ? ` — ошибки: ${bad.map(([k, v]) => (v.name || k) + ': ' + v.error).join('; ')}` : last.error ? ` — ${last.error}` : '') : null,
      h('div', { class: 'row', style: { gap: '8px', marginTop: '6px', flexWrap: 'wrap' } }, run, verifyBtn,
        j.targets.some(t => t.id === 's3_second') ? h('button', { class: 'btn sm', type: 'button', onclick: async () => {
          const r = await api('/backup/settings/s3-check', { method: 'POST' });
          toast(r.ok ? `Второе хранилище: ${r.steps.join(', ')}` : `Второе хранилище недоступно: ${r.error}`, r.ok ? 'good' : 'bad');
        } }, icon('check'), 'Проверить второе хранилище') : null,
        j.targets.some(t => t.id === 's3_second') ? h('button', { class: 'btn sm', type: 'button', onclick: () => secondStorageDlg(onDone) }, icon('history'), 'Копии во втором хранилище…') : null,
        h('a', { class: 'btn sm ghost', href: '#/settings?tab=sbackup' }, 'Настроить')));
  };
  api('/backup/settings/job', { silent: true }).then(drawJob).catch(() => {});
  return card('Копия всех настроек', h('div', { class: 'col' },
    h('div', { class: 'small ink2' }, 'Один файл со всеми настройками: сайты и потоки, сертификаты с ключами и данными certbot, учётные записи DNS, настройки nginx, панели и защиты от атак, оповещения, пользователи с 2FA и API-токены, ручные блокировки. Без статистики и журналов — файл небольшой.'),
    h('div', { class: 'field' }, h('label', { for: 'nm-sb-pass' }, 'Пароль для шифрования (рекомендуется)'), pass), note, btn, job));
}

/** Копии настроек во втором S3-хранилище: скачать на сервер и сразу восстановить. */
async function secondStorageDlg(onDone) {
  const body = h('div', {}, loading());
  const m = modal({ title: 'Копии настроек во втором хранилище', size: 'lg', body, footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Закрыть')] });
  let d;
  try { d = await api('/backup/settings/s3', { silent: true }); } catch (e) { mount(body, h('div', { class: 'alert bad' }, e.data?.detail || e.message)); return; }
  mount(body,
    h('p', { class: 'small muted' }, `Бакет ${d.bucket}, префикс ${d.prefix || '—'}. «Восстановить…» скачивает копию в каталог копий сервера и открывает окно восстановления (пароль — пароль копий настроек).`),
    d.items.length ? table([
      { title: 'Файл', render: (x) => h('span', { class: 'mono small', style: { wordBreak: 'break-all' } }, x.name) },
      { title: 'Размер', num: true, render: (x) => fmtBytes(x.size) },
      { title: 'Изменён', render: (x) => x.modified ? fmtDate(Date.parse(x.modified) / 1000) : '—' },
      { title: '', srTitle: 'Действия', render: (x) => {
        const b = h('button', { class: 'btn sm', type: 'button', onclick: async () => {
          b.disabled = true;
          try {
            const r = await api('/backup/settings/s3/download', { method: 'POST', body: { name: x.name } });
            m.close();
            if (onDone) onDone();
            restoreSettingsDlg(r.name, r.encrypted, onDone);
          } catch (e) { toast(e.data?.detail || e.message, 'bad'); b.disabled = false; }
        } }, icon('history'), 'Восстановить…');
        return b;
      } },
    ], d.items) : h('div', { class: 'empty' }, 'Копий настроек в хранилище нет'));
}

/** Окно восстановления настроек из копии: пароль (если зашифрована), проверка, выбор разделов, восстановление. */
export async function restoreSettingsDlg(name, encrypted, onDone) {
  const pass = h('input', { type: 'password', id: 'nm-rs-pass', autocomplete: 'off', placeholder: 'Пароль копии' });
  const body = h('div', { class: 'col' });
  const foot = h('div', { class: 'row' });
  let info = null;
  let mode = 'sections';
  const checks = {};
  const siteChecks = {};
  const applyCb = h('input', { type: 'checkbox', checked: true });
  const go = h('button', { class: 'btn danger solid', disabled: true, onclick: async () => {
    const sections = Object.keys(checks).filter(k => checks[k].checked);
    const sites = Object.keys(siteChecks).filter(k => siteChecks[k].checked).map(Number);
    let body, question;
    if (mode === 'sites') {
      if (!sites.length) { toast('Выберите сайты', 'bad'); return; }
      body = { name, password: pass.value, sites, apply: applyCb.checked };
      question = `Восстановить из копии ${name} сайтов: ${sites.length}?\nСайт с теми же доменами обновится, остальные будут созданы; другие сайты и настройки не меняются. Текущие настройки будут сохранены в копию before-settings-restore.`;
    } else {
      if (!sections.length) { toast('Выберите разделы', 'bad'); return; }
      body = { name, password: pass.value, sections, apply: applyCb.checked };
      question = `Заменить ${sections.length === Object.keys(checks).length ? 'все настройки' : 'выбранные разделы'} содержимым копии ${name}?\nТекущие настройки будут сохранены в копию before-settings-restore.`;
    }
    if (!await confirmDlg(question, { danger: true, ok: 'Восстановить' })) return;
    go.disabled = true;
    try {
      const r = await api('/backup/settings/restore', { method: 'POST', body });
      m.close();
      resultDlg(r);
      if (onDone) onDone();
    } catch (e) { toast(e.data?.detail || e.message, 'bad', 'Не восстановлено'); go.disabled = false; }
  } }, icon('history'), 'Восстановить');
  const show = () => {
    const dl = h('dl', { class: 'kv' });
    const mf = info.manifest;
    dl.append(h('dt', {}, 'Создана'), h('dd', {}, `${fmtDate(mf.created_at, { year: true })}${mf.host ? ' на сервере ' + mf.host : ''}`),
      h('dt', {}, 'Версия панели'), h('dd', {}, mf.version || '—'),
      h('dt', {}, 'Файлы сертификатов'), h('dd', {}, `${info.files.certs}` + (info.files.letsencrypt ? `, данные certbot — ${info.files.letsencrypt} файлов` : '')),
      h('dt', {}, 'Размер'), h('dd', {}, fmtBytes(info.size)));
    const siteSec = info.sections.find(x => x.id === 'sites');
    const secBox = h('div', { class: 'col', style: { gap: '6px' } });
    const siteBox = h('div', { class: 'col', style: { gap: '6px' } });
    const all = h('button', { class: 'btn sm ghost', type: 'button', onclick: () => Object.values(mode === 'sites' ? siteChecks : checks).forEach(c => { c.checked = true; }) }, 'Выбрать все');
    const pick = segmented([['sections', 'Разделы целиком'], ['sites', 'Отдельные сайты']], mode, (v) => {
      mode = v; secBox.style.display = v === 'sections' ? '' : 'none'; siteBox.style.display = v === 'sites' ? '' : 'none';
    });
    siteBox.style.display = 'none';
    mount(siteBox, h('div', { class: 'small muted' }, 'Отмеченные сайты восстанавливаются вместе с их сертификатами из копии; сайт с теми же доменами обновляется, остальные создаются. Другие сайты и разделы не меняются.'),
      ...((siteSec && siteSec.items) || []).map(it => {
        const cb = h('input', { type: 'checkbox' });
        siteChecks[it.id] = cb;
        return h('label', { class: 'check', style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, cb,
          h('span', {}, it.name, it.https ? h('span', { class: 'muted small' }, ' · HTTPS') : null,
            h('div', { class: 'small muted' }, (it.domains || []).join(', '))));
      }));
    mount(body,
      h('div', { class: 'alert good' }, 'Копия проверена: архив цел, контрольные суммы совпадают.'), dl,
      info.warnings.length ? h('div', { class: 'alert warn' }, info.warnings.map(w => h('div', {}, w))) : null,
      h('div', { class: 'row', style: { justifyContent: 'space-between', alignItems: 'center' } }, h('b', {}, 'Что восстановить'),
        h('div', { class: 'row', style: { gap: '8px' } }, siteSec && (siteSec.items || []).length ? pick : null, all)),
      siteBox, secBox);
    mount(secBox, info.sections.map(sec => {
      const cb = h('input', { type: 'checkbox', checked: true });
      checks[sec.id] = cb;
      return h('label', { class: 'check', style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, cb,
        h('span', {}, sec.title, h('span', { class: 'muted small' }, ` — ${sec.count}`),
          sec.names.length ? h('div', { class: 'small muted' }, sec.names.slice(0, 8).join(', ') + (sec.count > 8 ? ' …' : '')) : null,
          sec.id === 'users' ? h('div', { class: 'small warning-text' }, 'Все выйдут из панели и войдут с паролями и 2FA из копии') : null));
    }));
    body.append(
      h('label', { class: 'check', style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, applyCb,
        h('span', {}, 'Сразу применить конфигурацию nginx', h('div', { class: 'small muted' }, 'С проверкой nginx -t; если nginx её не примет — настройки вернутся к текущим автоматически'))),
      h('div', { class: 'alert info small' }, 'Каждый выбранный раздел заменяется целиком. Статистика, журналы и история версий не меняются. Перед восстановлением текущие настройки сохраняются в копию before-settings-restore — к ним можно вернуться так же.'));
    go.disabled = false;
  };
  const check = async () => {
    try {
      info = await api('/backup/settings/inspect', { method: 'POST', body: { name, password: pass.value }, silent: true });
      show();
    } catch (e) { mount(body, encrypted ? passRow() : null, h('div', { class: 'alert bad' }, e.data?.detail || e.message)); }
  };
  const passRow = () => h('div', { class: 'col' },
    h('div', { class: 'field' }, h('label', { for: 'nm-rs-pass' }, 'Пароль копии'), h('div', { class: 'row nowrap' }, pass,
      h('button', { class: 'btn', type: 'button', onclick: check }, 'Проверить'))),
    h('div', { class: 'small muted' }, 'Копия зашифрована паролем, заданным при её создании (или паролем шифрования S3).'));
  pass.addEventListener('keydown', (e) => { if (e.key === 'Enter') check(); });
  mount(foot, h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), go);
  const m = modal({ title: `Восстановить настройки из ${name}`, size: 'lg', body, footer: [foot] });
  if (encrypted) mount(body, passRow()); else { mount(body, loading('Проверка копии…')); check(); }
}

function resultDlg(r) {
  const ok = !r.rolled_back;
  const m = modal({ title: ok ? 'Настройки восстановлены' : 'Восстановление отменено', size: 'lg', body: h('div', { class: 'col' },
    ok ? h('div', { class: 'alert good' }, (r.sites ? `Сайты: создано ${r.sites.created}, обновлено ${r.sites.updated}${r.sites.skipped ? ', не восстановлено ' + r.sites.skipped : ''}. ` : `Восстановлено разделов: ${r.sections.length}. `) + (r.applied ? `Конфигурация nginx применена (версия ${r.applied}).` : r.nginx ? 'Конфигурация не применялась — примените её кнопкой «Применить» вверху.' : ''))
      : h('div', { class: 'alert bad' }, h('b', {}, 'nginx не принял конфигурацию из копии — настройки возвращены к прежним. '), h('pre', { class: 'code small', style: { whiteSpace: 'pre-wrap', maxHeight: '240px' } }, r.apply_error || '')),
    r.notes.length ? h('div', { class: 'alert warn' }, r.notes.map(n => h('div', {}, n))) : null,
    h('div', { class: 'small muted' }, `Прежние настройки сохранены в ${r.safety}.`),
    r.relogin && ok ? h('div', { class: 'alert info' }, 'Пользователи восстановлены из копии — войдите заново.') : null),
  footer: [h('button', { class: 'btn primary', onclick: () => { if (r.relogin && ok) location.reload(); else { refreshState(); m.close(); } } }, 'Готово')],
  onClose: () => { if (r.relogin && ok) location.reload(); } });
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
        b.kind === 'settings' || b.kind === 'settings-enc' ? h('button', { class: 'btn sm', title: 'Проверить копию и восстановить настройки (целиком или по разделам)', onclick: () => restoreSettingsDlg(b.name, b.kind === 'settings-enc', load) }, icon('history'), 'Восстановить') : null,
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
      settingsCard(load),
      card('Восстановить настройки', h('div', { class: 'col' },
        h('div', { class: 'small ink2' }, 'Из копии всех настроек этого или другого сервера — целиком или по разделам (только сайты, только сертификаты…). Перед восстановлением текущие настройки сохраняются автоматически; если nginx не примет конфигурацию — они вернутся сами.'),
        h('button', { class: 'btn', onclick: () => uploadBackup(load, (n, enc) => restoreSettingsDlg(n, enc, load)) }, icon('upload'), 'Загрузить копию…'),
        h('div', { class: 'small muted' }, 'Копия уже на сервере — кнопка «Восстановить» в списке ниже.'))),
      card('Полная копия базы', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Копия базы данных целиком (со статистикой, журналами и историей версий) и копия всех настроек' + (panel.s3_enabled ? ', сразу выгружается в хранилище.' : '.') + ' Восстановить базу из копии — кнопка «Восстановить» в списке ниже.'),
        h('button', { class: 'btn primary', onclick: async (e) => {
          e.target.disabled = true;
          try {
            const r = await api('/backup/create', { method: 'POST' });
            if (r.offsite && !r.offsite.ok) toast(`Копия ${r.name} создана, но не выгружена: ${r.offsite.error}`, 'bad');
            else toast(`Создана копия ${r.name}` + (r.offsite ? ' и выгружена в хранилище' : ''), 'good');
            load(); loadS3();
          } finally { e.target.disabled = false; }
        } }, icon('backup'), 'Создать копию'))),
      card('Экспорт в JSON', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Прежний формат: JSON с сайтами, потоками, настройками nginx и панели, оповещениями и загруженными сертификатами (без защиты от атак и сертификатов Let’s Encrypt). Для переноса удобнее копия всех настроек.'),
        h('label', { class: 'switch small' }, users, h('span', { class: 'track' }), 'Включить пользователей (хеши паролей)'),
        h('button', { class: 'btn', onclick: async () => {
          const r = await api('/backup/export', { query: { users: users.checked ? 1 : '' }, raw: true });
          downloadText(`nginx-manager-export-${new Date().toISOString().slice(0, 10)}.json`, await r.text());
        } }, icon('download'), 'Скачать экспорт'))),
      card('Импорт из JSON', h('div', { class: 'col' }, h('div', { class: 'small ink2' }, 'Загрузите файл экспорта. Перед импортом автоматически создаётся резервная копия. После импорта примените конфигурацию.'),
        h('button', { class: 'btn', onclick: async () => {
          const f = await pickFile('.json'); if (!f) return;
          let data; try { data = JSON.parse(f.text); } catch { toast('Файл не является JSON', 'bad'); return; }
          if (!await confirmDlg(`Импортировать «${f.name}»?\nТекущие сайты, потоки и правила будут ЗАМЕНЕНЫ содержимым файла.`, { danger: true, ok: 'Импортировать' })) return;
          const r = await api('/backup/import', { method: 'POST', body: data, query: { mode: 'replace' } });
          toast(`Импортировано: сайтов ${r.stats.sites}, потоков ${r.stats.streams}, сертификатов ${r.stats.certificates}, правил ${r.stats.rules}`, 'good');
          refreshState(); load();
        } }, icon('upload'), 'Выбрать файл…')))),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h2', {}, 'Сохранённые копии на сервере'),
      h('button', { class: 'btn sm', title: 'Загрузить на сервер копию настроек (.settings.tar.gz, .enc), копию базы (.db, .db.gz) или экспорт (.json), например с другого сервера', onclick: () => uploadBackup(load, (n, enc) => restoreSettingsDlg(n, enc, load)) }, icon('upload'), 'Загрузить копию…')),
    restoreBox, h('div', { class: 'card-body flush' }, box)),
    h('div', { class: 'card mt' }, h('div', { class: 'card-head' }, h('h2', {}, 'Внешнее хранилище (S3)'), s3actions), h('div', { class: 'card-body' }, s3box)));
  await load();
  loadS3();
}
