// Сертификаты SSL/TLS: ACME (Let's Encrypt и другие центры) с HTTP- или DNS-проверкой, загрузка, самоподписанные,
// файлы на диске; учётные записи DNS-провайдеров для DNS-проверки (wildcard).
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, confirmDlg, table, tabs, stateBadge, fmtDate, empty, loading, promptDlg } from '../ui.js';
import { model, defaults, renderFields, errorsToMap } from '../forms.js';
import { can, ctx, refreshState } from '../app.js';

export async function render(root) {
  let tab = ctx.params.tab === 'dns' ? 'dns' : 'certs';
  let timer = null;
  const box = h('div', {});
  const head = h('div', {});
  const tabBar = h('div', {});
  const lead = h('p', {});
  const actions = h('div', { class: 'row' });

  async function loadCerts() {
    const r = await api('/certs');
    mount(lead, `Центр сертификации: ${r.ca}. ACME-сертификаты продлеваются автоматически за ${r.renew_days} дн. до истечения (короткие — за треть срока). `,
      'Проверка владения доменом — через HTTP (файл в /.well-known/acme-challenge/) или через DNS (TXT-запись у провайдера; нужна для *.example.com).');
    mount(head, !r.certbot ? h('div', { class: 'alert warn mb' }, h('b', {}, 'certbot не установлен. '), 'Выпуск по ACME недоступен. Установите: ',
      h('code', {}, 'apt install certbot'), ' или ', h('code', {}, 'dnf install certbot'), ' (или нажмите «Исправить» в Диагностике).') : null,
    !r.email ? h('div', { class: 'alert mb' }, 'Совет: укажите e-mail для ACME в ', h('a', { href: '#/settings?tab=acme' }, 'настройках панели'), ' — на него придут предупреждения об истечении.') : null);
    mount(box, h('div', { class: 'card' }, r.items.length ? table([
      { title: 'Сертификат', render: (c) => h('div', {}, h('b', {}, c.name), h('div', { class: 'muted small' }, c.domains.join(', ') || '—')) },
      { title: 'Тип', render: (c) => c.type === 'letsencrypt'
        ? h('div', {}, badge(c.ca || "Let's Encrypt", 'info'), c.data.challenge === 'dns' ? h('div', { class: 'small muted' }, 'DNS-проверка') : null)
        : ({ upload: badge('загружен'), selfsigned: badge('самоподписанный', 'warn'), path: badge('файлы на диске') }[c.type]) },
      { title: 'Состояние', render: (c) => h('div', {}, stateBadge(c.status), c.job && c.job.state === 'running' ? h('span', { class: 'spinner', style: { marginLeft: '6px' } }) : null,
        c.last_error ? h('div', { class: 'small status-5', style: { maxWidth: '320px' } }, c.last_error) : null) },
      { title: 'Действует до', render: (c) => c.not_after ? h('div', {}, fmtDate(c.not_after, { year: true }),
        h('div', { class: 'small ' + (c.days_left < 7 ? 'status-5' : c.days_left < 21 ? 'status-4' : 'muted') }, `осталось ${Math.floor(c.days_left)} дн.`)) : '—' },
      { title: 'Издатель', render: (c) => h('span', { class: 'small muted ellipsis', style: { maxWidth: '220px', display: 'inline-block' } }, (c.issuer || '').replace(/^.*?O\s*=\s*/, '').split(',')[0]) },
      { title: 'Используется', render: (c) => c.used_by.length ? c.used_by.map(u => h('span', { class: 'tag' }, u)) : h('span', { class: 'muted small' }, 'нигде') },
      { title: '', render: (c) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        c.job ? h('button', { class: 'btn sm', onclick: () => jobLog(c) }, 'Журнал') : null,
        can('operator') && c.type !== 'upload' ? h('button', { class: 'btn sm', onclick: async () => { await api(`/certs/${c.id}/renew`, { method: 'POST' }); toast(c.type === 'letsencrypt' ? 'Продление запущено' : 'Обновлено', 'info'); loadCerts(); } },
          icon('refresh'), c.type === 'letsencrypt' ? 'Продлить' : c.type === 'selfsigned' ? 'Перевыпустить' : 'Перечитать') : null,
        can('operator') ? h('button', { class: 'btn sm danger', onclick: async () => {
          if (!await confirmDlg(`Удалить сертификат «${c.name}»?`, { danger: true, ok: 'Удалить' })) return;
          await api(`/certs/${c.id}`, { method: 'DELETE' }); toast('Удалён', 'good'); loadCerts();
        } }, icon('trash')) : null) },
    ], r.items) : empty('Сертификатов нет', 'Выпустите бесплатный сертификат Let\'s Encrypt — он будет продлеваться автоматически.',
      can('operator') ? h('button', { class: 'btn primary', onclick: () => certDialog({ onCreated: loadCerts }) }, icon('plus'), 'Добавить сертификат') : null, 'cert')));
    const running = r.items.some(c => c.status === 'pending' || (c.job && c.job.state === 'running'));
    clearTimeout(timer);
    if (running) timer = setTimeout(loadCerts, 2500);
  }

  async function loadDns() {
    clearTimeout(timer);
    mount(head, null);
    mount(lead, 'Учётные записи DNS-провайдеров для DNS-проверки: certbot сам создаёт и удаляет TXT-запись _acme-challenge. Нужна для wildcard-сертификатов (*.example.com) и для серверов, закрытых от интернета. Секреты хранятся в файлах с правами 600 и не показываются в интерфейсе.');
    const r = await api('/dns-accounts');
    mount(box, h('div', { class: 'card' }, r.items.length ? table([
      { title: 'Учётная запись', render: (a) => h('div', {}, h('b', {}, a.data.name), h('div', { class: 'muted small' }, a.provider_title)) },
      { title: 'Плагин certbot', render: (a) => a.data.provider === 'hook' ? h('span', { class: 'muted small' }, 'не нужен (свои скрипты)')
        : a.plugin === null ? badge('certbot не работает', 'bad')
        : a.plugin ? badge('установлен', 'good')
        : h('div', { class: 'row nowrap' }, badge('не установлен', 'warn'), can('operator') ? h('button', { class: 'btn sm', onclick: () => installPlugin(a, loadDns) }, icon('download'), 'Установить') : null) },
      { title: 'Используется', render: (a) => a.used_by.length ? a.used_by.map(u => h('span', { class: 'tag' }, u)) : h('span', { class: 'muted small' }, 'нигде') },
      { title: '', render: (a) => h('div', { class: 'row nowrap', style: { justifyContent: 'flex-end', gap: '4px' } },
        can('operator') ? h('button', { class: 'btn sm', onclick: () => checkAccount(a) }, icon('check'), 'Проверить') : null,
        can('admin') ? h('button', { class: 'btn sm', onclick: () => dnsDialog(a, loadDns) }, icon('edit'), 'Изменить') : null,
        can('admin') ? h('button', { class: 'btn sm danger', title: a.used_by.length ? 'Используется сертификатами' : 'Удалить', disabled: a.used_by.length > 0, onclick: async () => {
          if (!await confirmDlg(`Удалить учётную запись «${a.data.name}»? Файл с её секретами тоже будет удалён.`, { danger: true, ok: 'Удалить' })) return;
          await api(`/dns-accounts/${a.id}`, { method: 'DELETE' }); toast('Удалена', 'good'); loadDns();
        } }, icon('trash')) : null) },
    ], r.items) : empty('Учётных записей DNS нет', 'Добавьте API-токен DNS-провайдера (Cloudflare, DigitalOcean, Route 53…) или ключ TSIG своего DNS-сервера — и выпускайте wildcard-сертификаты.',
      can('admin') ? h('button', { class: 'btn primary', onclick: () => dnsDialog(null, loadDns) }, icon('plus'), 'Добавить учётную запись') : null, 'globe')));
  }

  const draw = () => {
    mount(tabBar, tabs([{ id: 'certs', label: 'Сертификаты' }, { id: 'dns', label: 'Учётные записи DNS' }], tab, (t) => {
      tab = t; ctx.params.tab = t; history.replaceState(null, '', '#/certs' + (t === 'dns' ? '?tab=dns' : '')); draw();
    }));
    mount(actions, tab === 'certs'
      ? [h('button', { class: 'btn', onclick: () => selfTest() }, icon('stethoscope'), 'Проверить домен'),
        can('operator') ? h('button', { class: 'btn primary', onclick: () => certDialog({ onCreated: loadCerts }) }, icon('plus'), 'Добавить сертификат') : null]
      : [can('admin') ? h('button', { class: 'btn primary', onclick: () => dnsDialog(null, loadDns) }, icon('plus'), 'Добавить учётную запись') : null]);
    mount(box, loading());
    (tab === 'certs' ? loadCerts() : loadDns()).catch((e) => mount(box, h('div', { class: 'alert bad' }, e.message)));
  };
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Сертификаты'), lead), actions),
    head, tabBar, box);
  draw();
  return () => clearTimeout(timer);
}

function jobLog(c) {
  modal({ title: `Журнал выпуска: ${c.name}`, size: 'lg', body: h('pre', { class: 'code' }, (c.job.log || []).join('\n') + (c.job.error ? `\n\nОШИБКА: ${c.job.error}` : '')) });
}

async function selfTest() {
  const d = await promptDlg('Проверка домена для HTTP-проверки ACME', 'Домен', '', { placeholder: 'example.com' });
  if (!d) return;
  const body = h('div', {}, loading('Проверка DNS и доступности по HTTP…'));
  modal({ title: `Проверка ${d}`, body });
  try {
    const r = await api('/certs/selftest', { method: 'POST', body: { domain: d } });
    mount(body, h('div', { class: 'col' },
      h('div', { class: 'alert ' + (r.ok ? 'good' : r.local ? 'warn' : 'bad') }, r.ok ? '✓ Домен готов к выпуску сертификата' : (r.error || 'Проверка не пройдена')),
      h('dl', { class: 'kv' }, h('dt', {}, 'DNS'), h('dd', {}, (r.dns || []).join(', ') || '—'),
        h('dt', {}, 'Через nginx локально'), h('dd', {}, r.local ? '✓ файл проверки отдаётся' : '✗ ' + (r.local_error || 'нет')),
        h('dt', {}, 'По доменному имени'), h('dd', {}, r.remote ? '✓ доступен' : '✗ ' + (r.remote_error || 'нет')))));
  } catch (e) { mount(body, h('div', { class: 'alert bad' }, e.message)); }
}

async function installPlugin(a, onDone) {
  const body = h('div', {}, loading(`Установка ${a.package}…`));
  modal({ title: 'Установка плагина certbot', size: 'lg', body });
  try {
    const r = await api('/diagnostics/fix', { method: 'POST', body: { action: 'install_dns_plugin', args: { provider: a.data.provider } } });
    mount(body, h('div', { class: 'alert ' + (r.ok ? 'good' : 'bad') }, r.ok ? '✓ Плагин установлен' : 'Установить не удалось'), h('pre', { class: 'code mt' }, r.output || ''));
    onDone && onDone();
  } catch (e) { mount(body, h('div', { class: 'alert bad' }, e.message)); }
}

async function checkAccount(a) {
  const body = h('div', {}, loading('Проверка…'));
  modal({ title: `Проверка: ${a.data.name}`, body });
  try {
    const r = await api(`/dns-accounts/${a.id}/check`, { method: 'POST' });
    mount(body, h('div', { class: 'col' },
      h('div', { class: 'alert ' + (r.ok ? 'good' : 'bad') }, r.ok ? '✓ Всё готово к DNS-проверке' : 'Есть проблемы'),
      r.items.map(it => h('div', {}, (it.ok ? '✓ ' : '✗ ') + it.text, it.hint ? h('div', { class: 'help' }, it.hint) : null)),
      h('div', { class: 'help' }, 'Права токена и доступ к зоне проверяются при выпуске: если что-то не так, журнал выпуска покажет ответ провайдера и подсказку.')));
  } catch (e) { mount(body, h('div', { class: 'alert bad' }, e.message)); }
}

export async function dnsDialog(acc, onSaved) {
  const obj = acc ? structuredClone(acc.data) : defaults(model('dns_account'));
  let errors = {};
  const box = h('div', {});
  const draw = () => {
    mount(box, obj.provider === 'hook' ? h('div', { class: 'alert mb' }, 'Скрипты запускаются от root для каждого домена: certbot передаёт CERTBOT_DOMAIN и CERTBOT_VALIDATION. Подходит для провайдеров без плагина (например, через lexicon или acme.sh dnsapi).') : null,
      obj.provider === 'rfc2136' ? h('div', { class: 'alert mb' }, 'В зоне на DNS-сервере разрешите обновление этим ключом, например в BIND: update-policy { grant acme-key name _acme-challenge.example.com. TXT; };') : null);
    renderFields(box, model('dns_account'), obj, { root: obj, advanced: true, errors, rerender: draw, onChange: () => {} });
  };
  draw();
  const btn = h('button', { class: 'btn primary' }, 'Сохранить');
  const m = modal({ title: acc ? `Учётная запись DNS: ${acc.data.name}` : 'Новая учётная запись DNS', size: 'lg', body: box,
    footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), btn] });
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      await api(acc ? `/dns-accounts/${acc.id}` : '/dns-accounts', { method: acc ? 'PUT' : 'POST', body: obj });
      m.close(); toast('Сохранено', 'good'); onSaved && onSaved();
    } catch (e) { errors = errorsToMap(e); draw(); btn.disabled = false; }
  };
}

export async function certDialog({ domains = [], onCreated } = {}) {
  const obj = defaults(model('certificate'));
  obj.domains = [...(domains || [])];
  obj.name = domains[0] || '';
  if (obj.domains.some(d => d.startsWith('*.'))) obj.challenge = 'dns';
  let dnsAccounts = [];
  try { dnsAccounts = (await api('/dns-accounts', { silent: true })).items; } catch { /* нет прав или сбой — DNS-проверка недоступна */ }
  let errors = {};
  const box = h('div', {});
  const draw = () => {
    const wild = (obj.domains || []).some(d => String(d).startsWith('*.'));
    mount(box,
      obj.type === 'letsencrypt' && obj.challenge === 'http' ? h('div', { class: 'alert mb' }, 'HTTP-проверка: домены указывают на внешний IP этого сервера (A/AAAA), порт 80 открыт снаружи, сайт с этими доменами уже применён или домен попадает в сервер по умолчанию.',
        wild ? h('div', { class: 'status-5 mt' }, 'Wildcard (*.example.com) выпускается только с DNS-проверкой — выберите «DNS».') : null) : null,
      obj.type === 'letsencrypt' && obj.challenge === 'dns' ? h('div', { class: 'alert mb' }, 'DNS-проверка: certbot создаст TXT-запись _acme-challenge через выбранную учётную запись DNS. Порт 80 и A-записи не нужны — подходит для wildcard (*.example.com) и внутренних серверов.',
        !dnsAccounts.length ? h('div', { class: 'mt' }, h('a', { href: '#/certs?tab=dns' }, 'Добавить учётную запись DNS →')) : null) : null,
      obj.type === 'selfsigned' ? h('div', { class: 'alert warn mb' }, 'Браузеры будут показывать предупреждение. Подходит для тестов, внутренних сервисов и как временная заглушка.') : null);
    renderFields(box, model('certificate'), obj, { root: obj, advanced: true, errors, rerender: draw, onChange: () => {}, dnsAccounts });
  };
  draw();
  const btn = h('button', { class: 'btn primary' }, 'Создать');
  const m = modal({ title: 'Новый сертификат', size: 'lg', body: box, footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), btn] });
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      const r = await api('/certs', { method: 'POST', body: obj });
      m.close();
      toast(obj.type === 'letsencrypt' ? (obj.challenge === 'dns' ? 'Выпуск запущен — DNS-проверка займёт несколько минут' : 'Выпуск запущен — это займёт до минуты') : 'Сертификат добавлен', 'good');
      refreshState();
      onCreated && onCreated(r.id);
    } catch (e) { errors = errorsToMap(e); draw(); btn.disabled = false; }
  };
}
