// Профиль: смена пароля, двухфакторная аутентификация, сессии, API-токены.
/* global qrcode */
import { api } from '../api.js';
import { h, mount, icon, badge, toast, modal, table, fmtAgo, fmtDate, confirmDlg, card, copyBtn, promptDlg } from '../ui.js';
import { ctx } from '../app.js';

export async function render(root) {
  const me = await api('/auth/me');
  const [sessions, tokens] = await Promise.all([api('/auth/sessions'), api('/auth/tokens')]);
  const cur = h('input', { type: 'password', autocomplete: 'current-password' });
  const n1 = h('input', { type: 'password', autocomplete: 'new-password' });
  const n2 = h('input', { type: 'password', autocomplete: 'new-password' });
  mount(root,
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Мой профиль'), h('p', {}, `${me.username} · ${me.role_label}`))),
    me.must_change_password ? h('div', { class: 'alert warn mb' }, h('b', {}, 'Смените временный пароль. '), 'Пароль был выдан администратором или создан при установке.') : null,
    ctx.state?.pending === undefined ? null : null,
    h('div', { class: 'grid g2' },
      card('Смена пароля', h('div', { class: 'col' },
        h('div', { class: 'field' }, h('label', {}, 'Текущий пароль'), cur), h('div', { class: 'field' }, h('label', {}, 'Новый пароль'), n1, h('div', { class: 'help' }, 'Не менее 8 символов, буквы разного регистра, цифры или символы.')),
        h('div', { class: 'field' }, h('label', {}, 'Повторите'), n2),
        h('div', {}, h('button', { class: 'btn primary', onclick: async () => {
          if (n1.value !== n2.value) { toast('Пароли не совпадают', 'bad'); return; }
          await api('/auth/password', { method: 'POST', body: { current: cur.value, new: n1.value } });
          toast('Пароль изменён. Войдите заново.', 'good'); setTimeout(() => location.reload(), 1200);
        } }, 'Сменить пароль')))),
      card('Двухфакторная аутентификация (TOTP)', h('div', { class: 'col' },
        h('div', { class: 'small ink2' }, 'Одноразовые коды из приложения (Google Authenticator, Яндекс Ключ, Aegis, 1Password, Bitwarden).'),
        me.totp_enabled ? h('div', { class: 'col' }, h('div', {}, badge('включена', 'good')), h('div', {}, h('button', { class: 'btn danger', onclick: async () => {
          const pw = await promptDlg('Отключение 2FA', 'Введите пароль для подтверждения'); if (!pw) return;
          await api('/auth/totp/disable', { method: 'POST', body: { password: pw } }); toast('2FA отключена', 'good'); render(root);
        } }, 'Отключить 2FA')))
          : h('div', {}, h('button', { class: 'btn primary', onclick: () => setup2fa(root) }, icon('lock'), 'Настроить 2FA'))))),
    h('div', { class: 'grid g2 mt' },
      card('Активные сессии', table([
        { title: 'IP', render: (s) => h('span', { class: 'mono' }, s.ip) }, { title: 'Браузер', render: (s) => h('span', { class: 'small ellipsis', style: { maxWidth: '240px', display: 'inline-block' }, title: s.user_agent }, s.user_agent) },
        { title: 'Активность', render: (s) => fmtAgo(s.last_seen) },
        { title: '', render: (s) => s.current ? badge('текущая', 'info') : h('button', { class: 'btn sm', onclick: async () => { await api(`/auth/sessions/${s.id}`, { method: 'DELETE' }); render(root); } }, 'Завершить') },
      ], sessions), { flush: true }),
      card('API-токены', h('div', {}, h('div', { class: 'small ink2', style: { padding: '0 0 10px' } }, 'Для автоматизации: заголовок ', h('code', {}, 'Authorization: Bearer nm_…'),
        '. Права токена = права пользователя. Описание API: ', h('a', { href: '/api/docs-ui', target: '_blank' }, '/api/docs-ui'), '.'),
      table([{ title: 'Название', render: (t) => t.name }, { title: 'Префикс', render: (t) => h('code', {}, t.prefix + '…') },
        { title: 'Создан', render: (t) => fmtDate(t.created_at) }, { title: 'Использован', render: (t) => t.last_used ? fmtAgo(t.last_used) : 'никогда' },
        { title: '', render: (t) => h('button', { class: 'btn sm danger', onclick: async () => { if (await confirmDlg(`Отозвать токен «${t.name}»?`, { danger: true, ok: 'Отозвать' })) { await api(`/auth/tokens/${t.id}`, { method: 'DELETE' }); render(root); } } }, icon('trash')) }],
      tokens, { empty: 'Токенов нет' }),
      h('div', { class: 'mt' }, h('button', { class: 'btn', onclick: async () => {
        const name = await promptDlg('Новый API-токен', 'Назначение', 'ci-deploy'); if (!name) return;
        const r = await api('/auth/tokens', { method: 'POST', body: { name, days: 0 } });
        modal({ title: 'Токен создан', body: h('div', { class: 'col' }, h('div', { class: 'alert warn' }, 'Скопируйте токен сейчас — повторно он показан не будет.'),
          h('div', { class: 'row nowrap' }, h('input', { type: 'text', value: r.token, readOnly: true, class: 'code' }), copyBtn(r.token))) });
        render(root);
      } }, icon('plus'), 'Создать токен'))))));
}

async function setup2fa(root) {
  const r = await api('/auth/totp/setup', { method: 'POST' });
  const qr = qrcode(0, 'M'); qr.addData(r.uri); qr.make();
  const code = h('input', { type: 'text', inputmode: 'numeric', placeholder: '123456', maxlength: 6, style: { width: '160px', fontSize: '18px', letterSpacing: '4px' } });
  const m = modal({ title: 'Настройка 2FA', body: h('div', { class: 'col', style: { alignItems: 'center', textAlign: 'center' } },
    h('div', {}, '1. Отсканируйте QR-код в приложении-аутентификаторе'),
    h('div', { class: 'qr', html: qr.createSvgTag(5, 0) }),
    h('div', { class: 'small muted' }, 'или введите ключ вручную: ', h('code', {}, r.secret)),
    h('div', {}, '2. Введите код из приложения'), code),
  footer: [h('button', { class: 'btn', onclick: () => m.close() }, 'Отмена'), h('button', { class: 'btn primary', onclick: async () => {
    await api('/auth/totp/enable', { method: 'POST', body: { secret: r.secret, code: code.value } });
    m.close(); toast('2FA включена', 'good'); render(root);
  } }, 'Включить')] });
  setTimeout(() => code.focus(), 50);
}
