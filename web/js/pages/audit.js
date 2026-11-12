// Аудит действий пользователей.
import { api } from '../api.js';
import { h, mount, table, fmtDate, debounce } from '../ui.js';

const A = {
  login: 'вход', login_failed: 'неудачный вход', password_changed: 'смена пароля', site_created: 'создан сайт', site_updated: 'изменён сайт',
  site_deleted: 'удалён сайт', site_enabled: 'сайт включён', site_disabled: 'сайт выключен', site_cloned: 'копия сайта', config_applied: 'применена конфигурация',
  config_rollback: 'откат конфигурации', global_settings_updated: 'глобальные настройки', panel_settings_updated: 'настройки панели', cert_created: 'сертификат',
  cert_deleted: 'удалён сертификат', cert_renew: 'продление сертификата', user_created: 'создан пользователь', user_updated: 'изменён пользователь',
  user_deleted: 'удалён пользователь', diag_fix: 'исправление из диагностики', maintenance_on: 'обслуживание включено', maintenance_off: 'обслуживание выключено',
  '2fa_enabled': '2FA включена', '2fa_disabled': '2FA выключена', token_created: 'создан API-токен', config_imported: 'импорт настроек', config_exported: 'экспорт настроек',
  token_deleted: 'удалён API-токен', user_2fa_reset: 'сброшена 2FA пользователя', sites_bulk: 'действие над несколькими сайтами',
  stream_created: 'создан поток', stream_updated: 'изменён поток', stream_deleted: 'удалён поток', nginx_imported: 'импорт из nginx',
  alert_rule_created: 'создано правило оповещения', alert_rule_updated: 'изменено правило оповещения', alert_rule_deleted: 'удалено правило оповещения',
  alert_channel_created: 'создан канал уведомлений', alert_channel_updated: 'изменён канал уведомлений', alert_channel_deleted: 'удалён канал уведомлений',
  alerts_silenced: 'тишина оповещений', alerts_unsilenced: 'тишина завершена', report_sent: 'отправлен отчёт',
  ip_banned: 'IP заблокирован', ip_unbanned: 'IP разблокирован', bans_cleared: 'блокировки сняты', geo_rebuild: 'пересборка сетей стран',
  insight_muted: 'скрыт тип подсказок', insight_thresholds: 'пороги анализа', backup_created: 'создана резервная копия', backup_deleted: 'удалена резервная копия',
  cli_allowlist_clear: 'консоль: снято ограничение доступа по IP',
};

// действие, которого нет в словаре: управление nginx и команды консоли — по шаблону, остальное — как есть
const actionLabel = (a) => A[a] || (a.startsWith('nginx_') ? `nginx: ${a.slice(6)}` : a.startsWith('cli_user_') ? `консоль: пользователь — ${a.slice(9)}` : a);

// длинные детали (например, список из сотен сайтов) сворачиваются, чтобы не раздувать таблицу
function details(text) {
  if (!text) return '';
  if (text.length <= 160) return h('span', { class: 'mono small muted' }, text);
  return h('details', { class: 'small' }, h('summary', { class: 'mono muted' }, text.slice(0, 120) + '…'),
    h('div', { class: 'mono small', style: 'white-space:pre-wrap;word-break:break-all;max-height:260px;overflow:auto' }, text));
}

export async function render(root) {
  let q = '';
  const box = h('div', {});
  const load = async () => {
    const list = await api('/audit', { query: { limit: 500, q } });
    mount(box, h('div', { class: 'card' }, table([
      { title: 'Время', render: (r) => h('span', { class: 'nowrap small' }, fmtDate(r.ts, { sec: true, year: true })) },
      { title: 'Пользователь', render: (r) => h('b', {}, r.username || '—') }, { title: 'IP', render: (r) => h('span', { class: 'mono small' }, r.ip || '') },
      { title: 'Действие', render: (r) => actionLabel(r.action) }, { title: 'Объект', render: (r) => r.target || '' },
      { title: 'Детали', render: (r) => details(r.details) },
    ], list, { cls: 'compact', empty: 'Записей нет' })));
  };
  mount(root, h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Аудит действий'), h('p', {}, 'Кто, когда и что изменил. Хранится 365 дней.'))),
    h('div', { class: 'toolbar' }, h('input', { type: 'search', placeholder: 'Пользователь, действие, объект…', oninput: debounce((e) => { q = e.target.value; load(); }, 400) })), box);
  await load();
}
