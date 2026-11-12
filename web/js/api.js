// Доступ к REST API и WebSocket.
import { toast } from './ui.js';

export class ApiError extends Error {
  constructor(status, data) {
    super(typeof data?.detail === 'string' ? data.detail : `Ошибка ${status}`);
    this.status = status; this.data = data || {};
  }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

export async function api(path, { method = 'GET', body, query, raw = false, silent = false } = {}) {
  let url = '/api' + path;
  if (query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== '') q.set(k, v);
    const s = q.toString(); if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  const opts = { method, headers: { 'X-NM-CSRF': '1' }, credentials: 'same-origin' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(url, opts); }
  catch (e) { if (!silent) toast('Нет связи с сервером панели. Проверьте, что сервис nginx-manager запущен.', 'bad', 'Сеть'); throw e; }
  if (res.status === 401 && !path.startsWith('/auth/login')) { onUnauthorized(); throw new ApiError(401, { detail: 'Требуется вход' }); }
  if (raw) return res;
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const err = new ApiError(res.status, typeof data === 'string' ? { detail: data } : data);
    if (!silent) showError(err);
    throw err;
  }
  return data;
}

export function showError(err) {
  const d = err.data || {};
  let msg = err.message;
  if (d.errors && d.errors.length && d.errors[0].message) {
    msg += '\n' + d.errors.slice(0, 4).map(e => `• ${e.message}${e.hint ? ' → ' + e.hint : ''}`).join('\n');
  } else if (d.errors && d.errors.length && d.errors[0].msg) {
    msg = d.errors.slice(0, 6).map(e => `• ${e.loc ? e.loc + ': ' : ''}${e.msg}`).join('\n');
  }
  toast(msg, 'bad', err.status === 409 ? 'Конфигурация не применена' : err.status === 422 ? 'Проверьте поля формы' : 'Ошибка');
}

// ---------- WebSocket ----------
class Live {
  constructor() { this.handlers = {}; this.ws = null; this.retry = 1000; this.subs = {}; this.connected = false; }
  connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    try { this.ws = new WebSocket(`${proto}://${location.host}/api/ws`); } catch { return this.later(); }
    this.ws.onopen = () => { this.connected = true; this.retry = 1000; this.emit('status', true);
      for (const [k, v] of Object.entries(this.subs)) this.ws.send(JSON.stringify({ type: k, ...v })); };
    this.ws.onmessage = (e) => { try { const m = JSON.parse(e.data); this.emit(m.type, m); } catch { /* ignore */ } };
    this.ws.onclose = (e) => { this.connected = false; this.emit('status', false); if (e.code !== 4401) this.later(); };
    this.ws.onerror = () => {};
  }
  later() { setTimeout(() => this.connect(), this.retry); this.retry = Math.min(this.retry * 2, 15000); }
  on(type, fn) { (this.handlers[type] ||= new Set()).add(fn); return () => this.handlers[type].delete(fn); }
  emit(type, m) { (this.handlers[type] || []).forEach(fn => { try { fn(m); } catch (e) { console.error(e); } }); }
  send(type, payload) {
    this.subs[type] = payload;
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify({ type, ...payload }));
  }
  close() { if (this.ws) { this.ws.onclose = null; this.ws.close(); } }
}
export const live = new Live();
