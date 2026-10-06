// Cookies reach every port on this host, so the session cookie alone opens nothing. Every request also
// carries the CSRF token, kept in this page's port-scoped sessionStorage so a reload needs no startup token.
const CSRF_KEY = 'vibeaudit.csrf';
let csrfToken = readStoredCSRF();
let startupToken = '';
function readStoredCSRF() {
  try { return typeof sessionStorage === 'undefined' ? '' : sessionStorage.getItem(CSRF_KEY) ?? ''; } catch { return ''; }
}
export function setCSRF(value: string) {
  csrfToken = value;
  try {
    if (typeof sessionStorage === 'undefined') return;
    if (value) sessionStorage.setItem(CSRF_KEY, value); else sessionStorage.removeItem(CSRF_KEY);
  } catch { /* Storage unavailable: the token stays in memory for this page only. */ }
}
// The launch URL carries the startup token in its fragment, which browsers never send to the server.
// Keep it in memory only, and drop it from the address bar and history.
function takeStartupToken() {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token) { startupToken = token; history.replaceState(null, '', location.pathname + location.search); }
  return startupToken;
}
// After logout the page must not quietly open a new session with the token it still holds.
export function forgetStartupToken() { startupToken = ''; }
function headers(path: string, json: boolean): Record<string, string> {
  const result: Record<string, string> = json ? { 'Content-Type': 'application/json' } : {};
  const token = path === '/session' ? takeStartupToken() : '';
  if (token) result['X-VibeAudit-Token'] = token;
  else if (csrfToken) result['X-CSRF-Token'] = csrfToken;
  return result;
}
async function failure(response: Response): Promise<Error> {
  let data: unknown;
  try { data = await response.json(); } catch { return new Error(`無法讀取服務回應（HTTP ${response.status}）。請確認本地 API 已啟動。`); }
  const detail = (data as {detail?: unknown})?.detail;
  return new Error(typeof detail === 'string' ? detail : JSON.stringify(detail ?? data));
}
export async function api<T>(path: string, body?: unknown, method: 'GET'|'POST'|'PUT' = body === undefined ? 'GET' : 'POST'): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: headers(path, body !== undefined),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (path === '/session' && response.status === 401) {
    setCSRF('');
    throw new Error('需要啟動權杖：請開啟本地服務啟動時印出的完整網址（含 #token=…）。');
  }
  if (!response.ok) throw await failure(response);
  try { return await response.json() as T; } catch { throw new Error(`無法讀取服務回應（HTTP ${response.status}）。請確認本地 API 已啟動。`); }
}
// A plain link cannot send the CSRF header, so exports are fetched and handed to the browser as a file.
export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin', headers: headers(path, false) });
  if (!response.ok) throw await failure(response);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
// EventSource cannot send headers either; read the event stream with fetch and report each event name.
export async function streamEvents(path: string, onEvent: (name: string) => void, signal: AbortSignal): Promise<void> {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin', headers: { ...headers(path, false), Accept: 'text/event-stream' }, signal });
  if (!response.ok || !response.body) throw await failure(response);
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += value;
    for (let end = buffer.indexOf('\n\n'); end >= 0; end = buffer.indexOf('\n\n')) {
      const name = buffer.slice(0, end).split('\n').find(line => line.startsWith('event:'))?.slice(6).trim();
      buffer = buffer.slice(end + 2);
      if (name) onEvent(name);
    }
  }
}
