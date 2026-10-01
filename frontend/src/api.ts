let csrfToken = '';
let startupToken = '';
export function setCSRF(value: string) { csrfToken = value; }
// The launch URL carries the startup token in its fragment, which browsers never send to the server.
// Keep it in memory only, and drop it from the address bar and history.
function takeStartupToken() {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token) { startupToken = token; history.replaceState(null, '', location.pathname + location.search); }
  return startupToken;
}
export async function api<T>(path: string, body?: unknown, method: 'GET'|'POST'|'PUT' = body === undefined ? 'GET' : 'POST'): Promise<T> {
  const token = path === '/session' ? takeStartupToken() : '';
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? (token ? { 'X-VibeAudit-Token': token } : {}) : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: unknown;
  try { data = await response.json(); } catch { throw new Error(`無法讀取服務回應（HTTP ${response.status}）。請確認本地 API 已啟動。`); }
  if (path === '/session' && response.status === 401) throw new Error('需要啟動權杖：請開啟本地服務啟動時印出的完整網址（含 #token=…）。');
  if (!response.ok) {
    const detail = (data as {detail?: unknown})?.detail;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail ?? data));
  }
  return data as T;
}
