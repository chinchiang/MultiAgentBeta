let csrfToken = '';
export function setCSRF(value: string) { csrfToken = value; }
export async function api<T>(path: string, body?: unknown, method: 'GET'|'POST'|'PUT' = body === undefined ? 'GET' : 'POST'): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: unknown;
  try { data = await response.json(); } catch { throw new Error(`無法讀取服務回應（HTTP ${response.status}）。請確認本地 API 已啟動。`); }
  if (!response.ok) {
    const detail = (data as {detail?: unknown})?.detail;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail ?? data));
  }
  return data as T;
}
