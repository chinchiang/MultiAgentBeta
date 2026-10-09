/** The API client: startup token from the URL fragment, CSRF token on every request, errors in the console's language. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type Api = typeof import('../src/api');

const fetchMock = vi.fn<typeof fetch>();
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const lastRequest = () => {
  const [url, init] = fetchMock.mock.calls.at(-1) as [string, RequestInit];
  return { url, init, headers: init.headers as Record<string, string> };
};

async function fresh(): Promise<Api> {
  vi.resetModules();
  const i18n = await import('../src/i18n');
  i18n.setLang('zh-Hant');
  return import('../src/api');
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  sessionStorage.clear();
  history.replaceState(null, '', '/');
});
afterEach(() => { sessionStorage.clear(); });

describe('the startup token', () => {
  it('is read from the fragment for /session only, then dropped from the address bar', async () => {
    history.replaceState(null, '', '/?x=1#token=abc%20def');
    const { api } = await fresh();
    fetchMock.mockResolvedValueOnce(json({ csrf_token: 'c1' }));
    await api('/session');
    expect(lastRequest().url).toBe('/api/session');
    expect(lastRequest().headers).toEqual({ 'X-VibeAudit-Token': 'abc def' });
    expect(location.hash).toBe('');
    expect(location.search).toBe('?x=1');
    // A second session exchange still has the token in memory; any other path never sends it.
    fetchMock.mockResolvedValueOnce(json({ csrf_token: 'c1' }));
    await api('/session');
    expect(lastRequest().headers).toEqual({ 'X-VibeAudit-Token': 'abc def' });
    fetchMock.mockResolvedValueOnce(json({ runs: [] }));
    await api('/runs');
    expect(lastRequest().headers).toEqual({});
  });

  it('is forgotten after logout, so the page cannot quietly open a new session', async () => {
    history.replaceState(null, '', '/#token=abc');
    const { api, forgetStartupToken } = await fresh();
    fetchMock.mockResolvedValueOnce(json({}));
    await api('/session');
    forgetStartupToken();
    fetchMock.mockResolvedValueOnce(json({}, 401));
    await expect(api('/session')).rejects.toThrow('需要啟動權杖');
    expect(lastRequest().headers).toEqual({});
  });
});

describe('the CSRF token', () => {
  it('is sent on every request after setCSRF, kept in sessionStorage, and cleared on a 401 session', async () => {
    const { api, setCSRF } = await fresh();
    setCSRF('csrf-1');
    expect(sessionStorage.getItem('vibeaudit.csrf')).toBe('csrf-1');
    fetchMock.mockResolvedValueOnce(json({ ok: true }));
    await expect(api('/runs/1/start', {})).resolves.toEqual({ ok: true });
    expect(lastRequest().init.method).toBe('POST');
    expect(lastRequest().init.credentials).toBe('same-origin');
    expect(lastRequest().init.body).toBe('{}');
    expect(lastRequest().headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf-1' });
    fetchMock.mockResolvedValueOnce(json({ detail: 'expired' }, 401));
    await expect(api('/session')).rejects.toThrow('需要啟動權杖：請開啟本地服務啟動時印出的完整網址（含 #token=…）。');
    expect(sessionStorage.getItem('vibeaudit.csrf')).toBeNull();
    fetchMock.mockResolvedValueOnce(json({}));
    await api('/runs');
    expect(lastRequest().headers).toEqual({});
  });

  it('is restored from sessionStorage on a reload, and PUT is honoured', async () => {
    sessionStorage.setItem('vibeaudit.csrf', 'kept');
    const { api } = await fresh();
    fetchMock.mockResolvedValueOnce(json({}));
    await api('/projects/p', { name: 'x' }, 'PUT');
    expect(lastRequest().init.method).toBe('PUT');
    expect(lastRequest().headers['X-CSRF-Token']).toBe('kept');
  });
});

describe('errors', () => {
  it('read the service detail in the console language, switching with it', async () => {
    const { api } = await fresh();
    const { setLang } = await import('../src/i18n');
    fetchMock.mockResolvedValueOnce(json({ detail: 'Run not found', detail_zh: '找不到這個執行' }, 404));
    const error = await api('/runs/x').catch((e: unknown) => e) as Error;
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('找不到這個執行');
    setLang('en');
    expect(error.message).toBe('Run not found');
  });

  it('fall back to the English detail, a serialised detail, or an HTTP status', async () => {
    const { api } = await fresh();
    fetchMock.mockResolvedValueOnce(json({ detail: 'Only English' }, 400));
    await expect(api('/x')).rejects.toThrow('Only English');
    fetchMock.mockResolvedValueOnce(json({ detail: [{ loc: ['body'], msg: 'required' }] }, 422));
    await expect(api('/x')).rejects.toThrow('[{"loc":["body"],"msg":"required"}]');
    fetchMock.mockResolvedValueOnce(new Response('<html>', { status: 502 }));
    await expect(api('/x')).rejects.toThrow('無法讀取服務回應（HTTP 502）。請確認本地 API 已啟動。');
    fetchMock.mockResolvedValueOnce(new Response('not json', { status: 200 }));
    await expect(api('/x')).rejects.toThrow('無法讀取服務回應（HTTP 200）。請確認本地 API 已啟動。');
  });
});

describe('download', () => {
  it('fetches with the CSRF header and hands the browser a named file', async () => {
    const { download, setCSRF } = await fresh();
    setCSRF('csrf-2');
    fetchMock.mockResolvedValueOnce(new Response('# report', { status: 200 }));
    vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(() => 'blob:report'), revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    await download('/runs/1/report?format=markdown', 'vibe-audit-1.md');
    expect(lastRequest().headers).toEqual({ 'X-CSRF-Token': 'csrf-2' });
    expect(click).toHaveBeenCalledOnce();
    const anchor = click.mock.instances[0] as HTMLAnchorElement;
    expect(anchor.download).toBe('vibe-audit-1.md');
    expect(anchor.href).toBe('blob:report');
    expect(document.body.contains(anchor)).toBe(false);
    fetchMock.mockResolvedValueOnce(json({ detail: 'nope' }, 403));
    await expect(download('/runs/1/report', 'x')).rejects.toThrow('nope');
  });
});

describe('streamEvents', () => {
  it('reports each event name as it arrives, across chunk boundaries, and stops at the end of the stream', async () => {
    const { streamEvents } = await fresh();
    const chunks = ['event: progress\ndata: {}\n\nevent: prog', 'ress\ndata: {}\n\n: comment\n\nevent: done\n\n'];
    const body = new ReadableStream({ start(controller) { for (const chunk of chunks) controller.enqueue(new TextEncoder().encode(chunk)); controller.close(); } });
    fetchMock.mockResolvedValueOnce(new Response(body, { status: 200 }));
    const names: string[] = [];
    await streamEvents('/runs/1/events', name => names.push(name), new AbortController().signal);
    expect(names).toEqual(['progress', 'progress', 'done']);
    expect(lastRequest().headers.Accept).toBe('text/event-stream');
  });

  it('turns a refused stream into the service error', async () => {
    const { streamEvents } = await fresh();
    fetchMock.mockResolvedValueOnce(json({ detail: 'forbidden', detail_zh: '禁止' }, 403));
    await expect(streamEvents('/runs/1/events', () => {}, new AbortController().signal)).rejects.toThrow('禁止');
  });
});
