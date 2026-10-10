/** The new-assessment form: the allowed-request line format, the demo submission, and the live-mode validation. */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { api } from '../src/api';
import { CreateForm, parseRequestLine, requestLine } from '../src/create-form';
import { setLang } from '../src/i18n';
import type { RunInput } from '../src/types';

vi.mock('../src/api', () => ({ api: vi.fn() }));
const serve = vi.mocked(api);
// The form's panels ask the backend for saved projects, model presets and the standards catalog on mount.
const EMPTY: Record<string, unknown> = { '/projects': { projects: [] }, '/models': { models: [] }, '/catalogs': { manifest: { collections: [] }, entries: [] } };

beforeEach(() => {
  setLang('zh-Hant');
  serve.mockImplementation(async path => { if (!(path in EMPTY)) throw new Error(`unexpected ${path}`); return EMPTY[path]; });
});
afterEach(() => { setLang('zh-Hant'); });

describe('parseRequestLine', () => {
  it('reads method and path, the model-body flag and the trailing header JSON', () => {
    expect(parseRequestLine('GET /api/profile')).toEqual({ method: 'GET', path: '/api/profile' });
    expect(parseRequestLine('  POST /chat model-body  ')).toEqual({ method: 'POST', path: '/chat', model_body: true });
    expect(parseRequestLine('GET /api {"Accept":["application/json","text/html"]}')).toEqual({ method: 'GET', path: '/api', model_headers: { Accept: ['application/json', 'text/html'] } });
    expect(parseRequestLine('PUT /x model-body {"X-A":["a b"]}')).toEqual({ method: 'PUT', path: '/x', model_body: true, model_headers: { 'X-A': ['a b'] } });
  });

  it('refuses anything else: unknown methods, relative paths, a brace in the path, and header JSON of the wrong shape', () => {
    for (const line of ['FETCH /x', 'GET x', 'GET /x{"A":["b"]}', 'GET /x {"A":"b"}', 'GET /x {"A":[]}', 'GET /x {"A":[1]}', 'GET /x ["A"]', 'GET /x {broken', 'GET /x extra', '']) {
      expect(parseRequestLine(line), line).toBeNull();
    }
  });

  it('round-trips through requestLine', () => {
    for (const line of ['GET /api/profile', 'POST /chat model-body', 'GET /api {"Accept":["application/json"]}', 'DELETE /a model-body {"X":["1","2"]}']) {
      expect(requestLine(parseRequestLine(line)!)).toBe(line);
    }
    expect(requestLine({ method: 'GET', path: '/x', model_headers: {} })).toBe('GET /x');
  });
});

describe('CreateForm', () => {
  it('submits a synthetic demo with the four synthetic models and no scope', async () => {
    const onCreate = vi.fn<(input: RunInput) => Promise<void>>().mockResolvedValue(undefined);
    render(<CreateForm onCreate={onCreate} busy={false} connected={true} />);
    expect(screen.getByLabelText('評估名稱')).toHaveProperty('value', '我的第一個安全評估');
    fireEvent.change(screen.getByLabelText('評估名稱'), { target: { value: '示範一' } });
    fireEvent.click(screen.getByRole('button', { name: '建立並開始' }));
    await waitFor(() => expect(onCreate).toHaveBeenCalledOnce());
    const input = onCreate.mock.calls[0][0];
    expect(input).toMatchObject({ schema_version: 2, name: '示範一', mode: 'demo', source_path: '', target_url: '', data_policy: 'local_only', allowed_requests: [], allowed_target_ips: [], auth_profiles: [], cases: [], parent_run_id: null });
    expect(input.models.map(m => [m.id, m.role, m.provider])).toEqual([['commander', 'commander', 'demo'], ['reviewer-a', 'reviewer', 'demo'], ['reviewer-b', 'reviewer', 'demo'], ['reviewer-c', 'reviewer', 'demo']]);
    expect(input.budget).toEqual({ max_seconds: 600, max_requests: 30, max_model_calls: 20, max_tokens: 50000 });
  });

  it('cannot be submitted while the service is not connected or a creation is in progress', () => {
    const onCreate = vi.fn<(input: RunInput) => Promise<void>>();
    const { unmount } = render(<CreateForm onCreate={onCreate} busy={false} connected={false} />);
    expect(screen.getByRole('button', { name: '建立並開始' })).toHaveProperty('disabled', true);
    unmount();
    render(<CreateForm onCreate={onCreate} busy={true} connected={true} />);
    expect(screen.getByRole('button', { name: /正在建立/ })).toHaveProperty('disabled', true);
    expect(onCreate).not.toHaveBeenCalled();
  });

  it('refuses an empty live assessment with the reasons, and the scope rules, before asking the backend', async () => {
    const onCreate = vi.fn<(input: RunInput) => Promise<void>>();
    render(<CreateForm onCreate={onCreate} busy={false} connected={true} />);
    fireEvent.click(screen.getByRole('button', { name: /實際評估/ }));
    fireEvent.change(screen.getByLabelText('本機程式來源', { exact: false }), { target: { value: 'relative/path' } });
    fireEvent.change(screen.getByLabelText('隔離 staging URL'), { target: { value: 'http://user:pw@127.0.0.1:8080' } });
    fireEvent.change(screen.getByLabelText('精確允許的請求', { exact: false }), { target: { value: 'GET /ok\nFETCH /nope' } });
    fireEvent.click(screen.getByRole('button', { name: '建立並開始' }));
    const alert = await screen.findByRole('alert');
    for (const reason of ['來源程式請使用本機絕對路徑。', '請設定有效的 HTTP(S) staging URL，不含帳密或 fragment。', '請填寫部署識別', '請明確列出允許測試的目標 IP。', '允許的請求每行填寫 GET /path 或 POST /path', '所有 Agent 都需要模型 ID、家族和 API 端點。', '三位審查員需要三個不同的模型家族。']) {
      expect(alert.textContent).toContain(reason);
    }
    expect(onCreate).not.toHaveBeenCalled();
  });

  it('switches to English with the interface', () => {
    setLang('en');
    render(<CreateForm onCreate={vi.fn()} busy={false} connected={true} />);
    expect(screen.getByLabelText('Assessment name')).toHaveProperty('value', 'My first security assessment');
    expect(screen.getByRole('button', { name: 'Create and start' })).toBeTruthy();
    expect(document.body.textContent).not.toContain('建立並開始');
  });
});
