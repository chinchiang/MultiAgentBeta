/** zh() reads the engine's English through the table the backend serves; say() shows it in the console's language. */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { api } from '../src/api';
import { setLang } from '../src/i18n';
import { loadMessages, say, zh } from '../src/messages';

vi.mock('../src/api', () => ({ api: vi.fn() }));
const serve = vi.mocked(api);

// A small table in the backend's shape: fixed messages, status words, and regex patterns with templates.
const TABLE = {
  exact: { 'Entering report': '進入報告階段', 'Gate': '閘門', 'Model refused the request': '模型拒絕了請求' },
  status: { pass: '未觀測到違規', fail: '觀測到違規' },
  patterns: [
    ['Excluded directory: (.+)', '已排除目錄：{0}'],
    ['(C-\\d+): (.+)', '{0}：{1}'],
    ['Model call failed \\((\\w+)\\): (.+)', '模型呼叫失敗（{0}）：{1}'],
  ],
};

beforeEach(async () => {
  setLang('zh-Hant');
  serve.mockResolvedValue(TABLE);
  await loadMessages();
});

describe('zh', () => {
  it('reads fixed messages, patterns with values, and statuses inside values', () => {
    expect(zh('Entering report')).toBe('進入報告階段');
    expect(zh('Excluded directory: node_modules/')).toBe('已排除目錄：node_modules/');
    expect(zh('C-9: pass')).toBe('C-9：未觀測到違規');
    expect(zh('Model call failed (refusal): Model refused the request')).toBe('模型呼叫失敗（refusal）：模型拒絕了請求');
  });

  it('reads "<label>: <message>" when either side is known, and leaves the rest as written', () => {
    expect(zh('Gate: pass')).toBe('閘門：未觀測到違規');
    expect(zh('semgrep: Entering report')).toBe('semgrep：進入報告階段');
    expect(zh('Gate: something a model wrote')).toBe('閘門：something a model wrote');
    expect(zh('Note: something a model wrote')).toBeUndefined();
    expect(zh('Unknown text')).toBeUndefined();
    expect(zh('')).toBeUndefined();
  });

  it('never reads an Object prototype member as an entry', () => {
    expect(zh('constructor')).toBeUndefined();
    expect(zh('toString: x')).toBeUndefined();
    expect(zh('C-1: constructor')).toBe('C-1：constructor');
  });

  it('matches a pattern against the whole message only', () => {
    expect(zh('Excluded directory: a\nb')).toBe('已排除目錄：a\nb');
    expect(zh('see Excluded directory: x')).toBeUndefined();
  });
});

describe('say', () => {
  it('shows the Chinese reading in Chinese and the original in English', () => {
    expect(say('Entering report')).toBe('進入報告階段');
    expect(say('Unknown text')).toBe('Unknown text');
    setLang('en');
    expect(say('Entering report')).toBe('Entering report');
  });

  it('turns anything that is not text into text', () => {
    expect(say(42)).toBe('42');
    expect(say(null)).toBe('');
    expect(say(undefined)).toBe('');
    expect(say({ a: 1 })).toBe('[object Object]');
  });
});

describe('loadMessages', () => {
  it('asks for /messages once and keeps the console working when the table cannot be loaded', async () => {
    expect(serve).toHaveBeenCalledWith('/messages');
    serve.mockRejectedValueOnce(new Error('offline'));
    await expect(loadMessages()).resolves.toBeUndefined();
    // The previous table stays in place: a failed reload loses nothing.
    expect(zh('Entering report')).toBe('進入報告階段');
  });
});
