/** The language switch: Chinese by default, English on request, remembered per browser, and every reader follows it. */
import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type I18n = typeof import('../src/i18n');

async function fresh(): Promise<I18n> {
  vi.resetModules();
  return import('../src/i18n');
}

beforeEach(() => { localStorage.clear(); });
afterEach(() => { localStorage.clear(); });

describe('the default language', () => {
  it('is Traditional Chinese, with the page language and title to match', async () => {
    const i18n = await fresh();
    expect(i18n.getLang()).toBe('zh-Hant');
    expect(i18n.t('中文', 'English')).toBe('中文');
    expect(i18n.locale()).toBe('zh-TW');
    expect(document.documentElement.lang).toBe('zh-Hant');
    expect(document.title).toBe('Vibe Audit · 安全驗證工作台');
  });

  it('is English when this browser chose English before', async () => {
    localStorage.setItem('vibeaudit-lang', 'en');
    const i18n = await fresh();
    expect(i18n.getLang()).toBe('en');
    expect(i18n.t('中文', 'English')).toBe('English');
    expect(i18n.locale()).toBe('en-US');
    expect(document.title).toBe('Vibe Audit · Security Workbench');
  });

  it('ignores a stored value that is not a language, and storage that throws', async () => {
    localStorage.setItem('vibeaudit-lang', 'fr');
    expect((await fresh()).getLang()).toBe('zh-Hant');
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked'); });
    expect((await fresh()).getLang()).toBe('zh-Hant');
  });
});

describe('setLang', () => {
  it('switches every reader, remembers the choice and survives storage that throws', async () => {
    const i18n = await fresh();
    const table = i18n.labels({ running: ['執行中', 'Running'] as const });
    const label = ['已完成', 'Completed'] as const;
    i18n.setLang('en');
    expect(i18n.t('中文', 'English')).toBe('English');
    expect(table.running).toBe('Running');
    expect(Object.entries(table)).toEqual([['running', 'Running']]);
    expect(i18n.pick(label)).toBe('Completed');
    expect(i18n.pick(undefined)).toBeUndefined();
    expect(localStorage.getItem('vibeaudit-lang')).toBe('en');
    expect(document.documentElement.lang).toBe('en');
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked'); });
    i18n.setLang('zh-Hant');
    expect(table.running).toBe('執行中');
    expect(i18n.pick(label)).toBe('已完成');
  });

  it('re-renders components that use useLang, and stops once they unmount', async () => {
    const i18n = await fresh();
    const { result, unmount } = renderHook(() => i18n.useLang());
    expect(result.current).toBe('zh-Hant');
    act(() => i18n.setLang('en'));
    expect(result.current).toBe('en');
    unmount();
    expect(() => act(() => i18n.setLang('zh-Hant'))).not.toThrow();
    expect(i18n.getLang()).toBe('zh-Hant');
  });
});
