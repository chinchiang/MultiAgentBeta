import { useSyncExternalStore } from 'react';

// The console shows Traditional Chinese (Taiwan) or English. Every visible string is written as t('中文','English')
// at the place it is used, so a translation can never drift away from its source text.
export type Lang = 'zh-Hant' | 'en';

const STORAGE_KEY = 'vibeaudit-lang';
const listeners = new Set<() => void>();

function stored(): Lang {
  // Storage can be missing (server render) or throw (private mode, blocked site data); Chinese stays the default.
  try {
    const value = typeof localStorage === 'undefined' ? null : localStorage.getItem(STORAGE_KEY);
    if (value === 'en' || value === 'zh-Hant') return value;
  } catch { /* fall back to the default */ }
  return 'zh-Hant';
}

let current: Lang = stored();

export const getLang = (): Lang => current;
export const t = (zh: string, en: string): string => current === 'en' ? en : zh;
/** A [Chinese, English] label pair, for tables of labels defined once at module level. */
export type Label = readonly [string, string];
export const pick = (label: Label | undefined): string | undefined => label && t(label[0], label[1]);
/** Locale for Intl number and date formatting. */
export const locale = (): string => current === 'en' ? 'en-US' : 'zh-TW';

function apply() {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = current;
  document.title = t('Vibe Audit · 安全驗證工作台', 'Vibe Audit · Security Workbench');
}
apply();

export function setLang(next: Lang) {
  current = next;
  try { localStorage.setItem(STORAGE_KEY, next); } catch { /* the choice still applies to this page */ }
  apply();
  listeners.forEach(listener => listener());
}

/** Re-render the calling component, and everything it renders, when the language changes. */
export function useLang(): Lang {
  return useSyncExternalStore(listener => { listeners.add(listener); return () => { listeners.delete(listener); }; }, getLang, getLang);
}

/** A table whose values are read in the current language each time, so `table[key]` and `Object.entries(table)` follow a switch. */
export function labels<K extends string>(table: Record<K, Label>): Record<K, string> {
  const out = {} as Record<K, string>;
  for (const key of Object.keys(table) as K[]) {
    Object.defineProperty(out, key, { enumerable: true, get: () => t(table[key][0], table[key][1]) });
  }
  return out;
}
