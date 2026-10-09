import { api } from './api';
import { t } from './i18n';

// The engine writes its activity log, gaps, verdicts and errors in English. GET /api/messages serves the same
// Chinese table the API and reports use (backend/vibe_audit/messages.py), and zh() below reads it the same way.
// Model, scanner, target and operator text has no entry and stays as it was written.
interface Table { exact: Record<string, string>; status: Record<string, string>; patterns: [string, string][] }

let table: Table = { exact: {}, status: {}, patterns: [] };
let compiled: [RegExp, string][] = [];

/** Load the table once per session; without it every message shows as written. */
export async function loadMessages(): Promise<void> {
  try {
    table = await api<Table>('/messages');
    compiled = table.patterns.map(([pattern, template]) => [new RegExp(`^(?:${pattern})$`, 's'), template]);
  } catch { /* The console still works, in the service's own wording. */ }
}

// Own keys only: a message such as "constructor" must not read an Object prototype member.
const own = (entries: Record<string, string>, key: string): string | undefined => Object.hasOwn(entries, key) ? entries[key] : undefined;
const part = (text: string): string => own(table.status, text) ?? zh(text) ?? text;

/** The Chinese wording of an engine message, or undefined when it has none. */
export function zh(text: string): string | undefined {
  const exact = own(table.exact, text);
  if (exact !== undefined) return exact;
  for (const [pattern, template] of compiled) {
    const match = pattern.exec(text);
    if (match) return template.replace(/\{(\d+)\}/g, (_, index: string) => part(match[Number(index) + 1] ?? ''));
  }
  // "<label>: <message>": a known label or a known message on either side of the first colon.
  const colon = text.indexOf(': ');
  if (colon < 0) return undefined;
  const label = text.slice(0, colon), rest = text.slice(colon + 2);
  if (own(table.exact, label) !== undefined || own(table.status, rest) !== undefined || zh(rest) !== undefined) {
    return `${own(table.exact, label) ?? label}：${part(rest)}`;
  }
  return undefined;
}

/** An engine message in the console's language. */
export function say(text: unknown): string {
  if (typeof text !== 'string') return text == null ? '' : String(text);
  return t(zh(text) ?? text, text);
}
