/** Tools and runtime, shown as the backend reports them, in the console's language. */
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { CapabilitiesView, limitationText } from '../src/capabilities';
import { setLang } from '../src/i18n';
import type { Capabilities, Session } from '../src/types';

afterEach(() => { setLang('zh-Hant'); });

const capabilities: Capabilities = {
  tools: [
    { id: 'semgrep', available: true, status: 'runtime_pinned', detail: '固定映像可用', detail_en: 'Pinned image available' },
    { id: 'zap', available: false, status: 'runtime_required', detail: '需要 Docker runtime' },
  ],
  runtime: { profile: 'default' },
  limitations: ['No live model was tested.', 'Shared with the session.'],
  limitations_zh: ['沒有測試真實模型。', '與工作階段相同。'],
};
const session: Session = { csrf_token: 'x', mode: 'local', limitations: ['Shared with the session.'], limitations_zh: ['與工作階段相同。'] };

describe('limitationText', () => {
  it('pairs each English limitation with its Chinese wording, and falls back to English when the lists differ', () => {
    expect(limitationText(capabilities)).toEqual(['沒有測試真實模型。', '與工作階段相同。']);
    expect(limitationText({ limitations: ['a', 'b'], limitations_zh: ['只有一個'] })).toEqual(['a', 'b']);
    expect(limitationText({ limitations: ['a'] })).toEqual(['a']);
    expect(limitationText(null)).toEqual([]);
    setLang('en');
    expect(limitationText(capabilities)).toEqual(['No live model was tested.', 'Shared with the session.']);
  });
});

describe('CapabilitiesView', () => {
  it('shows each tool with its availability, status and detail, and the limitations once each', () => {
    render(<CapabilitiesView capabilities={capabilities} session={session} />);
    expect(screen.getByText('semgrep').parentElement!.textContent).toContain('可使用');
    expect(screen.getByText('zap').parentElement!.textContent).toContain('尚不可使用');
    expect(screen.getByText('固定映像可用')).toBeTruthy();
    expect(screen.getByText('需要 Docker runtime')).toBeTruthy();
    expect(screen.getByText('runtime_pinned')).toBeTruthy();
    const limitations = screen.getAllByRole('listitem').map(item => item.textContent);
    expect(limitations).toEqual(['與工作階段相同。', '沒有測試真實模型。']);
    expect(screen.getByText(/"profile": "default"/)).toBeTruthy();
  });

  it('reads in English, using each tool\'s English detail', () => {
    setLang('en');
    render(<CapabilitiesView capabilities={capabilities} session={session} />);
    expect(screen.getByText('Pinned image available')).toBeTruthy();
    expect(screen.getByText('需要 Docker runtime')).toBeTruthy();
    expect(screen.getByText('Known limitations')).toBeTruthy();
    expect(screen.getAllByRole('listitem').map(item => item.textContent)).toEqual(['Shared with the session.', 'No live model was tested.']);
    expect(document.body.textContent).not.toContain('已知限制');
  });

  it('says so when there is no tool list yet', () => {
    render(<CapabilitiesView capabilities={null} session={null} />);
    expect(screen.getByText('尚無工具清單')).toBeTruthy();
    expect(screen.queryAllByRole('listitem')).toEqual([]);
  });
});
