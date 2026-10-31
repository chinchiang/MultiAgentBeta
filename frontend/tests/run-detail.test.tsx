/** The selected run, rendered from the sample report the docs are built from: tabs, findings and the evidence decision rules. */
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import sample from '../../docs/sample-report.json';
import { api } from '../src/api';
import { setLang } from '../src/i18n';
import { RunDetail } from '../src/run-detail';
import type { Run } from '../src/types';

vi.mock('../src/api', () => ({ api: vi.fn(), download: vi.fn() }));
const serve = vi.mocked(api);
const run = sample as unknown as Run;
const noop = () => {};
const detail = (props: Partial<Parameters<typeof RunDetail>[0]> = {}) =>
  render(<RunDetail run={run} tab="overview" setTab={noop} action={async () => {}} busy="" {...props} />);

beforeEach(() => {
  setLang('zh-Hant');
  serve.mockImplementation(async path => { if (path.endsWith('/traceability')) return { entities: [], links: [] }; throw new Error(`unexpected ${path}`); });
});
afterEach(() => { setLang('zh-Hant'); });

describe('RunDetail', () => {
  it('shows included source coverage and partial reviewer progress without claiming full coverage', () => {
    const copy = structuredClone(run);
    copy.review_coverage = {source_digest:'frozen',files:29,characters:400000,batches:4,completed:{'reviewer-a':[0,1]}};
    detail({run:copy});
    expect(screen.getByText('已納入的閱讀範圍')).toBeTruthy();
    expect(screen.getByText('reviewer-a: 2/4')).toBeTruthy();
    expect(screen.getByText('reviewer-b: 0/4')).toBeTruthy();
    expect(screen.getByText(/省略與語意限制仍見驗證缺口/)).toBeTruthy();
  });
  it('shows the synthetic banner, the truthful status, the stage pipeline and the metrics', () => {
    detail();
    expect(screen.getByText('合成示範 · 不是實際安全評估')).toBeTruthy();
    expect(screen.getByText('未完整完成')).toBeTruthy();
    const stages = screen.getAllByRole('listitem').filter(item => item.className.includes('done') || item.className.includes('current'));
    expect(stages.map(item => item.textContent)).toContain('09完成');
    const metrics = [...document.querySelectorAll('.metric')].map(metric => [metric.querySelector('span')!.textContent, metric.querySelector('strong')!.textContent]);
    expect(metrics).toEqual([['安全發現', '3'], ['威脅情境', '2'], ['測試案例', '3'], ['驗證缺口', '1']]);
    expect(screen.getByRole('tab', { name: '發現 (3)' }).getAttribute('aria-selected')).toBe('false');
    expect(screen.getByRole('tab', { name: '總覽與模型' }).getAttribute('aria-selected')).toBe('true');
  });

  it('offers the actions the status allows and asks for the tab the operator clicks', () => {
    const setTab = vi.fn();
    const action = vi.fn().mockResolvedValue(undefined);
    detail({ setTab, action });
    expect(screen.queryByRole('button', { name: /啟動/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /停止執行/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /嘗試恢復/ }));
    expect(action).toHaveBeenCalledWith('resume');
    fireEvent.click(screen.getByRole('tab', { name: '執行紀錄' }));
    expect(setTab).toHaveBeenCalledWith('activity');
    const { unmount } = render(<RunDetail run={{ ...run, status: 'created' }} tab="overview" setTab={noop} action={action} busy="" />);
    expect(screen.getByRole('button', { name: /啟動/ })).toBeTruthy();
    unmount();
    render(<RunDetail run={{ ...run, status: 'running' }} tab="overview" setTab={noop} action={action} busy="" />);
    expect(screen.getByRole('button', { name: /停止執行/ })).toBeTruthy();
  });

  it('lists every event of the activity log with its stage in the interface language', () => {
    detail({ tab: 'activity' });
    // The nine pipeline stages are list items too.
    expect(screen.getAllByRole('listitem')).toHaveLength(9 + run.events.length);
    expect(screen.getByText(`${run.events.length} 筆事件`)).toBeTruthy();
    setLang('en');
    const { container } = detail({ tab: 'activity' });
    expect(container.textContent).toContain(`${run.events.length} events`);
    expect(container.textContent).not.toContain('筆事件');
  });

  it('filters findings by evidence state and links each to its evidence', () => {
    const setTab = vi.fn();
    detail({ tab: 'findings', setTab });
    expect(screen.getAllByRole('article')).toHaveLength(3);
    fireEvent.change(screen.getByLabelText('篩選證據狀態'), { target: { value: 'validated_dynamic' } });
    const [card] = screen.getAllByRole('article');
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(card.textContent).toContain('動態驗證');
    fireEvent.click(within(card).getAllByRole('button').find(b => b.className === 'evidence-link')!);
    expect(setTab).toHaveBeenCalledWith('evidence');
    fireEvent.change(screen.getByLabelText('篩選證據狀態'), { target: { value: 'refuted' } });
    expect(screen.getByText('沒有符合篩選的發現')).toBeTruthy();
  });
});

describe('the evidence decision', () => {
  it('keeps refutation disabled when a second linked threat is inconclusive', () => {
    const copy = structuredClone(run);
    const candidate = copy.findings.find(f => f.state === 'hypothesis')!;
    candidate.threat_ids = ['T-001', 'T-002'];
    copy.cases = copy.cases.filter(c => c.id !== 'C-001');
    copy.executions = copy.executions.filter(e => (e as {case_id?:string}).case_id !== 'C-001');
    detail({ run: copy, tab: 'findings' });
    const card = document.getElementById(`finding-${candidate.id}`) ?? screen.getAllByRole('article').find(a => a.textContent!.includes(candidate.id))!;
    fireEvent.click(within(card).getByText('證據裁決'));
    fireEvent.change(within(card).getByLabelText('裁決理由（會存入證據紀錄）'), { target: { value: 'Only one threat passed' } });
    fireEvent.change(within(card).getByLabelText('裁決'), { target: { value: 'refuted' } });
    const pass = within(card).getAllByRole('checkbox').find(box => box.parentElement!.textContent!.includes('C-002'))!;
    fireEvent.click(pass);
    expect(within(card).getByRole('button', { name: '記錄證據裁決' })).toHaveProperty('disabled', true);
    expect(card.textContent).toContain('所有相關案例、重複次數與威脅');
  });
  const hypothesis = run.findings.find(f => f.state === 'hypothesis' && f.threat_ids.length === 0)!;
  const validated = run.findings.find(f => f.state === 'validated_dynamic')!;
  const cardOf = (id: string) => screen.getAllByRole('article').find(article => article.textContent!.includes(id))!;

  it('never refutes an observed violation here', () => {
    detail({ tab: 'findings' });
    expect(cardOf(validated.id).textContent).toContain('已觀測到違規的發現不能在此排除');
    expect(within(cardOf(validated.id)).queryByText('證據裁決')).toBeNull();
  });

  it('mirrors the backend rules: cited evidence must test the chosen threats, and Refuted needs a pass with no observed violation', async () => {
    const onUpdated = vi.fn();
    detail({ tab: 'findings', onCreated: onUpdated });
    const card = cardOf(hypothesis.id);
    fireEvent.click(within(card).getByText('證據裁決'));
    const record = within(card).getByRole('button', { name: '記錄證據裁決' });
    expect(record).toHaveProperty('disabled', true);
    // The three black-box executions are offered; none is usable until a threat is chosen.
    const evidence = within(card).getAllByRole('checkbox').filter(box => (box.parentElement as HTMLElement).className === 'muted');
    expect(evidence).toHaveLength(3);
    fireEvent.change(within(card).getByLabelText('裁決理由（會存入證據紀錄）'), { target: { value: '觀測足夠' } });
    const threatBoxes = within(card).getAllByRole('checkbox').filter(box => !evidence.includes(box));
    expect(threatBoxes).toHaveLength(run.threat_model!.threats.length);
    // T-002 is tested by C-003 only (inconclusive): it becomes selectable, the T-001 executions stay muted.
    fireEvent.click(threatBoxes[1]);
    const usable = within(card).getAllByRole('checkbox').filter(box => !box.hasAttribute('disabled') && !threatBoxes.includes(box));
    expect(usable).toHaveLength(1);
    expect((usable[0].parentElement as HTMLElement).textContent).toContain('C-003');
    fireEvent.click(usable[0]);
    expect(within(card).getByRole('button', { name: '記錄證據裁決' })).toHaveProperty('disabled', false);
    // Refuted needs a cited pass: C-003 was inconclusive, so the button locks and the reason is shown.
    fireEvent.change(within(card).getByLabelText('裁決'), { target: { value: 'refuted' } });
    expect(card.textContent).toContain('「已排除」需要至少一筆被引用執行觀測到安全條件成立（pass）');
    expect(within(card).getByRole('button', { name: '記錄證據裁決' })).toHaveProperty('disabled', true);
    // Adding T-001 opens C-001 (fail) and C-002 (pass), but the observed violation on T-001 forbids Refuted outright.
    fireEvent.click(threatBoxes[0]);
    expect(card.textContent).toContain('後端不會接受「已排除」');
    fireEvent.change(within(card).getByLabelText('裁決'), { target: { value: 'inconclusive' } });
    const passBox = within(card).getAllByRole('checkbox').find(box => (box.parentElement as HTMLElement).textContent!.includes('C-002'))!;
    fireEvent.click(passBox);
    serve.mockResolvedValueOnce({ ...run, name: 'updated' });
    fireEvent.click(within(card).getByRole('button', { name: '記錄證據裁決' }));
    await waitFor(() => expect(onUpdated).toHaveBeenCalledWith(expect.objectContaining({ name: 'updated' })));
    const [path, body] = serve.mock.calls.at(-1)!;
    expect(path).toBe(`/runs/${run.id}/findings/${hypothesis.id}/decision`);
    expect(body).toMatchObject({ decision: 'inconclusive', rationale: '觀測足夠', threat_ids: ['T-002', 'T-001'] });
    expect((body as { evidence_ids: string[] }).evidence_ids).toHaveLength(2);
  });

  it('shows the service refusal next to the form', async () => {
    detail({ tab: 'findings' });
    const card = cardOf(hypothesis.id);
    fireEvent.click(within(card).getByText('證據裁決'));
    fireEvent.change(within(card).getByLabelText('裁決理由（會存入證據紀錄）'), { target: { value: 'x' } });
    fireEvent.click(within(card).getAllByRole('checkbox')[1]);
    fireEvent.click(within(card).getAllByRole('checkbox').find(box => (box.parentElement as HTMLElement).textContent!.includes('C-003'))!);
    serve.mockRejectedValueOnce(new Error('Decision rejected'));
    fireEvent.click(within(card).getByRole('button', { name: '記錄證據裁決' }));
    expect((await within(card).findByRole('alert')).textContent).toBe('Decision rejected');
  });
});
