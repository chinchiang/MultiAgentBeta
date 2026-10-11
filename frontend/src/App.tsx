import { useCallback, useEffect, useState } from 'react';
import { api, forgetStartupToken, setCSRF, streamEvents } from './api';
import { CapabilitiesView } from './capabilities';
import { CreateForm } from './create-form';
import { setLang, t, useLang } from './i18n';
import { loadMessages } from './messages';
import { RunDetail, type RunAction } from './run-detail';
import type { Capabilities, Run, RunInput, RunSummary, Session } from './types';
import { Icon, STATUS, date } from './ui';

// The shell: session, run list, navigation between the three views, and the live refresh of the selected run.
export default function App() {
  const lang = useLang();
  const [session,setSession] = useState<Session|null>(null);
  const [capabilities,setCapabilities] = useState<Capabilities|null>(null);
  const [runs,setRuns] = useState<RunSummary[]>([]);
  const [selected,setSelected] = useState<Run|null>(null);
  const [view,setView] = useState<'runs'|'create'|'capabilities'>('runs');
  const [tab,setTab] = useState('overview');
  const [error,setError] = useState('');
  const [busy,setBusy] = useState('');
  const [connecting,setConnecting] = useState(true);
  const syncRun = useCallback((run:Run) => {setSelected(run); setRuns(prev => [run,...prev.filter(r=>r.id!==run.id)]);},[]);
  const connect = useCallback(async () => {
    setConnecting(true); setError('');
    try {
      const s = await api<Session>('/session'); setCSRF(s.csrf_token); setSession(s);
      const [caps,list] = await Promise.all([api<Capabilities>('/capabilities'),api<{runs:RunSummary[]}>('/runs'),loadMessages()]);
      setCapabilities(caps); setRuns(list.runs);
      if (list.runs.length) setSelected(await api<Run>(`/runs/${encodeURIComponent(list.runs[0].id)}`));
    } catch (e) {setError(e instanceof Error ? e.message : t('無法連線至本地服務','Cannot connect to the local service'));}
    finally {setConnecting(false);}
  },[]);
  const logout = useCallback(async () => {
    try {await api('/session/logout',{});} catch {/* An expired session is already ended. */}
    forgetStartupToken(); setCSRF(''); setSession(null); setRuns([]); setSelected(null); setCapabilities(null);
    setError(t('已登出。請用服務啟動時印出的網址重新開啟。','Signed out. Reopen the console with the URL printed when the service started.'));
  },[]);
  useEffect(()=>{void connect();},[connect]);
  // Polling follows the selected run's identity and status, not every refresh of its record.
  const selectedId=selected?.id; const selectedStatus=selected?.status;
  useEffect(()=>{
    if (!selectedId || !['running','cancelling'].includes(selectedStatus ?? '')) return;
    let active = true;
    let fetching = false;
    // Failed refreshes back off up to 30 s and report once, not every tick.
    let delay = 2500;
    let timer = 0;
    const refresh = async () => {
      if (fetching) return; fetching = true;
      try { const run = await api<Run>(`/runs/${encodeURIComponent(selectedId)}`); if(active) {syncRun(run); delay = 2500;} }
      catch(e) { if(active) {if(delay===2500)setError(t(`更新中斷：${e instanceof Error?e.message:'連線失敗'}。重新連線後可查看已保存進度。`,`Updates stopped: ${e instanceof Error?e.message:'connection failed'}. Reconnect to see the saved progress.`)); delay = Math.min(delay*2,30000);} }
      finally {fetching = false;}
    };
    const tick = async () => {await refresh(); if(active) timer = window.setTimeout(tick,delay);};
    const stream = new AbortController();
    // Polling below keeps the view current if the event stream drops.
    streamEvents(`/runs/${encodeURIComponent(selectedId)}/events`,name=>{void refresh();if(name==='done'||name==='expired')stream.abort();},stream.signal).catch(()=>{});
    timer = window.setTimeout(tick,delay);
    return ()=>{active=false;clearTimeout(timer);stream.abort();};
  },[selectedId,selectedStatus,syncRun]);
  async function selectRun(run:RunSummary) {setBusy('load');setError('');try {syncRun(await api<Run>(`/runs/${encodeURIComponent(run.id)}`));setView('runs');setTab('overview');}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy('');}}
  async function action(kind:RunAction) {if(!selected)return;let body={};if(kind==='approve-cases'){const count=selected.cases.filter(c=>c.designed_by==='model').length;if(!window.confirm(t(`將送出 ${selected.cases.length} 個已封存案例，其中 ${count} 個由模型設計。請先在「追溯」分頁核對每個案例的方法、路徑、標頭、本文與身分；核准只適用於目前這組案例。`,`This sends ${selected.cases.length} sealed cases, ${count} of them designed by a model. First check each case's method, path, headers, body and identity on the Trace tab; the approval covers only this set of cases.`)))return;body={receipt:selected.gate_receipts?.cases??''};}if(kind==='reconcile'){const attestation=window.prompt(t('監督程式未能確認工作容器已移除。請說明你如何確認已清理或重設測試環境。這段說明會存為證據；此執行之後不能再恢復，請以新的執行繼續。','The supervisor could not confirm that the worker container was removed. Describe how you confirmed the test environment was cleaned up or reset. This statement is stored as evidence; this run cannot be resumed afterwards, so continue with a new run.'))?.trim();if(!attestation)return;body={attestation};}setBusy(kind);setError('');try {syncRun(await api<Run>(`/runs/${encodeURIComponent(selected.id)}/${kind}`,body));}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy('');}}
  async function createRun(input:RunInput) {
    setBusy('create');setError('');
    try {const run=await api<Run>('/runs',input);syncRun(run);setView('runs');setTab('overview');syncRun(await api<Run>(`/runs/${encodeURIComponent(run.id)}/start`,{}));}
    catch(e){setError(e instanceof Error?e.message:String(e));throw e;}
    finally{setBusy('');}
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={e=>{e.preventDefault();setView('runs');}}><span className="brand-mark"><Icon name="shield" size={25}/></span><span>Vibe Audit<small>{t('安全驗證工作台','Security Workbench')}</small></span><span className="version">0.2.1</span></a>
      <div className="workspace-tag"><span className="live-dot"/> LOCAL WORKSPACE</div>
      <nav aria-label={t('主要導覽','Main navigation')}><button className={view==='runs'?'nav active':'nav'} aria-current={view==='runs'?'page':undefined} onClick={()=>setView('runs')}><Icon name="grid"/>{t('評估工作台','Assessments')}<span className="nav-count">{runs.length}</span></button><button className={view==='create'?'nav active':'nav'} aria-current={view==='create'?'page':undefined} onClick={()=>setView('create')}><Icon name="plus"/>{t('新建評估','New assessment')}</button><button className={view==='capabilities'?'nav active':'nav'} aria-current={view==='capabilities'?'page':undefined} onClick={()=>setView('capabilities')}><Icon name="chip"/>{t('工具與執行環境','Tools and runtime')}</button></nav>
      <div className="sidebar-label">{t('最近的評估','Recent assessments')}</div>
      <div className="recent-list">{runs.slice(0,8).map(run=><button key={run.id} className={`recent ${selected?.id===run.id&&view==='runs'?'selected':''}`} onClick={()=>void selectRun(run)}><span className={`status-dot ${run.status}`}/><span className="recent-content"><strong>{run.name}</strong><small>{run.mode==='demo'?t('示範','Demo'):t('實際評估','Live assessment')} · {STATUS[run.status]??run.status} · {date(run.created_at)}</small></span></button>)}{!runs.length&&<p className="sidebar-empty">{t('每一次評估，都留下','Every assessment leaves')}<br/>{t('可追溯的證據。','traceable evidence.')}</p>}</div>
      <div className="sidebar-footer"><Icon name="lock" size={17}/><span>{t('執行於本機','Runs on this machine')}<small>{t('資料送往模型依你的設定','Data goes to models only as you configure')}</small></span></div>
    </aside>
    <div className="main-shell"><header className="topbar"><div className="breadcrumb">{t('工作空間','Workspace')} <Icon name="chevron" size={13}/><strong>{view==='create'?t('新建評估','New assessment'):view==='capabilities'?t('工具與執行環境','Tools and runtime'):t('評估工作台','Assessments')}</strong></div><div className="topbar-status"><button type="button" className="button secondary small lang-toggle" lang={lang==='en'?'zh-Hant':'en'} aria-label={t('切換為英文介面','Switch to the Chinese interface')} onClick={()=>setLang(lang==='en'?'zh-Hant':'en')}>{lang==='en'?'中文':'English'}</button><span className={session?'live-dot':'live-dot off'}/>{connecting?t('連線中','Connecting'):session?t('本地服務已連線','Local service connected'):t('服務未連線','Service not connected')}<button className="icon-button" aria-label={t('重新連線並更新','Reconnect and refresh')} title={t('重新連線並更新','Reconnect and refresh')} onClick={()=>void connect()} disabled={connecting}><Icon name="refresh" size={16}/></button>{session&&<button className="button secondary small" title={t('結束這個工作階段；之後要用啟動網址重新開啟','End this session; reopen with the startup URL afterwards')} onClick={()=>void logout()}>{t('登出','Sign out')}</button>}</div></header>
      <main>
        {error&&<div className="notice error" role="alert"><Icon name="alert"/><div><strong>{t('這次操作尚未完成','This action did not complete')}</strong><p>{error}</p></div><button className="icon-button" aria-label={t('關閉提示','Dismiss notice')} onClick={()=>setError('')}><Icon name="close" size={16}/></button></div>}
        {!session&&!connecting?<div className="connection-card"><Icon name="pulse" size={38}/><h1>{t('等待本地服務','Waiting for the local service')}</h1><p>{t('先啟動 Vibe Audit 後端，並開啟它在終端機印出的含權杖網址。評估與證據會保存在你的本地工作空間。','Start the Vibe Audit backend, then open the URL with the token that it printed in the terminal. Assessments and evidence are stored in your local workspace.')}</p><button className="button primary" onClick={()=>void connect()}><Icon name="refresh" size={17}/>{t('重新連線','Reconnect')}</button><code>API · {import.meta.env.DEV?t('127.0.0.1:8000（開發模式經 Vite 代理）','127.0.0.1:8000 (through the Vite proxy in development)'):window.location.host||t('本機服務','Local service')}</code></div>:view==='create'?<CreateForm onCreate={createRun} busy={busy==='create'} connected={!!session}/>:view==='capabilities'?<CapabilitiesView capabilities={capabilities} session={session}/>:<>
          <div className="page-heading"><div><div className="eyebrow">EVIDENCE BEFORE CONFIDENCE</div><h1>{selected?selected.name:t('讓安全，有跡可循。','Make security traceable.')}</h1><p>{selected?t('從獨立白箱審查，到威脅導向驗證。每個結論都連回證據。','From independent white-box review to threat-driven verification. Every conclusion links back to evidence.'):t('先讀懂程式，再建立威脅模型，最後驗證真正的風險。','Understand the code first, then build the threat model, and finally verify the real risks.')}</p></div><button className="button primary" onClick={()=>setView('create')}><Icon name="plus" size={18}/>{t('新建評估','New assessment')}</button></div>
          {selected?<RunDetail run={selected} tab={tab} setTab={setTab} action={action} busy={busy} onCreated={syncRun}/>:<><div className="welcome-grid"><div className="welcome-main"><div className="orbit-graphic"><span className="orbit o1"/><span className="orbit o2"/><span className="orbit o3"/><span className="center-shield"><Icon name="shield" size={42}/></span><span className="orbit-node n1"><Icon name="code" size={18}/></span><span className="orbit-node n2"><Icon name="chip" size={18}/></span><span className="orbit-node n3"><Icon name="file" size={18}/></span></div><span className="eyebrow">MULTI-MODEL · LOCAL-FIRST</span><h2>{t('不同模型，獨立思考。','Different models, independent judgment.')}<br/>{t('共同依據，是證據。','The common ground is evidence.')}</h2><p>{t('一位指揮官協調三位審查員。各自完成初審後，再彙整工具結果與歧見，將威脅逐一轉為可驗證的測試。','One commander coordinates three reviewers. After each finishes an initial review, tool results and disagreements are combined and each threat becomes a verifiable test.')}</p><button className="button primary" onClick={()=>setView('create')}>{t('開始第一個評估','Start your first assessment')}<Icon name="arrow" size={17}/></button></div><div className="welcome-steps">{[['01',t('獨立白箱審查','Independent white-box review'),t('在同一份程式快照上，保留每個模型的判斷。','Keep each model\'s judgment on the same code snapshot.'),'code'],['02',t('威脅模型先行','Threat model first'),t('記錄資產、信任邊界與應被維持的安全條件。','Record assets, trust boundaries and the security conditions that must hold.'),'shield'],['03',t('用實際觀測驗證','Verify with real observations'),t('案例、執行與發現串成一條完整證據鏈。','Cases, executions and findings form one complete evidence chain.'),'link']].map(([n,title,desc,icon])=><div className="welcome-step" key={n}><span className="step-number">{n}</span><Icon name={icon}/><h3>{title}</h3><p>{desc}</p></div>)}</div></div><div className="notice subtle"><Icon name="file"/><p>{t('第一次使用？新建評估中的「合成示範」會在本地執行完整流程，不需模型金鑰，也不會對外發送測試請求。','First time here? The Synthetic demo under New assessment runs the whole flow locally, with no model keys and no outbound test requests.')}</p></div></>}
        </>}
      </main><footer className="main-footer"><span>VIBE AUDIT / LOCAL SECURITY WORKBENCH</span><span>{t('未發現違規 ≠ 已證明安全','No violation found ≠ proven secure')}</span></footer>
    </div>
  </div>;
}
