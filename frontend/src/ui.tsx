import type { ReactNode } from 'react';
import { labels, locale, t } from './i18n';
import type { Provider } from './types';

// Label tables, formatters and the small presentational pieces every screen of the console shares.
export const STAGES = () => [['intake',t('接收','Intake')],['preflight',t('預檢','Preflight')],['whitebox',t('白箱審查','White-box review')],['adjudication',t('證據仲裁','Adjudication')],['threat_model',t('威脅建模','Threat modeling')],['case_design',t('測試設計','Test design')],['blackbox',t('黑箱驗證','Black-box verification')],['report',t('產出報告','Report')],['complete',t('完成','Complete')]];
export const STATUS: Record<string,string> = labels({created:['待啟動','Not started'],awaiting_approval:['待核准案例','Cases awaiting approval'],running:['執行中','Running'],cancelling:['停止中','Stopping'],cancelled:['已停止','Stopped'],completed:['已完成','Completed'],complete:['已完成','Completed'],sealed:['初審已封存','Initial review sealed'],incomplete:['未完整完成','Incomplete'],blocked:['受阻','Blocked'],failed:['執行失敗','Failed'],pass:['未觀測到違規','No violation observed'],fail:['觀測到違規','Violation observed'],inconclusive:['證據不足','Insufficient evidence'],execution_error:['執行錯誤','Execution error'],outcome_unknown:['結果不明','Outcome unknown']});
export const STATES: Record<string,string> = labels({hypothesis:['待驗證假設','Unverified hypothesis'],corroborated_static:['靜態佐證','Statically corroborated'],validated_dynamic:['動態驗證','Dynamically validated'],refuted:['已排除','Refuted'],inconclusive:['尚無定論','Inconclusive'],resolved_in_retest:['複測已修正','Fixed in retest']});
export const SEVERITY: Record<string,string> = labels({critical:['嚴重','Critical'],high:['高','High'],medium:['中','Medium'],low:['低','Low'],info:['資訊','Info']});
export const PROVIDERS: Record<Provider,string> = labels<Provider>({demo:['本地合成示範','Local synthetic demo'],openai:['OpenAI','OpenAI'],anthropic:['Anthropic Claude','Anthropic Claude'],nvidia_nim:['NVIDIA NIM','NVIDIA NIM'],openai_compatible:['相容 API／本地模型','Compatible API / local model'],bedrock:['AWS Bedrock（Claude 等）','AWS Bedrock (Claude and others)']});
export const formatNumber = (n: number | undefined) => new Intl.NumberFormat(locale()).format(n ?? 0);
export const short = (text: string | undefined) => text ? `${text.slice(0,10)}${text.length > 10 ? '…' : ''}` : t('未記錄','Not recorded');
export const date = (value: string) => { const d = new Date(value); return Number.isNaN(d.getTime()) ? value : d.toLocaleString(locale(), {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); };
export const stringify = (v: unknown): string => typeof v === 'string' ? v : JSON.stringify(v,null,2) ?? '—';
export function record(value: unknown): Record<string,unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string,unknown> : {}; }
export function executionResult(ex: Record<string,unknown>) { return Object.keys(record(ex.result)).length ? record(ex.result) : ex; }
export function Icon({name,size=20}: {name:string;size?:number}) {
  const paths: Record<string,ReactNode> = {
    shield:<><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/></>,
    grid:<><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    plus:<path d="M12 5v14M5 12h14"/>, play:<path d="m8 4 12 8-12 8Z"/>, stop:<rect x="5" y="5" width="14" height="14" rx="2"/>,
    arrow:<path d="M5 12h14m-5-5 5 5-5 5"/>, check:<path d="m5 12 4 4L19 6"/>, refresh:<><path d="M20 11a8 8 0 0 0-14-5L3 9m0-5v5h5M4 13a8 8 0 0 0 14 5l3-3m0 5v-5h-5"/></>,
    chip:<><rect x="6" y="6" width="12" height="12" rx="3"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 3v3m6-3v3m-6 12v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3"/></>,
    lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/></>,
    file:<><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Z"/><path d="M14 3v6h6M8 13h8m-8 4h5"/></>,
    pulse:<path d="M2 12h5l3-8 4 16 3-8h5"/>, download:<><path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/></>,
    alert:<><path d="m12 3 10 18H2Z"/><path d="M12 9v5m0 3v.2"/></>, link:<><path d="m9 15 6-6m-7 3-2 2a4 4 0 0 0 6 6l2-2m-4-12 2-2a4 4 0 0 1 6 6l-2 2"/></>,
    code:<><path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-16-2 20"/></>, close:<path d="m6 6 12 12M6 18 18 6"/>, chevron:<path d="m9 5 7 7-7 7"/>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.file}</svg>;
}
export function Badge({value,children}: {value?:string;children?:ReactNode}) { return <span className={`badge ${value ?? ''}`}>{children ?? STATUS[value ?? ''] ?? value}</span>; }
export function Empty({title,children}: {title:string;children?:ReactNode}) { return <div className="empty"><span className="empty-icon"><Icon name="file" size={25}/></span><h3>{title}</h3><p>{children}</p></div>; }
export function SafeText({value}: {value:unknown}) { return <pre className="safe-text">{stringify(value)}</pre>; }
export function Panel({title,eyebrow,children,action}: {title:string;eyebrow?:string;children:ReactNode;action?:ReactNode}) { return <section className="panel"><div className="panel-heading"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{action}</div>{children}</section>; }
export function Metric({title,value,note,icon,warn=false}: {title:string;value:number;note:string;icon:string;warn?:boolean}) {return <div className={`metric ${warn?'warn':''}`}><div><span>{title}</span><Icon name={icon} size={18}/></div><strong>{formatNumber(value)}</strong><small>{note}</small></div>;}
export function Usage({label,used=0,max}: {label:string;used?:number;max:number}) {const percentage=Math.min(100,max>0?used/max*100:0);return <div className="usage"><div><span>{label}</span><strong>{formatNumber(used)}<small> / {formatNumber(max)}</small></strong></div><div className="usage-track" role="progressbar" aria-label={label} aria-valuenow={used} aria-valuemin={0} aria-valuemax={Math.max(max,used)}><span style={{width:`${percentage}%`}}/></div></div>;}
export function Field({label,hint,children}: {label:string;hint?:string;children:ReactNode}) {return <label className="field"><span>{label}</span>{children}{hint&&<small>{hint}</small>}</label>;}
