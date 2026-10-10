export type Provider = 'demo' | 'openai' | 'anthropic' | 'nvidia_nim' | 'openai_compatible' | 'bedrock';
export interface ModelProfile {
  id: string; role: 'commander' | 'reviewer' | 'architecture_mapper' | 'challenger' | 'threat_modeler' | 'test_designer' | 'reporter'; provider: Provider; model_id: string;
  family: string; endpoint: string; credential_env: string; aws_profile?: string; temperature: number | null; max_output_tokens: number;
  timeout_seconds?: number; prompt_version?: string;
}
export type HttpMethod = 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS';
export interface SecurityRequirement {id:string;statement:string;threat_ids:string[];source_kind:'operator'|'specification'|'derived';source:string;standard_ids:string[]}
export interface RunExtensions {requirements:SecurityRequirement[];runtime_profile:string;fixture_profile:string|null;static_tools:('semgrep'|'osv'|'gitleaks')[];deployment_header:string|null}
export interface ProjectSetting {id:string;name:string;configuration:RunInput}
export interface CatalogEntry {id:string;official_id:string;standard:string;version:string;title:string;description?:string;source:string;license:string}
export interface CatalogData {manifest:{collections:{standard:string;version:string;count:number;quality_notes:string[]}[]};entries:CatalogEntry[]}
export interface Budget { max_seconds: number; max_requests: number; max_model_calls: number; max_tokens: number }
export interface AuthProfile { id:string; credential_env:string; header:string; scheme:string; role:string; model_selectable?:boolean }
export interface RunInput {
  name: string; mode: 'demo' | 'live'; source_path: string; deployment_id: string; target_url: string;
  data_policy: 'local_only' | 'cloud_allowed'; allowed_model_origins: string[]; allowed_target_ips: string[];
  allowed_requests: {method: HttpMethod; path:string; model_body?:boolean; model_headers?:Record<string,string[]>}[];
  budget: Budget; models: ModelProfile[]; auth_profiles: AuthProfile[]; notes: string; parent_run_id: string | null; cases: TestCase[];
  schema_version?:2; requirements?:SecurityRequirement[]; runtime_profile?:string; fixture_profile?:string|null;
  static_tools?:('semgrep'|'osv'|'gitleaks')[]; deployment_header?:string|null; parent_finding_ids?:string[];
}
export interface AuditEvent { seq: number; at: string; stage: string; message: string; level: 'info' | 'warning' | 'error'; agent_id: string | null }
export interface Finding {
  id: string; title: string; severity: string; state: string; description: string; file: string | null;
  line: number | null; cwe: string | null; agent_ids: string[]; evidence_ids: string[]; threat_ids: string[];
  decisions?: {decision: string; rationale: string; evidence_ids: string[]; threat_ids: string[]; at: string; actor: string; previous_state: string}[];
  counterevidence?: string[];
}
export interface Review { agent_id: string; provider: string; model_id: string; family: string; status: string; findings: Finding[]; gaps: unknown[]; input_hash: string; simulated: boolean }
export interface Threat {
  id: string; title: string; asset_ids: string[]; category: string; preconditions: string[]; invariant: string;
  impact: string; control_evidence: unknown[]; assumptions: string[]; requirement_id: string; testability: string; blocked_reason: string | null;
}
export interface ThreatModel {
  id: string; version: number; source_digest: string; deployment_id: string; assets: {id: string; name: string; kind: string}[];
  dataflows: {id: string; source: string; target: string; boundary: string}[]; threats: Threat[]; standards: unknown[]; hash: string;
}
export interface TestCase {
  id: string; threat_ids: string[]; requirement_id: string; title: string; adapter: string; method: string; path: string;
  headers: Record<string,string>; body: unknown; identity: unknown; preconditions: unknown[]; designed_by?: string;
  oracle: {kind: string; forbidden_text: string[]; allowed_statuses: number[]; required_observations: string[]; expected_role: string | null};
  cleanup: unknown; side_effects: boolean; repetitions: number; observation_mode: string; source_digest: string; threat_model_hash: string; hash: string;
}
export type RunSummary = Pick<Run, 'id'|'name'|'mode'|'status'|'stage'|'created_at'|'updated_at'|'usage'|'usage_unknown'|'error'|'error_zh'|'workers_pending_cleanup'|'deployment_changed'>;
export interface Run {
  id: string; name: string; mode: string; status: string; stage: string; created_at: string; updated_at: string;
  manifest: RunInput; events: AuditEvent[]; reviews: Review[]; threat_model: ThreatModel | null; cases: TestCase[];
  executions: Record<string,unknown>[]; findings: Finding[]; gaps: unknown[]; limitations?: string[]; usage: {requests:number;model_calls:number;tokens:number};
  artifacts: unknown[]; error: unknown; error_zh?: string | null; workers_pending_cleanup?: boolean; usage_unknown?: boolean; deployment_changed?: boolean;
  gate_receipts?: Record<string,string>; case_approval?: {receipt:string; actor:string; approved_at:string; evidence_id:string};
}
export interface Capabilities { tools: {id:string;available:boolean;status:string;detail:string;detail_en?:string}[]; runtime: Record<string,unknown>; limitations: string[]; limitations_zh?: string[] }
export interface Session { csrf_token: string; mode: string; limitations: string[]; limitations_zh?: string[] }
