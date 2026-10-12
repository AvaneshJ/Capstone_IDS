import { apiFetch, withEnvToken, API_BASE as BASE } from './client';

// Types
export interface Metrics { total_flows_analyzed: number; total_threats_detected: number; active_firewall_blocks: number; average_threat_risk: number; attack_distribution: Record<string, number>; top_offenders: Offender[]; }
export interface Offender { src_ip: string; incident_count: number; max_risk_score: number; attack_types: string[]; last_seen: number; }
export interface IncidentRow { incident_id: string; timestamp: number; src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: number; attack_type: string; confidence: number; risk_score: number; severity: string; action_taken: string; mitre_technique_id: string; mitre_technique_name: string; explanation: string; raw_json: string; status: string; }
export interface IncidentsResponse { count: number; incidents: IncidentRow[]; }
export interface HostIncidentRow { incident_id: string; timestamp: number; hostname: string; pid: number; process_name: string; parent_name: string; cpu_percent: number; memory_mb: number; file_path: string; file_type: string; event_type: string; classification: string; confidence: number; risk_score: number; severity: string; mitre_technique_id: string; mitre_technique_name: string; soar_action: string; action_status: string; remediation_notes: string; raw_json: string; }
export interface HostIncidentsResponse { count: number; host_incidents: HostIncidentRow[]; }
export interface BlockedIP { rule_id: string; ip_address: string; direction: string; block_timestamp: number; expiry_timestamp: number | null; reason: string; status: string; command_executed: string; }
export interface BlocksResponse { count: number; blocked_ips: BlockedIP[]; }
export type SensorState = 'running' | 'unavailable' | 'error' | 'stopped' | 'disabled' | 'needs_admin';
export interface LiveStatus {
  network: {
    state: SensorState; reason: string; backend?: '' | 'npcap' | 'windivert'; interfaces: string[]; packets_seen: number; started_at: number | null; queue: number;
    flows_checked: number; threats_found: number; incidents_created: number; repeats_grouped: number;
    outbound_flagged: number; ignored_noise: number; dropped: number; last_flow_at: number | null; last_threat_at: number | null;
  };
  host: { process_sensor: SensorState; file_sensor: SensorState; tamper_sensor?: SensorState; alerts: number; repeats_grouped: number; trusted_location_skipped: number };
  elevated?: boolean;
  response_mode: 'test' | 'live';
}
export interface IntegrityReport { state: 'ok' | 'tampered' | 'bad_signature' | 'no_manifest'; checked_at: number; files_checked: number; modified: string[]; missing: string[]; added: string[]; manifest_created_at: number | null; }
export interface EvidenceChainReport { ok: boolean; entries: number; problem_count: number; problems: string[]; checked_at: number; }
export interface SensorHeartbeat { name: string; state: 'alive' | 'silenced'; last_seen: number; seconds_since: number; timeout: number | null; silenced_since: number | null; reason: string; beats: number; }
export interface TamperEvent { kind: string; title: string; details: string; mitre: string; timestamp: number; incident_id: string; }
export interface SelfProtectionStatus {
  integrity: IntegrityReport | null;
  evidence_chain: EvidenceChainReport | null;
  watchdog: { sensors: Record<string, SensorHeartbeat>; silenced: string[] };
  recent_tamper_events: TamperEvent[];
  auth_required: boolean;
}
export interface SystemStatus { timestamp: number; total_flows: number; total_threats: number; total_blocked_ips: number; total_alerts: number; active_firewall_rules: number; cpu_percent: number; memory_percent: number; uptime_seconds: number; agent_statuses: Record<string, string>; test_mode?: boolean; live?: LiveStatus; self_protection?: SelfProtectionStatus; }
export interface ReportResponse { status: string; filename: string; download_url: string; }
export interface IncidentDetail { incident_id: string; timestamp: number; status: string; flow: any; detection: any; threat: any; risk: any; action_plan: any; firewall_rule: any; llm_explanation: any; }

export async function getHealthCheck(): Promise<{ status: string }> {
  return apiFetch<{ status: string }>('/');
}

export async function getMetrics(): Promise<Metrics> {
  return apiFetch<Metrics>('/api/metrics');
}

export async function getIncidents(limit?: number, severity?: string): Promise<IncidentsResponse> {
  const params = new URLSearchParams();
  if (limit !== undefined) params.append('limit', limit.toString());
  if (severity) params.append('severity', severity);
  
  const query = params.toString();
  const path = query ? `/api/incidents?${query}` : '/api/incidents';
  
  return apiFetch<IncidentsResponse>(path);
}

export async function getIncidentDetail(id: string): Promise<IncidentDetail> {
  return apiFetch<IncidentDetail>(`/api/incidents/${id}`);
}

export async function getHostIncidents(limit?: number, classification?: string): Promise<HostIncidentsResponse> {
  const params = new URLSearchParams();
  if (limit !== undefined) params.append('limit', limit.toString());
  if (classification) params.append('classification', classification);
  
  const query = params.toString();
  const path = query ? `/api/host/incidents?${query}` : '/api/host/incidents';
  
  return apiFetch<HostIncidentsResponse>(path);
}

export async function getBlocks(): Promise<BlocksResponse> {
  return apiFetch<BlocksResponse>('/api/blocks');
}

export async function unblockIP(ruleId: string): Promise<any> {
  return apiFetch<any>(`/api/blocks/unblock/${ruleId}`, { method: 'POST' });
}

export async function getSystemStatus(): Promise<SystemStatus> {
  return apiFetch<SystemStatus>('/api/status');
}

export async function getLiveStatus(): Promise<LiveStatus> {
  return apiFetch<LiveStatus>('/api/live/status');
}

export async function generateReport(): Promise<ReportResponse> {
  return apiFetch<ReportResponse>('/api/reports/generate', { method: 'POST' });
}

export function getReportDownloadUrl(filename: string): string {
  return withEnvToken(`${BASE}/api/reports/download/${filename}`);
}

export async function getSelfProtectionStatus(): Promise<SelfProtectionStatus> {
  return apiFetch<SelfProtectionStatus>('/api/selfprotect/status');
}

export async function runSelfProtectionChecks(): Promise<SelfProtectionStatus> {
  return apiFetch<SelfProtectionStatus>('/api/selfprotect/verify', { method: 'POST' });
}

export async function ingestFlow(payload: any): Promise<any> {
  return apiFetch<any>('/api/flows/ingest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function ingestHostEvent(payload: any): Promise<any> {
  return apiFetch<any>('/api/host/events/ingest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}
