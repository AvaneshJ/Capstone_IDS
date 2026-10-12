import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getIncidents, getHostIncidents, getSystemStatus } from '../api/endpoints';
import type { IncidentRow, HostIncidentRow } from '../api/endpoints';
import { translateThreat, translateSeverity, translateNetworkAction, translateHostAction, isBenign } from '../lib/translate';

export interface MergedAlert {
  id: string;
  source: 'network' | 'computer';
  time: number;
  severity: string;
  severityRaw: string;
  riskScore: number;
  typeRaw: string;
  title: string;
  story: string;
  actionLabel: string;
  actionState: 'done' | 'test' | 'failed' | 'none';
  confidence?: number;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  processName?: string;
  soarAction?: string;
  isNew?: boolean;
}

export function networkIncidentToAlert(inc: IncidentRow, testMode = false): MergedAlert {
  const threat = translateThreat(inc.attack_type);
  const sev = translateSeverity(inc.severity);
  const actionStatus = inc.action_taken?.toUpperCase() || '';
  let actionState: MergedAlert['actionState'] = 'none';
  if (actionStatus.includes('BLOCK') || actionStatus.includes('BAN') || actionStatus.includes('RATE')) actionState = testMode ? 'test' : 'done';

  return {
    id: inc.incident_id,
    source: 'network',
    time: inc.timestamp,
    severity: sev.label,
    severityRaw: inc.severity,
    riskScore: inc.risk_score,
    typeRaw: inc.attack_type,
    title: threat.friendlyName,
    story: threat.explanation,
    actionLabel: translateNetworkAction(inc.action_taken),
    actionState,
    confidence: inc.confidence,
    srcIp: inc.src_ip,
    dstIp: inc.dst_ip,
    dstPort: inc.dst_port,
  };
}

export function hostIncidentToAlert(inc: HostIncidentRow): MergedAlert {
  const threat = translateThreat(inc.classification);
  const sev = translateSeverity(inc.severity);
  const status = inc.action_status?.toUpperCase() || '';
  let actionState: MergedAlert['actionState'] = 'none';
  if (status.includes('SUCCESS')) actionState = 'done';
  else if (status.includes('SIMULATED')) actionState = 'test';
  else if (status.includes('FAILED')) actionState = 'failed';

  return {
    id: inc.incident_id,
    source: 'computer',
    time: inc.timestamp,
    severity: sev.label,
    severityRaw: inc.severity,
    riskScore: inc.risk_score,
    typeRaw: inc.classification,
    title: threat.friendlyName,
    story: threat.explanation,
    actionLabel: translateHostAction(inc.soar_action),
    actionState,
    confidence: inc.confidence,
    processName: inc.process_name,
    soarAction: inc.soar_action,
  };
}

export function useMergedActivity(limit: number = 100) {
  const { data: networkData, isLoading: networkLoading, error: networkError } = useQuery({
    queryKey: ['incidents', limit],
    queryFn: () => getIncidents(limit),
    refetchInterval: 10000,
  });

  const { data: hostData, isLoading: hostLoading, error: hostError } = useQuery({
    queryKey: ['host-incidents', limit],
    queryFn: () => getHostIncidents(limit),
    refetchInterval: 10000,
  });

  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: getSystemStatus,
    refetchInterval: 15000,
  });
  const testMode = status?.test_mode ?? false;

  const merged = useMemo((): MergedAlert[] => {
    const items: MergedAlert[] = [];

    for (const inc of networkData?.incidents ?? []) {
      if (!isBenign(inc.attack_type)) items.push(networkIncidentToAlert(inc, testMode));
    }
    for (const inc of hostData?.host_incidents ?? []) {
      if (!isBenign(inc.classification)) items.push(hostIncidentToAlert(inc));
    }

    items.sort((a, b) => b.time - a.time);
    return items;
  }, [networkData, hostData, testMode]);

  return {
    alerts: merged,
    isLoading: networkLoading || hostLoading,
    error: networkError || hostError,
    networkCount: networkData?.count ?? 0,
    hostCount: hostData?.count ?? 0,
  };
}
