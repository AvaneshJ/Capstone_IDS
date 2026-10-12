import { useContext, useState, type ReactNode } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  CheckCircle2,
  Download,
  ShieldCheck,
  FlaskConical,
  XCircle,
  Clock,
  Unlock,
  Info,
  Check,
  Globe,
  Monitor,
  ExternalLink,
  Lightbulb,
  OctagonX,
  BadgeCheck,
} from 'lucide-react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { toast } from 'sonner';

import { ExpertContext } from '../App';
import { Skeleton, ErrorState, RiskGauge, TechDetails, ConfirmModal, StoryFlow, SeverityBadge, IconTile } from '../components/index';
import { getIncidentDetail, getHostIncidents, unblockIP, generateReport, getReportDownloadUrl, terminateHostProgram, trustHostProgram, type HostFollowup, type TrustScope } from '../api/endpoints';
import { translateThreat, translateFileType, translateHostAction, translateNetworkAction, formatDuration, translateIP, translatePort, mitreLink, isTrustedAccess } from '../lib/translate';
import { openDownload, openExternal } from '../lib/desktop';

dayjs.extend(relativeTime);

type ActionOutcome = 'done' | 'test' | 'failed' | 'other';

// Mirrors hids/trust.py: these sign Windows itself (including script hosts), so they can't be trusted wholesale.
const PLATFORM_PUBLISHERS = new Set(['microsoft windows', 'microsoft windows publisher', 'microsoft corporation']);

interface AlertView {
  source: 'network' | 'computer';
  incidentId: string;
  timestamp: number;
  threatRaw: string;
  severity: string;
  riskScore: number;
  confidence: number | null;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  processName?: string;
  pid?: number;
  exePath?: string;
  trust?: { level?: string; publisher?: string; signature?: string; reason?: string } | null;
  followups?: HostFollowup[];
  filePath?: string;
  fileType?: string;
  actionLabel: string;
  outcome: ActionOutcome;
  banSeconds?: number;
  ruleId?: string;
  ruleStatus?: string;
  expiresAt?: number | null;
  mitreId?: string;
  mitreName?: string;
  reasons?: string[];
  remediationNotes?: string;
  llm?: { summary?: string; soc_recommendations?: string[] } | null;
  raw: Record<string, any>;
}

function outcomeFromStatus(status: string | null | undefined): ActionOutcome {
  const s = (status || '').toUpperCase();
  if (s.includes('FAILED')) return 'failed';
  if (s.includes('SIMULATED')) return 'test';
  if (s.includes('SUCCESS') || s === 'ACTIVE') return 'done';
  return 'other';
}

// GET /api/incidents/{id} returns Incident.to_dict() (nested) when raw_json exists, otherwise the flat DB row.
function networkView(d: any): AlertView {
  if (d.flow) {
    const rule = d.firewall_rule;
    const action = d.action_plan?.action_type;
    return {
      source: 'network',
      incidentId: d.incident_id,
      timestamp: d.timestamp,
      threatRaw: d.detection?.attack_type || 'Unknown',
      severity: d.risk?.severity || 'LOW',
      riskScore: d.risk?.score ?? 0,
      confidence: d.detection?.confidence ?? null,
      srcIp: d.flow.src_ip,
      dstIp: d.flow.dst_ip,
      dstPort: d.flow.dst_port,
      actionLabel: translateNetworkAction(action, d.action_plan?.ban_duration_seconds),
      outcome: rule ? outcomeFromStatus(rule.status) : 'other',
      banSeconds: d.action_plan?.ban_duration_seconds,
      ruleId: rule?.rule_id,
      ruleStatus: rule?.status,
      expiresAt: rule?.expires_at ?? null,
      mitreId: d.threat?.mitre_technique_id,
      mitreName: d.threat?.mitre_technique_name,
      llm: d.llm_explanation,
      raw: d,
    };
  }
  return {
    source: 'network',
    incidentId: d.incident_id,
    timestamp: d.timestamp,
    threatRaw: d.attack_type || 'Unknown',
    severity: d.severity || 'LOW',
    riskScore: d.risk_score ?? 0,
    confidence: d.confidence ?? null,
    srcIp: d.src_ip,
    dstIp: d.dst_ip,
    dstPort: d.dst_port,
    actionLabel: translateNetworkAction(d.action_taken),
    outcome: 'other',
    mitreId: d.mitre_technique_id,
    mitreName: d.mitre_technique_name,
    llm: null,
    raw: d,
  };
}

function hostView(row: any): AlertView {
  const details = row.raw_json ? JSON.parse(row.raw_json) : {};
  return {
    source: 'computer',
    incidentId: row.incident_id,
    timestamp: row.timestamp,
    threatRaw: row.classification || 'Unknown',
    severity: row.severity || 'LOW',
    riskScore: row.risk_score ?? 0,
    confidence: row.confidence ?? null,
    processName: row.process_name,
    pid: row.pid,
    exePath: details.process?.exe_path || '',
    trust: details.raw_event?.trust ?? null,
    followups: row.followups ?? [],
    filePath: row.file_path,
    fileType: row.file_type,
    actionLabel: translateHostAction(row.soar_action),
    outcome: outcomeFromStatus(row.action_status),
    mitreId: row.mitre_technique_id,
    mitreName: row.mitre_technique_name,
    reasons: Array.isArray(details.reasons) ? details.reasons : [],
    remediationNotes: row.remediation_notes,
    llm: details.llm_explanation,
    raw: { ...row, raw_json: undefined, details },
  };
}

function StepCard({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <section className="glass p-5 animate-fade-up">
      <h2 className="flex items-center gap-3 text-[15px] font-semibold text-fg mb-4">
        <span className="w-7 h-7 rounded-lg bg-accent/15 ring-1 ring-inset ring-accent/30 text-accent-soft text-xs font-bold inline-flex items-center justify-center">
          {n}
        </span>
        {title}
      </h2>
      {children}
    </section>
  );
}

export default function AlertDetail() {
  const { expert } = useContext(ExpertContext);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { source, id } = useParams<{ source: string; id: string }>();
  const [unblockModalOpen, setUnblockModalOpen] = useState(false);
  const [stopModalOpen, setStopModalOpen] = useState(false);
  const [trustScope, setTrustScope] = useState<TrustScope | null>(null);
  const [busy, setBusy] = useState(false);
  const [isReviewed, setIsReviewed] = useState(localStorage.getItem(`sentinel_reviewed_${id}`) === 'true');

  const { data: view, isLoading, error, refetch } = useQuery({
    queryKey: ['incident-detail', source, id],
    queryFn: async (): Promise<AlertView> => {
      if (source === 'network') return networkView(await getIncidentDetail(id!));
      if (source === 'computer') {
        const { host_incidents } = await getHostIncidents(500);
        const incident = host_incidents.find((i) => i.incident_id === id);
        if (!incident) throw new Error('Incident not found');
        return hostView(incident);
      }
      throw new Error('Unknown source');
    },
    enabled: !!id && !!source,
  });

  const back = (
    <button onClick={() => navigate(-1)} className="btn btn-ghost btn-sm -ml-2 mb-4">
      <ArrowLeft size={15} /> Back
    </button>
  );

  if (isLoading) {
    return (
      <div className="space-y-5">
        {back}
        <Skeleton className="h-28" />
        <div className="grid grid-cols-2 gap-5">
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
        </div>
      </div>
    );
  }
  if (error || !view) {
    return (
      <div>
        {back}
        <ErrorState message="We couldn't load this alert." onRetry={() => refetch()} />
      </div>
    );
  }

  const markReviewed = () => {
    localStorage.setItem(`sentinel_reviewed_${id}`, 'true');
    setIsReviewed(true);
    toast.success('Marked as reviewed');
  };

  const handleDownload = async () => {
    try {
      const report = await generateReport();
      openDownload(getReportDownloadUrl(report.filename));
    } catch {
      toast.error("Couldn't create the report");
    }
  };

  const handleUnblock = async () => {
    if (!view.ruleId) return;
    try {
      await unblockIP(view.ruleId);
      toast.success('Address unblocked');
      queryClient.invalidateQueries({ queryKey: ['blocks'] });
      queryClient.invalidateQueries({ queryKey: ['incident-detail', source, id] });
    } catch {
      toast.error('Failed to unblock address');
    }
  };

  const refreshHost = () => {
    queryClient.invalidateQueries({ queryKey: ['incident-detail', source, id] });
    queryClient.invalidateQueries({ queryKey: ['host-incidents'] });
    queryClient.invalidateQueries({ queryKey: ['trusted-programs'] });
  };

  const handleStop = async () => {
    setBusy(true);
    try {
      const res = await terminateHostProgram(view.incidentId);
      if (res.status === 'SUCCESS' || res.status === 'ALREADY_EXITED') toast.success(res.message);
      else toast.error(res.message);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Couldn't stop the program");
    } finally {
      setBusy(false);
      refreshHost();
    }
  };

  const handleTrust = async (scope: TrustScope) => {
    setBusy(true);
    try {
      const res = await trustHostProgram(view.incidentId, scope);
      toast.success('Marked as safe', { description: `${res.rule.label} will no longer raise alerts. You can undo this in Settings.` });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Couldn't mark this program as safe");
    } finally {
      setBusy(false);
      refreshHost();
    }
  };

  const threatInfo = translateThreat(view.threatRaw);
  const time = dayjs.unix(view.timestamp);
  const targetFile = translateFileType(view.fileType, view.filePath);
  const isNetwork = view.source === 'network';
  const touchedFile = !isNetwork && !!view.filePath;
  const trusted = isTrustedAccess(view.threatRaw);
  const signedBy = view.trust?.signature === 'valid' ? view.trust.publisher : '';
  const publisherTrustable = !!signedBy && !PLATFORM_PUBLISHERS.has(signedBy.toLowerCase());
  const followups = view.followups ?? [];
  const markedSafe = followups.some((f) => f.action === 'MARKED_SAFE');
  const stopped = followups.some((f) => f.action === 'TERMINATED' || f.status === 'ALREADY_EXITED');
  const canStop = !isNetwork && !!view.pid && view.pid > 4 && !stopped && view.outcome !== 'done';

  let summary: string = threatInfo.explanation;
  if (touchedFile && trusted) summary = `${view.processName || 'A program'}${signedBy ? ` (signed by ${signedBy})` : ''} opened ${targetFile.charAt(0).toLowerCase()}${targetFile.slice(1)}. ${summary}`;
  else if (touchedFile) summary = `${view.processName || 'A program'} tried to open ${targetFile.charAt(0).toLowerCase()}${targetFile.slice(1)}. ${summary}`;
  else if (!isNetwork) summary = `${view.processName || 'A program'} behaved unusually. ${summary}`;
  const aiSummary = expert ? view.llm?.summary : undefined;

  const confidence = view.confidence != null ? Math.round(view.confidence * 100) : null;
  const expiry = view.expiresAt ? dayjs.unix(view.expiresAt) : null;
  const minutesLeft = expiry ? Math.max(expiry.diff(dayjs(), 'minute'), 0) : 0;
  const timerText = expiry ? `Block ends in ${Math.floor(minutesLeft / 60)}h ${minutesLeft % 60}m` : '';
  const canUnblock = isNetwork && !!view.ruleId && ['ACTIVE', 'SIMULATED'].includes((view.ruleStatus || '').toUpperCase());

  const expertAdvice = expert ? view.llm?.soc_recommendations ?? [] : [];
  let advice: string[] = [threatInfo.advice, ...expertAdvice].filter(Boolean);
  if (!trusted && !markedSafe && (view.threatRaw.toLowerCase().includes('stealer') || touchedFile)) {
    advice = [
      'Change the passwords saved in your browser.',
      'Sign out of all sessions on important websites (email, bank).',
      'Run a full antivirus scan.',
      ...expertAdvice,
    ];
  }
  advice = [...new Set(advice)];

  const blockedFor = view.banSeconds ? ` for ${formatDuration(view.banSeconds)}` : '';

  const outcome = {
    done: { icon: isNetwork ? CheckCircle2 : ShieldCheck, tone: 'safe' as const, title: isNetwork ? `Blocked this address${blockedFor}` : view.actionLabel, note: 'Handled automatically. No action needed from you.' },
    test: { icon: FlaskConical, tone: 'accent' as const, title: `Test mode: we would have ${isNetwork ? `blocked this address${blockedFor}` : view.actionLabel.toLowerCase()}`, note: `SentinelAI is in safe test mode, so nothing on your computer was changed.${isNetwork ? '' : ' You can still stop the program yourself below.'}` },
    failed: { icon: XCircle, tone: 'danger' as const, title: "We tried to stop it but couldn't", note: 'Please follow the steps on the right, or contact IT support.' },
    other: { icon: Info, tone: 'neutral' as const, title: view.actionLabel, note: view.remediationNotes || '' },
  }[view.outcome];
  const OutcomeIcon = outcome.icon;

  return (
    <div className="space-y-5">
      {back}

      <section className="glass p-6 flex items-center gap-5 animate-fade-up">
        <IconTile tone={isNetwork ? 'accent' : 'mint'} size="lg">
          {isNetwork ? <Globe size={24} /> : <Monitor size={24} />}
        </IconTile>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <SeverityBadge severity={view.severity} />
            <span className="tag tag-neutral">{isNetwork ? 'From the internet' : 'On this computer'}</span>
            {isReviewed && (
              <span className="tag tag-safe">
                <Check size={12} /> Reviewed
              </span>
            )}
          </div>
          <h2 className="text-xl font-semibold tracking-tight text-fg">{threatInfo.friendlyName}</h2>
          <p className="text-[13px] text-fg-muted mt-0.5" title={time.format('YYYY-MM-DD HH:mm:ss')}>
            {time.fromNow()} · {time.format('dddd, MMM D, h:mm A')}
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          {!isReviewed && (
            <button onClick={markReviewed} className="btn btn-secondary">
              <Check size={15} /> Mark as reviewed
            </button>
          )}
          <button onClick={handleDownload} className="btn btn-secondary">
            <Download size={15} /> Report
          </button>
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <StepCard n={1} title="What happened?">
          <p className="text-[15px] text-fg leading-relaxed">{summary}</p>
          {aiSummary && (
            <div className="mt-3 glass-inset p-3">
              <div className="text-[11px] text-fg-subtle mb-1">AI analysis</div>
              <p className="text-[13px] text-fg-muted leading-relaxed selectable">{aiSummary}</p>
            </div>
          )}
          {isNetwork && view.srcIp && (
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="glass-inset p-3">
                <div className="text-[11px] text-fg-subtle mb-0.5">Who</div>
                <div className="text-sm text-fg font-medium">{translateIP(view.srcIp, expert)}</div>
              </div>
              <div className="glass-inset p-3">
                <div className="text-[11px] text-fg-subtle mb-0.5">Tried to reach</div>
                <div className="text-sm text-fg font-medium">{view.dstPort ? translatePort(view.dstPort) : 'Your computer'}</div>
              </div>
            </div>
          )}
          {!isNetwork && view.reasons && view.reasons.length > 0 && (
            <div className="mt-4 glass-inset p-3">
              <div className="text-[11px] text-fg-subtle mb-1.5">Why it was flagged</div>
              <ul className="space-y-1.5">
                {view.reasons.map((reason, idx) => (
                  <li key={idx} className="text-[13px] text-fg-muted leading-relaxed flex items-start gap-2 selectable">
                    <span className="text-fg-subtle shrink-0">•</span>
                    {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {!isNetwork && (
            <div className="mt-4">
              <StoryFlow
                steps={[
                  { icon: 'cpu', label: view.processName || 'A program' },
                  { icon: touchedFile ? 'file-lock' : 'activity', label: touchedFile ? targetFile : 'Unusual behaviour' },
                  { icon: 'shield', label: view.outcome === 'test' ? `Test mode: ${view.actionLabel.toLowerCase()}` : view.actionLabel },
                ]}
              />
            </div>
          )}
        </StepCard>

        <StepCard n={2} title="How dangerous is it?">
          <div className="flex items-center justify-around gap-6">
            <RiskGauge score={view.riskScore} />
            <div className="space-y-3 text-sm max-w-[220px]">
              {confidence != null && (
                <div>
                  <div className="text-[11px] text-fg-subtle mb-1">How sure we are</div>
                  <div className="h-2 rounded-[3px] bg-white/8 overflow-hidden">
                    <div className="h-full rounded-[3px] bg-gradient-to-r from-accent-strong to-accent-soft" style={{ width: `${confidence}%` }} />
                  </div>
                  <div className="text-fg mt-1 font-medium">{confidence}% sure this is real</div>
                </div>
              )}
              {view.mitreId && view.mitreId !== 'T0000' && (
                <div>
                  <div className="text-[11px] text-fg-subtle mb-1">Known attack technique</div>
                  <button onClick={() => openExternal(mitreLink(view.mitreId!))} className="text-accent-soft hover:text-fg text-[13px] inline-flex items-center gap-1 text-left">
                    {view.mitreName || view.mitreId}
                    {expert && <span className="font-mono text-fg-subtle">({view.mitreId})</span>}
                    <ExternalLink size={12} />
                  </button>
                </div>
              )}
            </div>
          </div>
        </StepCard>

        <StepCard n={3} title="What did SentinelAI do?">
          <div className="glass-inset p-4 flex items-start gap-3">
            <IconTile tone={outcome.tone} size="sm">
              <OutcomeIcon size={16} />
            </IconTile>
            <div>
              <p className="text-sm font-medium text-fg">{outcome.title}</p>
              {outcome.note && <p className="text-[13px] text-fg-muted mt-0.5">{outcome.note}</p>}
              {timerText && (
                <p className="text-xs text-fg-subtle mt-2 flex items-center gap-1.5">
                  <Clock size={12} /> {timerText}
                </p>
              )}
            </div>
          </div>
          {canUnblock && (
            <button onClick={() => setUnblockModalOpen(true)} className="btn btn-ghost btn-sm mt-3">
              <Unlock size={14} /> Unblock this address
            </button>
          )}
          {followups.length > 0 && (
            <ul className="mt-3 space-y-1.5">
              {followups.map((f, idx) => (
                <li key={idx} className="text-[13px] text-fg-muted flex items-start gap-2">
                  {f.action === 'MARKED_SAFE' ? <BadgeCheck size={14} className="text-safe shrink-0 mt-0.5" /> : f.action === 'TERMINATED' ? <OctagonX size={14} className="text-safe shrink-0 mt-0.5" /> : <Info size={14} className="text-fg-subtle shrink-0 mt-0.5" />}
                  <span>
                    {f.action === 'MARKED_SAFE' ? `You marked this as safe: ${f.detail}` : f.detail}
                    <span className="text-fg-subtle"> · {dayjs.unix(f.created_at).fromNow()}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
          {!isNetwork && (canStop || !markedSafe) && (
            <div className="mt-4 pt-4 border-t border-line">
              <div className="text-[11px] text-fg-subtle mb-2">Your decision</div>
              <div className="flex flex-wrap gap-2">
                {canStop && (
                  <button disabled={busy} onClick={() => setStopModalOpen(true)} className="btn btn-secondary btn-sm text-danger">
                    <OctagonX size={14} /> Stop this program now
                  </button>
                )}
                {!markedSafe && publisherTrustable && (
                  <button disabled={busy} onClick={() => setTrustScope('publisher')} className="btn btn-secondary btn-sm">
                    <BadgeCheck size={14} /> Trust programs from {signedBy}
                  </button>
                )}
                {!markedSafe && (
                  <button disabled={busy} onClick={() => setTrustScope(view.trust ? 'file' : 'auto')} className="btn btn-ghost btn-sm">
                    <ShieldCheck size={14} /> {publisherTrustable ? 'Trust only this file' : 'This is safe, trust this program'}
                  </button>
                )}
              </div>
            </div>
          )}
        </StepCard>

        <StepCard n={4} title="What should you do?">
          {advice.length === 0 ? (
            <p className="text-sm text-fg-muted">Nothing. SentinelAI has handled it.</p>
          ) : (
            <ul className="space-y-2.5">
              {advice.map((item, idx) => (
                <li key={idx} className="flex items-start gap-3 text-sm text-fg">
                  <Lightbulb size={15} className="text-sun shrink-0 mt-0.5" />
                  {item}
                </li>
              ))}
            </ul>
          )}
        </StepCard>
      </div>

      <TechDetails data={view.raw} defaultOpen={expert} />

      <ConfirmModal
        isOpen={unblockModalOpen}
        title="Unblock this address?"
        message={`It was blocked for: ${threatInfo.friendlyName.toLowerCase()}. Once unblocked, it will be able to reach your computer again.`}
        cancelLabel="Keep blocked"
        confirmLabel="Unblock anyway"
        variant="danger"
        onConfirm={handleUnblock}
        onClose={() => setUnblockModalOpen(false)}
      />

      <ConfirmModal
        isOpen={stopModalOpen}
        title={`Stop ${view.processName || 'this program'} now?`}
        message={`This really closes the program (PID ${view.pid}), even though SentinelAI is in test mode. Anything unsaved in it will be lost. SentinelAI first checks that the PID still belongs to the same program, so nothing else gets closed by mistake.`}
        cancelLabel="Leave it running"
        confirmLabel="Stop it"
        variant="danger"
        onConfirm={handleStop}
        onClose={() => setStopModalOpen(false)}
      />

      <ConfirmModal
        isOpen={trustScope !== null}
        title={trustScope === 'publisher' ? `Trust every program signed by ${signedBy}?` : `Trust ${view.processName || 'this program'}?`}
        message={
          trustScope === 'publisher'
            ? `Any program carrying a valid ${signedBy} digital signature will stop raising alerts, including after updates. Only do this for software you installed on purpose.`
            : trustScope === 'auto'
            ? `If the program has a valid digital signature from a software company, SentinelAI will trust that company's programs (this survives updates). Otherwise it trusts only this exact file. Windows' own script tools can never be trusted this way.`
            : `Only this exact file${view.exePath ? ` (${view.exePath})` : ''} will stop raising alerts. If the file changes, for example after an update or if malware replaces it, SentinelAI will warn you again.`
        }
        cancelLabel="Cancel"
        confirmLabel="Yes, it's safe"
        onConfirm={() => trustScope && handleTrust(trustScope)}
        onClose={() => setTrustScope(null)}
      />
    </div>
  );
}
