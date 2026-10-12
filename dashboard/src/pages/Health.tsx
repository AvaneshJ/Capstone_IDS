import { useContext, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HeartPulse, Cpu, MemoryStick, Timer, AlertTriangle, ShieldCheck } from 'lucide-react';
import { ExpertContext } from '../App';
import { getSystemStatus, runSelfProtectionChecks, type IntegrityReport, type SelfProtectionStatus } from '../api/endpoints';
import { translateAgentName, translateAgentStatus } from '../lib/translate';
import { formatUptime } from '../lib/time';
import { Skeleton, ErrorState, IconTile, Panel, StatusDot } from '../components/index';
import { LiveSensors, useLiveStatus } from '../components/LiveSensors';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

dayjs.extend(relativeTime);
const nf = new Intl.NumberFormat();

function UsageCard({ icon, label, value, hint }: { icon: ReactNode; label: string; value: number; hint: string }) {
  const pct = Math.min(Math.max(value, 0), 100);
  const color = pct > 85 ? '#f87171' : pct > 65 ? '#fbbf24' : '#5eead4';
  const r = 34;
  const c = 2 * Math.PI * r;
  return (
    <div className="glass p-5 flex items-center gap-5 animate-fade-up">
      <svg width="84" height="84" viewBox="0 0 84 84" className="shrink-0 -rotate-90">
        <circle cx="42" cy="42" r={r} fill="none" stroke="rgb(255 255 255 / 0.08)" strokeWidth="8" />
        <circle
          cx="42"
          cy="42"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c - (pct / 100) * c}
          style={{ transition: 'stroke-dashoffset 800ms ease', filter: `drop-shadow(0 0 6px ${color}66)` }}
        />
      </svg>
      <div>
        <div className="flex items-center gap-2 text-[13px] text-fg-muted">
          {icon} {label}
        </div>
        <div className="text-2xl font-semibold text-fg tabular-nums mt-1">{pct.toFixed(0)}%</div>
        <div className="text-xs text-fg-subtle mt-0.5">{hint}</div>
      </div>
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="glass-inset p-3">
      <div className="text-[11px] text-fg-subtle">{label}</div>
      <div className="text-lg font-semibold text-fg tabular-nums mt-0.5">{value}</div>
      <div className="text-[11px] text-fg-muted mt-0.5 leading-snug">{hint}</div>
    </div>
  );
}

function LiveMonitoringPanel() {
  const { expert } = useContext(ExpertContext);
  const { data } = useLiveStatus();
  const net = data?.network;
  const host = data?.host;
  return (
    <Panel
      title="Live monitoring"
      subtitle="What SentinelAI is watching right now on this computer."
      info="Network monitoring reads connection details (never their contents) on this PC. Computer monitoring watches programs starting and stopping."
    >
      <LiveSensors />
      {net && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-3">
          <Stat label="Connections checked" value={nf.format(net.flows_checked)} hint="Since SentinelAI started" />
          <Stat label="Threats spotted" value={nf.format(net.threats_found)} hint="Connections the AI flagged as attacks" />
          <Stat label="Alerts created" value={nf.format(net.incidents_created + (host?.alerts ?? 0))} hint="Repeats of the same attack are grouped" />
          <Stat
            label="Last connection checked"
            value={net.last_flow_at ? dayjs.unix(net.last_flow_at).fromNow() : 'Not yet'}
            hint={net.state === 'running' ? 'Updates every few seconds' : 'Network monitoring is off'}
          />
        </div>
      )}
      {expert && net && host && (
        <p className="text-[11px] font-mono text-fg-subtle mt-3 leading-relaxed selectable">
          adapters: {net.interfaces.join(', ') || 'none'} | packets {nf.format(net.packets_seen)} | repeats grouped {nf.format(net.repeats_grouped)} |
          outbound flagged (ignored) {nf.format(net.outbound_flagged)} | noise {nf.format(net.ignored_noise)} | dropped {nf.format(net.dropped)} | queue {net.queue} |
          host alerts {host.alerts}, grouped {host.repeats_grouped}, system binaries skipped {host.trusted_location_skipped} | response: {data?.response_mode}
        </p>
      )}
    </Panel>
  );
}

const SENSOR_NAMES: Record<string, string> = {
  nids_capture: 'Internet connection monitor',
  hids_process: 'Program monitor',
  hids_file: 'Saved-password monitor',
  hids_tamper_log: 'Windows security log monitor',
  hids_live: 'Standalone computer monitor',
  supervisor: 'Restart guardian',
};

const INTEGRITY_VIEW: Record<IntegrityReport['state'], { tag: string; tagClass: string; detail: string }> = {
  ok: { tag: 'Verified', tagClass: 'tag-safe', detail: 'Detection models, rules and program files match the trusted copy.' },
  tampered: { tag: 'Changed', tagClass: 'tag-danger', detail: 'Some SentinelAI files changed since they were trusted.' },
  bad_signature: { tag: 'Forged', tagClass: 'tag-danger', detail: 'The trusted file list itself was edited. Nothing can be trusted until it is regenerated.' },
  no_manifest: { tag: 'Not set up', tagClass: 'tag-warn', detail: 'File checking is off. Run: python -m config.integrity generate' },
};

function ProtectionRow({ title, tag, tagClass, detail, technical }: { title: string; tag: string; tagClass: string; detail: string; technical?: string }) {
  const { expert } = useContext(ExpertContext);
  return (
    <div className="glass-inset p-3 flex items-start gap-3">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{title}</div>
        <div className="text-xs text-fg-muted leading-relaxed">{detail}</div>
        {expert && technical && <div className="text-[11px] text-fg-subtle font-mono mt-1 break-all selectable">{technical}</div>}
      </div>
      <span className={`tag ${tagClass}`}>{tag}</span>
    </div>
  );
}

function SelfProtectionPanel({ sp }: { sp: SelfProtectionStatus }) {
  const queryClient = useQueryClient();
  const verify = useMutation({
    mutationFn: runSelfProtectionChecks,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['system-status'] }),
  });
  const integrity = sp.integrity ? INTEGRITY_VIEW[sp.integrity.state] : { tag: 'Checking', tagClass: 'tag-neutral', detail: 'First check is running.' };
  const changed = sp.integrity ? [...sp.integrity.modified, ...sp.integrity.missing, ...sp.integrity.added] : [];
  const chain = sp.evidence_chain;
  const sensors = Object.values(sp.watchdog.sensors);

  return (
    <Panel
      title={<span className="flex items-center gap-2"><ShieldCheck size={15} /> Self-protection</span>}
      subtitle="SentinelAI checks that nothing has switched it off, changed its files or erased its records."
      info="Files are compared with a signed fingerprint list. The alert history is chained so edits or deletions show up. Monitors send heartbeats; if one goes quiet you get a critical alert."
      actions={
        <button className="btn btn-secondary btn-sm" disabled={verify.isPending} onClick={() => verify.mutate()}>
          {verify.isPending ? 'Checking' : 'Check now'}
        </button>
      }
    >
      <div className="space-y-3">
        <ProtectionRow
          title="Program files and detection models"
          {...integrity}
          technical={changed.length ? changed.slice(0, 12).join(', ') : sp.integrity ? `${sp.integrity.files_checked} files checked` : undefined}
        />
        <ProtectionRow
          title="Alert history"
          tag={!chain ? 'Checking' : chain.ok ? 'Intact' : 'Altered'}
          tagClass={!chain ? 'tag-neutral' : chain.ok ? 'tag-safe' : 'tag-danger'}
          detail={!chain ? 'First check is running.' : chain.ok ? 'No alert or log entry was edited or deleted.' : `${chain.problem_count} sign${chain.problem_count === 1 ? '' : 's'} that saved alerts were edited or deleted.`}
          technical={chain ? (chain.ok ? `${chain.entries} chained records` : chain.problems.slice(0, 5).join(' | ')) : undefined}
        />
        <ProtectionRow
          title="Protected connection"
          tag={sp.auth_required ? 'Locked' : 'Open'}
          tagClass={sp.auth_required ? 'tag-safe' : 'tag-warn'}
          detail={sp.auth_required ? 'Only SentinelAI\'s own app can give the engine commands.' : 'Any program on this PC can send commands to the engine (SENTINEL_AUTH=0).'}
        />
        {sensors.map((s) => (
          <ProtectionRow
            key={s.name}
            title={SENSOR_NAMES[s.name] ?? s.name}
            tag={s.state === 'alive' ? 'Reporting' : 'Silent'}
            tagClass={s.state === 'alive' ? 'tag-safe' : 'tag-danger'}
            detail={s.state === 'alive' ? `Last check-in ${dayjs.unix(s.last_seen).fromNow()}` : `Stopped reporting: ${s.reason}`}
            technical={`${s.name} | beats ${s.beats} | timeout ${s.timeout ?? 'probe only'}`}
          />
        ))}
        {sp.recent_tamper_events.length > 0 && (
          <div className="glass-inset p-3">
            <div className="text-sm font-medium text-danger flex items-center gap-2"><AlertTriangle size={14} /> Recent attempts to tamper with SentinelAI</div>
            <ul className="mt-2 space-y-1.5">
              {sp.recent_tamper_events.slice(0, 6).map((e) => (
                <li key={e.incident_id} className="text-xs text-fg-muted">
                  <span className="text-fg">{e.title}</span> · {dayjs.unix(e.timestamp).fromNow()}
                  <span className="block text-[11px] text-fg-subtle font-mono break-all selectable">{e.mitre} {e.details}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}

export function Health() {
  const { expert } = useContext(ExpertContext);
  const { data, isLoading, isError, refetch } = useQuery({ queryKey: ['system-status'], queryFn: getSystemStatus, refetchInterval: 15000 });

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-3 gap-5">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
        <Skeleton className="h-72" />
      </div>
    );
  }

  if (isError || !data) {
    return <ErrorState message="We can't reach the protection engine." hint="If you just opened SentinelAI, give it a few seconds to start." onRetry={() => refetch()} />;
  }

  const agents = Object.entries(data.agent_statuses || {});
  const problems = agents.filter(([, s]) => !translateAgentStatus(s).ok).length;
  const allGood = problems === 0;

  return (
    <div className="space-y-5">
      <section className="glass p-6 flex items-center gap-5 animate-fade-up">
        <IconTile tone={allGood ? 'safe' : 'danger'} size="lg">
          {allGood ? <HeartPulse size={26} /> : <AlertTriangle size={26} />}
        </IconTile>
        <div>
          <h2 className="text-lg font-semibold text-fg">{allGood ? 'Everything is working' : `${problems} part${problems > 1 ? 's' : ''} need${problems > 1 ? '' : 's'} attention`}</h2>
          <p className="text-sm text-fg-muted mt-0.5">
            {allGood ? `All ${agents.length} protection parts are running normally.` : 'Try restarting SentinelAI. If this keeps happening, contact IT support.'}
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <UsageCard icon={<Cpu size={14} />} label="Processor" value={data.cpu_percent} hint="How busy your computer's processor is" />
        <UsageCard icon={<MemoryStick size={14} />} label="Memory" value={data.memory_percent} hint="How much of your memory is in use" />
        <div className="glass p-5 flex items-center gap-5 animate-fade-up">
          <IconTile tone="accent" size="lg">
            <Timer size={24} />
          </IconTile>
          <div>
            <div className="text-[13px] text-fg-muted">Protecting you for</div>
            <div className="text-2xl font-semibold text-fg mt-1">{formatUptime(data.uptime_seconds)}</div>
            <div className="text-xs text-fg-subtle mt-0.5">Since SentinelAI last started</div>
          </div>
        </div>
      </div>

      <LiveMonitoringPanel />

      {data.self_protection && <SelfProtectionPanel sp={data.self_protection} />}

      <Panel title="Protection parts" subtitle="SentinelAI is a team of small helpers. Each one has a single job." info="Ready means the part is waiting for work. Working means it is handling something right now.">
        <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-3">
          {agents.map(([key, raw]) => {
            const { friendlyName, description } = translateAgentName(key);
            const st = translateAgentStatus(raw);
            return (
              <div key={key} className="glass-inset p-4 flex items-start gap-3">
                <StatusDot className={`${st.dotColor} mt-1.5`} pulse={raw?.toUpperCase() === 'PROCESSING'} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-fg truncate">{friendlyName}</span>
                    <span className={`tag ${st.tagClass}`}>{st.label}</span>
                  </div>
                  <p className="text-xs text-fg-muted mt-1">{description}</p>
                  {expert && <p className="text-[11px] font-mono text-fg-subtle mt-1.5">{key}</p>}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}
