import { useContext, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Globe, Monitor, ExternalLink, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import { getLiveStatus, type LiveStatus } from '../api/endpoints';
import { ExpertContext } from '../App';
import { desktop, openExternal } from '../lib/desktop';
import { IconTile } from './ui';

function AdminButton() {
  const [busy, setBusy] = useState(false);
  if (!desktop) return null;
  const relaunch = async () => {
    setBusy(true);
    const { ok } = await desktop!.relaunchAsAdmin();
    if (!ok) {
      setBusy(false);
      toast.error("Administrator access wasn't granted, so SentinelAI keeps running with limited protection.");
    }
  };
  return (
    <button onClick={relaunch} disabled={busy} className="btn btn-secondary btn-sm mt-2">
      <ShieldCheck size={13} /> {busy ? 'Waiting for permission' : 'Restart as administrator'}
    </button>
  );
}

const nf = new Intl.NumberFormat();
const NPCAP_URL = 'https://npcap.com/#download';

interface SensorView {
  tag: string;
  tagClass: string;
  detail: string;
  action?: ReactNode;
  technical?: string;
}

export function useLiveStatus() {
  return useQuery({ queryKey: ['live-status'], queryFn: getLiveStatus, refetchInterval: 5000, retry: false });
}

export function describeNetwork(live: LiveStatus | undefined): SensorView {
  const net = live?.network;
  if (!net) return { tag: 'Checking', tagClass: 'tag-neutral', detail: 'Waiting for the protection engine' };
  switch (net.state) {
    case 'running':
      return {
        tag: 'On',
        tagClass: 'tag-safe',
        detail: net.flows_checked > 0
          ? `Live: ${nf.format(net.flows_checked)} connections checked`
          : 'Live: watching for attacks coming from outside',
        technical: `${nf.format(net.packets_seen)} packets on ${net.interfaces.length} adapter(s) via ${net.backend || 'capture driver'}`,
      };
    case 'unavailable':
      if (net.reason === 'needs_admin') {
        return {
          tag: 'Needs permission',
          tagClass: 'tag-warn',
          detail: 'SentinelAI needs administrator permission to watch your internet connection.',
          action: <AdminButton />,
          technical: 'needs_admin (WinDivert capture requires an elevated engine)',
        };
      }
      if (net.reason === 'npcap_missing') {
        return {
          tag: 'Needs setup',
          tagClass: 'tag-warn',
          detail: 'Install the free Npcap driver so SentinelAI can watch your connection, then restart SentinelAI.',
          action: (
            <button onClick={() => openExternal(NPCAP_URL)} className="btn btn-secondary btn-sm mt-2">
              Get Npcap <ExternalLink size={13} />
            </button>
          ),
          technical: 'npcap_missing',
        };
      }
      return { tag: 'Off', tagClass: 'tag-danger', detail: "Network monitoring couldn't start.", technical: net.reason };
    case 'error':
      return { tag: 'Off', tagClass: 'tag-danger', detail: 'Network monitoring stopped. Restart SentinelAI to try again.', technical: net.reason };
    case 'disabled':
      return { tag: 'Off', tagClass: 'tag-neutral', detail: 'Turned off in the engine settings' };
    default:
      return { tag: 'Off', tagClass: 'tag-neutral', detail: 'Not running' };
  }
}

export function describeComputer(live: LiveStatus | undefined): SensorView {
  const host = live?.host;
  if (!host) return { tag: 'Checking', tagClass: 'tag-neutral', detail: 'Waiting for the protection engine' };
  const processOn = host.process_sensor === 'running';
  const filesOn = host.file_sensor === 'running';
  if (processOn && filesOn) {
    return { tag: 'On', tagClass: 'tag-safe', detail: 'Live: watching programs and your saved passwords' };
  }
  if (processOn && host.file_sensor === 'needs_admin') {
    return {
      tag: 'Limited',
      tagClass: 'tag-warn',
      detail: 'Watching programs. Run SentinelAI as administrator to also see who opens your saved passwords.',
      action: <AdminButton />,
      technical: 'file sensor needs Administrator (Security log auditing)',
    };
  }
  if (processOn) {
    return {
      tag: 'On',
      tagClass: 'tag-safe',
      detail: 'Live: watching programs on this computer',
      technical: `file sensor: ${host.file_sensor}`,
    };
  }
  if (host.process_sensor === 'disabled') return { tag: 'Off', tagClass: 'tag-neutral', detail: 'Turned off in the engine settings' };
  return {
    tag: 'Off',
    tagClass: 'tag-danger',
    detail: "Computer monitoring couldn't start. Restart SentinelAI to try again.",
    technical: `process: ${host.process_sensor}, files: ${host.file_sensor}`,
  };
}

function SensorRow({ icon, tone, title, view }: { icon: ReactNode; tone: 'accent' | 'mint'; title: string; view: SensorView }) {
  const { expert } = useContext(ExpertContext);
  return (
    <div className="glass-inset p-3 flex items-start gap-3">
      <IconTile tone={tone} size="sm">{icon}</IconTile>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{title}</div>
        <div className="text-xs text-fg-muted leading-relaxed">{view.detail}</div>
        {expert && view.technical && <div className="text-[11px] text-fg-subtle font-mono mt-1">{view.technical}</div>}
        {view.action}
      </div>
      <span className={`tag ${view.tagClass}`}>{view.tag}</span>
    </div>
  );
}

export function LiveSensors() {
  const { data } = useLiveStatus();
  return (
    <div className="space-y-3">
      <SensorRow icon={<Globe size={16} />} tone="accent" title="Your internet connection" view={describeNetwork(data)} />
      <SensorRow icon={<Monitor size={16} />} tone="mint" title="This computer" view={describeComputer(data)} />
    </div>
  );
}
