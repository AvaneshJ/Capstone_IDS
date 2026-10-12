import { useEffect, useState, type ReactNode } from 'react';
import { Activity, Clock, ShieldAlert, Timer } from 'lucide-react';
import { useLiveStatus } from './LiveSensors';

const nf = new Intl.NumberFormat();
const SLOTS = 24;

// Kept at module level so the chart survives switching pages.
const history: number[] = [];
let lastTotal: number | null = null;
let lastUpdate = 0;

function record(total: number, updatedAt: number) {
  if (updatedAt === lastUpdate) return;
  lastUpdate = updatedAt;
  if (lastTotal !== null) {
    history.push(Math.max(total - lastTotal, 0));
    if (history.length > SLOTS) history.shift();
  }
  lastTotal = total;
}

function duration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

function ago(unix: number | null | undefined): string | null {
  if (!unix) return null;
  const s = Date.now() / 1000 - unix;
  return s < 5 ? 'Just now' : `${duration(s)} ago`;
}

function Stat({ icon, label, value }: { icon: ReactNode; label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-fg-subtle whitespace-nowrap">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-sm font-semibold text-fg tabular-nums truncate">{value}</div>
    </div>
  );
}

export function LivePulse({ lastThreatAt }: { lastThreatAt?: number }) {
  const { data, dataUpdatedAt } = useLiveStatus();
  const [, tick] = useState(0);
  const net = data?.network;
  const running = net?.state === 'running';

  if (net) record(net.flows_checked, dataUpdatedAt);

  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 5000);
    return () => clearInterval(t);
  }, []);

  const bars = [...Array(Math.max(SLOTS - history.length, 0)).fill(null), ...history] as (number | null)[];
  const peak = Math.max(1, ...history);
  const recent = history.reduce((s, n) => s + n, 0);
  const lastThreat = net?.last_threat_at ?? lastThreatAt;

  return (
    <div className="grid grid-cols-12 gap-5 items-end">
      <div className="col-span-12 lg:col-span-5">
        <div className="flex items-center justify-between mb-2">
          <span className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-fg-subtle">
            <span className="relative flex w-2 h-2">
              {running && <span className="absolute inset-0 rounded-full bg-mint animate-ping opacity-60" />}
              <span className={`relative w-2 h-2 rounded-full ${running ? 'bg-mint' : 'bg-fg-subtle'}`} />
            </span>
            {running ? 'Live activity' : 'Live activity paused'}
          </span>
          <span className="text-[11px] text-fg-subtle tabular-nums">
            {running ? `${nf.format(recent)} in the last 2 min` : 'Network monitor is off'}
          </span>
        </div>
        <div className="flex items-end gap-[3px] h-10" aria-hidden>
          {bars.map((n, i) => (
            <div
              key={i}
              className="flex-1 rounded-[2px] transition-[height] duration-500"
              style={{
                height: n === null ? '8%' : `${Math.max((n / peak) * 100, 8)}%`,
                background: n === null ? 'rgb(255 255 255 / 0.06)' : 'linear-gradient(180deg, #c4b5fd, #a78bfa66)',
              }}
            />
          ))}
        </div>
      </div>

      <div className="col-span-12 lg:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Stat icon={<Activity size={12} />} label="Checked" value={running ? nf.format(net!.flows_checked) : '—'} />
        <Stat icon={<Clock size={12} />} label="Last check" value={ago(net?.last_flow_at) ?? '—'} />
        <Stat icon={<ShieldAlert size={12} />} label="Last threat" value={ago(lastThreat) ?? 'None yet'} />
        <Stat
          icon={<Timer size={12} />}
          label="Uptime"
          value={running && net?.started_at ? duration(Date.now() / 1000 - net.started_at) : '—'}
        />
      </div>
    </div>
  );
}
