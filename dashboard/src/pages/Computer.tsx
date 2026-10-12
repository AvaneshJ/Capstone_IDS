import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, Lock, Cookie, KeyRound, CreditCard, Wallet, AlertTriangle, Monitor, Ban, Eye } from 'lucide-react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';

import { Skeleton, ErrorState, AlertCard, EmptyState, IconTile, Panel, KpiCard } from '../components/index';
import { getHostIncidents } from '../api/endpoints';
import type { HostIncidentRow } from '../api/endpoints';
import { hostIncidentToAlert } from '../hooks/useMergedActivity';

dayjs.extend(relativeTime);

const PROTECTED_ITEMS = [
  { id: 'passwords', name: 'Saved browser passwords', hint: 'Chrome, Edge, Brave, Opera, Firefox', icon: Lock, match: ['login data', 'logins.json', 'key4.db'] },
  { id: 'cookies', name: 'Login sessions (cookies)', hint: 'What keeps you signed in to websites', icon: Cookie, match: ['cookies'] },
  { id: 'masterkey', name: 'Browser master key', hint: 'Unlocks your saved passwords', icon: KeyRound, match: ['local state'] },
  { id: 'cards', name: 'Autofill and saved cards', hint: 'Addresses and payment details', icon: CreditCard, match: ['web data'] },
  { id: 'wallet', name: 'Crypto wallet', hint: 'Bitcoin Core wallet file', icon: Wallet, match: ['wallet.dat'] },
];

function lastSuspiciousAccess(incidents: HostIncidentRow[], match: string[]) {
  const dayAgo = Date.now() / 1000 - 86400;
  return incidents.find((i) => {
    if (i.timestamp < dayAgo) return false;
    const hay = `${i.file_path ?? ''} ${i.file_type ?? ''}`.toLowerCase();
    return match.some((m) => hay.includes(m));
  });
}

export default function Computer() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['host-incidents', 100],
    queryFn: () => getHostIncidents(100),
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-36" />
        <div className="grid grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
      </div>
    );
  }
  if (error) return <ErrorState message="We couldn't load computer protection." onRetry={() => refetch()} />;

  const incidents = [...(data?.host_incidents ?? [])].sort((a, b) => b.timestamp - a.timestamp);
  const stopped = incidents.filter((i) => i.soar_action === 'TERMINATE_PROCESS').length;
  const watchedPrograms = new Set(incidents.map((i) => i.process_name)).size;

  return (
    <div className="space-y-5">
      <section className="glass p-6 flex items-center gap-6 animate-fade-up overflow-hidden">
        <div className="pointer-events-none absolute -right-20 -top-24 w-80 h-80 rounded-full bg-mint/10 blur-3xl" />
        <IconTile tone="mint" size="lg">
          <Monitor size={26} />
        </IconTile>
        <div className="relative max-w-3xl">
          <h2 className="text-lg font-semibold text-fg">How we protect this computer</h2>
          <p className="text-sm text-fg-muted mt-1 leading-relaxed">
            Password-stealing programs secretly copy the passwords and login sessions saved in your browser. SentinelAI watches these files and
            notices when an unknown program opens them. If it does, we stop the program and tell you what to do next.
          </p>
        </div>
      </section>

      <div className="grid grid-cols-3 gap-5">
        <KpiCard tone="mint" icon={<ShieldCheck size={18} />} title="Items guarded" value={PROTECTED_ITEMS.length} helperText="Types of sensitive files SentinelAI watches on this computer." />
        <KpiCard tone="rose" icon={<Ban size={18} />} title="Programs stopped" value={stopped} helperText="Harmful programs SentinelAI shut down (or would have, in test mode)." />
        <KpiCard tone="accent" icon={<Eye size={18} />} title="Suspicious programs seen" value={watchedPrograms} helperText="Different programs that triggered a computer alert." />
      </div>

      <Panel title="Protected items" subtitle="Files that password-stealers go after" info="Guarded means no unknown program has opened this in the last 24 hours.">
        <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-3">
          {PROTECTED_ITEMS.map((item) => {
            const hit = lastSuspiciousAccess(incidents, item.match);
            return (
              <div key={item.id} className="glass-inset p-4 flex items-start gap-3">
                <IconTile tone={hit ? 'high' : 'safe'} size="sm">
                  <item.icon size={16} />
                </IconTile>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium text-fg">{item.name}</div>
                  <div className="text-xs text-fg-subtle mt-0.5">{item.hint}</div>
                  {hit ? (
                    <div className="mt-2 text-xs text-high flex items-start gap-1.5">
                      <AlertTriangle size={13} className="shrink-0 mt-px" />
                      Opened by {hit.process_name || 'an unknown program'} {dayjs.unix(hit.timestamp).fromNow()}
                    </div>
                  ) : (
                    <div className="mt-2 text-xs text-safe flex items-center gap-1.5">
                      <ShieldCheck size={13} /> Guarded
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      <Panel title="Recent computer alerts" subtitle="Programs that tried to open your private files">
        {incidents.length === 0 ? (
          <EmptyState icon={<ShieldCheck size={24} />} title="No suspicious programs" description="Nothing has tried to open your saved passwords or login sessions." />
        ) : (
          <div className="space-y-2.5">
            {incidents.slice(0, 20).map((incident) => (
              <AlertCard key={incident.incident_id} alert={hostIncidentToAlert(incident)} />
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
