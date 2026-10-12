import { useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ConnectionStatus } from '../components/ConnectionStatus';
import { NotificationBell } from '../components/NotificationBell';
import { TestModeBadge } from '../components/TestModeBadge';
import { InfoTooltip } from '../components/InfoTooltip';
import { Segmented } from '../components/ui';
import { getSystemStatus, type SelfProtectionStatus } from '../api/endpoints';
import type { ConnectionState, LiveNotification } from '../hooks/useLiveStream';
import { pageMeta } from './nav';

interface TopBarProps {
  expertMode: boolean;
  setExpertMode: (v: boolean) => void;
  liveState: ConnectionState;
  unreadCount: number;
  notifications: LiveNotification[];
  onMarkAllRead: () => void;
}

function isTampered(sp: SelfProtectionStatus | undefined): boolean {
  if (!sp) return false;
  return (
    sp.recent_tamper_events.length > 0 ||
    sp.watchdog.silenced.length > 0 ||
    (sp.integrity?.state !== undefined && !['ok', 'no_manifest'].includes(sp.integrity.state)) ||
    sp.evidence_chain?.ok === false
  );
}

export function TopBar({ expertMode, setExpertMode, liveState, unreadCount, notifications, onMarkAllRead }: TopBarProps) {
  const { pathname } = useLocation();
  const meta = pageMeta(pathname);
  const { data: status } = useQuery({ queryKey: ['system-status'], queryFn: getSystemStatus, refetchInterval: 15000 });

  return (
    <header className="relative z-30 flex items-center justify-between gap-6 px-8 pt-5 pb-4">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold tracking-tight text-fg truncate">{meta.title}</h1>
        <p className="text-[13px] text-fg-muted truncate mt-0.5">{meta.description}</p>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        {status?.test_mode && <TestModeBadge />}
        <ConnectionStatus state={liveState} tampered={isTampered(status?.self_protection)} />
        <div className="h-6 w-px bg-line mx-1" />
        <div className="flex items-center gap-2">
          <Segmented
            ariaLabel="View"
            value={expertMode ? 'expert' : 'simple'}
            onChange={(v) => setExpertMode(v === 'expert')}
            options={[
              { value: 'simple', label: 'Simple' },
              { value: 'expert', label: 'Expert' },
            ]}
          />
          <InfoTooltip text="Simple shows plain-English explanations. Expert adds technical details like IP addresses, model confidence and raw data." />
        </div>
        <NotificationBell unreadCount={unreadCount} notifications={notifications} onMarkAllRead={onMarkAllRead} />
      </div>
    </header>
  );
}
