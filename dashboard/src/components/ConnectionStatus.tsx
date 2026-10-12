import type { ConnectionState } from '../hooks/useLiveStream';
import { StatusDot } from './ui';

export interface ConnectionStatusProps {
  state: ConnectionState;
  /** Something tried to stop, blind or modify SentinelAI (self-protection alert). */
  tampered?: boolean;
}

const CONFIG: Record<ConnectionState, { label: string; hint: string; tag: string; dot: string; pulse: boolean }> = {
  connected: { label: 'Live', hint: 'Receiving alerts in real time', tag: 'tag-safe', dot: 'bg-safe', pulse: true },
  reconnecting: { label: 'Reconnecting', hint: 'Trying to reach the protection engine', tag: 'tag-warn', dot: 'bg-warn', pulse: true },
  offline: { label: 'Offline', hint: "Can't reach the protection engine", tag: 'tag-neutral', dot: 'bg-fg-subtle', pulse: false },
};

export function ConnectionStatus({ state, tampered }: ConnectionStatusProps) {
  const c = CONFIG[state] ?? CONFIG.offline;
  return (
    <>
      {tampered && (
        <a href="#/health" className="tag tag-danger h-7 px-2.5" title="Something tried to stop or modify SentinelAI. Open System health for details.">
          <StatusDot className="bg-danger" pulse />
          Tamper alert
        </a>
      )}
      <span className={`tag ${c.tag} h-7 px-2.5`} title={c.hint}>
        <StatusDot className={c.dot} pulse={c.pulse} />
        {c.label}
      </span>
    </>
  );
}
