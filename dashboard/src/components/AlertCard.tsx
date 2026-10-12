import { Link } from 'react-router-dom';
import { Globe, Monitor, ChevronRight, CheckCircle2, FlaskConical, XCircle, Info } from 'lucide-react';
import type { MergedAlert } from '../hooks/useMergedActivity';
import { formatTime, formatExactTime } from '../lib/time';
import { translateSeverity } from '../lib/translate';
import { IconTile } from './ui';

export interface AlertCardProps {
  alert: MergedAlert;
  compact?: boolean;
}

const ACTION_TAG: Record<MergedAlert['actionState'], { cls: string; icon: typeof CheckCircle2 }> = {
  done: { cls: 'tag-safe', icon: CheckCircle2 },
  test: { cls: 'tag-accent', icon: FlaskConical },
  failed: { cls: 'tag-danger', icon: XCircle },
  none: { cls: 'tag-neutral', icon: Info },
};

export function AlertCard({ alert, compact = false }: AlertCardProps) {
  const sev = translateSeverity(alert.severityRaw);
  const action = ACTION_TAG[alert.actionState] ?? ACTION_TAG.none;
  const ActionIcon = action.icon;
  const isNetwork = alert.source === 'network';

  return (
    <Link
      to={`/activity/${alert.source}/${alert.id}`}
      className={`group relative flex items-center gap-4 glass-inset glass-hover pl-5 pr-4 ${compact ? 'py-3' : 'py-4'} overflow-hidden ${alert.isNew ? 'animate-slide-in' : ''}`}
    >
      <span className="absolute left-0 top-3 bottom-3 w-[3px] rounded-r" style={{ background: sev.hex }} />

      <IconTile tone={isNetwork ? 'accent' : 'mint'} size={compact ? 'sm' : 'md'}>
        {isNetwork ? <Globe size={compact ? 16 : 18} /> : <Monitor size={compact ? 16 : 18} />}
      </IconTile>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 min-w-0">
          <h3 className="text-sm font-semibold text-fg truncate">{alert.title}</h3>
          {alert.isNew && <span className="tag tag-accent">New</span>}
        </div>
        {!compact && <p className="text-[13px] text-fg-muted mt-0.5 line-clamp-1">{alert.story}</p>}
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <span className={`tag ${sev.tagClass}`}>
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: sev.hex }} />
            {sev.short}
          </span>
          <span className="tag tag-neutral">{isNetwork ? 'From the internet' : 'On this computer'}</span>
          <span className={`tag ${action.cls}`}>
            <ActionIcon size={12} />
            <span className="truncate max-w-[300px]">
              {alert.actionState === 'test' ? `Test mode: ${alert.actionLabel.toLowerCase()}` : alert.actionLabel}
            </span>
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0 self-start pt-0.5">
        <span className="text-xs text-fg-subtle tabular-nums" title={formatExactTime(alert.time)}>
          {formatTime(alert.time)}
        </span>
        <ChevronRight size={16} className="text-fg-subtle group-hover:text-fg group-hover:translate-x-0.5 transition-all" />
      </div>
    </Link>
  );
}
