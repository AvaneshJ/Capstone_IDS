import { translateSeverity } from '../lib/translate';

export interface SeverityBadgeProps {
  severity: string;
  short?: boolean;
}

export function SeverityBadge({ severity, short = false }: SeverityBadgeProps) {
  const info = translateSeverity(severity);
  return (
    <span className={`tag ${info.tagClass}`}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: info.hex }} />
      {short ? info.short : info.label}
    </span>
  );
}
