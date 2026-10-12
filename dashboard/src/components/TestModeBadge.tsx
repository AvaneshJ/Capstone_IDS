import { FlaskConical } from 'lucide-react';

export function TestModeBadge() {
  return (
    <span
      className="tag tag-accent h-7 px-2.5"
      title="Safe test mode: SentinelAI shows what it would block or stop, without changing anything on this computer."
    >
      <FlaskConical size={13} />
      Test mode
    </span>
  );
}
