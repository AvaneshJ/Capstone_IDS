import React from 'react';
import { InfoTooltip } from './InfoTooltip';
import { IconTile } from './ui';

export interface KpiCardProps {
  icon: React.ReactNode;
  value: string | number;
  title: string;
  helperText: string;
  tone?: 'accent' | 'sun' | 'mint' | 'rose';
  footnote?: React.ReactNode;
}

const GLOW: Record<NonNullable<KpiCardProps['tone']>, string> = {
  accent: 'from-accent/25',
  sun: 'from-sun/20',
  mint: 'from-mint/20',
  rose: 'from-rose/20',
};

export function KpiCard({ icon, value, title, helperText, tone = 'accent', footnote }: KpiCardProps) {
  return (
    <div className="glass glass-hover p-5 overflow-hidden animate-fade-up">
      <div className={`pointer-events-none absolute -top-16 -right-16 w-40 h-40 rounded-full bg-gradient-to-br ${GLOW[tone]} to-transparent blur-2xl`} />
      <div className="relative flex items-start justify-between">
        <IconTile tone={tone}>{icon}</IconTile>
        <InfoTooltip text={helperText} />
      </div>
      <div className="relative mt-5">
        <div className="text-[13px] font-medium text-fg-muted">{title}</div>
        <div className="mt-1 text-[28px] leading-none font-semibold tracking-tight text-fg tabular-nums">{value}</div>
        {footnote && <div className="mt-2.5 text-xs text-fg-subtle">{footnote}</div>}
      </div>
    </div>
  );
}
