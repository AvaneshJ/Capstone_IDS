import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, ShieldOff } from 'lucide-react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import type { OverallStatus } from '../hooks/useOverallStatus';

dayjs.extend(relativeTime);

export interface StatusBannerProps {
  status: OverallStatus;
  message: string;
  threatCount?: number;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
}

const CONFIG: Record<OverallStatus, { title: string; icon: typeof ShieldCheck; color: string; glow: string; tag: string; tagText: string }> = {
  protected: { title: "You're protected", icon: ShieldCheck, color: '#34d399', glow: 'rgb(52 211 153 / 0.35)', tag: 'tag-safe', tagText: 'All good' },
  handled: { title: "You're protected", icon: ShieldCheck, color: '#a78bfa', glow: 'rgb(167 139 250 / 0.4)', tag: 'tag-accent', tagText: 'Threats handled' },
  action_needed: { title: 'Something needs your attention', icon: ShieldAlert, color: '#fb923c', glow: 'rgb(251 146 60 / 0.4)', tag: 'tag-high', tagText: 'Action needed' },
  offline: { title: 'Protection engine is not running', icon: ShieldOff, color: '#a3a2b6', glow: 'rgb(163 162 182 / 0.25)', tag: 'tag-neutral', tagText: 'Offline' },
};

export function StatusBanner({ status, message, actions, footer }: StatusBannerProps) {
  const [lastChecked, setLastChecked] = useState(dayjs());

  useEffect(() => {
    setLastChecked(dayjs());
    const timer = setInterval(() => setLastChecked(dayjs()), 30000);
    return () => clearInterval(timer);
  }, [status, message]);

  const c = CONFIG[status];
  const Icon = c.icon;

  return (
    <section className="glass overflow-hidden h-full flex flex-col animate-fade-up">
      <div
        className="pointer-events-none absolute -left-24 -top-24 w-80 h-80 rounded-full blur-3xl opacity-60"
        style={{ background: `radial-gradient(circle, ${c.glow}, transparent 70%)` }}
      />
      <div className="relative flex items-center gap-6 p-6 flex-1">
        <div
          className="relative w-[88px] h-[88px] shrink-0 rounded-[22px] flex items-center justify-center animate-shield-glow"
          style={{
            ['--glow' as string]: c.glow,
            background: `linear-gradient(145deg, ${c.color}33, ${c.color}10)`,
            border: `1px solid ${c.color}55`,
          }}
        >
          <Icon size={44} strokeWidth={1.8} style={{ color: c.color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className={`tag ${c.tag}`}>{c.tagText}</span>
            <span className="text-xs text-fg-subtle">Checked {lastChecked.fromNow()}</span>
          </div>
          <h2 className="text-2xl font-semibold tracking-tight text-fg">{c.title}</h2>
          <p className="mt-1 text-[15px] text-fg-muted">{message}</p>
          {actions && <div className="mt-4 flex flex-wrap gap-2">{actions}</div>}
        </div>
      </div>
      {footer && <div className="relative border-t border-white/6 bg-black/10 px-6 py-4">{footer}</div>}
    </section>
  );
}
