import React from 'react';
import { InfoTooltip } from './InfoTooltip';

type Tone = 'accent' | 'sun' | 'mint' | 'rose' | 'safe' | 'info' | 'warn' | 'high' | 'danger' | 'neutral';

const TONE_TILE: Record<Tone, string> = {
  accent: 'bg-accent/15 text-accent-soft ring-accent/25',
  sun: 'bg-sun/15 text-sun ring-sun/25',
  mint: 'bg-mint/12 text-mint ring-mint/25',
  rose: 'bg-rose/12 text-rose ring-rose/25',
  safe: 'bg-safe/12 text-safe ring-safe/25',
  info: 'bg-info/12 text-info ring-info/25',
  warn: 'bg-warn/12 text-warn ring-warn/25',
  high: 'bg-high/12 text-high ring-high/25',
  danger: 'bg-danger/12 text-danger ring-danger/25',
  neutral: 'bg-white/6 text-fg-muted ring-white/10',
};

export function IconTile({
  tone = 'accent',
  size = 'md',
  children,
  className = '',
}: {
  tone?: Tone;
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
  className?: string;
}) {
  const dims = size === 'sm' ? 'w-8 h-8 rounded-lg' : size === 'lg' ? 'w-14 h-14 rounded-2xl' : 'w-10 h-10 rounded-xl';
  return (
    <div className={`${dims} shrink-0 inline-flex items-center justify-center ring-1 ring-inset ${TONE_TILE[tone]} ${className}`}>
      {children}
    </div>
  );
}

export function Panel({
  title,
  subtitle,
  info,
  actions,
  children,
  className = '',
  bodyClassName = '',
  padded = true,
}: {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  info?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  padded?: boolean;
}) {
  return (
    <section className={`glass animate-fade-up ${className}`}>
      {(title || actions) && (
        <header className={`flex items-start justify-between gap-4 ${padded ? 'px-5 pt-5' : 'px-5 pt-5 pb-4'}`}>
          <div className="min-w-0">
            {title && (
              <h2 className="text-[15px] font-semibold text-fg flex items-center gap-2">
                {title}
                {info && <InfoTooltip text={info} />}
              </h2>
            )}
            {subtitle && <p className="text-[13px] text-fg-muted mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={`${padded ? 'p-5' : ''} ${title && padded ? 'pt-4' : ''} ${bodyClassName}`}>{children}</div>
    </section>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`focus-ring relative w-11 h-6 shrink-0 rounded-[7px] border transition-colors duration-200 disabled:opacity-40 ${
        checked ? 'bg-accent border-accent' : 'bg-white/8 border-line-strong'
      }`}
    >
      <span
        className={`absolute top-[3px] left-[3px] w-4 h-4 rounded-[4px] shadow transition-transform duration-200 ${
          checked ? 'translate-x-5 bg-[#120d24]' : 'translate-x-0 bg-fg-muted'
        }`}
      />
    </button>
  );
}

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: React.ReactNode }[];
  ariaLabel: string;
}) {
  return (
    <div className="segmented" role="tablist" aria-label={ariaLabel}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={value === o.value}
          data-active={value === o.value}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function StatusDot({ className = '', pulse = false }: { className?: string; pulse?: boolean }) {
  return <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${pulse ? 'animate-pulse-live' : ''} ${className}`} />;
}
