import React from 'react';
import { IconTile } from './ui';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
  tone?: 'safe' | 'accent' | 'neutral';
}

export function EmptyState({ icon, title, description, action, tone = 'safe' }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center text-center px-6 py-12 rounded-xl border border-dashed border-line-strong bg-white/[0.02]">
      {icon && (
        <IconTile tone={tone} size="lg">
          {icon}
        </IconTile>
      )}
      <h3 className="mt-4 text-base font-semibold text-fg">{title}</h3>
      {description && <p className="mt-1 text-sm text-fg-muted max-w-md">{description}</p>}
      {action && (
        <button onClick={action.onClick} className="btn btn-primary mt-5">
          {action.label}
        </button>
      )}
    </div>
  );
}
