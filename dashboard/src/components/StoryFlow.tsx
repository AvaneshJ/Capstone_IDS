import React from 'react';
import { ArrowRight, Cpu, FileLock2, Shield, Globe, HelpCircle, Activity } from 'lucide-react';
import { IconTile } from './ui';

export interface StoryFlowStep {
  icon: string;
  label: string;
  sublabel?: string;
}

export interface StoryFlowProps {
  steps: StoryFlowStep[];
}

const ICONS: Record<string, { icon: typeof Cpu; tone: 'accent' | 'warn' | 'safe' | 'mint' }> = {
  cpu: { icon: Cpu, tone: 'warn' },
  'file-lock': { icon: FileLock2, tone: 'accent' },
  shield: { icon: Shield, tone: 'safe' },
  globe: { icon: Globe, tone: 'mint' },
  activity: { icon: Activity, tone: 'warn' },
};

export function StoryFlow({ steps }: StoryFlowProps) {
  if (!steps || steps.length === 0) return null;

  return (
    <div className="flex items-stretch gap-2 glass-inset p-3">
      {steps.map((step, index) => {
        const cfg = ICONS[step.icon] ?? { icon: HelpCircle, tone: 'accent' as const };
        const Icon = cfg.icon;
        return (
          <React.Fragment key={index}>
            <div className="flex-1 min-w-0 flex flex-col items-center text-center gap-2 px-1 py-2">
              <IconTile tone={cfg.tone} size="sm">
                <Icon size={16} />
              </IconTile>
              <div className="text-xs font-medium text-fg leading-snug break-words">{step.label}</div>
              {step.sublabel && <div className="text-[11px] text-fg-subtle">{step.sublabel}</div>}
            </div>
            {index < steps.length - 1 && (
              <div className="flex items-center text-fg-subtle">
                <ArrowRight size={16} />
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
