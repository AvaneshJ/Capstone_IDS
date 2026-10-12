import { riskToWord } from '../lib/translate';

export interface RiskGaugeProps {
  score: number;
  size?: number;
}

export function RiskGauge({ score, size = 180 }: RiskGaugeProps) {
  const value = Math.min(Math.max(score, 0), 10);
  const { label, hex } = riskToWord(value);
  const r = 70;
  const arc = Math.PI * r;
  const offset = arc - (value / 10) * arc;

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size * 0.6} viewBox="0 0 180 108" aria-label={`Danger ${value.toFixed(1)} out of 10`}>
        <defs>
          <linearGradient id="risk-track" x1="0" x2="1">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="50%" stopColor="#fbbf24" />
            <stop offset="75%" stopColor="#fb923c" />
            <stop offset="100%" stopColor="#f87171" />
          </linearGradient>
        </defs>
        <path d="M 20 95 A 70 70 0 0 1 160 95" fill="none" stroke="rgb(255 255 255 / 0.08)" strokeWidth="14" strokeLinecap="round" />
        <path
          d="M 20 95 A 70 70 0 0 1 160 95"
          fill="none"
          stroke="url(#risk-track)"
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={arc}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(0.2, 0.7, 0.2, 1)', filter: `drop-shadow(0 0 8px ${hex}66)` }}
        />
        <text x="90" y="82" textAnchor="middle" className="fill-fg" style={{ fontSize: 30, fontWeight: 650 }}>
          {value.toFixed(1)}
        </text>
        <text x="90" y="100" textAnchor="middle" className="fill-fg-subtle" style={{ fontSize: 11 }}>
          out of 10
        </text>
      </svg>
      <span className="tag mt-2" style={{ color: hex, background: `${hex}1f`, borderColor: `${hex}44` }}>
        {label} danger
      </span>
    </div>
  );
}
