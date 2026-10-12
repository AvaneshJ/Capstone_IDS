import { useContext, useMemo, useState } from 'react';
import { Search, Zap, Waves, Cpu, KeyRound, Radar, DoorOpen, Globe, AlertCircle, EyeOff, Lock, Bug, ShieldCheck, Lightbulb, type LucideIcon } from 'lucide-react';
import { ExpertContext } from '../App';
import { translateThreat } from '../lib/translate';
import { IconTile } from '../components/ui';

interface LearnItem {
  id: string;
  icon: LucideIcon;
  where: 'internet' | 'computer';
  detects: boolean;
}

const THREATS: LearnItem[] = [
  { id: 'DDoS', icon: Waves, where: 'internet', detects: true },
  { id: 'DoS', icon: Zap, where: 'internet', detects: true },
  { id: 'SSH-Bruteforce', icon: KeyRound, where: 'internet', detects: true },
  { id: 'FTP-BruteForce', icon: KeyRound, where: 'internet', detects: true },
  { id: 'PortScan', icon: Radar, where: 'internet', detects: true },
  { id: 'Botnet', icon: Cpu, where: 'internet', detects: true },
  { id: 'Stealer', icon: EyeOff, where: 'computer', detects: true },
  { id: 'AnomalousTraffic', icon: AlertCircle, where: 'internet', detects: true },
  { id: 'Infiltration', icon: DoorOpen, where: 'internet', detects: false },
  { id: 'WebAttack', icon: Globe, where: 'internet', detects: false },
  { id: 'Ransomware', icon: Lock, where: 'computer', detects: false },
  { id: 'Malware', icon: Bug, where: 'computer', detects: false },
];

type Filter = 'all' | 'internet' | 'computer';

export function Learn() {
  const { expert } = useContext(ExpertContext);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');

  const items = useMemo(() => {
    const q = query.toLowerCase();
    return THREATS.filter((t) => filter === 'all' || t.where === filter)
      .map((t) => ({ ...t, info: translateThreat(t.id) }))
      .filter((t) => !q || `${t.info.friendlyName} ${t.info.explanation}`.toLowerCase().includes(q));
  }, [query, filter]);

  return (
    <div className="space-y-5">
      <div className="glass p-4 flex flex-wrap items-center gap-3 animate-fade-up">
        <div className="relative flex-1 min-w-[260px] max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input className="field pl-9" placeholder="Search threats, for example 'password'" value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
        <div className="segmented">
          {(['all', 'internet', 'computer'] as Filter[]).map((f) => (
            <button key={f} data-active={filter === f} onClick={() => setFilter(f)}>
              {f === 'all' ? 'All threats' : f === 'internet' ? 'From the internet' : 'On your computer'}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-4">
        {items.map((t) => (
          <article key={t.id} className="glass glass-hover p-5 flex flex-col animate-fade-up">
            <div className="flex items-start gap-3">
              <IconTile tone={t.where === 'internet' ? 'accent' : 'mint'}>
                <t.icon size={18} />
              </IconTile>
              <div className="min-w-0 flex-1">
                <h2 className="text-[15px] font-semibold text-fg leading-snug">{t.info.friendlyName}</h2>
                <div className="flex gap-1.5 mt-1.5">
                  <span className="tag tag-neutral">{t.where === 'internet' ? 'Internet' : 'Computer'}</span>
                  {t.detects ? <span className="tag tag-safe">SentinelAI detects this</span> : <span className="tag tag-neutral">Not covered yet</span>}
                </div>
              </div>
            </div>

            <div className="mt-4 space-y-3 flex-1">
              <div>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle mb-1">What is it?</h3>
                <p className="text-sm text-fg-muted leading-relaxed">{t.info.explanation}</p>
              </div>
              <div>
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle mb-1">How SentinelAI helps</h3>
                <p className="text-sm text-fg-muted leading-relaxed flex gap-2">
                  <ShieldCheck size={15} className="text-safe shrink-0 mt-0.5" />
                  {!t.detects
                    ? "SentinelAI doesn't specifically recognise this yet. Keep Windows and your antivirus up to date."
                    : t.where === 'internet'
                      ? 'Our AI recognises the pattern in your network traffic and blocks the attacker.'
                      : 'We notice when an unknown program touches your private files and stop it.'}
                </p>
              </div>
              {t.info.advice && (
                <div>
                  <h3 className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle mb-1">What you can do</h3>
                  <p className="text-sm text-fg-muted leading-relaxed flex gap-2">
                    <Lightbulb size={15} className="text-sun shrink-0 mt-0.5" />
                    {t.info.advice}
                  </p>
                </div>
              )}
            </div>

            {expert && <p className="mt-4 pt-3 border-t border-line text-[11px] font-mono text-fg-subtle">Model label: {t.id}</p>}
          </article>
        ))}
      </div>
    </div>
  );
}
