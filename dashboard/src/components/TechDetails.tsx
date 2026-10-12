import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';
import dayjs from 'dayjs';

export interface TechDetailsProps {
  data: Record<string, any>;
  defaultOpen?: boolean;
}

const ACRONYMS: Record<string, string> = {
  id: 'ID', ip: 'IP', ips: 'IPs', ml: 'ML', llm: 'LLM', mitre: 'MITRE', pid: 'PID',
  cpu: 'CPU', mb: 'MB', soc: 'SOC', url: 'URL', ms: 'ms', ood: 'OOD', json: 'JSON',
  fwd: 'Forward', bwd: 'Backward', pkt: 'packet', pkts: 'packets', len: 'length', tot: 'Total',
};

// Backend field names are snake_case; anything else (e.g. model class names like "DDoS") is a label, shown as-is.
function humanize(key: string): string {
  if (!key.includes('_') && key !== key.toLowerCase()) return key;
  const words = key
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((w) => ACRONYMS[w.toLowerCase()] ?? w.toLowerCase());
  if (words.length === 0) return key;
  const first = words[0];
  words[0] = first === first.toUpperCase() ? first : first.charAt(0).toUpperCase() + first.slice(1);
  return words.join(' ');
}

const TIME_KEY = /(timestamp|_at$|^last_seen$|^expires)/i;
const RATIO_KEY = /(confidence|probabilit|anomaly_score)/i;

function isProbabilityMap(name: string, value: unknown): value is Record<string, number> {
  if (!RATIO_KEY.test(name) || !isPlainObject(value)) return false;
  const nums = Object.values(value);
  return nums.length > 0 && nums.every((n) => typeof n === 'number' && n >= 0 && n <= 1);
}

function ProbabilityBars({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-1.5 mt-1">
      {rows.map(([label, p]) => (
        <div key={label} className="flex items-center gap-3 text-xs">
          <span className="w-32 shrink-0 truncate font-medium text-fg" title={label}>{label}</span>
          <div className="flex-1 h-2 rounded-[3px] bg-white/8 overflow-hidden">
            <div className="h-full rounded-[3px] bg-gradient-to-r from-accent-strong to-accent-soft" style={{ width: `${Math.max(p * 100, 1)}%` }} />
          </div>
          <span className="w-12 text-right font-mono text-fg-muted">{(p * 100).toFixed(1)}%</span>
        </div>
      ))}
    </div>
  );
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === 'object') return Object.keys(value as object).length === 0;
  return false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function formatScalar(key: string, value: unknown): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') {
    if (TIME_KEY.test(key) && value > 1e9) return dayjs.unix(value).format('YYYY-MM-DD HH:mm:ss');
    if (RATIO_KEY.test(key) && value >= 0 && value <= 1) return `${(value * 100).toFixed(1)}%`;
    return Number.isInteger(value) ? value.toLocaleString() : String(Number(value.toFixed(4)));
  }
  return String(value);
}

function FieldList({ data, depth = 0 }: { data: Record<string, unknown>; depth?: number }) {
  const entries = Object.entries(data).filter(([, v]) => !isEmpty(v));
  if (entries.length === 0) return <p className="text-sm text-fg-subtle">No data</p>;

  return (
    <dl className={depth === 0
      ? 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-6 gap-y-3'
      : 'grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 pl-3 mt-1 border-l-2 border-line-strong'}>
      {entries.map(([key, value]) => (
        <Field key={key} name={key} value={value} depth={depth} />
      ))}
    </dl>
  );
}

function Field({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  const isComplex = isPlainObject(value) || (Array.isArray(value) && value.some((v) => typeof v === 'object'));

  return (
    <div className={`min-w-0 ${isComplex ? 'md:col-span-2 xl:col-span-3' : ''}`}>
      <dt className="text-[11px] font-semibold text-fg-subtle uppercase tracking-wider mb-0.5">{humanize(name)}</dt>
      <dd className="text-sm text-fg break-words selectable">
        {isProbabilityMap(name, value) ? (
          <ProbabilityBars data={value} />
        ) : isPlainObject(value) ? (
          <FieldList data={value} depth={depth + 1} />
        ) : Array.isArray(value) ? (
          value.every((v) => typeof v !== 'object') ? (
            <ul className="list-disc pl-5 space-y-0.5">
              {value.map((v, i) => <li key={i}>{formatScalar(name, v)}</li>)}
            </ul>
          ) : (
            <div className="space-y-2">
              {value.map((v, i) => (
                isPlainObject(v) ? <FieldList key={i} data={v} depth={depth + 1} /> : <p key={i}>{formatScalar(name, v)}</p>
              ))}
            </div>
          )
        ) : (
          <span className="font-mono">{formatScalar(name, value)}</span>
        )}
      </dd>
    </div>
  );
}

export function TechDetails({ data, defaultOpen = false }: TechDetailsProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const visible = Object.entries(data).filter(([, v]) => !isEmpty(v));
  const overview = Object.fromEntries(visible.filter(([, v]) => !isPlainObject(v)));
  const sections = visible.filter(([, v]) => isPlainObject(v)) as [string, Record<string, unknown>][];

  return (
    <div className="glass overflow-hidden animate-fade-up">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.03] transition-colors text-left focus:outline-none"
      >
        <div className="flex items-center gap-2 text-[15px] font-semibold text-fg">
          {isOpen ? <ChevronDown size={18} className="text-fg-muted" /> : <ChevronRight size={18} className="text-fg-muted" />}
          Technical details
          <span className="text-xs font-normal text-fg-subtle">For IT support and security experts</span>
        </div>
        <div
          onClick={handleCopy}
          className="icon-btn w-8 h-8"
          title="Copy as JSON"
        >
          {copied ? <Check size={15} className="text-safe" /> : <Copy size={15} />}
        </div>
      </button>

      {isOpen && (
        <div className="px-5 pb-5 space-y-3">
          {Object.keys(overview).length > 0 && (
            <section className="glass-inset p-4">
              <h3 className="text-sm font-semibold text-fg mb-3">Overview</h3>
              <FieldList data={overview} />
            </section>
          )}
          {sections.map(([key, value]) => (
            <section key={key} className="glass-inset p-4">
              <h3 className="text-sm font-semibold text-fg mb-3">{humanize(key)}</h3>
              <FieldList data={value} />
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
