import { useContext, useState, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, Inbox, List, Table2 } from 'lucide-react';
import dayjs from 'dayjs';
import { ExpertContext } from '../App';
import { AlertCard } from '../components/AlertCard';
import { SkeletonList } from '../components/Skeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { SeverityBadge } from '../components/SeverityBadge';
import { Segmented } from '../components/ui';
import { useMergedActivity } from '../hooks/useMergedActivity';
import type { MergedAlert } from '../hooks/useMergedActivity';
import { isBenign } from '../lib/translate';
import { formatTime } from '../lib/time';

type SourceFilter = 'all' | 'network' | 'computer';
type DangerFilter = 'all' | 'critical' | 'serious' | 'look' | 'minor';

const DANGER_TO_SEVERITY: Record<string, string> = {
  critical: 'CRITICAL',
  serious: 'HIGH',
  look: 'MEDIUM',
  minor: 'LOW',
};

export default function Activity() {
  const { expert } = useContext(ExpertContext);
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { alerts: activity, isLoading, error } = useMergedActivity();

  const [searchQuery, setSearchQuery] = useState('');
  const [showBenign, setShowBenign] = useState(false);
  const [tableView, setTableView] = useState(false);

  const filterSource = (searchParams.get('source') || 'all') as SourceFilter;
  const filterDanger = (searchParams.get('danger') || 'all') as DangerFilter;

  const updateParam = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value === 'all') next.delete(key);
    else next.set(key, value);
    setSearchParams(next);
  };

  const filtered = useMemo(() => {
    return activity.filter((item) => {
      if (!showBenign && isBenign(item.typeRaw)) return false;
      if (filterSource !== 'all' && item.source !== filterSource) return false;
      if (filterDanger !== 'all' && item.severityRaw?.toUpperCase() !== DANGER_TO_SEVERITY[filterDanger]) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const hay = `${item.typeRaw} ${item.title} ${item.srcIp ?? ''} ${item.processName ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [activity, filterSource, filterDanger, searchQuery, showBenign]);

  const grouped = useMemo(() => {
    const groups: [string, MergedAlert[]][] = [];
    const index = new Map<string, MergedAlert[]>();
    for (const item of filtered) {
      const d = dayjs.unix(item.time);
      const key = d.isSame(dayjs(), 'day') ? 'Today' : d.isSame(dayjs().subtract(1, 'day'), 'day') ? 'Yesterday' : d.format('dddd, MMM D');
      if (!index.has(key)) {
        const arr: MergedAlert[] = [];
        index.set(key, arr);
        groups.push([key, arr]);
      }
      index.get(key)!.push(item);
    }
    return groups;
  }, [filtered]);

  if (error) return <ErrorState message="We couldn't load your activity." />;

  return (
    <div className="space-y-5">
      <div className="glass p-4 flex flex-wrap items-center gap-3 animate-fade-up">
        <div className="relative flex-1 min-w-[260px] max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input
            type="text"
            placeholder="Search by threat, program or address"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="field pl-9"
          />
        </div>

        <Segmented<SourceFilter>
          ariaLabel="Where"
          value={filterSource}
          onChange={(v) => updateParam('source', v)}
          options={[
            { value: 'all', label: 'Everywhere' },
            { value: 'network', label: 'Internet' },
            { value: 'computer', label: 'This computer' },
          ]}
        />

        <Segmented<DangerFilter>
          ariaLabel="Danger level"
          value={filterDanger}
          onChange={(v) => updateParam('danger', v)}
          options={[
            { value: 'all', label: 'Any danger' },
            { value: 'critical', label: 'Critical' },
            { value: 'serious', label: 'Serious' },
            { value: 'look', label: 'Worth a look' },
            { value: 'minor', label: 'Minor' },
          ]}
        />

        <div className="flex items-center gap-4 ml-auto">
          <label className="flex items-center gap-2 text-[13px] text-fg-muted cursor-pointer">
            <input type="checkbox" className="checkbox" checked={showBenign} onChange={(e) => setShowBenign(e.target.checked)} />
            Include normal activity
          </label>
          {expert && (
            <Segmented
              ariaLabel="Layout"
              value={tableView ? 'table' : 'list'}
              onChange={(v) => setTableView(v === 'table')}
              options={[
                { value: 'list', label: <List size={14} /> },
                { value: 'table', label: <Table2 size={14} /> },
              ]}
            />
          )}
        </div>
      </div>

      <div className="text-[13px] text-fg-subtle px-1">
        Showing {filtered.length} of {activity.length} alerts
      </div>

      {isLoading ? (
        <SkeletonList count={5} />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Inbox size={24} />}
          tone="neutral"
          title="Nothing matches these filters"
          description="Try choosing 'Everywhere' and 'Any danger', or clear the search box."
        />
      ) : expert && tableView ? (
        <div className="glass overflow-hidden animate-fade-up">
          <div className="overflow-x-auto">
            <table className="min-w-full text-[13px] text-left">
              <thead className="text-[11px] uppercase tracking-wider text-fg-subtle border-b border-line">
                <tr>
                  {['Time', 'Where', 'Threat', 'Source → Target', 'Port', 'Confidence', 'Danger', 'Action'].map((h) => (
                    <th key={h} className="px-4 py-3 font-semibold whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filtered.map((item) => (
                  <tr
                    key={`${item.source}-${item.id}`}
                    onClick={() => navigate(`/activity/${item.source}/${item.id}`)}
                    className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-2.5 whitespace-nowrap text-fg-muted">{formatTime(item.time)}</td>
                    <td className="px-4 py-2.5 text-fg-muted">{item.source === 'network' ? 'Internet' : 'Computer'}</td>
                    <td className="px-4 py-2.5 text-fg font-medium">{item.title}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">
                      {item.srcIp || item.processName || '-'} → {item.dstIp || '-'}
                    </td>
                    <td className="px-4 py-2.5 text-fg-muted">{item.dstPort || '-'}</td>
                    <td className="px-4 py-2.5 text-fg-muted tabular-nums">{item.confidence ? `${Math.round(item.confidence * 100)}%` : '-'}</td>
                    <td className="px-4 py-2.5"><SeverityBadge severity={item.severityRaw} short /></td>
                    <td className="px-4 py-2.5 text-fg-muted">{item.actionState === 'test' ? `Test mode: ${item.actionLabel.toLowerCase()}` : item.actionLabel}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {grouped.map(([group, items]) => (
            <section key={group} className="animate-fade-up">
              <div className="flex items-center gap-3 mb-3 px-1">
                <h2 className="text-sm font-semibold text-fg">{group}</h2>
                <span className="tag tag-neutral">{items.length}</span>
                <div className="flex-1 border-t border-line" />
              </div>
              <div className="space-y-2.5">
                {items.map((item) => (
                  <AlertCard key={`${item.source}-${item.id}`} alert={item} />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
