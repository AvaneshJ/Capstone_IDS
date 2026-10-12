import { useContext, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Radar, ShieldAlert, Ban, Gauge, ChevronRight, FileText, Globe, Monitor, Sparkles } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid } from 'recharts';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { toast } from 'sonner';
import { ExpertContext } from '../App';
import { StatusBanner } from '../components/StatusBanner';
import { KpiCard } from '../components/KpiCard';
import { AlertCard } from '../components/AlertCard';
import { EmptyState } from '../components/EmptyState';
import { Skeleton, SkeletonList } from '../components/Skeleton';
import { Panel, Segmented } from '../components/ui';
import { LiveSensors } from '../components/LiveSensors';
import { LivePulse } from '../components/LivePulse';
import { getMetrics, getBlocks, generateReport, getReportDownloadUrl } from '../api/endpoints';
import { useMergedActivity } from '../hooks/useMergedActivity';
import { useOverallStatus } from '../hooks/useOverallStatus';
import { translateThreat, riskToWord, isBenign, maskIP } from '../lib/translate';
import { openDownload } from '../lib/desktop';

dayjs.extend(relativeTime);

const COLORS = ['#a78bfa', '#f3e17b', '#5eead4', '#f9a8d4', '#93c5fd', '#fdba74', '#86efac'];
const nf = new Intl.NumberFormat();

type Range = '24h' | '7d';

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  const n = payload[0].value;
  return (
    <div className="glass-strong px-3 py-2">
      <div className="text-[11px] text-fg-subtle">{label}</div>
      <div className="text-sm font-semibold text-fg">
        {n} threat{n === 1 ? '' : 's'} stopped
      </div>
    </div>
  );
}

export default function Home() {
  const { expert } = useContext(ExpertContext);
  const navigate = useNavigate();
  const [range, setRange] = useState<Range>('24h');
  const [creatingReport, setCreatingReport] = useState(false);

  const { data: metrics, isLoading: metricsLoading } = useQuery({ queryKey: ['metrics'], queryFn: getMetrics, refetchInterval: 10000 });
  const { data: blocks, isLoading: blocksLoading } = useQuery({ queryKey: ['blocks'], queryFn: getBlocks, refetchInterval: 15000 });
  const { alerts: activity, isLoading: activityLoading } = useMergedActivity();
  const overallStatus = useOverallStatus();

  const chartData = useMemo(() => {
    const now = dayjs();
    const buckets = new Map<string, number>();
    if (range === '24h') {
      for (let i = 23; i >= 0; i--) buckets.set(now.subtract(i, 'hour').format('h A'), 0);
      for (const a of activity) {
        const t = dayjs.unix(a.time);
        if (now.diff(t, 'hour') < 24) {
          const k = t.format('h A');
          if (buckets.has(k)) buckets.set(k, buckets.get(k)! + 1);
        }
      }
    } else {
      for (let i = 6; i >= 0; i--) buckets.set(now.subtract(i, 'day').format('ddd D'), 0);
      for (const a of activity) {
        const t = dayjs.unix(a.time);
        if (now.startOf('day').diff(t.startOf('day'), 'day') < 7) {
          const k = t.format('ddd D');
          if (buckets.has(k)) buckets.set(k, buckets.get(k)! + 1);
        }
      }
    }
    return [...buckets.entries()].map(([time, threats]) => ({ time, threats }));
  }, [activity, range]);

  const totalInRange = chartData.reduce((s, d) => s + d.threats, 0);

  const pieData = useMemo(() => {
    const counts = new Map<string, number>();
    for (const [type, count] of Object.entries(metrics?.attack_distribution ?? {})) {
      if (isBenign(type)) continue;
      const name = translateThreat(type).friendlyName;
      counts.set(name, (counts.get(name) ?? 0) + (count as number));
    }
    for (const a of activity) {
      if (a.source === 'computer') counts.set(a.title, (counts.get(a.title) ?? 0) + 1);
    }
    return [...counts.entries()].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [metrics, activity]);
  const pieTotal = pieData.reduce((s, d) => s + d.value, 0);

  const latestAlerts = activity.slice(0, 5);
  const networkCount = activity.filter((a) => a.source === 'network').length;
  const computerCount = activity.filter((a) => a.source === 'computer').length;
  const sourceTotal = Math.max(networkCount + computerCount, 1);
  const topOffender = metrics?.top_offenders?.[0];
  const avgRisk = metrics?.average_threat_risk || 0;
  const activeBlocks = (blocks?.blocked_ips ?? []).filter((b) => ['ACTIVE', 'SIMULATED'].includes(b.status?.toUpperCase())).length;

  const createReport = async () => {
    setCreatingReport(true);
    try {
      const r = await generateReport();
      toast.success('Your security report is ready');
      openDownload(getReportDownloadUrl(r.filename));
    } catch {
      toast.error("Couldn't create the report. Is the protection engine running?");
    } finally {
      setCreatingReport(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Row 1: status + quick summary */}
      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-12 xl:col-span-8">
          <StatusBanner
            {...overallStatus}
            actions={
              <>
                <button onClick={() => navigate('/activity')} className="btn btn-primary">
                  See what happened <ChevronRight size={16} />
                </button>
                <button onClick={createReport} disabled={creatingReport} className="btn btn-secondary">
                  <FileText size={15} /> {creatingReport ? 'Creating report' : 'Create report'}
                </button>
              </>
            }
            footer={<LivePulse lastThreatAt={activity[0]?.time} />}
          />
        </div>
        <div className="col-span-12 xl:col-span-4">
          <Panel title="What SentinelAI watches" info="SentinelAI protects you in two places at the same time." className="h-full">
            <div className="space-y-3">
              <LiveSensors />
              <div className="flex items-start gap-2 text-xs text-fg-subtle pt-1">
                <Sparkles size={14} className="text-accent-soft shrink-0 mt-px" />
                AI checks every connection and program automatically. You don't need to do anything.
              </div>
            </div>
          </Panel>
        </div>
      </div>

      {/* Row 2: KPIs */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-5">
        {metricsLoading ? <Skeleton className="h-[148px]" /> : (
          <KpiCard
            tone="accent"
            icon={<Radar size={18} />}
            title="Connections checked"
            value={nf.format(metrics?.total_flows_analyzed || 0)}
            helperText="Every network connection SentinelAI has inspected for danger."
            footnote="Checked by AI, in real time"
          />
        )}
        {metricsLoading ? <Skeleton className="h-[148px]" /> : (
          <KpiCard
            tone="rose"
            icon={<ShieldAlert size={18} />}
            title="Threats caught"
            value={nf.format((metrics?.total_threats_detected || 0) + computerCount)}
            helperText="Suspicious activity found on your network or your computer."
            footnote={`${networkCount} from the internet, ${computerCount} on this computer`}
          />
        )}
        {blocksLoading ? <Skeleton className="h-[148px]" /> : (
          <KpiCard
            tone="sun"
            icon={<Ban size={18} />}
            title="Addresses blocked"
            value={nf.format(activeBlocks)}
            helperText="Outside computers that are currently kept away from yours."
            footnote={<Link to="/blocked" className="hover:text-fg">Manage blocked connections</Link>}
          />
        )}
        {metricsLoading ? <Skeleton className="h-[148px]" /> : (
          <KpiCard
            tone="mint"
            icon={<Gauge size={18} />}
            title="Average danger level"
            value={`${avgRisk.toFixed(1)} / 10`}
            helperText="How serious the threats were on average, from 0 (harmless) to 10 (critical)."
            footnote={<span style={{ color: riskToWord(avgRisk).hex }}>{riskToWord(avgRisk).label} on average</span>}
          />
        )}
      </div>

      {/* Row 3: trend + breakdown */}
      <div className="grid grid-cols-12 gap-5">
        <Panel
          className="col-span-12 xl:col-span-8"
          title="Threats stopped"
          subtitle={`${totalInRange} in the last ${range === '24h' ? '24 hours' : '7 days'}`}
          info="How many threats SentinelAI stopped over time. Spikes usually mean someone was actively attacking."
          actions={
            <Segmented
              ariaLabel="Time range"
              value={range}
              onChange={setRange}
              options={[
                { value: '24h', label: '24 hours' },
                { value: '7d', label: '7 days' },
              ]}
            />
          }
        >
          {activityLoading ? <Skeleton className="h-[260px]" /> : (
            <div className="h-[260px] -ml-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
                  <defs>
                    <linearGradient id="threat-fill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.45} />
                      <stop offset="100%" stopColor="#a78bfa" stopOpacity={0} />
                    </linearGradient>
                    <filter id="threat-glow" x="-10%" y="-50%" width="120%" height="200%">
                      <feGaussianBlur stdDeviation="4" result="blur" />
                      <feMerge>
                        <feMergeNode in="blur" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                  </defs>
                  <CartesianGrid vertical={false} stroke="rgb(255 255 255 / 0.06)" strokeDasharray="3 6" />
                  <XAxis dataKey="time" stroke="#6f6e82" fontSize={11} tickLine={false} axisLine={false} interval={range === '24h' ? 3 : 0} />
                  <YAxis stroke="#6f6e82" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'rgb(255 255 255 / 0.2)', strokeDasharray: '4 4' }} />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#c4b5fd"
                    strokeWidth={2.5}
                    fill="url(#threat-fill)"
                    filter="url(#threat-glow)"
                    activeDot={{ r: 5, fill: '#f3e17b', stroke: '#08080d', strokeWidth: 2 }}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="Types of threats" info="What kinds of attacks SentinelAI has caught so far.">
          {metricsLoading ? <Skeleton className="h-[260px]" /> : pieData.length === 0 ? (
            <div className="h-[260px] flex flex-col items-center justify-center text-center">
              <p className="text-sm font-medium text-fg">No threats yet</p>
              <p className="text-xs text-fg-subtle mt-1">When something is caught, you'll see the mix here.</p>
            </div>
          ) : (
            <div className="flex flex-col gap-4">
              <div className="relative h-[170px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={56} outerRadius={78} paddingAngle={3} dataKey="value" stroke="none" cornerRadius={4} isAnimationActive={false}>
                      {pieData.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      content={({ active, payload }) =>
                        active && payload?.length ? (
                          <div className="glass-strong px-3 py-2 text-sm">
                            <span className="text-fg font-medium">{payload[0].name}</span>
                            <span className="text-fg-muted">: {payload[0].value}</span>
                          </div>
                        ) : null
                      }
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-2xl font-semibold text-fg tabular-nums">{nf.format(pieTotal)}</span>
                  <span className="text-[11px] text-fg-subtle">total</span>
                </div>
              </div>
              <ul className="space-y-2">
                {pieData.slice(0, 5).map((d, i) => (
                  <li key={d.name} className="flex items-center gap-2.5 text-[13px]">
                    <span className="w-2.5 h-2.5 rounded-[3px] shrink-0" style={{ background: COLORS[i % COLORS.length] }} />
                    <span className="text-fg-muted truncate flex-1">{d.name}</span>
                    <span className="text-fg font-medium tabular-nums">{Math.round((d.value / pieTotal) * 100)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      </div>

      {/* Row 4: latest alerts + where from */}
      <div className="grid grid-cols-12 gap-5">
        <Panel
          className="col-span-12 xl:col-span-8"
          title="Latest alerts"
          subtitle="Click any alert to see what happened in plain English"
          actions={
            <Link to="/activity" className="btn btn-ghost btn-sm">
              See all <ChevronRight size={14} />
            </Link>
          }
        >
          {activityLoading ? <SkeletonList count={3} /> : latestAlerts.length === 0 ? (
            <EmptyState icon={<ShieldAlert size={24} />} title="All clear" description="No threats have been detected recently. SentinelAI keeps watching in the background." />
          ) : (
            <div className="space-y-2.5">
              {latestAlerts.map((alert) => (
                <AlertCard key={`${alert.source}-${alert.id}`} alert={alert} />
              ))}
            </div>
          )}
        </Panel>

        <Panel className="col-span-12 xl:col-span-4" title="Where threats came from" info="Threats either arrive over the internet, or come from a program running on this computer.">
          <div className="space-y-4">
            {[
              { label: 'From the internet', count: networkCount, color: '#a78bfa', icon: Globe },
              { label: 'On this computer', count: computerCount, color: '#5eead4', icon: Monitor },
            ].map((row) => (
              <div key={row.label}>
                <div className="flex items-center justify-between text-[13px] mb-1.5">
                  <span className="flex items-center gap-2 text-fg-muted">
                    <row.icon size={14} style={{ color: row.color }} /> {row.label}
                  </span>
                  <span className="text-fg font-medium tabular-nums">{row.count}</span>
                </div>
                <div className="h-2.5 rounded-[4px] bg-white/6 overflow-hidden">
                  <div
                    className="h-full rounded-[4px] transition-[width] duration-700"
                    style={{ width: `${(row.count / sourceTotal) * 100}%`, background: `linear-gradient(90deg, ${row.color}99, ${row.color})` }}
                  />
                </div>
              </div>
            ))}

            {topOffender && (
              <div className="glass-inset p-4 mt-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle mb-2">Most active troublemaker</div>
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-fg font-mono truncate">{expert ? topOffender.src_ip : maskIP(topOffender.src_ip)}</div>
                    <div className="text-xs text-fg-muted mt-0.5">
                      {topOffender.incident_count} attempts, last seen {dayjs.unix(topOffender.last_seen).fromNow()}
                    </div>
                  </div>
                  <span className="tag" style={{ color: riskToWord(topOffender.max_risk_score).hex, background: `${riskToWord(topOffender.max_risk_score).hex}1f` }}>
                    {topOffender.max_risk_score.toFixed(1)} / 10
                  </span>
                </div>
              </div>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
