import { useState, useContext } from 'react';
import { ExpertContext } from '../App';
import { generateReport, getReportDownloadUrl } from '../api/endpoints';
import { FileText, Download, Loader2, CheckCircle2, ShieldCheck, ListChecks, Gauge, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { Panel, IconTile, EmptyState } from '../components/index';
import { openDownload } from '../lib/desktop';

dayjs.extend(relativeTime);

interface ReportRecord {
  filename: string;
  date: string;
}

function loadReports(): ReportRecord[] {
  try {
    return JSON.parse(localStorage.getItem('sentinel_reports') || '[]');
  } catch {
    return [];
  }
}

const CONTENTS = [
  { icon: ShieldCheck, text: 'Overall protection status' },
  { icon: ListChecks, text: 'Every threat found and what was done' },
  { icon: Gauge, text: 'How dangerous each threat was' },
];

export function Reports() {
  const { expert } = useContext(ExpertContext);
  const [loading, setLoading] = useState(false);
  const [reports, setReports] = useState<ReportRecord[]>(loadReports);

  const save = (next: ReportRecord[]) => {
    setReports(next);
    localStorage.setItem('sentinel_reports', JSON.stringify(next));
  };

  const handleGenerate = async () => {
    setLoading(true);
    try {
      const result = await generateReport();
      save([{ filename: result.filename, date: new Date().toISOString() }, ...reports]);
      toast.success('Your security report is ready', {
        action: { label: 'Save', onClick: () => openDownload(getReportDownloadUrl(result.filename)) },
      });
    } catch {
      toast.error("Couldn't create the report. Is the protection engine running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid grid-cols-12 gap-5">
      <section className="col-span-12 xl:col-span-5 glass p-6 animate-fade-up overflow-hidden">
        <div className="pointer-events-none absolute -left-20 -bottom-24 w-72 h-72 rounded-full bg-accent/15 blur-3xl" />
        <div className="relative">
          <IconTile tone="accent" size="lg">
            <FileText size={26} />
          </IconTile>
          <h2 className="mt-5 text-lg font-semibold text-fg">Create a security report</h2>
          <p className="mt-1 text-sm text-fg-muted leading-relaxed">
            A clear PDF summary of everything SentinelAI saw and did. Useful for your records, or to share with IT support if something went wrong.
          </p>
          <ul className="mt-5 space-y-2.5">
            {CONTENTS.map((c) => (
              <li key={c.text} className="flex items-center gap-3 text-sm text-fg">
                <CheckCircle2 size={16} className="text-safe shrink-0" />
                {c.text}
              </li>
            ))}
          </ul>
          <button onClick={handleGenerate} disabled={loading} className="btn btn-primary btn-lg w-full mt-6">
            {loading ? <Loader2 size={18} className="animate-spin" /> : <FileText size={18} />}
            {loading ? 'Creating your report' : 'Create report (PDF)'}
          </button>
        </div>
      </section>

      <Panel
        className="col-span-12 xl:col-span-7"
        title="Past reports"
        subtitle={reports.length ? `${reports.length} report${reports.length === 1 ? '' : 's'} created on this computer` : undefined}
        actions={
          reports.length > 0 && (
            <button onClick={() => save([])} className="btn btn-ghost btn-sm" title="Remove the list (files are kept)">
              <Trash2 size={14} /> Clear list
            </button>
          )
        }
      >
        {reports.length === 0 ? (
          <EmptyState icon={<FileText size={24} />} tone="neutral" title="No reports yet" description="Reports you create will appear here so you can download them again." />
        ) : (
          <div className="space-y-2">
            {reports.map((r, idx) => (
              <div key={`${r.filename}-${idx}`} className="glass-inset glass-hover px-4 py-3 flex items-center gap-4">
                <IconTile tone="accent" size="sm">
                  <FileText size={16} />
                </IconTile>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium text-fg">Security report</div>
                  <div className="text-xs text-fg-muted">
                    {dayjs(r.date).format('MMM D, YYYY h:mm A')} · {dayjs(r.date).fromNow()}
                  </div>
                  {expert && <div className="text-[11px] text-fg-subtle font-mono mt-0.5 truncate">{r.filename}</div>}
                </div>
                <button onClick={() => openDownload(getReportDownloadUrl(r.filename))} className="btn btn-secondary btn-sm">
                  <Download size={14} /> Download
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
