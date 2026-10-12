import { useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ExpertContext } from '../App';
import { ingestFlow, ingestHostEvent } from '../api/endpoints';
import { toast } from 'sonner';
import { Zap, KeyRound, Radar, EyeOff, CheckCircle2, Loader2, Lock, Play, Info } from 'lucide-react';
import { IconTile } from '../components/ui';

export function Demo() {
  const { expert, setExpert } = useContext(ExpertContext);
  const navigate = useNavigate();
  const [loadingId, setLoadingId] = useState<number | null>(null);

  if (!expert) {
    return (
      <div className="glass flex flex-col items-center justify-center text-center px-6 py-16 animate-fade-up">
        <IconTile tone="sun" size="lg">
          <Lock size={26} />
        </IconTile>
        <h2 className="mt-4 text-lg font-semibold text-fg">The demo panel is for experts</h2>
        <p className="mt-1 text-sm text-fg-muted max-w-md">Switch to Expert view to send safe practice attacks and see how SentinelAI responds.</p>
        <button onClick={() => setExpert(true)} className="btn btn-primary mt-5">
          Switch to Expert view
        </button>
      </div>
    );
  }

  const run = async (id: number, action: () => Promise<unknown>) => {
    setLoadingId(id);
    try {
      await action();
      toast.success('Practice attack sent', {
        description: 'Watch for the alert, or open Activity.',
        action: { label: 'Open Activity', onClick: () => navigate('/activity') },
      });
    } catch {
      toast.error("Couldn't send it. Is the protection engine running?");
    } finally {
      setTimeout(() => setLoadingId(null), 1200);
    }
  };

  const demos = [
    {
      id: 1,
      title: 'Password-guessing attack (SSH)',
      description: 'Someone repeatedly tries to log in remotely.',
      icon: KeyRound,
      tone: 'danger' as const,
      action: () => ingestFlow({ dst_port: 22, syn_flag_count: 50, flow_pkts_s: 500 }),
    },
    {
      id: 2,
      title: 'Flood attack (DDoS)',
      description: 'A huge burst of junk traffic to overwhelm the computer.',
      icon: Zap,
      tone: 'high' as const,
      action: () => ingestFlow({ flow_pkts_s: 50000, tot_fwd_pkts: 10000 }),
    },
    {
      id: 3,
      title: 'Port scan',
      description: 'An outsider checking for open doors into the computer.',
      icon: Radar,
      tone: 'warn' as const,
      action: () => ingestFlow({ dst_port: 0, syn_flag_count: 100 }),
    },
    {
      id: 4,
      title: 'Password-stealing program',
      description: 'An unknown program opens Chrome’s saved passwords.',
      icon: EyeOff,
      tone: 'accent' as const,
      action: () =>
        ingestHostEvent({
          pid: 40000 + Math.floor(Math.random() * 20000),
          process_name: 'svc_update.exe',
          parent_name: 'powershell.exe',
          file_path: 'C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
          event_type: 'READ',
          label: 'Stealer',
          confidence: 0.97,
        }),
    },
    {
      id: 5,
      title: 'Normal traffic',
      description: 'Ordinary web browsing. Should not raise an alert.',
      icon: CheckCircle2,
      tone: 'safe' as const,
      action: () => ingestFlow({ dst_port: 443, flow_pkts_s: 10, tot_fwd_pkts: 5 }),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="glass-inset px-4 py-3 flex items-center gap-3 text-[13px] text-fg-muted">
        <Info size={16} className="text-accent-soft shrink-0" />
        These are safe, made-up events sent through the real detection pipeline. Nothing actually attacks your computer.
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-4">
        {demos.map((demo) => {
          const loading = loadingId === demo.id;
          return (
            <div key={demo.id} className="glass glass-hover p-5 flex flex-col animate-fade-up">
              <div className="flex items-start gap-3">
                <IconTile tone={demo.tone}>
                  <demo.icon size={18} />
                </IconTile>
                <div>
                  <h3 className="text-[15px] font-semibold text-fg">{demo.title}</h3>
                  <p className="text-[13px] text-fg-muted mt-0.5">{demo.description}</p>
                </div>
              </div>
              <button onClick={() => run(demo.id, demo.action)} disabled={loadingId !== null} className="btn btn-secondary mt-5 self-start">
                {loading ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
                {loading ? 'Sending' : 'Send'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
