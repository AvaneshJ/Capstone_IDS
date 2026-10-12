import { useEffect, useState } from 'react';
import { Loader2, AlertTriangle, RotateCw } from 'lucide-react';
import { desktop, type EngineState } from '../lib/desktop';

export function EngineBanner() {
  const [engine, setEngine] = useState<EngineState | null>(null);
  const [retrying, setRetrying] = useState(false);

  useEffect(() => {
    if (!desktop) return;
    desktop.engineState().then(setEngine);
    return desktop.onEngineState(setEngine);
  }, []);

  if (!engine || engine.status === 'running' || engine.status === 'external') return null;

  if (engine.status === 'starting') {
    return (
      <div className="mx-8 mb-4 glass-inset px-4 py-3 flex items-center gap-3 animate-fade-up">
        <Loader2 size={18} className="text-accent-soft animate-spin" />
        <div>
          <p className="text-sm font-medium text-fg">Starting the protection engine</p>
          <p className="text-xs text-fg-muted">Loading the AI models. This usually takes a few seconds.</p>
        </div>
      </div>
    );
  }

  const retry = async () => {
    if (!desktop) return;
    setRetrying(true);
    try {
      setEngine(await desktop.restartEngine());
    } finally {
      setRetrying(false);
    }
  };

  return (
    <div className="mx-8 mb-4 rounded-xl border border-danger/30 bg-danger/10 px-4 py-3 flex items-center gap-3 animate-fade-up">
      <AlertTriangle size={18} className="text-danger shrink-0" />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-fg">The protection engine stopped</p>
        <p className="text-xs text-fg-muted truncate" title={engine.logPath}>
          {engine.message}
          {engine.logPath ? ` Details are saved in ${engine.logPath}` : ''}
        </p>
      </div>
      <button onClick={retry} disabled={retrying} className="btn btn-secondary btn-sm">
        <RotateCw size={14} className={retrying ? 'animate-spin' : ''} /> Start again
      </button>
    </div>
  );
}
