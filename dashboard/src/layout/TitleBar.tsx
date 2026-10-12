import { useEffect, useState } from 'react';
import { Minus, Square, Copy, X } from 'lucide-react';
import { BrandMark } from '../components/BrandMark';
import { desktop } from '../lib/desktop';

export function TitleBar() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    if (!desktop) return;
    desktop.isMaximized().then(setMaximized);
    return desktop.onMaximizedChange(setMaximized);
  }, []);

  if (!desktop) return null;

  return (
    <div className="drag relative z-50 h-9 shrink-0 flex items-center justify-between select-none" onDoubleClick={() => desktop?.toggleMaximize()}>
      <div className="flex items-center gap-2 pl-4 text-xs font-medium text-fg-muted">
        <BrandMark size={16} />
        <span className="text-fg">SentinelAI</span>
        <span className="text-fg-subtle">Security assistant</span>
      </div>

      <div className="no-drag flex h-full">
        <button onClick={() => desktop?.minimize()} className="w-12 h-full flex items-center justify-center text-fg-muted hover:bg-white/8 hover:text-fg transition-colors" aria-label="Minimize">
          <Minus size={15} />
        </button>
        <button onClick={() => desktop?.toggleMaximize()} className="w-12 h-full flex items-center justify-center text-fg-muted hover:bg-white/8 hover:text-fg transition-colors" aria-label={maximized ? 'Restore' : 'Maximize'}>
          {maximized ? <Copy size={13} className="-scale-x-100" /> : <Square size={12} />}
        </button>
        <button onClick={() => desktop?.close()} className="w-12 h-full flex items-center justify-center text-fg-muted hover:bg-[#e81123] hover:text-white transition-colors" aria-label="Close">
          <X size={16} />
        </button>
      </div>
    </div>
  );
}
