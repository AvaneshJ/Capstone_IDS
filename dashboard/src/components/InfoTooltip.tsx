import { useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Info } from 'lucide-react';

export interface InfoTooltipProps {
  text: string;
}

const WIDTH = 240;
const GAP = 8;
const EDGE = 12;

export function InfoTooltip({ text }: InfoTooltipProps) {
  const anchorRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  // Rendered in a portal with fixed positioning: cards use overflow-hidden for their glow,
  // which would otherwise clip the bubble.
  useLayoutEffect(() => {
    if (!open || !anchorRef.current || !tipRef.current) return;
    const a = anchorRef.current.getBoundingClientRect();
    const h = tipRef.current.offsetHeight;
    const left = Math.min(Math.max(a.left + a.width / 2 - WIDTH / 2, EDGE), window.innerWidth - WIDTH - EDGE);
    const above = a.top - GAP - h;
    const top = above >= EDGE ? above : a.bottom + GAP;
    setPos({ top, left });
  }, [open, text]);

  const show = () => setOpen(true);
  const hide = () => {
    setOpen(false);
    setPos(null);
  };

  return (
    <span
      ref={anchorRef}
      className="group relative inline-flex items-center justify-center cursor-help"
      tabIndex={0}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      <Info size={14} className="text-fg-subtle group-hover:text-fg-muted transition-colors" />
      {open &&
        createPortal(
          <div
            ref={tipRef}
            role="tooltip"
            className="fixed z-[1000] pointer-events-none px-3 py-2 glass-strong text-xs font-normal text-fg-muted leading-relaxed text-left transition-opacity duration-150"
            style={{ width: WIDTH, top: pos?.top ?? 0, left: pos?.left ?? 0, opacity: pos ? 1 : 0 }}
          >
            {text}
          </div>,
          document.body,
        )}
    </span>
  );
}
