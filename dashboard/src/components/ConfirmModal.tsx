import { useEffect } from 'react';
import { AlertTriangle, HelpCircle } from 'lucide-react';
import { IconTile } from './ui';

export interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'default';
}

export function ConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'default',
}: ConfirmModalProps) {
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center p-6 bg-black/55 backdrop-blur-sm" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        className="glass-strong w-full max-w-md animate-pop-in"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="p-6 flex gap-4">
          <IconTile tone={variant === 'danger' ? 'warn' : 'accent'}>
            {variant === 'danger' ? <AlertTriangle size={18} /> : <HelpCircle size={18} />}
          </IconTile>
          <div>
            <h3 className="text-base font-semibold text-fg">{title}</h3>
            <p className="mt-1.5 text-sm text-fg-muted leading-relaxed">{message}</p>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-line flex justify-end gap-2">
          {/* For risky actions the safe choice is the highlighted one. */}
          <button onClick={onClose} className={`btn ${variant === 'danger' ? 'btn-primary' : 'btn-ghost'}`} autoFocus>
            {cancelLabel}
          </button>
          <button
            onClick={() => {
              onConfirm();
              onClose();
            }}
            className={`btn ${variant === 'danger' ? 'btn-secondary text-danger' : 'btn-primary'}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
