import { AlertTriangle, RotateCw } from 'lucide-react';
import { IconTile } from './ui';

export interface ErrorStateProps {
  message?: string;
  hint?: string;
  onRetry?: () => void;
}

export function ErrorState({
  message = "We couldn't load this.",
  hint = 'SentinelAI may still be starting up. Try again in a few seconds.',
  onRetry,
}: ErrorStateProps) {
  return (
    <div className="glass flex flex-col items-center justify-center text-center px-6 py-12 animate-fade-up">
      <IconTile tone="danger" size="lg">
        <AlertTriangle size={26} />
      </IconTile>
      <p className="mt-4 text-base font-semibold text-fg">{message}</p>
      <p className="mt-1 text-sm text-fg-muted max-w-md">{hint}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn btn-secondary mt-5">
          <RotateCw size={15} /> Try again
        </button>
      )}
    </div>
  );
}
