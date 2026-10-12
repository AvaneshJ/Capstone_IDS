export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

export function SkeletonCard() {
  return (
    <div className="glass p-4 flex gap-4">
      <div className="w-10 h-10 skeleton shrink-0" />
      <div className="flex-1 space-y-2.5 py-1">
        <div className="h-3.5 skeleton w-1/2" />
        <div className="h-3 skeleton w-5/6" />
      </div>
    </div>
  );
}

export function SkeletonList({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  );
}

export function SkeletonText({ lines = 1, width = 'w-full', className = '' }: { lines?: number; width?: string; className?: string }) {
  if (lines === 1) return <div className={`h-4 skeleton ${width} ${className}`} />;
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className={`h-4 skeleton ${i === lines - 1 ? 'w-2/3' : 'w-full'}`} />
      ))}
    </div>
  );
}
