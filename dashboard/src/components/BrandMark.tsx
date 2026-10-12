export function BrandMark({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="brand-bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#c4b5fd" />
          <stop offset="55%" stopColor="#8b5cf6" />
          <stop offset="100%" stopColor="#5b3fd1" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="60" height="60" rx="16" fill="url(#brand-bg)" />
      <rect x="2.5" y="2.5" width="59" height="59" rx="15.5" fill="none" stroke="rgb(255 255 255 / 0.35)" />
      <path
        d="M32 13 L47 18.5 V31 C47 40.5 40.6 47.6 32 51 C23.4 47.6 17 40.5 17 31 V18.5 Z"
        fill="rgb(255 255 255 / 0.95)"
      />
      <path d="M25 31.5 L30 36.5 L39.5 26.5" fill="none" stroke="#6d4ae0" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
