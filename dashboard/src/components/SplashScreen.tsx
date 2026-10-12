import { useState, useEffect } from 'react';
import { BrandMark } from './BrandMark';

export function SplashScreen({ onFinish }: { onFinish: () => void }) {
  const [isFading, setIsFading] = useState(false);

  useEffect(() => {
    const fadeTimer = setTimeout(() => setIsFading(true), 1300);
    const unmountTimer = setTimeout(onFinish, 1800);
    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(unmountTimer);
    };
  }, [onFinish]);

  return (
    <div
      className={`fixed inset-0 z-[100] flex items-center justify-center transition-opacity duration-500 ${
        isFading ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      <div className="app-bg" />
      <div className="relative flex flex-col items-center animate-pop-in">
        <BrandMark size={84} />
        <h1 className="mt-6 text-3xl font-semibold tracking-tight text-fg">SentinelAI</h1>
        <p className="mt-2 text-sm text-fg-muted">Watching your network and your computer, so you don't have to.</p>
        <div className="mt-8 w-48 h-1 rounded-[2px] bg-white/8 overflow-hidden">
          <div
            className="h-full w-1/2 rounded-[2px] bg-gradient-to-r from-accent-strong to-mint"
            style={{ animation: 'splash-bar 1.2s ease-in-out infinite' }}
          />
        </div>
      </div>
      <style>{`@keyframes splash-bar { 0% { transform: translateX(-100%); } 100% { transform: translateX(200%); } }`}</style>
    </div>
  );
}
