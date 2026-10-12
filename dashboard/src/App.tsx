import React, { useCallback, useEffect, useRef, useState } from 'react';
import { HashRouter, Routes, Route, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';

import { Sidebar } from './layout/Sidebar';
import { TopBar } from './layout/TopBar';
import { TitleBar } from './layout/TitleBar';
import { EngineBanner } from './layout/EngineBanner';
import { useLiveStream } from './hooks/useLiveStream';
import { useOverallStatus } from './hooks/useOverallStatus';
import { desktop, navigateTo } from './lib/desktop';

import Home from './pages/Home';
import Activity from './pages/Activity';
import AlertDetail from './pages/AlertDetail';
import Blocked from './pages/Blocked';
import Computer from './pages/Computer';
import { Reports } from './pages/Reports';
import { Health } from './pages/Health';
import { Learn } from './pages/Learn';
import { Settings } from './pages/Settings';
import { Demo } from './pages/Demo';
import { SplashScreen } from './components/SplashScreen';

export const ExpertContext = React.createContext<{ expert: boolean; setExpert: (v: boolean) => void }>({
  expert: false,
  setExpert: () => {},
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
});

export default function App() {
  const [expertMode, setExpertMode] = useState(() => localStorage.getItem('sentinel_expert_mode') === 'true');
  const [showSplash, setShowSplash] = useState(true);
  const finishSplash = useCallback(() => setShowSplash(false), []);

  useEffect(() => {
    localStorage.setItem('sentinel_expert_mode', expertMode.toString());
  }, [expertMode]);

  return (
    <QueryClientProvider client={queryClient}>
      <ExpertContext.Provider value={{ expert: expertMode, setExpert: setExpertMode }}>
        <HashRouter>
          {showSplash && <SplashScreen onFinish={finishSplash} />}
          <AppShell expertMode={expertMode} setExpertMode={setExpertMode} />
        </HashRouter>
      </ExpertContext.Provider>
    </QueryClientProvider>
  );
}

function AppShell({ expertMode, setExpertMode }: { expertMode: boolean; setExpertMode: (value: boolean) => void }) {
  const { state: liveState, notifications, unreadCount, markAllRead } = useLiveStream();
  const { status } = useOverallStatus();
  const { pathname } = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sentinel_sidebar_collapsed') === 'true');

  const toggleSidebar = useCallback(() => {
    setCollapsed((c) => {
      localStorage.setItem('sentinel_sidebar_collapsed', String(!c));
      return !c;
    });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [toggleSidebar]);

  useEffect(() => desktop?.onNavigate(navigateTo), []);

  useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <>
      <div className="app-bg" />
      <div className="relative z-10 flex flex-col h-full">
        <TitleBar />
        <div className="flex flex-1 min-h-0">
          <Sidebar expertMode={expertMode} collapsed={collapsed} onToggle={toggleSidebar} status={status} />

          <div className="flex-1 min-w-0 flex flex-col">
            <TopBar
              expertMode={expertMode}
              setExpertMode={setExpertMode}
              liveState={liveState}
              unreadCount={unreadCount}
              notifications={notifications}
              onMarkAllRead={markAllRead}
            />
            <EngineBanner />
            <main ref={mainRef} className="flex-1 overflow-y-auto px-8 pb-8">
              <div className="max-w-[1440px] mx-auto">
                <Routes>
                  <Route path="/" element={<Home />} />
                  <Route path="/activity" element={<Activity />} />
                  <Route path="/activity/:source/:id" element={<AlertDetail />} />
                  <Route path="/blocked" element={<Blocked />} />
                  <Route path="/computer" element={<Computer />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/health" element={<Health />} />
                  <Route path="/learn" element={<Learn />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/demo" element={<Demo />} />
                  <Route path="*" element={<Home />} />
                </Routes>
              </div>
            </main>
          </div>
        </div>
      </div>
      <Toaster
        theme="dark"
        position="bottom-right"
        closeButton
        toastOptions={{
          style: {
            background: 'rgb(24 23 35 / 0.94)',
            border: '1px solid rgb(255 255 255 / 0.12)',
            borderRadius: 12,
            color: '#f2f1f7',
            backdropFilter: 'blur(20px)',
          },
        }}
      />
    </>
  );
}
