import { useContext, useEffect, useState, type ReactNode } from 'react';
import { ExpertContext } from '../App';
import { Bell, Volume2, Eye, MonitorDown, Power, Info, PanelsTopLeft } from 'lucide-react';
import { Panel, Toggle, IconTile, Segmented } from '../components/ui';
import { desktop, isDesktop, type AppInfo, type DesktopSettings, type EngineState } from '../lib/desktop';
import { playAlertSound } from '../lib/sound';
import { API_BASE } from '../api/client';

function Row({ icon, tone, title, description, control }: { icon: ReactNode; tone: 'accent' | 'mint' | 'sun' | 'rose' | 'info'; title: string; description: string; control: ReactNode }) {
  return (
    <div className="flex items-center gap-4 py-4 first:pt-0 last:pb-0">
      <IconTile tone={tone} size="sm">{icon}</IconTile>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-fg">{title}</div>
        <div className="text-[13px] text-fg-muted mt-0.5">{description}</div>
      </div>
      <div className="shrink-0">{control}</div>
    </div>
  );
}

const ENGINE_LABEL: Record<string, string> = {
  starting: 'Starting',
  running: 'Running (started by SentinelAI)',
  external: 'Running',
  stopped: 'Stopped',
  failed: 'Stopped with a problem',
};

export function Settings() {
  const { expert, setExpert } = useContext(ExpertContext);
  const [sound, setSound] = useState(() => localStorage.getItem('sentinel_sound') !== 'false');
  const [notify, setNotify] = useState(() => localStorage.getItem('sentinel_desktop_notify') !== 'false');
  const [desk, setDesk] = useState<DesktopSettings | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [engine, setEngine] = useState<EngineState | null>(null);

  useEffect(() => {
    if (!desktop) return;
    desktop.getSettings().then(setDesk);
    desktop.appInfo().then(setInfo);
    desktop.engineState().then(setEngine);
    return desktop.onEngineState(setEngine);
  }, []);

  const updateSound = (v: boolean) => {
    setSound(v);
    localStorage.setItem('sentinel_sound', String(v));
    if (v) playAlertSound(false);
  };

  const updateNotify = async (v: boolean) => {
    if (v && !isDesktop && 'Notification' in window && Notification.permission !== 'granted') {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return;
    }
    setNotify(v);
    localStorage.setItem('sentinel_desktop_notify', String(v));
  };

  const updateDesk = async (patch: Partial<DesktopSettings>) => {
    if (!desktop) return;
    setDesk(await desktop.setSettings(patch));
  };

  return (
    <div className="grid grid-cols-12 gap-5">
      <div className="col-span-12 xl:col-span-7 space-y-5">
        <Panel title="How SentinelAI looks">
          <div className="divide-y divide-line">
            <Row
              icon={<Eye size={16} />}
              tone="accent"
              title="View"
              description="Simple uses plain English. Expert adds IP addresses, model confidence, raw data and the demo panel."
              control={
                <Segmented
                  ariaLabel="View"
                  value={expert ? 'expert' : 'simple'}
                  onChange={(v) => setExpert(v === 'expert')}
                  options={[
                    { value: 'simple', label: 'Simple' },
                    { value: 'expert', label: 'Expert' },
                  ]}
                />
              }
            />
            <Row
              icon={<PanelsTopLeft size={16} />}
              tone="info"
              title="Sidebar"
              description="Press Ctrl + B at any time to collapse or expand the sidebar."
              control={<kbd className="tag tag-neutral font-mono">Ctrl + B</kbd>}
            />
          </div>
        </Panel>

        <Panel title="Alerts">
          <div className="divide-y divide-line">
            <Row
              icon={<Bell size={16} />}
              tone="sun"
              title="Pop-up notifications"
              description="Show a Windows notification for serious threats, even when SentinelAI is minimised."
              control={<Toggle label="Pop-up notifications" checked={notify} onChange={updateNotify} />}
            />
            <Row
              icon={<Volume2 size={16} />}
              tone="rose"
              title="Alert sound"
              description="Play a short sound when a serious threat is found."
              control={<Toggle label="Alert sound" checked={sound} onChange={updateSound} />}
            />
          </div>
        </Panel>

        {isDesktop && desk && (
          <Panel title="Desktop app">
            <div className="divide-y divide-line">
              <Row
                icon={<MonitorDown size={16} />}
                tone="mint"
                title="Keep protecting when I close the window"
                description="SentinelAI keeps running in the system tray (next to the clock). Right-click the tray icon to quit completely."
                control={<Toggle label="Keep running in tray" checked={desk.closeToTray} onChange={(v) => updateDesk({ closeToTray: v })} />}
              />
              <Row
                icon={<Power size={16} />}
                tone="accent"
                title="Start with Windows"
                description="Start SentinelAI quietly in the tray when you sign in, so you're always protected."
                control={<Toggle label="Start with Windows" checked={desk.launchAtLogin} onChange={(v) => updateDesk({ launchAtLogin: v })} />}
              />
            </div>
          </Panel>
        )}
      </div>

      <div className="col-span-12 xl:col-span-5">
        <Panel title="About" className="h-full">
          <div className="flex items-center gap-3 mb-5">
            <IconTile tone="accent"><Info size={18} /></IconTile>
            <div>
              <div className="text-sm font-semibold text-fg">SentinelAI</div>
              <div className="text-xs text-fg-muted">AI-powered network and computer protection</div>
            </div>
          </div>
          <dl className="space-y-3 text-[13px]">
            <div className="flex justify-between gap-4">
              <dt className="text-fg-subtle">Version</dt>
              <dd className="text-fg">{info?.version ?? 'Web preview'}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-fg-subtle">App type</dt>
              <dd className="text-fg">{isDesktop ? 'Desktop app' : 'Browser preview'}</dd>
            </div>
            {engine && (
              <div className="flex justify-between gap-4">
                <dt className="text-fg-subtle">Protection engine</dt>
                <dd className="text-fg text-right">{ENGINE_LABEL[engine.status] ?? engine.status}</dd>
              </div>
            )}
            {expert && (
              <div className="flex justify-between gap-4">
                <dt className="text-fg-subtle">Engine address</dt>
                <dd className="text-fg font-mono">{info?.apiBase ?? API_BASE}</dd>
              </div>
            )}
            {expert && engine?.logPath && (
              <div className="flex justify-between gap-4">
                <dt className="text-fg-subtle shrink-0">Engine log</dt>
                <dd className="text-fg font-mono text-right break-all">{engine.logPath}</dd>
              </div>
            )}
          </dl>
          <p className="mt-6 text-xs text-fg-subtle leading-relaxed">
            Everything runs on this computer. Your network traffic and files are never uploaded anywhere.
          </p>
        </Panel>
      </div>
    </div>
  );
}
