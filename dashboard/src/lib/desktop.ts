export type EngineStatus = 'starting' | 'running' | 'external' | 'stopped' | 'failed';

export interface EngineState {
  status: EngineStatus;
  message: string;
  logPath?: string;
}

export interface DesktopSettings {
  closeToTray: boolean;
  launchAtLogin: boolean;
}

export interface AppInfo {
  version: string;
  platform: string;
  apiBase: string;
  elevated?: boolean;
}

export interface SentinelBridge {
  isDesktop: true;
  minimize(): void;
  toggleMaximize(): void;
  close(): void;
  isMaximized(): Promise<boolean>;
  onMaximizedChange(cb: (maximized: boolean) => void): () => void;
  appInfo(): Promise<AppInfo>;
  relaunchAsAdmin(): Promise<{ ok: boolean }>;
  notify(payload: { title: string; body: string; route?: string; urgent?: boolean }): void;
  onNavigate(cb: (route: string) => void): () => void;
  download(url: string): void;
  openExternal(url: string): void;
  engineState(): Promise<EngineState>;
  onEngineState(cb: (state: EngineState) => void): () => void;
  restartEngine(): Promise<EngineState>;
  getSettings(): Promise<DesktopSettings>;
  setSettings(patch: Partial<DesktopSettings>): Promise<DesktopSettings>;
  apiToken?(): Promise<string>;
}

declare global {
  interface Window {
    sentinel?: SentinelBridge;
  }
}

export const desktop: SentinelBridge | undefined = typeof window !== 'undefined' ? window.sentinel : undefined;
export const isDesktop = !!desktop;

export function navigateTo(route: string) {
  window.location.hash = route.startsWith('#') ? route : `#${route}`;
}

export function openDownload(url: string) {
  if (desktop) desktop.download(url);
  else window.open(url, '_blank');
}

export function openExternal(url: string) {
  if (desktop) desktop.openExternal(url);
  else window.open(url, '_blank', 'noopener');
}
