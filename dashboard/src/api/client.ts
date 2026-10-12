import { desktop } from '../lib/desktop';

export const API_BASE: string = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000';
const BASE = API_BASE;
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true';
export const TOKEN_HEADER = 'X-SentinelAI-Token';
const ENV_TOKEN: string = import.meta.env.VITE_API_TOKEN || '';

// Desktop: Electron's main process reads the per-install token file. Web dev: VITE_API_TOKEN.
let tokenPromise: Promise<string> | null = null;

export function getApiToken(refresh = false): Promise<string> {
  if (!desktop?.apiToken) return Promise.resolve(ENV_TOKEN);
  if (refresh || !tokenPromise) {
    tokenPromise = desktop.apiToken().then((t) => t || ENV_TOKEN).catch(() => ENV_TOKEN);
  }
  return tokenPromise;
}

/** Synchronous variant for links opened outside fetch (web mode only; Electron adds the token itself). */
export function withEnvToken(url: string): string {
  if (!ENV_TOKEN || desktop) return url;
  return `${url}${url.includes('?') ? '&' : '?'}token=${encodeURIComponent(ENV_TOKEN)}`;
}

async function authorizedFetch(url: string, options: RequestInit | undefined, refresh: boolean): Promise<Response> {
  const token = await getApiToken(refresh);
  const headers = new Headers(options?.headers);
  if (token) headers.set(TOKEN_HEADER, token);
  return fetch(url, { ...options, headers });
}
const mockModules = import.meta.glob('./mocks/*.json', {
  eager: true,
  import: 'default',
}) as Record<string, unknown>;

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  if (USE_MOCKS) {
    console.log(`[Mock Fetch] ${options?.method || 'GET'} ${path}`);
    
    // For POST/PUT requests in mock mode, return fake success
    if (options?.method && options.method !== 'GET') {
      return { success: true, message: 'Mock POST successful' } as unknown as T;
    }
    
    if (path === '/') return { status: 'ONLINE' } as unknown as T;
    
    const url = new URL(path, 'http://localhost');
    const pathname = url.pathname;
    
    let mockFileName = '';
    
    if (pathname === '/api/metrics') mockFileName = 'metrics.json';
    else if (pathname === '/api/host/incidents') mockFileName = 'host_incidents.json';
    else if (pathname.startsWith('/api/incidents/')) {
        const parts = pathname.split('/');
        const id = parts[3];
        if (id === 'INC-001') mockFileName = 'incident_detail_1.json';
        else mockFileName = 'incident_detail_2.json';
    }
    else if (pathname === '/api/incidents') mockFileName = 'incidents.json';
    else if (pathname === '/api/blocks') mockFileName = 'blocks.json';
    else if (pathname === '/api/status') mockFileName = 'status.json';
    else {
      throw new Error(`No mock mapped for path: ${path}`);
    }

    try {
      const mockModule = mockModules[`./mocks/${mockFileName}`];
      if (mockModule === undefined) {
        throw new Error(`Mock module not found for ${mockFileName}`);
      }
      return mockModule as T;
    } catch (err) {
      console.error(`Failed to load mock file ${mockFileName}:`, err);
      throw new Error(`Failed to load mock file ${mockFileName}`);
    }
  }

  const url = `${BASE}${path}`;
  let response = await authorizedFetch(url, options, false);
  // The engine creates the token on first start, which can be after the window loaded.
  if (response.status === 401) response = await authorizedFetch(url, options, true);

  if (!response.ok) {
    throw new Error(`API Error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}
