import { useEffect, useRef, useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { translateThreat, translateSeverity, isBenign } from '../lib/translate';
import { desktop, navigateTo } from '../lib/desktop';
import { playAlertSound } from '../lib/sound';
import { API_BASE, getApiToken } from '../api/client';

export type ConnectionState = 'connected' | 'reconnecting' | 'offline';

export interface LiveNotification {
  id: string;
  incidentId?: string;
  source: 'network' | 'computer';
  title: string;
  story: string;
  severity: string;
  time: number;
  isNew: boolean;
}

interface LiveStreamOptions {
  onThreatAlert?: (data: any) => void;
  onNewIncident?: (data: any) => void;
  onNewHostIncident?: (data: any) => void;
}

const LIVE_QUERY_KEYS = ['metrics', 'incidents', 'host-incidents', 'blocks'];

export function alertLink(n: Pick<LiveNotification, 'source' | 'incidentId'>): string {
  return n.incidentId ? `/activity/${n.source}/${n.incidentId}` : '/activity';
}

function defaultWsUrl(): string {
  return API_BASE.replace(/^http/, 'ws').replace(/\/$/, '') + '/ws/live-stream';
}

export function useLiveStream(options: LiveStreamOptions = {}) {
  const wsUrl = import.meta.env.VITE_WS_URL || defaultWsUrl();
  const useMocks = import.meta.env.VITE_USE_MOCKS === 'true';
  const queryClient = useQueryClient();
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const [state, setState] = useState<ConnectionState>(useMocks ? 'connected' : 'reconnecting');
  const [notifications, setNotifications] = useState<LiveNotification[]>([]);
  const unreadCount = notifications.filter((n) => n.isNew).length;

  useEffect(() => {
    document.title = unreadCount > 0 ? `(${unreadCount}) SentinelAI` : 'SentinelAI';
  }, [unreadCount]);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, isNew: false })));
  }, []);

  // One incident arrives as THREAT_ALERT + NEW_INCIDENT, and floods arrive in bursts: refetch once per burst.
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const refreshData = useCallback(() => {
    if (refreshTimer.current) return;
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = undefined;
      for (const key of LIVE_QUERY_KEYS) queryClient.invalidateQueries({ queryKey: [key] });
    }, 1000);
  }, [queryClient]);

  useEffect(() => () => clearTimeout(refreshTimer.current), []);

  const handleThreatAlert = useCallback((alert: any) => {
    refreshData();
    if (!alert || isBenign(alert.attack_type)) return;

    const threat = translateThreat(alert.attack_type);
    const severity = translateSeverity(alert.severity);
    const notification: LiveNotification = {
      id: alert.alert_id || String(Date.now()),
      incidentId: alert.incident_id || undefined,
      source: alert.source === 'HIDS' ? 'computer' : 'network',
      title: threat.friendlyName,
      story: threat.explanation,
      severity: severity.label,
      time: alert.timestamp || Date.now() / 1000,
      isNew: true,
    };

    setNotifications((prev) => [notification, ...prev].slice(0, 20));

    const sevRaw = String(alert.severity || '').toUpperCase();
    if (sevRaw === 'CRITICAL' || sevRaw === 'HIGH') {
      toast.error(threat.friendlyName, {
        description: threat.explanation,
        duration: sevRaw === 'CRITICAL' ? Infinity : 8000,
        action: { label: 'View', onClick: () => navigateTo(alertLink(notification)) },
      });
      if (localStorage.getItem('sentinel_sound') !== 'false') playAlertSound(sevRaw === 'CRITICAL');
      if (desktop && localStorage.getItem('sentinel_desktop_notify') !== 'false') {
        desktop.notify({
          title: threat.friendlyName,
          body: threat.explanation,
          route: alertLink(notification),
          urgent: sevRaw === 'CRITICAL',
        });
      }
    }
  }, [refreshData]);

  const handleMessageRef = useRef<(raw: string) => void>(() => {});
  handleMessageRef.current = (raw: string) => {
    let msg: any;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    switch (msg.event_type) {
      case 'THREAT_ALERT':
        handleThreatAlert(msg.data);
        optionsRef.current.onThreatAlert?.(msg.data);
        break;
      case 'NEW_INCIDENT':
        refreshData();
        optionsRef.current.onNewIncident?.(msg.data);
        break;
      case 'NEW_HOST_INCIDENT':
        refreshData();
        optionsRef.current.onNewHostIncident?.(msg.data);
        break;
    }
  };

  useEffect(() => {
    if (useMocks) return;

    let disposed = false;
    let ws: WebSocket | null = null;
    let pingTimer: ReturnType<typeof setInterval> | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const connect = async () => {
      // Browsers can't set headers on WebSockets, so the token travels as a query parameter.
      const token = await getApiToken(attempt > 0);
      if (disposed) return;
      ws = new WebSocket(token ? `${wsUrl}${wsUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}` : wsUrl);

      ws.onopen = () => {
        attempt = 0;
        setState('connected');
        refreshData();
        pingTimer = setInterval(() => {
          if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ action: 'PING' }));
        }, 25000);
      };
      ws.onmessage = (event) => handleMessageRef.current(event.data);
      ws.onerror = () => ws?.close();
      ws.onclose = () => {
        clearInterval(pingTimer);
        if (disposed) return;
        setState(attempt >= 3 ? 'offline' : 'reconnecting');
        const delay = Math.min(1000 * 2 ** attempt, 15000);
        attempt++;
        reconnectTimer = setTimeout(() => void connect(), delay);
      };
    };

    void connect();
    return () => {
      disposed = true;
      clearInterval(pingTimer);
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [wsUrl, useMocks, refreshData]);

  // Mock mode: emit a fake alert every 15 seconds so the bell and toasts can be previewed.
  useEffect(() => {
    if (!useMocks) return;
    const mockTypes = ['DDoS', 'SSH-Bruteforce', 'PortScan', 'Stealer', 'Botnet'];
    const mockSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const interval = setInterval(() => {
      const type = mockTypes[Math.floor(Math.random() * mockTypes.length)];
      handleThreatAlert({
        alert_id: `MOCK-${Date.now()}`,
        timestamp: Date.now() / 1000,
        severity: mockSeverities[Math.floor(Math.random() * mockSeverities.length)],
        attack_type: type,
        source: type === 'Stealer' ? 'HIDS' : 'NIDS',
      });
    }, 15000);
    return () => clearInterval(interval);
  }, [useMocks, handleThreatAlert]);

  // Polling fallback while the live connection is down.
  useEffect(() => {
    if (state === 'connected') return;
    const interval = setInterval(() => {
      if (!document.hidden) refreshData();
    }, 5000);
    return () => clearInterval(interval);
  }, [state, refreshData]);

  return { state, unreadCount, notifications, markAllRead };
}
