import { useState, useRef, useEffect } from 'react';
import { Bell, CheckCheck, Globe, Monitor } from 'lucide-react';
import { Link } from 'react-router-dom';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { alertLink } from '../hooks/useLiveStream';
import type { LiveNotification } from '../hooks/useLiveStream';
import { IconTile } from './ui';

dayjs.extend(relativeTime);

export interface NotificationBellProps {
  unreadCount: number;
  notifications: LiveNotification[];
  onMarkAllRead: () => void;
}

export function NotificationBell({ unreadCount, notifications, onMarkAllRead }: NotificationBellProps) {
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) setIsOpen(false);
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`icon-btn relative ${isOpen ? 'bg-white/8 text-fg' : ''}`}
        aria-label={unreadCount > 0 ? `${unreadCount} new alerts` : 'Alerts'}
      >
        <Bell size={18} />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 min-w-4 h-4 px-1 rounded-[5px] bg-danger text-[10px] font-bold text-white flex items-center justify-center">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-[380px] glass-strong z-50 overflow-hidden animate-pop-in">
          <div className="px-4 py-3 border-b border-line flex justify-between items-center">
            <div>
              <h3 className="text-sm font-semibold text-fg">Alerts</h3>
              <p className="text-xs text-fg-subtle">New threats SentinelAI found while you were working</p>
            </div>
            {unreadCount > 0 && (
              <button onClick={onMarkAllRead} className="btn btn-ghost btn-sm">
                <CheckCheck size={14} /> Mark read
              </button>
            )}
          </div>

          <div className="max-h-[420px] overflow-y-auto p-2">
            {notifications.length === 0 ? (
              <div className="py-10 text-center">
                <Bell className="mx-auto mb-2 text-fg-subtle" size={28} />
                <p className="text-sm text-fg-muted">No new alerts</p>
                <p className="text-xs text-fg-subtle mt-0.5">We'll let you know the moment something happens.</p>
              </div>
            ) : (
              notifications.slice(0, 20).map((n) => (
                <Link
                  key={n.id}
                  to={alertLink(n)}
                  onClick={() => setIsOpen(false)}
                  className="flex gap-3 p-3 rounded-lg hover:bg-white/5 transition-colors"
                >
                  <IconTile tone={n.source === 'network' ? 'accent' : 'mint'} size="sm">
                    {n.source === 'network' ? <Globe size={15} /> : <Monitor size={15} />}
                  </IconTile>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className={`text-sm truncate ${n.isNew ? 'font-semibold text-fg' : 'font-medium text-fg-muted'}`}>{n.title}</p>
                      {n.isNew && <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />}
                    </div>
                    <p className="text-xs text-fg-muted mt-0.5 line-clamp-2">{n.story}</p>
                    <p className="text-[11px] text-fg-subtle mt-1">{dayjs.unix(n.time).fromNow()}</p>
                  </div>
                </Link>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
