import { NavLink } from 'react-router-dom';
import { PanelLeftClose, PanelLeftOpen, ShieldCheck, ShieldAlert, ShieldOff } from 'lucide-react';
import { BrandMark } from '../components/BrandMark';
import { NAV_GROUPS, FOOTER_NAV, type NavItem } from './nav';
import type { OverallStatus } from '../hooks/useOverallStatus';

interface SidebarProps {
  expertMode: boolean;
  collapsed: boolean;
  onToggle: () => void;
  status: OverallStatus;
}

const STATUS_CARD: Record<OverallStatus, { label: string; hint: string; color: string; icon: typeof ShieldCheck }> = {
  protected: { label: 'Protected', hint: 'Everything looks normal', color: '#34d399', icon: ShieldCheck },
  handled: { label: 'Protected', hint: 'Threats were stopped today', color: '#a78bfa', icon: ShieldCheck },
  action_needed: { label: 'Needs attention', hint: 'Open Home to see why', color: '#fb923c', icon: ShieldAlert },
  offline: { label: 'Not running', hint: 'Protection engine is off', color: '#a3a2b6', icon: ShieldOff },
};

function NavRow({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  return (
    <NavLink
      to={item.to}
      end={item.to === '/'}
      className={({ isActive }) =>
        `group relative flex items-center h-10 rounded-[10px] transition-colors duration-150 ${
          collapsed ? 'justify-center px-0' : 'px-3 gap-3'
        } ${
          isActive
            ? 'bg-gradient-to-r from-accent/20 to-accent/5 text-fg ring-1 ring-inset ring-accent/25'
            : 'text-fg-muted hover:text-fg hover:bg-white/5'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && <span className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r bg-accent" />}
          <item.icon size={18} strokeWidth={isActive ? 2.2 : 1.9} className={isActive ? 'text-accent-soft' : ''} />
          {!collapsed && <span className="text-[13.5px] font-medium truncate">{item.label}</span>}
          {collapsed && (
            <span className="pointer-events-none absolute left-full ml-3 px-2.5 py-1.5 glass-strong text-xs font-medium text-fg whitespace-nowrap opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all z-50">
              {item.label}
            </span>
          )}
        </>
      )}
    </NavLink>
  );
}

export function Sidebar({ expertMode, collapsed, onToggle, status }: SidebarProps) {
  const card = STATUS_CARD[status];
  const StatusIcon = card.icon;
  const footer = FOOTER_NAV.filter((i) => !i.expertOnly || expertMode);

  return (
    <aside
      className={`glass relative z-40 shrink-0 flex flex-col my-3 ml-3 transition-[width] duration-300 ease-[cubic-bezier(0.2,0.7,0.2,1)] ${
        collapsed ? 'w-[72px]' : 'w-[244px]'
      }`}
    >
      <div className={`flex items-center h-16 ${collapsed ? 'justify-center' : 'px-4 gap-3'}`}>
        <BrandMark size={32} />
        {!collapsed && (
          <div className="min-w-0">
            <div className="text-[15px] font-semibold text-fg leading-tight">SentinelAI</div>
            <div className="text-[11px] text-fg-subtle">Your security assistant</div>
          </div>
        )}
      </div>

      <nav className={`flex-1 px-3 pb-2 ${collapsed ? 'overflow-visible' : 'overflow-y-auto'}`}>
        {NAV_GROUPS.map((group, gi) => (
          <div key={group.label} className={gi > 0 ? 'mt-4' : 'mt-1'}>
            {collapsed ? (
              gi > 0 && <div className="mx-2 mb-3 border-t border-line" />
            ) : (
              <div className="px-3 mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-fg-subtle">{group.label}</div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => (
                <NavRow key={item.to} item={item} collapsed={collapsed} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-3 pb-3 space-y-0.5">
        {!collapsed && (
          <div className="glass-inset p-3 mb-3 flex items-center gap-3">
            <div
              className="w-9 h-9 shrink-0 rounded-[10px] flex items-center justify-center"
              style={{ background: `${card.color}1f`, border: `1px solid ${card.color}44` }}
            >
              <StatusIcon size={18} style={{ color: card.color }} />
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-semibold text-fg">{card.label}</div>
              <div className="text-[11px] text-fg-subtle truncate">{card.hint}</div>
            </div>
          </div>
        )}
        {collapsed && (
          <div className="flex justify-center mb-3" title={`${card.label}: ${card.hint}`}>
            <div
              className="w-10 h-10 rounded-[10px] flex items-center justify-center"
              style={{ background: `${card.color}1f`, border: `1px solid ${card.color}44` }}
            >
              <StatusIcon size={18} style={{ color: card.color }} />
            </div>
          </div>
        )}

        {footer.map((item) => (
          <NavRow key={item.to} item={item} collapsed={collapsed} />
        ))}

        <button
          onClick={onToggle}
          className={`w-full flex items-center h-10 rounded-[10px] text-fg-subtle hover:text-fg hover:bg-white/5 transition-colors ${
            collapsed ? 'justify-center' : 'px-3 gap-3'
          }`}
          title={collapsed ? 'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          {!collapsed && <span className="text-[13px] font-medium">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
