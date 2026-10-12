import {
  LayoutDashboard,
  Activity,
  ShieldBan,
  MonitorSmartphone,
  FileText,
  HeartPulse,
  BookOpen,
  Settings,
  FlaskConical,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  expertOnly?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Overview',
    items: [
      { label: 'Home', to: '/', icon: LayoutDashboard },
      { label: 'Activity', to: '/activity', icon: Activity },
    ],
  },
  {
    label: 'Protection',
    items: [
      { label: 'Blocked connections', to: '/blocked', icon: ShieldBan },
      { label: 'Computer protection', to: '/computer', icon: MonitorSmartphone },
    ],
  },
  {
    label: 'Insights',
    items: [
      { label: 'Reports', to: '/reports', icon: FileText },
      { label: 'System health', to: '/health', icon: HeartPulse },
      { label: 'Learn', to: '/learn', icon: BookOpen },
    ],
  },
];

export const FOOTER_NAV: NavItem[] = [
  { label: 'Demo panel', to: '/demo', icon: FlaskConical, expertOnly: true },
  { label: 'Settings', to: '/settings', icon: Settings },
];

interface PageMeta {
  title: string;
  description: string;
}

const PAGE_META: Record<string, PageMeta> = {
  '/': { title: 'Home', description: 'Your protection at a glance' },
  '/activity': { title: 'Activity', description: 'Everything SentinelAI noticed, newest first' },
  '/blocked': { title: 'Blocked connections', description: 'Outside addresses SentinelAI is keeping away from your computer' },
  '/computer': { title: 'Computer protection', description: 'Guarding your saved passwords, login sessions and crypto wallets' },
  '/reports': { title: 'Reports', description: 'Create a PDF summary to keep or share with IT support' },
  '/health': { title: 'System health', description: 'Check that every part of SentinelAI is working' },
  '/learn': { title: 'Learn', description: 'Simple explanations of the threats we protect you from' },
  '/settings': { title: 'Settings', description: 'Make SentinelAI work the way you like' },
  '/demo': { title: 'Demo panel', description: 'Send safe practice attacks and watch SentinelAI respond' },
};

export function pageMeta(pathname: string): PageMeta {
  if (pathname.startsWith('/activity/')) return { title: 'Alert details', description: 'What happened, how serious it is, and what we did about it' };
  return PAGE_META[pathname] ?? PAGE_META['/'];
}
