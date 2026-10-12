import { useContext, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck, Clock, Ban, FlaskConical, Unlock, Globe } from 'lucide-react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { toast } from 'sonner';

import { ExpertContext } from '../App';
import { Skeleton, ErrorState, ConfirmModal, EmptyState, IconTile, KpiCard } from '../components/index';
import { getBlocks, unblockIP } from '../api/endpoints';
import type { BlocksResponse, BlockedIP } from '../api/endpoints';
import { translateThreat, maskIP, isPrivateIP } from '../lib/translate';

dayjs.extend(relativeTime);

const STATUS: Record<string, { label: string; tag: string }> = {
  ACTIVE: { label: 'Blocked', tag: 'tag-safe' },
  SIMULATED: { label: 'Test mode', tag: 'tag-accent' },
  RELEASED: { label: 'Unblocked', tag: 'tag-neutral' },
  FAILED: { label: "Couldn't block", tag: 'tag-danger' },
};

export default function Blocked() {
  const { expert } = useContext(ExpertContext);
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<BlockedIP | null>(null);

  const { data, isLoading, error, refetch } = useQuery({ queryKey: ['blocks'], queryFn: getBlocks, refetchInterval: 15000 });

  const unblockMutation = useMutation({
    mutationFn: unblockIP,
    onMutate: async (ruleId: string) => {
      await queryClient.cancelQueries({ queryKey: ['blocks'] });
      const previousBlocks = queryClient.getQueryData<BlocksResponse>(['blocks']);
      queryClient.setQueryData<BlocksResponse>(['blocks'], (old) =>
        old && { ...old, blocked_ips: old.blocked_ips.map((b) => (b.rule_id === ruleId ? { ...b, status: 'RELEASED' } : b)) }
      );
      return { previousBlocks };
    },
    onError: (_err, _ruleId, context) => {
      queryClient.setQueryData(['blocks'], context?.previousBlocks);
      toast.error('Failed to unblock address');
    },
    onSuccess: () => {
      toast.success('Address unblocked');
      queryClient.invalidateQueries({ queryKey: ['blocks'] });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="grid grid-cols-3 gap-5">
          <Skeleton className="h-[148px]" />
          <Skeleton className="h-[148px]" />
          <Skeleton className="h-[148px]" />
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }
  if (error) return <ErrorState message="We couldn't load blocked addresses." onRetry={() => refetch()} />;

  const blocks = data?.blocked_ips ?? [];
  const active = blocks.filter((b) => b.status === 'ACTIVE').length;
  const simulated = blocks.filter((b) => b.status === 'SIMULATED').length;
  const released = blocks.filter((b) => b.status === 'RELEASED').length;

  const label = (ip: string) => (expert ? ip : `${isPrivateIP(ip) ? 'Device on your network' : 'Outside computer'} ${maskIP(ip)}`);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-5">
        <KpiCard tone="sun" icon={<Ban size={18} />} title="Blocked right now" value={active} helperText="Addresses your firewall is actively keeping out." />
        <KpiCard tone="accent" icon={<FlaskConical size={18} />} title="Would block (test mode)" value={simulated} helperText="In safe test mode SentinelAI shows what it would block without touching your firewall." />
        <KpiCard tone="mint" icon={<Unlock size={18} />} title="Unblocked" value={released} helperText="Addresses whose block has ended or that you allowed back in." />
      </div>

      {blocks.length === 0 ? (
        <div className="glass p-5">
          <EmptyState icon={<ShieldCheck size={24} />} title="No one is blocked right now" description="That's a good thing. SentinelAI will block anyone who tries to attack your computer." />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-4">
          {blocks.map((block) => {
            const threat = translateThreat(block.reason || 'Unknown');
            const status = STATUS[block.status?.toUpperCase()] ?? { label: block.status, tag: 'tag-neutral' };
            const expiry = block.expiry_timestamp ? dayjs.unix(block.expiry_timestamp) : null;
            let timer = 'Until you unblock it';
            if (expiry) {
              const mins = Math.max(expiry.diff(dayjs(), 'minute'), 0);
              timer = mins >= 60 ? `${Math.floor(mins / 60)}h ${mins % 60}m left` : `${mins}m left`;
            }
            const canUnblock = block.status === 'ACTIVE' || block.status === 'SIMULATED';

            return (
              <div key={block.rule_id || block.ip_address} className="glass glass-hover p-5 flex flex-col animate-fade-up">
                <div className="flex items-start gap-3">
                  <IconTile tone={canUnblock ? 'sun' : 'neutral'}>
                    <Globe size={18} />
                  </IconTile>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-semibold text-fg font-mono truncate">{label(block.ip_address)}</div>
                    <div className="text-[13px] text-fg-muted mt-0.5">{threat.friendlyName}</div>
                  </div>
                  <span className={`tag ${status.tag}`}>{status.label}</span>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                  <div className="glass-inset px-3 py-2">
                    <div className="text-fg-subtle">Blocked</div>
                    <div className="text-fg mt-0.5">{dayjs.unix(block.block_timestamp).fromNow()}</div>
                  </div>
                  <div className="glass-inset px-3 py-2">
                    <div className="text-fg-subtle flex items-center gap-1"><Clock size={11} /> How long</div>
                    <div className="text-fg mt-0.5">{canUnblock ? timer : 'Ended'}</div>
                  </div>
                </div>

                {expert && block.command_executed && (
                  <div className="mt-3 text-[11px] font-mono text-fg-subtle truncate" title={block.command_executed}>
                    {block.command_executed}
                  </div>
                )}

                {canUnblock && (
                  <button onClick={() => setSelected(block)} className="btn btn-secondary btn-sm mt-4 w-full">
                    <Unlock size={14} /> Unblock
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {selected && (
        <ConfirmModal
          isOpen
          title={`Unblock ${label(selected.ip_address)}?`}
          message={`This address was blocked for: ${translateThreat(selected.reason || 'Unknown').friendlyName.toLowerCase()}. Once unblocked, it will be able to reach your computer again.`}
          cancelLabel="Keep blocked"
          confirmLabel="Unblock anyway"
          variant="danger"
          onConfirm={() => unblockMutation.mutate(selected.rule_id)}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
