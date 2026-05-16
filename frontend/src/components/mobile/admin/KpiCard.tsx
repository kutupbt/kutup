import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'

/**
 * KPI card — one cell of the 2×2 grid on the admin Overview tab.
 *
 * Header row: icon tile (filled with `primary-faint` if `accent`) on the
 * left, optional delta badge on the right. Body: large value + small label.
 *
 * Delta badge is intentionally optional. Kutup's `/admin/stats` endpoint
 * doesn't return historical deltas yet, so PR 12 renders the cards without
 * deltas; the prop is kept for the future when an endpoint exists.
 */
interface KpiCardProps {
  icon: IconName
  label: string
  value: string | number
  /** Free-text delta string, e.g. "+2 this week". Omit to hide the badge. */
  delta?: string
  /** True → green up-arrow badge, false → red down-arrow. Default true. */
  deltaUp?: boolean
  /** Tint the icon tile with the primary color (vs neutral surface-sunken). */
  accent?: boolean
}

export function KpiCard({
  icon,
  label,
  value,
  delta,
  deltaUp = true,
  accent,
}: KpiCardProps) {
  return (
    <div className="bg-surface border border-border-light rounded-[var(--radius-lg)] p-3 flex flex-col gap-2.5">
      <div className="flex items-center justify-between">
        <div
          className={cn(
            'w-7 h-7 rounded-lg flex items-center justify-center',
            accent
              ? 'bg-primary-faint text-primary'
              : 'bg-surface-sunken text-text-secondary',
          )}
          aria-hidden="true"
        >
          <Icon d={ICONS[icon]} size={14} />
        </div>
        {delta != null && (
          <div
            className={cn(
              'flex items-center gap-0.5 text-[10.5px] font-semibold px-1.5 py-0.5 rounded-lg',
              deltaUp
                ? 'bg-success-faint text-success'
                : 'bg-destructive-faint text-destructive',
            )}
          >
            <Icon d={ICONS[deltaUp ? 'plus' : 'plus']} size={9} />
            {delta}
          </div>
        )}
      </div>
      <div>
        <div className="text-[22px] font-bold text-text-primary tracking-[-0.5px] leading-none">
          {value}
        </div>
        <div className="text-[11.5px] text-text-tertiary mt-1">{label}</div>
      </div>
    </div>
  )
}
