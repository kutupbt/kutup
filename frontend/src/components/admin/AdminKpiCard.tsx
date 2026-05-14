import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'

/**
 * AdminKpiCard — desktop-sized KPI card for the Admin Overview grid.
 *
 * Distinct from the mobile `KpiCard` (2×2 phone-grid sized): this one is
 * bigger across the board (34×34 icon tile, 28px value, more padding) so
 * a 5-up auto-fit grid reads correctly on a desktop display.
 *
 * Per the design, the icon tile gets a primary-faint tint when `accent` is
 * true (one card per page), and a neutral surface-sunken background
 * otherwise. The delta badge is intentionally optional — kutup's
 * `/admin/stats` endpoint doesn't return historical deltas today, so PR 13
 * renders without any of them. The prop is kept for the future when a
 * historical-stats endpoint lands.
 */
export interface AdminKpiCardProps {
  icon: IconName
  label: string
  /** Already-formatted display string (e.g. `"38.4 KB"` or `"1,247"`). */
  value: string | number
  /** Short hint shown after the label, e.g. "of 500 GB allocated". */
  hint?: string
  /** Free-text delta, e.g. "+2 this week". Omit to hide the badge entirely. */
  delta?: string
  /** True → green up-arrow badge, false → red down-arrow badge. Default true. */
  deltaUp?: boolean
  /** Tint the icon tile with the primary color (vs neutral surface-sunken). */
  accent?: boolean
}

export function AdminKpiCard({
  icon,
  label,
  value,
  hint,
  delta,
  deltaUp = true,
  accent,
}: AdminKpiCardProps) {
  return (
    <div className="bg-surface border border-border-light rounded-[var(--radius-lg)] p-4 flex flex-col gap-3.5 transition-colors">
      <div className="flex items-center justify-between">
        <div
          className={cn(
            'w-[34px] h-[34px] rounded-[10px] flex items-center justify-center',
            accent
              ? 'bg-primary-faint text-primary'
              : 'bg-surface-sunken text-text-secondary',
          )}
          aria-hidden="true"
        >
          <Icon d={ICONS[icon]} size={17} />
        </div>
        {delta != null && (
          <div
            className={cn(
              'flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-[10px]',
              deltaUp
                ? 'bg-success-faint text-success'
                : 'bg-destructive-faint text-destructive',
            )}
          >
            {/* No arrow icons available in our path map yet; "+" stands in for the up arrow,
                "−" (minus) approximates the down arrow. Keep this in sync with the mobile
                KpiCard if/when we add arrowUp/arrowDown to ICONS. */}
            <span aria-hidden="true">{deltaUp ? '↑' : '↓'}</span>
            {delta}
          </div>
        )}
      </div>
      <div>
        <div className="text-[28px] font-bold text-text-primary tracking-[-0.5px] leading-none">
          {value}
        </div>
        <div className="text-[12.5px] text-text-tertiary mt-1.5 flex items-center gap-1.5">
          <span>{label}</span>
          {hint && (
            <>
              <span aria-hidden="true">·</span>
              <span>{hint}</span>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
