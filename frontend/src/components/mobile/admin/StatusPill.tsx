import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

/**
 * Status pill — Active / Disabled. Kutup has no `pending` state (only
 * `isActive` boolean), so the design's three-state pill collapses to two
 * here. Color tokens come from the design's `success-faint` / `success`
 * and `destructive-faint` / `destructive` pairs.
 */
interface StatusPillProps {
  /** `isActive` from `UserRow`. */
  active: boolean
  className?: string
}

export function StatusPill({ active, className }: StatusPillProps) {
  const { t } = useTranslation()
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-[10px]',
        'text-[10.5px] font-semibold leading-[1.4]',
        active
          ? 'bg-success-faint text-success'
          : 'bg-destructive-faint text-destructive',
        className,
      )}
    >
      <span
        className={cn(
          'w-[5px] h-[5px] rounded-full opacity-90',
          active ? 'bg-success' : 'bg-destructive',
        )}
      />
      {active
        ? t('mobile.admin.status.active', 'Active')
        : t('mobile.admin.status.disabled', 'Disabled')}
    </span>
  )
}
