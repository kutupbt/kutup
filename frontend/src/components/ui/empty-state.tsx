import type { ReactNode } from 'react'
import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'

/**
 * EmptyState — illustration tile + title + subtitle + optional action button.
 * Used by Trash (empty trash hero), Shared ("Nothing shared yet"), and search
 * empty results.
 *
 * Pattern ported from the design prototype: a 56–64px rounded tile holds the
 * icon, then a 14–15px bold title, then a 12px tertiary subtitle, then an
 * optional CTA button.
 */
interface EmptyStateProps {
  icon: IconName
  title: string
  subtitle?: string
  /** Optional CTA. Renders as a primary-filled pill below the subtitle. */
  actionLabel?: string
  onAction?: () => void
  /** "primary" (default) vs "muted" tint for the icon tile. */
  tint?: 'primary' | 'muted'
  className?: string
  children?: ReactNode
}

export function EmptyState({
  icon,
  title,
  subtitle,
  actionLabel,
  onAction,
  tint = 'primary',
  className,
  children,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center text-center py-12 px-6',
        className,
      )}
      role="status"
    >
      <div
        className={cn(
          'w-16 h-16 rounded-[18px] inline-flex items-center justify-center mb-3',
          tint === 'primary'
            ? 'bg-primary-faint text-primary'
            : 'bg-surface-sunken text-text-tertiary',
        )}
        aria-hidden="true"
      >
        <Icon d={ICONS[icon]} size={26} />
      </div>
      <div className="text-[15px] font-semibold text-text-primary">{title}</div>
      {subtitle && (
        <div className="text-[12px] text-text-tertiary mt-1 max-w-xs">
          {subtitle}
        </div>
      )}
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-4 px-4 py-2 rounded-full bg-primary text-primary-foreground text-[13px] font-medium cursor-pointer hover:bg-primary-pressed transition-colors"
        >
          {actionLabel}
        </button>
      )}
      {children}
    </div>
  )
}
