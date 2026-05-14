import { useState } from 'react'
import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'

/**
 * SheetAction — row primitive for inside bottom sheets (item-details actions,
 * add-sheet actions, share-sheet actions).
 *
 * Structure ported from the design prototype: icon-circle (32×32) + label
 * (14px / 500) + optional sub-text (12px tertiary). Three semantic variants:
 *
 *   - `default` — neutral. Icon tile uses `surface-sunken`.
 *   - `primary` — affirmative action (e.g. "Upload files", "Open"). Icon tile
 *                 uses `primary-faint`, label + icon tint to primary.
 *   - `danger`  — destructive (e.g. "Move to Trash"). Icon tile uses
 *                 `destructive-faint`, label + icon tint to destructive.
 */
interface SheetActionProps {
  icon: IconName
  label: string
  sub?: string
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger'
  /** Hide the bottom border (set on the final row in a group). */
  last?: boolean
}

export function SheetAction({
  icon,
  label,
  sub,
  onClick,
  variant = 'default',
  last,
}: SheetActionProps) {
  const [pressed, setPressed] = useState(false)

  const danger = variant === 'danger'
  const primary = variant === 'primary'

  return (
    <button
      type="button"
      onClick={onClick}
      onTouchStart={() => setPressed(true)}
      onTouchEnd={() => setPressed(false)}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      className={cn(
        'w-full flex items-center gap-3.5 px-4 py-3.5 border-0 text-left transition-colors cursor-pointer',
        pressed ? 'bg-surface-raised' : 'bg-transparent',
        danger ? 'text-destructive' : primary ? 'text-primary' : 'text-text-primary',
        last ? 'border-b-0' : 'border-b border-border-light',
      )}
    >
      <div
        className={cn(
          'w-8 h-8 rounded-2xl flex items-center justify-center shrink-0',
          danger
            ? 'bg-destructive-faint text-destructive'
            : primary
              ? 'bg-primary-faint text-primary'
              : 'bg-surface-sunken text-text-secondary',
        )}
        aria-hidden="true"
      >
        <Icon d={ICONS[icon]} size={16} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium">{label}</div>
        {sub && (
          <div className="text-[12px] text-text-tertiary mt-0.5">{sub}</div>
        )}
      </div>
    </button>
  )
}
