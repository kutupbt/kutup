import { useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * PressableRow — list-row wrapper with tap-feedback (briefly tints the row
 * `surface-raised` when held). Use inside `<Surface>` containers. Set
 * `last` on the final row to suppress its bottom border.
 *
 * Matches the design prototype's `PressableRow` — touch + mouse handlers both
 * drive the pressed state so it works on phone + desktop.
 */
interface PressableRowProps {
  children: ReactNode
  onClick?: () => void
  last?: boolean
  className?: string
  /** Optional aria-label for screen readers when the row is interactive. */
  ariaLabel?: string
}

export function PressableRow({
  children,
  onClick,
  last,
  className,
  ariaLabel,
}: PressableRowProps) {
  const [pressed, setPressed] = useState(false)

  return (
    <div
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      aria-label={ariaLabel}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onClick()
              }
            }
          : undefined
      }
      onTouchStart={() => setPressed(true)}
      onTouchEnd={() => setPressed(false)}
      onTouchCancel={() => setPressed(false)}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      className={cn(
        'flex items-center gap-3 px-3.5 py-3 select-none transition-colors',
        'cursor-pointer',
        pressed ? 'bg-surface-raised' : 'bg-transparent',
        last ? 'border-b-0' : 'border-b border-border-light',
        className,
      )}
    >
      {children}
    </div>
  )
}
