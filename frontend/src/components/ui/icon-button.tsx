import { useState } from 'react'
import { Icon, type IconName, ICONS } from '@/components/mobile/Icon'
import { cn } from '@/lib/utils'

/**
 * IconButton — round, tap-feedback icon button used in mobile page headers
 * (search, plus, back, etc.).
 *
 * `accent` lifts the icon color to the primary color (used for the `+` add
 * button in the Files page header). `size` controls the circle diameter; the
 * icon scales to either 18 or 20 depending on size.
 */
interface IconButtonProps {
  icon: IconName
  onClick?: () => void
  size?: number
  accent?: boolean
  ariaLabel: string
  className?: string
}

export function IconButton({
  icon,
  onClick,
  size = 38,
  accent,
  ariaLabel,
  className,
}: IconButtonProps) {
  const [pressed, setPressed] = useState(false)
  return (
    <button
      type="button"
      onClick={onClick}
      onTouchStart={() => setPressed(true)}
      onTouchEnd={() => setPressed(false)}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      aria-label={ariaLabel}
      style={{ width: size, height: size, borderRadius: size / 2 }}
      className={cn(
        'border-0 flex items-center justify-center shrink-0 cursor-pointer transition-colors',
        pressed ? 'bg-border-light' : 'bg-transparent',
        accent ? 'text-primary' : 'text-text-primary',
        className,
      )}
    >
      <Icon d={ICONS[icon]} size={size > 36 ? 20 : 18} />
    </button>
  )
}
