import { Users } from 'lucide-react'
import { cn } from '../lib/cn'
import { initialsOf } from '../lib/initials'

/**
 * A person's or group's picture: their profile picture when they shared
 * one, else their initials, else (a group) the group glyph.
 */
export function Avatar({
  name,
  image,
  contentType,
  group,
  size = 48,
  className,
}: {
  name: string
  /** Base64 profile picture. */
  image?: string
  contentType?: string
  group?: boolean
  size?: 16 | 24 | 28 | 32 | 48 | 80
  className?: string
}) {
  const box = { 16: 'size-4 text-[0.5rem]', 24: 'size-6 text-[0.5625rem]', 28: 'size-7 text-[0.625rem]', 32: 'size-8 text-xs', 48: 'size-12 text-sm', 80: 'size-20 text-2xl' }[size]
  return (
    <span
      aria-hidden
      className={cn(
        'inline-flex shrink-0 select-none items-center justify-center overflow-hidden rounded-full bg-accent font-semibold text-accent-foreground',
        box,
        className,
      )}
    >
      {image ? (
        <img src={`data:${contentType ?? 'image/jpeg'};base64,${image}`} alt="" className="size-full object-cover" />
      ) : group ? (
        <Users className="size-1/2" />
      ) : (
        initialsOf(name)
      )}
    </span>
  )
}
