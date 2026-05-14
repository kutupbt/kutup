import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

/**
 * Surface — a bordered, rounded card. Hosts grouped row-lists (e.g. settings,
 * file lists, profile sections). Background uses `--surface`; border uses
 * `--border-light` for a softer line than the regular `--border`.
 *
 * `var(--radius-lg)` (= 14px) matches the design's surface radius.
 */
export function Surface({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden',
        className,
      )}
      {...rest}
    />
  )
}
