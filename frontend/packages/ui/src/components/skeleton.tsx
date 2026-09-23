import type { HTMLAttributes } from 'react'
import { cn } from '../lib/cn'

/**
 * The shape of what is coming.
 *
 * Used where the layout is known before the data is — a table of a known
 * column count, a detail header. Where it is not known, `LoadingPanel` says so
 * in words instead; a skeleton that guesses wrong is a layout that jumps.
 */
export function Skeleton({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('animate-pulse rounded-md bg-muted', className)} {...props} />
}
