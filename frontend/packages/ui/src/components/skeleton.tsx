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

/**
 * A loading list: rows with a leading icon or avatar and two lines of text,
 * as a file, an entry or a conversation is shown (Proton's list placeholders).
 * Announced once to screen readers by `label`; the rows themselves are hidden.
 */
export function ListSkeleton({
  label,
  rows = 8,
  avatar = 'square',
  className,
}: {
  label: string
  rows?: number
  /** A round avatar (people, conversations) or a square icon (files, entries). */
  avatar?: 'round' | 'square'
  className?: string
}) {
  return (
    <div role="status" aria-busy="true" className={cn('space-y-1 p-3', className)}>
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} aria-hidden="true" className="flex items-center gap-3 px-2 py-2">
          <Skeleton className={cn('size-9 shrink-0', avatar === 'round' ? 'rounded-full' : 'rounded-md')} />
          <div className="min-w-0 flex-1 space-y-2">
            {/* Varying widths, so the rows read as names, not as a table. */}
            <Skeleton className={cn('h-3.5', ['w-2/5', 'w-1/2', 'w-1/3', 'w-3/5'][i % 4])} />
            <Skeleton className={cn('h-3', ['w-1/4', 'w-1/3', 'w-1/5', 'w-2/5'][i % 4])} />
          </div>
        </div>
      ))}
    </div>
  )
}

/**
 * A loading grid of square thumbnails, as a photo timeline or album list is
 * shown. Announced once by `label`.
 */
export function GridSkeleton({ label, count = 24, className }: { label: string; count?: number; className?: string }) {
  return (
    <div
      role="status"
      aria-busy="true"
      className={cn('grid grid-cols-3 gap-1 p-3 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8', className)}
    >
      <span className="sr-only">{label}</span>
      {Array.from({ length: count }, (_, i) => (
        <Skeleton key={i} aria-hidden="true" className="aspect-square w-full rounded-sm" />
      ))}
    </div>
  )
}

/**
 * A loading settings page or form: a heading, then label-and-field rows, as
 * Proton's settings sections load. Announced once by `label`.
 */
export function FormSkeleton({ label, rows = 4, className }: { label: string; rows?: number; className?: string }) {
  return (
    <div role="status" aria-busy="true" className={cn('max-w-2xl space-y-6 p-3', className)}>
      <span className="sr-only">{label}</span>
      <Skeleton aria-hidden="true" className="h-5 w-1/3" />
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} aria-hidden="true" className="space-y-2">
          <Skeleton className={cn('h-3.5', ['w-1/4', 'w-1/3', 'w-1/5', 'w-2/5'][i % 4])} />
          <Skeleton className="h-9 w-full" />
        </div>
      ))}
    </div>
  )
}

/**
 * A loading month: a row of weekday names over six weeks of day cells, as a
 * calendar opens. Announced once by `label`.
 */
export function CalendarSkeleton({ label, className }: { label: string; className?: string }) {
  return (
    <div role="status" aria-busy="true" className={cn('flex h-full min-h-0 flex-col gap-2 p-4', className)}>
      <span className="sr-only">{label}</span>
      <div aria-hidden="true" className="flex items-center gap-2">
        <Skeleton className="h-8 w-16" />
        <Skeleton className="h-8 w-8" />
        <Skeleton className="h-8 w-8" />
        <Skeleton className="h-6 w-40" />
      </div>
      <div aria-hidden="true" className="grid flex-1 grid-cols-7 grid-rows-[auto_repeat(6,minmax(0,1fr))] gap-1">
        {Array.from({ length: 7 }, (_, i) => (
          <Skeleton key={`d${i}`} className="mx-auto h-3 w-8" />
        ))}
        {Array.from({ length: 42 }, (_, i) => (
          <Skeleton key={i} className="min-h-16 w-full rounded-sm opacity-60" />
        ))}
      </div>
    </div>
  )
}
