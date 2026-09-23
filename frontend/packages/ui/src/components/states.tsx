import { Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/** Busy indicator. */
export function Spinner({ className, label }: { className?: string; label: string }) {
  return (
    <span role="status" className={cn('inline-flex items-center gap-2', className)}>
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  )
}

/** Centred loading block for a whole page or panel. */
export function LoadingPanel({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center py-16 text-muted-foreground">
      <Spinner label={label} />
    </div>
  )
}

/**
 * Empty state.
 *
 * Always says *why* it is empty. "This folder is empty" and "nothing matches
 * the filter" produce an identical blank screen otherwise.
 */
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="max-w-md text-sm text-muted-foreground">{description}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  )
}
