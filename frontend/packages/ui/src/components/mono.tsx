import type { HTMLAttributes } from 'react'
import { cn } from '../lib/cn'

/**
 * A string the *system* asserted.
 *
 * Key fingerprints, safety numbers, device and session IDs, server names,
 * exact byte counts, absolute timestamps. Not prose — a file name is what a
 * person typed, even when it looks technical.
 *
 * This exists as a component rather than a `font-mono` class so the rule is
 * applied by **meaning** rather than by eye, and so changing how machine facts
 * read is one edit instead of a search across forty files.
 *
 * `as` is that same rule reaching machine output that is not a phrase: a
 * captured request, a scanner's stdout, a stack trace. Those are a `pre`, and
 * writing `font-mono` on one directly would be the first leak out of the one
 * edit — a `pre` inherits the platform's monospace, not the product's.
 */
export function Mono({
  as: Tag = 'span',
  className,
  emphasis = false,
  ...props
}: HTMLAttributes<HTMLElement> & { emphasis?: boolean; as?: 'span' | 'code' | 'pre' }) {
  return (
    <Tag
      className={cn('font-mono text-[0.9em]', emphasis && 'font-medium', className)}
      {...props}
    />
  )
}
