import { cva, type VariantProps } from 'class-variance-authority'
import type { HTMLAttributes } from 'react'
import { cn } from '../lib/cn'

/**
 * Status pill.
 *
 * The `ok` / `warn` / `danger` / `neutral` variants map to the general status
 * tokens. A badge restates something the text already says ("Active",
 * "Revoked"); colour is never the only carrier of the meaning.
 */
const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium [&_svg]:size-3',
  {
    variants: {
      variant: {
        outline: 'border border-border text-muted-foreground',
        ok: 'bg-status-ok text-status-ok-foreground',
        warn: 'bg-status-warn text-status-warn-foreground',
        danger: 'bg-status-danger text-status-danger-foreground',
        neutral: 'bg-status-neutral text-status-neutral-foreground',
      },
    },
    defaultVariants: { variant: 'outline' },
  },
)

export function Badge({
  className,
  variant,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
