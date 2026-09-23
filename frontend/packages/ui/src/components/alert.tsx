import { AlertTriangle, Info } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/**
 * Inline message.
 *
 * `role="alert"` on the error variant so a failed mutation is announced rather
 * than silently appearing below the fold — an admin screen that fails quietly
 * is how someone concludes a button "did nothing".
 *
 * `warn` is for a consequence rather than a failure: nothing has gone wrong,
 * but something is about to be irreversible. Unlike `error`, it does **not**
 * take `role="alert"` — it is present before the user acts, so interrupting a
 * screen reader mid-sentence would be noise, and the surrounding dialog already
 * announces itself.
 *
 * The warn variant tints the surface and the icon rather than the text. The
 * `--status-warn` token is a mid yellow chosen to sit under near-black
 * foreground on a solid badge; as *text* on a 10%-tinted surface it would fail
 * contrast in the light theme. Colour carries the meaning through the border
 * and icon; the words stay readable.
 */
export function Alert({
  variant = 'info',
  title,
  children,
  className,
}: {
  variant?: 'info' | 'error' | 'warn'
  title?: string
  children?: ReactNode
  className?: string
}) {
  const Icon = variant === 'info' ? Info : AlertTriangle
  return (
    <div
      role={variant === 'error' ? 'alert' : undefined}
      className={cn(
        'flex gap-2.5 rounded-md border p-3 text-sm',
        variant === 'error' && 'border-destructive/40 bg-destructive/10 text-destructive',
        variant === 'warn' && 'border-status-warn/50 bg-status-warn/10 text-foreground',
        variant === 'info' && 'border-border bg-muted text-muted-foreground',
        className,
      )}
    >
      <Icon
        className={cn('mt-0.5 h-4 w-4 shrink-0', variant === 'warn' && 'text-status-warn')}
        aria-hidden
      />
      <div className="min-w-0 space-y-0.5">
        {title ? <p className="font-medium">{title}</p> : null}
        {children ? <div className="break-words">{children}</div> : null}
      </div>
    </div>
  )
}
