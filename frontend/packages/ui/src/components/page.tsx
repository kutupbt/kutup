import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

/**
 * The furniture every page shares.
 *
 * Before this, each page opened with its own `<h1 className="text-xl
 * font-semibold">` and its own idea of the gap beneath it, and the primary
 * action sat wherever the markup happened to put it — sometimes under the
 * description, sometimes above the table, once inside a form. A page header is
 * a component so that "where is the button that makes a new one" has the same
 * answer everywhere.
 *
 * The title takes the condensed display face. It is the one place the
 * typography announces itself, and it does the job an `h1` should: telling you
 * what you are looking at from across the desk.
 */
export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  /** The primary action, and at most one or two beside it. */
  actions?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap items-start justify-between gap-4', className)}>
      <div className="min-w-0 space-y-1">
        <h1 className="font-display text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? (
          <p className="max-w-2xl text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/**
 * The content column.
 *
 * `wide` is the default because this product's pages are mostly tables, and the
 * old `max-w-5xl` left roughly a third of a 1600px screen empty beside a table
 * that wanted the room. `prose` is for the pages that are genuinely a single
 * column of reading or one form — a measure of about 75 characters, which is
 * where lines stop being comfortable to track.
 */
export function PageBody({
  children,
  width = 'wide',
  className,
}: {
  children: ReactNode
  width?: 'wide' | 'prose'
  className?: string
}) {
  return (
    <div
      className={cn(
        'mx-auto w-full space-y-6',
        width === 'wide' ? 'max-w-7xl' : 'max-w-3xl',
        className,
      )}
    >
      {children}
    </div>
  )
}

/**
 * A label over a value: the read-only twin of a `Field`.
 *
 * Detail views are full of facts nobody edits in place — when a session was
 * created, which device it runs on, a file's exact size — and each would
 * otherwise grow its own `<p>` pair with its own gap. The
 * spacing matches `Field` deliberately, so a card holding both does not step.
 *
 * The label is a `<p>` rather than a `<label>`: there is no control for it to
 * name, and a `<label>` pointing at nothing promises a screen reader an
 * association the page does not have.
 */
export function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <p className="text-sm font-medium leading-none">{label}</p>
      <div className="text-sm text-muted-foreground">{children}</div>
    </div>
  )
}

/**
 * A named region within a page: the heading a settings screen uses instead of a
 * second `h1`, and the grouping for the cases where a `Card` would be too much
 * furniture.
 *
 * **The description is measured, like `PageHeader`'s.** Left unbounded it takes
 * the full row, and `justify-between` then wraps the action onto a line of its
 * own — which is how "New service account" ended up under its own paragraph
 * while the shorter descriptions beside it kept their buttons in place. A rule
 * that holds only for short sentences is not a layout.
 */
export function Section({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <h2 className="font-display text-lg font-semibold tracking-tight">{title}</h2>
          {description ? (
            <p className="max-w-2xl text-sm text-muted-foreground">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}
