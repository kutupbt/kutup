import { forwardRef, type HTMLAttributes } from 'react'
import { cn } from '../lib/cn'

/**
 * A container with a name.
 *
 * The product had none, and so every page stacked its sections directly on the
 * page: a table, then a heading, then a form, all on one undifferentiated
 * plane, with nothing saying where one thing ended and the next began. That is
 * the whole of what "looks like a bad html website" meant.
 *
 * `--card` is white against a `--background` that is paper, so a card reads as
 * raised without a shadow. Shadows are reserved for the popover layer, where
 * they mean "floating above the page" rather than "is a section".
 */
export const Card = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  function Card({ className, ...props }, ref) {
    return (
      <div
        ref={ref}
        className={cn(
          'rounded-lg border border-border bg-card text-card-foreground',
          className,
        )}
        {...props}
      />
    )
  },
)

export const CardHeader = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  function CardHeader({ className, ...props }, ref) {
    return <div ref={ref} className={cn('flex flex-col gap-1 p-5', className)} {...props} />
  },
)

/**
 * `h3` by default: a card sits under the page's `h1` and usually under a
 * section `h2`, and skipping a level breaks the outline a screen reader reads.
 * Override with `as` where the nesting genuinely differs.
 *
 * `h1` is in the union for the two screens where **the card is the page**:
 * sign-in and setup have no shell, no page title above them, and nothing else
 * to be the top of the document. Anywhere inside the app shell it would be a
 * second first-level heading on a page that already has one.
 */
export const CardTitle = forwardRef<
  HTMLHeadingElement,
  HTMLAttributes<HTMLHeadingElement> & { as?: 'h1' | 'h2' | 'h3' | 'h4' }
>(function CardTitle({ className, as: Tag = 'h3', ...props }, ref) {
  return (
    <Tag
      ref={ref}
      className={cn('font-display text-base font-semibold tracking-tight', className)}
      {...props}
    />
  )
})

export const CardDescription = forwardRef<HTMLParagraphElement, HTMLAttributes<HTMLParagraphElement>>(
  function CardDescription({ className, ...props }, ref) {
    return <p ref={ref} className={cn('text-sm text-muted-foreground', className)} {...props} />
  },
)

export const CardContent = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  function CardContent({ className, ...props }, ref) {
    return <div ref={ref} className={cn('p-5 pt-0', className)} {...props} />
  },
)

export const CardFooter = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
  function CardFooter({ className, ...props }, ref) {
    return (
      <div
        ref={ref}
        className={cn('flex items-center gap-2 border-t border-border px-5 py-4', className)}
        {...props}
      />
    )
  },
)
