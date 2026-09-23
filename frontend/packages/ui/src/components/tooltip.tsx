import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef, type ReactNode } from 'react'
import { cn } from '../lib/cn'

/**
 * A label for a control that shows only an icon.
 *
 * `@radix-ui/react-tooltip` was installed in `ef613ea` and then used nowhere,
 * which is the same failure as a button wired to nothing: a dependency in the
 * lockfile that no screen depends on. This is the decision to keep it, and the
 * use that earns it.
 *
 * **A tooltip is never the only label.** Every control it describes still
 * carries an `aria-label`, because a tooltip is unreachable by touch and
 * announced inconsistently by screen readers. It exists for the sighted mouse
 * user looking at a chevron and wondering which way it goes — an addition to
 * the accessible name, never a substitute for it.
 *
 * Not for prose. A tooltip that holds something the user needs in order to
 * decide is holding it somewhere they cannot keep it open while they act.
 */
export const TooltipProvider = TooltipPrimitive.Provider

export const TooltipContent = forwardRef<
  ElementRef<typeof TooltipPrimitive.Content>,
  ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>
>(function TooltipContent({ className, sideOffset = 6, ...props }, ref) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        ref={ref}
        sideOffset={sideOffset}
        className={cn(
          'z-50 rounded-md border border-border bg-card px-2 py-1 text-xs',
          'text-card-foreground shadow-md',
          className,
        )}
        {...props}
      />
    </TooltipPrimitive.Portal>
  )
})

/**
 * The whole pattern in one component, because it is always the same three.
 *
 * `asChild` on the trigger so the tooltip wraps the real control rather than
 * inserting a span around it — a span between a `<td>` and a `<button>` is a
 * layout bug waiting to happen.
 */
export function Tooltip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipContent>{label}</TooltipContent>
    </TooltipPrimitive.Root>
  )
}
