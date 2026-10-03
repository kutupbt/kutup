import * as CheckboxPrimitive from '@radix-ui/react-checkbox'
import { Check } from 'lucide-react'
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from 'react'
import { cn } from '../lib/cn'

/**
 * A checkbox the product draws, for the same reason `select.tsx` exists.
 *
 * The three that were left were native. `accent-color` themes the *fill* and
 * nothing else: the box, its border, the tick glyph and the focus ring all stay
 * the platform's, so a GTK checkbox sat beside a styled badge in the same row —
 * and one of the three, the library picker's, carried no styling at all. That is
 * the complaint this whole direction answers.
 *
 * **Composing it costs the wrapping `<label>`, and that is worth knowing.**
 * Radix renders a `<button role="checkbox">`, and a button inside a label is not
 * toggled by clicking that label the way an input is. So every caller pairs an
 * explicit `htmlFor` with an `id`, and the row's hover affordance moves to a
 * `div`. The ids are built from a component-level `useId()` plus the row's own
 * key, because a `useId` cannot be called inside a loop and a bare key would
 * collide if a page ever showed two of the same picker.
 */
export const Checkbox = forwardRef<
  ElementRef<typeof CheckboxPrimitive.Root>,
  ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>
>(function Checkbox({ className, ...props }, ref) {
  return (
    <CheckboxPrimitive.Root
      ref={ref}
      className={cn(
        'peer size-4 shrink-0 rounded-sm border border-input bg-card',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        'focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        'disabled:cursor-not-allowed disabled:opacity-50',
        'data-[state=checked]:border-primary data-[state=checked]:bg-primary',
        'data-[state=checked]:text-primary-foreground',
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator className="flex items-center justify-center text-current">
        <Check className="size-3.5" strokeWidth={3} />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  )
})
