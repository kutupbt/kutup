import * as TabsPrimitive from '@radix-ui/react-tabs'
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from 'react'
import { cn } from '../lib/cn'

/**
 * Tabs, from Radix rather than by hand.
 *
 * Two pages had grown their own out of `<button role="tab">` and a `useState`,
 * and neither implemented the keyboard behaviour the role promises: a tab list
 * moves with the arrow keys and takes one tab stop, not one per tab. Announcing
 * `role="tablist"` without that is worse than plain buttons, because assistive
 * technology tells the user to press a key that does nothing.
 *
 * The active tab carries the spine in `--primary`, the same mark the sidebar
 * uses for the current destination.
 */
export const Tabs = TabsPrimitive.Root

/**
 * **The list scrolls; the page does not.** A report has five tabs and they need
 * about 480px, so at 375 they were making the whole document scroll sideways —
 * found by measuring `scrollWidth` against `clientWidth` on every route, not by
 * looking, because a screenshot of an overflowing page just looks like a page
 * with something cut off.
 *
 * Scrolling rather than wrapping, because a wrapped tab list puts `border-b`
 * under only the last row and the rows above float unattached. The partially
 * visible last tab is the affordance, which is the convention on every mobile
 * UI that does this.
 *
 * The scrollbar is suppressed deliberately: `overflow-x-auto` makes `overflow-y`
 * compute to `auto` as well, so the trigger's 1px `-mb-px` overhang would
 * otherwise raise a vertical scrollbar on a 36px-tall strip.
 */
export const TabsList = forwardRef<
  ElementRef<typeof TabsPrimitive.List>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(function TabsList({ className, ...props }, ref) {
  return (
    <TabsPrimitive.List
      ref={ref}
      className={cn(
        'flex items-center gap-1 overflow-x-auto border-b border-border',
        '[scrollbar-width:none] [&::-webkit-scrollbar]:hidden',
        className,
      )}
      {...props}
    />
  )
})

export const TabsTrigger = forwardRef<
  ElementRef<typeof TabsPrimitive.Trigger>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(function TabsTrigger({ className, ...props }, ref) {
  return (
    <TabsPrimitive.Trigger
      ref={ref}
      className={cn(
        '-mb-px inline-flex items-center gap-2 border-b-2 border-transparent px-3 py-2 text-sm',
        'font-medium text-muted-foreground transition-colors hover:text-foreground',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
        'focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50',
        'data-[state=active]:border-primary data-[state=active]:text-foreground',
        className,
      )}
      {...props}
    />
  )
})

/**
 * A count beside a tab's name. Muted, and never the only thing that changes —
 * a tab whose label is a number tells you nothing about what is in it.
 */
export function TabsCount({ children }: { children: number }) {
  return <span className="rounded bg-muted px-1.5 py-0.5 text-xs tabular-nums">{children}</span>
}

export const TabsContent = forwardRef<
  ElementRef<typeof TabsPrimitive.Content>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(function TabsContent({ className, ...props }, ref) {
  return (
    <TabsPrimitive.Content
      ref={ref}
      className={cn(
        // Hide the inactive panel explicitly: a `forceMount`ed panel (e.g. a live scan's activity,
        // kept mounted so its event stream isn't torn down) has `present=true`, so Radix does NOT
        // set `hidden` on it when it's not selected — without this it would bleed onto the active tab.
        'mt-6 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=inactive]:hidden',
        className,
      )}
      {...props}
    />
  )
})
