import * as PopoverPrimitive from '@radix-ui/react-popover'
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from 'react'
import { cn } from '../lib/cn'

export const Popover = PopoverPrimitive.Root
export const PopoverTrigger = PopoverPrimitive.Trigger
export const PopoverClose = PopoverPrimitive.Close
/** Where the panel points when it has no trigger (an element, or a `virtualRef` measured on each move). */
export const PopoverAnchor = PopoverPrimitive.Anchor

/** A small panel anchored to its trigger, dismissed by Escape or a click outside. */
export const PopoverContent = forwardRef<
  ElementRef<typeof PopoverPrimitive.Content>,
  ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>
>(function PopoverContent({ className, sideOffset = 8, ...props }, ref) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        ref={ref}
        sideOffset={sideOffset}
        collisionPadding={16}
        className={cn(
          'z-50 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-border bg-popover p-4',
          'text-popover-foreground shadow-md focus:outline-none',
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
})
