import * as ContextMenuPrimitive from '@radix-ui/react-context-menu'
import { ChevronRight } from 'lucide-react'
import { forwardRef, type ComponentPropsWithoutRef, type ElementRef } from 'react'
import { cn } from '../lib/cn'

/**
 * The right-click menu (long-press on touch). Styled exactly like
 * dropdown-menu.tsx: the same actions often appear in both, from a "⋯"
 * button and from a right click, and they must read as one menu.
 */
export const ContextMenu = ContextMenuPrimitive.Root
export const ContextMenuTrigger = ContextMenuPrimitive.Trigger

export const ContextMenuContent = forwardRef<
  ElementRef<typeof ContextMenuPrimitive.Content>,
  ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Content>
>(function ContextMenuContent({ className, ...props }, ref) {
  return (
    <ContextMenuPrimitive.Portal>
      <ContextMenuPrimitive.Content
        ref={ref}
        className={cn(
          'z-50 min-w-48 overflow-hidden rounded-md border border-border bg-popover p-1',
          'text-popover-foreground shadow-md',
          className,
        )}
        {...props}
      />
    </ContextMenuPrimitive.Portal>
  )
})

export const ContextMenuItem = forwardRef<
  ElementRef<typeof ContextMenuPrimitive.Item>,
  ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Item> & { destructive?: boolean }
>(function ContextMenuItem({ className, destructive, ...props }, ref) {
  return (
    <ContextMenuPrimitive.Item
      ref={ref}
      className={cn(
        'relative flex cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none',
        'focus:bg-accent focus:text-accent-foreground',
        'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        '[&_svg]:size-4 [&_svg]:shrink-0',
        destructive && 'text-destructive focus:bg-destructive focus:text-destructive-foreground',
        className,
      )}
      {...props}
    />
  )
})

export function ContextMenuSeparator({ className }: { className?: string }) {
  return <ContextMenuPrimitive.Separator className={cn('-mx-1 my-1 h-px bg-border', className)} />
}

export function ContextMenuLabel({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof ContextMenuPrimitive.Label>) {
  return (
    <ContextMenuPrimitive.Label
      className={cn('px-2 py-1.5 text-xs font-medium text-muted-foreground', className)}
      {...props}
    />
  )
}

/** A nested menu ("Mute" → durations). */
export const ContextMenuSub = ContextMenuPrimitive.Sub

export const ContextMenuSubTrigger = forwardRef<
  ElementRef<typeof ContextMenuPrimitive.SubTrigger>,
  ComponentPropsWithoutRef<typeof ContextMenuPrimitive.SubTrigger>
>(function ContextMenuSubTrigger({ className, children, ...props }, ref) {
  return (
    <ContextMenuPrimitive.SubTrigger
      ref={ref}
      className={cn(
        'relative flex cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none',
        'focus:bg-accent focus:text-accent-foreground data-[state=open]:bg-accent',
        'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        '[&_svg]:size-4 [&_svg]:shrink-0',
        className,
      )}
      {...props}
    >
      {children}
      <ChevronRight className="ml-auto" aria-hidden />
    </ContextMenuPrimitive.SubTrigger>
  )
})

export const ContextMenuSubContent = forwardRef<
  ElementRef<typeof ContextMenuPrimitive.SubContent>,
  ComponentPropsWithoutRef<typeof ContextMenuPrimitive.SubContent>
>(function ContextMenuSubContent({ className, ...props }, ref) {
  return (
    <ContextMenuPrimitive.Portal>
      <ContextMenuPrimitive.SubContent
        ref={ref}
        className={cn(
          'z-50 min-w-40 overflow-hidden rounded-md border border-border bg-popover p-1',
          'text-popover-foreground shadow-md',
          className,
        )}
        {...props}
      />
    </ContextMenuPrimitive.Portal>
  )
})
