import type { ReactNode } from 'react'
import { Drawer } from 'vaul'
import { cn } from '@/lib/utils'

/**
 * BottomSheet — Vaul wrapper. Renders a slide-up sheet with the design's
 * grabber handle + optional title row + scrollable content slot.
 *
 * Vaul (vaul.emilkowal.ski) gives us iOS-style detents (drag-to-close, snap
 * stops) out of the box, which Radix Sheet doesn't. The `open`/`onOpenChange`
 * API matches Radix Sheet so we can swap them per surface if needed.
 *
 * Background scrim: Vaul renders a dimmed overlay automatically.
 */
interface BottomSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Optional sheet title (rendered above the content). */
  title?: string
  children: ReactNode
  /** Override the max-height. Default 85%. */
  maxHeight?: string
}

export function BottomSheet({
  open,
  onOpenChange,
  title,
  children,
  maxHeight = '85%',
}: BottomSheetProps) {
  return (
    <Drawer.Root open={open} onOpenChange={onOpenChange}>
      <Drawer.Portal>
        <Drawer.Overlay className="fixed inset-0 z-90 bg-black/35" />
        <Drawer.Content
          className={cn(
            'fixed left-0 right-0 bottom-0 z-100',
            'bg-surface rounded-t-[18px] flex flex-col pb-3',
            'shadow-[var(--shadow-lg)]',
            'outline-none',
          )}
          style={{ maxHeight }}
        >
          {/* Required by Vaul for screen-reader semantics — visually hidden if
              no title is provided. */}
          <Drawer.Title className={title ? 'sr-only' : 'sr-only'}>
            {title ?? 'Sheet'}
          </Drawer.Title>
          <Drawer.Description className="sr-only">{title ?? ''}</Drawer.Description>

          {/* Grabber handle */}
          <div className="flex justify-center pt-2 pb-1">
            <div className="w-9 h-[5px] rounded-[3px] bg-border" />
          </div>

          {title && (
            <div className="px-4 py-2.5 text-sm font-semibold text-text-primary text-center border-b border-border-light">
              {title}
            </div>
          )}

          <div className="overflow-auto flex-1">{children}</div>
        </Drawer.Content>
      </Drawer.Portal>
    </Drawer.Root>
  )
}
