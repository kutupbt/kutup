import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import {
  forwardRef,
  type ComponentPropsWithoutRef,
  type ElementRef,
  type HTMLAttributes,
} from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/cn'

/**
 * Modal dialog.
 *
 * Radix rather than hand-rolled: focus trapping, focus restore, `Escape`,
 * scroll locking and `aria-modal` are each easy to get subtly wrong, and a
 * dialog that leaks focus behind itself is a keyboard-only user's dead end.
 */
export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export const DialogContent = forwardRef<
  ElementRef<typeof DialogPrimitive.Content>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(function DialogContent({ className, children, ...props }, ref) {
  const { t } = useTranslation()
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        className={cn(
          'fixed inset-0 z-50 bg-foreground/40 backdrop-blur-[1px]',
          'data-[state=open]:animate-in data-[state=closed]:animate-out',
        )}
      />
      <DialogPrimitive.Content
        ref={ref}
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2',
          'rounded-lg border border-border bg-card p-6 text-card-foreground shadow-lg',
          // A centred dialog taller than the window grows off both ends, and
          // the submit button — always last — is the half that goes. Every
          // dialog here fitted until one had nine fields, and the walkthrough
          // found it by being unable to click Save. `dvh` rather than `vh`
          // because a phone's toolbars are part of the window and `vh` is not.
          'max-h-[85dvh] overflow-y-auto',
          'focus:outline-none',
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          className={cn(
            'absolute right-4 top-4 rounded-sm text-muted-foreground transition-colors',
            'hover:text-foreground focus:outline-none focus:ring-2 focus:ring-ring',
          )}
        >
          <X className="h-4 w-4" />
          <span className="sr-only">{t('common.close')}</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
})

export function DialogHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('mb-4 space-y-1.5 pr-8', className)} {...props} />
}

export function DialogFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end', className)}
      {...props}
    />
  )
}

export const DialogTitle = forwardRef<
  ElementRef<typeof DialogPrimitive.Title>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Title>
>(function DialogTitle({ className, ...props }, ref) {
  return (
    <DialogPrimitive.Title
      ref={ref}
      className={cn('text-base font-semibold leading-none tracking-tight', className)}
      {...props}
    />
  )
})

export const DialogDescription = forwardRef<
  ElementRef<typeof DialogPrimitive.Description>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Description>
>(function DialogDescription({ className, ...props }, ref) {
  return (
    <DialogPrimitive.Description
      ref={ref}
      className={cn('text-sm text-muted-foreground', className)}
      {...props}
    />
  )
})
