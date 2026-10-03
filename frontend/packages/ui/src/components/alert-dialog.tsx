import * as AlertDialogPrimitive from '@radix-ui/react-alert-dialog'
import {
  forwardRef,
  type ComponentPropsWithoutRef,
  type ElementRef,
  type HTMLAttributes,
} from 'react'
import { Button, type ButtonProps } from './button'
import { cn } from '../lib/cn'

/**
 * The dialog for a question with consequences.
 *
 * Not `Dialog` with different copy — a different primitive, because Radix's
 * alert dialog behaves differently in the three ways that matter when the
 * answer is destructive:
 *
 * - **It does not close on an outside click.** A normal dialog dismisses when
 *   you click past it, which is right for a picker and wrong here: the same
 *   reflex that dismisses a picker would otherwise be one pixel away from
 *   deleting a client. Radix prevents `onPointerDownOutside` and
 *   `onInteractOutside`, and nothing else.
 * - **`Escape` still closes it**, deliberately. It is the documented way out of
 *   any modal and the APG requires it of `alertdialog` too; a dialog that traps
 *   somebody is not safer, it is just stuck. Escape is a *dismissal*, and the
 *   thing being guarded is the accidental confirm.
 * - **Focus lands on `AlertDialogCancel`** — Radix cancels the content's own
 *   autofocus and focuses whatever registered as the cancel — and the markup is
 *   `role="alertdialog"`, so a screen reader announces the description as well
 *   as the title. Somebody who hits Enter out of habit cancels.
 *
 * Six confirmations use it: deleting an asset, a client, a subject or a
 * template, revoking a token, and resetting a password.
 *
 * **There is no `AlertDialogAction` here, and its absence is the design.**
 * Radix's is `Dialog.Close` under another name: it closes the dialog the
 * instant it is clicked. Every confirmation in this product is an async
 * mutation the server can refuse — a client with reports, a break-glass subject
 * — and the refusal is rendered *inside* this dialog, because the server is the
 * only party that knows why. An action that closed on click would throw that
 * message away and leave the row still sitting in the list, which reads as a
 * silent success. So the confirming control is the app's own
 * `<Button type="submit" variant="destructive">` inside the form, and the
 * dialog closes when the mutation succeeds and not before.
 * `DeleteSubjectDialog.test.tsx` asserts exactly that.
 */
export const AlertDialog = AlertDialogPrimitive.Root
export const AlertDialogTrigger = AlertDialogPrimitive.Trigger

export const AlertDialogContent = forwardRef<
  ElementRef<typeof AlertDialogPrimitive.Content>,
  ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Content>
>(function AlertDialogContent({ className, ...props }, ref) {
  return (
    <AlertDialogPrimitive.Portal>
      <AlertDialogPrimitive.Overlay
        className={cn(
          'fixed inset-0 z-50 bg-foreground/40 backdrop-blur-[1px]',
          'data-[state=open]:animate-in data-[state=closed]:animate-out',
        )}
      />
      <AlertDialogPrimitive.Content
        ref={ref}
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2',
          'rounded-lg border border-border bg-card p-6 text-card-foreground shadow-lg',
          'max-h-[85dvh] overflow-y-auto focus:outline-none',
          className,
        )}
        {...props}
      />
    </AlertDialogPrimitive.Portal>
  )
})

/**
 * `mb-4` to match `DialogHeader`, because without it the description and the
 * first label sit six pixels apart and read as one block — which is what the
 * "Set password" confirmation looked like, since it is the one with no alert
 * between them to hide the gap.
 *
 * No `pr-8`, which is the one place this differs from `DialogHeader`: that
 * padding clears the close ✕, and an alert dialog deliberately has none.
 */
export function AlertDialogHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('mb-4 flex flex-col gap-2 text-left', className)} {...props} />
}

export function AlertDialogFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end', className)}
      {...props}
    />
  )
}

export const AlertDialogTitle = forwardRef<
  ElementRef<typeof AlertDialogPrimitive.Title>,
  ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Title>
>(function AlertDialogTitle({ className, ...props }, ref) {
  return (
    <AlertDialogPrimitive.Title
      ref={ref}
      className={cn('text-lg font-semibold', className)}
      {...props}
    />
  )
})

export const AlertDialogDescription = forwardRef<
  ElementRef<typeof AlertDialogPrimitive.Description>,
  ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Description>
>(function AlertDialogDescription({ className, ...props }, ref) {
  return (
    <AlertDialogPrimitive.Description
      ref={ref}
      className={cn('text-sm text-muted-foreground', className)}
      {...props}
    />
  )
})

/**
 * The way out, and the one that holds focus when the dialog opens.
 *
 * This one *is* `AlertDialogPrimitive.Cancel` rather than a plain button,
 * because the primitive is what registers the element as the dialog's cancel
 * ref — which is what Radix focuses on open. A styled `<Button>` in its place
 * would leave focus on the content and quietly drop the property the whole
 * primitive was chosen for.
 *
 * Composed with `asChild` so it *is* the app's `Button` rather than a copy of
 * its classes; a copy would stop tracking the original the next time the button
 * changes. Radix's own `type="button"` comes through the slot, so it never
 * submits the form it sits in.
 */
export const AlertDialogCancel = forwardRef<HTMLButtonElement, ButtonProps>(
  function AlertDialogCancel({ variant = 'outline', ...props }, ref) {
    return (
      <AlertDialogPrimitive.Cancel asChild>
        <Button ref={ref} variant={variant} {...props} />
      </AlertDialogPrimitive.Cancel>
    )
  },
)
