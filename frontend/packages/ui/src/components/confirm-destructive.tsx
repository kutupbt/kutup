import type { FormEvent, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from './alert'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from './alert-dialog'
import { Button } from './button'
import { apiErrorMessage } from '../lib/apiError'

/**
 * The one way this product asks "are you sure".
 *
 * - `AlertDialog`, not `Dialog`: a click outside does not dismiss it and focus
 *   opens on Cancel, so Enter out of habit cancels rather than destroys.
 * - The confirming control is a plain submit, never `AlertDialogAction` (that
 *   closes on click and would discard a refusal the server has not sent yet).
 *   The caller closes the dialog when its mutation resolves.
 * - The server's own words win: `error` renders through `apiErrorMessage`;
 *   `errorFallback` is only for when the server did not say why.
 * - `blocked` renders the obstacle and disables the submit from one prop.
 *
 * If success unmounts the caller, confirm with `mutateAsync` so the
 * continuation (a redirect, a toast) survives the unmount.
 */
export interface ConfirmDestructiveProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  /** The sentence naming what is about to go. */
  description: ReactNode
  /** What is irreversible, in red (or amber with `warningVariant="warn"`). */
  warning?: ReactNode
  warningVariant?: 'error' | 'warn'
  /** An obstacle known before the attempt; non-null disables the submit. */
  blocked?: ReactNode
  /** The destructive verb on the button: "Delete folder", not "Confirm". */
  submit: string
  pending?: boolean
  error?: unknown
  errorFallback: string
  onConfirm: () => void
}

export function ConfirmDestructive({
  open,
  onOpenChange,
  title,
  description,
  warning,
  warningVariant = 'error',
  blocked,
  submit,
  pending,
  error,
  errorFallback,
  onConfirm,
}: ConfirmDestructiveProps) {
  const { t } = useTranslation()

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!blocked && !pending) onConfirm()
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>

        {error !== undefined && error !== null ? (
          <Alert variant="error" className="mb-4">
            {apiErrorMessage(error, errorFallback)}
          </Alert>
        ) : null}

        {blocked ? (
          <Alert variant="warn" className="mb-4">
            {blocked}
          </Alert>
        ) : null}

        <form className="space-y-4" onSubmit={handleSubmit}>
          {warning ? <Alert variant={warningVariant}>{warning}</Alert> : null}
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <Button type="submit" variant="destructive" loading={pending} disabled={!!blocked}>
              {submit}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}
