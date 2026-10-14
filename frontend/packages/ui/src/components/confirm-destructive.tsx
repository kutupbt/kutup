import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'
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
import { Input } from './input'
import { Label } from './label'
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
 * - `confirmPhrase` (for what cannot be undone: wiping or deleting an
 *   account) asks for that exact text to be typed before the submit enables.
 * - `passwordLabel` asks for the signed-in person's own password (an act the
 *   server allows only after proving it again); `onConfirm` receives it.
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
  /** When set, this exact text must be typed to enable the submit. */
  confirmPhrase?: string
  /** When set, the person's own password is asked for (labelled so) and passed to `onConfirm`. */
  passwordLabel?: string
  onConfirm: (password: string) => void
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
  confirmPhrase,
  passwordLabel,
  onConfirm,
}: ConfirmDestructiveProps) {
  const { t } = useTranslation()
  const phraseId = useId()
  const passwordId = useId()
  const [typed, setTyped] = useState('')
  const [password, setPassword] = useState('')
  useEffect(() => {
    if (!open) {
      setTyped('')
      setPassword('')
    }
  }, [open])
  const phraseMissing = confirmPhrase !== undefined && typed.trim() !== confirmPhrase
  const passwordMissing = passwordLabel !== undefined && password === ''

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (blocked || pending || phraseMissing || passwordMissing) return
    onConfirm(password)
    // Handed over once: a failed attempt (or a retry) asks for it again, and
    // the dialog does not keep it meanwhile.
    setPassword('')
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
          {confirmPhrase !== undefined ? (
            <div className="space-y-1.5">
              <Label htmlFor={phraseId}>{t('common.typeToConfirm', { phrase: confirmPhrase })}</Label>
              <Input
                id={phraseId}
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          ) : null}
          {passwordLabel !== undefined ? (
            <div className="space-y-1.5">
              <Label htmlFor={passwordId}>{passwordLabel}</Label>
              <Input
                id={passwordId}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <Button type="submit" variant="destructive" loading={pending} disabled={!!blocked || phraseMissing || passwordMissing}>
              {submit}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  )
}
