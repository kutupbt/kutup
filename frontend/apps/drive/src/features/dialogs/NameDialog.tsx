import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { asNameTaken, canonicalName } from '@kutup/drive-core/names'

/** The server's limit for a name. */
const MAX_NAME = 255

/**
 * Name something: a new folder, or a rename. For files with an extension the
 * editors depend on, only the part before it is selected on open, the way
 * desktop file managers do it — the extension stays but is not locked.
 */
export function NameDialog({
  open,
  title,
  description,
  initial,
  submit,
  pending,
  error,
  taken,
  onClose,
  onSubmit,
}: {
  open: boolean
  title: string
  description?: string
  initial: string
  submit: string
  pending: boolean
  error: unknown
  /** Names already in the folder, in canonical form (`canonicalName`): the server's clash check. */
  taken?: ReadonlySet<string>
  onClose: () => void
  onSubmit: (name: string) => void
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState(initial)
  const input = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (!open) return
    setValue(initial)
    // Select the base name, leaving ".docx" in place.
    requestAnimationFrame(() => {
      const dot = initial.lastIndexOf('.')
      input.current?.setSelectionRange(0, dot > 0 ? dot : initial.length)
    })
  }, [open, initial])

  const name = value.trim()
  const problem =
    name.length === 0
      ? t('dialogs.name.required')
      : name.length > MAX_NAME
        ? t('dialogs.name.tooLong', { max: MAX_NAME })
        : /[/\\]/.test(name)
          ? t('dialogs.name.slash')
          : canonicalName(name) !== canonicalName(initial) && taken?.has(canonicalName(name))
            ? t('dialogs.name.taken')
            : null

  function handle(event: FormEvent) {
    event.preventDefault()
    if (!problem && name !== initial) onSubmit(name)
    else if (name === initial) onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        <form className="space-y-4" onSubmit={handle}>
          <Field label={t('dialogs.name.label')} error={value !== initial ? (problem ?? undefined) : undefined} required>
            {(field) => (
              <Input {...field} ref={input} value={value} onChange={(e) => setValue(e.target.value)} autoFocus autoComplete="off" />
            )}
          </Field>
          {error ? (
            <Alert variant="error">{asNameTaken(error) ? t('dialogs.name.taken') : apiErrorMessage(error, t('dialogs.name.failed'))}</Alert>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={Boolean(problem) && name !== initial}>
              {submit}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
