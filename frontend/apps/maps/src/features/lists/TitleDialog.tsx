import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/** A list's title becomes its file name, before `.kutupmap`: the server's name limit, less that. */
const MAX_TITLE = 240

/** Name a new list, or rename one. */
export function TitleDialog({
  open,
  title,
  description,
  initial,
  submit,
  pending,
  error,
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
  onClose: () => void
  onSubmit: (title: string) => void
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState(initial)
  useEffect(() => {
    if (open) setValue(initial)
  }, [open, initial])

  const trimmed = value.trim()
  const problem =
    trimmed.length === 0
      ? t('title.required')
      : trimmed.length > MAX_TITLE
        ? t('title.tooLong', { max: MAX_TITLE })
        : /[/\\]/.test(trimmed)
          ? t('title.slash')
          : null

  function submitForm(event: FormEvent) {
    event.preventDefault()
    if (!problem) onSubmit(trimmed)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        <form className="space-y-4" onSubmit={submitForm}>
          <Field label={t('title.label')} error={value !== initial ? (problem ?? undefined) : undefined} required>
            {(field) => <Input {...field} value={value} onChange={(e) => setValue(e.target.value)} autoFocus onFocus={(e) => e.target.select()} />}
          </Field>
          {error ? <Alert variant="error">{apiErrorMessage(error, t('title.failed'))}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={problem !== null}>
              {submit}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
