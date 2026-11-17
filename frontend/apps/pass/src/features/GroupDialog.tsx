import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { Textarea } from '@kutup/ui/components/textarea'

/** Names a new group, or renames one. */
export function GroupDialog({
  open,
  onOpenChange,
  title,
  initial,
  onSubmit,
  describeError,
  label,
  notes,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  initial: string
  /** The field's label; the group name's by default. */
  label?: string
  /** What to say when `onSubmit` fails; a generic message otherwise. */
  describeError?: (error: unknown) => string | null
  /** A group's notes, edited beside its name (KeePass's group notes); absent for no notes field. */
  notes?: string
  onSubmit: (name: string, notes?: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initial)
  const [noteText, setNoteText] = useState(notes ?? '')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) {
      setName(initial)
      setNoteText(notes ?? '')
      setError(null)
    }
  }, [open, initial, notes])
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <form
          className="mt-4 space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (!name.trim()) return
            setPending(true)
            onSubmit(name.trim(), notes === undefined ? undefined : noteText)
              .then(() => onOpenChange(false))
              .catch((failure: unknown) => setError(describeError?.(failure) ?? t('entry.saveFailed')))
              .finally(() => setPending(false))
          }}
        >
          <Field label={label ?? t('groups.name')} required>
            {(field) => <Input {...field} value={name} onChange={(e) => setName(e.target.value)} maxLength={256} required autoFocus />}
          </Field>
          {notes !== undefined ? (
            <Field label={t('groups.notes')}>{(field) => <Textarea {...field} value={noteText} onChange={(e) => setNoteText(e.target.value)} rows={4} />}</Field>
          ) : null}
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending} disabled={!name.trim()}>
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
