import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'

/** Names a new group, or renames one. */
export function GroupDialog({
  open,
  onOpenChange,
  title,
  initial,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  initial: string
  onSubmit: (name: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initial)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState(false)
  useEffect(() => {
    if (open) {
      setName(initial)
      setError(false)
    }
  }, [open, initial])
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
            onSubmit(name.trim())
              .then(() => onOpenChange(false))
              .catch(() => setError(true))
              .finally(() => setPending(false))
          }}
        >
          <Field label={t('groups.name')} required>
            {(field) => <Input {...field} value={name} onChange={(e) => setName(e.target.value)} maxLength={256} required autoFocus />}
          </Field>
          {error ? <Alert variant="error">{t('entry.saveFailed')}</Alert> : null}
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
