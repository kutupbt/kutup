import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'

/** An album's name: for a new album, or to rename one. */
export function NameAlbumDialog({ open, title, initial, pending, onClose, onSubmit }: {
  open: boolean
  title: string
  initial: string
  pending: boolean
  onClose: () => void
  onSubmit: (name: string) => void
}) {
  const { t } = useTranslation()
  const [name, setName] = useState(initial)
  useEffect(() => {
    if (open) setName(initial)
  }, [open, initial])
  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (name.trim()) onSubmit(name)
          }}
        >
          <Field label={t('albums.name')}>
            {(field) => <Input {...field} autoFocus value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={pending || !name.trim()}>
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
