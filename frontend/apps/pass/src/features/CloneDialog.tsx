import { useEffect, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import type { VaultSession } from '../sync/vaultSession'

/**
 * Clones entries as KeePassXC's dialog does (docs/plans/pass-gaps-2.md P4):
 * " - Clone" after the title (on by default) and the history (off). Its
 * "replace user name and password with references" waits for references
 * to be resolved (pass-parity item 12), so no raw {REF:…} is ever copied.
 */
export function CloneDialog({
  session,
  ids,
  onOpenChange,
  onCloned,
}: {
  session: VaultSession
  /** The entries to clone; the dialog is open while there are some. */
  ids: string[]
  onOpenChange: (open: boolean) => void
  /** The first copy, to open it. */
  onCloned: (id: string) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const open = ids.length > 0
  const [suffix, setSuffix] = useState(true)
  const [history, setHistory] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (open) setError(null)
  }, [open])
  return (
    <Dialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('clone.title', { count: ids.length })}</DialogTitle>
          <DialogDescription>{t('clone.description', { count: ids.length })}</DialogDescription>
        </DialogHeader>
        <form
          className="mt-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault()
            setPending(true)
            setError(null)
            session
              .apply({ op: 'cloneEntries', ids, titleSuffix: suffix ? t('clone.suffix') : null, history })
              .then(
                (applied) => {
                  toast.success(t('clone.done', { count: ids.length }))
                  onOpenChange(false)
                  if (applied.id) onCloned(applied.id)
                },
                () => setError(t('entry.saveFailed')),
              )
              .finally(() => setPending(false))
          }}
        >
          <div className="flex items-center gap-2">
            <Checkbox id={`${id}-suffix`} checked={suffix} onCheckedChange={(v) => setSuffix(v === true)} />
            <label htmlFor={`${id}-suffix`} className="text-sm">
              {t('clone.appendSuffix', { suffix: t('clone.suffix').trim() })}
            </label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox id={`${id}-history`} checked={history} onCheckedChange={(v) => setHistory(v === true)} />
            <label htmlFor={`${id}-history`} className="text-sm">
              {t('clone.copyHistory')}
            </label>
          </div>
          {error ? <Alert variant="error">{error}</Alert> : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" loading={pending}>
              {t('clone.submit')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
