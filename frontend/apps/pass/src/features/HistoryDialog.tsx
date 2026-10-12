import { History } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Spinner } from '@kutup/ui/components/states'
import { formatInstant } from '@kutup/ui/lib/format'
import type { VaultSession } from '../sync/vaultSession'
import type { EntryView } from '../vault/types'
import { fieldValue } from '../vault/types'

/** An entry's earlier states, newest first; one can be made current again. */
export function HistoryDialog({
  session,
  entry,
  open,
  onOpenChange,
}: {
  session: VaultSession
  entry: EntryView
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t, i18n } = useTranslation()
  const [items, setItems] = useState<EntryView[] | null>(null)
  const [shown, setShown] = useState<number | null>(null)
  useEffect(() => {
    if (!open) return
    setItems(null)
    setShown(null)
    void session
      .vault()
      .history(entry.id)
      .then(setItems)
      .catch(() => setItems([]))
  }, [open, session, entry.id, entry.historyCount])
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('history.title')}</DialogTitle>
          <DialogDescription>{t('history.description')}</DialogDescription>
        </DialogHeader>
        {!items ? (
          <Spinner label={t('common.loading')} />
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('history.empty')}</p>
        ) : (
          <ol className="mt-2 space-y-2">
            {items
              .map((item, index) => ({ item, index }))
              .reverse()
              .map(({ item, index }) => (
                <li key={index} className="rounded-md border border-border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{fieldValue(item, 'Title') || t('entry.untitled')}</p>
                      <p className="text-xs text-muted-foreground">{formatInstant(item.modified, i18n.language) ?? t('history.unknownTime')}</p>
                    </div>
                    <div className="flex gap-1">
                      <Button type="button" variant="ghost" size="sm" onClick={() => setShown(shown === index ? null : index)}>
                        {shown === index ? t('history.hide') : t('history.show')}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={!session.canEdit}
                        onClick={() => {
                          void session.apply({ op: 'restoreHistory', id: entry.id, index }).then(() => onOpenChange(false))
                        }}
                      >
                        <History />
                        {t('history.restore')}
                      </Button>
                    </div>
                  </div>
                  {shown === index ? (
                    <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                      {item.fields.map((f) => (
                        <div key={f.key} className="contents">
                          <dt className="text-muted-foreground">{f.key}</dt>
                          <dd className="break-all font-mono text-xs">{f.value}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : null}
                </li>
              ))}
          </ol>
        )}
      </DialogContent>
    </Dialog>
  )
}
