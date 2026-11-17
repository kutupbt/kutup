import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useCreateFilter } from '@kutup/mail-core/filters'
import type { MailPlaces } from '@kutup/mail-core/places'
import { sieveToFilters, type SieveImport } from '@kutup/mail-core/sieve'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { describeFilter } from './filterText'
import { sievePlaces } from './sieveFiles'

/**
 * Import from Sieve (docs/plans/mail-filters.md, F4): a script pasted or
 * chosen, read in the browser; the filters Kutup can hold are listed and
 * added after the existing ones, and what it cannot take is named.
 */
export function SieveImportDialog({ places, onClose }: { places: MailPlaces | undefined; onClose: () => void }) {
  const { t } = useTranslation()
  const create = useCreateFilter()
  const [script, setScript] = useState('')
  const [read, setRead] = useState<SieveImport | null>(null)
  const [adding, setAdding] = useState(false)

  async function add() {
    if (!read) return
    setAdding(true)
    let added = 0
    try {
      for (const filter of read.filters) {
        // One at a time, in order: each runs after those before it.
        await create.mutateAsync({ ...filter, id: crypto.randomUUID() })
        added++
      }
      toast.success(t('sieve.added', { count: added }))
      onClose()
    } catch (error) {
      toast.error(t('sieve.addFailed', { count: added, error: apiErrorMessage(error, t('common.tryAgain')) }))
      setRead({ ...read, filters: read.filters.slice(added) })
    } finally {
      setAdding(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !adding && onClose()}>
      <DialogContent className="sm:max-w-2xl" data-testid="sieve-import">
        <DialogHeader>
          <DialogTitle>{t('sieve.importTitle')}</DialogTitle>
          <DialogDescription>{t('sieve.importDescription')}</DialogDescription>
        </DialogHeader>
        {read === null ? (
          <div className="space-y-3">
            <Textarea
              value={script}
              onChange={(e) => setScript(e.target.value)}
              rows={12}
              spellCheck={false}
              className="font-mono text-xs"
              aria-label={t('sieve.script')}
              placeholder={'require ["fileinto"];\nif header :contains "Subject" "invoice" {\n    fileinto "Bills";\n}'}
            />
            <input
              type="file"
              accept=".sieve,.siv,.txt,text/plain,application/sieve"
              aria-label={t('sieve.chooseFile')}
              className="text-sm"
              onChange={(e) => {
                const file = e.target.files?.[0]
                // A script is text; 1 MB is far past any real one.
                if (file && file.size <= 1_000_000) void file.text().then(setScript)
                else if (file) toast.error(t('sieve.tooLarge'))
              }}
            />
          </div>
        ) : (
          <div className="max-h-[50vh] space-y-3 overflow-y-auto">
            {read.filters.length ? (
              <section aria-label={t('sieve.toAdd', { count: read.filters.length })} className="space-y-1">
                <h3 className="text-sm font-medium">{t('sieve.toAdd', { count: read.filters.length })}</h3>
                <ul className="divide-y divide-border rounded-md border border-border">
                  {read.filters.map((filter, i) => (
                    <li key={i} className="px-3 py-2">
                      <p className="text-sm font-medium">{filter.name}</p>
                      <p className="text-xs text-muted-foreground">{describeFilter(filter, places, t)}</p>
                    </li>
                  ))}
                </ul>
              </section>
            ) : (
              <Alert>{t('sieve.nothing')}</Alert>
            )}
            {read.problems.length ? (
              <Alert variant="warn" title={t('sieve.skipped', { count: read.problems.length })}>
                <ul className="list-disc space-y-1 pl-4">
                  {read.problems.map((problem, i) => (
                    <li key={i}>
                      {t(`sieve.problem.${problem.kind}`)} <code className="break-all text-xs">{problem.what}</code>
                    </li>
                  ))}
                </ul>
              </Alert>
            ) : null}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={read ? () => setRead(null) : onClose} disabled={adding}>
            {read ? t('sieve.back') : t('common.cancel')}
          </Button>
          {read === null ? (
            <Button disabled={!script.trim()} onClick={() => setRead(sieveToFilters(script, sievePlaces(places)))}>
              {t('sieve.read')}
            </Button>
          ) : (
            <Button disabled={adding || read.filters.length === 0} onClick={() => void add()}>
              {t('sieve.add', { count: read.filters.length })}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
