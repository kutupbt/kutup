import { FileUp } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useImportContacts } from '@kutup/contacts-core/api'
import { displayName, type Contact, type ContactDraft } from '@kutup/contacts-core/model'
import { parseVCards } from '@kutup/contacts-core/vcard'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

interface Card {
  uid?: string
  draft: ContactDraft
  duplicate: boolean
}

/** Reads .vcf files (one or many cards), shows what came, and imports. */
export function ImportDialog({ open, onOpenChange, existing }: { open: boolean; onOpenChange: (open: boolean) => void; existing: Contact[] }) {
  const { t } = useTranslation()
  const importer = useImportContacts()
  const [cards, setCards] = useState<Card[] | null>(null)
  const [failed, setFailed] = useState<string[]>([])
  const [skipDuplicates, setSkipDuplicates] = useState(true)

  useEffect(() => {
    if (!open) return
    setCards(null)
    setFailed([])
    importer.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset once per opening
  }, [open])

  async function read(files: FileList) {
    const knownUids = new Set(existing.map((contact) => contact.uid))
    const knownEmails = new Set(existing.flatMap((contact) => contact.draft.emails.map((e) => e.address.toLowerCase())))
    const read: Card[] = []
    const bad: string[] = []
    for (const file of Array.from(files)) {
      try {
        for (const card of parseVCards(await file.text())) {
          if (!displayName(card.draft)) continue
          const duplicate = (card.uid !== undefined && knownUids.has(card.uid)) || card.draft.emails.some((e) => knownEmails.has(e.address.toLowerCase()))
          read.push({ ...card, duplicate })
        }
      } catch {
        bad.push(file.name)
      }
    }
    setCards(read)
    setFailed(bad)
  }

  const chosen = (cards ?? []).filter((card) => !(skipDuplicates && card.duplicate))
  const duplicates = (cards ?? []).filter((card) => card.duplicate).length

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('import.title')}</DialogTitle>
          <DialogDescription>{t('import.description')}</DialogDescription>
        </DialogHeader>
        <div className="mt-4 space-y-4">
          <Button variant="outline" asChild>
            <label className="cursor-pointer">
              <FileUp />
              {t('import.choose')}
              <input
                type="file"
                accept=".vcf,.vcard,text/vcard,text/x-vcard"
                multiple
                className="sr-only"
                data-testid="import-file"
                onChange={(e) => {
                  if (e.target.files?.length) void read(e.target.files)
                  e.target.value = ''
                }}
              />
            </label>
          </Button>
          {failed.length > 0 ? <Alert variant="error">{t('import.unreadable', { names: failed.join(', ') })}</Alert> : null}
          {cards ? (
            cards.length === 0 ? (
              <Alert>{t('import.none')}</Alert>
            ) : (
              <div className="space-y-3">
                <p className="text-sm">{t('import.found', { count: cards.length })}</p>
                {duplicates > 0 ? (
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox checked={skipDuplicates} onCheckedChange={(on) => setSkipDuplicates(on === true)} />
                    {t('import.skipDuplicates', { count: duplicates })}
                  </label>
                ) : null}
                <ul className="max-h-48 divide-y divide-border overflow-y-auto rounded-md border border-border text-sm">
                  {cards.slice(0, 200).map((card, i) => (
                    <li key={i} className="flex justify-between gap-2 px-3 py-1.5">
                      <span className="truncate">{displayName(card.draft)}</span>
                      {card.duplicate ? <span className="shrink-0 text-xs text-muted-foreground">{t('import.duplicate')}</span> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )
          ) : null}
          {importer.error ? <Alert variant="error">{apiErrorMessage(importer.error, t('import.failed'))}</Alert> : null}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t('common.cancel')}</Button>
          <Button
            disabled={chosen.length === 0}
            loading={importer.isPending}
            onClick={() =>
              importer.mutate(
                { cards: chosen, takenUids: new Set(existing.map((contact) => contact.uid)) },
                {
                  onSuccess: (count) => {
                    toast.success(t('import.done', { count }))
                    onOpenChange(false)
                  },
                },
              )
            }
          >
            {t('import.submit', { count: chosen.length })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
