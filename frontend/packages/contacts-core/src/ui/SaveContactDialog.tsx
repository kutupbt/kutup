import { Check, ExternalLink, Search, UserPlus, UserRoundPlus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { appUrl } from '@kutup/session/apps'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { cn } from '@kutup/ui/lib/cn'
import { useAddEmailToContact, useContacts, useSaveContact } from '../api'
import { displayName, emptyDraft, type Contact } from '../model'

type Mode = 'new' | 'existing'

function photoOf(contact: Contact) {
  const match = contact.draft.photo.match(/^data:(image\/[a-z+.-]+);base64,(.+)$/)
  return match ? { image: match[2], contentType: match[1] } : {}
}

/**
 * Saves an address someone wrote from (or was written to) into the address
 * book, without leaving the app: as a new contact, named as their mail named
 * them, or added to a contact who is already there (a second address for
 * the same person). Never without the person's action (docs/plans/contacts.md).
 */
export function SaveContactDialog({ address, name, onClose }: { address: string; name?: string; onClose: () => void }) {
  const { t } = useTranslation()
  const lower = address.trim().toLowerCase()
  const contacts = useContacts()
  const save = useSaveContact()
  const addEmail = useAddEmailToContact()
  const [mode, setMode] = useState<Mode>('new')
  const [newName, setNewName] = useState(name?.trim() ?? '')
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState<string | null>(null)
  const pending = save.isPending || addEmail.isPending
  const hasContacts = (contacts.data?.contacts.length ?? 0) > 0

  const matches = useMemo(() => {
    const all = contacts.data?.contacts ?? []
    const q = query.trim().toLocaleLowerCase()
    const found = q
      ? all.filter(
          (c) =>
            displayName(c.draft).toLocaleLowerCase().includes(q) ||
            c.draft.emails.some((e) => e.address.toLowerCase().includes(q)) ||
            c.draft.organization.toLocaleLowerCase().includes(q),
        )
      : all
    return [...found].sort((a, b) => displayName(a.draft).localeCompare(displayName(b.draft))).slice(0, 50)
  }, [contacts.data, query])

  function done() {
    toast.success(t('contactSave.saved', { address: lower }))
    onClose()
  }

  function submit() {
    const onError = (error: unknown) => toast.error(apiErrorMessage(error, t('contactSave.failed')))
    if (mode === 'new') {
      save.mutate({ draft: { ...emptyDraft(), name: newName.trim(), emails: [{ address: lower }] } }, { onSuccess: done, onError })
    } else if (chosen) {
      addEmail.mutate({ contactId: chosen, address: lower, name: name?.trim() }, { onSuccess: done, onError })
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('contactSave.title')}</DialogTitle>
          <DialogDescription className="break-all">{lower}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <div role="radiogroup" aria-label={t('contactSave.how')} className="grid gap-2 sm:grid-cols-2">
            {(
              [
                ['new', UserPlus, t('contactSave.newContact'), t('contactSave.newContactHint')],
                ['existing', UserRoundPlus, t('contactSave.existing'), t('contactSave.existingHint')],
              ] as const
            ).map(([value, Icon, label, hint]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={mode === value}
                disabled={value === 'existing' && !hasContacts}
                onClick={() => setMode(value)}
                className={cn(
                  'flex items-start gap-2 rounded-md border px-3 py-2 text-left text-sm transition-colors disabled:opacity-50',
                  mode === value ? 'border-primary bg-primary/10 ring-1 ring-primary' : 'border-border hover:bg-muted/60',
                )}
              >
                <Icon className={cn('mt-0.5 size-4 shrink-0', mode === value ? 'text-primary' : 'text-muted-foreground')} aria-hidden />
                <span className="flex-1">
                  <span className="block font-medium">{label}</span>
                  <span className="block text-xs text-muted-foreground">{hint}</span>
                </span>
                {mode === value ? <Check className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden /> : null}
              </button>
            ))}
          </div>

          {mode === 'new' ? (
            <Field label={t('contactSave.name')}>
              {(props) => <Input {...props} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder={lower} autoFocus />}
            </Field>
          ) : (
            <div className="space-y-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
                <Input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t('contactSave.search')}
                  aria-label={t('contactSave.search')}
                  className="pl-9"
                  autoFocus
                />
              </div>
              <ul role="listbox" aria-label={t('contactSave.existing')} className="max-h-64 overflow-y-auto rounded-md border border-border">
                {matches.length === 0 ? (
                  <li className="px-3 py-4 text-center text-sm text-muted-foreground">{t('contactSave.noMatches')}</li>
                ) : (
                  matches.map((contact) => (
                    <li
                      key={contact.id}
                      role="option"
                      aria-selected={chosen === contact.id}
                      tabIndex={0}
                      onClick={() => setChosen(contact.id)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          setChosen(contact.id)
                        }
                      }}
                      className={cn(
                        'flex cursor-pointer items-center gap-3 px-3 py-2 text-sm outline-none focus-visible:bg-muted',
                        chosen === contact.id ? 'bg-primary/15' : 'hover:bg-muted/60',
                      )}
                    >
                      <Avatar name={displayName(contact.draft)} size={32} {...photoOf(contact)} />
                      <span className="min-w-0">
                        <span className="block truncate font-medium">{displayName(contact.draft)}</span>
                        <span className="block truncate text-xs text-muted-foreground">
                          {contact.draft.emails.map((e) => e.address).join(', ')}
                        </span>
                      </span>
                      {chosen === contact.id ? <Check className="ml-auto size-4 shrink-0 text-primary" aria-hidden /> : null}
                    </li>
                  ))
                )}
              </ul>
            </div>
          )}

          <DialogFooter className="items-center sm:justify-between">
            <Button variant="link" size="sm" className="px-0" asChild>
              <a href={appUrl('contacts', `/?add=${encodeURIComponent(lower)}`)} target="_blank" rel="noopener">
                <ExternalLink />
                {t('contactSave.moreDetails')}
              </a>
            </Button>
            <span className="flex flex-col-reverse gap-2 sm:flex-row">
              <Button type="button" variant="outline" onClick={onClose}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={pending || (mode === 'existing' && !chosen)}>
                {t('contactSave.save')}
              </Button>
            </span>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
